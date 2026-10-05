"""Race-condition probe (synchronized bursts, opt-in)."""
from typing import List

from ...budgets import BudgetExceeded, BudgetTracker
from ...logging_setup import get_logger
from ...logic.observations import (evaluate_observation, violated)
from ...logic.race import run_race, single_use_field
from ...models import (Confidence, Endpoint, Finding, ValidationStatus,
                       stable_finding_id)
from ...reporting.coverage import CoverageTracker
from ...validation.evidence import EvidenceStore
from ...reporting.metrics import Metrics
from ...safety.preflight import plan_race
from . import ProbeControls, reserve_or_block

log = get_logger("stages-validation")


def race_probe(endpoints: List[Endpoint],
               evidence: EvidenceStore, metrics: Metrics,
               budgets: BudgetTracker,
               coverage: CoverageTracker, client,
               cfg, scope, controls: ProbeControls,
               identities) -> List[Finding]:
    cfg_r = cfg.race
    profile = (cfg_r.profile or "generic").lower()
    if profile not in ("generic", "single_use", "idempotency",
                       "inventory"):
        coverage.record("race", "untestable",
                        f"unknown race profile: {profile}")
        return []
    targets = [e for e in endpoints
               if e.body_parameters and e.endpoint_type != "static"
               and scope.active_test_allowed(e.url)]
    actors = [i for i in identities if i.name != "anonymous"] or \
        identities[:1]
    actor = actors[0]
    aname = getattr(actor, "name", "anonymous")
    atenant = getattr(actor, "tenant", "") or ""
    aheaders = dict(getattr(actor, "auth_headers", None) or {})
    if profile == "single_use":
        targets = [e for e in targets if single_use_field({
            p.name: p.sample_value for p in e.body_parameters
            if p.name and p.sample_value})]
    elif profile == "idempotency":
        targets = [e for e in targets if
                   any("idempotency" in p.name.lower()
                       and p.sample_value for p in e.body_parameters
                       if p.name)
                   or any("idempotency" in k.lower() and v
                          for k, v in aheaders.items())]
    elif profile == "inventory":
        selector = (cfg_r.inventory_endpoint or "").strip()
        if not selector or not cfg_r.inventory_read_url or \
                not cfg_r.inventory_jsonpath:
            coverage.record(
                "race", "untestable",
                "inventory profile requires inventory_endpoint, "
                "inventory_read_url, and inventory_jsonpath")
            return []
        targets = [e for e in targets
                   if e.path == selector or e.url == selector or
                   e.path.endswith(selector)]
    targets = targets[:cfg_r.max_endpoints]
    if not targets:
        coverage.record("race", "untestable",
                        f"no POST-able endpoints match {profile} profile")
        return []
    log.info("race: %d endpoints ×%d/%d as %s", len(targets),
             cfg_r.concurrency, cfg_r.rounds, aname)
    if not reserve_or_block(
            budgets, coverage, "race",
            plan_race(len(targets), cfg_r.concurrency,
                      cfg_r.rounds)):
        return []
    findings: List[Finding] = []
    for ep in targets:
        if controls.halted():
            log.info("race: halted by stop control; "
                     "remaining targets stay untested")
            break
        controls.paced()
        if not budgets.consume_test("race", ep.normalized_url):
            coverage.record("race", "blocked",
                            f"budget: {ep.normalized_url}")
            continue
        body = {p.name: (p.sample_value or "1")
                for p in ep.body_parameters if p.name}
        inventory_before = None
        if profile == "inventory":
            before = read_race_inventory(client, ep, aheaders, cfg,
                                         scope, controls)
            if before.get("status") != "read":
                before_status = ("blocked" if
                                 before.get("status") == "blocked"
                                 else "inconclusive")
                coverage.record("race", before_status,
                                before.get("detail", "inventory read failed"))
                continue
            inventory_before = before["value"]
            if inventory_before <= 0:
                coverage.record("race", "untestable",
                                "inventory precondition requires stock > 0")
                continue
        try:
            res = run_race(client, "POST", ep.url, body, aheaders,
                           concurrency=cfg_r.concurrency,
                           rounds=cfg_r.rounds,
                           timeout=cfg.scan.http_timeout,
                           profile=profile)
        except BudgetExceeded:
            coverage.record("race", "blocked",
                            f"budget: {ep.normalized_url}")
            continue
        inventory_verification = None
        if profile == "inventory":
            after = read_race_inventory(client, ep, aheaders, cfg,
                                        scope, controls)
            completed = all(
                not rr.errors and len(rr.statuses) == cfg_r.concurrency
                and all(200 <= status < 300 or 400 <= status < 500
                        for status in rr.statuses)
                for rr in res.round_results)
            accepted = sum(
                1 for rr in res.round_results for status in rr.statuses
                if 200 <= status < 300)
            if after.get("status") != "read":
                if (after.get("status") == "blocked" and
                        accepted > inventory_before):
                    res.verdict = "strong_candidate"
                else:
                    res.verdict = "inconclusive"
                res.notes = "inventory post-read failed: " + \
                    after.get("detail", "unknown error")
                inventory_verification = {
                    "status": "inconclusive", "detail": res.notes,
                    "evidence": {"before": inventory_before}}
            elif after["value"] < 0:
                obs = {"action": "write", "resource": ep.url,
                       "quantity_after": after["value"]}
                res.violations = [v.to_dict() for v in
                                  violated(evaluate_observation(obs))]
                res.verdict = "strong_candidate"
                res.notes = (f"inventory fell below zero: "
                             f"{after['value']}")
                inventory_verification = {
                    "status": "verified", "detail": res.notes,
                    "evidence": {"before": inventory_before,
                                 "after": after["value"],
                                 "accepted": accepted,
                                 "read_url": after.get("read_url")}}
            elif accepted > inventory_before:
                res.verdict = "strong_candidate"
                res.notes = (f"{accepted} reservations accepted with "
                             f"starting inventory {inventory_before}; "
                             "post-read did not prove a negative balance")
                inventory_verification = {
                    "status": "inconclusive", "detail": res.notes,
                    "evidence": {"before": inventory_before,
                                 "after": after["value"],
                                 "accepted": accepted,
                                 "read_url": after.get("read_url")}}
            elif completed and after["value"] >= 0:
                res.verdict = "negative"
                res.notes = (f"inventory remained non-negative "
                             f"({inventory_before} → {after['value']}); "
                             "completed requests respected available stock")
                inventory_verification = {
                    "status": "refuted", "detail": res.notes,
                    "evidence": {"before": inventory_before,
                                 "after": after["value"],
                                 "accepted": accepted,
                                 "read_url": after.get("read_url")}}
            else:
                res.verdict = "inconclusive"
                res.notes = "inventory race responses were incomplete or ambiguous"
                inventory_verification = {
                    "status": "inconclusive", "detail": res.notes,
                    "evidence": {"before": inventory_before,
                                 "after": after["value"],
                                 "accepted": accepted}}
        metrics.race_tests += 1
        if res.verdict == "strong_candidate":
            metrics.race_candidates += 1
            controls.noted()
            metrics.invariants_tested += 1
            metrics.invariants_violated += len(res.violations)
            coverage.record("race", "candidate", res.notes)
            if inventory_verification is not None:
                ver = inventory_verification
            elif profile == "single_use":
                ver = verify_race_single_use(
                    client, ep, body, aheaders,
                    single_use_field(body), cfg)
            else:
                ver = verify_race_idempotent(
                    client, ep, body, aheaders, cfg)
            status, conf = (
                ValidationStatus.STRONG_CANDIDATE.value,
                Confidence.PROBABLE.value)
            extra_tags: list = []
            if ver["status"] == "verified":
                status = ValidationStatus.CONFIRMED.value
                conf = Confidence.CONFIRMED.value
                metrics.effects_verified += 1
                extra_tags.append("verified-effect")
                log.info("race verified: %s", ver["detail"])
            f = Finding(
                id=stable_finding_id("race", ep.normalized_url),
                source="race",
                name=(f"Race condition: {cfg_r.concurrency}× POST "
                      f"{ep.path} processed concurrently with "
                      f"divergent results"
                      + (" [verified effect]"
                         if ver["status"] == "verified" else "")),
                severity="high",
                confidence=conf,
                validation_status=status,
                host=ep.host, matched_at=ep.url,
                endpoint_url=ep.url, method="POST",
                description=res.notes + (
                    f" Verification: {ver['detail']}"
                    if ver["detail"] else ""),
                tags=["race", "business-logic", ep.endpoint_type] +
                extra_tags,
                raw={"race": res.to_dict(),
                     "verification": ver},
                false_positive_notes=(
                    "Divergent IDs across a synchronized burst "
                    "indicate duplicate processing; rule out "
                    "request-specific randomness (timestamps, "
                    "nonces) before reporting."
                    + (" Sequential idempotency re-check CONFIRMED "
                       "double processing; see verification evidence."
                       if ver["status"] == "verified" else "")),
                identity=aname, tenant=atenant,
            )
            evidence.allocate(f)
            evidence.record(
                f,
                request_text=(f"{cfg_r.concurrency}× POST {ep.url} "
                              f"through a start barrier, "
                              f"{cfg_r.rounds} rounds"),
                response_text=res.notes + (
                    f"\n--- verification ---\n{ver['detail']}"
                    if ver["detail"] else ""))
            findings.append(f)
            log.info("race: %s", res.notes)
        elif res.verdict == "negative":
            coverage.record("race", "tested_negative",
                            f"{ep.normalized_url}: {res.notes}")
        else:
            coverage.record("race", "inconclusive",
                            f"{ep.normalized_url}: {res.notes}")
    return findings


def verify_race_idempotent(client, ep, body, headers, cfg) -> dict:
    """Sequential idempotency re-check for a divergent burst.

    Only runs when the request carries an idempotency key
    (Idempotency-Key header or *idempotency* body field) — without
    one, there is nothing well-defined to re-check, so verification
    stays inconclusive and the candidate stands as-is.
    """
    from ...verify.base import verify_idempotency
    timeout = cfg.scan.http_timeout
    key_name = ""
    for hk in headers:
        if hk.lower() == "idempotency-key":
            key_name = hk
            break
    if not key_name:
        for bk in body:
            if "idempotency" in bk.lower():
                key_name = bk
                break
    if not key_name:
        return {"status": "inconclusive",
                "detail": "no idempotency key present — nothing "
                          "well-defined to re-check",
                "evidence": {}}
    v = verify_idempotency(client, "POST", ep.url, body, headers,
                           key_name, timeout)
    return {"status": v.status, "detail": v.detail,
            "evidence": v.evidence}


def verify_race_single_use(client, ep, body, headers,
                           key_name: str, cfg) -> dict:
    """Sequentially re-submit a token-like value after a race signal."""
    from ...verify.base import verify_token_reuse
    v = verify_token_reuse(client, "POST", ep.url, body, headers,
                           key_name, cfg.scan.http_timeout)
    return {"status": v.status, "detail": v.detail,
            "evidence": v.evidence}


def read_race_inventory(client, ep, headers, cfg, scope,
                        controls: ProbeControls) -> dict:
    """Read a configured inventory field before/after a reservation race."""
    from urllib.parse import urljoin
    from ...logic.race import inventory_value
    raw_url = (cfg.race.inventory_read_url or "").strip()
    if not raw_url:
        return {"status": "inconclusive",
                "detail": "race.inventory_read_url is required"}
    read_url = (raw_url if raw_url.startswith(("http://", "https://"))
                else urljoin(ep.url, raw_url))
    if not scope.is_in_scope(read_url):
        return {"status": "inconclusive",
                "detail": "inventory read URL is out of scope",
                "read_url": read_url}
    try:
        controls.paced()
        response = client.get(read_url, headers=headers,
                              timeout=cfg.scan.http_timeout)
    except BudgetExceeded:
        return {"status": "blocked",
                "detail": "inventory read blocked by request budget",
                "read_url": read_url}
    except Exception as e:
        return {"status": "inconclusive",
                "detail": f"inventory read failed: {e}"[:200],
                "read_url": read_url}
    if response.status_code != 200:
        return {"status": "inconclusive",
                "detail": f"inventory read → HTTP {response.status_code}",
                "read_url": read_url}
    value = inventory_value(response.text or "",
                            cfg.race.inventory_jsonpath)
    if value is None:
        return {"status": "inconclusive",
                "detail": "inventory JSONPath did not select one number",
                "read_url": read_url}
    return {"status": "read", "value": value,
            "read_url": read_url}
