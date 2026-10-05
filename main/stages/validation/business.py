"""Business-logic mutation probe (state-changing, opt-in)."""
from typing import List

from ...budgets import BudgetExceeded, BudgetTracker
from ...logging_setup import get_logger
from ...logic.business_logic import (BusinessLogicTester,
                                      candidate_params)
from ...models import (Confidence, Endpoint, Finding, ValidationStatus,
                       stable_finding_id)
from ...reporting.coverage import CoverageTracker
from ...validation.evidence import EvidenceStore
from ...reporting.metrics import Metrics
from ...safety.preflight import plan_business
from . import ProbeControls, reserve_or_block

log = get_logger("stages-validation")


def business_logic_probe(endpoints: List[Endpoint],
                         evidence: EvidenceStore, metrics: Metrics,
                         budgets: BudgetTracker,
                         coverage: CoverageTracker, client,
                         cfg, scope, controls: ProbeControls,
                         identities) -> List[Finding]:
    cfg_b = cfg.business
    scored = [(e, candidate_params(e, cfg_b.max_params))
              for e in endpoints
              if e.endpoint_type != "static"
              and scope.active_test_allowed(e.url)]
    scored = [(e, c) for e, c in scored if c][:cfg_b.max_endpoints]
    if not scored:
        coverage.record("business_logic", "untestable",
                        "no transactional parameters")
        return []
    actors = [i for i in identities if i.name != "anonymous"] or \
        identities[:1]
    actor = actors[0]
    aname = getattr(actor, "name", "anonymous")
    atenant = getattr(actor, "tenant", "") or ""
    tester = BusinessLogicTester(cfg, client)
    log.info("business-logic: %d endpoints as %s",
             len(scored), aname)
    if not reserve_or_block(
            budgets, coverage, "business_logic",
            plan_business(len(scored), cfg_b.max_params)):
        return []
    findings: List[Finding] = []
    for ep, cands in scored:
        if not budgets.consume_test("business_logic",
                                    ep.normalized_url):
            coverage.record("business_logic", "blocked",
                            f"budget: {ep.normalized_url}")
            continue
        for cand in cands:
            if controls.halted():
                log.info("business-logic: halted by stop control; "
                         "remaining targets stay untested")
                break
            controls.paced()
            try:
                results = tester.probe(
                    ep, cand, actor,
                    timeout=cfg.scan.http_timeout)
            except BudgetExceeded:
                coverage.record("business_logic", "blocked",
                                f"budget: {ep.normalized_url}")
                break
            for res in results:
                metrics.business_logic_tests += 1
                if res.verdict == "strong_candidate":
                    metrics.business_logic_candidates += 1
                    controls.noted()
                    metrics.invariants_violated += len(res.violations)
                    coverage.record("business_logic", "candidate",
                                    res.notes)
                    inv = res.violations[0]["invariant_id"] \
                        if res.violations else "invariant"
                    # readback verification: echo is not proof —
                    # re-observe clean state before confirming
                    ver = verify_business_effect(
                        client, ep, cand, res, actor, cfg)
                    status, conf = (
                        ValidationStatus.STRONG_CANDIDATE.value,
                        Confidence.PROBABLE.value)
                    extra_tags: list = []
                    suffix = ""
                    if ver["status"] == "verified":
                        status = ValidationStatus.CONFIRMED.value
                        conf = Confidence.CONFIRMED.value
                        metrics.effects_verified += 1
                        extra_tags.append("verified-effect")
                        suffix = " [verified effect]"
                        log.info("business-logic verified: %s",
                                 ver["detail"])
                    elif ver["status"] == "refuted":
                        # positive proof of NO persistence: the
                        # echo-only candidate cannot stand
                        status = ValidationStatus.INCONCLUSIVE.value
                        conf = Confidence.UNKNOWN.value
                        suffix = " [effect not persisted]"
                    f = Finding(
                        id=stable_finding_id("bl", ep.normalized_url,
                                             cand.param, str(res.mutated)),
                        source="business-logic",
                        name=(f"Business logic: {cand.param}="
                              f"{res.mutated} accepted, violates "
                              f"{inv} ({ep.path})" + suffix),
                        severity="high",
                        confidence=conf,
                        validation_status=status,
                        host=ep.host, matched_at=ep.url,
                        endpoint_url=ep.url, method=ep.method,
                        parameter=cand.param,
                        description=res.notes + (
                            f" Verification: {ver['detail']}"
                            if ver["detail"] else ""),
                        tags=["business-logic", cand.kind,
                              ep.endpoint_type] + extra_tags,
                        raw={"business": res.to_dict(),
                             "verification": ver},
                        false_positive_notes=(
                            "Acceptance is echo-based (mutated value "
                            "reflected with HTTP 200) — a proxy for "
                            "server-side effect, not proof of it. "
                            + ("Persistence CONFIRMED by clean "
                               "re-read; see verification evidence."
                               if ver["status"] == "verified"
                               else "Confirm the persisted state "
                               "before reporting.")),
                        identity=aname, tenant=atenant,
                        resource_key=(f"{ep.normalized_url}::"
                                      f"{cand.param}"),
                    )
                    evidence.allocate(f)
                    evidence.record(
                        f,
                        request_text=(
                            f"{ep.method} {ep.url} "
                            f"({cand.param}={res.mutated})"),
                        response_text=res.notes + (
                            f"\n--- verification ---\n{ver['detail']}"
                            if ver["detail"] else ""))
                    findings.append(f)
                    log.info("business-logic: %s", res.notes)
                elif res.baseline_status != 200:
                    coverage.record("business_logic", "inconclusive",
                                    f"{ep.normalized_url}: "
                                    f"{res.notes}")
                else:
                    coverage.record("business_logic", "tested_negative",
                                    f"{ep.normalized_url}::"
                                    f"{cand.param}: {res.notes}")
    metrics.invariants_tested += tester.evaluations
    return findings


def verify_business_effect(client, ep, cand, res, actor,
                           cfg) -> dict:
    """Readback verification for one accepted mutation.

    Returns {"status": verified|refuted|inconclusive, "detail",
    "evidence"}. Order: user assertions (explicit read URL wins) →
    token-reuse sequential check → generic persistence readback.
    POST endpoints without an after_read have no safe re-read
    (re-POSTing is another write) → inconclusive, finding stands.
    """
    from urllib.parse import urljoin
    from ...verify.base import (verify_persisted, verify_token_reuse)
    from ...verify.assertions import (matching_assertions,
                                      evaluate_assertions)
    timeout = cfg.scan.http_timeout
    headers = dict(getattr(actor, "auth_headers", None) or {})
    blank = {"status": "inconclusive", "detail": "", "evidence": {}}

    def _wrap(v):
        return {"status": v.status, "detail": v.detail,
                "evidence": v.evidence}

    # 1) user-supplied assertions (explicit readback contract)
    matched = matching_assertions(
        getattr(cfg.business, "assertions", []) or [],
        ep.path, cand.param, ep.method)
    for a in matched:
        after = (a.get("after_read") or "").strip()
        if not after:
            continue
        read_url = after if after.startswith("http") else \
            urljoin(ep.url, after)
        try:
            r = client.get(read_url, headers=headers,
                           timeout=timeout)
        except Exception as e:
            return {"status": "inconclusive",
                    "detail": f"assertion readback failed: {e}"[:200],
                    "evidence": {}}
        if r.status_code != 200:
            return {"status": "inconclusive",
                    "detail": f"assertion readback → "
                              f"HTTP {r.status_code}",
                    "evidence": {}}
        verdict, detail, ev = evaluate_assertions(
            [a], r.text or "")
        if verdict == "passed":
            # invariant holds on re-read: violation did NOT persist
            return {"status": "refuted",
                    "detail": f"assertion holds on re-read: {detail}",
                    "evidence": {**ev, "read_url": read_url}}
        if verdict == "failed":
            return {"status": "verified",
                    "detail": f"assertion violated on re-read: "
                              f"{detail}",
                    "evidence": {**ev, "read_url": read_url}}
        return {"status": "inconclusive", "detail": detail,
                "evidence": ev}
    # 2) token-reuse: sequential double-submit is self-contained
    if cand.kind == "token_reuse":
        params = {p.name: (p.sample_value or "1") for p in
                  list(ep.query_parameters or []) +
                  list(ep.body_parameters or []) if p.name}
        has_body = bool(ep.body_parameters)
        v = verify_token_reuse(
            client, "POST" if has_body else "GET", ep.url,
            params if has_body else {},
            headers, timeout,
            query=None if has_body else params)
        return _wrap(v)
    # 3) generic persistence: safe re-read exists only for GET
    # endpoints (re-POSTing baseline would be another write).
    # The mutated param is stripped: a clean re-read observes
    # persisted state instead of re-applying the mutation.
    has_body = bool(ep.body_parameters)
    if has_body:
        return blank
    from urllib.parse import (urlsplit, urlunsplit, parse_qsl,
                              urlencode)
    parts = urlsplit(ep.url)
    q = [(k, v) for k, v in
         parse_qsl(parts.query, keep_blank_values=True)
         if k != cand.param]
    read_url = urlunsplit(
        (parts.scheme, parts.netloc, parts.path,
         urlencode(q, doseq=True), ""))
    v = verify_persisted(client, read_url, headers, cand.param,
                         res.mutated, timeout)
    return _wrap(v)
