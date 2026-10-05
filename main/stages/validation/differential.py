"""Differential auth-context probe (BOLA/IDOR/broken access)."""
from typing import List

from ...budgets import BudgetExceeded, BudgetTracker
from ...logging_setup import get_logger
from ...models import (Confidence, Endpoint, Finding, ValidationStatus,
                       stable_finding_id)
from ...reporting.coverage import CoverageTracker
from ...validation.evidence import EvidenceStore
from ...reporting.metrics import Metrics
from ...safety.preflight import plan_differential
from ...validation.differential import (
    PRIVILEGED_TYPES, DifferentialTester, has_idor_params)
from . import ProbeControls, reserve_or_block

log = get_logger("stages-validation")


def differential_probe(endpoints: List[Endpoint],
                       diff: DifferentialTester,
                       evidence: EvidenceStore, metrics: Metrics,
                       budgets: BudgetTracker,
                       coverage: CoverageTracker, cfg, scope,
                       controls: ProbeControls
                       ) -> List[Finding]:
    targets = [e for e in endpoints
               if e.endpoint_type in PRIVILEGED_TYPES
               or (has_idor_params(e)
                   and e.endpoint_type != "static")]
    # per-resource endpoints (idor params) first — BOLA hides there
    targets.sort(key=lambda e: 0 if has_idor_params(e) else 1)
    targets = targets[:cfg.validation.differential_max_endpoints]
    if not targets:
        log.info("differential: no privileged/identifier endpoints "
                 "discovered — nothing to compare")
        return []
    log.info("differential: probing %d endpoints "
             "(contexts=%s)", len(targets),
             [c["name"] for c in diff.contexts])
    if not reserve_or_block(
            budgets, coverage, "authz",
            plan_differential(len(targets), len(diff.contexts))):
        return []
    tenant_of = {c.name: (getattr(c, "tenant", "") or "")
                 for c in cfg.auth.contexts}
    findings: List[Finding] = []
    for ep in targets:
        if controls.halted():
            log.info("differential: halted by stop control; "
                     "remaining targets stay untested")
            break
        if not scope.active_test_allowed(ep.url):
            continue
        if not budgets.consume_test("authz", ep.normalized_url):
            coverage.record("authz", "blocked",
                            f"budget: {ep.normalized_url}")
            continue
        try:
            res = diff.probe(ep.url, ep.endpoint_type,
                             timeout=cfg.scan.http_timeout)
        except BudgetExceeded:
            coverage.record("authz", "blocked",
                            f"budget: {ep.normalized_url}")
            continue
        metrics.differential_probes += 1
        metrics.authorization_tests += 1
        authed = [c.name for c in res.contexts
                  if c.name != "anonymous"]
        if getattr(res, "edge_denied", False):
            coverage.record("authz", "inconclusive",
                            f"{ep.normalized_url}: edge/bot-wall "
                            f"answers; app never reached")
            continue
        if any(getattr(c, "error", "") for c in res.contexts):
            # Rule 1: incomplete comparisons stay inconclusive,
            # never tested_negative.
            coverage.record("authz", "inconclusive",
                            f"{ep.normalized_url}: incomplete "
                            f"context comparison")
            continue
        if res.verdict != "strong_candidate":
            # tested, no authorization gap observed (§45)
            coverage.record("authz", "tested_negative",
                            f"{ep.normalized_url}: {res.notes}")
            if has_idor_params(ep):
                coverage.record("idor", "tested_negative",
                                ep.normalized_url)
            continue
        metrics.differential_candidates += 1
        metrics.authorization_confirmed += 1
        controls.noted()
        is_bola = "BOLA" in res.notes
        coverage.record("bola" if is_bola else "authz", "candidate",
                        res.notes)
        coverage.record("idor", "candidate", res.notes)
        f = Finding(
            id=stable_finding_id("diff", ep.normalized_url),
            source="differential",
            name=("BOLA/IDOR: identical access for two users "
                  f"({ep.path})" if is_bola
                  else f"Broken access control on {ep.path}"),
            severity="high",
            confidence=Confidence.PROBABLE.value,
            validation_status=ValidationStatus.STRONG_CANDIDATE.value,
            host=ep.host,
            matched_at=ep.url,
            endpoint_url=ep.url,
            method=ep.method,
            description=res.notes,
            tags=["bola", "idor", "authz", ep.endpoint_type],
            raw={"contexts": [vars(c) for c in res.contexts],
                 "endpoint_type": ep.endpoint_type,
                 "confirmed": bool(getattr(res, "confirmed", False)),
                 "confirmation_notes": getattr(
                     res, "confirmation_notes", "")},
            false_positive_notes=(
                "Responses compared across auth contexts; volatile "
                "keys (csrf/token/timestamp/nonce) excluded; length "
                "bucketed to 1KB."),
            identity="+".join(authed),
            tenant="+".join(sorted({tenant_of.get(a, "")
                                    for a in authed} - {""})),
        )
        evidence.allocate(f)
        evidence.record(
            f,
            request_text=(
                "GET " + ep.url + "\n--- per-context results ---\n" +
                "\n".join(f"{c.name}: HTTP {c.status} "
                          f"(len={c.length}, shape={c.key_shape[:60] or 'n/a'}, "
                          f"hash={c.body_hash}, "
                          f"ct={getattr(c, 'content_type', '') or 'n/a'}, "
                          f"{getattr(c, 'elapsed_ms', 0.0):.0f}ms"
                          f"{', sig=' + getattr(c, 'error_signature', '') if getattr(c, 'error_signature', '') else ''})"
                          for c in res.contexts)),
            response_text=res.notes)
        findings.append(f)
    return findings
