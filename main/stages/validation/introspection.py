"""GraphQL introspection-exposure probe (schema disclosure)."""
from typing import List

from ...budgets import BudgetExceeded, BudgetTracker
from ...logging_setup import get_logger
from ...models import (Confidence, Endpoint, Finding, ValidationStatus,
                       stable_finding_id)
from ...reporting.coverage import CoverageTracker
from ...validation.evidence import EvidenceStore
from ...reporting.metrics import Metrics
from ...safety.preflight import plan_graphql_introspection
from ...validation.graphql_introspection import (
    _MAX_ENDPOINTS, probe_introspection)
from . import ProbeControls, reserve_or_block

log = get_logger("stages-validation")


def graphql_introspection_probe(endpoints: List[Endpoint],
                                evidence: EvidenceStore,
                                metrics: Metrics,
                                budgets: BudgetTracker,
                                coverage: CoverageTracker,
                                client, cfg, scope,
                                controls: ProbeControls
                                ) -> List[Finding]:
    """Probe GraphQL endpoints for enabled __schema introspection.

    One minimal document per endpoint (type inventory only). POST
    endpoints go through the state-change gate like any mutating
    method — introspection is read-only by contract, but the gate
    cannot prove that, so POST needs --ack-state-change.
    """
    targets = [e for e in endpoints or []
               if getattr(e, "endpoint_type", "") == "graphql"]
    targets = targets[:_MAX_ENDPOINTS]
    if not targets:
        log.info("graphql-introspection: no GraphQL endpoints "
                 "discovered — nothing to probe")
        return []
    if not reserve_or_block(
            budgets, coverage, "graphql",
            plan_graphql_introspection(len(targets))):
        return []
    findings: List[Finding] = []
    for ep in targets:
        if controls.halted():
            log.info("graphql-introspection: halted by stop control")
            break
        if not scope.active_test_allowed(ep.url):
            continue
        if not budgets.consume_test(
                "graphql", ep.normalized_url, limit=2):
            coverage.record("graphql", "blocked",
                            f"budget: {ep.normalized_url}")
            continue
        try:
            res = probe_introspection(
                client, ep.url, ep.method or "GET",
                timeout=cfg.scan.http_timeout)
        except BudgetExceeded:
            coverage.record("graphql", "blocked",
                            f"budget: {ep.normalized_url}")
            continue
        if res.exposed is None:
            coverage.record("graphql", "inconclusive",
                            f"{ep.normalized_url}: {res.notes}")
            continue
        if not res.exposed:
            coverage.record("graphql", "tested_negative",
                            f"{ep.normalized_url}: {res.notes}")
            continue
        controls.noted()
        coverage.record("graphql", "candidate", res.notes)
        coverage.record("info_disclosure", "candidate", res.notes)
        f = Finding(
            id=stable_finding_id("graphql-intro",
                                 ep.normalized_url),
            source="graphql-introspection",
            name=(f"GraphQL introspection enabled "
                  f"({len(res.types)} types disclosed, {ep.path})"),
            severity="low",
            confidence=Confidence.PROBABLE.value,
            validation_status=ValidationStatus.
            STRONG_CANDIDATE.value,
            host=ep.host, matched_at=ep.url,
            endpoint_url=ep.url, method=(ep.method or "GET"),
            description=res.notes,
            tags=["graphql", "info_disclosure",
                  ep.endpoint_type],
            raw={"types": res.types, "method": res.method,
                 "status": res.status},
            false_positive_notes=(
                "Schema exposure alone is not a vulnerability: "
                "assess whether disclosed types/fields reveal "
                "non-public operations or data before reporting. "
                "Some frameworks scope introspection per role — "
                "compare authenticated vs anonymous answers by hand."),
        )
        evidence.allocate(f)
        evidence.record(
            f,
            request_text=(f"{res.method} {ep.url}\n"
                          f"introspection document (type inventory)"),
            response_text=res.notes)
        findings.append(f)
        log.info("graphql-introspection: %s", res.notes)
    return findings
