"""GraphQL operation replay (read side; mutations never replay)."""
from typing import List

from ...budgets import BudgetExceeded
from ...logging_setup import get_logger
from ...models import (Confidence, Finding, ValidationStatus,
                       stable_finding_id)
from ...reporting.coverage import CoverageTracker
from ...validation.evidence import EvidenceStore
from ...reporting.metrics import Metrics
from ...authorization.graphql_replay import replay_operations
from ...validation.graphql import (is_mutation_operation,
                                   parse_graphql_body)
from . import ProbeControls

log = get_logger("stages-validation")


def authz_graphql_probe(endpoints, pool, identities,
                        owner_headers, evidence: EvidenceStore,
                        metrics: Metrics, coverage: CoverageTracker,
                        client, matrix, cfg, scope,
                        controls: ProbeControls) -> List[Finding]:
    """Replay observed query operations with victim variables."""
    cfg_a = cfg.authorization
    findings: List[Finding] = []
    gql_targets = []
    for ep in endpoints or []:
        if len(gql_targets) >= cfg_a.max_endpoints:
            break
        if not scope.active_test_allowed(ep.url):
            continue
        for shape in list(getattr(ep, "observed_requests", [])
                          or []):
            if not isinstance(shape, dict):
                continue
            if str(shape.get("method") or "").upper() != "POST":
                continue
            parsed = parse_graphql_body(shape.get("post_data"))
            if parsed is None or is_mutation_operation(
                    parsed["query"]):
                continue
            gql_targets.append(ep)
            break
    if not gql_targets:
        log.info("authz-graphql: no observed GraphQL query operations "
                 "— nothing to replay")
    for ep in gql_targets:
        if controls.halted():
            log.info("authz-graphql: halted by stop control")
            break
        controls.paced()
        for tester in identities or []:
            tester_name = getattr(tester, "name", "anonymous")
            victims = [h for h in pool
                       if getattr(h, "source", "response") == "response"
                       and getattr(h, "owner", "") not in
                       ("", tester_name)]
            if not victims:
                continue
            try:
                results = replay_operations(
                    client, ep, victims, tester, owner_headers,
                    timeout=cfg.scan.http_timeout,
                    max_ids=cfg_a.max_ids_per_endpoint,
                    scope=scope, matrix=matrix,
                    ownership_fields=list(
                        cfg_a.ownership_fields or []))
            except BudgetExceeded:
                coverage.record("authz", "blocked",
                                f"budget: {ep.normalized_url}")
                break
            for res in results:
                metrics.authorization_tests += 1
                cross_tenant = bool(
                    res.tester_tenant and res.owner_tenant and
                    res.tester_tenant != res.owner_tenant)
                if getattr(res, "edge_denied", False):
                    coverage.record(
                        "tenant_isolation" if cross_tenant
                        else "bola", "inconclusive",
                        f"{ep.normalized_url}::{res.variable}: "
                        f"{tester_name} hit edge infrastructure")
                    continue
                if res.verdict != "strong_candidate":
                    if 400 <= res.status < 500 or res.status == 200:
                        coverage.record(
                            "tenant_isolation" if cross_tenant
                            else "bola", "tested_negative",
                            f"{ep.normalized_url}::{res.variable}: "
                            f"{tester_name}→{res.status}")
                    continue
                metrics.authorization_confirmed += 1
                controls.noted()
                cls = ("tenant_isolation" if cross_tenant else "bola")
                coverage.record(cls, "candidate", res.notes)
                coverage.record("idor", "candidate", res.notes)
                kind_label = "Cross-tenant GraphQL read" \
                    if cross_tenant else "GraphQL BOLA"
                f = Finding(
                    id=stable_finding_id(
                        "graphql", res.endpoint_url, res.operation,
                        res.variable, res.victim_value),
                    source="graphql-bola",
                    name=(f"{kind_label}: "
                          f"'{res.tester}' reads '{res.owner}''s "
                          f"'{res.variable}={res.victim_value}' "
                          f"({ep.path})"),
                    severity="high",
                    confidence=Confidence.PROBABLE.value,
                    validation_status=ValidationStatus.
                    STRONG_CANDIDATE.value,
                    host=ep.host, matched_at=res.endpoint_url,
                    endpoint_url=res.endpoint_url, method="POST",
                    parameter=res.variable,
                    description=res.notes,
                    tags=["bola", "idor", "authz", "graphql",
                          "tenant-isolation" if cross_tenant else
                          "cross-user", ep.endpoint_type],
                    raw={"graphql": res.to_dict()},
                    false_positive_notes=(
                        "Victim variable harvested from the owner's own "
                        "session; the same observed operation document "
                        "replayed with only that variable swapped. "
                        "Mutation operations are never replayed. "
                        "Confirm interactively before reporting."),
                    identity=res.tester, tenant=res.tester_tenant,
                    resource_key=(f"{ep.normalized_url}::"
                                  f"{res.variable}={res.victim_value}"),
                )
                evidence.allocate(f)
                evidence.record(
                    f,
                    request_text=(f"POST {res.endpoint_url}\n"
                                  f"operation {res.operation}\n(as "
                                  f"{res.tester}; owner: {res.owner})"),
                    response_text=res.notes)
                findings.append(f)
                log.info("authz-graphql: %s", res.notes)
    return findings
