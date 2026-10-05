"""OAST blind-SSRF sweep (per-request callback nonces)."""
from pathlib import Path
from typing import List

from ...budgets import BudgetExceeded, BudgetTracker
from ...logging_setup import get_logger
from ...models import (Confidence, Endpoint, Finding, ValidationStatus,
                       stable_finding_id)
from ...reporting.coverage import CoverageTracker
from ...validation.evidence import EvidenceStore
from ...reporting.metrics import Metrics
from ...safety.preflight import plan_oast
from ...validation.oast import (probe_endpoint, ssrf_candidate_score,
                                ssrf_candidates)
from ...validation.evidence import interaction_line
from . import ProbeControls, reserve_or_block

log = get_logger("stages-validation")

_OAST_PRIORITY_TYPES = ("proxy", "webhook", "callback", "import",
                        "export", "download", "upload", "api")


def oast_sweep(endpoints: List[Endpoint],
               provider,
               evidence: EvidenceStore, metrics: Metrics,
               client, out_dir: Path,
               budgets: BudgetTracker,
               coverage: CoverageTracker, cfg, scope,
               controls: ProbeControls) -> List[Finding]:
    _ = out_dir  # reserved: provider state already lives on the provider
    ranked_targets = []
    for endpoint in endpoints:
        if (endpoint.endpoint_type == "static" or
                not scope.active_test_allowed(endpoint.url)):
            continue
        parameters = (list(endpoint.query_parameters) +
                      list(endpoint.body_parameters) +
                      list(endpoint.header_parameters))
        candidates = ssrf_candidates(parameters, endpoint)
        if not candidates:
            continue
        field_score = max(ssrf_candidate_score(p, endpoint)[0]
                          for p in candidates)
        route_bonus = int(endpoint.endpoint_type in
                          _OAST_PRIORITY_TYPES)
        ranked_targets.append((field_score + route_bonus, endpoint))
    ranked_targets.sort(key=lambda row: (-row[0], row[1].url))
    targets = [endpoint for _, endpoint in ranked_targets][:
               cfg.oast.max_endpoints]
    if not targets:
        log.info("oast: no SSRF-suspect endpoints discovered — "
                 "nothing to sweep")
        return []
    log.info("oast: sweeping %d SSRF-suspect endpoints",
             len(targets))
    if not reserve_or_block(
            budgets, coverage, "ssrf",
            plan_oast(len(targets),
                      cfg.oast.max_params_per_endpoint)):
        return []
    findings: List[Finding] = []
    for ep in targets:
        if controls.halted():
            log.info("oast: halted by stop control; "
                     "remaining targets stay untested")
            break
        if not budgets.consume_test(
                "ssrf", ep.normalized_url,
                limit=cfg.oast.max_endpoints):
            coverage.record("ssrf", "blocked",
                            f"budget: {ep.normalized_url}")
            continue
        try:
            res = probe_endpoint(
                client, ep, provider,
                poll_timeout=cfg.oast.poll_timeout,
                poll_interval=cfg.oast.poll_interval,
                max_params=cfg.oast.max_params_per_endpoint)
        except BudgetExceeded:
            coverage.record("ssrf", "blocked",
                            f"budget: {ep.normalized_url}")
            continue
        metrics.oast_endpoints_probed += 1
        if res is None or not res.confirmed:
            detail = (res.notes if res else "no probe was sent")
            coverage.record(
                "ssrf", "inconclusive",
                f"{ep.normalized_url}: no correlated callback; {detail}")
            continue
        metrics.oast_confirmed += 1
        controls.noted()
        coverage.record("ssrf", "confirmed",
                        f"OAST callback on '{res.parameter}'")
        bypass_suffix = (f" through parser-bypass variant "
                         f"({res.bypass_kind})" if res.bypass_kind
                         else "")
        reflects_note = (" The target response reflects the callback "
                         "token (possible full-read: confirm manually; "
                         "callback-grade proof, not data access)."
                         if res.response_reflects_token else "")
        f = Finding(
            id=stable_finding_id("oast", ep.normalized_url),
            source="oast-sweep",
            name=(f"Blind SSRF confirmed via OAST on "
                  f"'{res.parameter}' ({ep.path})"),
            severity="medium",
            confidence=Confidence.CONFIRMED.value,
            validation_status=ValidationStatus.CONFIRMED.value,
            host=ep.host,
            matched_at=ep.url,
            endpoint_url=ep.url,
            method=ep.method,
            parameter=res.parameter,
            description=(
                "The server fetched our unique out-of-band Interactsh "
                f"callback on parameter '{res.parameter}' "
                f"using {res.payload}.{bypass_suffix}{reflects_note}"),
            tags=["ssrf", "oast", ep.endpoint_type]
            + (["ssrf-bypass"] if res.bypass_kind else [])
            + (["ssrf-reflects-token"]
               if res.response_reflects_token else []),
            raw={"interactions": res.interactions[:10],
                 "callback_host": res.callback_host,
                 "request_method": res.request_method,
                 "request_url": res.request_url,
                 "parameter_location": res.parameter_location,
                 "response_status": res.response_status,
                 "response_length": res.response_length,
                 "response_time_ms": res.response_time_ms,
                 "bypass_kind": res.bypass_kind,
                 "response_reflects_token":
                     res.response_reflects_token},
            false_positive_notes=(
                "Confirmed via unique out-of-band Interactsh "
                "callback (DNS/HTTP/SMTP), not response shape. "
                "Unique callback host per request eliminates cross-probe "
                "correlation."
                + (" A reflected token is a full-read signal, not "
                   "proof of internal data access."
                   if res.response_reflects_token else "")),
            identity="anonymous",
        )
        evidence.allocate(f)
        evidence.record(
            f,
            request_text=(f"{res.request_method} {res.request_url}\n"
                          f"{res.parameter_location}::{res.parameter}="
                          f"{res.payload or ''}"),
            response_text="\n".join(
                interaction_line(i) for i in res.interactions[:10]))
        findings.append(f)
        log.info("oast: CONFIRMED SSRF on %s param=%s",
                 ep.url, res.parameter)
        return findings
