"""Lead-independent prescreen sweep (mutation prescreens, no Nuclei)."""
from typing import List

from ...budgets import BudgetExceeded, BudgetTracker
from ...logging_setup import get_logger
from ...models import (Confidence, Endpoint, Finding, ValidationStatus,
                       stable_finding_id)
from ...reporting.coverage import CoverageTracker, classify_finding
from ...validation.evidence import EvidenceStore
from ...reporting.metrics import Metrics
from ...safety.preflight import plan_prescreen
from ...validation.base import Candidate
from ...validation.differential import IDOR_PARAM_NAMES, has_idor_params
from ...validation.mutate import MutationEngine
from ...discovery.url_normalizer import normalize_url
from . import ProbeControls, reserve_or_block

log = get_logger("stages-validation")


def prescreen_sweep(endpoints: List[Endpoint],
                    findings: List[Finding],
                    evidence: EvidenceStore, metrics: Metrics,
                    budgets: BudgetTracker,
                    coverage: CoverageTracker, client,
                    cfg, scope, controls: ProbeControls,
                    waf=None, reviews=None
                    ) -> List[Finding]:
    """Probe endpoint parameters with the mutation prescreens directly.

    Nuclei misses an endpoint and the deep validators never run: this
    sweep closes that lead dependency for SQLi/XSS prescreens only
    (no heavy tools, no delays). Hits become findings so the plugin
    loop below can drive sqlmap/dalfox confirmation. Silence records
    nothing: a prescreen miss is not a negative. Triples marked
    false-positive in reviews.jsonl are skipped as untestable.
    """
    cfg_v = cfg.validation
    max_eps = max(0, int(getattr(cfg_v, "prescreen_max_endpoints",
                                 30)))
    max_params = max(0, int(getattr(cfg_v, "prescreen_max_params", 3)))
    if max_eps == 0 or max_params == 0:
        return []

    def _params_of(ep):
        out = []
        for src, loc in ((ep.query_parameters, "query"),
                         (ep.body_parameters, "body"),
                         (ep.header_parameters, "header")):
            for item in list(src or []):
                name = getattr(item, "name", "")
                if name and (name, loc) not in out:
                    out.append((name, loc))
        idorish = [pair for pair in out
                   if pair[0].lower() in IDOR_PARAM_NAMES]
        rest = [pair for pair in out if pair not in idorish]
        return (idorish + rest)[:max_params]

    candidates = []
    for ep in endpoints or []:
        if ep.endpoint_type == "static":
            continue
        if not scope.active_test_allowed(ep.url):
            continue
        pairs = _params_of(ep)
        if pairs:
            candidates.append((ep, pairs))
    candidates.sort(key=lambda row: (
        0 if has_idor_params(row[0]) else 1, row[0].url))
    candidates = candidates[:max_eps]
    if not candidates:
        log.info("prescreen-sweep: no endpoints with parameters "
                 "discovered — nothing to probe")
        return []
    log.info("prescreen-sweep: %d endpoints", len(candidates))
    if not reserve_or_block(
            budgets, coverage, "prescreen",
            plan_prescreen(len(candidates), max_params)):
        return []

    covered = set()
    for f in findings or []:
        try:
            covered.add((classify_finding(f),
                         normalize_url(f.endpoint_url or
                                       f.matched_at or ""),
                         f.parameter or ""))
        except Exception:
            continue
    engine = MutationEngine(cfg, client, waf)
    new_findings: List[Finding] = []
    for ep, pairs in candidates:
        if controls.halted():
            log.info("prescreen-sweep: halted by stop control")
            break
        controls.paced()
        content_types = list(
            getattr(ep, "request_content_types", []) or [])
        content_type = ((content_types[0] if content_types else "")
                        or getattr(ep, "content_type", ""))
        for name, location in pairs:
            for test_class in ("sqli", "xss"):
                if (test_class, ep.normalized_url, name) in covered:
                    continue
                if reviews is not None and reviews.is_fp_triple(
                        test_class, ep.normalized_url, name):
                    coverage.mark_untestable(
                        test_class,
                        f"operator-marked false positive: "
                        f"{ep.normalized_url}::{name}")
                    log.info("prescreen-sweep: skipping %s (marked "
                             "false positive in reviews.jsonl)",
                             f"{ep.normalized_url}::{name}")
                    continue
                candidate = Candidate(
                    finding=Finding(id="probe", source="prescreen"),
                    test_class=test_class, endpoint_url=ep.url,
                    method=ep.method or "GET", parameter=name,
                    parameter_location=location,
                    request_content_type=content_type,
                    body_parameters=list(ep.body_parameters or []))
                try:
                    if test_class == "sqli":
                        outcome = engine.prescreen_sqli(candidate)
                    else:
                        outcome = engine.prescreen_xss(candidate)
                except BudgetExceeded:
                    coverage.record(test_class, "blocked",
                                    f"budget: {ep.normalized_url}")
                    break
                if outcome is None or outcome.status not in (
                        ValidationStatus.STRONG_CANDIDATE.value,):
                    continue
                metrics.validation_candidates += 1
                controls.noted()
                coverage.record(test_class, "candidate",
                                outcome.notes or "")
                covered.add((test_class, ep.normalized_url, name))
                f = Finding(
                    id=stable_finding_id(f"prescreen-{test_class}",
                                         ep.normalized_url, name),
                    source=f"prescreen-{test_class}",
                    name=(f"{'SQLi' if test_class == 'sqli' else 'XSS'} "
                          f"prescreen hit on '{name}' ({ep.path})"),
                    severity="medium",
                    confidence=Confidence.PROBABLE.value,
                    validation_status=ValidationStatus.
                    STRONG_CANDIDATE.value,
                    host=ep.host, matched_at=ep.url,
                    endpoint_url=ep.url, method=candidate.method,
                    parameter=name,
                    description=(outcome.notes or "") + " Lead-"
                                    "independent prescreen signal; "
                                    "requires independent validation.",
                    tags=[test_class, "prescreen", ep.endpoint_type],
                    raw={"prescreen": dict(outcome.evidence or {})},
                    false_positive_notes=(
                        "Prescreen-level signal only (boolean "
                        "differential or reflection/error marker). "
                        "Confirm with the follow-up validators before "
                        "reporting."),
                )
                evidence.allocate(f)
                evidence.record(
                    f,
                    request_text=(
                        f"{candidate.method} {ep.url}\n{location}::"
                        f"{name}"),
                    response_text=(outcome.notes or "")[:2000])
                new_findings.append(f)
                log.info("prescreen-sweep: %s %s on %s", test_class,
                         name, ep.url)
    return new_findings
