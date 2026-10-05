"""File-upload workflow probe (opt-in: persists files server-side)."""
from typing import List

from ...budgets import BudgetExceeded, BudgetTracker
from ...logging_setup import get_logger
from ...models import (Confidence, Endpoint, Finding, ValidationStatus,
                       stable_finding_id)
from ...reporting.coverage import CoverageTracker
from ...validation.evidence import EvidenceStore
from ...reporting.metrics import Metrics
from ...safety.preflight import plan_upload
from ...validation.upload import probe_upload
from . import ProbeControls, reserve_or_block

log = get_logger("stages-validation")


def upload_probe(endpoints: List[Endpoint],
                 evidence: EvidenceStore, metrics: Metrics,
                 budgets: BudgetTracker,
                 coverage: CoverageTracker, client, cfg, scope,
                 controls: ProbeControls) -> List[Finding]:
    targets = [e for e in endpoints or []
               if getattr(e, "endpoint_type", "") == "upload"
               and scope.active_test_allowed(e.url)]
    targets = targets[:max(0, cfg.validation.upload_max_endpoints)]
    if not targets:
        log.info("upload: no in-scope upload endpoints — nothing "
                 "to probe")
        return []
    log.info("upload: probing %d endpoints (inert content only)",
             len(targets))
    if not reserve_or_block(budgets, coverage, "upload",
                            plan_upload(len(targets))):
        return []
    findings: List[Finding] = []
    for ep in targets:
        if controls.halted():
            log.info("upload: halted by stop control")
            break
        if not budgets.consume_test("upload", ep.normalized_url,
                                    limit=3):
            coverage.record("upload", "blocked",
                            f"budget: {ep.normalized_url}")
            continue
        field = next((p.name for p in
                      list(ep.body_parameters or []) if p.name),
                     "file")
        try:
            results = probe_upload(
                client, ep.url, field,
                timeout=cfg.scan.http_timeout)
        except BudgetExceeded:
            coverage.record("upload", "blocked",
                            f"budget: {ep.normalized_url}")
            continue
        for res in results:
            if res.verdict == "candidate":
                controls.noted()
                coverage.record("upload", "candidate",
                                f"{ep.normalized_url}::{res.variant}: "
                                f"{res.notes}")
                f = Finding(
                    id=stable_finding_id("upload", ep.normalized_url,
                                         res.variant),
                    source="upload-probe",
                    name=(f"Unsafe upload handling: {res.variant} "
                          f"accepted ({ep.path})"),
                    severity="medium",
                    confidence=Confidence.PROBABLE.value,
                    validation_status=ValidationStatus.
                    STRONG_CANDIDATE.value,
                    host=ep.host, matched_at=ep.url,
                    endpoint_url=ep.url, method="POST",
                    description=res.notes,
                    tags=["upload", "file-upload", ep.endpoint_type],
                    raw={"upload": res.to_dict()},
                    false_positive_notes=(
                        "Probe content was inert text; execution was "
                        "never attempted. Confirm how the stored file "
                        "is served (content type, path, executability) "
                        "before reporting."),
                )
                evidence.allocate(f)
                evidence.record(
                    f,
                    request_text=(f"POST {ep.url}\nmultipart field "
                                  f"{field}, filename {res.filename} "
                                  f"(inert text content)"),
                    response_text=(
                        f"{res.notes}\nHTTP {res.status}"
                        + (f"\nserved: {res.served_url} "
                           f"({res.served_content_type})"
                           if res.served_url else "")))
                findings.append(f)
                log.info("upload: %s on %s", res.variant, ep.url)
            elif res.verdict in ("rejected", "safe"):
                coverage.record("upload", "tested_negative",
                                f"{ep.normalized_url}::{res.variant}: "
                                f"{res.notes}")
            else:
                coverage.record("upload", "inconclusive",
                                f"{ep.normalized_url}::{res.variant}: "
                                f"{res.notes}")
    return findings
