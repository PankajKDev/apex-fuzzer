"""Passive misconfiguration sweep (read-only GETs, informational)."""
from typing import List

from ...budgets import BudgetExceeded, BudgetTracker
from ...logging_setup import get_logger
from ...models import (Confidence, Endpoint, Finding, ValidationStatus,
                       stable_finding_id)
from ...reporting.coverage import CoverageTracker
from ...validation.evidence import EvidenceStore
from ...reporting.metrics import Metrics
from ...safety.preflight import plan_misconfig
from ...validation.misconfig import (check_clickjacking,
                                     check_csrf_forms)
from . import ProbeControls, reserve_or_block

log = get_logger("stages-validation")

_MAX_ENDPOINTS = 10


def misconfig_probe(endpoints: List[Endpoint],
                    evidence: EvidenceStore, metrics: Metrics,
                    budgets: BudgetTracker,
                    coverage: CoverageTracker, client, cfg, scope,
                    controls: ProbeControls) -> List[Finding]:
    """Flag missing framing protection and tokenless forms.

    Informational candidates only: headers and form shapes prove no
    impact by themselves. Protected pages record genuine negatives.
    """
    targets = [e for e in endpoints or []
               if (getattr(e, "method", "GET") or "GET").upper() == "GET"
               and getattr(e, "endpoint_type", "") == "page"
               and scope.active_test_allowed(e.url)][: _MAX_ENDPOINTS]
    if not targets:
        log.info("misconfig: no in-scope page endpoints — nothing "
                 "to check")
        return []
    if not reserve_or_block(budgets, coverage, "clickjacking",
                            plan_misconfig(len(targets))):
        return []
    findings: List[Finding] = []
    for ep in targets:
        if controls.halted():
            log.info("misconfig: halted by stop control")
            break
        if not budgets.consume_test("clickjacking",
                                    ep.normalized_url, limit=2):
            coverage.record("clickjacking", "blocked",
                            f"budget: {ep.normalized_url}")
            continue
        try:
            r = client.get(ep.url, timeout=cfg.scan.http_timeout)
        except BudgetExceeded:
            coverage.record("clickjacking", "blocked",
                            f"budget: {ep.normalized_url}")
            continue
        except Exception as e:
            log.debug("misconfig fetch failed %s: %s", ep.url, e)
            continue
        headers = dict(getattr(r, "headers", None) or {})
        ctype = ""
        for name, value in headers.items():
            if str(name).lower() == "content-type":
                ctype = str(value or "")
                break
        body = getattr(r, "text", "") or ""
        click = check_clickjacking(headers, ctype, ep.url)
        if click["verdict"] == "candidate":
            controls.noted()
            coverage.record("clickjacking", "candidate",
                            f"{ep.normalized_url}: {click['evidence']}")
            findings.append(_finding(
                ep, "clickjacking", "Clickjacking: no framing protection",
                "info", click["evidence"],
                f"{click['notes']}. Informational: framing alone proves "
                "no impact — confirm a sensitive action is framable "
                "while authenticated before reporting.",
                evidence, {"check": "clickjacking",
                           "evidence": click["evidence"]}))
        elif click["verdict"] == "protected":
            coverage.record("clickjacking", "tested_negative",
                            f"{ep.normalized_url}: {click['evidence']}")
        csrf = check_csrf_forms(body, ep.url)
        if csrf["verdict"] == "candidate":
            controls.noted()
            coverage.record("csrf", "candidate",
                            f"{ep.normalized_url}: {csrf['notes']}")
            findings.append(_finding(
                ep, "csrf", "CSRF: state-changing form without token",
                "info", csrf["notes"],
                f"{csrf['notes']}. Informational: token absence alone "
                "proves no exploitability (SameSite cookies, custom "
                "headers, or server-side checks may still protect). "
                "Prove a state change cross-site before reporting.",
                evidence, {"check": "csrf",
                           "forms": [{"action": f.action,
                                      "method": f.method,
                                      "inputs": [i["name"] for i in
                                                 f.inputs]}
                                     for f in csrf["forms"]]}))
        elif csrf["verdict"] == "protected":
            coverage.record("csrf", "tested_negative",
                            f"{ep.normalized_url}: {csrf['notes']}")
    return findings


def _finding(ep, source: str, name: str, severity: str, notes: str,
             fp_notes: str, evidence, raw: dict) -> Finding:
    f = Finding(
        id=stable_finding_id("misconfig", source, ep.normalized_url),
        source=f"misconfig-{source}",
        name=f"{name} ({ep.path})",
        severity=severity,
        confidence=Confidence.POSSIBLE.value,
        validation_status=ValidationStatus.STRONG_CANDIDATE.value,
        host=ep.host, matched_at=ep.url,
        endpoint_url=ep.url, method="GET",
        description=notes,
        tags=[source, "misconfiguration", ep.endpoint_type,
              "informational"],
        raw=raw,
        false_positive_notes=fp_notes,
    )
    evidence.allocate(f)
    evidence.record(f, request_text=f"GET {ep.url}",
                    response_text=notes[:2000])
    log.info("misconfig: %s on %s", source, ep.url)
    return f
