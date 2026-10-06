"""Passive misconfiguration sweep (read-only GETs, informational)."""
from typing import List

from ...budgets import BudgetExceeded, BudgetTracker
from ...logging_setup import get_logger
from ...models import (Confidence, Endpoint, Finding, ValidationStatus,
                       stable_finding_id)
from ...reporting.coverage import CoverageTracker
from ...validation.evidence import EvidenceStore
from ...reporting.metrics import Metrics
from ...safety.preflight import (plan_hpp, plan_info,
                                  plan_misconfig)
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
             fp_notes: str, evidence, raw: dict,
             extra_tags=()) -> Finding:
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
              "informational"] + list(extra_tags),
        raw=raw,
        false_positive_notes=fp_notes,
    )
    evidence.allocate(f)
    evidence.record(f, request_text=f"GET {ep.url}",
                    response_text=notes[:2000])
    log.info("misconfig: %s on %s", source, ep.url)
    return f


_MAX_HEADER_ENDPOINTS = 10
_MAX_HEADER_PARAMS = 3


def header_probe(endpoints: List[Endpoint],
                 evidence: EvidenceStore, metrics: Metrics,
                 budgets: BudgetTracker,
                 coverage: CoverageTracker, client, cfg, scope,
                 controls: ProbeControls) -> List[Finding]:
    """Host-override and CRLF checks over query-bearing endpoints."""
    from ...validation.header_probe import (
        check_crlf, check_host_override, query_param_names)
    from ...safety.preflight import plan_header
    targets = [e for e in endpoints or []
               if (getattr(e, "method", "GET") or "GET").upper() == "GET"
               and query_param_names(getattr(e, "url", "") or "")
               and scope.active_test_allowed(e.url)][: _MAX_HEADER_ENDPOINTS]
    if not targets:
        log.info("header-probe: no in-scope parameterized GET "
                 "endpoints — nothing to check")
        return []
    if not reserve_or_block(
            budgets, coverage, "host_header",
            plan_header(len(targets), _MAX_HEADER_PARAMS)):
        return []
    findings: List[Finding] = []
    for ep in targets:
        if controls.halted():
            log.info("header-probe: halted by stop control")
            break
        params = query_param_names(ep.url)[:_MAX_HEADER_PARAMS]
        if not budgets.consume_test("host_header", ep.normalized_url,
                                    limit=2 + _MAX_HEADER_PARAMS):
            coverage.record("host_header", "blocked",
                            f"budget: {ep.normalized_url}")
            continue
        try:
            host_res = check_host_override(
                client, ep.url, timeout=cfg.scan.http_timeout)
        except BudgetExceeded:
            coverage.record("host_header", "blocked",
                            f"budget: {ep.normalized_url}")
            continue
        if host_res.verdict == "candidate":
            controls.noted()
            coverage.record("host_header", "candidate",
                            f"{ep.normalized_url}: {host_res.notes}")
            findings.append(_finding(
                ep, "host-header",
                "Host-dependent redirect", "medium",
                host_res.notes,
                f"{host_res.notes}. A redirect target derived from a "
                f"client-controlled Host header enables phishing and "
                f"password-reset poisoning chains. Confirm the redirect "
                f"is reachable cross-context before reporting.",
                evidence, {"check": "host-override",
                           "evidence": host_res.evidence}))
        elif host_res.verdict == "negative":
            coverage.record("host_header", "tested_negative",
                            f"{ep.normalized_url}: {host_res.notes}")
        else:
            coverage.record("host_header", "inconclusive",
                            f"{ep.normalized_url}: {host_res.notes}")
        for param in params:
            try:
                crlf = check_crlf(client, ep.url, param,
                                  timeout=cfg.scan.http_timeout)
            except BudgetExceeded:
                coverage.record("header_injection", "blocked",
                                f"budget: {ep.normalized_url}")
                break
            if crlf.verdict == "candidate":
                controls.noted()
                coverage.record("header_injection", "candidate",
                                f"{ep.normalized_url}::{param}: "
                                f"{crlf.notes}")
                findings.append(_finding(
                    ep, "crlf",
                    "CRLF response splitting", "medium",
                    crlf.notes,
                    f"{crlf.notes}. A split header enables cache "
                    f"poisoning and reflected XSS chains. Confirm the "
                    f"header survives to the client (no proxy "
                    f"sanitization) before reporting.",
                    evidence, {"check": "crlf",
                               "evidence": crlf.evidence}))
            elif crlf.verdict == "negative":
                coverage.record("header_injection", "tested_negative",
                                f"{ep.normalized_url}::{param}")
            else:
                coverage.record("header_injection", "inconclusive",
                                f"{ep.normalized_url}::{param}: "
                                f"{crlf.notes}")
    return findings


_MAX_INFO_ENDPOINTS = 10


def info_disclosure_probe(endpoints: List[Endpoint],
                          evidence: EvidenceStore, metrics: Metrics,
                          budgets: BudgetTracker,
                          coverage: CoverageTracker, client, cfg, scope,
                          controls: ProbeControls) -> List[Finding]:
    """Version banners plus 404-handler error disclosure.

    Read-only GETs only (endpoint fetch + one nonexistent child
    path). Informational candidates; bodies are never persisted.
    """
    from ...validation.info_disclosure import (
        check_disclosing_headers, check_verbose_error,
        not_found_child)
    targets = [e for e in endpoints or []
               if (getattr(e, "method", "GET") or "GET").upper() == "GET"
               and getattr(e, "endpoint_type", "") in
               ("page", "api", "unknown")
               and scope.active_test_allowed(e.url)][: _MAX_INFO_ENDPOINTS]
    if not targets:
        log.info("info-disclosure: no in-scope GET endpoints — "
                 "nothing to check")
        return []
    if not reserve_or_block(
            budgets, coverage, "info_disclosure",
            plan_info(len(targets))):
        return []
    findings: List[Finding] = []
    for ep in targets:
        if controls.halted():
            log.info("info-disclosure: halted by stop control")
            break
        if not budgets.consume_test("info_disclosure",
                                    ep.normalized_url, limit=2):
            coverage.record("info_disclosure", "blocked",
                            f"budget: {ep.normalized_url}")
            continue
        try:
            r = client.get(ep.url, timeout=cfg.scan.http_timeout)
        except BudgetExceeded:
            coverage.record("info_disclosure", "blocked",
                            f"budget: {ep.normalized_url}")
            continue
        except Exception as e:
            log.debug("info-disclosure fetch failed %s: %s", ep.url, e)
            coverage.record("info_disclosure", "inconclusive",
                            f"{ep.normalized_url}: fetch failed")
            continue
        headers = dict(getattr(r, "headers", None) or {})
        hdrs = check_disclosing_headers(headers)
        if hdrs["verdict"] == "candidate":
            controls.noted()
            coverage.record("info_disclosure", "candidate",
                            f"{ep.normalized_url}: {hdrs['notes']}")
            findings.append(_finding(
                ep, "info-headers",
                "Information disclosure: version banner",
                "info", hdrs["notes"],
                f"{hdrs['notes']}. Informational: banners aid "
                f"fingerprinting but prove no exploitability. "
                f"Confirm the version is actually outdated and "
                f"reachable before reporting.",
                evidence, {"check": "disclosing-headers",
                           "evidence": hdrs["disclosures"]},
                ["info_disclosure"]))
        else:
            coverage.record("info_disclosure", "tested_negative",
                            f"{ep.normalized_url}: {hdrs['notes']}")
        child = not_found_child(ep.url)
        if child is None or not scope.active_test_allowed(child):
            coverage.record("info_disclosure", "inconclusive",
                            f"{ep.normalized_url}: 404 probe unusable")
            continue
        try:
            r404 = client.get(child, timeout=cfg.scan.http_timeout)
        except BudgetExceeded:
            coverage.record("info_disclosure", "blocked",
                            f"budget: {ep.normalized_url}")
            continue
        except Exception as e:
            log.debug("info-disclosure 404 probe failed %s: %s",
                      child, e)
            coverage.record("info_disclosure", "inconclusive",
                            f"{ep.normalized_url}: 404 probe failed")
            continue
        err = check_verbose_error(
            getattr(r404, "text", "") or "")
        if err["verdict"] == "candidate":
            controls.noted()
            coverage.record("info_disclosure", "candidate",
                            f"{ep.normalized_url}: {err['notes']}")
            findings.append(_finding(
                ep, "info-error",
                "Information disclosure: verbose error page",
                "info", err["notes"],
                f"{err['notes']}. Informational: error text aids "
                f"fingerprinting but proves no exploitability. "
                f"Confirm the trace reaches attacker-influenced "
                f"input before reporting.",
                evidence, {"check": "verbose-error",
                           "evidence": err["family"]},
                ["info_disclosure"]))
        else:
            coverage.record("info_disclosure", "tested_negative",
                            f"{ep.normalized_url}: {err['notes']}")
    return findings


_MAX_HPP_ENDPOINTS = 10
_MAX_HPP_PARAMS = 3


def csrf_browser_probe(csrf_findings, evidence: EvidenceStore,
                       metrics: Metrics, budgets: BudgetTracker,
                       coverage: CoverageTracker, client, cfg, scope,
                       controls: ProbeControls,
                       identities) -> List[Finding]:
    """Prove tokenless forms execute cross-site with a victim session.

    Opt-in Chromium proof (validation.csrf_browser + state-change
    ack): a null-origin page auto-submits the observed form shape
    with victim cookies; server acceptance proves execution (a new
    high finding). Denied executions are genuine negatives; anything
    else leaves the tokenless-form candidate standing.
    """
    import importlib.util
    from urllib.parse import urlencode, urljoin, urlsplit
    from ...safety.preflight import plan_csrf
    from ...validation.csrf_browser import prove_csrf_execution
    if not getattr(getattr(cfg, "validation", None),
                   "csrf_browser", False):
        return []
    if not getattr(getattr(cfg, "safety", None),
                   "allow_state_change", False):
        log.info("csrf-proof: needs --ack-state-change (executes a "
                 "state change as the victim session) — skipping")
        return []
    if importlib.util.find_spec("playwright") is None:
        log.info("csrf-proof: playwright not installed — skipping")
        coverage.record("csrf", "untestable",
                        "browser proof needs playwright")
        return []
    victims = [i for i in identities or []
               if getattr(i, "name", "anonymous") != "anonymous"
               and (dict(getattr(i, "auth_headers", None) or {})
                    or str(getattr(i, "storage_state", "") or ""))]
    if not victims:
        log.info("csrf-proof: no authenticated victim identity — "
                 "skipping")
        coverage.record("csrf", "untestable",
                        "browser proof needs a victim session")
        return []
    targets = []
    for finding in csrf_findings or []:
        raw = getattr(finding, "raw", None) or {}
        if isinstance(raw, dict):
            forms = raw.get("forms") or []
        else:
            forms = []
        forms = [f for f in forms if isinstance(f, dict)
                 and str(f.get("method", "GET")).upper()
                 in ("GET", "POST")][:2]
        if forms:
            targets.append((finding, forms))
    max_eps = max(0, int(getattr(cfg.validation, "csrf_max_endpoints",
                                 5)))
    targets = targets[:max_eps]
    if not targets:
        log.info("csrf-proof: no tokenless GET/POST forms — "
                 "nothing to prove")
        return []
    if not reserve_or_block(
            budgets, coverage, "csrf",
            plan_csrf(len(targets))):
        return []
    findings: List[Finding] = []
    victim = victims[0]
    victim_name = getattr(victim, "name", "victim")
    victim_headers = dict(getattr(victim, "auth_headers", None) or {})
    for finding, forms in targets:
        if controls.halted():
            log.info("csrf-proof: halted by stop control")
            break
        base_url = str(getattr(finding, "endpoint_url", "") or
                       getattr(finding, "matched_at", "") or "")
        for form in forms:
            action = urljoin(base_url, str(form.get("action", "") or ""))
            try:
                ok_url = urlsplit(action).scheme.lower() in (
                    "http", "https")
            except ValueError:
                ok_url = False
            if not ok_url or not scope.active_test_allowed(action):
                continue
            method = str(form.get("method", "GET")).upper()
            fields = {str(item.get("name", "")): "1"
                      for item in (form.get("inputs") or [])
                      if isinstance(item, dict) and item.get("name")}
            if not fields:
                coverage.record("csrf", "untestable",
                                f"{action}: form has no named inputs")
                continue
            norm = action.split("?")[0]
            if not budgets.consume_test("csrf", norm, limit=3):
                coverage.record("csrf", "blocked", f"budget: {norm}")
                break
            # Baseline: the shape must work same-origin first.
            try:
                if method == "POST":
                    headers = dict(victim_headers)
                    headers["Content-Type"] = \
                        "application/x-www-form-urlencoded"
                    base = client.post(
                        action, data=urlencode(fields), headers=headers,
                        timeout=cfg.scan.http_timeout)
                else:
                    sep = "&" if urlsplit(action).query else "?"
                    base = client.get(
                        action + sep + urlencode(fields),
                        headers=victim_headers,
                        timeout=cfg.scan.http_timeout)
            except BudgetExceeded:
                coverage.record("csrf", "blocked", f"budget: {norm}")
                break
            except Exception as exc:
                log.debug("csrf-proof baseline failed %s: %s",
                          action, exc)
                coverage.record("csrf", "inconclusive",
                                f"{norm}: baseline failed")
                continue
            if getattr(base, "status_code", 0) != 200:
                coverage.record("csrf", "inconclusive",
                                f"{norm}: same-origin baseline "
                                f"{getattr(base, 'status_code', 0)}")
                continue
            controls.paced()
            proof = prove_csrf_execution(
                action, method, fields, victim, cfg,
                timeout_ms=10000)
            if proof.get("status") == "executed":
                controls.noted()
                coverage.record("csrf", "candidate",
                                f"{norm}: {proof.get('reason')}")
                f = Finding(
                    id=stable_finding_id("csrfexec", norm, method),
                    source="csrf-execution",
                    name=(f"CSRF executes cross-site with victim "
                          f"session ({urlsplit(action).path or '/'})"),
                    severity="high",
                    confidence=Confidence.PROBABLE.value,
                    validation_status=ValidationStatus.
                    STRONG_CANDIDATE.value,
                    host=urlsplit(action).hostname or "",
                    matched_at=action,
                    endpoint_url=action, method=method,
                    description=(f"{proof.get('reason')} "
                                 f"(response {proof.get('response_status')}, "
                                 f"cookie sent, {proof.get('request_count')} "
                                 f"request(s) via "
                                 f"{proof.get('browser')})"),
                    tags=["csrf", "csrf-executed", "session-riding"],
                    raw={"csrf_proof": dict(proof)},
                    false_positive_notes=(
                        "Cross-site execution with the victim session "
                        "was observed in Chromium and the server "
                        "accepted (2xx). Persistence of the state "
                        "change was not verified — confirm the effect "
                        "stuck (re-read as the victim) and that the "
                        "session was genuinely privileged before "
                        "reporting."),
                    identity=victim_name,
                )
                evidence.allocate(f)
                evidence.record(
                    f,
                    request_text=(f"{method} {action}\n(cross-site, "
                                  f"as {victim_name}; fields: "
                                  f"{', '.join(sorted(fields))})"),
                    response_text=str(proof.get("reason") or ""))
                findings.append(f)
                log.info("csrf-proof: %s executes cross-site", norm)
            elif proof.get("status") == "denied":
                coverage.record("csrf", "tested_negative",
                                f"{norm}: {proof.get('reason')}")
            else:
                coverage.record("csrf", "inconclusive",
                                f"{norm}: {proof.get('reason')}")
    return findings


def hpp_probe(endpoints: List[Endpoint],
              evidence: EvidenceStore, metrics: Metrics,
              budgets: BudgetTracker,
              coverage: CoverageTracker, client, cfg, scope,
              controls: ProbeControls) -> List[Finding]:
    """Duplicated-parameter handling over observed GET query fields.

    Read-only GET pairs only. Inconsistent handling is a candidate
    (filter-bypass primitive); identical handling is a genuine
    negative.
    """
    from ...validation.param_pollution import check_hpp, query_params
    targets = [e for e in endpoints or []
               if (getattr(e, "method", "GET") or "GET").upper() == "GET"
               and query_params(getattr(e, "url", "") or "")
               and scope.active_test_allowed(e.url)][: _MAX_HPP_ENDPOINTS]
    if not targets:
        log.info("hpp: no in-scope parameterized GET endpoints — "
                 "nothing to check")
        return []
    if not reserve_or_block(
            budgets, coverage, "parameter_pollution",
            plan_hpp(len(targets), _MAX_HPP_PARAMS)):
        return []
    findings: List[Finding] = []
    for ep in targets:
        if controls.halted():
            log.info("hpp: halted by stop control")
            break
        params = [p for p in query_params(ep.url)
                  if p][: _MAX_HPP_PARAMS]
        if not budgets.consume_test("parameter_pollution",
                                    ep.normalized_url,
                                    limit=1 + 2 * len(params)):
            coverage.record("parameter_pollution", "blocked",
                            f"budget: {ep.normalized_url}")
            continue
        for param in params:
            try:
                res = check_hpp(client, ep.url, param,
                                timeout=cfg.scan.http_timeout)
            except BudgetExceeded:
                coverage.record("parameter_pollution", "blocked",
                                f"budget: {ep.normalized_url}")
                break
            if res.verdict == "candidate":
                controls.noted()
                coverage.record("parameter_pollution", "candidate",
                                f"{ep.normalized_url}::{param}: "
                                f"{res.notes}")
                findings.append(_finding(
                    ep, "hpp",
                    "HTTP Parameter Pollution: inconsistent "
                    "duplicate handling", "medium",
                    res.notes,
                    f"{res.notes}. Inconsistent duplicate handling "
                    f"enables filter and WAF bypass chains. Confirm "
                    f"which occurrence wins server-side and whether "
                    f"a security control can be bypassed before "
                    f"reporting.",
                    evidence, {"check": "hpp",
                               "evidence": res.evidence},
                    ["parameter_pollution"]))
            elif res.verdict == "negative":
                coverage.record("parameter_pollution", "tested_negative",
                                f"{ep.normalized_url}::{param}")
            else:
                coverage.record("parameter_pollution", "inconclusive",
                                f"{ep.normalized_url}::{param}: "
                                f"{res.notes}")
    return findings


_MAX_HTML_ENDPOINTS = 10
_MAX_HTML_PARAMS = 3


def html_injection_probe(endpoints: List[Endpoint],
                         evidence: EvidenceStore, metrics: Metrics,
                         budgets: BudgetTracker,
                         coverage: CoverageTracker, client, cfg, scope,
                         controls: ProbeControls) -> List[Finding]:
    """Inert structural tags over observed GET query fields.

    Read-only GETs only. A tag parsed as a real element is a
    candidate (phishing/defacement primitive); neutralized or
    absent tags with completed probes are genuine negatives.
    Script execution stays with the XSS engine.
    """
    from ...safety.preflight import plan_html
    from ...validation.html_injection import check_html_injection
    from ...validation.param_pollution import query_params
    targets = [e for e in endpoints or []
               if (getattr(e, "method", "GET") or "GET").upper() == "GET"
               and query_params(getattr(e, "url", "") or "")
               and scope.active_test_allowed(e.url)][: _MAX_HTML_ENDPOINTS]
    if not targets:
        log.info("html: no in-scope parameterized GET endpoints — "
                 "nothing to check")
        return []
    if not reserve_or_block(
            budgets, coverage, "html",
            plan_html(len(targets), _MAX_HTML_PARAMS)):
        return []
    findings: List[Finding] = []
    for ep in targets:
        if controls.halted():
            log.info("html: halted by stop control")
            break
        params = [p for p in query_params(ep.url)
                  if p][: _MAX_HTML_PARAMS]
        if not budgets.consume_test("html", ep.normalized_url,
                                    limit=1 + 2 * len(params)):
            coverage.record("html", "blocked",
                            f"budget: {ep.normalized_url}")
            continue
        for param in params:
            try:
                res = check_html_injection(
                    client, ep.url, param,
                    timeout=cfg.scan.http_timeout)
            except BudgetExceeded:
                coverage.record("html", "blocked",
                                f"budget: {ep.normalized_url}")
                break
            if res.verdict == "candidate":
                controls.noted()
                coverage.record("html", "candidate",
                                f"{ep.normalized_url}::{param}: "
                                f"{res.notes}")
                f = Finding(
                    id=stable_finding_id("html", ep.normalized_url,
                                         param, res.evidence.get(
                                             "shape", "")),
                    source="html-injection",
                    name=(f"HTML injection: inert {res.evidence.get('shape', '')} "
                          f"tag via '{param}' parsed as an element "
                          f"({ep.path})"),
                    severity="medium",
                    confidence=Confidence.PROBABLE.value,
                    validation_status=ValidationStatus.
                    STRONG_CANDIDATE.value,
                    host=ep.host, matched_at=ep.url,
                    endpoint_url=ep.url, method="GET",
                    parameter=param,
                    description=res.notes,
                    tags=["html", "html-injection", "phishing-surface",
                          ep.endpoint_type],
                    raw={"html": res.to_dict()},
                    false_positive_notes=(
                        f"{res.notes}. Element injection proves tag "
                        f"survival, not impact: confirm a phishing or "
                        f"defacement primitive (link target, form "
                        f"action, page context) before reporting. "
                        f"Script execution belongs to the XSS engine."),
                )
                evidence.allocate(f)
                evidence.record(
                    f,
                    request_text=(f"GET {ep.url}\n(html probe ::{param})"),
                    response_text=res.notes)
                findings.append(f)
                log.info("html: %s on %s", param, ep.url)
            elif res.verdict == "negative":
                coverage.record("html", "tested_negative",
                                f"{ep.normalized_url}::{param}")
            else:
                coverage.record("html", "inconclusive",
                                f"{ep.normalized_url}::{param}: "
                                f"{res.notes}")
    return findings
