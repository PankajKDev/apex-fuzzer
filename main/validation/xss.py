"""XSS validation through Dalfox's structured report and safe replay."""
import json
import re
import secrets
import tempfile
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlsplit

from .base import Validator, Candidate, ValidationOutcome
from ..shell import run, which, redact
from ..models import ValidationStatus, Confidence
from .mutate import _inject


_XSS_TIERS = {
    "V", "R", "A", "VERIFIED", "REFLECTED", "AST",
    "AST_DETECTED", "INHTML", "INJS", "INATTR", "INURL",
}


def parse_dalfox_output(raw: str):
    """Parse JSON and JSONL Dalfox result shapes without grepping prose."""
    if not raw or not raw.strip():
        return []
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        data = []
        for line in raw.splitlines():
            try:
                data.append(json.loads(line))
            except (ValueError, TypeError):
                continue
    return _entries(data)


def _entries(data):
    if isinstance(data, list):
        return [entry for item in data for entry in _entries(item)]
    if not isinstance(data, dict):
        return []
    for key in ("findings", "results", "data", "entries"):
        if isinstance(data.get(key), (dict, list)):
            return _entries(data[key])
    if any(key in data for key in ("type", "poc", "payload", "poc_url")):
        return [data]
    return []


def _actionable(entry):
    tier = str(entry.get("type", "")).strip().upper()
    return tier in _XSS_TIERS


def _poc_url(entry, candidate, marker):
    for key in ("poc_url", "poc", "url", "target"):
        value = entry.get(key)
        if isinstance(value, str):
            parsed = urlsplit(value)
            if (parsed.scheme in ("http", "https") and parsed.netloc and
                    marker.lower() in unquote(value).lower()):
                return value
    payload = entry.get("payload")
    if (isinstance(payload, str) and payload and candidate.parameter and
            candidate.parameter_location == "query"):
        return _inject(candidate.endpoint_url, candidate.parameter, payload)
    return ""


def _dalfox_limits():
    """Use bounded flags supported by the installed Dalfox major version."""
    version = run(["dalfox", "version"], timeout=10)
    version_text = (version.stdout or "") + (version.stderr or "")
    match = re.search(r"\bv?(\d+)\.\d+", version_text, re.I)
    if not match:
        version = run(["dalfox", "--version"], timeout=10)
        version_text = (version.stdout or "") + (version.stderr or "")
        match = re.search(r"\bv?(\d+)\.\d+", version_text, re.I)
    major = int(match.group(1)) if match else 2
    if major >= 3:
        return ["--workers", "1", "--limit", "1"]
    return ["--worker", "1", "--limit-result", "1"]


class XssValidator(Validator):
    name = "dalfox"
    test_class = "xss"

    def __init__(self, cfg, browser_enabled: bool = False):
        super().__init__(cfg)
        self.browser_enabled = browser_enabled

    def can_handle(self, candidate: Candidate) -> bool:
        return candidate.test_class == "xss" and which("dalfox") is not None

    def validate(self, candidate: Candidate) -> ValidationOutcome:
        if candidate.method.upper() != "GET" or \
                candidate.parameter_location != "query":
            return ValidationOutcome(
                status=ValidationStatus.INCONCLUSIVE.value,
                confidence=Confidence.UNKNOWN.value,
                notes="Dalfox adapter currently supports GET query inputs")

        param = candidate.parameter
        if not param:
            query = parse_qsl(urlsplit(candidate.endpoint_url).query,
                              keep_blank_values=True)
            param = query[-1][0] if query else None
        if not param:
            return ValidationOutcome(
                status=ValidationStatus.INCONCLUSIVE.value,
                confidence=Confidence.UNKNOWN.value,
                notes="Dalfox skipped: no observed query parameter")
        query_names = {name for name, _ in parse_qsl(
            urlsplit(candidate.endpoint_url).query, keep_blank_values=True)}
        if param not in query_names:
            return ValidationOutcome(
                status=ValidationStatus.INCONCLUSIVE.value,
                confidence=Confidence.UNKNOWN.value,
                notes="Dalfox skipped: selected parameter is absent from URL")
        # Dalfox takes the target as a bare positional: require a
        # plain http(s) URL with a hostname, so a flag-shaped value
        # can never be flag-parsed. Anything else fails closed.
        try:
            parts = urlsplit(candidate.endpoint_url or "")
        except ValueError:
            parts = None
        if parts is None or parts.scheme.lower() not in (
                "http", "https") or not parts.hostname:
            return ValidationOutcome(
                status=ValidationStatus.INCONCLUSIVE.value,
                confidence=Confidence.UNKNOWN.value,
                notes="Dalfox skipped: target is not a plain http(s) URL")

        marker = "apexxss_" + secrets.token_hex(8)
        evidence_dir = getattr(candidate.finding, "evidence_dir", None)
        temp_dir = None
        if evidence_dir:
            output_path = Path(evidence_dir) / "dalfox.json"
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.unlink(missing_ok=True)
        else:
            temp_dir = tempfile.TemporaryDirectory(prefix="apex-dalfox-")
            output_path = Path(temp_dir.name) / "report.json"

        args = [
            "dalfox", "url", candidate.endpoint_url,
            "--no-color", "--silence", "--format", "json",
            "--output", str(output_path),
            "--skip-discovery", "--param", param,
            "--timeout",
            str(max(1, int(getattr(self.cfg.scan, "http_timeout", 10)))),
            "--custom-alert-value", marker,
            "--custom-alert-type", "str",
        ]
        args.extend(_dalfox_limits())
        try:
            result = run(args, timeout=300)
            file_text = (output_path.read_text(errors="replace")
                         if output_path.exists() else "")
            raw = file_text or result.stdout or ""
            records = parse_dalfox_output(raw)
            candidates = [entry for entry in records if _actionable(entry)]
            report_text = redact(json.dumps(candidates, ensure_ascii=False))
            try:
                safe_candidates = json.loads(report_text)
            except (ValueError, TypeError):
                safe_candidates = []
            evidence = {
                "dalfox_findings": safe_candidates[:20],
                "dalfox_report": report_text[:12000],
                "parameter": param,
                "custom_execution_marker": marker,
            }
            if candidates:
                browser_result = {"status": "not_enabled"}
                if self.browser_enabled:
                    poc = next((_poc_url(entry, candidate, marker)
                                for entry in candidates
                                if _poc_url(entry, candidate, marker)), "")
                    payload = next((entry.get("payload", "")
                                    for entry in candidates
                                    if isinstance(entry.get("payload"),
                                                  str)
                                    and _poc_url(entry, candidate, marker)),
                                   "")
                    if poc:
                        from .xss_browser import verify_execution
                        # query first, then fragment and cookie sinks with
                        # the same marker; stop at the first execution
                        attempts = [("query", poc, "", None)]
                        page = poc.split("#", 1)[0].split("?", 1)[0]
                        if payload:
                            attempts.append(
                                ("fragment", page, payload, None))
                            attempts.append(
                                ("cookie", page, "",
                                 {"apexxss": payload}))
                        for _source, _url, _frag, _jar in attempts:
                            browser_result = verify_execution(
                                candidate.endpoint_url, _url, marker,
                                self.cfg, candidate.request_headers,
                                fragment=_frag, cookies=_jar)
                            browser_result["attempted_source"] = _source
                            if browser_result.get("status") == "executed":
                                break
                    else:
                        browser_result = {"status": "no_replayable_poc"}
                if browser_result.get("reason"):
                    browser_result["reason"] = redact(
                        str(browser_result["reason"]))[:300]
                evidence["browser_verification"] = browser_result
                if browser_result.get("status") == "executed":
                    via = browser_result.get("attempted_source") or "query"
                    return ValidationOutcome(
                        status=ValidationStatus.CONFIRMED.value,
                        confidence=Confidence.CONFIRMED.value,
                        evidence=evidence,
                        notes="Playwright observed the per-scan execution "
                              "marker in a same-origin JavaScript dialog "
                              f"(source: {via})")
                return ValidationOutcome(
                    status=ValidationStatus.STRONG_CANDIDATE.value,
                    confidence=Confidence.PROBABLE.value,
                    evidence=evidence,
                    notes="Dalfox structured output reported XSS evidence; "
                          "browser execution was not independently observed")
            if not result.ok:
                return ValidationOutcome(
                    status=ValidationStatus.INCONCLUSIVE.value,
                    confidence=Confidence.UNKNOWN.value,
                    evidence={"dalfox_tail": redact(
                        (result.stdout or "") + (result.stderr or ""))[-1000:],
                              "report_parse": "no actionable structured result"},
                    notes="Dalfox exited unsuccessfully without a structured "
                          "XSS finding")
            return ValidationOutcome(
                status=ValidationStatus.NOT_TESTED.value,
                confidence=Confidence.UNKNOWN.value,
                evidence={"dalfox_report": report_text[:12000]},
                notes="Dalfox structured report contained no XSS finding")
        finally:
            if temp_dir is not None:
                temp_dir.cleanup()
