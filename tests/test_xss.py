"""Dalfox structured output and safe browser-confirmation tests."""
import json
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlencode

from apex_fuzzer.config import Config
from apex_fuzzer.models import Finding
from apex_fuzzer.validation.base import Candidate
from apex_fuzzer.validation import xss as xss_mod
from apex_fuzzer.validation import xss_browser as xss_browser_mod


def _candidate(tmp_path, parameter="q"):
    return Candidate(
        finding=Finding(id="xss-test", source="test",
                        evidence_dir=str(tmp_path)),
        test_class="xss",
        endpoint_url="https://example.test/search?q=hello",
        parameter=parameter)


def test_parse_dalfox_json_and_jsonl():
    rows = [{"type": "V", "payload": "<svg>"},
            {"type": "R", "payload": "<img>"},
            {"type": "I", "payload": "not xss"}]
    assert xss_mod.parse_dalfox_output(json.dumps(rows)) == rows
    assert xss_mod.parse_dalfox_output("\n".join(
        json.dumps(row) for row in rows)) == rows
    assert xss_mod.parse_dalfox_output("verified poc") == []


def test_xss_validator_parses_structured_report_and_pins_parameter(
        monkeypatch, tmp_path):
    calls = []

    def fake_run(args, timeout):
        if len(args) > 1 and args[1] in {"version", "--version"}:
            return SimpleNamespace(ok=True, stdout="Dalfox v2.13.0",
                                   stderr="")
        calls.append(args)
        output = Path(args[args.index("--output") + 1])
        marker = args[args.index("--custom-alert-value") + 1]
        payload = f"<svg onload=alert('{marker}')>"
        poc = "https://example.test/search?" + urlencode({"q": payload})
        output.write_text(json.dumps([{
            "type": "R", "poc": poc, "payload": payload,
            "evidence": "reflected in HTML context"}]))
        return SimpleNamespace(ok=True, stdout="", stderr="")

    monkeypatch.setattr(xss_mod, "which", lambda _: "/usr/bin/dalfox")
    monkeypatch.setattr(xss_mod, "run", fake_run)
    result = xss_mod.XssValidator(Config()).validate(_candidate(tmp_path))
    assert result.status == "strong_candidate"
    assert result.evidence["dalfox_findings"][0]["type"] == "R"
    assert result.evidence["browser_verification"]["status"] == "not_enabled"
    assert result.evidence["custom_execution_marker"].startswith("apexxss_")
    assert calls[0][calls[0].index("--param") + 1] == "q"
    assert "--skip-discovery" in calls[0]
    assert calls[0][calls[0].index("--worker") + 1] == "1"
    assert calls[0][calls[0].index("--limit-result") + 1] == "1"


def test_xss_validator_does_not_grep_prose_for_findings(monkeypatch, tmp_path):
    monkeypatch.setattr(xss_mod, "which", lambda _: "/usr/bin/dalfox")
    def prose_run(args, **kwargs):
        if len(args[0]) > 1 and args[0][1] in {"version", "--version"}:
            return SimpleNamespace(ok=True, stdout="Dalfox v2.13.0",
                                   stderr="")
        return SimpleNamespace(ok=True, stdout="verified XSS PoC", stderr="")

    monkeypatch.setattr(xss_mod, "run", prose_run)
    result = xss_mod.XssValidator(Config()).validate(_candidate(tmp_path))
    assert result.status == "not_tested"
    assert result.evidence["dalfox_report"] == "[]"


def test_xss_validator_promotes_only_browser_observed_marker(
        monkeypatch, tmp_path):
    def fake_run(args, timeout):
        if len(args) > 1 and args[1] in {"version", "--version"}:
            return SimpleNamespace(ok=True, stdout="Dalfox v2.13.0",
                                   stderr="")
        output = Path(args[args.index("--output") + 1])
        marker = args[args.index("--custom-alert-value") + 1]
        payload = f"<svg onload=alert('{marker}')>"
        poc = "https://example.test/search?" + urlencode({"q": payload})
        output.write_text(json.dumps([{
            "type": "V", "poc": poc, "payload": payload}]))
        return SimpleNamespace(ok=True, stdout="", stderr="")

    monkeypatch.setattr(xss_mod, "which", lambda _: "/usr/bin/dalfox")
    monkeypatch.setattr(xss_mod, "run", fake_run)
    monkeypatch.setattr(xss_browser_mod, "verify_execution",
                        lambda *args, **kwargs: {
                            "status": "executed", "dialog_observed": True})
    result = xss_mod.XssValidator(Config(), browser_enabled=True).validate(
        _candidate(tmp_path))
    assert result.status == "confirmed"


def test_browser_replay_same_origin_and_get_only(monkeypatch):
    calls = []

    class Route:
        def __init__(self, url, method):
            self.request = SimpleNamespace(url=url, method=method)

        def continue_(self):
            calls.append((self.request.url, "continued"))

        def abort(self):
            calls.append((self.request.url, "aborted"))

    class Page:
        def on(self, event, handler):
            self.dialog_handler = handler

        def goto(self, url, **kwargs):
            self.route_handler(Route(url, "GET"))
            self.route_handler(Route("https://evil.test/pixel", "GET"))
            self.route_handler(Route("https://example.test/write", "POST"))
            self.dialog_handler(SimpleNamespace(
                message="marker-123", accept=lambda: None))

        def wait_for_timeout(self, timeout):
            pass

    class Context:
        def set_extra_http_headers(self, headers):
            pass

        def route(self, pattern, handler):
            self.guard = handler

        def new_page(self):
            page = Page()
            page.route_handler = self.guard
            return page

        def close(self):
            pass

    class Engine:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            pass

        def new_context(self):
            return Context()

        def stop(self):
            pass

    monkeypatch.setattr(xss_browser_mod, "BrowserEngine", Engine)
    result = xss_browser_mod.verify_execution(
        "https://example.test/search", "https://example.test/search?q=x",
        "marker-123", Config())
    assert result["status"] == "executed"
    assert [state for _, state in calls] == [
        "continued", "aborted", "aborted"]


def test_browser_replay_rejects_cross_origin_before_launch(monkeypatch):
    monkeypatch.setattr(
        xss_browser_mod, "BrowserEngine",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError()))
    result = xss_browser_mod.verify_execution(
        "https://example.test/", "https://other.test/?q=x", "marker",
        Config())
    assert result["status"] == "rejected"


def test_dalfox_v3_gets_current_bounded_flag_names(monkeypatch):
    monkeypatch.setattr(
        xss_mod, "run", lambda *args, **kwargs:
        SimpleNamespace(ok=True, stdout="Dalfox v3.1.0", stderr=""))
    assert xss_mod._dalfox_limits() == ["--workers", "1", "--limit", "1"]
