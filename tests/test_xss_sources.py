"""XSS fragment/cookie sources: same sandbox, non-query sinks.

Fake browser engine only (no Chromium). Live-Chromium coverage runs in
the virtual lab when browsers are installed.
"""
from types import SimpleNamespace
from urllib.parse import urlencode

from main.config import Config
from main.models import Finding
from main.validation import xss_browser as xss_browser_mod
from main.validation import xss as xss_mod
from main.validation.base import Candidate


def _engine_for(exec_sources, seen):
    """Fake engine: dialogs fire only for sources listed in exec_sources."""

    class Route:
        def __init__(self, url, method="GET"):
            self.request = SimpleNamespace(url=url, method=method,
                                           resource_type="document",
                                           frame=None)

        def continue_(self):
            pass

        def abort(self):
            pass

    class Page:
        def __init__(self, ctx):
            self.ctx = ctx
            self.handler = None

        def on(self, event, handler):
            self.handler = handler

        def goto(self, url, **kwargs):
            seen.append((url, dict(self.ctx.cookies)))
            from urllib.parse import urlsplit
            parts = urlsplit(url)
            fragment = parts.fragment
            hit = False
            if "query" in exec_sources and "alert(" in url:
                hit = True
            if "fragment" in exec_sources and "alert(" in fragment:
                hit = True
            if "cookie" in exec_sources and any(
                    "alert(" in value
                    for value in self.ctx.cookies.values()):
                hit = True
            if hit:
                self.handler(SimpleNamespace(message="marker-1",
                                             accept=lambda: None))

        def wait_for_timeout(self, timeout):
            pass

    class Context:
        def __init__(self):
            self.cookies = {}
            self.guard = None

        def set_extra_http_headers(self, headers):
            pass

        def add_cookies(self, cookies):
            for entry in cookies:
                self.cookies[entry["name"]] = entry["value"]

        def route(self, pattern, handler):
            self.guard = handler

        def new_page(self):
            return Page(self)

        def close(self):
            pass

    class Engine:
        def __init__(self, *args, **kwargs):
            self.ctx = Context()

        def start(self):
            pass

        def new_context(self):
            return self.ctx

        def stop(self):
            pass

    return Engine


def test_fragment_source_executes_when_query_does_not(tmp_path):
    seen = []
    monkeypatch_engine = _engine_for({"fragment"}, seen)
    old = xss_browser_mod.BrowserEngine
    xss_browser_mod.BrowserEngine = monkeypatch_engine
    try:
        result = xss_browser_mod.verify_execution(
            "https://example.test/page", "https://example.test/page?q=x",
            "marker-1", Config(), fragment="<script>alert(1)</script>")
    finally:
        xss_browser_mod.BrowserEngine = old
    assert result["status"] == "executed"
    assert result["source"] == "fragment"
    assert seen[0][0].startswith("https://example.test/page?q=x#")


def test_cookie_source_executes_with_clean_page(tmp_path):
    seen = []
    old = xss_browser_mod.BrowserEngine
    xss_browser_mod.BrowserEngine = _engine_for({"cookie"}, seen)
    try:
        result = xss_browser_mod.verify_execution(
            "https://example.test/page", "https://example.test/page",
            "marker-1", Config(),
            cookies={"apexxss": "<img src=x onerror=alert(1)>"})
    finally:
        xss_browser_mod.BrowserEngine = old
    assert result["status"] == "executed"
    assert result["source"] == "cookie"
    assert seen[0][1].get("apexxss", "").startswith("<img")


def test_cross_origin_fragment_is_rejected():
    result = xss_browser_mod.verify_execution(
        "https://example.test/", "https://other.test/?q=x", "marker",
        Config(), fragment="x")
    assert result["status"] == "rejected"


def _dalfox_candidate(tmp_path, parameter="q"):
    return Candidate(
        finding=Finding(id="xss-src", source="test",
                        evidence_dir=str(tmp_path)),
        test_class="xss",
        endpoint_url="https://example.test/search?q=hello",
        parameter=parameter)


def test_validator_falls_back_to_fragment_then_confirms(
        monkeypatch, tmp_path):
    import json
    from pathlib import Path

    def fake_run(args, timeout):
        if len(args) > 1 and args[1] in {"version", "--version"}:
            return SimpleNamespace(ok=True, stdout="Dalfox v2.13.0",
                                   stderr="")
        output = Path(args[args.index("--output") + 1])
        marker = args[args.index("--custom-alert-value") + 1]
        payload = f"<svg onload=alert('{marker}')>"
        poc = "https://example.test/search?" + urlencode({"q": payload})
        output.write_text(json.dumps([{
            "type": "R", "poc": poc, "payload": payload}]))
        return SimpleNamespace(ok=True, stdout="", stderr="")

    monkeypatch.setattr(xss_mod, "which", lambda _: "/usr/bin/dalfox")
    monkeypatch.setattr(xss_mod, "run", fake_run)
    calls = []

    def fake_verify(target_url, poc_url, marker, cfg, headers=None,
                    fragment="", cookies=None):
        calls.append((fragment, cookies))
        if fragment:
            return {"status": "executed", "source": "fragment"}
        return {"status": "not_executed", "source": "query"}

    monkeypatch.setattr(xss_browser_mod, "verify_execution", fake_verify)
    result = xss_mod.XssValidator(Config(), browser_enabled=True).validate(
        _dalfox_candidate(tmp_path))
    assert result.status == "confirmed"
    assert "(source: fragment)" in result.notes
    assert calls[0] == ("", None)
    assert calls[1][0] != ""


def test_validator_stays_candidate_when_no_source_executes(
        monkeypatch, tmp_path):
    import json
    from pathlib import Path

    def fake_run(args, timeout):
        if len(args) > 1 and args[1] in {"version", "--version"}:
            return SimpleNamespace(ok=True, stdout="Dalfox v2.13.0",
                                   stderr="")
        output = Path(args[args.index("--output") + 1])
        marker = args[args.index("--custom-alert-value") + 1]
        payload = f"<svg onload=alert('{marker}')>"
        poc = "https://example.test/search?" + urlencode({"q": payload})
        output.write_text(json.dumps([{
            "type": "R", "poc": poc, "payload": payload}]))
        return SimpleNamespace(ok=True, stdout="", stderr="")

    monkeypatch.setattr(xss_mod, "which", lambda _: "/usr/bin/dalfox")
    monkeypatch.setattr(xss_mod, "run", fake_run)
    monkeypatch.setattr(
        xss_browser_mod, "verify_execution",
        lambda *a, **k: {"status": "not_executed", "source": "query"})
    result = xss_mod.XssValidator(Config(), browser_enabled=True).validate(
        _dalfox_candidate(tmp_path))
    assert result.status == "strong_candidate"
