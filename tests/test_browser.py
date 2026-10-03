"""Browser + session engine tests (agent Phase 1).

Unit tests use fakes (no browser needed). Integration tests drive a
real Chromium against a local HTTP server and skip cleanly when no
launchable browser exists.
"""
import json
import threading

import pytest

from apex_fuzzer.browser.browser import (
    playwright_available, chromium_available)
from apex_fuzzer.browser.network import (
    NetworkRecorder, _query_names, _form_names)
from apex_fuzzer.browser.storage import (
    cookies_to_dict, build_cookie_header, parse_storage_state,
    extract_tokens, extract_csrf_from_html, read_web_storage,
    StorageCapture)
from apex_fuzzer.browser.actions import (
    snapshot_dom, fill_form, click, run_js, ActionLog)
from apex_fuzzer.browser.sessions import (
    BrowserSession, SessionManager, looks_logged_out)
from apex_fuzzer.browser.workflows import BrowserWorkflow
from apex_fuzzer.config import AuthContext

needs_browser = pytest.mark.skipif(
    not chromium_available(), reason="no launchable chromium")


# ── fakes ─────────────────────────────────────────────────────────────
class FakeRequest:
    def __init__(self, url, method="GET", headers=None, post_data=None,
                 resource_type="document"):
        self.url = url
        self.method = method
        self.headers = headers or {}
        self.post_data = post_data
        self.resource_type = resource_type


class FakeResponse:
    def __init__(self, url, status=200):
        self.url = url
        self.status = status


class FakePage:
    def __init__(self, title="T", forms=None, links=None, scripts=None,
                 iframes=None, storage=None, fail_fill=()):
        self._title = title
        self._forms = forms or []
        self._sels = {"a[href]": links or [], "script[src]": scripts or [],
                      "iframe[src]": iframes or []}
        self._storage = storage or {}
        self._fail_fill = set(fail_fill)
        self.filled = {}
        self.clicked = []
        self.evaluated = []

    def title(self):
        return self._title

    def evaluate(self, expr):
        self.evaluated.append(expr)
        if "localStorage" in expr:
            return dict(self._storage.get("local", {}))
        if "sessionStorage" in expr:
            return dict(self._storage.get("session", {}))
        if "document.forms" in expr:
            return self._forms
        if expr.startswith("() =>"):
            raise RuntimeError("nope")
        return {"forms": self._forms}

    def eval_on_selector_all(self, sel, expr):
        return list(self._sels.get(sel, []))

    def fill(self, selector, value, timeout=None):
        if selector in self._fail_fill:
            raise RuntimeError("no such element")
        self.filled[selector] = value

    def click(self, selector, timeout=None):
        if selector == "button.missing":
            raise RuntimeError("no such element")
        self.clicked.append(selector)


class FakeContext:
    def __init__(self, cookies=None, state=None, fail=False):
        self._cookies = cookies or []
        self._state = state or {}
        self._fail = fail

    def cookies(self):
        if self._fail:
            raise RuntimeError("denied")
        return self._cookies

    def storage_state(self):
        if self._fail:
            raise RuntimeError("denied")
        return self._state


def _scope_for(hosts):
    from apex_fuzzer.scope import Scope
    from apex_fuzzer.config import ScopeConfig
    return Scope(ScopeConfig(allowed_domains=list(hosts)))


# ── network recorder ──────────────────────────────────────────────────
def test_to_endpoints_conversion_and_scope():
    rec = NetworkRecorder(scope=_scope_for(["example.com"]))
    rec._on_request(FakeRequest("https://example.com/api/u?id=1&x=2"))
    rec._on_request(FakeRequest("https://other.com/api/u?id=1"))
    rec._on_request(FakeRequest("https://example.com/a.png"))
    rec._on_request(FakeRequest(
        "https://example.com/submit", method="POST",
        headers={"content-type": "application/x-www-form-urlencoded"},
        post_data="name=bob&role=user"))
    rec._on_request(FakeRequest(
        "https://example.com/api/json", method="POST",
        headers={"content-type": "application/json"},
        post_data=json.dumps({"q": "hi"})))
    rec._on_response(FakeResponse("https://example.com/api/u?id=1&x=2",
                                  200))
    rec._on_websocket(type("W", (), {"url": "wss://example.com/ws"})())
    eps = rec.to_endpoints()
    by_url = {e["url"]: e for e in eps}
    assert set(by_url) == {"https://example.com/api/u?id=1&x=2",
                           "https://example.com/submit",
                           "https://example.com/api/json"}
    assert by_url["https://example.com/api/u?id=1&x=2"]["params"] == [
        "id", "x"]
    assert by_url["https://example.com/submit"]["body"] == {
        "name": "bob", "role": "user"}
    assert by_url["https://example.com/api/json"]["body"] == {"q": "hi"}
    assert rec.requests[0].status == 200
    assert rec.websockets == ["wss://example.com/ws"]


def test_recorder_request_cap_and_bad_events():
    rec = NetworkRecorder(max_requests=2)
    rec._on_request(FakeRequest("https://a.com/1"))
    rec._on_request(FakeRequest("https://a.com/2"))
    rec._on_request(FakeRequest("https://a.com/3"))
    assert len(rec.requests) == 2
    rec._on_request(object())  # no .url → ignored, no crash
    rec._on_response(object())
    rec._on_websocket(object())
    assert _query_names("not a url") == []
    assert _form_names("{bad json", {"content-type": "application/json"}) \
        == {}


# ── storage ───────────────────────────────────────────────────────────
def test_cookie_helpers():
    cookies = [{"name": "session", "value": "abc"},
               {"name": "csrf", "value": "tok"}]
    assert cookies_to_dict(cookies) == {"session": "abc", "csrf": "tok"}
    assert build_cookie_header(cookies) == "session=abc; csrf=tok"
    assert build_cookie_header([]) == ""


def test_parse_storage_state():
    state = {"cookies": [{"name": "a", "value": "1"}],
             "origins": [{"origin": "https://x.com"}]}
    cookies, origins = parse_storage_state(state)
    assert cookies == [{"name": "a", "value": "1"}]
    assert "https://x.com" in origins
    assert parse_storage_state({}) == ([], {})
    assert parse_storage_state(None) == ([], {})


def test_extract_tokens():
    jwt = ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0."
           "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c")
    found = extract_tokens(
        [{"name": "csrftoken", "value": "abc123"},
         {"name": "plain", "value": "x"}],
        {"auth": jwt, "other": "Bearer tok1234567890"},
        {"s": "nothing"},
        '<meta name="csrf-token" content="meta123">')
    assert found["jwt"] == [jwt]
    assert found["bearer"] == ["tok1234567890"]
    assert any("csrftoken" in c for c in found["csrf"])


def test_extract_csrf_from_html():
    html = ('<meta name="csrf-token" content="M1">'
            '<form><input type="hidden" name="authenticity_token" '
            'value="T9"></form>')
    tokens = extract_csrf_from_html(html)
    assert tokens == ["M1", "T9"]
    assert extract_csrf_from_html("<p>none</p>") == []


def test_read_web_storage_and_capture():
    page = FakePage(storage={"local": {"k": "v"}, "session": {"s": "1"}})
    assert read_web_storage(page) == {
        "local_storage": {"k": "v"}, "session_storage": {"s": "1"}}

    class BadPage(FakePage):
        def evaluate(self, expr):
            raise RuntimeError("dead")

    assert read_web_storage(BadPage()) == {
        "local_storage": {}, "session_storage": {}}
    cap = StorageCapture().capture(
        FakeContext([{"name": "a", "value": "b"}]), page)
    assert cap["cookie_header"] == "a=b"
    cap2 = StorageCapture().capture(FakeContext(fail=True), None)
    assert cap2["cookies"] == [] and cap2["storage_state"] == {}


# ── actions ───────────────────────────────────────────────────────────
def test_snapshot_dom():
    page = FakePage(
        title="Hi",
        forms=[{"action": "/login", "method": "post", "inputs": []}],
        links=["/a", "/b"], scripts=["/app.js"], iframes=[])
    snap = snapshot_dom(page)
    assert snap["title"] == "Hi"
    assert snap["forms"][0]["action"] == "/login"
    assert snap["links"] == ["/a", "/b"]
    assert snap["scripts"] == ["/app.js"]


def test_fill_click_js():
    page = FakePage(fail_fill={'input[name="nope"]',
                               'textarea[name="nope"]',
                               'select[name="nope"]'})
    assert fill_form(page, {"user": "u", "nope": "x"}) == 1
    assert page.filled == {'input[name="user"]': "u"}
    assert click(page, "button.go") is True
    assert click(page, "button.missing") is False
    assert run_js(page, "() => 1") is None  # FakePage raises by default
    log = ActionLog()
    fill_form(page, {"user": "u"}, log)
    click(page, "button.go", log)
    assert [a["kind"] for a in log.to_dict()] == ["fill", "click"]


# ── sessions ──────────────────────────────────────────────────────────
def test_session_to_identity_and_expiry():
    s = BrowserSession(
        "user_a", role="member", tenant="acme",
        cookies=[{"name": "session", "value": "AAA"}],
        tokens={"jwt": ["J.W.T"], "bearer": [], "csrf": []},
        expires_in=60)
    ident = s.to_identity()
    assert ident.name == "user_a" and ident.roles == ["member"]
    assert ident.auth_headers["Cookie"] == "session=AAA"
    assert ident.auth_headers["Authorization"] == "Bearer J.W.T"
    assert s.is_expired() is False
    assert s.is_expired(s.created_ts + 61) is True
    rt = BrowserSession.from_dict(s.to_dict())
    assert rt.identity == "user_a" and rt.tenant == "acme"


def test_looks_logged_out():
    assert looks_logged_out("https://t.com/login?next=/", "<p>x</p>")
    assert looks_logged_out("https://t.com/a",
                            '<input type="password" name="pw">')
    assert not looks_logged_out("https://t.com/dashboard",
                                "<h1>welcome</h1>")


def test_session_manager_files(tmp_path):
    mgr = SessionManager(tmp_path)
    state = {"cookies": [{"name": "s", "value": "1", "domain": "t.com"}],
             "origins": []}
    (tmp_path / "u.json").write_text(json.dumps(state))
    s = mgr.from_storage_file(tmp_path / "u.json", "user_a")
    assert s.cookies == state["cookies"]
    dest = mgr.save(s)
    assert mgr.load(dest).identity == "user_a"
    cap = {"cookies": state["cookies"], "tokens": {},
           "storage_state": state}
    s2 = mgr.from_capture(cap, "user_b", role="admin")
    assert s2.role == "admin" and s2.to_identity().auth_headers[
        "Cookie"] == "s=1"


def test_apply_to_contexts(tmp_path):
    mgr = SessionManager()
    state = {"cookies": [{"name": "s", "value": "9"}], "origins": []}
    p = tmp_path / "a.json"
    p.write_text(json.dumps(state))
    ctx_empty = AuthContext(name="user_a", storage_state=str(p))
    ctx_full = AuthContext(name="user_b", headers={"Cookie": "s=old"},
                           storage_state=str(p))
    ctx_missing = AuthContext(name="user_c",
                              storage_state=str(tmp_path / "no.json"))
    assert mgr.apply_to_contexts(
        [ctx_empty, ctx_full, ctx_missing]) == 1
    assert ctx_empty.headers == {"Cookie": "s=9"}
    assert ctx_full.headers == {"Cookie": "s=old"}  # static wins


# ── workflows ─────────────────────────────────────────────────────────
class FlowPage(FakePage):
    def __init__(self, **kw):
        super().__init__(**kw)
        self.visited = []
        self.keys = []
        self.waited_urls = []

    def goto(self, url, timeout=None):
        self.visited.append(url)

    @property
    def keyboard(self):
        outer = self

        class K:
            def press(self, key, timeout=None):
                outer.keys.append(key)
        return K()

    def wait_for_url(self, pattern, timeout=None):
        self.waited_urls.append(pattern)

    def get_by_text(self, text):
        outer = self

        class G:
            first = self

            def wait_for(self, timeout=None):
                outer.waited_urls.append(f"text:{text}")
        g = G()
        g.first = g
        return g


def test_workflow_replay_and_roundtrip():
    from apex_fuzzer.browser.workflows import BrowserWorkflow
    wf = (BrowserWorkflow("login")
          .add("goto", "https://t.com/login")
          .add("fill", 'input[name="user"]', "bob")
          .add("click", "button.submit")
          .add("press", "", "Enter")
          .add("wait_url", "**/dashboard"))
    page = FlowPage()
    results = wf.replay(page)
    assert all(r["ok"] for r in results)
    assert page.visited == ["https://t.com/login"]
    assert page.keys == ["Enter"]
    rt = BrowserWorkflow.from_dict(wf.to_dict())
    assert [s.action for s in rt.steps] == ["goto", "fill", "click",
                                            "press", "wait_url"]


def test_workflow_unknown_action_and_break():
    from apex_fuzzer.browser.workflows import BrowserWorkflow
    wf = BrowserWorkflow("x").add("teleport", "mars").add(
        "goto", "https://t.com/")
    page = FlowPage()
    results = wf.replay(page)
    assert results[0]["ok"] is False
    assert len(results) == 1  # stops at first failure
    assert page.visited == []


# ── orchestrator merge helpers ────────────────────────────────────────
def test_merge_browser_entry_and_resolve_link():
    from apex_fuzzer.orchestrator import Orchestrator
    from apex_fuzzer.config import Config
    from apex_fuzzer.profiles import get as get_profile
    import tempfile
    from pathlib import Path
    orch = Orchestrator(Config(), Path(tempfile.mkdtemp()),
                        profile=get_profile("standard"))
    by_norm = {}
    orch._merge_browser_entry(by_norm, "t.com",
                              {"url": "https://t.com/api/u?id=1",
                               "method": "GET", "params": ["id"],
                               "body": {}})
    assert "browser" in by_norm[
        "https://t.com/api/u?id=1"].source
    # merge into existing keeps both sources + adds body params
    orch._merge_browser_entry(by_norm, "t.com",
                              {"url": "https://t.com/api/u?id=1",
                               "method": "POST",
                               "params": ["id"],
                               "body": {"name": "x"}})
    ep = by_norm["https://t.com/api/u?id=1"]
    assert {p.name for p in ep.body_parameters} == {"name"}
    # form entry upgrades method + records inputs
    orch._merge_browser_entry(
        by_norm, "t.com",
        {"url": "https://t.com/login", "method": "GET", "params": {},
         "body": {}, "inputs": ["user", "pw"], "form_method": "POST"})
    lep = [e for e in by_norm.values() if e.path == "/login"][0]
    assert lep.method == "POST"
    assert {p.name for p in lep.body_parameters} == {"user", "pw"}
    assert orch._resolve_link("https://t.com/a",
                              "/b?x=1#f") == "https://t.com/b?x=1"
    assert orch._resolve_link("https://t.com/a",
                              "javascript:void(0)") is None
    assert orch._resolve_link("https://t.com/a", "/x.png") is None


def test_browser_discover_skip_paths(monkeypatch, tmp_path):
    from apex_fuzzer.orchestrator import Orchestrator
    from apex_fuzzer.config import Config
    from apex_fuzzer.profiles import get as get_profile
    from apex_fuzzer.reporting.metrics import Metrics
    from apex_fuzzer.budgets import BudgetTracker
    orch = Orchestrator(Config(), tmp_path,
                        profile=get_profile("standard"))
    # disabled by default profile
    assert orch._browser_discover(
        "https://t.com/", "t.com", tmp_path, BudgetTracker(Config()),
        Metrics()) == []
    # enabled but no playwright
    cfg = Config()
    cfg.browser.enabled = True
    orch2 = Orchestrator(cfg, tmp_path, profile=get_profile("standard"))
    monkeypatch.setattr("apex_fuzzer.browser.browser.playwright_available",
                        lambda: True)
    import apex_fuzzer.browser.browser as bmod
    monkeypatch.setattr(bmod, "playwright_available", lambda: False)
    assert orch2._browser_discover(
        "https://t.com/", "t.com", tmp_path, BudgetTracker(cfg),
        Metrics()) == []


def test_playwright_available_is_bool():
    assert isinstance(playwright_available(), bool)


# ── integration: real Chromium + local server ─────────────────────────
class _Handler:
    routes = {}

    def __init__(self, *args, **kwargs):
        from http.server import BaseHTTPRequestHandler

        class H(BaseHTTPRequestHandler):
            server_ref = None

            def log_message(self, *a):
                pass

            def _cookie(self):
                hdr = self.headers.get("Cookie", "")
                return "session=ABC" in hdr

            def do_GET(self):
                if self.path == "/":
                    body = (
                        "<html><head><title>Home</title></head><body>"
                        "<a href='/page2'>two</a> "
                        "<a href='https://other.com/x'>ext</a>"
                        "<form action='/login' method='post'>"
                        "<input name='user'><input name='pw' type='password'>"
                        "<button type='submit'>go</button></form>"
                        "<script>localStorage.setItem('k','v');"
                        "fetch('/api/data?id=7');</script>"
                        "</body></html>").encode()
                    self._send(200, body, "text/html")
                elif self.path == "/page2":
                    self._send(200, b"<html><body>p2</body></html>",
                               "text/html")
                elif self.path == "/dashboard":
                    if self._cookie():
                        self._send(200, b"<html><body>dash</body></html>",
                                   "text/html")
                    else:
                        self._send(302, b"", "text/html",
                                   {"Location": "/login"})
                elif self.path.startswith("/api/data"):
                    self._send(200, b'{"id": 7}', "application/json")
                else:
                    self._send(404, b"nope", "text/plain")

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                self.rfile.read(length)
                if self.path == "/login":
                    self._send(302, b"", "text/html",
                               {"Location": "/dashboard",
                                "Set-Cookie": "session=ABC; Path=/"})
                else:
                    self._send(404, b"nope", "text/plain")

            def _send(self, code, body, ctype, extra=None):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)

        self._H = H

    def handler(self):
        return self._H


@pytest.fixture()
def local_site():
    from http.server import ThreadingHTTPServer
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler().handler())
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


@needs_browser
def test_browser_login_capture_reuse(local_site):
    from apex_fuzzer.browser.browser import BrowserEngine
    from apex_fuzzer.browser.network import NetworkRecorder
    from apex_fuzzer.browser.actions import snapshot_dom, fill_form
    from apex_fuzzer.browser.storage import StorageCapture
    from apex_fuzzer.browser.sessions import SessionManager
    from apex_fuzzer.config import Config

    cfg = Config()
    with BrowserEngine(cfg, headless=True) as engine:
        ctx = engine.new_context()
        page = ctx.new_page()
        rec = NetworkRecorder()
        rec.attach(page)
        page.goto(local_site + "/", timeout=15000)
        page.wait_for_timeout(800)  # let fetch() + storage run
        snap = snapshot_dom(page)
        assert snap["title"] == "Home"
        assert any("/login" in (f.get("action") or "")
                   for f in snap["forms"])
        assert snap["links"]  # includes absolute + external hrefs
        assert fill_form(page, {"user": "u", "pw": "p"}) == 2
        page.keyboard.press("Enter")
        page.wait_for_url("**/dashboard", timeout=15000)
        assert "dash" in page.content()
        stores = StorageCapture().capture(ctx, page)
        assert stores["cookie_header"] == "session=ABC"
        eps = rec.to_endpoints()
        urls = [e["url"] for e in eps]
        assert any(u.endswith("/api/data?id=7") for u in urls)
        assert any(u.endswith("/login") for u in urls
                   if e_method(eps, u) == "POST")
        mgr = SessionManager()
        sess = mgr.from_capture(stores, "browser")
        ident = sess.to_identity()
        assert ident.auth_headers["Cookie"] == "session=ABC"
        # reuse through plain HTTP (no browser): the cookie works
        import urllib.request
        req = urllib.request.Request(
            local_site + "/dashboard",
            headers={"Cookie": ident.auth_headers["Cookie"]})
        with urllib.request.urlopen(req, timeout=10) as r:
            assert r.status == 200 and b"dash" in r.read()
        page.close()
        ctx.close()


def e_method(eps, url):
    for e in eps:
        if e["url"] == url:
            return e["method"]
    return ""


@needs_browser
def test_orchestrator_browser_crawl(local_site, tmp_path):
    from apex_fuzzer.orchestrator import Orchestrator
    from apex_fuzzer.config import Config
    from apex_fuzzer.profiles import get as get_profile
    from apex_fuzzer.reporting.metrics import Metrics
    from apex_fuzzer.budgets import BudgetTracker
    from urllib.parse import urlparse
    host = urlparse(local_site).hostname
    cfg = Config()
    cfg.browser.enabled = True
    cfg.browser.max_pages = 5
    cfg.scope.allowed_domains = [host]
    orch = Orchestrator(cfg, tmp_path, profile=get_profile("deep"))
    metrics = Metrics()
    entries = orch._browser_discover(
        local_site + "/", host, tmp_path, BudgetTracker(cfg), metrics)
    assert metrics.browser_pages >= 2
    assert any("/api/data" in e["url"] for e in entries)
    assert (tmp_path / "browser_urls.txt").exists()
    assert (tmp_path / "sessions" / "browser.json").exists()
    # merge path produces pipeline endpoints incl. form bodies
    by_norm = {}
    for entry in entries:
        orch._merge_browser_entry(by_norm, host, entry)
    assert any("browser" in e.source for e in by_norm.values())
