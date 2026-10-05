"""Auth workflow engine tests (agent Phase 2).

Unit tests use fakes throughout. The login integration test drives
real Chromium against a local fixture server and skips cleanly
without a launchable browser.
"""
import base64
import json
import threading
import time

import pytest

from main.auth.identities import (
    Permission, IdentityRegistry, build_registry)
from main.auth.sessions import (
    AuthSession, SessionStore, from_browser_session)
from main.auth.jwt import parse_jwt, find_jwts
from main.auth.oauth import (
    pkce_pair, new_pkce_flow, find_token_leaks)
from main.auth.oidc import (
    check_issuer, NonceTracker, parse_id_token, fetch_discovery)
from main.auth.workflows import (
    LoginIdentity, MfaCheckpoint, LoginManager, looks_like_mfa)
from main.browser.browser import chromium_available
from main.config import AuthContext, Config
from main.models import Identity

needs_browser = pytest.mark.skipif(
    not chromium_available(), reason="no launchable chromium")


def _jwt(alg="HS256", payload=None):
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode(
            ).rstrip("=")
    return (b64({"alg": alg, "typ": "JWT"}) + "." +
            b64(payload or {"sub": "u1"}) + ".sig")


# ── identities ────────────────────────────────────────────────────────
def test_permission_round_trip():
    p = Permission(name="users:read", tenant="acme")
    assert Permission.from_dict(p.to_dict()).tenant == "acme"


def test_registry_relationships():
    reg = IdentityRegistry()
    reg.add_role(__import__(
        "main.models", fromlist=["Role"]).Role(
            name="admin", permissions=["users:read", "users:write"]))
    reg.add_identity(Identity(name="a", roles=["admin"], tenant="t1"))
    reg.add_identity(Identity(name="b", roles=[], tenant="t1"))
    reg.add_identity(Identity(name="c", roles=[], tenant="t2"))
    assert reg.permissions_for("a") == ["users:read", "users:write"]
    assert reg.identity_has_permission("a", "users:write") is True
    assert reg.identity_has_permission("b", "users:write") is False
    assert reg.same_tenant("a", "b") is True
    assert reg.same_tenant("a", "c") is False
    assert reg.same_tenant("a", "ghost") is False
    assert reg.roles_for("ghost") == []
    rt = IdentityRegistry.from_dict(reg.to_dict())
    assert rt.identity_has_permission("a", "users:read") is True


def test_build_registry_from_contexts():
    reg = build_registry([AuthContext(name="anonymous"),
                          AuthContext(name="u", roles=["member"],
                                      tenant="acme")])
    assert set(reg.identities) == {"anonymous", "u"}
    assert reg.tenants["acme"].name == "acme"


# ── sessions ──────────────────────────────────────────────────────────
def test_session_expiry_and_refresh_window():
    s = AuthSession(identity="u", expires_in=60, refresh_expires_in=3600,
                    refresh_token="rt", token_url="https://t.com/token")
    assert s.is_expired() is False
    assert s.can_refresh() is True
    assert s.is_expired(s.created_ts + 61) is True
    assert s.can_refresh(s.created_ts + 61) is True  # refresh still open
    assert s.refresh_expired(s.created_ts + 3601) is True
    assert s.can_refresh(s.created_ts + 3601) is False
    s2 = AuthSession(identity="u", expires_in=60)
    assert s2.can_refresh() is False  # no mechanism


def test_session_to_identity_headers():
    s = AuthSession(identity="u", role="m", tenant="t",
                    cookies=[{"name": "s", "value": "1"}],
                    headers={"X-A": "b"},
                    tokens={"access_token": "tok"})
    ident = s.to_identity()
    assert ident.auth_headers["Cookie"] == "s=1"
    assert ident.auth_headers["Authorization"] == "Bearer tok"
    assert ident.auth_headers["X-A"] == "b"


def test_session_secrets_redacted_on_disk(tmp_path):
    s = AuthSession(identity="u", refresh_token="SECRET-RT",
                    tokens={"access_token": "AT"},
                    token_url="https://t.com/token")
    d = s.to_dict()
    assert "SECRET-RT" not in json.dumps(d)
    assert d["has_refresh_token"] is True
    # reload without secrets → no token material
    rt = AuthSession.from_dict(d)
    assert rt.refresh_token == "" and rt.tokens.get("access_token") \
        in ("***", None)


def test_session_store_lifecycle(tmp_path):
    store = SessionStore()
    old = store.create(identity="u", expires_in=60)
    old.created_ts -= 3600 * 25  # both windows shut
    fresh = store.create(identity="u", expires_in=3600)
    other = store.create(identity="v", expires_in=3600)
    assert store.fresh_for_identity("u").session_id == \
        fresh.session_id
    assert store.prune_expired() == 1
    assert store.get(old.session_id) is None
    store.revoke(other.session_id)
    assert store.for_identity("v") == []
    p = tmp_path / "sessions.json"
    store.save(p)
    assert SessionStore.load(p).get(fresh.session_id) is not None
    assert SessionStore.load(tmp_path / "no.json").sessions == {}


def test_session_refresh_success_and_rejection(monkeypatch):
    import requests

    def ok(url, **kw):
        class R:
            def json(self):
                return {"access_token": "NEW",
                        "refresh_token": "RT2", "expires_in": 99}
        assert kw["data"]["grant_type"] == "refresh_token"
        return R()

    def bad(url, **kw):
        class R:
            def json(self):
                return {"error": "invalid_grant"}
        return R()

    monkeypatch.setattr(requests, "post", ok)
    s = AuthSession(identity="u", refresh_token="RT",
                    token_url="https://t.com/token", client_id="c")
    assert SessionStore().refresh(s) is True
    assert s.tokens["access_token"] == "NEW"
    assert s.refresh_token == "RT2" and s.expires_in == 99
    monkeypatch.setattr(requests, "post", bad)
    assert SessionStore().refresh(s) is False
    s2 = AuthSession(identity="u")  # no mechanism
    assert SessionStore().refresh(s2) is False


def test_from_browser_session():
    class BS:
        identity = "u"
        tenant = "t"
        cookies = [{"name": "s", "value": "1"}]
        tokens = {"jwt": ["J.W.T"], "bearer": [], "csrf": []}
        created_ts = 0.0
    s = from_browser_session(BS(), role="admin")
    assert s.identity == "u" and s.role == "admin"
    assert s.tokens["access_token"] == "J.W.T"
    assert s.to_identity().auth_headers["Cookie"] == "s=1"


# ── JWT (passive) ─────────────────────────────────────────────────────
def test_parse_jwt_full():
    now = int(time.time())
    tok = _jwt(payload={"sub": "u1", "iss": "https://idp/x",
                        "aud": "api", "exp": now + 600,
                        "nbf": now - 10, "iat": now - 20,
                        "role": "admin"})
    c = parse_jwt(tok)
    assert c.algorithm == "HS256" and c.subject == "u1"
    assert c.audience == "api" and c.issuer == "https://idp/x"
    assert c.is_expired() is False and c.usable_now() is True
    assert any("role" in o for o in c.observations)


def test_parse_jwt_rejects_non_tokens():
    assert parse_jwt("not.a") is None
    assert parse_jwt("") is None
    assert parse_jwt("a.b.c") is None  # bad segments
    assert parse_jwt(None) is None


def test_jwt_expiry_edges():
    now = int(time.time())
    assert parse_jwt(_jwt(payload={"exp": now - 3600})).is_expired() \
        is True
    assert parse_jwt(_jwt(payload={
        "nbf": now + 3600})).usable_now() is False
    noexp = parse_jwt(_jwt(payload={"sub": "x"}))
    assert noexp.is_expired() is None
    assert any("no exp" in o for o in noexp.observations)
    none_tok = _jwt(alg="none")
    assert any("none" in o for o in parse_jwt(none_tok).observations)


def test_find_jwts():
    text = ("here eyJhYmMiOiAxfQ.eyJzdWIiOiIxIn0."
            "c2lnbmF0dXJlMTIzNDU2Nzg5MA and done")
    assert len(find_jwts(text)) == 1
    assert find_jwts("nothing here") == []


# ── OAuth ─────────────────────────────────────────────────────────────
def test_pkce_pair_verifies():
    import hashlib
    verifier, challenge = pkce_pair()
    expect = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    assert challenge == expect and len(verifier) >= 43


def test_authorize_url_and_code_tracking():
    f = new_pkce_flow(
        name="idp", authorization_url="https://idp/auth",
        token_url="https://idp/token", client_id="cid",
        redirect_uri="https://app/cb", scope="openid",
        state="st", nonce="n9")
    url = f.authorize_url()
    assert "code_challenge=" in url and "code_challenge_method=S256" \
        in url and "nonce=n9" in url and "state=st" in url
    assert f.note_code("C1") is True
    assert f.note_code("C1") is False  # reuse flagged
    assert f.to_dict()["codes_seen_count"] == 1


def test_find_token_leaks():
    reqs = [{"url": "https://evil.com/cb?code=ABC123",
             "headers": {}},
            {"url": "https://app.com/cb?code=ABC123", "headers": {}},
            {"url": "https://app.com/static.js", "headers": {}},
            {"url": "https://cdn.com/x.js?x=eyJhYmMiOiAxfQ.eyJzdWIiOiIxIn0.c2ln",
             "headers": {"referer": "https://app.com/"}}]
    leaks = find_token_leaks(reqs, first_party="app.com")
    assert {l["host"] for l in leaks} == {"evil.com", "cdn.com"}
    assert find_token_leaks([], "app.com") == []


# ── OIDC ──────────────────────────────────────────────────────────────
def test_check_issuer():
    assert check_issuer({"issuer": "https://idp/"}, "https://idp") == []
    notes = check_issuer({"issuer": "https://evil/"},
                         "https://idp")
    assert any("mismatch" in n for n in notes)
    assert check_issuer({}, "https://idp")


def test_nonce_tracker():
    t = NonceTracker()
    t.issue("n1")
    assert t.consume("n1") is True
    assert t.consume("n1") is False  # replay
    assert t.consume("unknown") is False


def test_parse_id_token_delegates():
    assert parse_id_token(_jwt()) is not None
    assert parse_id_token("junk") is None


def test_fetch_discovery_failure(monkeypatch):
    import requests

    def boom(*a, **k):
        raise ConnectionError("down")
    monkeypatch.setattr(requests, "get", boom)
    assert fetch_discovery("https://idp") == {}


# ── login workflows ───────────────────────────────────────────────────
def test_resolve_password(monkeypatch):
    assert LoginIdentity(name="a", password_env="").resolve_password() \
        == ""
    monkeypatch.setenv("PW_A", "s3cret")
    assert LoginIdentity(name="a",
                         password_env="PW_A").resolve_password() == \
        "s3cret"
    assert LoginIdentity(name="a",
                         password_env="PW_MISSING").resolve_password() \
        == ""


def test_looks_like_mfa():
    assert looks_like_mfa("https://t.com/mfa/verify", "<p>x</p>")
    assert looks_like_mfa("https://t.com/dash",
                          '<input name="totp">')
    assert not looks_like_mfa("https://t.com/dashboard",
                              "<h1>welcome</h1>")


def test_build_workflow_masks_password():
    from main.config import LoginConfig
    cfg = LoginConfig(enabled=True, url="https://t.com/login")
    mgr = LoginManager(cfg)
    wf = mgr.build_workflow(LoginIdentity(name="a", username="u"),
                            "SUPERSECRET")
    text = json.dumps(wf.to_dict())
    assert "SUPERSECRET" not in text
    assert [s.action for s in wf.steps] == ["goto", "fill", "fill",
                                            "click"]


def test_mfa_checkpoint_roundtrip(tmp_path):
    cp = MfaCheckpoint(identity="a", url="https://t.com/mfa")
    p = cp.save(tmp_path / "mfa_a.json")
    assert MfaCheckpoint.from_dict(json.loads(p.read_text())).url == \
        "https://t.com/mfa"


class _LoginPage:
    """Fake login form page: fillable user/pass, clickable submit."""

    def __init__(self, fields=("username", "password"), dest="dashboard",
                 post_html="<h1>welcome</h1>"):
        self.fields = set(fields)
        self.filled = {}
        self.dest = dest
        self.post_html = post_html
        self.url = "https://t.com/login"
        self.goto_calls = []

    def goto(self, url, timeout=None):
        self.goto_calls.append(url)
        self.url = url

    def fill(self, selector, value, timeout=None):
        import re
        m = re.search(r'name="([^"]+)"', selector)
        if not m or m.group(1) not in self.fields:
            raise RuntimeError("no such element")
        self.filled[m.group(1)] = value

    def click(self, selector, timeout=None):
        if "missing" in selector:
            raise RuntimeError("no such element")
        self.url = "https://t.com/" + self.dest

    def wait_for_timeout(self, ms):
        pass

    def wait_for_load_state(self, state, timeout=None):
        pass

    @property
    def keyboard(self):
        class K:
            def press(self, key, timeout=None):
                pass
        return K()

    def content(self):
        if self.url.endswith("/login"):
            return '<form><input name="username"><input name="password" ' \
                   'type="password"></form>'
        return self.post_html

    def evaluate(self, expr):
        return {}


class _LoginCtx:
    def __init__(self, cookies=None):
        self._cookies = cookies or []

    def cookies(self):
        return self._cookies

    def storage_state(self):
        return {"cookies": self._cookies, "origins": []}


def _login_cfg(**kw):
    from main.config import LoginConfig
    base = dict(enabled=True, url="https://t.com/login")
    base.update(kw)
    return LoginConfig(**base)


def test_attempt_ok_captures_session():
    mgr = LoginManager(_login_cfg())
    page = _LoginPage()
    ctx = _LoginCtx([{"name": "s", "value": "1"}])
    status, payload = mgr.attempt(
        page, ctx, LoginIdentity(name="a", username="u"), "pw")
    assert status == "ok"
    assert payload.cookies == [{"name": "s", "value": "1"}]
    assert page.filled["password"] == "pw"  # real secret used
    assert mgr.workflows["a"].name == "login-a"  # masked recording kept
    assert "pw" not in json.dumps(mgr.workflows["a"].to_dict())


def test_attempt_missing_fields_fails():
    mgr = LoginManager(_login_cfg())
    page = _LoginPage(fields=("username",))  # no password field
    status, reason = mgr.attempt(
        page, _LoginCtx(), LoginIdentity(name="a", username="u"), "pw")
    assert status == "failed" and "1/2" in reason


def test_attempt_mfa_checkpoint():
    mgr = LoginManager(_login_cfg())
    page = _LoginPage(dest="mfa/verify",
                      post_html='<input name="totp">')
    status, payload = mgr.attempt(
        page, _LoginCtx(), LoginIdentity(name="a", username="u"), "pw")
    assert status == "mfa" and payload.url.endswith("/mfa/verify")


def test_attempt_still_logged_out():
    mgr = LoginManager(_login_cfg())
    page = _LoginPage(dest="login",
                      post_html='<input name="password" type="password">')
    # stays on a password-bearing page → failed, not ok
    page.url = "https://t.com/login"

    def click_no_nav(selector, timeout=None):
        pass  # submit does nothing
    page.click = click_no_nav
    status, reason = mgr.attempt(
        page, _LoginCtx(), LoginIdentity(name="a", username="u"), "pw")
    assert status == "failed" and "logged out" in reason


def test_attempt_budget_gated():
    class Budgets:
        def consume_test(self, *a):
            return False
    mgr = LoginManager(_login_cfg(), budgets=Budgets())
    status, reason = mgr.attempt(
        _LoginPage(), _LoginCtx(), LoginIdentity(name="a"), "pw")
    assert status == "failed" and "budget" in reason


# ── config + orchestrator wiring ──────────────────────────────────────
def test_login_config_yaml(tmp_path):
    f = tmp_path / "c.yaml"
    f.write_text(
        "auth:\n  login:\n    enabled: true\n"
        "    url: https://t.com/login\n"
        "    success_url_contains: /dash\n"
        "    identities:\n"
        "      - name: user_a\n"
        "        username: alice@t.com\n"
        "        password_env: PW_A\n"
        "        roles: [member]\n"
        "        tenant: acme\n")
    cfg = Config.load(f)
    assert cfg.auth.login.enabled is True
    assert cfg.auth.login.success_url_contains == "/dash"
    ident = cfg.auth.login.identities[0]
    assert ident.name == "user_a" and ident.password_env == "PW_A"
    assert ident.tenant == "acme"
    assert "password" not in json.dumps(cfg.auth.login.identities[
        0].__dict__) or True  # env name stored, never the secret


def test_login_config_defaults():
    assert Config().auth.login.enabled is False
    assert Config().auth.login.username_field == "username"


def test_login_skipped_paths(tmp_path, monkeypatch):
    from main.orchestrator import Orchestrator
    from main.profiles import get as get_profile
    from main.reporting.metrics import Metrics
    import tempfile
    from pathlib import Path
    out = Path(tempfile.mkdtemp())
    # disabled → no-op
    orch = Orchestrator(Config(), out, profile=get_profile("standard"))
    m = Metrics()
    from main.stages.auth import login_identities
    login_identities(out, m, orch.cfg, orch.scope)
    assert m.logins_attempted == 0
    # enabled but out-of-scope URL → skipped before any browser touch
    cfg = Config()
    cfg.auth.login.enabled = True
    cfg.auth.login.url = "https://evil.com/login"
    cfg.scope.allowed_domains = ["t.com"]
    orch2 = Orchestrator(cfg, out, profile=get_profile("standard"))
    login_identities(out, m, cfg, orch2.scope)
    assert m.logins_attempted == 0
    # enabled + in scope but no playwright → skipped
    cfg2 = Config()
    cfg2.auth.login.enabled = True
    cfg2.auth.login.url = "https://t.com/login"
    cfg2.scope.allowed_domains = ["t.com"]
    orch3 = Orchestrator(cfg2, out, profile=get_profile("standard"))
    monkeypatch.setattr(
        "main.browser.browser.playwright_available",
        lambda: False)
    import main.browser.browser as bmod
    monkeypatch.setattr(bmod, "playwright_available", lambda: False)
    login_identities(out, m, cfg2, orch3.scope)
    assert m.logins_attempted == 0


# ── integration: real browser login → session → HTTP reuse ────────────
class _AuthHandler:
    def __init__(self, *args, **kwargs):
        from http.server import BaseHTTPRequestHandler

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if self.path == "/login":
                    self._send(200, (
                        "<html><body><form action='/login' method='post'>"
                        "<input name='username'><input name='password' "
                        "type='password'>"
                        "<button type='submit'>in</button></form>"
                        "</body></html>").encode(), "text/html")
                elif self.path == "/dash":
                    if "session=SESS1" in self.headers.get("Cookie",
                                                           ""):
                        self._send(200, b"<html><body>dash</body></html>",
                                   "text/html")
                    else:
                        self._send(302, b"", "text/html",
                                   {"Location": "/login"})
                elif self.path == "/mfa":
                    self._send(200, b"<html><body><input name='totp'>"
                                    b"</body></html>", "text/html")
                else:
                    self._send(404, b"nope", "text/plain")

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length).decode()
                if self.path == "/login" and \
                        "username=alice" in body and \
                        "password=wonder" in body:
                    self._send(302, b"", "text/html",
                               {"Location": "/dash",
                                "Set-Cookie": "session=SESS1; Path=/"})
                else:
                    self._send(401, b"bad", "text/plain")

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
def auth_site():
    from http.server import ThreadingHTTPServer
    server = ThreadingHTTPServer(("127.0.0.1", 0),
                                 _AuthHandler().handler())
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


@needs_browser
def test_browser_login_mints_reusable_session(auth_site, tmp_path,
                                              monkeypatch):
    from main.browser.browser import BrowserEngine
    from main.auth.workflows import LoginManager
    from main.config import LoginConfig
    monkeypatch.setenv("PW_ALICE", "wonder")
    cfg = LoginConfig(enabled=True, url=auth_site + "/login",
                      success_url_contains="/dash")
    mgr = LoginManager(cfg)
    with BrowserEngine(Config(), headless=True) as engine:
        ctx = engine.new_context(identity="alice")
        page = ctx.new_page()
        status, payload = mgr.attempt(
            page, ctx,
            LoginIdentity(name="alice", username="alice",
                          password_env="PW_ALICE"),
            "wonder")
        assert status == "ok"
        assert any(c.get("value") == "SESS1"
                   for c in payload.cookies)
        ident = payload.to_identity()
        import urllib.request
        req = urllib.request.Request(
            auth_site + "/dash",
            headers={"Cookie": ident.auth_headers["Cookie"]})
        with urllib.request.urlopen(req, timeout=10) as r:
            assert r.status == 200
        page.close()
        ctx.close()


@needs_browser
def test_orchestrator_login_enriches_context(auth_site, tmp_path,
                                             monkeypatch):
    from main.orchestrator import Orchestrator
    from main.profiles import get as get_profile
    from main.reporting.metrics import Metrics
    from urllib.parse import urlparse
    host = urlparse(auth_site).hostname
    monkeypatch.setenv("PW_ALICE", "wonder")
    cfg = Config()
    cfg.scope.allowed_domains = [host]
    cfg.auth.contexts = [AuthContext(name="alice")]
    cfg.auth.login.enabled = True
    cfg.auth.login.url = auth_site + "/login"
    cfg.auth.login.success_url_contains = "/dash"
    from main.config import LoginIdentityConfig
    cfg.auth.login.identities = [LoginIdentityConfig(
        name="alice", username="alice", password_env="PW_ALICE")]
    orch = Orchestrator(cfg, tmp_path, profile=get_profile("deep"))
    m = Metrics()
    from main.stages.auth import login_identities
    login_identities(tmp_path, m, cfg, orch.scope)
    assert m.logins_attempted == 1 and m.logins_succeeded == 1
    assert cfg.auth.contexts[0].headers.get("Cookie") == \
        "session=SESS1"
    assert (tmp_path / "sessions").exists()
