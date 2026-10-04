"""Real Chromium CORS checks with a hermetic loopback-origin route fixture."""
from __future__ import annotations

import importlib.util
import json
import shutil
import uuid

import pytest

from apex_fuzzer.browser.browser import BrowserEngine
from apex_fuzzer.config import Config
from apex_fuzzer.models import Confidence, Finding, ValidationStatus
from apex_fuzzer.validation import cors_browser


if not importlib.util.find_spec("playwright"):
    pytest.skip("install the browser extra to run Chromium integration",
                allow_module_level=True)


class FixtureRoute:
    """Stand in for loopback HTTP after the verifier's guard inspects it."""

    def __init__(self, route, target_origin, request_log):
        self._route = route
        self.request = route.request
        self.target_origin = target_origin
        self.request_log = request_log

    def continue_(self):
        request = self.request
        if cors_browser._origin(request.url) != self.target_origin:
            self._route.abort()
            return
        origin = request.headers.get("origin", "")
        if request.method == "OPTIONS":
            self.request_log.append(("OPTIONS", False))
            self._route.fulfill(status=204, headers={
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
                "Access-Control-Allow-Methods": "GET",
                "Access-Control-Allow-Private-Network": "true",
                "Vary": "Origin",
            }, body="")
            return
        if request.method != "GET":
            self._route.abort()
            return
        has_cookie = bool(request.headers.get("cookie"))
        self.request_log.append(("GET", has_cookie))
        self._route.fulfill(
            status=200 if has_cookie else 401,
            headers={
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
                "Vary": "Origin",
                "Content-Type": "text/plain",
            },
            body="private profile data" if has_cookie else "login required")

    def abort(self):
        self._route.abort()

    def fulfill(self, **kwargs):
        self._route.fulfill(**kwargs)


class InterceptedContext:
    """Return local app responses while leaving CORS checks to Chromium."""

    def __init__(self, context, target_url, request_log):
        self.context = context
        self.target_origin = cors_browser._origin(target_url)
        self.request_log = request_log

    def route(self, pattern, handler):
        self.context.route(
            pattern,
            lambda route: handler(FixtureRoute(
                route, self.target_origin, self.request_log)))

    def __getattr__(self, name):
        return getattr(self.context, name)


def _candidate(url, origin):
    return Finding(
        id="cors-browser-fixture", source="cors-validator",
        name="Potential credentialed cross-origin data read",
        confidence=Confidence.PROBABLE.value,
        validation_status=ValidationStatus.STRONG_CANDIDATE.value,
        endpoint_url=url, matched_at=url, method="GET", identity="alice",
        response_headers={
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true"},
        raw={"origin": origin, "allow_origin": origin, "body_length": 19})


@pytest.mark.parametrize("same_site", ["None", "Lax"])
def test_chromium_proves_readability_only_with_cross_site_cookie(
        tmp_path, monkeypatch, same_site):
    chromium = shutil.which("chromium")
    if not chromium:
        pytest.skip("system Chromium is required")
    origin = f"https://apex-{uuid.uuid4().hex}.invalid"
    target_url = "https://127.0.0.1:65432/private"
    storage_state = tmp_path / "storage-state.json"
    storage_state.write_text(json.dumps({
        "cookies": [{
            "name": "session", "value": "local-secret",
            "domain": "127.0.0.1", "path": "/", "expires": -1,
            "httpOnly": True, "secure": True, "sameSite": same_site}],
        "origins": [],
    }), encoding="utf-8")
    cfg = Config()
    cfg.browser.chromium_executable_path = chromium
    cfg.browser.navigation_timeout_ms = 5000
    identity = type("TestIdentity", (), {
        "name": "alice", "storage_state": str(storage_state),
        "auth_headers": {"Cookie": "session=local-secret"}})()
    request_log = []

    class FixtureBrowserEngine(BrowserEngine):
        def new_context(self, *args, **kwargs):
            context = super().new_context(*args, **kwargs)
            return InterceptedContext(context, target_url, request_log)

    monkeypatch.setattr(cors_browser, "BrowserEngine", FixtureBrowserEngine)
    result = cors_browser.confirm_cors_readability(
        _candidate(target_url, origin), identity, cfg, timeout_ms=5000)

    if same_site == "None":
        assert result["status"] == "confirmed", result
        assert result["cookie_sent"] is True
        assert result["response_length"] > 0
        assert any(method == "GET" and cookie
                   for method, cookie in request_log)
    else:
        assert result["status"] == "not_confirmed", result
        assert result["cookie_sent"] is False
        assert not any(method == "GET" and cookie
                       for method, cookie in request_log)
