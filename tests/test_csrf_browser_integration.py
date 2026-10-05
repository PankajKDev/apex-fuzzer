"""Real Chromium CSRF checks: null-origin submit with victim cookies.

A loopback HTTP(S) server stands in for the target; the attacker
page is fulfilled in-route by the prover (never hosted). SameSite
semantics are real: Lax cookies stay home on cross-site POST
(denied), SameSite=None+Secure cookies ride along (executed).
"""
from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest

from main.config import Config
from main.validation import csrf_browser


if importlib.util.find_spec("playwright") is None:
    pytest.skip("install the browser extra to run Chromium integration",
                allow_module_level=True)


class _Handler(BaseHTTPRequestHandler):
    seen = []

    def log_message(self, *a):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        cookie = self.headers.get("Cookie") or ""
        type(self).seen.append(cookie)
        if "session=" in cookie:
            body = b'{"ok":true}'
            self.send_response(200)
        else:
            body = b'{"error":"login required"}'
            self.send_response(403)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _serve(secure: bool, tmp_path):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    if secure:
        key, cert = str(tmp_path / "k.pem"), str(tmp_path / "c.pem")
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048",
             "-keyout", key, "-out", cert, "-days", "1", "-nodes",
             "-subj", "/CN=127.0.0.1"],
            check=True, capture_output=True, timeout=60)
        import ssl
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket,
                                            server_side=True)
    thread = threading.Thread(target=server.serve_forever,
                              kwargs={"poll_interval": 0.05},
                              daemon=True)
    thread.start()
    return server


def _cfg(tmp_path):
    chromium = shutil.which("chromium")
    if not chromium:
        pytest.skip("system Chromium is required")
    cfg = Config()
    cfg.browser.chromium_executable_path = chromium
    return cfg


def test_chromium_denies_lax_cookie_cross_site_post(tmp_path):
    server = _serve(False, tmp_path)
    try:
        port = server.server_address[1]
        target = f"http://127.0.0.1:{port}/submit"
        identity = SimpleNamespace(
            name="victim",
            auth_headers={"Cookie": "session=VICTIM-SECRET"},
            storage_state="")
        result = csrf_browser.prove_csrf_execution(
            target, "POST", {"comment": "1"}, identity, _cfg(tmp_path),
            timeout_ms=8000)
    finally:
        server.shutdown()
    assert result["status"] == "denied", result
    assert result["cookie_sent"] is False


def test_chromium_executes_with_cross_site_cookie(tmp_path):
    if not shutil.which("openssl"):
        pytest.skip("openssl is required to mint the fixture cert")
    server = _serve(True, tmp_path)
    try:
        port = server.server_address[1]
        target = f"https://127.0.0.1:{port}/submit"
        state = tmp_path / "storage-state.json"
        state.write_text(json.dumps({
            "cookies": [{
                "name": "session", "value": "VICTIM-SECRET",
                "domain": "127.0.0.1", "path": "/", "expires": -1,
                "httpOnly": True, "secure": True,
                "sameSite": "None"}],
            "origins": [],
        }), encoding="utf-8")
        identity = SimpleNamespace(name="victim", auth_headers={},
                                   storage_state=str(state))
        result = csrf_browser.prove_csrf_execution(
            target, "POST", {"comment": "1"}, identity, _cfg(tmp_path),
            timeout_ms=8000)
    finally:
        server.shutdown()
    assert result["status"] == "executed", result
    assert result["cookie_sent"] is True
    assert result["response_status"] == 200
