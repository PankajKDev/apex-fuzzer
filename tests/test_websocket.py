"""WebSocket handshake layer: auth boundary + origin validation.

No message frames are ever spoken — only HTTP Upgrade handshakes,
read-only. The live test speaks a real 101 over loopback to prove
the transport mechanism.
"""
import json
import socket
import threading
from types import SimpleNamespace

from main.budgets import BudgetExceeded, BudgetTracker
from main.config import Config, ScopeConfig
from main.reporting.coverage import CoverageTracker
from main.reporting.metrics import Metrics
from main.scope import Scope
from main.stages.validation import ProbeControls
from main.stages.validation.websocket import websocket_probe
from main.validation import websocket as ws_mod
from main.validation.evidence import EvidenceStore


def _scope():
    return Scope(ScopeConfig(allowed_domains=["example.test"]))


def _resp(status=200, headers=None):
    return SimpleNamespace(status_code=status, text="", headers=headers)


def test_ws_url_mapping():
    assert ws_mod.ws_http_url("ws://example.test/socket") == \
        "http://example.test/socket"
    assert ws_mod.ws_http_url("wss://example.test:8443/a?q=1") == \
        "https://example.test:8443/a?q=1"
    assert ws_mod.ws_http_url("wss://example.test/x") == \
        "https://example.test/x"
    assert ws_mod.ws_http_url("ws://user@example.test/x") is None
    assert ws_mod.ws_http_url("https://example.test/x") is None
    assert ws_mod.ws_http_url("not a url") is None


def test_handshake_accept_and_refusal():
    accept = _resp(101, {"Upgrade": "websocket",
                         "Sec-WebSocket-Accept": "abc="})

    class Http:
        def get(self, url, **kwargs):
            assert kwargs["headers"]["Upgrade"] == "websocket"
            assert kwargs["headers"]["Sec-WebSocket-Version"] == "13"
            return accept

    out = ws_mod.check_ws_handshake(
        Http(), "http://example.test/socket", {}, "anon")
    assert out.accepted is True
    assert out.status == 101

    class Denied:
        def get(self, url, **kwargs):
            return _resp(401, {})

    out = ws_mod.check_ws_handshake(
        Denied(), "http://example.test/socket", {}, "anon")
    assert out.accepted is False

    class Broke:
        def get(self, *a, **k):
            raise ConnectionError("down")

    out = ws_mod.check_ws_handshake(
        Broke(), "http://example.test/socket", {}, "anon")
    assert out.accepted is False
    assert "failed" in out.notes


def test_budget_propagates():
    class Http:
        def get(self, *a, **k):
            raise BudgetExceeded("spent")

    try:
        ws_mod.check_ws_handshake(
            Http(), "http://example.test/socket", {}, "anon")
    except BudgetExceeded:
        return
    raise AssertionError("BudgetExceeded must propagate")


def test_target_dedupe_and_cap():
    urls = ["ws://example.test/a", "ws://example.test/a",
            "wss://example.test/b", "https://example.test/c"]
    assert ws_mod.ws_targets(urls) == ["http://example.test/a",
                                       "https://example.test/b"]


def _traffic(tmp_path, sockets):
    (tmp_path / "browser_traffic.json").write_text(json.dumps(
        {"websockets": sockets}))


def _identities():
    return [SimpleNamespace(name="anonymous", auth_headers={}),
            SimpleNamespace(name="member",
                            auth_headers={"Cookie": "s=M"})]


def _run(tmp_path, http, identities=None, scope=None):
    cfg = Config()
    coverage = CoverageTracker()
    out = websocket_probe(
        tmp_path, EvidenceStore(tmp_path / "p"), Metrics(),
        BudgetTracker(cfg), coverage, http, cfg, scope or _scope(),
        ProbeControls(), identities if identities is not None
        else _identities())
    return out, coverage


def test_anonymous_privileged_accept_is_candidate(tmp_path):
    class Http:
        def get(self, url, **kwargs):
            return _resp(101, {"Upgrade": "websocket",
                               "Sec-WebSocket-Accept": "x"})

    _traffic(tmp_path, ["ws://example.test/admin/socket"])
    out, coverage = _run(tmp_path, Http())
    assert len(out) == 1
    assert out[0].source == "websocket-handshake"
    assert out[0].severity == "high"
    assert coverage.summary()["websocket"] == "candidate"


def test_authed_only_plus_evil_origin_is_hijack(tmp_path):
    class Http:
        def get(self, url, **kwargs):
            headers = kwargs.get("headers") or {}
            if "Origin" in headers:
                assert headers["Origin"] == ws_mod.EVIL_ORIGIN
                return _resp(101, {"Upgrade": "websocket",
                                   "Sec-WebSocket-Accept": "x"})
            if "Cookie" in headers:
                return _resp(101, {"Upgrade": "websocket",
                                   "Sec-WebSocket-Accept": "x"})
            return _resp(401, {})

    _traffic(tmp_path, ["ws://example.test/api/feed"])
    out, coverage = _run(tmp_path, Http())
    assert len(out) == 1
    assert out[0].source == "websocket-origin"
    assert coverage.summary()["websocket"] == "candidate"


def test_evil_origin_refused_is_negative(tmp_path):
    class Http:
        def get(self, url, **kwargs):
            headers = kwargs.get("headers") or {}
            if "Origin" in headers:
                return _resp(403, {})
            if "Cookie" in headers:
                return _resp(101, {"Upgrade": "websocket",
                                   "Sec-WebSocket-Accept": "x"})
            return _resp(401, {})

    _traffic(tmp_path, ["ws://example.test/api/feed"])
    out, coverage = _run(tmp_path, Http())
    assert out == []
    assert coverage.summary()["websocket"] == "tested_negative"


def test_public_socket_is_negative(tmp_path):
    class Http:
        def get(self, url, **kwargs):
            return _resp(101, {"Upgrade": "websocket",
                               "Sec-WebSocket-Accept": "x"})

    _traffic(tmp_path, ["ws://example.test/echo"])
    out, coverage = _run(tmp_path, Http())
    assert out == []
    assert coverage.summary()["websocket"] == "tested_negative"


def test_no_traffic_is_untestable(tmp_path):
    cfg = Config()
    coverage = CoverageTracker()
    out = websocket_probe(
        tmp_path, EvidenceStore(tmp_path / "p"), Metrics(),
        BudgetTracker(cfg), coverage, None, cfg, _scope(),
        ProbeControls(), _identities())
    assert out == []
    assert coverage.summary()["websocket"] == "untestable"


def test_reviews_map_websocket_findings():
    from main.models import Finding
    from main.reporting.reviews import finding_test_class
    assert finding_test_class(
        Finding(id="a", source="websocket-handshake",
                tags=["websocket"])) == "websocket"


def test_plan_accounts_websocket_requests():
    from main.safety.preflight import plan_websocket
    assert plan_websocket(4, 3).total == 20


class _UpgradeServer:
    """Minimal loopback WebSocket acceptor: 101 when Cookie present."""

    def __init__(self):
        self.seen = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        self.sock.settimeout(5)
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            try:
                data = b""
                while b"\r\n\r\n" not in data and len(data) < 32768:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                head = data.decode("latin-1", "replace")
                headers = {}
                for line in head.split("\r\n")[1:]:
                    if ":" in line:
                        name, _, value = line.partition(":")
                        headers[name.strip().lower()] = value.strip()
                self.seen.append(headers)
                if headers.get("upgrade", "").lower() == "websocket" \
                        and "cookie" in headers:
                    conn.sendall(
                        b"HTTP/1.1 101 Switching Protocols\r\n"
                        b"Upgrade: websocket\r\n"
                        b"Sec-WebSocket-Accept: test=\r\n"
                        b"Connection: close\r\n\r\n")
                else:
                    conn.sendall(b"HTTP/1.1 401 Unauthorized\r\n"
                                b"Content-Length: 0\r\n"
                                b"Connection: close\r\n\r\n")
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def stop(self):
        try:
            self.sock.close()
        except OSError:
            pass


def test_live_loopback_handshake_101(tmp_path):
    from main.http import HTTPClient
    server = _UpgradeServer()
    server.thread.start()

    def _client():
        return HTTPClient(scope=Scope(ScopeConfig()),
                          allow_private_targets=True)

    try:
        url = f"http://127.0.0.1:{server.port}/socket"
        authed = ws_mod.check_ws_handshake(
            _client(), url, {"Cookie": "session=V"}, "member")
        assert authed.accepted is True, authed.notes
        anon = ws_mod.check_ws_handshake(_client(), url, {},
                                         "anonymous")
        assert anon.accepted is False
        assert anon.status == 401
        assert any("cookie" in headers for headers in server.seen)
    finally:
        server.stop()
