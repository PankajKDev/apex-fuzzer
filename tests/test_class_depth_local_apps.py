"""Loopback-only integration checks against real parsers and file handling.

Run with the ``integration`` extra installed. Every request stays on the
ephemeral local HTTP server created by the fixture.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest
import requests

from main.config import Config
from main.models import Endpoint, Finding
from main.plugins.adapters import _xxe_candidate_from
from main.plugins.base import TestTarget
from main.validation.base import Candidate
from main.validation.path_traversal import PathTraversalValidator
from main.validation.ssti import SstiValidator
from main.validation.xxe import XxeValidator


MARKER = "APEX_LOCAL_INTEGRATION_MARKER_2026"


@pytest.fixture
def local_lab(tmp_path):
    hits = []
    app_root = tmp_path / "app"
    docs = app_root / "docs"
    docs.mkdir(parents=True)
    (app_root / "apex-marker.txt").write_text(MARKER, encoding="utf-8")
    (docs / "hello.txt").write_text("ordinary file", encoding="utf-8")

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def _send(self, status, body):
            data = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            parsed = urlsplit(self.path)
            if parsed.path == "/render":
                jinja2 = pytest.importorskip("jinja2")
                value = parse_qs(parsed.query, keep_blank_values=True).get(
                    "name", [""])[0]
                # Deliberately vulnerable lab sink: user input is compiled as
                # template source, as in render_template_string(f"Hi {name}").
                self._send(200, jinja2.Template("Hello " + value).render())
                return
            if parsed.path == "/download":
                value = parse_qs(parsed.query, keep_blank_values=True).get(
                    "file", [""])[0]
                try:
                    body = (docs / value).resolve().read_text(encoding="utf-8")
                except (OSError, UnicodeError):
                    self._send(404, "not found")
                    return
                self._send(200, body)
                return
            if parsed.path.startswith("/stored/"):
                hits.append(parsed.path)
                self._send(200, "callback recorded")
                return
            self._send(404, "not found")

        def do_POST(self):
            parsed = urlsplit(self.path)
            size = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(size)
            if parsed.path != "/import":
                self._send(404, "not found")
                return
            lxml = pytest.importorskip("lxml.etree")
            # This controlled endpoint models a vulnerable parser. lxml builds
            # often omit libxml2 HTTP support, so the resolver supplies the
            # same fetch behavior but permits only this server's callback path.
            parser = lxml.XMLParser(resolve_entities=True, load_dtd=True,
                                    no_network=False)

            class LoopbackOnlyResolver(lxml.Resolver):
                def resolve(self, url, _public_id, context):
                    callback = urlsplit(url)
                    if (callback.hostname != "127.0.0.1" or
                            callback.port != self_port or
                            not callback.path.startswith("/stored/")):
                        raise OSError("external entity outside loopback fixture")
                    requests.get(url, timeout=2)
                    return self.resolve_string("", context)

            self_port = self.server.server_address[1]
            parser.resolvers.add(LoopbackOnlyResolver())
            try:
                root = lxml.fromstring(body, parser=parser)
            except lxml.XMLSyntaxError:
                self._send(400, "XML rejected")
                return
            self._send(200, "parsed " + (root.text or ""))

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[0], server.server_address[1], hits
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _url(lab, path):
    return f"http://{lab[0]}:{lab[1]}{path}"


def _candidate(url, test_class, parameter=None, method="GET", **kwargs):
    finding = Finding(id=f"local-{test_class}", source="integration",
                      name=f"Local {test_class} fixture", parameter=parameter,
                      method=method, request_body=kwargs.get("request_body"))
    return Candidate(finding=finding, test_class=test_class, endpoint_url=url,
                     parameter=parameter, method=method, **kwargs)


def test_real_jinja_template_engine_confirms_paired_arithmetic(local_lab):
    pytest.importorskip("jinja2")
    cfg = Config()
    outcome = SstiValidator(cfg, requests.Session()).validate(_candidate(
        _url(local_lab, "/render?name=sample"), "ssti", "name"))

    assert outcome.status == "confirmed"
    assert outcome.evidence["syntax"] == "double-curly"
    assert outcome.evidence["expressions"] == ["7*7 -> 49", "7+7 -> 14"]


class LocalOast:
    def __init__(self, base, hits):
        self.base = base
        self.hits = hits

    def available(self):
        return True

    def create_token(self):
        return self.base

    @staticmethod
    def correlation_key(callback):
        return urlsplit(callback).path.rsplit("/", 1)[-1]

    def poll(self, **_kwargs):
        return [{"full-id": self.correlation_key(f"http://lab/stored/{path}"),
                 "proto": "http"} for path in self.hits]


def test_real_lxml_parser_resolves_only_loopback_oast_callback(local_lab):
    pytest.importorskip("lxml.etree")
    base = f"http://{local_lab[0]}:{local_lab[1]}"
    provider = LocalOast(base, local_lab[2])
    cfg = Config()
    cfg.safety.allow_state_change = True
    body = "<root><name>sample</name></root>"
    endpoint_url = _url(local_lab, "/import")
    finding = Finding(
        id="local-nuclei-xxe", source="nuclei", method="HTTP",
        raw={"request": ("POST /import HTTP/1.1\r\n"
                          "Content-Type: application/xml\r\n\r\n" + body)})
    endpoint = Endpoint(url=endpoint_url, normalized_url=endpoint_url,
                        method="GET")
    target = TestTarget(endpoint_url, method="HTTP", finding=finding,
                        endpoint=endpoint, test_class="xxe")
    candidate = _xxe_candidate_from(target)
    assert candidate.method == "POST"
    assert candidate.request_content_type == "application/xml"
    assert candidate.request_body == body

    outcome = XxeValidator(cfg, requests.Session(), provider).validate(candidate)

    assert outcome.status == "confirmed", (outcome.notes, outcome.evidence)
    assert outcome.evidence["interaction_protocols"] == ["http"]
    assert len(local_lab[2]) == 1
    assert local_lab[2][0].startswith("/stored/")


def test_real_local_file_endpoint_reads_only_operator_marker(local_lab):
    cfg = Config()
    cfg.validation.path_traversal_marker_path = "apex-marker.txt"
    cfg.validation.path_traversal_marker_content = MARKER
    cfg.validation.path_traversal_max_depth = 4
    candidate = _candidate(
        _url(local_lab, "/download?file=hello.txt"), "path_traversal",
        "file", parameter_location="query")

    outcome = PathTraversalValidator(cfg, requests.Session()).validate(candidate)

    assert outcome.status == "confirmed"
    assert outcome.evidence["marker_path"] == "apex-marker.txt"
    assert outcome.evidence["response_body_recorded"] is False
    assert MARKER not in json.dumps(outcome.evidence)
