"""Multipart capture slice: parser + recorder + no-replay guards.

In-memory fixtures and test doubles only. No network or public targets.
"""
import json

from main.browser.network import (
    NetworkRecorder, parse_multipart, _form_names)
from main.config import Config
from main.models import Endpoint, Finding
from main.validation import request_shape as shape_mod
from main.validation import sqli as sqli_mod
from main.validation import mutate as mut_mod
from main.validation.base import Candidate


BOUNDARY = "bound123"


def _multipart_body():
    lines = [
        "--bound123",
        'Content-Disposition: form-data; name="title"',
        "",
        "hello",
        "--bound123",
        'Content-Disposition: form-data; name="upload"; '
        'filename="report.pdf"',
        "Content-Type: application/pdf",
        "",
        "%PDF-1.4-binary-bytes",
        "--bound123",
        'Content-Disposition: form-data; name="csrf_token"',
        "",
        "csrf-secret-value",
        "--bound123--",
        "",
    ]
    return "\r\n".join(lines).encode("utf-8")


def _headers():
    return {"Content-Type": "multipart/form-data; boundary=bound123"}


class _FakeRequest:
    def __init__(self, url, method="POST", headers=None, post_data=None,
                 resource_type="xhr"):
        self.url = url
        self.method = method
        self.headers = headers or {}
        self.post_data = post_data
        self.resource_type = resource_type


def _scope_for(hosts):
    from main.scope import Scope
    from main.config import ScopeConfig
    return Scope(ScopeConfig(allowed_domains=list(hosts)))


def test_parse_multipart_extracts_shape_without_file_contents():
    fields, parts = parse_multipart(_multipart_body(), _headers())
    assert fields["title"] == "hello"
    # File parts never contribute content; secrets never contribute values.
    assert fields["upload"] == ""
    assert fields["csrf_token"] == ""
    by_name = {p["name"]: p for p in parts}
    assert by_name["upload"]["filename"] == "report.pdf"
    assert by_name["upload"]["content_type"] == "application/pdf"
    assert by_name["upload"]["size"] > 0
    assert by_name["title"]["filename"] == ""
    assert "%PDF-1.4" not in json.dumps(fields)
    assert "csrf-secret-value" not in json.dumps(fields)
    assert "csrf-secret-value" not in json.dumps(parts)


def test_parse_multipart_fails_closed():
    fields, parts = parse_multipart(b"not-multipart",
                                    {"Content-Type": "text/plain"})
    assert (fields, parts) == ({}, [])
    fields, parts = parse_multipart(_multipart_body(),
                                    {"Content-Type":
                                     "multipart/form-data"})
    assert (fields, parts) == ({}, [])
    oversized = b"x" * 1_000_001
    fields, parts = parse_multipart(oversized, _headers())
    assert (fields, parts) == ({}, [])
    # Non-multipart fallback keeps existing urlencoded behavior.
    assert _form_names("a=1", {"Content-Type": "text/plain"}) == {"a": "1"}


def test_file_payload_boundary_like_bytes_and_empty_filename_are_not_fields():
    payload = b"prefix--bound123inside-file\r\n--bound123-not-a-delimiter"
    body = (b"--bound123\r\n"
            b'Content-Disposition: form-data; name="upload"; filename=""\r\n'
            b"Content-Type: application/octet-stream\r\n\r\n" + payload +
            b"\r\n--bound123--\r\n")
    fields, parts = parse_multipart(body, _headers())
    assert fields == {"upload": ""}
    assert len(parts) == 1
    assert parts[0]["size"] == len(payload)


def test_recorder_retains_bytes_runtime_only_and_redacts_artifacts():
    rec = NetworkRecorder(scope=_scope_for(["example.com"]))
    body = _multipart_body()
    rec._on_request(_FakeRequest(
        "https://user:pass@example.com/upload?access_token=url-secret"
        "&page=2#frag-secret",
        headers={"Content-Type": _headers()["Content-Type"],
                 "Authorization": "Bearer header-secret"},
        post_data=body))
    endpoints = rec.to_endpoints()
    assert len(endpoints) == 1
    runtime = endpoints[0]["observed_requests"][0]
    assert runtime["post_data"] == body
    assert {p["name"] for p in runtime["multipart"]} == {
        "title", "upload", "csrf_token"}
    # Endpoint parameter model carries field names without file content.
    assert endpoints[0]["body"]["title"] == "hello"
    assert endpoints[0]["body"]["upload"] == ""
    assert endpoints[0]["body"]["csrf_token"] == ""

    persisted = json.dumps(rec.to_dict())
    for secret in ("header-secret", "url-secret", "user:pass",
                   "frag-secret", "%PDF-1.4", "csrf-secret-value"):
        assert secret not in persisted
    assert '"post_data": null' in persisted
    assert "post_data_length" in persisted
    assert "report.pdf" in persisted
    assert "application/pdf" in persisted


def test_recorder_prefers_exact_playwright_post_data_buffer():
    raw = _multipart_body()
    request = type("BufferedRequest", (), {
        "url": "https://example.com/upload",
        "method": "POST",
        "headers": _headers(),
        "post_data_buffer": raw,
        "post_data": "lossy-text-fallback",
        "resource_type": "xhr",
    })()
    recorder = NetworkRecorder(scope=_scope_for(["example.com"]))
    recorder._on_request(request)
    assert recorder.requests[0].post_data == raw


def test_authenticated_multipart_values_are_blanked():
    rec = NetworkRecorder(scope=_scope_for(["example.com"]),
                          identity="alice")
    rec._on_request(_FakeRequest(
        "https://example.com/upload", headers=_headers(),
        post_data=_multipart_body()))
    endpoints = rec.to_endpoints()
    assert endpoints[0]["body"]["title"] == ""
    runtime = endpoints[0]["observed_requests"][0]
    assert runtime["identity"] == "alice"
    assert runtime["post_data"] == _multipart_body()


def test_merge_browser_entry_keeps_multipart_runtime_only():
    from main.discovery.url_normalizer import normalize_url
    from main.stages.endpoints import merge_browser_entry
    url = "https://example.com/upload"
    endpoint = Endpoint(url=url, normalized_url=normalize_url(url))
    entry = {"url": url, "method": "POST", "params": [],
             "body": {"title": "hello", "upload": ""},
             "observed_requests": [{
                 "identity": "anonymous", "method": "POST", "url": url,
                 "headers": {"Content-Type": _headers()["Content-Type"]},
                 "post_data": _multipart_body(),
                 "multipart": [{"name": "upload", "filename": "r.pdf",
                                "content_type": "application/pdf",
                                "size": 20}]}]}
    merge_browser_entry(
        {normalize_url(url): endpoint}, "example.com", entry)
    assert {p.name for p in endpoint.body_parameters} == {
        "title", "upload"}
    upload = next(p for p in endpoint.body_parameters
                  if p.name == "upload")
    assert upload.sample_value == ""
    assert endpoint.observed_requests[0]["post_data"] == _multipart_body()
    assert "observed_requests" not in endpoint.to_dict()


def test_multipart_has_no_validation_or_replay():
    candidate = Candidate(
        finding=Finding(id="mp1", source="test"), test_class="sqli",
        endpoint_url="https://example.test/upload", parameter="title",
        method="POST", parameter_location="body",
        request_content_type="multipart/form-data; boundary=bound123",
        request_body="retained")
    assert shape_mod.is_multipart(candidate) is True
    for fn in (lambda: shape_mod.body_with_parameter(candidate, "t", "v"),
               lambda: shape_mod.body_parameter_value(candidate, "t")):
        try:
            fn()
        except ValueError:
            pass
        else:
            raise AssertionError("multipart shaping must fail closed")

    class NoNet:
        def __init__(self):
            self.calls = 0

        def request(self, *a, **k):
            self.calls += 1
            raise AssertionError("multipart must not send requests")

    cfg = Config()
    cfg.safety.allow_state_change = True
    outcome = mut_mod.MutationEngine(cfg, NoNet()).prescreen_sqli(candidate)
    assert outcome is not None and outcome.status == "inconclusive"
    assert "multipart" in outcome.notes.lower()
    result = sqli_mod.SqliValidator(cfg).validate(candidate)
    assert result.status == "inconclusive"
    assert "multipart" in result.notes.lower()
