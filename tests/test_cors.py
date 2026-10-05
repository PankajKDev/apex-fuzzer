"""CORS validator tests use local fakes and never issue network requests."""
import json
from pathlib import Path
from urllib.parse import urlparse

from main.config import Config
from main.discovery.url_normalizer import normalize_url
from main.models import Endpoint, Identity
from main.reporting.coverage import CoverageTracker
from main.reporting.metrics import Metrics
from main.scope import Scope
from main.validation.cors import probe_cors
from main.validation.evidence import EvidenceStore


class Response:
    def __init__(self, status=200, headers=None, text="private profile"):
        self.status_code = status
        self.headers = headers or {}
        self.text = text


class Http:
    def __init__(self, responder=None, error=None):
        self.responder = responder or (lambda _url, _kwargs: Response())
        self.error = error
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if self.error:
            raise self.error
        return self.responder(url, kwargs)


def endpoint(url="https://app.example.com/api/profile", method="GET"):
    parsed = urlparse(url)
    return Endpoint(url=url, normalized_url=normalize_url(url),
                    host=parsed.hostname or "", path=parsed.path,
                    method=method)


def run_probe(tmp_path, http, endpoints=None, identities=None, **caps):
    metrics, coverage = Metrics(), CoverageTracker()
    cfg = Config().scope
    cfg.allowed_domains = ["app.example.com"]
    findings = probe_cors(
        endpoints or [endpoint()], http,
        EvidenceStore(tmp_path / "proofs"), metrics, coverage,
        Scope(cfg), identities or [Identity(
            name="alice", auth_headers={"Cookie": "session=secret"})],
        timeout=5, **caps)
    return findings, metrics, coverage


def reflected(url, _kwargs):
    origin = next(v for k, v in _kwargs["headers"].items()
                  if k.lower() == "origin")
    return Response(headers={
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Allow-Headers": "content-type",
        "Access-Control-Allow-Methods": "GET",
        "Vary": "Origin",
    })


def test_reflection_with_cookie_credentials_is_candidate_and_redacts_body(
        tmp_path):
    http = Http(reflected)
    findings, metrics, coverage = run_probe(tmp_path, http)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.validation_status == "strong_candidate"
    assert finding.confidence == "probable"
    assert finding.identity == "alice"
    assert finding.raw["response_body_recorded"] is False
    assert "Access-Control-Allow-Headers" in finding.response_headers
    assert coverage.status["cors"] == "candidate"
    assert metrics.validation_candidates == 1
    request_headers = http.calls[0][1]["headers"]
    assert request_headers["Cookie"] == "session=secret"
    assert request_headers["Origin"].endswith(".invalid")
    proof = Path(finding.evidence_dir)
    assert "private profile" not in (proof / "response.txt").read_text()
    assert "session=secret" not in (proof / "request.txt").read_text()
    metadata = json.loads((proof / "metadata.json").read_text())
    assert "Cookie" not in metadata["response_headers"]


def test_wildcard_or_missing_credentials_header_is_not_a_finding(tmp_path):
    for headers in (
            {"Access-Control-Allow-Origin": "*",
             "Access-Control-Allow-Credentials": "true"},
            {"Access-Control-Allow-Origin": "https://attacker.invalid"}):
        http = Http(lambda _url, _kwargs: Response(headers=headers))
        findings, _, coverage = run_probe(tmp_path / str(len(headers)), http)
        assert findings == []
        assert coverage.status["cors"] == "tested_negative"


def test_no_cookie_identity_is_untestable(tmp_path):
    http = Http(reflected)
    findings, _, coverage = run_probe(
        tmp_path, http, identities=[Identity(name="anonymous")])
    assert findings == []
    assert http.calls == []
    assert coverage.status["cors"] == "untestable"


def test_skips_out_of_scope_and_non_get_endpoints(tmp_path):
    http = Http(reflected)
    findings, _, coverage = run_probe(tmp_path, http, [
        endpoint(method="POST"), endpoint("https://outside.invalid/profile")])
    assert findings == []
    assert http.calls == []
    assert coverage.status["cors"] == "untestable"


def test_caps_endpoints_and_authenticated_identities(tmp_path):
    eps = [endpoint(f"https://app.example.com/api/profile/{i}")
           for i in range(12)]
    identities = [Identity(name=f"user{i}", auth_headers={
        "Cookie": f"session={i}"}) for i in range(5)]
    http = Http(reflected)
    run_probe(tmp_path, http, eps, identities,
              max_endpoints=100, max_identities=100)
    assert len(http.calls) == 30  # hard cap: 10 endpoints × 3 identities


def test_request_error_is_inconclusive(tmp_path):
    http = Http(error=TimeoutError("timeout"))
    findings, _, coverage = run_probe(tmp_path, http)
    assert findings == []
    assert coverage.status["cors"] == "inconclusive"
