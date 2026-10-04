"""Open redirect validator checks use synthetic HTTP responses only."""
from urllib.parse import parse_qs, urlparse

from apex_fuzzer.discovery.url_normalizer import normalize_url
from apex_fuzzer.models import Endpoint, Parameter
from apex_fuzzer.reporting.coverage import CoverageTracker
from apex_fuzzer.reporting.metrics import Metrics
from apex_fuzzer.scope import Scope
from apex_fuzzer.config import Config
from apex_fuzzer.validation.evidence import EvidenceStore
from apex_fuzzer.validation.open_redirect import (
    _is_external_marker, probe_open_redirects)


class Response:
    def __init__(self, status=200, headers=None):
        self.status_code = status
        self.headers = headers or {}
        self.text = ""


class Http:
    def __init__(self, status=302, location=""):
        self.status = status
        self.location = location
        self.calls = []
        self.error = None

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if self.error:
            raise self.error
        parsed = parse_qs(urlparse(url).query)
        marker = urlparse(parsed["next"][0]).netloc
        location = self.location.replace("{marker}", marker)
        return Response(self.status, {"Location": location} if location else {})


def endpoint(url="https://app.example.com/login?next=%2Fhome&x=1",
             params=None, method="GET"):
    parsed = urlparse(url)
    return Endpoint(url=url, normalized_url=normalize_url(url),
                    host=parsed.hostname or "", path=parsed.path,
                    method=method,
                    query_parameters=[Parameter(name=p, location="query")
                                      for p in (params or ["next", "x"])])


def run_probe(tmp_path, http, endpoints=None, **caps):
    metrics, coverage = Metrics(), CoverageTracker()
    cfg = Config().scope
    cfg.allowed_domains = ["app.example.com"]
    findings = probe_open_redirects(
        endpoints or [endpoint()], http, EvidenceStore(tmp_path / "proofs"),
        metrics, coverage, Scope(cfg), timeout=4, **caps)
    return findings, metrics, coverage


def test_confirms_exact_external_marker_and_records_evidence(tmp_path):
    http = Http(location="https://{marker}/path")
    findings, metrics, coverage = run_probe(tmp_path, http)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.parameter == "next"
    assert finding.validation_status == "confirmed"
    assert finding.raw["followed_redirects"] is False
    assert http.calls[0][1] == {"timeout": 4}
    assert metrics.validated_confirmed == 1
    assert coverage.status["open_redirect"] == "confirmed"
    assert (tmp_path / "proofs/finding-001/metadata.json").exists()


def test_requires_browser_redirect_status_and_exact_host():
    assert _is_external_marker(
        302, "//apex-a.invalid/", "apex-a.invalid",
        "https://app.example.com/")
    assert not _is_external_marker(
        304, "https://apex-a.invalid/", "apex-a.invalid",
        "https://app.example.com/")
    assert not _is_external_marker(
        302, "https://apex-a.invalid.evil.test/", "apex-a.invalid",
        "https://app.example.com/")


def test_non_external_location_is_a_tested_negative(tmp_path):
    http = Http(location="https://app.example.com/home")
    findings, _, coverage = run_probe(tmp_path, http)
    assert findings == []
    assert coverage.status["open_redirect"] == "tested_negative"


def test_only_observed_query_fields_get_tested(tmp_path):
    ep = endpoint(params=["next", "return_to", "not_present"])
    http = Http(location="https://app.example.com/home")
    run_probe(tmp_path, http, [ep])
    assert len(http.calls) == 1


def test_caps_endpoint_and_parameter_counts(tmp_path):
    ep = endpoint("https://app.example.com/?next=/&return_to=/&url=/",
                  ["next", "return_to", "url"])
    http = Http(location="https://app.example.com/home")
    run_probe(tmp_path, http, [ep], max_endpoints=99, max_params=99)
    assert len(http.calls) == 3


def test_skips_non_get_out_of_scope_and_handles_errors(tmp_path):
    post = endpoint(method="POST")
    outside = endpoint("https://outside.invalid/?next=/", ["next"])
    http = Http()
    _, _, coverage = run_probe(tmp_path, http, [post, outside])
    assert http.calls == []
    assert coverage.status["open_redirect"] == "untestable"

    http = Http()
    http.error = TimeoutError("timeout")
    _, _, coverage = run_probe(tmp_path, http)
    assert coverage.status["open_redirect"] == "inconclusive"
