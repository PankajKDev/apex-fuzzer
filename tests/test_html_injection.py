"""HTML injection: inert structural tags with parse proof.

No network. Fake HTTP clients only. Read-only GETs in production;
script execution is never attempted (XSS engine territory).
"""
from types import SimpleNamespace

from main.budgets import BudgetExceeded, BudgetTracker
from main.config import Config, ScopeConfig
from main.models import Endpoint
from main.reporting.coverage import CoverageTracker
from main.reporting.metrics import Metrics
from main.scope import Scope
from main.stages.validation import ProbeControls
from main.stages.validation.misconfig import html_injection_probe
from main.validation import html_injection as html_mod
from main.validation.evidence import EvidenceStore


def _endpoint():
    return Endpoint(url="https://example.test/page?name=x",
                    normalized_url="https://example.test/page?name=x",
                    method="GET", host="example.test", path="/page",
                    endpoint_type="page")


def _scope():
    return Scope(ScopeConfig(allowed_domains=["example.test"]))


def _resp(status=200, text=""):
    return SimpleNamespace(status_code=status, text=text, headers={})


class _ReflectiveHttp:
    """Reflects the injected tag back as a real element."""

    def get(self, url, **kwargs):
        from urllib.parse import parse_qsl, urlsplit
        query = dict(parse_qsl(urlsplit(url).query,
                               keep_blank_values=True))
        value = query.get("name", "x")
        if "<apexhtml" in value or "<a href" in value:
            return _resp(200, f"<html><body><p>hi</p>{value}</body></html>")
        return _resp(200, "<html><body><p>hi</p></body></html>")


def test_element_injection_is_candidate():
    out = html_mod.check_html_injection(
        _ReflectiveHttp(), "https://example.test/page?name=x", "name")
    assert out.verdict == "candidate"
    assert out.evidence["shape"] in ("block", "link")
    assert "apex-html.invalid" not in out.notes
    assert out.evidence["nonce"] not in out.notes


def test_encoded_or_absent_tags_are_negative():
    class Http:
        def get(self, url, **kwargs):
            if "apexhtml" in url or "apex-html" in url:
                return _resp(
                    200, "<p>&lt;apexhtml&gt; sanitized</p>")
            return _resp(200, "<p>hi</p>")

    out = html_mod.check_html_injection(
        Http(), "https://example.test/page?name=x", "name")
    assert out.verdict == "negative"

    class Silent:
        def get(self, url, **kwargs):
            return _resp(200, "<p>hi</p>")

    out = html_mod.check_html_injection(
        Silent(), "https://example.test/page?name=x", "name")
    assert out.verdict == "negative"


def test_script_context_does_not_count():
    class Http:
        def get(self, url, **kwargs):
            from urllib.parse import parse_qsl, urlsplit
            query = dict(parse_qsl(urlsplit(url).query,
                                   keep_blank_values=True))
            value = query.get("name", "x")
            if value.startswith("<"):
                return _resp(
                    200, f"<script>var x = '{value}';</script>")
            return _resp(200, "<p>hi</p>")

    out = html_mod.check_html_injection(
        Http(), "https://example.test/page?name=x", "name")
    assert out.verdict == "negative"


def test_server_error_is_inconclusive():
    class Http:
        def get(self, url, **kwargs):
            return _resp(500, "error")

    out = html_mod.check_html_injection(
        Http(), "https://example.test/page?name=x", "name")
    assert out.verdict == "inconclusive"


def test_missing_param_fails_closed():
    class Http:
        def get(self, *a, **k):
            raise AssertionError("must not send without the param")

    out = html_mod.check_html_injection(
        Http(), "https://example.test/page?name=x", "missing")
    assert out.verdict == "inconclusive"
    assert "not in query" in out.notes


def test_budget_propagates():
    class Http:
        def get(self, *a, **k):
            raise BudgetExceeded("spent")

    try:
        html_mod.check_html_injection(
            Http(), "https://example.test/page?name=x", "name")
    except BudgetExceeded:
        return
    raise AssertionError("BudgetExceeded must propagate")


def test_nonce_is_fresh_per_check():
    seen = set()
    for _ in range(3):
        out = html_mod.check_html_injection(
            _ReflectiveHttp(), "https://example.test/page?name=x",
            "name")
        assert out.verdict == "candidate"
        seen.add(out.evidence["nonce"])
    assert len(seen) == 3


def test_probe_emits_candidate_finding(tmp_path):
    cfg = Config()
    coverage = CoverageTracker()
    out = html_injection_probe(
        [_endpoint()], EvidenceStore(tmp_path / "p"), Metrics(),
        BudgetTracker(cfg), coverage, _ReflectiveHttp(), cfg,
        _scope(), ProbeControls())
    assert len(out) == 1
    assert out[0].source == "html-injection"
    assert out[0].severity == "medium"
    assert out[0].parameter == "name"
    assert coverage.summary()["html"] == "candidate"


def test_reviews_map_html_findings():
    from main.models import Finding
    from main.reporting.reviews import finding_test_class
    assert finding_test_class(
        Finding(id="a", source="html-injection",
                tags=["html"])) == "html"


def test_plan_accounts_html_requests():
    from main.safety.preflight import plan_html
    assert plan_html(4, 3).total == 28
