"""Info disclosure: version banners + 404-handler error disclosure.

No network. Fake HTTP clients only. Read-only GETs in production;
bodies are never persisted — only marker families and header names.
"""
from types import SimpleNamespace

from main.budgets import BudgetExceeded, BudgetTracker
from main.config import Config, ScopeConfig
from main.models import Endpoint
from main.reporting.coverage import CoverageTracker
from main.reporting.metrics import Metrics
from main.scope import Scope
from main.validation import info_disclosure as id_mod
from main.validation.evidence import EvidenceStore


def _endpoint():
    return Endpoint(url="https://example.test/app",
                    normalized_url="https://example.test/app",
                    method="GET", host="example.test", path="/app",
                    endpoint_type="page")


def _scope():
    return Scope(ScopeConfig(allowed_domains=["example.test"]))


def _resp(status=200, text="", headers=None):
    return SimpleNamespace(status_code=status, text=text,
                           headers=headers or {})


def test_traceback_body_is_candidate():
    out = id_mod.check_verbose_error(
        "Traceback (most recent call last):\n  File \"app.py\"")
    assert out["verdict"] == "candidate"
    assert out["family"] == "python-traceback"


def test_sql_error_body_is_candidate():
    out = id_mod.check_verbose_error(
        "You have an error in your SQL syntax near 'x'")
    assert out["verdict"] == "candidate"
    assert out["family"].startswith("sql-")


def test_clean_body_is_negative():
    out = id_mod.check_verbose_error("<h1>Not found</h1>")
    assert out["verdict"] == "negative"


def test_versioned_server_banner_is_candidate():
    out = id_mod.check_disclosing_headers(
        {"Server": "nginx/1.18.0", "Content-Type": "text/html"})
    assert out["verdict"] == "candidate"
    assert any(d.startswith("server:") for d in out["disclosures"])


def test_framework_headers_are_candidates():
    out = id_mod.check_disclosing_headers(
        {"X-Powered-By": "PHP/8.1.2", "X-Debug-Token": "abc"})
    assert out["verdict"] == "candidate"
    names = [d.split(":")[0] for d in out["disclosures"]]
    assert "x-powered-by" in names
    assert "x-debug-token" in names


def test_bare_server_banner_is_negative():
    out = id_mod.check_disclosing_headers({"Server": "nginx"})
    assert out["verdict"] == "negative"


def test_no_headers_is_negative():
    out = id_mod.check_disclosing_headers({})
    assert out["verdict"] == "negative"


def test_not_found_child_drops_query():
    child = id_mod.not_found_child(
        "https://example.test/app?x=1#frag")
    assert child == \
        "https://example.test/app/apex-nonexistent-probe"
    assert id_mod.not_found_child("ftp://example.test/app") is None


def test_probe_emits_both_findings(tmp_path):
    from main.stages.validation import ProbeControls
    from main.stages.validation.misconfig import info_disclosure_probe

    class Http:
        def get(self, url, **kwargs):
            if "apex-nonexistent-probe" in url:
                return _resp(404, "NullPointerException at Foo.java:12")
            return _resp(200, "<h1>hi</h1>",
                         {"Server": "Apache/2.4.41"})

    cfg = Config()
    coverage = CoverageTracker()
    out = info_disclosure_probe(
        [_endpoint()], EvidenceStore(tmp_path / "p"), Metrics(),
        BudgetTracker(cfg), coverage, Http(), cfg, _scope(),
        ProbeControls())
    assert len(out) == 2
    assert {f.source for f in out} == {"misconfig-info-headers",
                                       "misconfig-info-error"}
    assert all(f.severity == "info" for f in out)
    assert coverage.summary()["info_disclosure"] == "candidate"


def test_probe_negative_and_failure_paths(tmp_path):
    from main.stages.validation import ProbeControls
    from main.stages.validation.misconfig import info_disclosure_probe

    class Clean:
        def get(self, url, **kwargs):
            return _resp(200, "<h1>hi</h1>", {"Server": "nginx"})

    cfg = Config()
    coverage = CoverageTracker()
    out = info_disclosure_probe(
        [_endpoint()], EvidenceStore(tmp_path / "p"), Metrics(),
        BudgetTracker(cfg), coverage, Clean(), cfg, _scope(),
        ProbeControls())
    assert out == []
    assert coverage.summary()["info_disclosure"] == "tested_negative"

    class Broke:
        def get(self, url, **kwargs):
            raise BudgetExceeded("spent")

    coverage2 = CoverageTracker()
    out = info_disclosure_probe(
        [_endpoint()], EvidenceStore(tmp_path / "p2"), Metrics(),
        BudgetTracker(cfg), coverage2, Broke(), cfg, _scope(),
        ProbeControls())
    assert out == []
    assert coverage2.summary()["info_disclosure"] == "blocked"


def test_reviews_map_info_findings():
    from main.models import Finding
    from main.reporting.reviews import finding_test_class
    assert finding_test_class(
        Finding(id="a", source="misconfig-info-error",
                tags=["info-error", "misconfiguration",
                      "info_disclosure"])) == "info_disclosure"
    # existing mappings unchanged
    assert finding_test_class(
        Finding(id="b", source="nuclei-x",
                tags=["CORS"])) == "cors"
    assert finding_test_class(
        Finding(id="c", source="authz-matrix")) == "authz"


def test_plan_accounts_info_requests():
    from main.safety.preflight import plan_info
    assert plan_info(4).total == 8
