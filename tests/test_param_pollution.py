"""HPP: duplicated query parameters, baseline vs polluted GET pair.

No network. Fake HTTP clients only. Read-only GETs in production.
"""
from types import SimpleNamespace

from main.budgets import BudgetExceeded, BudgetTracker
from main.config import Config, ScopeConfig
from main.models import Endpoint
from main.reporting.coverage import CoverageTracker
from main.reporting.metrics import Metrics
from main.scope import Scope
from main.validation import param_pollution as hpp_mod
from main.validation.evidence import EvidenceStore


def _endpoint():
    return Endpoint(url="https://example.test/search?q=books",
                    normalized_url="https://example.test/search?q=books",
                    method="GET", host="example.test", path="/search",
                    endpoint_type="page")


def _scope():
    return Scope(ScopeConfig(allowed_domains=["example.test"]))


def _resp(status=200, text=""):
    return SimpleNamespace(status_code=status, text=text, headers={})


def test_inconsistent_handling_is_candidate():
    class Http:
        def get(self, url, **kwargs):
            if "apex-pollution-probe" in url:
                return _resp(200, '{"results":[],"mode":"concat"}')
            return _resp(200, '{"results":[]}')

    out = hpp_mod.check_hpp(
        Http(), "https://example.test/search?q=books", "q")
    assert out.verdict == "candidate"
    assert out.evidence["param"] == "q"


def test_identical_handling_is_negative():
    class Http:
        def get(self, url, **kwargs):
            return _resp(200, '{"results":[]}')

    out = hpp_mod.check_hpp(
        Http(), "https://example.test/search?q=books", "q")
    assert out.verdict == "negative"


def test_echo_only_difference_is_negative():
    class Http:
        def get(self, url, **kwargs):
            return _resp(200, f'{{"echo":"{url}"}}')

    out = hpp_mod.check_hpp(
        Http(), "https://example.test/search?q=books", "q")
    assert out.verdict == "negative"


def test_server_error_is_inconclusive():
    class Http:
        def get(self, url, **kwargs):
            return _resp(500, "error")

    out = hpp_mod.check_hpp(
        Http(), "https://example.test/search?q=books", "q")
    assert out.verdict == "inconclusive"


def test_missing_param_fails_closed():
    class Http:
        def get(self, *a, **k):
            raise AssertionError("must not send without the param")

    out = hpp_mod.check_hpp(
        Http(), "https://example.test/search?q=books", "missing")
    assert out.verdict == "inconclusive"
    assert "not in query" in out.notes


def test_budget_propagates():
    class Http:
        def get(self, *a, **k):
            raise BudgetExceeded("spent")

    try:
        hpp_mod.check_hpp(
            Http(), "https://example.test/search?q=books", "q")
    except BudgetExceeded:
        return
    raise AssertionError("BudgetExceeded must propagate")


def test_polluted_url_builder():
    dup = hpp_mod.polluted_url(
        "https://example.test/search?q=books", "q",
        hpp_mod.DUP_VALUE)
    assert dup is not None
    assert "q=books" in dup and "apex-pollution-probe" in dup
    control = hpp_mod.polluted_url(
        "https://example.test/search?q=books", "q")
    assert control is not None
    assert control.count("q=books") == 2
    assert hpp_mod.polluted_url(
        "https://example.test/search?q=books", "missing") is None
    assert hpp_mod.query_params(
        "https://example.test/search?q=books&q=again") == ["q", "q"]


def test_probe_emits_candidate_finding(tmp_path):
    from main.stages.validation import ProbeControls
    from main.stages.validation.misconfig import hpp_probe

    class Http:
        def get(self, url, **kwargs):
            if "apex-pollution-probe" in url:
                return _resp(200, '{"mode":"last-wins"}')
            return _resp(200, '{"results":[]}')

    cfg = Config()
    coverage = CoverageTracker()
    out = hpp_probe([_endpoint()], EvidenceStore(tmp_path / "p"),
                    Metrics(), BudgetTracker(cfg), coverage, Http(),
                    cfg, _scope(), ProbeControls())
    assert len(out) == 1
    assert out[0].source == "misconfig-hpp"
    assert out[0].severity == "medium"
    assert coverage.summary()["parameter_pollution"] == "candidate"


def test_reviews_map_hpp_findings():
    from main.models import Finding
    from main.reporting.reviews import finding_test_class
    assert finding_test_class(
        Finding(id="a", source="misconfig-hpp",
                tags=["hpp", "parameter_pollution"])) == \
        "parameter_pollution"


def test_plan_accounts_hpp_requests():
    from main.safety.preflight import plan_hpp
    assert plan_hpp(4, 3).total == 28
