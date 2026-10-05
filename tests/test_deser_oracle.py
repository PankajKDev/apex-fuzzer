"""Deserialization error oracle: type confusion on JSON endpoints.

No network. Fake HTTP clients only. Always POSTs JSON in
production behind state-change authorization; candidate-only
(exception text never proves gadget reachability).
"""
from types import SimpleNamespace

from main.budgets import BudgetExceeded, BudgetTracker
from main.config import Config, ScopeConfig
from main.models import Endpoint, Parameter
from main.reporting.coverage import CoverageTracker
from main.reporting.metrics import Metrics
from main.scope import Scope
from main.validation import deser_oracle as deser_mod
from main.validation.evidence import EvidenceStore


def _endpoint():
    ep = Endpoint(url="https://example.test/api/update",
                  normalized_url="https://example.test/api/update",
                  method="POST", host="example.test",
                  path="/api/update", endpoint_type="api",
                  body_parameters=[Parameter(name="name",
                                             location="body")])
    ep.request_content_types = ["application/json"]
    return ep


def _scope():
    return Scope(ScopeConfig(allowed_domains=["example.test"]))


def _resp(status=200, text=""):
    return SimpleNamespace(status_code=status, text=text, headers={})


def test_jackson_exception_is_candidate():
    class Http:
        def post(self, url, **kwargs):
            import json as _json
            value = _json.loads(kwargs.get("data") or "{}")["name"]
            if isinstance(value, list):
                return _resp(
                    400, "MismatchedInputException: Cannot deserialize")
            return _resp(200, '{"ok":true}')

    out = deser_mod.check_deser_oracle(
        Http(), "https://example.test/api/update", "name")
    assert out.verdict == "candidate"
    assert out.evidence["families"] == ["jackson"]
    assert out.evidence["shape"] == "array"


def test_clean_shapes_are_negative():
    class Http:
        def post(self, url, **kwargs):
            return _resp(200, '{"ok":true}')

    out = deser_mod.check_deser_oracle(
        Http(), "https://example.test/api/update", "name")
    assert out.verdict == "negative"


def test_dirty_control_fails_closed():
    class Http:
        def post(self, url, **kwargs):
            return _resp(200, "JsonMappingException: always here")

    out = deser_mod.check_deser_oracle(
        Http(), "https://example.test/api/update", "name")
    assert out.verdict == "inconclusive"
    assert "control" in out.notes


def test_server_error_is_inconclusive():
    class Http:
        def post(self, url, **kwargs):
            return _resp(500, "error")

    out = deser_mod.check_deser_oracle(
        Http(), "https://example.test/api/update", "name")
    assert out.verdict == "inconclusive"


def test_budget_propagates():
    class Http:
        def post(self, *a, **k):
            raise BudgetExceeded("spent")

    try:
        deser_mod.check_deser_oracle(
            Http(), "https://example.test/api/update", "name")
    except BudgetExceeded:
        return
    raise AssertionError("BudgetExceeded must propagate")


def test_probe_skips_without_state_change_ack(tmp_path):
    from main.stages.validation import ProbeControls
    from main.stages.validation.prescreen import deser_probe

    class Http:
        def post(self, *a, **k):
            raise AssertionError("must not send without ack")

    cfg = Config()
    out = deser_probe([_endpoint()], EvidenceStore(tmp_path / "p"),
                      Metrics(), BudgetTracker(cfg),
                      CoverageTracker(), Http(), cfg, _scope(),
                      ProbeControls())
    assert out == []


def test_probe_emits_oracle_finding(tmp_path):
    from main.stages.validation import ProbeControls
    from main.stages.validation.prescreen import deser_probe

    class Http:
        def post(self, url, **kwargs):
            import json as _json
            value = _json.loads(kwargs.get("data") or "{}")["name"]
            if isinstance(value, dict):
                return _resp(400, "JsonSyntaxException: Expected "
                                  "BEGIN_OBJECT")
            return _resp(200, '{"ok":true}')

    cfg = Config()
    cfg.safety.allow_state_change = True
    coverage = CoverageTracker()
    out = deser_probe([_endpoint()], EvidenceStore(tmp_path / "p"),
                      Metrics(), BudgetTracker(cfg), coverage, Http(),
                      cfg, _scope(), ProbeControls())
    assert len(out) == 1
    assert out[0].source == "deser-oracle"
    assert out[0].parameter == "name"
    assert coverage.summary()["deserialization"] == "candidate"


def test_reviews_map_deser_findings():
    from main.models import Finding
    from main.reporting.reviews import finding_test_class
    assert finding_test_class(
        Finding(id="a", source="deser-oracle",
                tags=["deserialization"])) == "deserialization"


def test_plan_accounts_deser_requests():
    from main.safety.preflight import plan_deser
    assert plan_deser(4, 3).total == 36
