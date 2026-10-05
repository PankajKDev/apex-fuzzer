"""Tests: CMDI error-oracle prescreen (no network)."""
from main.validation import mutate as mut_mod


class _Resp:
    def __init__(self, status, text, headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}


class FakeHttp:
    def __init__(self, script):
        # script: list of response texts (one per GET), or Exception
        self._script = list(script)
        self.calls = []

    def get(self, url, **kw):
        self.calls.append(url)
        action = self._script.pop(0) if self._script else ""
        if isinstance(action, Exception):
            raise action
        return _Resp(200, action)


def _candidate(url="https://example.com/run?cmd=test"):
    from main.validation.base import Candidate
    return Candidate(finding=None, test_class="cmdi",
                     endpoint_url=url, method="GET", parameter="cmd",
                     parameter_location="query")


def _engine(http):
    from main.config import Config
    return mut_mod.MutationEngine(Config(), http, None)


def test_markers():
    assert mut_mod.cmdi_error_markers(
        "sh: 1: foo: command not found") == ["shell-error"]
    assert mut_mod.cmdi_error_markers(
        "uid=0(root) gid=0(root)") == ["command-output"]
    assert mut_mod.cmdi_error_markers("all clear, 0 errors") == []
    assert mut_mod.cmdi_error_signal("") is False


def test_hit_on_id_output():
    http = FakeHttp(["clean baseline",
                     "clean baseline",
                     "clean baseline",
                     "uid=0(root) gid=0(root) groups=0(root)"])
    outcome = _engine(http).prescreen_cmdi(_candidate())
    assert outcome is not None
    assert outcome.status == "strong_candidate"
    assert outcome.evidence["payload"] == ";id"
    assert outcome.evidence["markers"] == ["command-output"]
    assert len(http.calls) >= 2  # baseline plus probes


def test_baseline_poisoning_disables_error_stage():
    http = FakeHttp(["uid=0(root) always here",
                     "uid=0(root) always here",
                     "uid=0(root) always here",
                     "uid=0(root) always here",
                     "uid=0(root) always here",
                     "uid=0(root) always here"])
    assert _engine(http).prescreen_cmdi(_candidate()) is None


def test_state_gate_and_method_gate():
    from main.config import Config
    outcome = _engine(FakeHttp([])).prescreen_cmdi(_candidate(
        "https://example.com/run"))
    assert outcome is None  # no param and no query to guess
    cfg = Config()
    engine = mut_mod.MutationEngine(cfg, FakeHttp([]), None)
    from main.validation.base import Candidate
    cand = Candidate(finding=None, test_class="cmdi",
                     endpoint_url="https://example.com/run",
                     method="DELETE", parameter="cmd",
                     parameter_location="query")
    out = engine.prescreen_cmdi(cand)
    assert out.status == "inconclusive"


def test_budget_propagates():
    from main.budgets import BudgetExceeded
    import pytest
    http = FakeHttp([BudgetExceeded("cap")])
    with pytest.raises(BudgetExceeded):
        _engine(http).prescreen_cmdi(_candidate())


def test_plugin_adapter_maps_candidate():
    from main.plugins.adapters import CmdiMutationPlugin
    from main.plugins.base import TestTarget, TestContext
    from main.config import Config
    from main.models import Finding
    http = FakeHttp(["clean", "clean", "clean",
                     "uid=33(www-data) gid=33(www-data)"])
    cfg = Config()
    target = TestTarget(
        "https://example.com/run?cmd=test", endpoint_type="api",
        parameter="cmd", method="GET",
        finding=Finding(id="c", source="prescreen-cmdi"),
        endpoint=None, test_class="cmdi")
    ctx = TestContext(cfg, http=http, scope=None, budgets=None,
                      oast_provider=None, waf=None, technologies=[],
                      identities=[], evidence=None, timeout=10,
                      browser_enabled=False)
    res = CmdiMutationPlugin().run(target, ctx)
    assert res.status == "candidate"
    assert "cmdi" in str(res.observations).lower() or res.evidence


def test_sweep_emits_cmdi_findings(tmp_path):
    from urllib.parse import parse_qsl, urlsplit
    from main.budgets import BudgetTracker
    from main.config import Config
    from main.models import Endpoint, Parameter
    from main.reporting.coverage import CoverageTracker
    from main.reporting.metrics import Metrics
    from main.scope import Scope
    from main.stages.validation import ProbeControls
    from main.stages.validation.prescreen import prescreen_sweep
    from main.validation.evidence import EvidenceStore

    class SmartHttp:
        def get(self, url, **kw):
            value = dict(parse_qsl(urlsplit(url).query)).get("cmd", "")
            text = ("uid=33(www-data) gid=33(www-data)"
                    if value == ";id" else "clean")
            return _Resp(200, text)

    cfg = Config()
    ep = Endpoint(url="https://example.com/run?cmd=test",
                  normalized_url="https://example.com/run?cmd=test",
                  host="example.com", path="/run", method="GET",
                  endpoint_type="api",
                  query_parameters=[Parameter(name="cmd",
                                              location="query")])
    coverage = CoverageTracker()
    found = prescreen_sweep(
        [ep], [], EvidenceStore(tmp_path / "proofs"), Metrics(),
        BudgetTracker(cfg), coverage, SmartHttp(), cfg,
        Scope(cfg.scope), ProbeControls())
    kinds = {(f.source, f.parameter) for f in found}
    assert ("prescreen-cmdi", "cmd") in kinds
    assert coverage.summary()["cmdi"] == "candidate"
