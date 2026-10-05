"""CSRF cross-site execution proof: gating, mapping, and verdicts.

Browser plumbing runs against fakes here; real Chromium behavior
(null-origin submit, cookie semantics) is covered by
test_csrf_browser_integration.py.
"""
from types import SimpleNamespace

from main.budgets import BudgetTracker
from main.config import Config, ScopeConfig
from main.models import Finding
from main.reporting.coverage import CoverageTracker
from main.reporting.metrics import Metrics
from main.scope import Scope
from main.stages.validation import ProbeControls
from main.stages.validation import misconfig as misconfig_mod
from main.validation import csrf_browser as csrf_mod
from main.validation.evidence import EvidenceStore


def _scope():
    return Scope(ScopeConfig(allowed_domains=["example.test"]))


def _cfg():
    cfg = Config()
    cfg.validation.csrf_browser = True
    cfg.safety.allow_state_change = True
    return cfg


def _finding():
    return Finding(
        id="csrf1", source="misconfig-csrf", host="example.test",
        endpoint_url="https://example.test/page",
        matched_at="https://example.test/page",
        raw={"forms": [{"action": "/submit", "method": "POST",
                        "inputs": [{"name": "comment"}]}]})


def _victim():
    return SimpleNamespace(name="victim", tenant="acme",
                           auth_headers={"Cookie": "session=V"},
                           storage_state="")


def _run_probe(monkeypatch, tmp_path, prove=None, client=None, cfg=None,
               findings=None, identities=None):
    if prove is not None and monkeypatch is not None:
        monkeypatch.setattr(csrf_mod, "prove_csrf_execution", prove)
    # Unit branches must not depend on the interpreter's browser extra.
    if monkeypatch is not None:
        import importlib.util
        real_find_spec = importlib.util.find_spec
        monkeypatch.setattr(
            importlib.util, "find_spec",
            lambda name: SimpleNamespace(name=name)
            if name == "playwright" else real_find_spec(name))
    http = client or SimpleNamespace(
        get=lambda url, **k: SimpleNamespace(status_code=200, text="ok",
                                             headers={}),
        post=lambda url, **k: SimpleNamespace(status_code=200,
                                              text="ok", headers={}))
    cfg = cfg or _cfg()
    coverage = CoverageTracker()
    out = misconfig_mod.csrf_browser_probe(
        findings if findings is not None else [_finding()],
        EvidenceStore(tmp_path / "p"), Metrics(), BudgetTracker(cfg),
        coverage, http, cfg, _scope(), ProbeControls(),
        identities if identities is not None else [_victim()])
    return out, coverage


def test_executed_emits_high_finding(tmp_path, monkeypatch):
    def prove(*a, **k):
        return {"status": "executed", "cookie_sent": True,
                "response_status": 200, "request_count": 1,
                "browser": "chromium", "reason": "executed"}
    out, coverage = _run_probe(monkeypatch, tmp_path, prove=prove)
    assert len(out) == 1
    assert out[0].source == "csrf-execution"
    assert out[0].severity == "high"
    assert "csrf-executed" in out[0].tags
    assert coverage.summary()["csrf"] == "candidate"


def test_denied_records_negative_without_finding(tmp_path, monkeypatch):
    def prove(*a, **k):
        return {"status": "denied", "cookie_sent": False,
                "response_status": 403, "request_count": 1,
                "browser": "chromium", "reason": "denied"}
    out, coverage = _run_probe(monkeypatch, tmp_path, prove=prove)
    assert out == []
    assert coverage.summary()["csrf"] == "tested_negative"


def test_failed_baseline_never_reaches_browser(tmp_path, monkeypatch):
    def prove(*a, **k):
        raise AssertionError("browser must not run")

    def post(url, **k):
        return SimpleNamespace(status_code=500, text="err", headers={})
    http = SimpleNamespace(
        get=lambda url, **k: SimpleNamespace(status_code=500, text="",
                                             headers={}),
        post=post)
    out, coverage = _run_probe(monkeypatch, tmp_path, prove=prove,
                               client=http)
    assert out == []
    assert coverage.summary()["csrf"] == "inconclusive"


def test_gates_skip_without_sending(tmp_path):
    class Http:
        def post(self, *a, **k):
            raise AssertionError("must not send")

        def get(self, *a, **k):
            raise AssertionError("must not send")

    # flag off
    cfg = Config()
    cfg.safety.allow_state_change = True
    out, _ = _run_probe(None, tmp_path, client=Http(), cfg=cfg)
    assert out == []
    # no ack
    cfg = Config()
    cfg.validation.csrf_browser = True
    out, _ = _run_probe(None, tmp_path, client=Http(), cfg=cfg)
    assert out == []
    # no victim
    out, coverage = _run_probe(None, tmp_path, client=Http(),
                               identities=[SimpleNamespace(
                                   name="anonymous", auth_headers={},
                                   storage_state="")])
    assert out == []
    assert coverage.summary()["csrf"] == "untestable"


def test_form_page_builder_escapes_attributes():
    page = csrf_mod._form_page(
        "https://example.test/submit?a=b", "POST",
        {'x"><script>': 'y"&<>'})
    assert 'x"><script>' not in page
    assert "x&quot;&gt;&lt;script&gt;" in page
    assert "y&quot;&amp;&lt;&gt;" in page
    assert "https://example.test/submit?a=b" in page


def test_method_and_url_guards():
    assert csrf_mod.prove_csrf_execution(
        "https://example.test/submit", "PUT", {}, None,
        Config())["status"] == "inconclusive"
    assert csrf_mod.prove_csrf_execution(
        "not-a-url", "POST", {}, None, Config())["status"] == \
        "inconclusive"


def test_reviews_map_csrf_findings():
    from main.reporting.reviews import finding_test_class
    assert finding_test_class(
        Finding(id="a", source="misconfig-csrf",
                tags=["csrf"])) == "csrf"
    assert finding_test_class(
        Finding(id="b", source="csrf-execution",
                tags=["csrf", "csrf-executed"])) == "csrf"


def test_plan_accounts_csrf_requests():
    from main.safety.preflight import plan_csrf
    assert plan_csrf(4).total == 12


def test_config_defaults_and_bounds():
    cfg = Config()
    assert cfg.validation.csrf_browser is False
    assert cfg.validation.csrf_max_endpoints == 5
    assert cfg.validate()["errors"] == []
    bad = Config()
    bad.validation.csrf_max_endpoints = -1
    assert bad.validate()["errors"]
    assert Config.load("config.yaml").validate()["errors"] == []
