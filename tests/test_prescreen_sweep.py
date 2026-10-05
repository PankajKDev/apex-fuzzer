"""Lead-independent prescreen sweep: findings without Nuclei leads.

Fake HTTP only. No network.
"""
from types import SimpleNamespace

from main.config import Config, ScopeConfig
from main.models import Endpoint, Finding, Parameter
from main.orchestrator import Orchestrator
from main.profiles import get as get_profile
from main.reporting.coverage import CoverageTracker
from main.reporting.metrics import Metrics
from main.budgets import BudgetTracker, BudgetExceeded
from main.scope import Scope
from main.stages.validation import ProbeControls
from main.stages.validation.prescreen import prescreen_sweep
from main.validation.evidence import EvidenceStore


def _controls(orch):
    return ProbeControls.from_orchestrator(orch)


def _orch(tmp_path, cfg=None):
    cfg = cfg or Config()
    cfg.scope.allowed_domains = ["example.test"]
    orch = Orchestrator(cfg, tmp_path, profile=get_profile("standard"))
    orch.scope = Scope(ScopeConfig(allowed_domains=["example.test"]))
    return orch, cfg


def _ep(url, params):
    from urllib.parse import urlparse
    p = urlparse(url)
    ep = Endpoint(url=url, normalized_url=url, host=p.hostname or "",
                  path=p.path, method="GET", endpoint_type="api",
                  source=["recon"])
    for name in params:
        ep.query_parameters.append(Parameter(name=name, location="query"))
    return ep


class _AppHttp:
    """JSON rows for /items (boolean-diffable); tag echo for /search."""

    def __init__(self):
        self.calls = 0

    def get(self, url, **kwargs):
        self.calls += 1
        from urllib.parse import urlsplit, parse_qsl, unquote_plus
        query = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))
        value = unquote_plus(next(iter(query.values()), ""))
        if "/items" in url:
            if "1=1" in value and "1=2" not in value:
                return SimpleNamespace(status_code=200,
                                       text='{"rows":[1,2]}')
            return SimpleNamespace(status_code=200, text='{"rows":[]}')
        if "/search" in value or True:
            pass
        text = next(iter(query.values()), "")
        return SimpleNamespace(status_code=200,
                               text=f"<div>{text}</div>")


def _ctx(tmp_path, orch, cfg):
    return (EvidenceStore(tmp_path / "proofs"), Metrics(),
            BudgetTracker(cfg), CoverageTracker(), _AppHttp())


def test_sweep_finds_without_leads(tmp_path):
    orch, cfg = _orch(tmp_path)
    evidence, metrics, budgets, coverage, http = _ctx(tmp_path, orch, cfg)
    endpoints = [_ep("https://example.test/items?id=1", ["id"]),
                 _ep("https://example.test/search?q=hello", ["q"])]
    found = prescreen_sweep(endpoints, [], evidence, metrics,
                                  budgets, coverage, http, cfg,
                                  orch.scope, _controls(orch))
    by_source = {f.source for f in found}
    assert "prescreen-sqli" in by_source
    assert "prescreen-xss" in by_source
    assert all(f.validation_status == "strong_candidate" for f in found)
    assert metrics.validation_candidates == len(found)
    assert coverage.summary()["sqli"] == "candidate"
    assert coverage.summary()["xss"] == "candidate"
    ids = [f.id for f in found]
    assert len(set(ids)) == len(ids)


def test_sweep_skips_already_covered(tmp_path):
    orch, cfg = _orch(tmp_path)
    evidence, metrics, budgets, coverage, http = _ctx(tmp_path, orch, cfg)
    existing = Finding(id="old", source="nuclei", name="old SQLi",
                       endpoint_url="https://example.test/items?id=1",
                       matched_at="https://example.test/items?id=1",
                       parameter="id", method="GET")
    existing.validation_status = "strong_candidate"
    from main.reporting.coverage import classify_finding
    assert classify_finding(existing) == "sqli"
    found = prescreen_sweep(
        [_ep("https://example.test/items?id=1", ["id"])], [existing],
        evidence, metrics, budgets, coverage, http, cfg, orch.scope,
        _controls(orch))
    assert [f for f in found if f.parameter == "id"
            and f.source == "prescreen-sqli"] == []


def test_sweep_respects_caps_and_gates(tmp_path):
    orch, cfg = _orch(tmp_path)
    cfg.validation.prescreen_max_endpoints = 1
    evidence, metrics, budgets, coverage, http = _ctx(tmp_path, orch, cfg)
    endpoints = [_ep("https://example.test/items?id=1", ["id"]),
                 _ep("https://example.test/other?id=1", ["id"])]
    found = prescreen_sweep(endpoints, [], evidence, metrics,
                                  budgets, coverage, http, cfg,
                                  orch.scope, _controls(orch))
    urls = {f.endpoint_url for f in found}
    assert len(urls) <= 1

    cfg2 = Config()
    cfg2.scope.allowed_domains = ["example.test"]
    orch2, _ = _orch(tmp_path, cfg2)
    post = _ep("https://example.test/submit?id=1", ["id"])
    post.method = "POST"
    evidence2, metrics2, budgets2, coverage2, http2 = _ctx(
        tmp_path, orch2, cfg2)
    found = prescreen_sweep([post], [], evidence2, metrics2,
                            budgets2, coverage2, http2, cfg2,
                            orch2.scope, _controls(orch2))
    assert found == []
    assert http2.calls == 0


def test_sweep_budget_exhaustion_is_blocked(tmp_path):
    orch, cfg = _orch(tmp_path)
    evidence, metrics, budgets, coverage, _ = _ctx(tmp_path, orch, cfg)

    class Http:
        def get(self, *args, **kwargs):
            raise BudgetExceeded("budget exhausted")

        def request(self, *args, **kwargs):
            raise BudgetExceeded("budget exhausted")

    found = prescreen_sweep(
        [_ep("https://example.test/items?id=1", ["id"])], [], evidence,
        metrics, budgets, coverage, Http(), cfg, orch.scope,
        _controls(orch))
    assert found == []
    assert coverage.summary()["sqli"] == "blocked"


def test_sweep_disabled_by_zero_cap(tmp_path):
    orch, cfg = _orch(tmp_path)
    cfg.validation.prescreen_max_endpoints = 0
    evidence, metrics, budgets, coverage, http = _ctx(tmp_path, orch, cfg)
    assert prescreen_sweep(
        [_ep("https://example.test/items?id=1", ["id"])], [], evidence,
        metrics, budgets, coverage, http, cfg, orch.scope,
        _controls(orch)) == []
    assert http.calls == 0


def test_plan_prescreen_math():
    from main.safety.preflight import plan_prescreen
    assert plan_prescreen(4, 3).total == 120
