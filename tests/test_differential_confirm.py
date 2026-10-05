"""Tests: differential confirmation repeats + error-is-not-negative."""
import json

import pytest

from main.budgets import BudgetExceeded
from main.validation import differential as diff_mod
from main.validation.differential import DifferentialTester


class _Resp:
    def __init__(self, status, text, headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}


class ScriptedHttp:
    """Pop responses per context cookie; optional exception scripts."""

    def __init__(self, scripts):
        # scripts: {(cookie_or_anon, call_index): _Resp | Exception}
        self.scripts = scripts
        self.calls = []

    def get(self, url, headers=None, timeout=10):
        raw_cookie = (headers or {}).get("Cookie", "")
        cookie = ("AAA" if "AAA" in raw_cookie else
                  "BBB" if "BBB" in raw_cookie else "anon")
        idx = sum(1 for c in self.calls if c == cookie)
        self.calls.append(cookie)
        action = self.scripts.get((cookie, idx), self.scripts.get(cookie))
        if isinstance(action, Exception):
            raise action
        if callable(action):
            return action(url, headers, timeout)
        return action


def _tester(http, authed=("AAA", "BBB")):
    from main.config import AuthContext, Config
    cfg = Config()
    cfg.auth.contexts = [AuthContext(name="anonymous", headers={})] + [
        AuthContext(name=f"user_{c}", headers={"Cookie": f"session={c}"})
        for c in authed]
    return DifferentialTester(cfg, http)


BODY = json.dumps({"id": 1, "email": "a@b.c"})
OTHER = json.dumps({"id": 2, "email": "z@y.x"})


def test_stable_candidate_confirms():
    http = ScriptedHttp({"AAA": _Resp(200, BODY),
                         "BBB": _Resp(200, BODY),
                         "anon": _Resp(401, "")})
    res = _tester(http).probe("https://example.com/api/u/1", "api")
    assert res.verdict == "strong_candidate"
    assert res.confirmed is True
    assert "2/2" in res.confirmation_notes
    # first pass + one confirmation pass per context
    assert len(http.calls) == 2 * 3


def test_flaky_candidate_downgrades():
    http = ScriptedHttp({
        ("AAA", 0): _Resp(200, BODY), ("AAA", 1): _Resp(200, BODY),
        ("BBB", 0): _Resp(200, BODY), ("BBB", 1): _Resp(403, "denied"),
        ("anon", 0): _Resp(401, ""), ("anon", 1): _Resp(401, "")})
    res = _tester(http).probe("https://example.com/api/u/1", "api")
    assert res.verdict == "inconclusive"
    assert res.confirmed is False
    assert "disagreed" in res.confirmation_notes


def test_blocked_confirmation_keeps_candidate():
    http = ScriptedHttp({
        ("AAA", 0): _Resp(200, BODY), ("AAA", 1): BudgetExceeded("cap"),
        ("BBB", 0): _Resp(200, BODY), ("BBB", 1): _Resp(200, BODY),
        ("anon", 0): _Resp(401, ""), ("anon", 1): _Resp(401, "")})
    res = _tester(http).probe("https://example.com/api/u/1", "api")
    assert res.verdict == "strong_candidate"
    assert res.confirmed is False
    assert "single-sample" in res.confirmation_notes


def test_first_pass_block_propagates():
    http = ScriptedHttp({"AAA": BudgetExceeded("cap")})
    with pytest.raises(BudgetExceeded):
        _tester(http).probe("https://example.com/api/u/1", "api")


def test_evaluate_all_error_is_inconclusive():
    res = diff_mod.DifferentialResult(url="x", endpoint_type="api")
    bad = diff_mod.ContextResult(name="user_a", error="timeout")
    res.contexts = [diff_mod.ContextResult(name="anonymous", error="dns"),
                    bad]
    verdict, notes = DifferentialTester.evaluate(res)
    assert verdict == "inconclusive"
    assert "incomplete" in notes


def test_orchestrator_error_result_is_not_negative(tmp_path):
    from main.budgets import BudgetTracker
    from main.config import Config
    from main.models import Endpoint
    from main.orchestrator import Orchestrator
    from main.profiles import get as get_profile
    from main.reporting.coverage import CoverageTracker
    from main.reporting.metrics import Metrics
    from main.validation.evidence import EvidenceStore
    cfg = Config()
    cfg.scope.allowed_domains = ["example.com"]
    orch = Orchestrator(cfg, tmp_path, profile=get_profile("standard"))

    class StubDiff:
        contexts = [{"name": "anonymous"}, {"name": "user_a"}]

        def probe(self, url, etype, timeout=10):
            res = diff_mod.DifferentialResult(url=url,
                                              endpoint_type=etype)
            res.contexts = [
                diff_mod.ContextResult(name="anonymous", error="timeout"),
                diff_mod.ContextResult(name="user_a", error="timeout")]
            res.verdict, res.notes = DifferentialTester.evaluate(res)
            return res

    ep = Endpoint(url="https://example.com/api/u/1",
                  normalized_url="https://example.com/api/u/1",
                  host="example.com", path="/api/u/1",
                  method="GET", endpoint_type="api")
    coverage = CoverageTracker()
    from main.stages.validation import ProbeControls
    from main.stages.validation.differential import differential_probe
    findings = differential_probe(
        [ep], StubDiff(), EvidenceStore(tmp_path), Metrics(),
        BudgetTracker(cfg), coverage, orch.cfg, orch.scope,
        ProbeControls.from_orchestrator(orch))
    assert findings == []
    flat = json.dumps(coverage.to_dict())
    assert "tested_negative" not in flat
    assert "incomplete" in flat
