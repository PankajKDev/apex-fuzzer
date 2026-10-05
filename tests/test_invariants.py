"""Invariant inference tests (agent Phase 6).

Scoping, new checks, engine log/summary/persist, discovery rules,
matrix-cell producers, and the orchestrator second-opinion step
(corroborate vs emit vs silent). No network in any test.
"""
import json

from main.logic.invariants import (
    Invariant, evaluate, default_invariants, BUILTIN_IDS)
from main.logic.invariant_engine import (
    InvariantEngine, EvaluationRecord)
from main.logic.invariant_discovery import (
    DiscoveredRule, discover_holdings, discover_invariants)
from main.logic.observations import observation_from_matrix_cell
from main.authorization.matrix import AuthorizationObservation
from main.authorization.harvest import HarvestedId
from main.models import Finding


def _obs(identity="user_b", status=200, shape="s", tenant="t2",
         endpoint="https://t.com/api/u", method="GET", resource="v1",
         h="h1"):
    return AuthorizationObservation(
        identity=identity, status=status, shape=shape, tenant=tenant,
        endpoint=endpoint, method=method, resource=resource,
        body_hash=h, length_bucket=0)


def _pool():
    return [HarvestedId(endpoint_url="https://t.com/api/u",
                         normalized_url="https://t.com/api/u",
                         param="id", value="v1", owner="user_a",
                         owner_tenant="t1", shape="s", body_hash="h")]


# ── central scoping ───────────────────────────────────────────────────
def test_scoping_filters_without_silence():
    inv = Invariant(id="t", description="t", check="no_cross_user_read",
                    params={"endpoint": "https://t.com/api/u"})
    obs = {"actor": "b", "action": "read", "resource_owner": "a",
           "endpoint": "https://t.com/other"}
    r = evaluate(inv, obs)
    assert r.violated is False and "out of scope" in r.detail
    obs["endpoint"] = "https://t.com/api/u"
    assert evaluate(inv, obs).violated is True
    # actor + tenant scoping: the rule watches tenant t2's
    # resources, so an outsider reading them still fires; a rule
    # about another tenant's resources stays silent
    inv2 = Invariant(id="t2", description="t", check="no_cross_user_read",
                     params={"actor": "b", "tenant": "t2"})
    assert evaluate(inv2, {**obs, "actor_tenant": "t2",
                           "resource_tenant": "t2"}).violated is True
    assert evaluate(inv2, {**obs, "actor_tenant": "t9",
                           "resource_tenant": "t2"}).violated is True
    assert evaluate(inv2, {**obs, "actor_tenant": "t2",
                           "resource_tenant": "t9"}).violated is False
    # empty params: scoping is a no-op (regression guard)
    assert evaluate(Invariant(id="t3", description="t",
                              check="no_cross_user_read"),
                    obs).violated is True


def test_new_checks_and_contracts():
    acc = Invariant(id="a", description="a", check="no_access_deleted")
    assert evaluate(acc, {"action": "read", "state_before": "deleted",
                          "actor": "u"}).violated is True
    assert evaluate(acc, {"action": "read", "state_before": "active",
                          "actor": "u"}).violated is False
    assert evaluate(acc, {"action": "write", "state_before": "deleted",
                          "actor": "u"}).violated is False  # modify's job
    exp = Invariant(id="e", description="e", check="no_expired_session")
    assert evaluate(exp, {"session_expired": True, "status": 200,
                          "actor": "u"}).violated is True
    assert evaluate(exp, {"session_expired": True, "status": 403,
                          "actor": "u"}).violated is False  # enforced
    assert evaluate(exp, {"session_expired": False, "status": 200,
                          "actor": "u"}).violated is False
    assert evaluate(exp, {"session_expired": True, "status": 200,
                          "actor": "u",
                          "endpoint_type": "static"}).violated is False
    rch = Invariant(id="r", description="r",
                    check="no_recharge_refunded")
    assert evaluate(rch, {"state_before": "refunded", "action": "pay",
                          "actor": "u"}).violated is True
    assert evaluate(rch, {"state_before": "paid", "action": "pay",
                          "actor": "u"}).violated is False
    assert "no_access_deleted" in BUILTIN_IDS
    assert "no_expired_session" in BUILTIN_IDS
    assert "no_recharge_refunded" in BUILTIN_IDS
    assert len(default_invariants()) == 12


# ── engine ────────────────────────────────────────────────────────────
def test_engine_log_summary_holdings():
    engine = InvariantEngine()
    assert len(engine.invariants) == 12
    engine.evaluate({"actor": "b", "action": "read",
                     "resource_owner": "a"}, observation_ref="cell-1")
    engine.evaluate({"actor": "a", "action": "read",
                     "resource_owner": "a"}, observation_ref="cell-2")
    assert len(engine.violations()) == 1
    assert engine.violations()[0].observation_ref == "cell-1"
    assert engine.summary()["evaluations"] == 24  # 12 checks × 2 obs
    assert engine.summary()["violations"] == 1
    # holdings exclude scope-skips and errors, include real passes
    assert any(r.invariant_id == "inv-quantity"
               for r in engine.holdings())
    rt = InvariantEngine.from_dict(engine.to_dict())
    assert len(rt.log) == 24 and len(rt.invariants) == 12
    # custom invariants ride along
    engine.add(Invariant(id="custom", description="c",
                         check="no_cross_user_read",
                         params={"actor": "nobody"}))
    assert len(engine.invariants) == 13
    engine.add(Invariant(id="custom", description="c2",
                         check="no_cross_user_read"))
    assert len(engine.invariants) == 13  # idempotent by id
    assert EvaluationRecord.from_dict(
        engine.log[0].to_dict()).invariant_id == \
        engine.log[0].invariant_id


# ── discovery ─────────────────────────────────────────────────────────
def _denied_cell(identity, endpoint="https://t.com/api/u"):
    return AuthorizationObservation(
        identity=identity, status=403, shape="", tenant="t9",
        endpoint=endpoint, method="GET", body_hash="", length_bucket=0)


def test_discovery_holding_emitted():
    obs = [_obs("user_a", status=200, shape="s", tenant="t1", h="ha"),
           _obs("user_b", status=403, tenant="t2"),
           _obs("user_c", status=404, tenant="t2")]
    rules = discover_holdings(obs)
    assert len(rules) == 1
    rule = rules[0]
    assert rule.confidence in ("high", "medium")
    assert rule.invariant.check == "no_cross_user_read"
    assert rule.invariant.params == {
        "endpoint": "https://t.com/api/u"}
    assert rule.evidence["denials"] == 2
    assert rule.evidence["tenants"] == ["t1", "t2"]  # full population
    assert DiscoveredRule.from_dict(rule.to_dict()).invariant.id == \
        rule.invariant.id
    # deterministic IDs across runs
    again = discover_holdings(obs)
    assert again[0].invariant.id == rule.invariant.id


def test_discovery_withholds_without_evidence():
    # single identity proves nothing about isolation
    assert discover_holdings([_obs("user_a", status=200)]) == []
    # nobody ever refused → no enforcement shown
    assert discover_holdings(
        [_obs("user_a", status=200, h="ha"),
         _obs("user_b", status=200, h="hb")]) == []
    # shared object across identities → verdict territory, not holding
    assert discover_holdings(
        [_obs("user_a", status=200, shape="s", h="same"),
         _obs("user_b", status=200, shape="s", h="same"),
         _denied_cell("user_c")]) == []
    assert discover_holdings([]) == []
    assert discover_invariants([]) == []


# ── producers ─────────────────────────────────────────────────────────
def test_observation_from_matrix_cell():
    obs = observation_from_matrix_cell(
        _obs("user_b", resource="v1"), _pool())
    assert obs == {"actor": "user_b", "actor_tenant": "t2",
                   "action": "read", "resource": "v1",
                   "resource_owner": "user_a",
                   "endpoint": "https://t.com/api/u", "status": 200}
    # unknown resource → owner None, checks abstain safely
    obs2 = observation_from_matrix_cell(_obs("user_b", resource="zzz"),
                                        _pool())
    assert obs2["resource_owner"] is None
    # POST method maps to write
    obs3 = observation_from_matrix_cell(
        AuthorizationObservation(identity="u", method="DELETE",
                                 endpoint="e", status=200), [])
    assert obs3["action"] == "write"


# ── orchestrator second-opinion step ──────────────────────────────────
def _orch_matrix(monkeypatch=None):
    import tempfile
    from pathlib import Path
    from main.orchestrator import Orchestrator
    from main.config import Config
    from main.profiles import get as get_profile
    out = Path(tempfile.mkdtemp())
    orch = Orchestrator(Config(), out, profile=get_profile("standard"))
    return orch, out


def _stash_matrix(orch, observations):
    from main.authorization.matrix import AuthorizationMatrix
    m = AuthorizationMatrix()
    for o in observations:
        m.record(o)
    orch._last_matrix = m
    orch._harvest_pool = _pool()


def test_invariants_new_finding_when_uncovered(tmp_path):
    import tempfile
    from pathlib import Path
    from main.orchestrator import Orchestrator
    from main.config import Config
    from main.profiles import get as get_profile
    from main.reporting.metrics import Metrics
    from main.reporting.coverage import CoverageTracker
    from main.validation.evidence import EvidenceStore
    out = Path(tempfile.mkdtemp())
    orch = Orchestrator(Config(), out, profile=get_profile("standard"))
    owner = _obs("user_a", status=200, shape="s", tenant="t1", h="same")
    tester = _obs("user_b", status=200, shape="s", tenant="t2", h="same")
    _stash_matrix(orch, [owner, tester])
    m = Metrics()
    cov = CoverageTracker()
    new = orch._discover_invariants(
        out, [], EvidenceStore(out / "proofs"), m, cov, [])
    assert len(new) == 1
    f = new[0]
    assert f.source == "invariant"
    assert f.validation_status == "strong_candidate"
    assert f.identity == "user_b"
    assert m.invariants_tested > 0 and m.invariants_violated == 1
    assert cov.summary()["bola"] == "candidate"
    art = json.loads((out / "invariants.json").read_text())
    assert art["summary"]["violations"] == 1
    assert art["discovered"] == []  # shared object → no holding


def test_invariants_corroborate_instead_of_duplicating(tmp_path):
    import tempfile
    from pathlib import Path
    from main.orchestrator import Orchestrator
    from main.config import Config
    from main.profiles import get as get_profile
    from main.reporting.metrics import Metrics
    from main.reporting.coverage import CoverageTracker
    from main.validation.evidence import EvidenceStore
    out = Path(tempfile.mkdtemp())
    orch = Orchestrator(Config(), out, profile=get_profile("standard"))
    owner = _obs("user_a", status=200, shape="s", tenant="t1", h="same")
    tester = _obs("user_b", status=200, shape="s", tenant="t2", h="same")
    _stash_matrix(orch, [owner, tester])
    existing = Finding(id="f1", source="idor-swap", name="BOLA",
                       matched_at="https://t.com/api/u",
                       tags=["bola", "idor"], raw={})
    new = orch._discover_invariants(
        out, [], EvidenceStore(out / "proofs"), Metrics(),
        CoverageTracker(), [existing])
    assert new == []
    attached = existing.raw.get("invariants", [])
    assert any(e["invariant_id"] == "inv-cross-user-read"
               for e in attached)


def test_invariants_silent_without_matrix(tmp_path):
    import tempfile
    from pathlib import Path
    from main.orchestrator import Orchestrator
    from main.config import Config
    from main.profiles import get as get_profile
    from main.reporting.metrics import Metrics
    from main.reporting.coverage import CoverageTracker
    from main.validation.evidence import EvidenceStore
    out = Path(tempfile.mkdtemp())
    orch = Orchestrator(Config(), out, profile=get_profile("standard"))
    m = Metrics()
    assert orch._discover_invariants(
        out, [], EvidenceStore(out / "proofs"), m, CoverageTracker(),
        []) == []
    assert m.invariants_tested == 0
    assert not (out / "invariants.json").exists()
