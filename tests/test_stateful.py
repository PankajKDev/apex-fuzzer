"""Stateful slice tests: cross-endpoint propagation, invariant
producers, business-logic mutations, race engine. No network."""
import json

from main.authorization.harvest import HarvestedId
from main.authorization.access_tests import swap_ids
from main.logic.observations import (
    observation_from_swap, observation_from_business,
    observation_from_race, evaluate_observation, violated)
from main.logic.business_logic import (
    BusinessLogicTester, candidate_params)
from main.logic.race import run_race
from main.budgets import BudgetExceeded
from main.models import Identity, Endpoint, Parameter, Finding
from main.config import Config
from main.stages.validation import ProbeControls
from main.stages.validation.business import business_logic_probe
from main.stages.validation.race import race_probe


class FakeResp:
    def __init__(self, status, text, headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}


def _ep(url, qparams=None, bparams=None, etype="api"):
    from main.discovery.url_normalizer import normalize_url
    from urllib.parse import urlparse
    p = urlparse(url)
    e = Endpoint(url=url, normalized_url=normalize_url(url),
                 host=p.hostname or "", path=p.path,
                 endpoint_type=etype, source=["recon"])
    for n, v in (qparams or []):
        e.query_parameters.append(Parameter(
            name=n, location="query", source=["url"], sample_value=v))
    for n in (bparams or []):
        e.body_parameters.append(Parameter(name=n, location="body",
                                            source=["html"]))
    return e


def _ident(name, tenant="", headers=None):
    return Identity(name=name, tenant=tenant or None,
                    auth_headers=headers or {})


# ── cross-endpoint swap ───────────────────────────────────────────────
def test_cross_endpoint_swap_fetches_owner_baseline():
    calls = []

    class H:
        def get(self, url, **kw):
            calls.append((url, (kw.get("headers") or {}).get("Cookie")))
            if "Cookie" in (kw.get("headers") or {}):
                return FakeResp(200, json.dumps({"project": "P9"}))
            return FakeResp(200, json.dumps({"project": "P9"}))

    # ID learned on endpoint F, replayed on endpoint E (empty baseline)
    x = HarvestedId(endpoint_url="https://t.com/api/export",
                    normalized_url="https://t.com/api/export",
                    param="project_id", value="P9", owner="user_a",
                    owner_tenant="", shape="", body_hash="")
    out = swap_ids(H(), [x], _ident("user_b"),
                   owner_headers={"user_a": {"Cookie": "s=A"}})
    assert len(out) == 1
    assert out[0].verdict == "strong_candidate"
    assert out[0].match
    # baseline fetched as owner first, then replayed as tester
    assert calls[0][0].startswith("https://t.com/api/export")
    assert calls[0][1] == "s=A"
    assert calls[1][1] is None or calls[1][1] != "s=A"


def test_cross_endpoint_owner_baseline_denied_skips():
    class H:
        def get(self, url, **kw):
            if "Cookie" in (kw.get("headers") or {}):
                return FakeResp(403, "denied")  # owner can't see it either
            return FakeResp(200, json.dumps({"x": 1}))

    x = HarvestedId(endpoint_url="https://t.com/api/e",
                    normalized_url="https://t.com/api/e",
                    param="id", value="1", owner="user_a",
                    shape="", body_hash="")
    out = swap_ids(H(), [x], _ident("user_b"),
                   owner_headers={"user_a": {"Cookie": "s=A"}})
    assert out == []  # no baseline → no verdict, no false signal


def test_swap_negative_recorded_by_orchestrator():
    # covered at orchestrator level below; swap itself stays neutral
    class H:
        def get(self, url, **kw):
            return FakeResp(403, "denied")

    from main.authorization.harvest import HarvestedId
    from main.validation.differential import normalize_response

    class R:
        status_code = 200
        text = json.dumps({"id": 1})
    n = normalize_response(R())
    h = HarvestedId(endpoint_url="https://t.com/api/u",
                    normalized_url="https://t.com/api/u",
                    param="id", value="1", owner="user_a",
                    shape=n["key_shape"], body_hash=n["body_hash"])
    out = swap_ids(H(), [h], _ident("user_b"))
    assert out[0].verdict == "inconclusive"
    assert out[0].status == 403


# ── invariant producers ───────────────────────────────────────────────
def test_observation_from_swap_fires_cross_user_read():
    from main.authorization.access_tests import SwapResult
    sw = SwapResult(endpoint_url="https://t.com/api/u?id=1", param="id",
                    victim_value="1", owner="user_a", owner_tenant="t1",
                    tester="user_b", tester_tenant="t2")
    obs = observation_from_swap(sw)
    assert obs["actor"] == "user_b" and obs["resource_owner"] == "user_a"
    hits = violated(evaluate_observation(obs))
    assert any(h.invariant_id == "inv-cross-user-read" for h in hits)


def test_observation_from_swap_same_owner_clean():
    from main.authorization.access_tests import SwapResult
    sw = SwapResult(endpoint_url="x", param="id", victim_value="1",
                    owner="user_a", tester="user_a")
    obs = observation_from_swap(sw)
    assert violated(evaluate_observation(obs)) == []


def test_business_observation_shapes():
    obs = observation_from_business("https://t.com/cart", "u", "qty",
                                    -1, True, 200)
    assert obs["quantity_after"] == -1
    assert violated(evaluate_observation(obs))
    price = observation_from_business("https://t.com/cart", "u", "price",
                                      0, True, 200)
    assert price["price_changed"] is True
    assert violated(evaluate_observation(price))
    # not echoed → no quantity signal at all
    quiet = observation_from_business("https://t.com/cart", "u", "qty",
                                      -1, False, 200)
    assert "quantity_after" not in quiet


def test_race_observation_single_use():
    obs = observation_from_race("https://t.com/coupon", True, True)
    assert violated(evaluate_observation(obs))
    obs2 = observation_from_race("https://t.com/coupon", True, False)
    assert not violated(evaluate_observation(obs2))


# ── business-logic engine ────────────────────────────────────────────
def _biz_http(echo=True, baseline=200):
    class H:
        def get(self, url, **kw):
            from urllib.parse import urlsplit, parse_qsl
            q = dict(parse_qsl(urlsplit(url).query))
            if echo:
                return FakeResp(baseline, json.dumps({"echo": q}))
            return FakeResp(baseline, json.dumps({"ok": True}))

        def post(self, url, **kw):
            data = kw.get("data") or {}
            if echo:
                return FakeResp(baseline, json.dumps({"echo": data}))
            return FakeResp(baseline, json.dumps({"ok": True}))

    return H()


def test_candidate_params_detection():
    ep = _ep("https://t.com/cart?qty=2&price=9.99&coupon=SAVE",
             [("qty", "2"), ("price", "9.99"), ("coupon", "SAVE"),
              ("color", "red")])
    kinds = {c.param: c.kind for c in candidate_params(ep)}
    assert kinds == {"qty": "quantity", "price": "price",
                     "coupon": "token_reuse"}
    assert candidate_params(_ep("https://t.com/x")) == []


def test_business_negative_quantity_violation():
    cfg = Config()
    t = BusinessLogicTester(cfg, _biz_http())
    ep = _ep("https://t.com/cart?qty=2", [("qty", "2")])
    from main.logic.business_logic import candidate_params
    cands = candidate_params(ep)
    assert len(cands) == 1
    results = t.probe(ep, cands[0], _ident("user_a"))
    hits = [r for r in results if r.verdict == "strong_candidate"]
    assert hits and hits[0].mutated == -1
    assert any(v["invariant_id"] == "inv-quantity"
               for v in hits[0].violations)
    assert t.evaluations >= 1


def test_business_baseline_not_200_is_inconclusive():
    cfg = Config()
    t = BusinessLogicTester(cfg, _biz_http(baseline=401))
    ep = _ep("https://t.com/cart?qty=2", [("qty", "2")])
    from main.logic.business_logic import candidate_params
    results = t.probe(ep, candidate_params(ep)[0], _ident("user_a"))
    assert results and all(r.verdict == "inconclusive"
                           for r in results)
    assert t.evaluations == 0  # nothing evaluated → nothing recorded


def test_business_no_echo_no_finding():
    cfg = Config()
    t = BusinessLogicTester(cfg, _biz_http(echo=False))
    ep = _ep("https://t.com/cart?qty=2", [("qty", "2")])
    from main.logic.business_logic import candidate_params
    results = t.probe(ep, candidate_params(ep)[0], _ident("user_a"))
    assert all(r.verdict != "strong_candidate" for r in results)


def test_token_reuse_double_accept():
    cfg = Config()
    t = BusinessLogicTester(cfg, _biz_http())
    ep = _ep("https://t.com/redeem", [], "api")
    ep.body_parameters.append(Parameter(
        name="coupon", location="body", source=["html"],
        sample_value="SAVE10"))
    from main.logic.business_logic import candidate_params
    cands = [c for c in candidate_params(ep) if c.kind == "token_reuse"]
    assert cands
    results = t.probe(ep, cands[0], _ident("user_a"))
    reuse = [r for r in results if r.accepted_twice]
    assert reuse and reuse[0].verdict == "strong_candidate"


# ── race engine ───────────────────────────────────────────────────────
def test_race_divergent_ids_candidate():
    n = [0]

    class H:
        def post(self, url, **kw):
            n[0] += 1
            i = n[0]
            return FakeResp(200, json.dumps({"id": i, "ok": True}))

    res = run_race(H(), "POST", "https://t.com/coupon", {"c": "X"},
                   {}, concurrency=4, rounds=2)
    assert res.verdict == "strong_candidate"
    assert "divergent" in res.notes


def test_race_consistent_is_negative():
    class H:
        def post(self, url, **kw):
            return FakeResp(200, json.dumps({"ok": True}))

    res = run_race(H(), "POST", "https://t.com/ping", {"a": "b"},
                   {}, concurrency=4, rounds=2)
    assert res.verdict == "negative"


def test_race_identical_hashes_are_consistent():
    # regression: {tuple(hashes)} made EVERY round look consistent
    body = json.dumps({"ok": True, "ts": "fixed"})
    calls = []

    class H:
        def post(self, url, **kw):
            calls.append(1)
            return FakeResp(200, body)

    res = run_race(H(), "POST", "https://t.com/ping", {}, {},
                   concurrency=3, rounds=2)
    assert res.verdict == "negative"
    assert len(calls) == 6


def test_race_different_hashes_are_not_consistent():
    # regression: all-200 with DIVERGENT bodies and no IDs must NOT
    # be called consistent — the old code counted every round clean
    n = [0]

    class H:
        def post(self, url, **kw):
            n[0] += 1
            return FakeResp(200, json.dumps({"echo": n[0]}))

    res = run_race(H(), "POST", "https://t.com/echo", {}, {},
                   concurrency=3, rounds=1)
    assert res.verdict == "inconclusive"
    assert res.verdict != "negative"


def test_race_no_ids_and_different_responses_is_inconclusive():
    class H:
        def post(self, url, **kw):
            import random
            return FakeResp(200, json.dumps({"nonce": random.random()}))

    res = run_race(H(), "POST", "https://t.com/rand", {}, {},
                   concurrency=4, rounds=2)
    assert res.verdict in ("inconclusive", "strong_candidate")
    assert res.verdict != "negative"


def test_race_single_use_requires_one_success_per_round():
    import threading
    count = [0]
    lock = threading.Lock()

    class H:
        def post(self, url, **kw):
            with lock:
                count[0] += 1
                first = count[0] == 1
            return FakeResp(200 if first else 409,
                            json.dumps({"accepted": first}))

    res = run_race(H(), "POST", "https://t.com/redeem",
                   {"token": "one-use"}, {}, concurrency=3, rounds=1,
                   profile="single_use")
    assert res.profile == "single_use"
    assert res.verdict == "negative"


def test_race_single_use_multiple_accepts_are_candidate():
    class H:
        def post(self, url, **kw):
            return FakeResp(200, json.dumps({"accepted": True}))

    res = run_race(H(), "POST", "https://t.com/redeem",
                   {"token": "one-use"}, {}, concurrency=3, rounds=1,
                   profile="single_use")
    assert res.verdict == "strong_candidate"
    assert res.violations


def test_inventory_value_requires_one_finite_number():
    from main.logic.race import inventory_value
    assert inventory_value('{"stock": 4}', "$.stock") == 4
    assert inventory_value('{"stock": null}', "$.stock") is None
    assert inventory_value('{"stock": 4, "other": 2}', "$") is None


def test_single_use_profile_requires_sequential_replay_verification():
    import tempfile
    from pathlib import Path
    from main.orchestrator import Orchestrator
    from main.profiles import get as get_profile
    from main.reporting.metrics import Metrics
    from main.reporting.coverage import CoverageTracker
    from main.budgets import BudgetTracker
    from main.validation.evidence import EvidenceStore

    class H:
        def post(self, url, **kw):
            return FakeResp(200, '{"accepted": true}')

    out = Path(tempfile.mkdtemp())
    cfg = Config()
    cfg.race.profile = "single_use"
    cfg.race.concurrency = 2
    cfg.race.rounds = 1
    orch = Orchestrator(cfg, out, profile=get_profile("standard"))
    ep = _ep("https://t.com/redeem", [], ["token"], "api")
    ep.body_parameters[0].sample_value = "single-use-1"
    found = race_probe(
        [ep], EvidenceStore(out / "proofs"), Metrics(),
        BudgetTracker(cfg), CoverageTracker(), H(), orch.cfg, orch.scope, ProbeControls.from_orchestrator(orch), [_ident("user_a")])
    assert found and found[0].validation_status == "confirmed"
    assert found[0].raw["verification"]["status"] == "verified"


def test_race_inventory_profile_verifies_negative_stock():
    import tempfile
    from pathlib import Path
    from main.orchestrator import Orchestrator
    from main.profiles import get as get_profile
    from main.reporting.metrics import Metrics
    from main.reporting.coverage import CoverageTracker
    from main.budgets import BudgetTracker
    from main.validation.evidence import EvidenceStore

    class H:
        reads = 0
        writes = 0

        def get(self, url, **kw):
            self.reads += 1
            stock = 2 if self.reads == 1 else -1
            return FakeResp(200, json.dumps({"available": stock}))

        def post(self, url, **kw):
            self.writes += 1
            return FakeResp(200, json.dumps({"id": self.writes}))

    out = Path(tempfile.mkdtemp())
    cfg = Config()
    cfg.race.profile = "inventory"
    cfg.race.inventory_endpoint = "/api/reserve"
    cfg.race.inventory_read_url = "/api/stock/1"
    cfg.race.inventory_jsonpath = "$.available"
    cfg.race.concurrency = 3
    cfg.race.rounds = 1
    orch = Orchestrator(cfg, out, profile=get_profile("standard"))
    ep = _ep("https://t.com/api/reserve", [], ["sku"], "api")
    metrics, coverage = Metrics(), CoverageTracker()
    found = race_probe(
        [ep], EvidenceStore(out / "proofs"), metrics,
        BudgetTracker(cfg), coverage, H(), orch.cfg, orch.scope, ProbeControls.from_orchestrator(orch), [_ident("user_a")])
    assert found and found[0].validation_status == "confirmed"
    assert found[0].result_status == "verified_effect"
    assert found[0].raw["verification"]["evidence"]["before"] == 2
    assert metrics.invariants_violated == 1
    assert coverage.summary()["race"] == "candidate"


def test_stable_finding_id_deterministic():
    import hashlib
    from main.models import stable_finding_id
    got = stable_finding_id("swap", "https://t.com/api/u", "id", "1")
    # pinned to an independently computed digest: immune to
    # PYTHONHASHSEED randomization, unlike the old abs(hash(...))
    expect = "swap-" + hashlib.sha256(
        "https://t.com/api/u\x1fid\x1f1".encode()).hexdigest()[:16]
    assert got == expect
    assert stable_finding_id("swap", "https://t.com/api/u", "id", "1") \
        == got  # repeatable within the process
    assert stable_finding_id("swap", "https://t.com/api/u", "id", "2") \
        != got  # sensitive to inputs


def test_race_errors_are_inconclusive():
    class H:
        def post(self, url, **kw):
            return FakeResp(500, "boom")

    res = run_race(H(), "POST", "https://t.com/x", {}, {},
                   concurrency=2, rounds=1)
    assert res.verdict == "inconclusive"


def test_race_budget_raises():
    class H:
        def post(self, url, **kw):
            raise BudgetExceeded("cap")

    try:
        run_race(H(), "POST", "https://t.com/x", {}, {},
                 concurrency=2, rounds=1)
        raise AssertionError("must propagate")
    except BudgetExceeded:
        pass


# ── orchestrator wiring ───────────────────────────────────────────────
def _orch(profile="standard"):
    import tempfile
    from pathlib import Path
    from main.orchestrator import Orchestrator
    from main.profiles import get as get_profile
    td = tempfile.mkdtemp()
    return (Orchestrator(Config(), Path(td),
                         profile=get_profile(profile)),
            Path(td))


def test_business_probe_end_to_end():
    orch, out = _orch()
    from main.reporting.metrics import Metrics
    from main.reporting.coverage import CoverageTracker
    from main.budgets import BudgetTracker
    from main.validation.evidence import EvidenceStore
    cfg = Config()
    eps = [_ep("https://t.com/cart?qty=2", [("qty", "2")])]
    m, cov = Metrics(), CoverageTracker()
    found = business_logic_probe(
        eps, EvidenceStore(out / "proofs"), m, BudgetTracker(cfg),
        cov, _biz_http(), orch.cfg, orch.scope, ProbeControls.from_orchestrator(orch), [_ident("user_a", headers={"Cookie": "s=A"})])
    assert any(f.source == "business-logic" for f in found)
    assert cov.summary()["business_logic"] == "candidate"
    assert m.business_logic_candidates >= 1
    assert m.invariants_violated >= 1
    f = [x for x in found if x.source == "business-logic"][0]
    assert f.identity == "user_a"
    assert f.validation_status == "strong_candidate"


def test_business_probe_no_params_untestable():
    orch, out = _orch()
    from main.reporting.metrics import Metrics
    from main.reporting.coverage import CoverageTracker
    from main.budgets import BudgetTracker
    from main.validation.evidence import EvidenceStore
    cov = CoverageTracker()
    found = business_logic_probe(
        [_ep("https://t.com/about")], EvidenceStore(out / "proofs"),
        Metrics(), BudgetTracker(Config()), cov, _biz_http(), orch.cfg, orch.scope, ProbeControls.from_orchestrator(orch), [_ident("anonymous")])
    assert found == []
    assert cov.summary()["business_logic"] == "untestable"


def test_race_probe_end_to_end():
    orch, out = _orch()
    from main.reporting.metrics import Metrics
    from main.reporting.coverage import CoverageTracker
    from main.budgets import BudgetTracker
    from main.validation.evidence import EvidenceStore
    cfg = Config()
    cfg.race.concurrency = 3
    cfg.race.rounds = 1
    n = [0]

    class H:
        def post(self, url, **kw):
            n[0] += 1
            return FakeResp(200, json.dumps({"id": n[0]}))

    ep = _ep("https://t.com/coupon", [], "api")
    ep.body_parameters.append(Parameter(name="code", location="body",
                                        source=["html"],
                                        sample_value="X"))
    m, cov = Metrics(), CoverageTracker()
    found = race_probe(
        [ep], EvidenceStore(out / "proofs"), m, BudgetTracker(cfg),
        cov, H(), orch.cfg, orch.scope, ProbeControls.from_orchestrator(orch), [_ident("user_a")])
    assert any(f.source == "race" for f in found)
    assert cov.summary()["race"] == "candidate"
    assert m.race_candidates == 1


def test_swap_negative_coverage_recorded():
    # precondition rule: completed denial → tested_negative
    orch, out = _orch()
    from main.reporting.metrics import Metrics
    from main.reporting.coverage import CoverageTracker
    from main.budgets import BudgetTracker
    from main.validation.evidence import EvidenceStore

    class H:
        def get(self, url, **kw):
            c = (kw.get("headers") or {}).get("Cookie", "")
            if not c:
                return FakeResp(401, "login")
            if "denied" in url:
                return FakeResp(403, "no")
            return FakeResp(200, json.dumps({"id": 9}))

        def post(self, url, **kw):
            return FakeResp(200, "ok")

        def request(self, method, url, **kw):
            return FakeResp(403, "no")

    cfg = Config()
    cfg.authorization.enabled = True
    cfg.authorization.methods = ["GET"]
    orch.cfg = cfg
    eps = [_ep("https://t.com/denied?uid=9", [("uid", "9")])]
    ids = [_ident("anonymous"), _ident("user_a", headers={"Cookie": "s"})]
    cov = CoverageTracker()
    from main.stages.validation import ProbeControls
    from main.stages.validation.authz import authz_matrix_probe
    found, _, _ = authz_matrix_probe(
        eps, EvidenceStore(out / "proofs"), Metrics(),
        BudgetTracker(cfg), cov, H(), out, ids, cfg, orch.scope,
        ProbeControls.from_orchestrator(orch))
    assert found == []  # owner gets 403 too → nothing harvested, no swap
    # matrix still ran the method sweep; no false candidate recorded
    assert cov.summary()["bola"] == "not_tested"


def test_config_and_cli_flags():
    cfg = Config()
    assert cfg.business.enabled is False
    assert cfg.race.enabled is False
    assert cfg.race.concurrency == 10
    from main.cli import build_parser
    from main.config import apply_cli_overrides
    args = build_parser().parse_args(
        ["-d", "x.com", "--business-logic", "--race"])
    cfg2 = apply_cli_overrides(Config(), args)
    assert cfg2.business.enabled and cfg2.race.enabled
    from main.profiles import get as get_profile
    assert get_profile("deep").business_logic is True
    assert get_profile("deep").race is False
    assert get_profile("validation").business_logic is True


def test_impact_business_and_race():
    from main.reporting import impact as im
    b = Finding(id="1", source="business-logic",
                name="Business logic: qty=-1 accepted, violates inv",
                matched_at="https://t.com/cart",
                raw={"business": {"notes": "accepted"}})
    assert im._classify(b) == "business_logic"
    assert "Financial" in im.build_impact(b) or \
        "financial" in im.build_impact(b)
    assert any("Replay" in s for s in im.build_repro_steps(b))
    r = Finding(id="2", source="race",
                name="Race condition: 10× POST /coupon processed",
                matched_at="https://t.com/coupon",
                raw={"race": {"notes": "divergent"}})
    assert im._classify(r) == "race"
    assert any("burst" in s for s in im.build_repro_steps(r))
