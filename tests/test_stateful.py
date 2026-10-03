"""Stateful slice tests: cross-endpoint propagation, invariant
producers, business-logic mutations, race engine. No network."""
import json

from apex_fuzzer.authorization.harvest import HarvestedId
from apex_fuzzer.authorization.access_tests import swap_ids
from apex_fuzzer.logic.observations import (
    observation_from_swap, observation_from_business,
    observation_from_race, evaluate_observation, violated)
from apex_fuzzer.logic.business_logic import (
    BusinessLogicTester, candidate_params)
from apex_fuzzer.logic.race import run_race
from apex_fuzzer.budgets import BudgetExceeded
from apex_fuzzer.models import Identity, Endpoint, Parameter, Finding
from apex_fuzzer.config import Config


class FakeResp:
    def __init__(self, status, text, headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}


def _ep(url, qparams=None, bparams=None, etype="api"):
    from apex_fuzzer.discovery.url_normalizer import normalize_url
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

    from apex_fuzzer.authorization.harvest import HarvestedId
    from apex_fuzzer.validation.differential import normalize_response

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
    from apex_fuzzer.authorization.access_tests import SwapResult
    sw = SwapResult(endpoint_url="https://t.com/api/u?id=1", param="id",
                    victim_value="1", owner="user_a", owner_tenant="t1",
                    tester="user_b", tester_tenant="t2")
    obs = observation_from_swap(sw)
    assert obs["actor"] == "user_b" and obs["resource_owner"] == "user_a"
    hits = violated(evaluate_observation(obs))
    assert any(h.invariant_id == "inv-cross-user-read" for h in hits)


def test_observation_from_swap_same_owner_clean():
    from apex_fuzzer.authorization.access_tests import SwapResult
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
    from apex_fuzzer.logic.business_logic import candidate_params
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
    from apex_fuzzer.logic.business_logic import candidate_params
    results = t.probe(ep, candidate_params(ep)[0], _ident("user_a"))
    assert results and all(r.verdict == "inconclusive"
                           for r in results)
    assert t.evaluations == 0  # nothing evaluated → nothing recorded


def test_business_no_echo_no_finding():
    cfg = Config()
    t = BusinessLogicTester(cfg, _biz_http(echo=False))
    ep = _ep("https://t.com/cart?qty=2", [("qty", "2")])
    from apex_fuzzer.logic.business_logic import candidate_params
    results = t.probe(ep, candidate_params(ep)[0], _ident("user_a"))
    assert all(r.verdict != "strong_candidate" for r in results)


def test_token_reuse_double_accept():
    cfg = Config()
    t = BusinessLogicTester(cfg, _biz_http())
    ep = _ep("https://t.com/redeem", [], "api")
    ep.body_parameters.append(Parameter(
        name="coupon", location="body", source=["html"],
        sample_value="SAVE10"))
    from apex_fuzzer.logic.business_logic import candidate_params
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
    from apex_fuzzer.orchestrator import Orchestrator
    from apex_fuzzer.profiles import get as get_profile
    td = tempfile.mkdtemp()
    return (Orchestrator(Config(), Path(td),
                         profile=get_profile(profile)),
            Path(td))


def test_business_probe_end_to_end():
    orch, out = _orch()
    from apex_fuzzer.reporting.metrics import Metrics
    from apex_fuzzer.reporting.coverage import CoverageTracker
    from apex_fuzzer.budgets import BudgetTracker
    from apex_fuzzer.validation.evidence import EvidenceStore
    cfg = Config()
    eps = [_ep("https://t.com/cart?qty=2", [("qty", "2")])]
    m, cov = Metrics(), CoverageTracker()
    found = orch._business_logic_probe(
        eps, EvidenceStore(out / "proofs"), m, BudgetTracker(cfg),
        cov, _biz_http(),
        [_ident("user_a", headers={"Cookie": "s=A"})])
    assert any(f.source == "business-logic" for f in found)
    assert cov.summary()["business_logic"] == "candidate"
    assert m.business_logic_candidates >= 1
    assert m.invariants_violated >= 1
    f = [x for x in found if x.source == "business-logic"][0]
    assert f.identity == "user_a"
    assert f.validation_status == "strong_candidate"


def test_business_probe_no_params_untestable():
    orch, out = _orch()
    from apex_fuzzer.reporting.metrics import Metrics
    from apex_fuzzer.reporting.coverage import CoverageTracker
    from apex_fuzzer.budgets import BudgetTracker
    from apex_fuzzer.validation.evidence import EvidenceStore
    cov = CoverageTracker()
    found = orch._business_logic_probe(
        [_ep("https://t.com/about")], EvidenceStore(out / "proofs"),
        Metrics(), BudgetTracker(Config()), cov, _biz_http(),
        [_ident("anonymous")])
    assert found == []
    assert cov.summary()["business_logic"] == "untestable"


def test_race_probe_end_to_end():
    orch, out = _orch()
    from apex_fuzzer.reporting.metrics import Metrics
    from apex_fuzzer.reporting.coverage import CoverageTracker
    from apex_fuzzer.budgets import BudgetTracker
    from apex_fuzzer.validation.evidence import EvidenceStore
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
    found = orch._race_probe(
        [ep], EvidenceStore(out / "proofs"), m, BudgetTracker(cfg),
        cov, H(), [_ident("user_a")])
    assert any(f.source == "race" for f in found)
    assert cov.summary()["race"] == "candidate"
    assert m.race_candidates == 1


def test_swap_negative_coverage_recorded():
    # precondition rule: completed denial → tested_negative
    orch, out = _orch()
    from apex_fuzzer.reporting.metrics import Metrics
    from apex_fuzzer.reporting.coverage import CoverageTracker
    from apex_fuzzer.budgets import BudgetTracker
    from apex_fuzzer.validation.evidence import EvidenceStore
    from apex_fuzzer.validation.differential import DifferentialTester

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
    found = orch._authz_matrix_probe(
        eps, EvidenceStore(out / "proofs"), Metrics(),
        BudgetTracker(cfg), cov, H(), out, ids)
    assert found == []  # owner gets 403 too → nothing harvested, no swap
    # matrix still ran the method sweep; no false candidate recorded
    assert cov.summary()["bola"] == "not_tested"


def test_config_and_cli_flags():
    cfg = Config()
    assert cfg.business.enabled is False
    assert cfg.race.enabled is False
    assert cfg.race.concurrency == 10
    from apex_fuzzer.cli import build_parser
    from apex_fuzzer.config import apply_cli_overrides
    args = build_parser().parse_args(
        ["-d", "x.com", "--business-logic", "--race"])
    cfg2 = apply_cli_overrides(Config(), args)
    assert cfg2.business.enabled and cfg2.race.enabled
    from apex_fuzzer.profiles import get as get_profile
    assert get_profile("deep").business_logic is True
    assert get_profile("deep").race is False
    assert get_profile("validation").business_logic is True


def test_impact_business_and_race():
    from apex_fuzzer.reporting import impact as im
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
