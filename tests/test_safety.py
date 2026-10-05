"""Milestone 1 tests: impact levels, authorization gates, cost
planning, dry-run, budgets, stop controls, strict refusals. No
network in any test (dry-run asserts zero HTTP explicitly)."""
import pytest

from main.safety.impact import (
    max_level, needs_authorization, MODULE_LEVELS, ModuleState,
    PASSIVE, READ_ONLY, ACTIVE, STATEFUL, BURST, CLAIMING)
from main.safety.authorization import (
    Authorization, AuthorizationRefused, EXIT_OK, EXIT_FAIL, EXIT_REFUSED)
from main.safety.preflight import (
    resolve_modules, RequestPlan, plan_differential, plan_authz_matrix,
    plan_race, plan_business, plan_second_order, plan_oast,
    plan_second_order_ssrf, plan_graphql_introspection,
    render_plan_text, check_fit, StopFlag, Pacer,
    get_interrupt_flag, install_signal_handlers)
from main.config import Config
from main.budgets import BudgetTracker, BudgetExceeded


def _strict_cfg(**kw):
    cfg = Config()
    cfg.safety.strict = True
    cfg.safety.authorization_ref = "ENG-2026-1"
    cfg.safety.approved_domains = ["staging.example.com"]
    cfg.safety.allow_state_change = True
    cfg.safety.allowed_modules = ["business_logic", "race",
                                  "second_order", "authz_matrix",
                                  "takeover_claim", "login"]
    for k, v in kw.items():
        setattr(cfg.safety, k, v)
    return cfg


# ── impact levels ─────────────────────────────────────────────────────
def test_max_level_and_gating():
    assert max_level([]) == PASSIVE
    assert max_level([ModuleState("x", READ_ONLY, False)]) == PASSIVE
    assert max_level([ModuleState("nuclei", ACTIVE, True),
                      ModuleState("race", BURST, False)]) == ACTIVE
    assert max_level([ModuleState("race", BURST, True)]) == BURST
    assert needs_authorization(STATEFUL)
    assert needs_authorization(BURST)
    assert needs_authorization(CLAIMING)
    assert not needs_authorization(ACTIVE)
    assert not needs_authorization(READ_ONLY)
    assert MODULE_LEVELS["authz_matrix"] == STATEFUL  # verbs, not reads
    assert MODULE_LEVELS["differential"] == ACTIVE
    assert MODULE_LEVELS["race"] == BURST


def test_resolve_modules_mirrors_orchestrator(monkeypatch):
    from main.profiles import get as get_profile
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    cfg = Config()
    states = {s.name: s for s in
              resolve_modules(cfg, get_profile("deep"))}
    assert states["authz_matrix"].enabled is True
    assert states["race"].enabled is False
    assert states["second_order"].enabled is True
    std = {s.name: s for s in
           resolve_modules(cfg, get_profile("standard"))}
    assert std["authz_matrix"].enabled is False
    assert std["recon"].enabled is True
    # takeover claiming needs the token present, fingerprint does not
    assert states["takeover_fingerprint"].enabled is True
    assert states["takeover_claim"].enabled is False

    cfg = Config()
    cfg.validation.second_order_ssrf = True
    ssrf_states = {s.name: s for s in
                   resolve_modules(cfg, get_profile("standard"))}
    assert ssrf_states["second_order"].enabled is True
    assert ssrf_states["oast"].enabled is True


# ── authorization gates ───────────────────────────────────────────────
def test_auth_ok_when_complete():
    auth = Authorization.from_safety_cfg(_strict_cfg())
    assert auth.check("https://staging.example.com/api",
                      ["race", "business_logic"]) == []


def test_auth_missing_reference():
    auth = Authorization.from_safety_cfg(
        _strict_cfg(authorization_ref=""))
    reasons = auth.check("https://staging.example.com", ["race"])
    assert any("reference" in r for r in reasons)


def test_auth_missing_ack():
    auth = Authorization.from_safety_cfg(
        _strict_cfg(allow_state_change=False))
    reasons = auth.check("https://staging.example.com", ["race"])
    assert any("acknowledged" in r or "ack" in r for r in reasons)


def test_auth_non_allowlisted_target():
    auth = Authorization.from_safety_cfg(_strict_cfg())
    reasons = auth.check("https://evil.com/", ["race"])
    assert any("allowlisted" in r for r in reasons)
    # subdomains of approved domains pass
    assert auth.check("https://a.staging.example.com", ["race"]) == []


def test_auth_cidr_matching():
    cfg = _strict_cfg(approved_domains=[])
    cfg.safety.approved_cidrs = ["10.0.0.0/8"]
    auth = Authorization.from_safety_cfg(cfg)
    assert auth.check("http://10.1.2.3/", ["race"]) == []
    assert auth.check("http://11.0.0.1/", ["race"]) != []
    # malformed CIDR never matches, fails closed
    cfg.safety.approved_cidrs = ["not-a-cidr"]
    assert Authorization.from_safety_cfg(cfg).check(
        "http://10.1.2.3/", ["race"]) != []


def test_auth_expired_and_not_yet_valid():
    auth = Authorization.from_safety_cfg(
        _strict_cfg(valid_until="2020-01-01T00:00:00Z"))
    assert auth.check("https://staging.example.com", ["race"]) != []
    auth2 = Authorization.from_safety_cfg(
        _strict_cfg(valid_from="2999-01-01T00:00:00Z"))
    assert auth2.check("https://staging.example.com", ["race"]) != []
    auth3 = Authorization.from_safety_cfg(
        _strict_cfg(valid_from="2020-01-01T00:00:00Z",
                    valid_until="2999-01-01T00:00:00Z"))
    assert auth3.check("https://staging.example.com", ["race"]) == []
    # malformed bounds fail closed
    auth4 = Authorization.from_safety_cfg(
        _strict_cfg(valid_until="tomorrow-ish"))
    assert auth4.check("https://staging.example.com", ["race"]) != []


def test_auth_unlisted_module():
    auth = Authorization.from_safety_cfg(
        _strict_cfg(allowed_modules=["race"]))
    reasons = auth.check("https://staging.example.com",
                         ["race", "business_logic"])
    assert any("business_logic" in r for r in reasons)


def test_auth_non_gated_modules_need_nothing():
    auth = Authorization.from_safety_cfg(_strict_cfg(
        authorization_ref="", allow_state_change=False,
        approved_domains=[], allowed_modules=[]))
    assert auth.check("https://anything.example/", ["nuclei"]) == []


def test_refusal_carries_reasons():
    err = AuthorizationRefused(["a", "b"])
    assert err.reasons == ["a", "b"] and "a; b" in str(err)
    assert (EXIT_OK, EXIT_FAIL, EXIT_REFUSED) == (0, 1, 2)


# ── cost planning ─────────────────────────────────────────────────────
def test_request_plan_totals():
    p = RequestPlan("race", "e", 1, 2, 30, 1)
    assert p.total == 34
    with pytest.raises(AttributeError):
        p.total = 5  # frozen dataclass rejects mutation


def test_planner_math():
    assert plan_race(3, 10, 3).total == 96  # burst + 2 verify/read requests
    assert plan_race(3, 10, 3).concurrency_requests == 90
    assert plan_race(3, 10, 3).verification_requests == 6
    d = plan_differential(5, 3)
    assert d.total == 15 and d.mutation_requests == 15
    a = plan_authz_matrix(2, 3, 5, 3)
    # harvest 2×3 + swap 2×3×2×2 + sweep 2×5×3
    assert a.baseline_requests == 6
    assert a.total == 6 + 24 + 30
    b = plan_business(4, 3)
    assert b.total == 4 * (1 + 3 * 5)
    s = plan_second_order(2, 10)
    assert (s.mutation_requests, s.verification_requests,
            s.total) == (2, 20, 22)
    o = plan_oast(4, 3)
    assert o.total == 144
    ssrf = plan_second_order_ssrf(6, 4)
    assert (ssrf.mutation_requests, ssrf.verification_requests,
            ssrf.total) == (6, 24, 30)
    g = plan_graphql_introspection(4)
    assert (g.mutation_requests, g.total) == (4, 4)


# ── dry-run: zero network ─────────────────────────────────────────────
def test_dry_run_sends_zero_requests(tmp_path, monkeypatch):
    from main.orchestrator import Orchestrator
    from main.profiles import get as get_profile

    def _boom(*a, **k):
        raise AssertionError("dry-run must not touch the network")
    import requests
    monkeypatch.setattr(requests, "get", _boom)
    monkeypatch.setattr(requests, "post", _boom)
    monkeypatch.setattr("socket.getaddrinfo", _boom)
    cfg = _strict_cfg()
    cfg.business.enabled = True
    orch = Orchestrator(cfg, tmp_path, profile=get_profile("standard"))
    plan = orch.dry_run("https://staging.example.com")
    assert plan["strict"] is True and plan["refusal"] == []
    assert plan["inventory_estimated"] is True
    mods = {m["name"]: m for m in plan["modules"]}
    assert mods["business_logic"]["enabled"] is True
    assert mods["race"]["enabled"] is False
    text = render_plan_text(plan)
    assert "TOTAL planned stateful requests" in text
    assert (tmp_path / "staging.example.com" / "preflight.json"
            ).exists()


def test_dry_run_uses_inventory_when_present(tmp_path):
    from main.orchestrator import Orchestrator
    from main.profiles import get as get_profile
    cfg = Config()
    orch = Orchestrator(cfg, tmp_path, profile=get_profile("standard"))
    host_dir = tmp_path / "t.com"
    host_dir.mkdir()
    (host_dir / "endpoints.jsonl").write_text('{"url": "https://t.com/a"}\n'
                                              '{"url": "https://t.com/b"}\n')
    plan = orch.dry_run("https://t.com")
    assert plan["inventory_endpoints"] == 2
    assert plan["inventory_estimated"] is False
    assert plan["target_in_scope"] is True


def test_dry_run_flags_out_of_scope_target(tmp_path):
    from main.orchestrator import Orchestrator
    from main.profiles import get as get_profile
    cfg = Config()
    cfg.scope.allowed_domains = ["other.com"]
    orch = Orchestrator(cfg, tmp_path, profile=get_profile("standard"))
    plan = orch.dry_run("https://t.com")
    assert plan["target_in_scope"] is False
    assert "outside the configured scope" in render_plan_text(plan)


def test_dry_run_refusal_reported_not_raised(tmp_path):
    from main.orchestrator import Orchestrator
    from main.profiles import get as get_profile
    cfg = _strict_cfg(allowed_modules=[])  # business not allowlisted
    cfg.business.enabled = True
    orch = Orchestrator(cfg, tmp_path, profile=get_profile("standard"))
    plan = orch.dry_run("https://staging.example.com")
    assert plan["refusal"]  # reported in-plan, nothing raised
    assert "business-logic" in render_plan_text(plan) or \
        "business_logic" in render_plan_text(plan)


def test_check_fit():
    cfg = Config()
    ok, reasons = check_fit(cfg, 10**9)
    assert ok is False and reasons  # host cap trips first
    cfg.budgets.requests_per_host = 10**12
    ok, _ = check_fit(cfg, 5)
    assert ok is True
    cfg.safety.max_requests = 10
    ok, reasons = check_fit(cfg, 11)
    assert ok is False and any("max_requests" in r for r in reasons)


# ── budgets: global + mutation caps, reservation ──────────────────────
def test_max_requests_gate():
    cfg = Config()
    cfg.safety.max_requests = 2
    t = BudgetTracker(cfg)
    assert t.consume_request("h", "e1")
    assert t.consume_request("h", "e2")
    assert t.consume_request("h", "e3") is False
    assert t.usage.total_requests == 2 and t.usage.blocked == 1
    assert t.reserve(1) is False
    assert t.reserve(0) is True


def test_max_state_changes_gate():
    cfg = Config()
    cfg.safety.max_state_changes = 1
    t = BudgetTracker(cfg)
    assert t.consume_mutation("h", "e1") is True
    assert t.consume_mutation("h", "e2") is False
    assert t.usage.mutating_requests == 1
    # mutating also counts as a plain request
    assert t.usage.total_requests == 1


def test_caps_unset_by_default():
    t = BudgetTracker(Config())
    for _ in range(50):
        assert t.consume_request("h", "e")
        assert t.consume_mutation("h", "e")
    assert t.reserve(10**9) is True


def test_budget_usage_roundtrip_with_new_counters():
    from main.budgets import BudgetUsage
    u = BudgetUsage(total_requests=3, mutating_requests=1, blocked=2)
    rt = BudgetUsage.from_dict(u.to_dict())
    assert (rt.total_requests, rt.mutating_requests, rt.blocked) == \
        (3, 1, 2)
    # old blobs without the counters still load
    rt2 = BudgetUsage.from_dict({"blocked": 1})
    assert rt2.total_requests == 0


def test_http_client_mutation_gate():
    from main.orchestrator import _HTTPClient
    cfg = Config()
    cfg.safety.max_state_changes = 0
    client = _HTTPClient(budgets=BudgetTracker(cfg))

    class FakeSession:
        def post(self, *a, **k):
            raise AssertionError("must not fire")

        def get(self, *a, **k):
            class R:
                status_code = 200
            return R()
    client.session = FakeSession()
    try:
        client.post("https://t.com/form")
        raise AssertionError("must raise")
    except BudgetExceeded:
        pass
    assert client.get("https://t.com/").status_code == 200  # reads pass


# ── stop flag, pacer, signals ─────────────────────────────────────────
def test_stop_flag_halts_sweep():
    from main.orchestrator import Orchestrator
    from main.profiles import get as get_profile
    import tempfile
    from pathlib import Path
    orch = Orchestrator(Config(), Path(tempfile.mkdtemp()),
                        profile=get_profile("standard"))
    assert orch._halted() is False  # no flag set, no signal
    orch._stop_flag.set()
    assert orch._halted() is True


def test_stop_on_candidate_halts_remaining_targets():
    import tempfile
    from pathlib import Path
    from main.orchestrator import Orchestrator
    from main.profiles import get as get_profile
    from main.reporting.metrics import Metrics
    from main.reporting.coverage import CoverageTracker
    from main.validation.evidence import EvidenceStore
    from main.validation.differential import DifferentialTester
    from main.models import Endpoint, Parameter
    from main.config import AuthContext
    import json as _json

    class H:
        def get(self, url, **kw):
            class R:
                status_code = 200
                text = _json.dumps({"id": 1})
                headers = {}
            return R()

    out = Path(tempfile.mkdtemp())
    cfg = Config()
    cfg.validation.differential = True
    cfg.safety.stop_on_candidate = True
    cfg.auth.contexts = [AuthContext(name="a", headers={"C": "1"}),
                         AuthContext(name="b", headers={"C": "2"})]
    orch = Orchestrator(cfg, out, profile=get_profile("standard"))
    orch._stop_flag = StopFlag()
    orch._pacer = Pacer(0)
    eps = []
    for i in range(3):
        e = Endpoint(url=f"https://t.com/api/{i}",
                     normalized_url=f"https://t.com/api/{i}", host="t.com",
                     path=f"/api/{i}", endpoint_type="api",
                     source=["recon"])
        e.query_parameters.append(Parameter(name="id", location="query",
                                            source=["url"]))
        eps.append(e)
    m = Metrics()
    found = orch._differential_probe(
        eps, DifferentialTester(cfg, H()), EvidenceStore(out / "proofs"),
        m, BudgetTracker(cfg), CoverageTracker())
    # first endpoint yields BOLA (identical bodies) → flag set → rest
    # of the sweep halts; only one endpoint's probes ran
    assert m.differential_probes == 1
    assert len(found) == 1


def test_pacer_sleeps_only_when_configured(monkeypatch):
    slept = []
    monkeypatch.setattr("time.sleep", lambda s: slept.append(s))
    Pacer(0).wait()
    assert slept == []
    Pacer(250).wait()
    assert slept == [0.25]


def test_signal_handler_sets_flag_and_second_forces_exit():
    import signal as _signal
    install_signal_handlers()
    install_signal_handlers()  # idempotent
    flag = get_interrupt_flag()
    assert flag.is_set() is False
    import os
    os.kill(os.getpid(), _signal.SIGINT)
    assert flag.is_set() is True
    flag.clear()


def test_cli_safety_flags():
    from main.cli import build_parser
    from main.config import apply_cli_overrides
    args = build_parser().parse_args(
        ["-d", "x.com", "--strict", "--auth-ref", "R-1",
         "--ack-state-change", "--dry-run", "--max-requests", "50",
         "--max-state-changes", "5", "--stop-on-candidate",
         "--cooldown-ms", "100"])
    cfg = apply_cli_overrides(Config(), args)
    assert cfg.safety.strict is True
    assert cfg.safety.authorization_ref == "R-1"
    assert cfg.safety.allow_state_change is True
    assert cfg.safety.max_requests == 50
    assert cfg.safety.max_state_changes == 5
    assert cfg.safety.stop_on_candidate is True
    assert cfg.safety.cooldown_ms == 100


def test_safety_config_yaml_and_defaults(tmp_path):
    cfg = Config()
    assert cfg.safety.strict is False
    assert cfg.safety.max_requests is None
    f = tmp_path / "c.yaml"
    f.write_text("safety:\n  strict: true\n"
                 "  authorization_ref: R\n"
                 "  approved_domains: [a.com]\n"
                 "  allowed_modules: [race]\n"
                 "  max_requests: 100\n")
    loaded = Config.load(f)
    assert loaded.safety.strict is True
    assert loaded.safety.approved_domains == ["a.com"]
    assert loaded.safety.max_requests == 100


def test_strict_refusal_end_to_end(tmp_path):
    from main.orchestrator import Orchestrator
    from main.profiles import get as get_profile
    cfg = Config()
    cfg.safety.strict = True  # nothing else configured
    cfg.race.enabled = True
    orch = Orchestrator(cfg, tmp_path, profile=get_profile("standard"))
    try:
        orch._preflight_or_refuse("https://t.com", tmp_path,
                                  StopFlag())
        raise AssertionError("must refuse")
    except AuthorizationRefused as e:
        assert len(e.reasons) >= 3  # ref, ack, allowlist, modules...


def test_non_strict_never_refuses(tmp_path):
    from main.orchestrator import Orchestrator
    from main.profiles import get as get_profile
    cfg = Config()
    cfg.race.enabled = True  # would need 4+ gates under strict
    orch = Orchestrator(cfg, tmp_path, profile=get_profile("standard"))
    info = orch._preflight_or_refuse("https://t.com", tmp_path,
                                     StopFlag())
    assert info["strict"] is False and info["refusal"] == []
    assert info["max_impact"] == "burst"


def test_report_safety_block(tmp_path):
    from main.reporting.html import render_html
    out = tmp_path / "r.html"
    render_html(out, "t.com", [], [], {},
                safety_info={"strict": True, "max_impact": "burst",
                             "gated_modules": ["race"],
                             "authorization": {"reference": "R-1"}})
    html = out.read_text()
    assert "Authorization" in html and "R-1" in html
    out2 = tmp_path / "r2.html"
    render_html(out2, "t.com", [], [], {})
    assert "Authorization" not in out2.read_text()


def test_doctor_config_checks(tmp_path, monkeypatch):
    from main.cli import doctor_config
    monkeypatch.chdir(tmp_path)
    # default config.yaml absent → defaults → clean
    assert doctor_config(Config()) == []
    cfg = Config()
    cfg.ai.enabled = True
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    assert any("GEMINI_API_KEY" in p for p in doctor_config(cfg))
    cfg = Config()
    cfg.ai.enabled = True
    cfg.ai.provider = "mystery"
    assert any("unknown ai.provider" in p for p in doctor_config(cfg))
    cfg = Config()
    cfg.race.enabled = True
    assert any("strict" in p for p in doctor_config(cfg))
    cfg = Config()
    cfg.auth.login.enabled = True
    from main.config import LoginIdentityConfig
    cfg.auth.login.identities = [LoginIdentityConfig(
        name="a", username="u", password_env="PW_MISSING_XYZ")]
    problems = doctor_config(cfg)
    assert any("browser" in p for p in problems)
    assert any("PW_MISSING_XYZ" in p or "a" in p for p in problems)
    # unreadable config
    bad = tmp_path / "bad.yaml"
    bad.write_text(":\tbad: [\n")
    orig_load = Config.load

    def _boom(path):
        raise ValueError("nope")
    monkeypatch.setattr(Config, "load", classmethod(lambda c, p: _boom(p)))
    assert any("unreadable" in p for p in doctor_config())
    monkeypatch.setattr(Config, "load", orig_load)
