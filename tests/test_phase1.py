"""Phase 1 (foundation) tests: application model, graph, invariants,
coverage, budgets, checkpoint blobs, plugin interface, orchestrator
wiring. No network access in any test."""

import pytest

from main.models import (
    Identity, Resource, TestResult, AttackChain,
    Finding, Hypothesis,
    RESULT_INCONCLUSIVE,
)
from main.config import Config, AuthContext
from main.budgets import BudgetTracker, BudgetExceeded, BudgetUsage
from main.checkpoints import Checkpoint
from main.application.application_model import (
    Application, build_from_scan)
from main.application.identities import from_auth_contexts
from main.application.resources import (
    extract_resources)
from main.application.workflows import Workflow, WorkflowStep
from main.graph.application_graph import (
    ApplicationGraph, build_from_application, NODE_TYPES, EDGE_TYPES, nid)
from main.logic import invariants as inv_mod
from main.logic.invariants import (
    Invariant, evaluate, evaluate_all, default_invariants, register_check)
from main.reporting.coverage import (
    CoverageTracker, KNOWN_CLASSES)
from main.plugins.base import (
    SecurityTest, TestTarget, TestContext, run_plugins,
    register, get, registered)
from main.models import Endpoint, Parameter


def _ep(url, params=None, etype="api"):
    from main.discovery.url_normalizer import normalize_url
    from urllib.parse import urlparse
    p = urlparse(url)
    e = Endpoint(url=url, normalized_url=normalize_url(url),
                 host=p.hostname or "", path=p.path,
                 endpoint_type=etype, source=["recon"])
    for name in (params or []):
        e.query_parameters.append(Parameter(name=name, location="query",
                                            source=["url"]))
    return e


# ── models ────────────────────────────────────────────────────────────
def test_identity_round_trip():
    i = Identity(name="user_a", roles=["user"], tenant="t1",
                 auth_headers={"Cookie": "s=1"})
    assert Identity.from_dict(i.to_dict()).name == "user_a"


def test_resource_round_trip():
    r = Resource(key="k", resource_type="user",
                 identifiers={"id": "5"}, exposed_by=["e"])
    assert Resource.from_dict(r.to_dict()).identifiers == {"id": "5"}


def test_attack_chain_round_trip():
    c = AttackChain(id="c1", nodes=[{"id": "n1"}], impact="x")
    assert AttackChain.from_dict(c.to_dict()).id == "c1"


def test_finding_old_jsonl_loads():
    # backwards compat: artifacts without the new fields still load
    old = {"id": "f", "source": "nuclei", "matched_at": "https://a.com/"}
    f = Finding.from_dict(old)
    assert f.identity == "" and f.tenant == "" and f.resource_key == ""
    assert f.impact == ""


def test_hypothesis_evidence_contract_defaults():
    h = Hypothesis(hypothesis="h", endpoint=None, reason="r",
                   test_class="ssrf", confidence=0.5)
    assert h.expected_signal == "" and h.status == "hypothesized"


def test_testresult_defaults():
    assert TestResult().status == RESULT_INCONCLUSIVE


# ── auth contexts ─────────────────────────────────────────────────────
def test_auth_context_extended_yaml(tmp_path):
    f = tmp_path / "c.yaml"
    f.write_text(
        "auth:\n  contexts:\n"
        "    - name: user_a\n"
        "      headers:\n        Cookie: 's=A'\n"
        "      identity: user_a\n"
        "      roles: ['member']\n"
        "      tenant: acme\n"
        "      storage_state: auth/user_a.json\n")
    cfg = Config.load(f)
    ctx = cfg.auth.contexts[0]
    assert ctx.identity == "user_a" and ctx.roles == ["member"]
    assert ctx.tenant == "acme"
    assert ctx.storage_state == "auth/user_a.json"


def test_auth_context_old_yaml_still_loads(tmp_path):
    f = tmp_path / "c.yaml"
    f.write_text("auth:\n  contexts:\n    - name: user_a\n"
                 "      headers:\n        Cookie: 's=A'\n")
    cfg = Config.load(f)
    assert cfg.auth.contexts[0].tenant == ""


def test_from_auth_contexts():
    ctxs = [AuthContext(name="anonymous"),
            AuthContext(name="user_a", roles=["member"], tenant="acme",
                        headers={"Cookie": "s=A"})]
    ids, roles, tenants = from_auth_contexts(ctxs)
    assert [i.name for i in ids] == ["anonymous", "user_a"]
    assert roles[0].name == "member"
    assert tenants[0].name == "acme"
    assert ids[1].auth_headers == {"Cookie": "s=A"}


def test_budgets_config_defaults():
    cfg = Config()
    assert cfg.budgets.requests_per_host == 10000
    assert cfg.budgets.authz_tests_per_endpoint == 20


# ── budgets ───────────────────────────────────────────────────────────
def test_budget_request_caps():
    cfg = Config()
    cfg.budgets.requests_per_host = 2
    cfg.budgets.requests_per_endpoint = 1
    t = BudgetTracker(cfg)
    assert t.consume_request("h", "e1")
    assert not t.consume_request("h", "e1")  # endpoint cap
    assert t.consume_request("h", "e2")
    assert not t.consume_request("h", "e3")  # host cap
    assert t.usage.blocked == 2


def test_budget_test_caps():
    cfg = Config()
    t = BudgetTracker(cfg)
    for _ in range(20):
        assert t.consume_test("authz", "ep")
    assert not t.consume_test("authz", "ep")
    assert t.consume_test("authz", "other-ep")
    assert t.consume_test("custom", limit=1)
    assert not t.consume_test("custom", limit=1)


def test_budget_usage_round_trip():
    u = BudgetUsage(per_host={"h": 3}, blocked=1)
    assert BudgetUsage.from_dict(u.to_dict()).blocked == 1


def test_http_client_raises_on_exhaustion():
    from main.orchestrator import _HTTPClient
    cfg = Config()
    cfg.budgets.requests_per_host = 0
    client = _HTTPClient(budgets=BudgetTracker(cfg))
    with pytest.raises(BudgetExceeded):
        client.get("https://example.com/")


def test_differential_reraises_budget():
    from main.validation.differential import DifferentialTester

    class Boom:
        def get(self, *a, **k):
            raise BudgetExceeded("x")

    cfg = Config()
    cfg.auth.contexts = [AuthContext(name="user_a")]
    with pytest.raises(BudgetExceeded):
        DifferentialTester(cfg, Boom()).probe("https://a.com/api", "api")


# ── resources ─────────────────────────────────────────────────────────
def test_extract_resources():
    eps = [_ep("https://a.com/api/u?user_id=1&debug=x",
               ["user_id", "debug"]),
           _ep("https://a.com/api/o?order_id=9", ["order_id"]),
           _ep("https://a.com/api/g?id=7", ["id"])]
    rs = extract_resources(eps)
    by_type = {r.resource_type for r in rs}
    assert by_type == {"user", "order", "object"}
    assert all(r.key and r.exposed_by for r in rs)
    assert "debug" not in {k for r in rs for k in r.identifiers}


def test_workflow_schema_round_trip():
    w = Workflow(name="crud",
                 steps=[WorkflowStep(name="create", endpoint="/api/x",
                                     method="POST")])
    assert Workflow.from_dict(w.to_dict()).steps[0].method == "POST"


# ── application model ─────────────────────────────────────────────────
def _app():
    eps = [_ep("https://a.com/api/u?id=1", ["id"], "api"),
           _ep("https://a.com/admin", [], "admin")]
    techs = [{"name": "nginx", "category": "server"}]
    ctxs = [AuthContext(name="anonymous"),
            AuthContext(name="user_a", tenant="acme")]
    return build_from_scan("a.com", eps, techs, ctxs)


def test_application_incremental():
    app = _app()
    assert app.hosts == ["a.com"]
    assert len(app.endpoints) == 2
    assert len(app.resources) == 1
    assert {i.name for i in app.identities} == {"anonymous", "user_a"}
    # idempotent re-ingest
    n = len(app.endpoints)
    app.ingest_endpoints([e.to_dict() for e in
                          [_ep("https://a.com/api/u?id=1", ["id"])]])
    assert len(app.endpoints) == n
    rt = Application.from_dict(app.to_dict())
    assert len(rt.resources) == 1 and rt.tenants[0].name == "acme"


# ── graph ─────────────────────────────────────────────────────────────
def test_graph_build_and_query():
    g = build_from_application(_app())
    assert g.nodes_of_type("endpoint")
    assert g.nodes_of_type("parameter")
    assert g.nodes_of_type("identity")
    rid = [n["id"] for n in g.nodes_of_type("resource")][0]
    exposed = g.endpoints_exposing_resource(rid)
    assert len(exposed) == 1
    assert exposed[0]["attrs"]["endpoint_type"] == "api"
    # tenant attribution
    assert g.neighbors(nid("identity", "user_a"), "BELONGS_TO")


def test_graph_edge_dedupe_and_errors():
    g = ApplicationGraph()
    g.add_node("host:h", "host", "h")
    g.add_node("host:h", "host", "h", {"x": 1})
    assert g.nodes["host:h"]["attrs"] == {"x": 1}
    g.add_node("endpoint:e", "endpoint", "e")
    g.add_edge("host:h", "endpoint:e", "CALLS")
    g.add_edge("host:h", "endpoint:e", "CALLS")
    assert len(g.edges) == 1
    with pytest.raises(ValueError):
        g.add_node("x", "nope", "x")
    with pytest.raises(ValueError):
        g.add_edge("host:h", "endpoint:e", "NOPE")
    with pytest.raises(KeyError):
        g.add_edge("host:h", "missing", "CALLS")


def test_graph_save_load(tmp_path):
    g = build_from_application(_app())
    p = tmp_path / "g.json"
    g.save(p)
    g2 = ApplicationGraph.load(p)
    assert len(g2.nodes) == len(g.nodes)
    assert len(g2.edges) == len(g.edges)


def test_node_edge_type_vocab():
    assert {"domain", "finding", "secret"} <= NODE_TYPES
    assert {"EXPOSED_BY", "CAN_ACCESS", "LEADS_TO"} <= EDGE_TYPES


# ── invariants ────────────────────────────────────────────────────────
def test_builtin_invariants_fire():
    cases = [
        ("no_cross_user_read",
         {"action": "read", "actor": "a", "resource_owner": "b"}, True),
        ("no_cross_user_read",
         {"action": "read", "actor": "a", "resource_owner": "a"}, False),
        ("no_unauthorized_write",
         {"action": "delete", "actor": "a", "authorized": False}, True),
        ("no_modify_deleted",
         {"action": "update", "state_before": "deleted"}, True),
        ("no_self_promote", {"actor": "a", "self_promotion": True}, True),
        ("quantity_non_negative", {"quantity_after": -3}, True),
        ("quantity_non_negative", {"quantity_after": 0}, False),
        ("price_stable", {"price_changed": True}, True),
        ("price_stable", {"price_changed": True,
                           "price_authorized": True}, False),
        ("refund_lte_payment", {"payment": 100, "refund": 120}, True),
        ("refund_lte_payment", {"payment": 100, "refund": 100}, False),
        ("single_use_token", {"token_single_use": True,
                              "token_reused": True}, True),
        ("no_revert_completed", {"state_before": "completed",
                                 "state_after": "draft"}, True),
    ]
    for check, obs, want in cases:
        inv = Invariant(id="t", description="t", check=check)
        assert evaluate(inv, obs).violated is want, check


def test_invariant_unknown_and_custom():
    r = evaluate(Invariant(id="t", description="t", check="nope"), {})
    assert r.violated is False and "unknown check" in r.detail
    register_check("always", lambda obs, p: (True, "boom"))
    assert evaluate(Invariant(id="t", description="t",
                              check="always"), {}).violated is True


def test_default_invariants_cover_spec():
    assert len(default_invariants()) == 12
    assert {i.check for i in default_invariants()} == set(
        inv_mod.BUILTIN_IDS)


def test_evaluate_all():
    out = evaluate_all(default_invariants(),
                       {"action": "read", "actor": "a",
                        "resource_owner": "a"})
    assert all(not r.violated for r in out)


# ── coverage ──────────────────────────────────────────────────────────
def test_coverage_precedence():
    c = CoverageTracker()
    c.record("sqli", "candidate")
    c.record("sqli", "tested_negative")  # must not downgrade
    c.record("sqli", "confirmed")
    assert c.summary()["sqli"] == "confirmed"
    assert "graphql" in c.untested()
    assert "sqli" in c.tested()


def test_coverage_invalid_status():
    with pytest.raises(ValueError):
        CoverageTracker().record("xss", "maybe")


def test_coverage_round_trip():
    c = CoverageTracker()
    c.record("ssrf", "confirmed", "oast hit")
    c2 = CoverageTracker.from_dict(c.to_dict())
    assert c2.summary()["ssrf"] == "confirmed"


def test_known_classes_cover_dod():
    for cls in ("sqli", "csrf", "graphql", "race", "bfla",
                "request_smuggling", "mass_assignment"):
        assert cls in KNOWN_CLASSES


# ── plugins ───────────────────────────────────────────────────────────
class _Echo(SecurityTest):
    name = "echo-test"
    supported_endpoint_types = ("api",)
    prerequisites = ()

    def run(self, target, ctx):
        from main.models import TestResult
        return TestResult(status="candidate",
                          observations=["echo"],
                          evidence={"url": target.endpoint_url})


class _Boom(SecurityTest):
    name = "boom-test"

    def run(self, target, ctx):
        raise RuntimeError("kablam")


def test_plugin_registry_and_order():
    register(_Echo())
    register(_Boom())
    assert "echo-test" in registered()
    assert get("nope") is None
    ctx = TestContext(Config())
    tgt = TestTarget("https://a.com/api", endpoint_type="api")
    out = run_plugins(tgt, ctx, ["echo-test", "boom-test", "nope"])
    assert [p.name for p, _ in out] == ["echo-test", "boom-test"]
    assert out[0][1].status == "candidate"
    assert out[1][1].status == "error"  # contained, not raised


def test_plugin_supports_filter():
    ctx = TestContext(Config())
    tgt = TestTarget("https://a.com/", endpoint_type="page")
    out = run_plugins(tgt, ctx, ["echo-test"])
    assert out[0][1].status == "skipped"


def test_plugin_prerequisites():
    from main.models import Identity
    ctx = TestContext(Config(), oast_provider=None,
                      identities=[Identity(name="user_a")],
                      technologies=[{"name": "nginx"}])

    class NeedOast(SecurityTest):
        name = "need-oast-t"
        prerequisites = ("oast",)

        def run(self, t, c):
            return TestResult()

    class NeedAuth2(SecurityTest):
        name = "need-auth2-t"
        prerequisites = ("auth:2",)

        def run(self, t, c):
            return TestResult()

    class NeedTool(SecurityTest):
        name = "need-tool-t"
        prerequisites = ("tool:definitely-not-a-binary-xyz",)

        def run(self, t, c):
            return TestResult()

    class NeedTech(SecurityTest):
        name = "need-tech-t"
        prerequisites = ("tech:nginx",)

        def run(self, t, c):
            from main.models import TestResult
            return TestResult(status="candidate")

    for cls in (NeedOast, NeedAuth2, NeedTool, NeedTech):
        register(cls())

    tgt = TestTarget("https://a.com/")
    out = {p.name: r.status for p, r in
           run_plugins(tgt, ctx, ["need-oast-t", "need-auth2-t",
                                  "need-tool-t", "need-tech-t"])}
    assert out == {"need-oast-t": "skipped", "need-auth2-t": "skipped",
                   "need-tool-t": "skipped", "need-tech-t": "candidate"}


def test_builtin_plugins_registered():
    for name in ("sqli-mutation", "sqli-sqlmap", "xss-mutation",
                 "xss-dalfox", "ssrf-oast", "ssti-arithmetic",
                 "xxe-oast", "path-traversal-marker"):
        assert name in registered()


def test_mutation_plugins_respect_kill_switch():
    cfg = Config()
    cfg.validation.mutation = False
    ctx = TestContext(cfg)
    tgt = TestTarget("https://a.com/?id=1", test_class="sqli",
                     parameter="id")
    for name in ("sqli-mutation", "xss-mutation"):
        _, res = run_plugins(tgt, ctx, [name])[0]
        assert res.status == "skipped"


def test_adapter_class_gating():
    ctx = TestContext(Config())
    tgt = TestTarget("https://a.com/", test_class="unknown")
    for name in ("sqli-mutation", "sqli-sqlmap", "xss-mutation",
                 "xss-dalfox", "ssrf-oast", "ssti-arithmetic",
                 "xxe-oast", "path-traversal-marker"):
        _, res = run_plugins(tgt, ctx, [name])[0]
        assert res.status == "skipped", name


# ── checkpoints ───────────────────────────────────────────────────────
def test_checkpoint_blobs(tmp_path):
    ck = Checkpoint(tmp_path / "checkpoint.json")
    assert not ck.has_blob("application")
    ck.save_blob("application", {"id": "app-x"})
    assert ck.has_blob("application")
    assert ck.load_blob("application") == {"id": "app-x"}
    assert ck.load_blob("missing") == {}
    ck2 = Checkpoint(tmp_path / "checkpoint.json")
    assert ck2.has_blob("application")  # survives reload


# ── orchestrator wiring ───────────────────────────────────────────────
def _orch():
    from main.orchestrator import Orchestrator
    from main.profiles import get as get_profile
    import tempfile
    from pathlib import Path
    td = tempfile.mkdtemp()
    return (Orchestrator(Config(), Path(td),
                         profile=get_profile("standard")),
            Path(td))


def test_build_app_state_fresh_and_resume():
    orch, out = _orch()
    from main.reporting.metrics import Metrics
    from main.checkpoints import Checkpoint
    (out / "technologies.jsonl").write_text("")
    eps = [_ep("https://a.com/api/u?id=1", ["id"])]
    ck = Checkpoint(out / "checkpoint.json")
    cov = CoverageTracker()
    m = Metrics()
    app, g = orch._build_app_state(eps, "a.com", out, ck, False, m, cov)
    assert m.resources_discovered == 1
    assert (out / "application.json").exists()
    assert (out / "application_graph.json").exists()
    assert (out / "attack_chains.jsonl").exists()
    assert ck.has_blob("application")
    # resume path reloads instead of rebuilding
    ck.mark("mapping")
    app2, g2 = orch._build_app_state([], "a.com", out, ck, True, m, cov)
    assert len(app2.endpoints) == 1 and len(g2.nodes) == len(g.nodes)


def test_apply_plugin_result_mappings(tmp_path):
    orch, out = _orch()
    from main.validation.evidence import EvidenceStore
    from main.models import TestResult
    from main.stages.validation.plugins import apply_plugin_result
    ev = EvidenceStore(out / "proofs")
    cov = CoverageTracker()

    class Heavy:
        name = "heavy"
        allocates_evidence = True

    class Pre:
        name = "pre"
        allocates_evidence = False

    f = Finding(id="1", source="nuclei",
                matched_at="https://a.com/?id=1")
    apply_plugin_result(
        f, Heavy(),
        TestResult(status="confirmed", evidence={"k": "v"},
                   observations=["o"]),
        ev, "sqli", cov)
    assert f.validation_status == "confirmed" and f.confidence == "confirmed"
    assert f.evidence_dir is not None
    assert cov.summary()["sqli"] == "confirmed"

    f2 = Finding(id="2", source="nuclei",
                 matched_at="https://a.com/?q=1")
    apply_plugin_result(
        f2, Pre(),
        TestResult(status="candidate", evidence={"p": 1},
                   observations=["note"]),
        ev, "xss", cov)
    assert f2.validation_status == "strong_candidate"
    assert f2.false_positive_notes == "note"
    assert f2.raw == {"evidence": {"p": 1}}

    f3 = Finding(id="3", source="nuclei", matched_at="https://a.com/")
    apply_plugin_result(
        f3, Heavy(), TestResult(status="negative"), ev, "ssrf", cov)
    assert f3.validation_status == "false_positive"
    assert cov.summary()["ssrf"] == "tested_negative"


def test_apply_plugin_results_aggregates_and_retains_each_tool(tmp_path):
    from main.validation.evidence import EvidenceStore
    from main.stages.validation.plugins import apply_plugin_results
    orch, out = _orch()
    evidence = EvidenceStore(out / "proofs")
    coverage = CoverageTracker()

    class Pre:
        name = "prescreen"
        allocates_evidence = False

    class Heavy:
        name = "heavy"
        allocates_evidence = True

    candidate = Finding(id="agg-1", source="nuclei",
                        matched_at="https://a.com/?id=1",
                        raw={"template": "kept"})
    apply_plugin_results(
        candidate,
        [(Pre(), TestResult(status="candidate", evidence={"marker": "sql"},
                            observations=["candidate signal"])),
         (Heavy(), TestResult(status="inconclusive",
                              evidence={"tool": "no verdict"},
                              observations=["validator inconclusive"]))],
        evidence, "sqli", coverage)
    assert candidate.result_status == "candidate"
    assert candidate.raw["template"] == "kept"
    assert [item["plugin"] for item in candidate.raw["validator_results"]] \
        == ["prescreen", "heavy"]
    assert candidate.raw["validator_results"][0]["evidence"] == {
        "marker": "sql"}
    assert coverage.summary()["sqli"] == "candidate"

    conflict = Finding(id="agg-2", source="nuclei",
                       matched_at="https://a.com/?id=2")
    conflict_coverage = CoverageTracker()
    apply_plugin_results(
        conflict,
        [(Pre(), TestResult(status="candidate")),
         (Heavy(), TestResult(status="negative"))],
        evidence, "sqli", conflict_coverage)
    assert conflict.result_status == "inconclusive"
    assert conflict_coverage.summary()["sqli"] == "inconclusive"


def test_finding_endpoint_lookup():
    from main.stages.validation.plugins import finding_endpoint
    orch, _ = _orch()
    eps = [_ep("https://a.com/api/u?id=1", ["id"])]
    by_norm = {e.normalized_url: e for e in eps}
    f = Finding(id="1", source="n",
                matched_at="https://a.com/api/u?id=1&x=2")
    # different query order/extra param → no normalized match
    assert finding_endpoint(f, by_norm) is None
    f.matched_at = "https://a.com/api/u?id=1"
    assert finding_endpoint(f, by_norm) is not None


def test_differential_probe_records_negative_and_blocked():
    import tempfile
    from pathlib import Path
    from main.orchestrator import Orchestrator
    from main.profiles import get as get_profile
    from main.reporting.metrics import Metrics
    from main.validation.evidence import EvidenceStore
    from main.validation.differential import DifferentialTester

    class Calm:
        def get(self, url, **kw):

            class R:
                status_code = 403
                text = "forbidden"
                headers = {}
            return R()

    out = Path(tempfile.mkdtemp())
    cfg = Config()
    cfg.validation.differential = True
    orch = Orchestrator(cfg, out, profile=get_profile("standard"))
    eps = [_ep("https://a.com/admin", [], "admin")]
    m = Metrics()
    budgets = BudgetTracker(cfg)
    cov = CoverageTracker()
    ev = EvidenceStore(out / "proofs")
    from main.stages.validation import ProbeControls
    from main.stages.validation.differential import differential_probe
    found = differential_probe(eps, DifferentialTester(cfg, Calm()),
                               ev, m, budgets, cov, orch.cfg, orch.scope,
                               ProbeControls.from_orchestrator(orch))
    assert found == []
    assert cov.summary()["authz"] == "tested_negative"
    assert m.authorization_tests == 1 and m.authorization_confirmed == 0

    # exhausted authz budget → blocked, no request attempted
    cfg2 = Config()
    cfg2.budgets.authz_tests_per_endpoint = 0
    orch2 = Orchestrator(cfg2, out, profile=get_profile("standard"))
    cov2 = CoverageTracker()
    found2 = differential_probe(
        eps, DifferentialTester(cfg2, Calm()), ev, Metrics(),
        BudgetTracker(cfg2), cov2, orch2.cfg, orch2.scope,
        ProbeControls.from_orchestrator(orch2))
    assert found2 == [] and cov2.summary()["authz"] == "blocked"


def test_report_with_and_without_coverage(tmp_path):
    from main.reporting.html import render_html
    out = tmp_path
    cov = CoverageTracker()
    cov.record("sqli", "confirmed")
    render_html(out / "a.html", "t.com", [], [], {},
                coverage=cov.to_dict())
    html = (out / "a.html").read_text()
    assert "sqli: confirmed" in html
    assert "Untested attack classes" in html
    # backwards compatible: no coverage kwarg
    render_html(out / "b.html", "t.com", [], [], {})
    assert "Coverage" not in (out / "b.html").read_text()
