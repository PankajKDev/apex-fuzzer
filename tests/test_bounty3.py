"""Bounty top-3 tests: ID harvest/swap, authz matrix/BFLA, stored XSS.
All HTTP is faked — no network in any test."""
import json

from apex_fuzzer.authorization.harvest import (
    harvest_ids, extract_ids_from_body)
from apex_fuzzer.authorization.matrix import (
    AuthorizationMatrix, AuthorizationObservation, same_object,
    evaluate_cell, describe_cell)
from apex_fuzzer.authorization.access_tests import (
    swap_ids, sweep_methods, SwapResult)
from apex_fuzzer.validation.second_order import (
    make_canary, classify_context, inject_canary, find_renders,
    INERT_TAG)
from apex_fuzzer.budgets import BudgetExceeded
from apex_fuzzer.models import Identity, Endpoint, Parameter, Finding
from apex_fuzzer.config import Config


class FakeResp:
    def __init__(self, status, text, headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}


def _ep(url, body_params=None, etype="api"):
    from apex_fuzzer.discovery.url_normalizer import normalize_url
    from urllib.parse import urlparse
    p = urlparse(url)
    e = Endpoint(url=url, normalized_url=normalize_url(url),
                 host=p.hostname or "", path=p.path,
                 endpoint_type=etype, source=["recon"])
    for name in (body_params or []):
        e.body_parameters.append(Parameter(name=name, location="body",
                                            source=["html"]))
    return e


def _ident(name, tenant="", headers=None, roles=None):
    return Identity(name=name, tenant=tenant or None,
                    auth_headers=headers or {}, roles=roles or [])


# ── harvest ───────────────────────────────────────────────────────────
def test_extract_ids_nested():
    body = json.dumps({"data": {"user": {"id": 7, "name": "x"},
                                "items": [{"order_id": "A1"}]},
                       "debug": True})
    out = extract_ids_from_body(body)
    assert out == {"id": "7", "order_id": "A1"}


def test_extract_ids_non_json():
    assert extract_ids_from_body("<html>hi") == {}
    assert extract_ids_from_body("") == {}
    assert extract_ids_from_body(None) == {}


def test_harvest_ids_per_identity():
    body_a = json.dumps({"id": 1, "owner": "a"})
    body_b = json.dumps({"id": 2, "owner": "b"})

    class H:
        def get(self, url, **kw):
            c = (kw.get("headers") or {}).get("Cookie", "")
            if c == "s=A":
                return FakeResp(200, body_a)
            if c == "s=B":
                return FakeResp(200, body_b)
            return FakeResp(401, "no")

    ep = _ep("https://t.com/api/u")
    ids = harvest_ids(H(), ep, [_ident("user_a", headers={"Cookie": "s=A"}),
                                _ident("user_b", headers={"Cookie": "s=B"}),
                                _ident("anonymous")], max_ids_per_param=5)
    by_owner = {h.owner: h.value for h in ids}
    assert by_owner == {"user_a": "1", "user_b": "2"}
    assert all(h.shape and h.body_hash for h in ids)


def test_harvest_skips_errors_and_caps():
    class H:
        def get(self, url, **kw):
            if "Cookie" in (kw.get("headers") or {}):
                return FakeResp(200, json.dumps({"id": 1, "uid": 2,
                                                 "uuid": 3, "slug": 4}))
            raise TimeoutError("down")

    ep = _ep("https://t.com/api/u")
    ids = harvest_ids(H(), ep, [_ident("user_a", headers={"Cookie": "s"})],
                      max_ids_per_param=2)
    # cap is per (endpoint, param, owner): 4 distinct params all pass,
    # the failing anonymous identity contributes nothing
    assert {h.param for h in ids} == {"id", "uid", "uuid", "slug"}
    assert all(h.owner == "user_a" for h in ids)


# ── matrix store ──────────────────────────────────────────────────────
def _obs(identity, status=200, shape='{"id": 1}', tenant="",
         method="GET", endpoint="e", role="", h="hash"):
    return AuthorizationObservation(
        identity=identity, status=status, shape=shape, tenant=tenant,
        method=method, endpoint=endpoint, role=role, body_hash=h,
        length_bucket=0)


def test_matrix_record_dedupe_and_query(tmp_path):
    m = AuthorizationMatrix()
    m.record(_obs("a"))
    m.record(_obs("a"))  # dupe
    assert len(m.observations) == 1
    m.record(_obs("b", method="POST"))
    assert len(m.query(method="POST")) == 1
    assert len(m.query(identity="zzz")) == 0
    assert set(m.cells()) == {"GET::e", "POST::e"}
    m.save(tmp_path / "m.json")
    assert len(AuthorizationMatrix.load(tmp_path / "m.json")
               .observations) == 2
    assert len(AuthorizationMatrix.from_dict(
        {"observations": [{"bad": 1}, _obs("c").to_dict()]})
        .observations) == 2


def test_same_object_rules():
    a = _obs("a", 200, '{"id":1}', h="h1")
    b = _obs("b", 200, '{"id":1}', h="h1")
    assert same_object(a, b)
    c = _obs("c", 200, '{"id":1}', h="other")
    assert same_object(a, c)  # same shape, same bucket
    assert not same_object(a, _obs("d", 403, '{"id":1}', h="h1"))
    assert not same_object(_obs("e", 200, "", h=""), _obs("f", 200, ""))
    assert "a→200" in describe_cell([a])


def test_evaluate_cell_tenant_bola_bfla():
    # cross-tenant same object
    v, n, k = evaluate_cell([_obs("a", 200, tenant="t1"),
                             _obs("b", 200, tenant="t2")], "api")
    assert v == "strong_candidate" and k == "tenant_isolation"
    # plain BOLA
    v, n, k = evaluate_cell([_obs("a", 200), _obs("b", 200)], "api")
    assert v == "strong_candidate" and k == "bola" and "BOLA" in n
    # admin role gap → BFLA
    v, n, k = evaluate_cell([_obs("admin", 200, role="admin"),
                             _obs("u", 200, role="member")], "admin")
    assert v == "strong_candidate" and k == "bfla"
    # healthy: allowed vs denied
    v, n, k = evaluate_cell([_obs("a", 200), _obs("b", 403)], "api")
    assert v == "inconclusive" and k == ""
    # broken access per method on privileged endpoint
    v, n, k = evaluate_cell(
        [_obs("anonymous", 401), _obs("u", 200)], "admin")
    assert v == "strong_candidate" and k == "bfla"
    # single identity → nothing to compare
    assert evaluate_cell([_obs("a", 200)], "api")[0] == "inconclusive"


# ── swap ──────────────────────────────────────────────────────────────
def _harvested(owner="user_a", value="1", tenant="",
               shape='{"id":1}', h="h1"):
    from apex_fuzzer.authorization.harvest import HarvestedId
    return HarvestedId(endpoint_url="https://t.com/api/u?id=1",
                       normalized_url="https://t.com/api/u",
                       param="id", value=value, owner=owner,
                       owner_tenant=tenant, shape=shape, body_hash=h)


def _harvested_matching(body, owner="user_a", tenant=""):
    """Build a HarvestedId whose baseline equals ``body``'s fingerprint."""
    from apex_fuzzer.authorization.harvest import HarvestedId
    from apex_fuzzer.validation.differential import normalize_response

    class R:
        status_code = 200
        text = body
    norm = normalize_response(R())
    return HarvestedId(endpoint_url="https://t.com/api/u?id=1",
                       normalized_url="https://t.com/api/u",
                       param="id", value="1", owner=owner,
                       owner_tenant=tenant,
                       shape=norm.get("key_shape", ""),
                       body_hash=norm.get("body_hash", ""))


def test_swap_bola_match():
    victim_body = json.dumps({"id": 1, "email": "v@x.com"})

    class H:
        def get(self, url, **kw):
            return FakeResp(200, victim_body)

    m = AuthorizationMatrix()
    out = swap_ids(H(), [_harvested_matching(victim_body)],
                   _ident("user_b"), matrix=m)
    assert len(out) == 1
    assert out[0].verdict == "strong_candidate" and out[0].match
    assert "BOLA" in out[0].notes
    assert len(m.observations) == 1


def test_swap_cross_tenant():
    body = json.dumps({"id": 1})

    class H:
        def get(self, url, **kw):
            return FakeResp(200, body)

    out = swap_ids(H(), [_harvested_matching(body, owner="a",
                                             tenant="t1")],
                   _ident("b", tenant="t2"))
    assert out[0].verdict == "strong_candidate"
    assert "cross-tenant" in out[0].notes


def test_swap_no_match_and_own_skip():
    class H:
        def get(self, url, **kw):
            return FakeResp(200, json.dumps({"other": "data"}))

    out = swap_ids(H(), [_harvested()], _ident("user_b"))
    assert out[0].verdict == "inconclusive" and not out[0].match
    # own ids never replayed
    assert swap_ids(H(), [_harvested()], _ident("user_a")) == []


def test_swap_budget_propagates():
    class H:
        def get(self, url, **kw):
            raise BudgetExceeded("cap")

    try:
        swap_ids(H(), [_harvested()], _ident("user_b"))
        raise AssertionError("must propagate")
    except BudgetExceeded:
        pass


# ── BFLA sweep ────────────────────────────────────────────────────────
def test_sweep_methods_uses_verbs_and_contains_errors():
    calls = []

    class H:
        def get(self, url, **kw):
            calls.append("GET")
            return FakeResp(200, json.dumps({"id": 1}))

        def request(self, method, url, **kw):
            calls.append(method)
            if method == "DELETE":
                raise ConnectionError("rst")
            return FakeResp(403, "no")

    m = AuthorizationMatrix()
    obs = sweep_methods(H(), _ep("https://t.com/api/u"),
                        [_ident("user_a")], ["GET", "DELETE", "POST"],
                        matrix=m)
    assert calls == ["GET", "DELETE", "POST"]
    assert {(o.method, o.status) for o in obs} == {("GET", 200),
                                                   ("POST", 403)}
    assert len(m.observations) == 2


def test_sweep_budget_propagates():
    class H:
        def get(self, url, **kw):
            raise BudgetExceeded("cap")

    try:
        sweep_methods(H(), _ep("https://t.com/x"), [_ident("a")], ["GET"])
        raise AssertionError("must propagate")
    except BudgetExceeded:
        pass


# ── stored XSS ────────────────────────────────────────────────────────
def test_canary_format():
    c = make_canary()
    assert c.startswith("ax") and f"<{INERT_TAG}>" in c


def test_classify_contexts():
    tag = f"<{INERT_TAG}>"
    assert classify_context(
        f"<script>var x='{tag}';</script>", "")["context"] == "script"
    assert classify_context(
        f'<div onload="x(\'{tag}\')">', "")["context"] == "event_handler"
    assert classify_context(
        f'<a href="javascript:go(\'{tag}\')">', "")["context"] == \
        "javascript_uri"
    assert classify_context(f"<p>hi {tag}</p>", "")["dangerous"] is True
    enc = classify_context(f"<p>&lt;{INERT_TAG}&gt;</p>", "")
    assert enc == {"dangerous": False, "context": "encoded",
                   "detail": "canary HTML-entity-encoded"}
    assert classify_context("<p>clean</p>", "")["context"] == "absent"


def test_inject_posts_canary_to_all_fields():
    posted = {}

    class H:
        def post(self, url, **kw):
            posted.update(kw.get("data") or {})
            return FakeResp(302, "created")

    ep = _ep("https://t.com/comment", ["body", "author"], "page")
    res = inject_canary(H(), ep, {}, "user_a")
    assert res.status == 302 and res.fields == ["author", "body"]
    assert all(f"<{INERT_TAG}>" in v for v in posted.values())


def test_inject_no_forms_and_failure():
    assert inject_canary(None, _ep("https://t.com/x"),
                         {}, "a").fields == []

    class H:
        def post(self, url, **kw):
            raise ConnectionError("down")

    res = inject_canary(H(), _ep("https://t.com/c", ["b"]), {}, "a")
    assert "inject failed" in res.notes


def test_find_renders_hits_and_skips():
    canary = make_canary()
    tag = f"<{INERT_TAG}>"
    pages = {"https://t.com/list": f"<ul><li>{tag}</li></ul>",
             "https://t.com/safe": "<p>&lt;axsl&gt;</p>",
             "https://t.com/empty": "<p>nothing</p>",
             "https://t.com/err": None}

    class H:
        def get(self, url, **kw):
            if url.endswith("/err"):
                return FakeResp(500, "")
            return FakeResp(200, pages[url])

    hits = find_renders(H(), list(pages), canary, "https://t.com/c")
    by_url = {h.render_url: h.context for h in hits}
    assert by_url["https://t.com/list"] == "dangerous:raw_html"
    assert by_url["https://t.com/safe"] == "encoded"
    assert "https://t.com/empty" not in by_url
    assert "https://t.com/err" not in by_url
    assert all(h.snippet for h in hits)


# ── orchestrator: authz matrix probe ──────────────────────────────────
def _orch():
    import tempfile
    from pathlib import Path
    from apex_fuzzer.orchestrator import Orchestrator
    from apex_fuzzer.profiles import get as get_profile
    td = tempfile.mkdtemp()
    return (Orchestrator(Config(), Path(td),
                         profile=get_profile("standard")),
            Path(td))


def _matrix_http():
    victim = json.dumps({"id": 1, "email": "v@x.com"})

    class H:
        def get(self, url, **kw):
            c = (kw.get("headers") or {}).get("Cookie", "")
            if "api/u" in url and not c:
                return FakeResp(401, "login")
            return FakeResp(200, victim)

        def request(self, method, url, **kw):
            c = (kw.get("headers") or {}).get("Cookie", "")
            if not c:
                return FakeResp(401, "login")
            if method in ("PUT", "DELETE"):
                return FakeResp(200, victim)
            return FakeResp(200, victim)

        def post(self, url, **kw):
            return FakeResp(200, "ok")

    return H()


def test_authz_matrix_probe_bola_and_bfla():
    import tempfile
    from pathlib import Path
    from apex_fuzzer.orchestrator import Orchestrator
    from apex_fuzzer.profiles import get as get_profile
    from apex_fuzzer.reporting.metrics import Metrics
    from apex_fuzzer.reporting.coverage import CoverageTracker
    from apex_fuzzer.budgets import BudgetTracker
    from apex_fuzzer.validation.evidence import EvidenceStore
    from apex_fuzzer.models import Identity

    out = Path(tempfile.mkdtemp())
    cfg = Config()
    cfg.authorization.enabled = True
    cfg.authorization.methods = ["GET", "PUT"]
    orch = Orchestrator(cfg, out, profile=get_profile("standard"))
    eps = [_ep("https://t.com/api/u", [], "api")]
    ids = [Identity(name="anonymous"),
           Identity(name="user_a", tenant="t1",
                    auth_headers={"Cookie": "s=A"}),
           Identity(name="user_b", tenant="t1",
                    auth_headers={"Cookie": "s=B"})]
    m, cov = Metrics(), CoverageTracker()
    found = orch._authz_matrix_probe(
        eps, EvidenceStore(out / "proofs"), m, BudgetTracker(cfg),
        cov, _matrix_http(), out, ids)
    kinds = {f.source for f in found}
    assert "idor-swap" in kinds and "authz-matrix" in kinds
    swap = [f for f in found if f.source == "idor-swap"][0]
    assert swap.identity in ("user_a", "user_b")
    assert swap.validation_status == "strong_candidate"
    assert cov.summary()["bola"] == "candidate"
    assert m.authorization_tests >= 2 and m.authorization_confirmed >= 2
    assert (out / "authorization_matrix.json").exists()


def test_authz_matrix_single_identity_untestable(tmp_path):
    orch, out = _orch()
    from apex_fuzzer.reporting.metrics import Metrics
    from apex_fuzzer.reporting.coverage import CoverageTracker
    from apex_fuzzer.budgets import BudgetTracker
    from apex_fuzzer.validation.evidence import EvidenceStore
    cov = CoverageTracker()
    found = orch._authz_matrix_probe(
        [_ep("https://t.com/api/u")], EvidenceStore(out / "proofs"),
        Metrics(), BudgetTracker(Config()), cov, _matrix_http(), out,
        [Identity(name="anonymous")])
    assert found == [] and cov.summary()["authz"] == "untestable"


def test_authz_matrix_budget_blocked():
    orch, out = _orch()
    from apex_fuzzer.reporting.metrics import Metrics
    from apex_fuzzer.reporting.coverage import CoverageTracker
    from apex_fuzzer.budgets import BudgetTracker
    from apex_fuzzer.validation.evidence import EvidenceStore
    cfg = Config()
    cfg.budgets.authz_tests_per_endpoint = 0
    cov = CoverageTracker()
    found = orch._authz_matrix_probe(
        [_ep("https://t.com/api/u")], EvidenceStore(out / "proofs"),
        Metrics(), BudgetTracker(cfg), cov, _matrix_http(), out,
        [Identity(name="anonymous"), Identity(name="user_a")])
    assert found == [] and cov.summary()["authz"] == "blocked"


# ── orchestrator: second-order probe ──────────────────────────────────
def _so_http(store):
    class H:
        def post(self, url, **kw):
            data = kw.get("data") or {}
            store.update(data)
            return FakeResp(302, "created")

        def get(self, url, **kw):
            if url.endswith("/list"):
                vals = " ".join(store.values())
                return FakeResp(200, f"<ul><li>{vals}</li></ul>")
            return FakeResp(200, "<p>home</p>")

    return H()


def test_second_order_probe_finds_stored():
    orch, out = _orch()
    from apex_fuzzer.reporting.metrics import Metrics
    from apex_fuzzer.reporting.coverage import CoverageTracker
    from apex_fuzzer.budgets import BudgetTracker
    from apex_fuzzer.validation.evidence import EvidenceStore
    cfg = Config()
    eps = [_ep("https://t.com/comment", ["body"], "page"),
           _ep("https://t.com/list", [], "page")]
    m, cov = Metrics(), CoverageTracker()
    found = orch._second_order_probe(
        eps, EvidenceStore(out / "proofs"), m, BudgetTracker(cfg),
        cov, _so_http({}),
        [Identity(name="user_a", auth_headers={"Cookie": "s=A"})])
    assert len(found) == 1
    f = found[0]
    assert f.source == "second-order"
    assert f.validation_status == "strong_candidate"
    assert f.identity == "user_a"
    assert cov.summary()["second_order"] == "candidate"
    assert m.second_order_tests == 1 and m.second_order_candidates == 1


def test_second_order_encoded_is_negative():
    orch, out = _orch()
    from apex_fuzzer.reporting.metrics import Metrics
    from apex_fuzzer.reporting.coverage import CoverageTracker
    from apex_fuzzer.budgets import BudgetTracker
    from apex_fuzzer.validation.evidence import EvidenceStore

    class H:
        def post(self, url, **kw):
            return FakeResp(200, "ok")

        def get(self, url, **kw):
            return FakeResp(200, "<p>&lt;axsl&gt;</p>")

    cfg = Config()
    cov = CoverageTracker()
    found = orch._second_order_probe(
        [_ep("https://t.com/c", ["b"], "page"),
         _ep("https://t.com/list", [], "page")],
        EvidenceStore(out / "proofs"), Metrics(), BudgetTracker(cfg),
        cov, H(), [Identity(name="anonymous")])
    assert found == []
    assert cov.summary()["second_order"] == "tested_negative"


def test_second_order_no_forms_untestable():
    orch, out = _orch()
    from apex_fuzzer.reporting.metrics import Metrics
    from apex_fuzzer.reporting.coverage import CoverageTracker
    from apex_fuzzer.budgets import BudgetTracker
    from apex_fuzzer.validation.evidence import EvidenceStore
    cov = CoverageTracker()
    found = orch._second_order_probe(
        [_ep("https://t.com/api/x")], EvidenceStore(out / "proofs"),
        Metrics(), BudgetTracker(Config()), cov, _so_http({}),
        [Identity(name="anonymous")])
    assert found == []
    assert cov.summary()["second_order"] == "untestable"


# ── config / profiles / impact ────────────────────────────────────────
def test_validate_runs_authz_and_second_order_steps():
    import tempfile
    from pathlib import Path
    from apex_fuzzer.orchestrator import Orchestrator
    from apex_fuzzer.profiles import get as get_profile
    from apex_fuzzer.reporting.metrics import Metrics
    from apex_fuzzer.reporting.coverage import CoverageTracker
    from apex_fuzzer.budgets import BudgetTracker
    from apex_fuzzer.validation.evidence import EvidenceStore
    from apex_fuzzer.models import Identity

    store = {}

    class H:
        def get(self, url, **kw):
            c = (kw.get("headers") or {}).get("Cookie", "")
            if url.endswith("/list"):
                vals = " ".join(store.values())
                return FakeResp(200, f"<ul><li>{vals}</li></ul>")
            if "api/u" in url:
                if not c:
                    return FakeResp(401, "login")
                return FakeResp(200, json.dumps({"id": 1}))
            return FakeResp(200, "<p>home</p>",
                            {"server": "nginx"})

        def post(self, url, **kw):
            store.update(kw.get("data") or {})
            return FakeResp(200, "ok")

        def request(self, method, url, **kw):
            return FakeResp(200, json.dumps({"id": 1}))

    out = Path(tempfile.mkdtemp())
    (out / "technologies.jsonl").write_text("")
    cfg = Config()
    cfg.authorization.enabled = True
    cfg.validation.second_order = True
    cfg.auth.contexts = []
    from apex_fuzzer.config import AuthContext
    cfg.auth.contexts = [AuthContext(name="user_a",
                                     headers={"Cookie": "s=A"}),
                         AuthContext(name="user_b",
                                     headers={"Cookie": "s=B"})]
    orch = Orchestrator(cfg, out, profile=get_profile("standard"))
    eps = [_ep("https://t.com/api/u", [], "api"),
           _ep("https://t.com/comment", ["body"], "page"),
           _ep("https://t.com/list", [], "page")]
    m, cov = Metrics(), CoverageTracker()
    found = orch._validate(
        [], eps, EvidenceStore(out / "proofs"), m, H(), out,
        BudgetTracker(cfg), cov)
    sources = {f.source for f in found}
    assert "idor-swap" in sources
    assert "second-order" in sources
    assert cov.summary()["bola"] == "candidate"
    assert cov.summary()["second_order"] == "candidate"
    assert (out / "authorization_matrix.json").exists()


def test_authorization_config_defaults():
    cfg = Config()
    assert cfg.authorization.methods[:2] == ["GET", "POST"]
    assert cfg.authorization.max_endpoints == 20
    assert cfg.validation.second_order is False


def test_profiles_wire_new_stages():
    from apex_fuzzer.profiles import get as get_profile
    assert get_profile("deep").authz_matrix is True
    assert get_profile("deep").second_order is True
    assert get_profile("api").authz_matrix is True
    assert get_profile("api").second_order is False
    assert get_profile("standard").authz_matrix is False
    assert get_profile("validation").second_order is True


def test_cli_second_order_flag():
    from apex_fuzzer.cli import build_parser
    from apex_fuzzer.config import apply_cli_overrides
    args = build_parser().parse_args(["-d", "x.com", "--second-order"])
    cfg = apply_cli_overrides(Config(), args)
    assert cfg.validation.second_order is True


def test_impact_new_classes():
    from apex_fuzzer.reporting import impact as im
    bfla = Finding(id="1", source="authz-matrix",
                   name="BFLA: DELETE /api/users treats roles identically",
                   matched_at="https://t.com/api/users")
    assert im._classify(bfla) == "bfla"
    assert "privilege escalation" in im.build_impact(bfla)
    so = Finding(id="2", source="second-order",
                 name="Stored XSS candidate: canary renders raw_html",
                 matched_at="https://t.com/list",
                 raw={"inject_url": "https://t.com/c",
                      "render_url": "https://t.com/list",
                      "context": "dangerous:raw_html"})
    assert im._classify(so) == "second_order"
    steps = im.build_repro_steps(so)
    assert any("POST" in s for s in steps)
    assert "inert" in im.build_fp_notes(so)
    rep = im.build_repro_steps(Finding(
        id="3", source="idor-swap", name="BOLA: u reads object",
        matched_at="https://t.com/api/u?id=1",
        raw={"observations": [{"identity": "user_b", "method": "GET",
                               "status": 200}]}))
    assert any("Replay" in s for s in rep)
