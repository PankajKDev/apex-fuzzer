"""Phase 7 tests: ownership comparison, generic guard, extended
matrix views, graph sync. No network in any test."""
import json

from main.authz.compare import (
    is_generic_response, compare_access)
from main.authz.matrix import (
    ExtendedMatrix, AuthzCell, build_extended, display_status)
from main.authz.roles import (
    role_access_map, is_privileged_role, check_vertical_escalation)
from main.authz.tenants import tenant_view
from main.authz.resources import resource_access_map
from main.authz.actions import action_coverage
from main.authz.graph import sync_extended
from main.authorization.harvest import HarvestedId, harvest_ids
from main.authorization.access_tests import swap_ids
from main.authorization.matrix import (
    AuthorizationMatrix, AuthorizationObservation)
from main.graph.application_graph import ApplicationGraph
from main.models import Identity, Endpoint, Parameter
from main.config import Config


class FakeResp:
    def __init__(self, status, text):
        self.status_code = status
        self.text = text
        self.headers = {}


def _ep(url):
    from main.discovery.url_normalizer import normalize_url
    from urllib.parse import urlparse
    p = urlparse(url)
    return Endpoint(url=url, normalized_url=normalize_url(url),
                    host=p.hostname or "", path=p.path,
                    endpoint_type="api", source=["recon"])


# ── generic guard ─────────────────────────────────────────────────────
def test_generic_patterns():
    assert is_generic_response('{"ok": true}')[0] is True
    assert is_generic_response(
        '{"success": true, "message": "done"}')[0] is True
    assert is_generic_response('[]')[0] is True
    assert is_generic_response('{}')[0] is True
    assert is_generic_response(
        '{"data": [], "page": 1, "total": 0}')[0] is True
    assert is_generic_response('{"id": 1, "email": "a@b.c"}') == \
        (False, "")
    assert is_generic_response('[{"id": 1}]')[0] is False
    assert is_generic_response("<html>hi</html>") == (False, "")
    assert is_generic_response("") == (False, "")


def test_compare_levels():
    owner = {"id": "1", "owner_id": "u_a", "email": "a@x.com"}
    tester = json.dumps({"id": "1", "owner_id": "u_a",
                         "email": "a@x.com"})
    r = compare_access(owner, tester)
    assert r["level"] == "high" and "owner_id" in r["matched"]
    # custom ownership fields respected
    r2 = compare_access({"dept": "d1"}, json.dumps({"dept": "d1"}),
                        ownership_fields=["dept"])
    assert r2["level"] == "high"
    # equal bare id only → medium with reflection caveat
    r3 = compare_access({"id": "1"}, json.dumps({"id": "1"}),
                        ownership_fields=["owner_id"])
    assert r3["level"] == "medium" and "reflection" in r3["detail"]
    # differing values → voided even though keys overlap
    r4 = compare_access({"id": "1", "owner_id": "u_a"},
                        json.dumps({"id": "1", "owner_id": "u_b"}))
    assert r4["level"] == "none" and "different object" in r4["detail"]
    # generic tester body → voided
    r5 = compare_access(owner, '{"ok": true}')
    assert r5["level"] == "none" and "generic" in r5["detail"]
    # no markers anywhere → shape-only medium
    r6 = compare_access({}, json.dumps({"x": 1}))
    assert r6["level"] == "medium"
    # tester without identifiers → cannot confirm
    r7 = compare_access(owner, json.dumps({"msg": "hi"}))
    assert r7["level"] == "none"
    r8 = compare_access(owner, tester, owner_generic=True)
    assert r8["level"] == "none" and "owner baseline" in r8["detail"]


# ── harvest markers ───────────────────────────────────────────────────
def test_harvest_records_markers_and_redacted_snippet():
    class H:
        def get(self, url, **kw):
            return FakeResp(200, json.dumps(
                {"id": 1, "owner_id": "u_a",
                 "token": "SUPERSECRETVALUE123"}))

    ep = _ep("https://t.com/api/u")
    ids = harvest_ids(H(), ep, [Identity(name="user_a")])
    # id + owner_id both extracted now (ownership needs owner_id)
    assert {h.param for h in ids} == {"id", "owner_id"}
    owner_rec = [h for h in ids if h.param == "owner_id"][0]
    assert owner_rec.markers["owner_id"] == "u_a"
    assert "SUPERSECRETVALUE123" not in owner_rec.snippet
    assert owner_rec.to_dict()["markers"]["owner_id"] == "u_a"


def test_harvest_custom_nested_ownership_field():
    class H:
        def get(self, url, **kw):
            return FakeResp(200, json.dumps(
                {"id": 1, "profile": {"department": "research"}}))

    ids = harvest_ids(H(), _ep("https://t.com/api/u"),
                      [Identity(name="user_a")],
                      ownership_fields=["department"])
    assert [h.param for h in ids] == ["id"]
    assert ids[0].markers["department"] == "research"
    body = json.dumps({"id": 1,
                       "profile": {"department": "research"}})
    result = swap_ids(
        _swap_http(body, body), ids,
        Identity(name="user_b", auth_headers={"Cookie": "s=B"}),
        ownership_fields=["department"])
    assert result[0].markers_matched == ["department"]


def test_per_endpoint_ownership_fields_config_loads(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(
        "authorization:\n"
        "  ownership_fields_by_endpoint:\n"
        "    /api/profile: [account_ref, email]\n")
    cfg = Config.load(path)
    assert cfg.authorization.ownership_fields_by_endpoint["/api/profile"] == [
        "account_ref", "email"]


# ── swap with comparison ──────────────────────────────────────────────
def _swap_http(owner_body, tester_body):
    class H:
        def get(self, url, **kw):
            c = (kw.get("headers") or {}).get("Cookie", "")
            return FakeResp(200, tester_body if "s=B" in c
                            else owner_body)
    return H()


def _harvested(owner_body, owner="user_a"):
    from main.validation.differential import normalize_response

    class R:
        status_code = 200
        text = owner_body
    n = normalize_response(R())
    from main.authorization.harvest import extract_ids_from_body
    return HarvestedId(
        endpoint_url="https://t.com/api/u", normalized_url="https://t.com/api/u",
        param="id", value="1", owner=owner, shape=n["key_shape"],
        body_hash=n["body_hash"],
        markers=extract_ids_from_body(owner_body))


def test_swap_markers_noted_and_high_confidence():
    owner = json.dumps({"id": 1, "owner_id": "u_a"})
    out = swap_ids(_swap_http(owner, owner),
                   [_harvested(owner)],
                   Identity(name="user_b",
                            auth_headers={"Cookie": "s=B"}))
    assert out[0].verdict == "strong_candidate"
    assert out[0].markers_matched == ["owner_id"]
    assert "owner_id" in out[0].notes
    assert out[0].to_dict()["markers_matched"] == ["owner_id"]


def test_swap_generic_identical_is_no_finding():
    # THE false-positive class: both sides serve {"ok": true} with a
    # matching shape. Must not become a candidate.
    generic = json.dumps({"ok": True})
    out = swap_ids(_swap_http(generic, generic),
                   [_harvested(generic)],
                   Identity(name="user_b",
                            auth_headers={"Cookie": "s=B"}))
    assert out[0].verdict == "inconclusive"
    assert out[0].generic_response is True
    assert "generic" in out[0].notes


def test_swap_different_object_voided():
    owner = json.dumps({"id": 1, "owner_id": "u_a"})
    tester = json.dumps({"id": 1, "owner_id": "u_b"})
    out = swap_ids(_swap_http(owner, tester),
                   [_harvested(owner)],
                   Identity(name="user_b",
                            auth_headers={"Cookie": "s=B"}))
    # same shape (same keys) but contradictory markers → voided
    assert out[0].verdict == "inconclusive"
    assert "different object" in out[0].notes


# ── extended matrix ───────────────────────────────────────────────────
def test_extended_build_merge_query_counts():
    m = AuthorizationMatrix()
    m.record(AuthorizationObservation(
        identity="a", role="member", tenant="t1",
        endpoint="https://h/api", method="GET", status=200,
        shape="s", body_hash="h"))
    ext = build_extended(m.observations, [])
    assert len(ext.cells) == 1
    cell = ext.query(identity="a")[0]
    assert cell.role == "member" and cell.status == "tested_negative"
    assert ext.status_counts() == {"tested_negative": 1}
    # merge precedence: candidate beats negative
    ext.set(AuthzCell(identity="a", role="member", tenant="t1",
                      resource="", endpoint="https://h/api",
                      method="GET", status="candidate"))
    assert ext.query(identity="a")[0].status == "candidate"
    assert display_status("tested_negative") == "negative"
    rt = ExtendedMatrix.from_dict(ext.to_dict())
    assert len(rt.cells) == 1


# ── role / tenant / resource / action views ───────────────────────────
def _obs(identity, status=200, shape='{"id":1}', role="", tenant="",
         endpoint="https://h/api", method="GET", h="h1"):
    return AuthorizationObservation(
        identity=identity, status=status, shape=shape, role=role,
        tenant=tenant, endpoint=endpoint, method=method, body_hash=h,
        length_bucket=0)


def test_role_view_and_escalation():
    from main.authz.matrix import build_extended
    ext = build_extended([_obs("admin", role="admin"),
                          _obs("u", role="member"),
                          _obs("anon", status=401)], [])
    amap = role_access_map(ext.cells.values())
    assert amap["admin"]["https://h/api"]["GET"] == "tested_negative"
    assert is_privileged_role("super-admin") is True
    assert is_privileged_role("member") is False
    esc = check_vertical_escalation([_obs("admin", role="admin"),
                                     _obs("u", role="member")])
    assert len(esc) == 1
    assert esc[0]["kind"] == "vertical_escalation"
    assert check_vertical_escalation(
        [_obs("admin", role="admin", shape='{"a":1}', h="ha"),
         _obs("u", role="member", shape='{"b":2}', h="hb")]) == []
    assert check_vertical_escalation([_obs("a")]) == []


def test_tenant_view():
    h1 = HarvestedId(endpoint_url="https://t.com/a",
                     normalized_url="https://t.com/a", param="id",
                     value="1", owner="a", owner_tenant="t1")
    h2 = HarvestedId(endpoint_url="https://t.com/b",
                     normalized_url="https://t.com/b", param="id",
                     value="2", owner="b", owner_tenant="t2")

    class Sw:
        def __init__(self, **kw):
            self.__dict__.update(kw)

    swaps = [Sw(owner="a", owner_tenant="t1", tester="b",
                tester_tenant="t2", victim_value="1",
                endpoint_url="https://t.com/a?id=1",
                verdict="strong_candidate"),
             Sw(owner="a", owner_tenant="t1", tester="c",
                tester_tenant="t1", victim_value="1",
                endpoint_url="https://t.com/a?id=1",
                verdict="inconclusive")]
    view = tenant_view([h1, h2], swaps)
    assert view["owned_resources"] == {"t1": ["1"], "t2": ["2"]}
    assert len(view["cross_tenant_access"]) == 1
    assert view["cross_tenant_access"][0]["tester"] == "b"


def test_resource_access_map():
    h = HarvestedId(endpoint_url="https://t.com/a?id=1",
                    normalized_url="https://t.com/a", param="id",
                    value="1", owner="a", owner_tenant="t1")

    class Sw:
        verdict = "strong_candidate"
        tester = "b"
        tester_tenant = "t2"
        endpoint_url = "https://t.com/a?id=1"
        param = "id"

    m = resource_access_map([h], [Sw()],
                            [_obs("b", tenant="t2",
                                  endpoint="https://t.com/a")])
    key = "https://t.com/a::id"
    assert m[key]["owner"] == "a"
    assert {"identity": "b", "tenant": "t2"} in m[key]["accessed_by"]


def test_action_coverage():
    from main.authz.matrix import build_extended
    ext = build_extended([_obs("a", method="GET"),
                          _obs("a", method="POST")], [])
    cov = action_coverage(
        ext.cells.values(), [], ["GET", "POST", "DELETE"])
    assert cov["https://h/api"]["methods"] == {
        "GET": "tested_negative", "POST": "tested_negative"}
    assert cov["https://h/api"]["untested_methods"] == ["DELETE"]


def test_graph_sync_edges():
    g = ApplicationGraph()
    h = HarvestedId(endpoint_url="https://t.com/a?id=1",
                    normalized_url="https://t.com/a", param="id",
                    value="1", owner="a", owner_tenant="t1")
    from main.graph.application_graph import nid
    assert sync_extended(g, [h]) == 2  # OWNS + CONTAINS (EXPOSED_BY
    # needs a pre-existing endpoint node, absent here by design)
    types = {(e["src"], e["dst"], e["type"]) for e in g.edges}
    assert (nid("identity", "a"), nid("resource", "https://t.com/a",
                                      "id", "1"), "OWNS") in types
    assert (nid("tenant", "t1"), nid("resource", "https://t.com/a",
                                     "id", "1"), "CONTAINS") in types
    assert sync_extended(g, [h]) == 0  # idempotent on re-sync


# ── config + orchestrator ─────────────────────────────────────────────
def test_ownership_fields_config():
    cfg = Config()
    assert "owner_id" in cfg.authorization.ownership_fields
    assert "email" in cfg.authorization.ownership_fields


def test_extended_artifact_and_escalation_coverage(tmp_path):
    import tempfile
    from pathlib import Path
    from main.orchestrator import Orchestrator
    from main.profiles import get as get_profile
    from main.reporting.metrics import Metrics
    from main.reporting.coverage import CoverageTracker
    from main.budgets import BudgetTracker
    from main.validation.evidence import EvidenceStore
    victim = json.dumps({"id": 1, "owner_id": "u_a"})

    class H:
        def get(self, url, **kw):
            return FakeResp(200, victim)

        def post(self, url, **kw):
            return FakeResp(200, "ok")

        def request(self, method, url, **kw):
            return FakeResp(403, "no")

    out = Path(tempfile.mkdtemp())
    cfg = Config()
    cfg.authorization.enabled = True
    cfg.authorization.methods = ["GET"]
    orch = Orchestrator(cfg, out, profile=get_profile("standard"))
    ep = _ep("https://t.com/api/u")
    ep.query_parameters.append(Parameter(
        name="id", location="query", source=["url"], sample_value="1"))
    ids = [Identity(name="user_a", auth_headers={"Cookie": "s=A"}),
           Identity(name="admin", roles=["admin"],
                    auth_headers={"Cookie": "s=ROOT"})]
    found = orch._authz_matrix_probe(
        [ep], EvidenceStore(out / "proofs"), Metrics(),
        BudgetTracker(cfg), CoverageTracker(), H(), out, ids)
    art = json.loads((out / "authorization_matrix.json").read_text())
    assert "extended" in art and "views" in art
    assert set(art["views"]) == {"roles", "vertical_escalations",
                                 "tenants", "resources", "actions"}
    assert any(f.source == "idor-swap" for f in found)
    swap = [f for f in found if f.source == "idor-swap"][0]
    assert "owner_id" in swap.description  # ownership evidence shown
