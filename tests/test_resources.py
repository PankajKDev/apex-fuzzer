"""Resource intelligence tests (agent Phase 5).

Multi-source ID extractors, lifecycle-aware enrichment, shared-ID
graph links, CRUD helper reuse, and the offline orchestrator intel
step. No network in any test.
"""

from apex_fuzzer.application.resources import (
    discover_ids_from_html, discover_ids_from_headers,
    discover_ids_from_js, discover_ids_from_graphql,
    discover_ids_from_traffic, _guess_type)
from apex_fuzzer.state.resources import (
    ResourceTracker, link_crud_from_endpoints)
from apex_fuzzer.authz.resources import enrich_resource_records
from apex_fuzzer.authorization.harvest import HarvestedId
from apex_fuzzer.authorization.matrix import AuthorizationObservation
from apex_fuzzer.graph.application_graph import ApplicationGraph
from apex_fuzzer.models import Endpoint, Parameter


def _ep(url, method="GET", qparams=None):
    from apex_fuzzer.discovery.url_normalizer import normalize_url
    from urllib.parse import urlparse
    p = urlparse(url)
    e = Endpoint(url=url, normalized_url=normalize_url(url),
                 host=p.hostname or "", path=p.path, method=method,
                 endpoint_type="api", source=["recon"])
    for n, v in (qparams or []):
        e.query_parameters.append(Parameter(
            name=n, location="query", source=["url"], sample_value=v))
    return e


def _hid(url, param, value, owner="u", tenant="t1", hint=""):
    return HarvestedId(endpoint_url=url, normalized_url=url,
                       param=param, value=value, owner=owner,
                       owner_tenant=tenant, shape="s", body_hash="h",
                       resource_type_hint=hint)


# ── extractors ────────────────────────────────────────────────────────
def test_html_extractors():
    html = ('<form><input type="hidden" name="user_id" value="u_4242">'
            '<input type="hidden" name="csrf" value="tok123456">'
            '<div data-project-id="proj_9911">x</div>'
            '<a href="/orders/ord_5522/details">view</a></form>')
    out = discover_ids_from_html(html)
    assert out["user_id"] == "u_4242"
    assert out["project_id"] == "proj_9911"
    assert out["path_id"] == "ord_5522"
    assert "csrf" not in out  # not identifier-like
    assert discover_ids_from_html("") == {}
    assert discover_ids_from_html(None) == {}


def test_header_extractor():
    out = discover_ids_from_headers({
        "X-User-Id": "u_7777", "Content-Type": "text/html",
        "Location": "https://t.com/orders/ord_9911/confirm"})
    assert out["user_id"] == "u_7777"
    assert out["path_id"] == "ord_9911"
    assert "content_type" not in out
    assert discover_ids_from_headers({}) == {}
    assert discover_ids_from_headers(None) == {}


def test_js_extractor():
    js = ('const cfg = {"userId": "nope", "user_id": "u_31337",'
          '"debug": true}; fetch("/api/orders?order_id=ord_1234&x=1");')
    out = discover_ids_from_js(js)
    assert out["user_id"] == "u_31337"
    assert out["order_id"] == "ord_1234"
    assert "debug" not in out and "x" not in out
    assert discover_ids_from_js("") == {}


def test_graphql_extractor_typename():
    data = {"data": {"user": {"__typename": "User", "id": "u_1001",
                              "email": "a@b.c",
                              "posts": [{"__typename": "Post",
                                         "id": "p_9001"}]}}}
    ids, typename = discover_ids_from_graphql(data)
    assert typename == "User"
    assert ids["id"] == "u_1001" and ids["email"] == "a@b.c"
    # sub-minimum-length values are noise by design (see dependencies)
    assert discover_ids_from_graphql(
        {"data": {"id": "7"}})[0] == {}
    assert discover_ids_from_graphql({}) == ({}, "")
    assert discover_ids_from_graphql(None) == ({}, "")
    assert discover_ids_from_graphql("junk") == ({}, "")


def test_traffic_extractor():
    reqs = [{"url": "https://t.com/api/u?user_id=u_4242&verbose=1"},
            {"url": "https://t.com/static/app.js"},
            {"url": ""}, {}, {"url": "not a url at all!!! $$$"}]
    out = discover_ids_from_traffic(reqs)
    assert ("https://t.com/api/u?user_id=u_4242&verbose=1",
            "user_id", "u_4242") in out
    assert all(t[1] != "verbose" for t in out)
    assert discover_ids_from_traffic([]) == []


def test_guess_type_sanity():
    assert _guess_type("user_id", "") == "user"
    assert _guess_type("order_id", "") == "order"
    assert _guess_type("whatever", "") == "object"


# ── enrichment ────────────────────────────────────────────────────────
def test_enrich_prefers_typename_and_maps_permissions():
    pool = [_hid("https://t.com/gql", "id", "u_1", hint="User")]
    obs = [AuthorizationObservation(
        identity="user_b", tenant="t2", endpoint="https://t.com/gql",
        method="GET", status=200, shape="s", body_hash="h")]
    ep = _ep("https://t.com/gql?id=u_1", qparams=[("id", "u_1")])
    tracker = ResourceTracker()
    recs = enrich_resource_records(pool, obs, tracker, [ep])
    assert len(recs) == 1
    rec = recs[0]
    assert rec["resource_type"] == "User"  # typename beats heuristic
    assert rec["owner"] == "u" and rec["tenant"] == "t1"
    assert rec["permissions"] == {"read_by": ["user_b"]}
    assert rec["fields"] == ["id"]
    assert rec["lifecycle"]["state"] == "active"
    assert rec["identifiers"] == {"id": "u_1"}
    assert rec["source"] == "response"


def test_enrich_heuristic_type_and_empty_tracker():
    pool = [_hid("https://t.com/o", "order_id", "o_5")]
    recs = enrich_resource_records(pool, [], None, [])
    assert recs[0]["resource_type"] == "order"
    assert recs[0]["permissions"] == {"read_by": []}
    assert recs[0]["lifecycle"]["state"] == "active"
    assert enrich_resource_records([], [], None, []) == []


def test_crud_helper_shared_rule():
    from apex_fuzzer.models import Resource
    tracker = ResourceTracker()
    res = [Resource(key="https://t.com/o::query:order_id",
                    resource_type="order",
                    identifiers={"order_id": "o_5"})]
    eps = [_ep("https://t.com/o", method="POST",
               qparams=[("order_id", "o_5")]),
           _ep("https://t.com/o/1", method="GET",
               qparams=[("order_id", "1")]),
           _ep("https://t.com/o/1", method="DELETE",
               qparams=[("order_id", "1")]),
           _ep("https://t.com/other", method="GET")]
    assert link_crud_from_endpoints(tracker, res, eps) == 3
    crud = tracker.resources["https://t.com/o::query:order_id"].crud
    assert crud == {"create": "https://t.com/o",
                    "read": "https://t.com/o/1",
                    "delete": "https://t.com/o/1"}
    # second call adds nothing (first match wins per action)
    assert link_crud_from_endpoints(tracker, res, eps) == 0
    assert link_crud_from_endpoints(ResourceTracker(), [], eps) == 0


# ── shared-identifier graph links ─────────────────────────────────────
def test_shared_identifier_links():
    from apex_fuzzer.authz.graph import sync_extended
    g = ApplicationGraph()
    pool = [_hid("https://t.com/orders", "user_id", "u_9999",
                 owner="alice"),
            _hid("https://t.com/users", "id", "u_9999", owner="alice"),
            _hid("https://t.com/noise", "page", "1", owner="alice")]
    n = sync_extended(g, pool)
    assert n > 0
    deps = [e for e in g.edges if e["type"] == "DEPENDS_ON"]
    assert len(deps) == 1
    assert deps[0]["attrs"].get("symmetric") is True
    assert "u_9999" in deps[0]["attrs"].get("via_value", "")
    # short/generic values never link
    assert not [e for e in deps if "page" in str(e)]
    # second sync adds nothing (idempotent)
    assert sync_extended(g, pool) == 0


# ── orchestrator intel step (offline) ─────────────────────────────────
def _orch():
    import tempfile
    from pathlib import Path
    from apex_fuzzer.orchestrator import Orchestrator
    from apex_fuzzer.config import Config
    from apex_fuzzer.profiles import get as get_profile
    td = tempfile.mkdtemp()
    return (Orchestrator(Config(), Path(td),
                         profile=get_profile("standard")),
            Path(td))


def test_intel_step_offline_end_to_end(tmp_path):
    import tempfile
    from pathlib import Path
    from apex_fuzzer.orchestrator import Orchestrator
    from apex_fuzzer.config import Config
    from apex_fuzzer.profiles import get as get_profile
    from apex_fuzzer.reporting.metrics import Metrics
    from apex_fuzzer.checkpoints import Checkpoint
    from apex_fuzzer.graph.application_graph import ApplicationGraph
    from types import SimpleNamespace
    out = Path(tempfile.mkdtemp())
    orch = Orchestrator(Config(), out, profile=get_profile("standard"))
    eps = [_ep("https://t.com/api/u?id=u_4242",
               qparams=[("id", "u_4242")])]
    # JS cache producer
    cache = out / "cache"
    cache.mkdir()
    js_url = "https://t.com/static/app.js"
    key = "https___t.com_static_app.js"
    (cache / key).write_text(
        'fetch("/api/orders?order_id=ord_1234");')
    import json as _json
    (cache / (key + ".meta")).write_text(_json.dumps({"url": js_url}))
    # traffic producer
    (out / "browser_traffic.json").write_text(_json.dumps({
        "requests": [{"url": "https://t.com/api/u?uid=u_9999",
                      "method": "GET"}]}))
    # harvest pool (response-sourced) as the probe would leave it
    orch._harvest_pool = [
        HarvestedId(endpoint_url="https://t.com/api/u?id=u_4242",
                    normalized_url="https://t.com/api/u",
                    param="id", value="u_4242", owner="user_a",
                    owner_tenant="t1", shape="s", body_hash="h")]
    orch._page_ids = [("https://t.com/p", "user_id", "u_31337",
                       "html")]
    app = SimpleNamespace(resources=[], workflows=[],
                          to_dict=lambda: {"workflows": []})
    g = ApplicationGraph()
    m = Metrics()
    orch._build_resource_intel(out, eps, app, g, m,
                               Checkpoint(out / "checkpoint.json"))
    payload = _json.loads((out / "resources.json").read_text())
    recs = payload["records"]
    by_src = {}
    for r in recs:
        by_src.setdefault(r["source"], []).append(r["key"])
    assert "response" in by_src and "javascript" in by_src
    assert "traffic" in by_src and "html" in by_src
    assert any("ord_1234" in str(r["identifiers"]) for r in recs)
    # graph grew with resource nodes, metrics untouched (no new metric)
    assert g.nodes
    # run twice: artifact stable, no duplicates
    orch._build_resource_intel(out, eps, app, g, m,
                               Checkpoint(out / "checkpoint.json"))
    payload2 = _json.loads((out / "resources.json").read_text())
    assert len(payload2["records"]) == len(recs)


def test_intel_step_empty_inputs():
    orch, out = _orch()
    from apex_fuzzer.reporting.metrics import Metrics
    from apex_fuzzer.checkpoints import Checkpoint
    m = Metrics()
    orch._build_resource_intel(out, [], None, None, m,
                               Checkpoint(out / "checkpoint.json"))
    import json as _json
    assert _json.loads(
        (out / "resources.json").read_text()) == {"records": []}
