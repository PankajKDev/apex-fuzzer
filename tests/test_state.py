"""Application state graph tests (agent Phase 3).

Unit tests for vocabulary, builders, snapshots, transitions, diffs,
resources and lifecycles — plus orchestrator integration proving
matrix observations land in the graph with snapshots, transitions,
and resume-aware change detection. No network in any test.
"""
import json

from apex_fuzzer.graph.application_graph import (
    ApplicationGraph, NODE_TYPES, EDGE_TYPES, nid)
from apex_fuzzer.state.graph import (
    ensure_identity, ensure_endpoint, ensure_session,
    record_observation, record_transition, sync_matrix_observations,
    ensure_workflow)
from apex_fuzzer.state.snapshots import StateSnapshot, SnapshotStore
from apex_fuzzer.state.transitions import Transition, TransitionLog
from apex_fuzzer.state.diff import (diff_snapshots, diff_graphs,
                                     summarize)
from apex_fuzzer.state.resources import ResourceState, ResourceTracker
from apex_fuzzer.state.lifecycle import (
    Lifecycle, check_transition, DEFAULT_LIFECYCLES)
from apex_fuzzer.authorization.matrix import (
    AuthorizationMatrix, AuthorizationObservation)
from apex_fuzzer.models import Identity, Endpoint, Parameter


def _ep(url):
    from apex_fuzzer.discovery.url_normalizer import normalize_url
    from urllib.parse import urlparse
    p = urlparse(url)
    return Endpoint(url=url, normalized_url=normalize_url(url),
                    host=p.hostname or "", path=p.path,
                    endpoint_type="api", source=["recon"])


class FakeResp:
    def __init__(self, status, text):
        self.status_code = status
        self.text = text
        self.headers = {}


# ── vocabulary: additive, old artifacts unaffected ────────────────────
def test_phase3_vocab_present_and_old_artifact_loads():
    for t in ("state", "transition", "request", "response",
              "observation", "token", "resource_field",
              "workflow_step"):
        assert t in NODE_TYPES
    for t in ("AUTHENTICATED_AS", "UPDATES", "TRANSITIONS", "PRECEDES",
              "REQUIRES", "PRODUCES", "CONSUMES", "TRIGGERS", "STORES",
              "RENDERS", "INVALIDATES", "REQUIRES_STATE",
              "CHANGES_STATE"):
        assert t in EDGE_TYPES
    old = {"nodes": [{"id": "endpoint:/x", "type": "endpoint",
                      "label": "/x", "attrs": {}}], "edges": []}
    g = ApplicationGraph.from_dict(old)
    assert len(g.nodes) == 1
    try:
        g.add_node("x", "bogus", "x")
        raise AssertionError("unknown node type must raise")
    except ValueError:
        pass
    try:
        g.add_node("a", "host", "a")
        g.add_node("b", "host", "b")
        g.add_edge("a", "b", "BOGUS")
        raise AssertionError("unknown edge type must raise")
    except ValueError:
        pass


# ── behavioral builders ───────────────────────────────────────────────
def test_ensure_helpers_idempotent():
    g = ApplicationGraph()
    assert ensure_identity(g, "u", "t1", "member") == \
        ensure_identity(g, "u", "t1", "member")
    assert ensure_endpoint(g, "https://h/api") == \
        ensure_endpoint(g, "https://h/api")
    iid = nid("identity", "u")
    sid = ensure_session(g, iid, "s1")
    assert ensure_session(g, iid, "s1") == sid
    assert (iid, sid, "AUTHENTICATED_AS") in [
        (e["src"], e["dst"], e["type"]) for e in g.edges]


def test_record_observation_edges():
    g = ApplicationGraph()
    record_observation(g, "u", "https://h/api", "GET", 200, "s1")
    types = {(e["src"], e["dst"], e["type"]) for e in g.edges}
    iid, eid = nid("identity", "u"), nid("endpoint", "https://h/api")
    assert (iid, eid, "CAN_ACCESS") in types
    assert any(t == "READS" for _, _, t in types)
    # denial: observation recorded, but no access edge
    g2 = ApplicationGraph()
    record_observation(g2, "u", "https://h/api", "GET", 403, "s1")
    assert not [e for e in g2.edges if e["type"] == "CAN_ACCESS"]
    assert [e for e in g2.edges if e["type"] == "READS"]
    # POST 200 → WRITES, not READS
    g3 = ApplicationGraph()
    record_observation(g3, "u", "https://h/api", "POST", 200, "s1")
    types3 = {e["type"] for e in g3.edges}
    assert "WRITES" in types3 and "READS" not in types3


def test_record_transition_and_workflow():
    g = ApplicationGraph()
    tid = record_transition(g, "state:a", "state:b", "obs:1",
                            actor="u")
    assert tid == record_transition(g, "state:a", "state:b", "obs:1")
    assert len([e for e in g.edges if e["type"] == "TRANSITIONS"]) == 2
    wid = ensure_workflow(g, "checkout", ["/cart", "/pay", "/done"])
    prec = [(e["src"], e["dst"]) for e in g.edges
            if e["type"] == "PRECEDES"]
    assert len(prec) == 2
    assert wid == nid("workflow", "checkout")


def test_sync_matrix_observations():
    g = ApplicationGraph()
    m = AuthorizationMatrix()
    m.record(AuthorizationObservation(
        identity="a", tenant="t1", endpoint="https://h/api",
        method="GET", status=200, shape="s", body_hash="h"))
    m.record(AuthorizationObservation(
        identity="", endpoint="", method="GET", status=200))
    assert sync_matrix_observations(g, m.observations) == 1
    assert sync_matrix_observations(g, []) == 0
    assert [e for e in g.edges if e["type"] == "CAN_ACCESS"]


# ── snapshots ─────────────────────────────────────────────────────────
def test_snapshot_capture_and_store(tmp_path):
    s = StateSnapshot.capture("u", "https://h/api", "GET", 200,
                              '{"a":1}', cookies="s=1", storage="{}")
    assert s.cookies_digest and s.storage_digest
    assert s.key() == "u::GET::https://h/api"
    store = SnapshotStore()
    store.add(s)
    assert store.latest("u", "https://h/api", "GET").snapshot_id == \
        s.snapshot_id
    assert store.latest("ghost", "https://h/api") is None
    p = tmp_path / "snaps.jsonl"
    store.save(p)
    rt = SnapshotStore.load(p)
    assert len(rt.snapshots) == 1
    assert rt.snapshots[0].status == 200
    assert SnapshotStore.load(tmp_path / "nope.jsonl").snapshots == []
    # corrupt lines skipped
    p.write_text("not json\n" + open(p).read())
    assert len(SnapshotStore.load(p).snapshots) == 1


# ── transitions ───────────────────────────────────────────────────────
def test_transition_only_on_change(tmp_path):
    blog = TransitionLog()
    a = StateSnapshot.capture("u", "e", "GET", 200, "s1")
    same = StateSnapshot.capture("u", "e", "GET", 200, "s1")
    changed = StateSnapshot.capture("u", "e", "GET", 403, "s1")
    assert blog.record_if_changed(a, same) is None
    assert blog.record_if_changed(None, changed) is None
    t = blog.record_if_changed(a, changed, via="probe", actor="u")
    assert t is not None and t.actor == "u"
    assert blog.successors(a.snapshot_id) == [t]
    assert blog.successors("nothing") == []
    p = tmp_path / "t.jsonl"
    blog.save(p)
    assert len(TransitionLog.load(p).transitions) == 1
    assert Transition.from_dict(t.to_dict()).to_id == t.to_id


# ── diffs ─────────────────────────────────────────────────────────────
def test_diff_snapshots_and_graphs():
    a = StateSnapshot.capture("u", "e", "GET", 200, "s1")
    b = StateSnapshot.capture("u", "e", "GET", 403, "s1")
    d = diff_snapshots(a, b)
    assert d["changed"] and d["changes"]["status"] == {
        "before": 200, "after": 403}
    assert diff_snapshots(a, a)["changed"] is False
    old = {"nodes": [{"id": "a", "type": "host", "label": "a",
                      "attrs": {}}], "edges": []}
    new = {"nodes": [{"id": "a", "type": "host", "label": "a",
                      "attrs": {}},
                     {"id": "b", "type": "host", "label": "b",
                      "attrs": {}}],
           "edges": [{"src": "a", "dst": "b", "type": "CALLS",
                      "attrs": {}}]}
    gd = diff_graphs(old, new)
    assert gd["added_nodes"] == ["b"] and gd["removed_nodes"] == []
    assert gd["added_edges"] == [["a", "b", "CALLS"]]
    assert gd["changed"] is True
    assert summarize(gd) == "added_nodes=1, added_edges=1"
    assert summarize(diff_graphs(old, old)) == "no changes"


# ── resources + lifecycles ────────────────────────────────────────────
def test_resource_state_history_and_crud(tmp_path):
    r = ResourceState("k", "order", owner="a", tenant="t1")
    r.observe("active", via="POST /orders")
    r.observe("active", via="GET")  # unchanged → no history
    r.link_crud("create", "https://h/orders")
    r.link_crud("bogus", "https://h/x")  # ignored
    assert [h["to"] for h in r.history] == ["active"]
    assert r.crud == {"create": "https://h/orders"}
    tracker = ResourceTracker()
    tracker.resources["k"] = r
    assert tracker.of_tenant("t1") == [r]
    assert tracker.of_tenant("t2") == []
    p = tmp_path / "r.jsonl"
    tracker.save(p)
    rt = ResourceTracker.load(p)
    assert rt.resources["k"].state == "active"
    assert ResourceTracker.load(tmp_path / "no.jsonl").resources == {}
    assert ResourceState.from_dict(r.to_dict()).owner == "a"


def test_lifecycle_rules():
    assert check_transition(
        DEFAULT_LIFECYCLES["order"], "paid", "completed")[0] == \
        "allowed"
    status, reason = check_transition(
        DEFAULT_LIFECYCLES["order"], "completed", "draft")
    assert status == "denied" and "terminal" in reason
    assert check_transition(
        DEFAULT_LIFECYCLES["object"], "active", "deleted")[0] == \
        "allowed"
    assert check_transition(None, "a", "b")[0] == "inconclusive"
    assert check_transition(
        DEFAULT_LIFECYCLES["object"], "active", "weird")[0] == \
        "inconclusive"
    assert check_transition(
        DEFAULT_LIFECYCLES["invitation"], "sent", "accepted")[0] == \
        "allowed"
    from apex_fuzzer.state.lifecycle import Lifecycle
    assert Lifecycle.from_dict(
        DEFAULT_LIFECYCLES["order"].to_dict()).states[0] == "draft"


# ── orchestrator: matrix → graph + snapshots + transitions ────────────
def _matrix_http(mode):
    class H:
        def get(self, url, **kw):
            c = (kw.get("headers") or {}).get("Cookie", "")
            if "api/u" in url:
                if not c:
                    return FakeResp(401, "login")
                if mode == "open" or "s=A" in c:
                    return FakeResp(200, '{"id": 1}')
                return FakeResp(200 if mode == "open" else 403,
                                '{"id": 1}' if mode == "open" else "no")
            return FakeResp(200, "<p>x</p>")

        def post(self, url, **kw):
            return FakeResp(200, "ok")

        def request(self, method, url, **kw):
            return FakeResp(403, "no")

    return H()


def _run_matrix(out_dir, http, identities, app_graph=None):
    import tempfile
    from pathlib import Path
    from apex_fuzzer.orchestrator import Orchestrator
    from apex_fuzzer.config import Config
    from apex_fuzzer.profiles import get as get_profile
    from apex_fuzzer.reporting.metrics import Metrics
    from apex_fuzzer.reporting.coverage import CoverageTracker
    from apex_fuzzer.budgets import BudgetTracker
    from apex_fuzzer.validation.evidence import EvidenceStore
    out = Path(out_dir)
    cfg = Config()
    cfg.authorization.enabled = True
    cfg.authorization.methods = ["GET"]
    orch = Orchestrator(cfg, out, profile=get_profile("standard"))
    eps = [_ep("https://t.com/api/u")]
    eps[0].query_parameters.append(Parameter(
        name="id", location="query", source=["url"], sample_value="1"))
    found = orch._authz_matrix_probe(
        eps, EvidenceStore(out / "proofs"), Metrics(),
        BudgetTracker(cfg), CoverageTracker(), http, out, identities,
        app_graph=app_graph)
    return orch, out, found


def test_matrix_observations_land_in_graph(tmp_path):
    from apex_fuzzer.graph.application_graph import ApplicationGraph
    ids = [Identity(name="anonymous"),
           Identity(name="user_a", auth_headers={"Cookie": "s=A"}),
           Identity(name="user_b", auth_headers={"Cookie": "s=B"})]
    g = ApplicationGraph()
    _, out, found = _run_matrix(tmp_path, _matrix_http("open"), ids, g)
    access = [e for e in g.edges if e["type"] == "CAN_ACCESS"]
    assert access  # both users got 200 → edges recorded
    assert any(e["type"] == "READS" for e in g.edges)
    assert (out / "state" / "snapshots.jsonl").exists()
    assert (out / "state" / "transitions.jsonl").exists()
    assert any(f.source == "idor-swap" for f in found)
    # swap findings carry no duplicate invariant findings
    assert not [f for f in found if f.source == "invariant"]


def test_resume_detects_behavior_change(tmp_path):
    from apex_fuzzer.graph.application_graph import ApplicationGraph
    from apex_fuzzer.state.transitions import TransitionLog
    ids = [Identity(name="anonymous"),
           Identity(name="user_a", auth_headers={"Cookie": "s=A"}),
           Identity(name="user_b", auth_headers={"Cookie": "s=B"})]
    g = ApplicationGraph()
    _run_matrix(tmp_path, _matrix_http("open"), ids, g)
    # second run: user_b now denied → transition 200 → 403
    _run_matrix(tmp_path, _matrix_http("closed"), ids, g)
    tlog = TransitionLog.load(tmp_path / "state" / "transitions.jsonl")
    assert tlog.transitions  # the behavior change was linked
    assert any(t.to_id for t in tlog.transitions)
    trans_edges = [e for e in g.edges if e["type"] == "TRANSITIONS"]
    assert trans_edges


def test_matrix_probe_without_graph_unchanged(tmp_path):
    # backwards compat: app_graph=None behaves exactly as before
    ids = [Identity(name="anonymous"),
           Identity(name="user_a", auth_headers={"Cookie": "s=A"}),
           Identity(name="user_b", auth_headers={"Cookie": "s=B"})]
    _, out, found = _run_matrix(tmp_path, _matrix_http("open"), ids)
    assert any(f.source == "idor-swap" for f in found)
    assert not (out / "state" / "snapshots.jsonl").exists()
