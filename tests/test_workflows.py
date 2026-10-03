"""Workflow discovery tests (agent Phase 4).

Unit tests for model, dependencies, discovery producers, replay,
and mutations — plus orchestrator integration proving discovery is
pure analysis (zero network) with persisted artifacts. No network
in any test.
"""
import json

from apex_fuzzer.workflows.model import Flow, FlowStep
from apex_fuzzer.workflows.dependencies import (
    find_dependencies, prerequisite_map, endpoint_param_values)
from apex_fuzzer.workflows.discovery import (
    discover_all, discover_rest_flows, discover_traffic_flows,
    discover_crud_flows, discover_dependency_flows)
from apex_fuzzer.workflows.replay import replay_flow
from apex_fuzzer.workflows.mutations import mutate, mutation_catalog
from apex_fuzzer.models import Endpoint, Parameter, Identity
from apex_fuzzer.budgets import BudgetExceeded


def _ep(url, method="GET", qparams=None, bparams=None, etype="page"):
    from apex_fuzzer.discovery.url_normalizer import normalize_url
    from urllib.parse import urlparse
    p = urlparse(url)
    e = Endpoint(url=url, normalized_url=normalize_url(url),
                 host=p.hostname or "", path=p.path, method=method,
                 endpoint_type=etype, source=["recon"])
    for n, v in (qparams or []):
        e.query_parameters.append(Parameter(
            name=n, location="query", source=["url"], sample_value=v))
    for n in (bparams or []):
        e.body_parameters.append(Parameter(name=n, location="body",
                                            source=["html"]))
    return e


def _hid(url, param, value, owner="u"):
    from apex_fuzzer.authorization.harvest import HarvestedId
    return HarvestedId(endpoint_url=url, normalized_url=url, param=param,
                       value=value, owner=owner)


class FakeResp:
    def __init__(self, status, text):
        self.status_code = status
        self.text = text
        self.headers = {}


# ── model ─────────────────────────────────────────────────────────────
def test_flow_round_trip_and_stored_conversion():
    step = FlowStep(name="POST /projects", endpoint="https://t.com/p",
                    normalized_url="https://t.com/p", method="POST",
                    produces=["proj"], consumes=[],
                    requires=[], evidence="e")
    flow = Flow(name="f", steps=[step], observed=True,
                confidence="observed", evidence="ev")
    rt = Flow.from_dict(flow.to_dict())
    assert rt.step_names() == ["POST /projects"]
    assert rt.confidence == "observed"
    stored = flow.to_stored()
    assert stored.name == "f" and stored.observed is True
    assert stored.steps[0].method == "POST"


# ── dependencies ──────────────────────────────────────────────────────
def test_value_overlap_links_producer_consumer():
    producer = _ep("https://t.com/api/projects")
    consumer = _ep("https://t.com/api/deploy?project_id=abc123XYZ",
                   qparams=[("project_id", "abc123XYZ")])
    pool = [_hid("https://t.com/api/projects", "project_id",
                 "abc123XYZ")]
    links = find_dependencies([producer, consumer], pool)
    assert len(links) == 1
    link = links[0]
    assert link["producer"].endswith("/api/projects")
    assert link["via_param"] == "project_id"
    assert "evidence" in link


def test_noise_values_and_self_links_ignored():
    ep = _ep("https://t.com/a?id=1", qparams=[("id", "1")])
    pool = [_hid("https://t.com/a", "id", "1")]
    assert find_dependencies([ep], pool) == []  # self-link
    ep2 = _ep("https://t.com/b?x=true", qparams=[("x", "true")])
    pool2 = [_hid("https://t.com/a", "x", "true")]
    assert find_dependencies([ep, ep2], pool2) == []  # noise value
    assert endpoint_param_values(_ep("https://t.com/x")) == {}
    assert prerequisite_map([]) == {}


def test_prerequisite_map_merges():
    f1 = Flow(name="a", steps=[
        FlowStep(name="s1"), FlowStep(name="s2", requires=["s1"])])
    f2 = Flow(name="b", steps=[
        FlowStep(name="s2", requires=["s0"])])
    merged = prerequisite_map([f1, f2])
    assert sorted(merged["s2"]) == ["s0", "s1"]


# ── discovery producers ───────────────────────────────────────────────
def test_rest_stem_grouping():
    eps = [_ep("https://t.com/api/projects", method="POST"),
           _ep("https://t.com/api/projects", method="GET"),
           _ep("https://t.com/api/projects/42", method="DELETE"),
           _ep("https://t.com/about", method="GET")]
    flows = discover_rest_flows(eps)
    assert len(flows) == 1
    flow = flows[0]
    assert flow.confidence == "inferred" and not flow.observed
    assert [s.method for s in flow.steps] == ["POST", "GET", "DELETE"]
    assert flow.steps[1].requires == [flow.steps[0].name]
    assert flow.steps[0].requires == []


def test_rest_single_verb_and_unknown_method_skipped():
    assert discover_rest_flows(
        [_ep("https://t.com/a", method="GET")]) == []
    assert discover_rest_flows(
        [_ep("https://t.com/a", method="OPTIONS")]) == []


def test_traffic_chains_and_gaps():
    traffic = {"requests": [
        {"url": "https://t.com/a", "method": "GET",
         "resource_type": "document", "timestamp": 100},
        {"url": "https://t.com/api/x", "method": "GET",
         "resource_type": "xhr", "timestamp": 101},
        {"url": "ftp://t.com/f", "method": "GET",
         "resource_type": "document", "timestamp": 102},
        {"url": "https://t.com/b", "method": "GET",
         "resource_type": "document", "timestamp": 500},
    ]}
    flows = discover_traffic_flows(traffic, gap_seconds=60)
    assert len(flows) == 1  # ftp skipped, far-apart page splits off
    assert flows[0].observed is True
    assert [s.endpoint for s in flows[0].steps] == [
        "https://t.com/a", "https://t.com/api/x"]
    assert flows[0].steps[1].requires == [flows[0].steps[0].name]
    assert discover_traffic_flows({"requests": []}) == []
    single = {"requests": [{"url": "https://t.com/a", "method": "GET",
                            "resource_type": "document",
                            "timestamp": 1}]}
    assert discover_traffic_flows(single) == []


def test_crud_flows():
    from apex_fuzzer.state.resources import ResourceState
    r = ResourceState("k", "order")
    r.link_crud("create", "https://t.com/orders")
    r.link_crud("read", "https://t.com/orders/1")
    r.link_crud("delete", "https://t.com/orders/1")
    flows = discover_crud_flows([r])
    assert len(flows) == 1
    assert [s.method for s in flows[0].steps] == ["POST", "GET",
                                                  "DELETE"]
    lonely = ResourceState("k2", "object")
    lonely.link_crud("read", "https://t.com/x")
    assert discover_crud_flows([lonely]) == []


def test_dependency_flows():
    consumer = _ep("https://t.com/api/deploy?project_id=abc123XYZ",
                   qparams=[("project_id", "abc123XYZ")])
    pool = [_hid("https://t.com/api/projects", "project_id",
                 "abc123XYZ")]
    flows = discover_dependency_flows([consumer], pool)
    assert len(flows) == 1
    assert flows[0].steps[1].consumes == ["project_id"]
    assert flows[0].steps[1].requires == [flows[0].steps[0].name]


def test_discover_all_dedupes_and_caps():
    eps = [_ep("https://t.com/api/p", method="POST"),
           _ep("https://t.com/api/p", method="GET")]
    out = discover_all(endpoints=eps, max_flows=1)
    assert len(out) == 1
    assert discover_all() == []


# ── replay ────────────────────────────────────────────────────────────
def _replay_http(bodies):
    class H:
        def __init__(self):
            self.calls = []

        def get(self, url, **kw):
            self.calls.append(("GET", url))
            return FakeResp(200, bodies.get("GET", '{"ok": true}'))

        def post(self, url, **kw):
            self.calls.append(("POST", url, dict(kw.get("data") or {})))
            return FakeResp(200, bodies.get("POST", '{"id": 9}'))

        def request(self, method, url, **kw):
            self.calls.append((method, url))
            return FakeResp(200, bodies.get(method, "{}"))

    return H()


def test_replay_order_and_param_binding():
    from apex_fuzzer.models import Parameter as P
    http = _replay_http({})
    s1 = FlowStep(name="create", endpoint="https://t.com/p",
                  normalized_url="https://t.com/p", method="POST",
                  parameters=[P(name="name", location="body",
                                source=["t"], sample_value="n")])
    s2 = FlowStep(name="read", endpoint="https://t.com/p/9",
                  normalized_url="https://t.com/p/9", method="GET")
    flow = Flow(name="f", steps=[s1, s2])
    res = replay_flow(http, flow, Identity(name="u"))
    assert res.completed is True
    assert [s.status for s in res.steps] == [200, 200]
    assert http.calls[0][2] == {"name": "n"}
    rt = res.to_dict()
    assert rt["flow"] == "f" and rt["completed"] is True


def test_replay_harvest_overrides_samples():
    http = _replay_http({})
    s = FlowStep(name="use", endpoint="https://t.com/x",
                 normalized_url="https://t.com/x", method="GET",
                 parameters=[])
    from apex_fuzzer.models import Parameter as P
    s.parameters = [P(name="pid", location="query", source=["t"],
                      sample_value="old")]
    flow = Flow(name="f", steps=[s])
    pool = [_hid("https://t.com/other", "pid", "fresh999")]
    replay_flow(http, flow, Identity(name="u"), harvest_pool=pool)
    assert "pid=fresh999" in http.calls[0][1]
    assert "pid=old" not in http.calls[0][1]


def test_replay_stops_on_non_200():
    class H:
        def get(self, url, **kw):
            return FakeResp(403, "denied")

    flow = Flow(name="f", steps=[
        FlowStep(name="a", endpoint="https://t.com/a",
                 normalized_url="https://t.com/a"),
        FlowStep(name="b", endpoint="https://t.com/b",
                 normalized_url="https://t.com/b")])
    res = replay_flow(H(), flow, Identity(name="u"))
    assert res.completed is False
    assert len(res.steps) == 1 and res.steps[0].status == 403


def test_replay_scope_and_budget_gates():
    class Scope:
        def is_in_scope(self, url):
            return "allowed" in url

    class Budgets:
        def consume_test(self, *a):
            return False

    flow = Flow(name="f", steps=[
        FlowStep(name="a", endpoint="https://t.com/nope",
                 normalized_url="https://t.com/nope")])
    res = replay_flow(_replay_http({}), flow, Identity(name="u"),
                      scope=Scope())
    assert res.completed is False and "scope" in res.steps[0].note
    res2 = replay_flow(_replay_http({}), flow, Identity(name="u"),
                       budgets=Budgets())
    assert "budget" in res2.steps[0].note


def test_replay_budget_exhaustion_propagates():

    class H:
        def get(self, url, **kw):
            raise BudgetExceeded("cap")

    flow = Flow(name="f", steps=[
        FlowStep(name="a", endpoint="https://t.com/a",
                 normalized_url="https://t.com/a")])
    try:
        replay_flow(H(), flow, Identity(name="u"))
        raise AssertionError("must propagate")
    except BudgetExceeded:
        pass


def test_replay_failure_contained():
    class H:
        def get(self, url, **kw):
            raise ConnectionError("down")

    flow = Flow(name="f", steps=[
        FlowStep(name="a", endpoint="https://t.com/a",
                 normalized_url="https://t.com/a")])
    res = replay_flow(H(), flow, Identity(name="u"))
    assert res.completed is False and "failed" in res.steps[0].note


# ── mutations ─────────────────────────────────────────────────────────
def _flow3():
    return Flow(name="crud", steps=[
        FlowStep(name="create", endpoint="https://t.com/p",
                 normalized_url="https://t.com/p", method="POST"),
        FlowStep(name="read", endpoint="https://t.com/p/1",
                 normalized_url="https://t.com/p/1", method="GET"),
        FlowStep(name="delete", endpoint="https://t.com/p/1",
                 normalized_url="https://t.com/p/1", method="DELETE")])


def test_mutation_kinds_present_and_capped():
    muts = mutate(_flow3())
    kinds = {m.kind for m in muts}
    assert {"skip_step", "reorder_steps", "repeat_step",
            "replay_stale", "drop_prerequisite",
            "invalid_transition"} <= kinds
    assert all(m.steps for m in muts)
    limited = mutate(_flow3(), kinds=["skip_step"], max_per_kind=1)
    assert len(limited) == 1 and limited[0].kind == "skip_step"
    assert mutate(_flow3(), kinds=["bogus"]) == []


def test_mutation_semantics():
    muts = {m.kind: m for m in mutate(_flow3())}
    # skip removes exactly one non-final step
    assert len(muts["skip_step"].steps) == 2
    # invalid transition jumps to the final step
    assert [s.name for s in muts["invalid_transition"].steps] == \
        ["delete"]
    # replay duplicates the whole flow
    assert len(muts["replay_stale"].steps) == 6
    # actor variants recorded when identities given
    actor = mutate(_flow3(), kinds=["change_identity"],
                   identities=["mallory"])
    assert actor and "mallory" in actor[0].detail
    assert mutate(Flow(name="empty")) == []
    single = Flow(name="s", steps=[
        FlowStep(name="only", endpoint="https://t.com/x",
                 normalized_url="https://t.com/x")])
    single_kinds = {m.kind for m in mutate(single)}
    assert "invalid_transition" not in single_kinds
    assert "drop_prerequisite" not in single_kinds
    catalog = mutation_catalog([_flow3()])
    assert isinstance(catalog["crud"], list) and catalog["crud"]


# ── orchestrator integration: pure analysis ───────────────────────────
def test_discover_workflows_end_to_end(tmp_path):
    import tempfile
    from pathlib import Path
    from types import SimpleNamespace
    from apex_fuzzer.orchestrator import Orchestrator
    from apex_fuzzer.config import Config
    from apex_fuzzer.profiles import get as get_profile
    from apex_fuzzer.reporting.metrics import Metrics
    from apex_fuzzer.checkpoints import Checkpoint
    out = Path(tempfile.mkdtemp())
    orch = Orchestrator(Config(), out, profile=get_profile("standard"))
    eps = [_ep("https://t.com/api/p", method="POST"),
           _ep("https://t.com/api/p", method="GET"),
           _ep("https://t.com/api/d?pid=zz99qq88",
               qparams=[("pid", "zz99qq88")])]
    app = SimpleNamespace(resources=[], workflows=[],
                          to_dict=lambda: {"workflows": []})
    m = Metrics()
    orch._discover_workflows(out, eps, app, None, m,
                             Checkpoint(out / "checkpoint.json"))
    payload = json.loads((out / "workflows.json").read_text())
    assert payload["flows"]  # REST lifecycle found
    assert m.workflows_discovered == len(payload["flows"])
    assert len(app.workflows) == len(payload["flows"])
    assert set(payload).issuperset({"flows", "mutations"})
