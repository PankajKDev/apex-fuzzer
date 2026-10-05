"""GraphQL variables + operation-aware BOLA replay.

No network. Fake HTTP clients only.
"""
import json
from types import SimpleNamespace

from main.authorization import graphql_replay as gql_mod
from main.config import Config, ScopeConfig
from main.models import Endpoint, Finding, Parameter
from main.plugins.adapters import _candidate_from
from main.plugins.base import TestTarget
from main.scope import Scope
from main.validation import graphql as gql_val
from main.validation import mutate as mut_mod
from main.validation.base import Candidate

QUERY = ("query GetUser($id: ID!) { user(id: $id) "
         "{ id name email } }")
MUTATION = ("mutation UpdateUser($id: ID!, $name: String) { "
            "updateUser(id: $id, name: $name) { id } }")
SNEAKY = 'query GetMutationHistory { logs(filter: "mutation") { id } }'


def _body(vars=None, query=QUERY, op="GetUser"):
    doc = {"query": query, "variables": vars or {"id": "u-1"}}
    if op is not None:
        doc["operationName"] = op
    return json.dumps(doc)


def _scope():
    return Scope(ScopeConfig(allowed_domains=["example.test"]))


def test_mutation_guard_with_strings_and_names():
    assert gql_val.is_mutation_operation(MUTATION) is True
    assert gql_val.is_mutation_operation(QUERY) is False
    assert gql_val.is_mutation_operation(SNEAKY) is False
    assert gql_val.operation_kind(MUTATION) == "mutation"
    assert gql_val.operation_kind(QUERY) == "query"
    assert gql_val.parse_graphql_body("not json") is None
    assert gql_val.parse_graphql_body('{"nope": 1}') is None


def test_variable_paths_and_normalization():
    body = _body({"user": {"id": "u-1", "tags": ["a"]}, "n": 3})
    parsed = gql_val.parse_graphql_body(body)
    assert parsed is not None
    assert gql_val.normalize_parameter(body, "id") == "variables.user.id"
    assert gql_val.normalize_parameter(
        body, "variables.user.id") == "variables.user.id"
    assert gql_val.normalize_parameter(body, "missing") is None
    assert gql_val.variable_leaf("variables.user.id") == "id"


def test_set_variable_preserves_operation():
    rebuilt, changed = gql_val.set_variable(
        _body({"id": "u-1"}), "variables.id", "u-2")
    assert changed is True
    data = json.loads(rebuilt)
    assert data["query"] == QUERY
    assert data["operationName"] == "GetUser"
    assert data["variables"] == {"id": "u-2"}
    try:
        gql_val.set_variable(_body({"id": "u-1"}), "variables.nope", "x")
    except ValueError:
        pass
    else:
        raise AssertionError("missing path must fail closed")


def test_candidate_normalizes_bare_graphql_variable():
    ep = Endpoint(url="https://example.test/graphql",
                  normalized_url="https://example.test/graphql",
                  method="POST", endpoint_type="graphql",
                  request_content_types=["application/json"])
    finding = Finding(id="g1", source="nuclei", method="POST",
                      parameter="id",
                      endpoint_url="https://example.test/graphql",
                      matched_at="https://example.test/graphql",
                      request_body=_body({"id": "u-1"}),
                      request_headers={"Content-Type": "application/json"})
    target = TestTarget(finding.endpoint_url, parameter="id", method="POST",
                        finding=finding, endpoint=ep, test_class="sqli")
    candidate = _candidate_from(target, "sqli")
    assert candidate.parameter == "variables.id"
    assert candidate.parameter_location == "body"


def test_graphql_variable_prescreen_is_candidate():
    seen = {}

    class Http:
        def request(self, method, url, **kwargs):
            seen["body"] = kwargs["json"]
            data = kwargs["json"]
            marker = data["variables"]["id"]
            if ("'1'='1" in marker or '"1"="1' in marker
                    or "1=1" in marker) and "'1'='2" not in marker \
                    and '"1"="2' not in marker and "1=2" not in marker:
                return SimpleNamespace(status_code=200,
                                       text='{"data":{"user":{"id":1}}}')
            return SimpleNamespace(status_code=200,
                                   text='{"data":{"user":null}}')

    cfg = Config()
    cfg.safety.allow_state_change = True
    candidate = Candidate(
        finding=Finding(id="g2", source="test"), test_class="sqli",
        endpoint_url="https://example.test/graphql", parameter="variables.id",
        method="POST", parameter_location="body",
        request_content_type="application/json",
        request_body=_body({"id": "u-1"}))
    outcome = mut_mod.MutationEngine(cfg, Http()).prescreen_sqli(candidate)
    assert outcome is not None
    assert outcome.status == "strong_candidate"
    assert seen["body"]["query"] == QUERY  # operation preserved


def test_graphql_needs_retained_operation_without_body():
    cfg = Config()
    cfg.safety.allow_state_change = True
    candidate = Candidate(
        finding=Finding(id="g3", source="test"), test_class="sqli",
        endpoint_url="https://example.test/graphql",
        parameter="variables.id", method="POST",
        parameter_location="body",
        request_content_type="application/json",
        body_parameters=[Parameter(name="variables.id", location="body",
                                   sample_value="u-1")])
    outcome = mut_mod.MutationEngine(cfg, FakeNoNet()).prescreen_sqli(
        candidate)
    assert outcome is not None
    assert outcome.status == "inconclusive"
    assert "retained operation" in outcome.notes


class FakeNoNet:
    def request(self, *args, **kwargs):
        raise AssertionError("must not send without operation text")

    def get(self, *args, **kwargs):
        raise AssertionError("must not send without operation text")


def _endpoint(shapes):
    ep = Endpoint(url="https://example.test/graphql",
                  normalized_url="https://example.test/graphql",
                  method="POST", host="example.test", path="/graphql",
                  endpoint_type="graphql")
    ep.observed_requests = shapes
    return ep


def _shape(identity, variables, query=QUERY, op="GetUser"):
    return {"identity": identity, "method": "POST",
            "url": "https://example.test/graphql",
            "headers": {"Content-Type": "application/json"},
            "post_data": _body(variables, query, op),
            "content_type": "application/json"}


def _victim():
    return SimpleNamespace(param="id", value="u-victim", owner="owner",
                           owner_tenant="acme", source="response")


def _tester():
    return SimpleNamespace(name="attacker", tenant="acme",
                           auth_headers={"Authorization": "Bearer ATTACKER"})


class _BolaHttp:
    """Owner baseline without attacker marker; tester sees victim object."""

    def __init__(self, mutate_check="ATTACKER-NAME"):
        self.calls = []
        self.marker = mutate_check

    def request(self, method, url, **kwargs):
        self.calls.append((method, kwargs["headers"].get("Authorization")))
        data = json.loads(kwargs["data"])
        if data["variables"].get("name") == self.marker:
            return SimpleNamespace(
                status_code=200,
                text='{"data":{"user":{"id":"u-victim","owner_id":"o1",'
                     '"name":"ATTACKER-NAME"}}}')
        return SimpleNamespace(
            status_code=200,
            text='{"data":{"user":{"id":"u-victim","owner_id":"o1",'
                 '"name":"Victim Name"}}}')


def test_operation_replay_confirms_cross_user_read():
    http = _BolaHttp()
    ep = _endpoint([_shape("attacker", {"id": "u-a", "name": "Bob"})])
    out = gql_mod.replay_operations(
        http, ep, [_victim()], _tester(),
        {"owner": {"Authorization": "Bearer OWNER"}}, scope=_scope(),
        ownership_fields=["owner_id"])
    assert len(out) == 1
    res = out[0]
    assert res.verdict == "strong_candidate", res.notes
    assert res.variable == "variables.id"
    assert "owner_id" in res.markers_matched
    # same operation for baseline and replay; only the variable moved
    assert len(http.calls) == 2


def test_mutation_operations_are_never_replayed():
    class Http:
        def request(self, *args, **kwargs):
            raise AssertionError("mutations must never replay")

    ep = _endpoint([_shape("attacker", {"id": "u-a", "name": "Bob"},
                           query=MUTATION, op="UpdateUser")])
    out = gql_mod.replay_operations(
        Http(), ep, [_victim()], _tester(),
        {"owner": {"Authorization": "Bearer OWNER"}}, scope=_scope())
    assert out == []


def test_denied_operation_is_not_a_finding():
    class Http:
        def request(self, method, url, **kwargs):
            return SimpleNamespace(status_code=403, text="denied")

    ep = _endpoint([_shape("attacker", {"id": "u-a"})])
    out = gql_mod.replay_operations(
        Http(), ep, [_victim()], _tester(),
        {"owner": {"Authorization": "Bearer OWNER"}}, scope=_scope())
    assert out == [] or all(r.verdict != "strong_candidate" for r in out)


def test_ambiguous_shapes_fail_closed():
    class Http:
        def request(self, *args, **kwargs):
            raise AssertionError("ambiguous must not send")

    ep = _endpoint([_shape("attacker", {"id": "u-a"}),
                    _shape("attacker", {"id": "u-b"})])
    out = gql_mod.replay_operations(
        Http(), ep, [_victim()], _tester(),
        {"owner": {"Authorization": "Bearer OWNER"}}, scope=_scope())
    assert out == []


def test_budget_exhaustion_propagates():
    from main.budgets import BudgetExceeded

    class Http:
        def request(self, *args, **kwargs):
            raise BudgetExceeded("budget exhausted")

    ep = _endpoint([_shape("attacker", {"id": "u-a"})])
    try:
        gql_mod.replay_operations(
            Http(), ep, [_victim()], _tester(),
            {"owner": {"Authorization": "Bearer OWNER"}}, scope=_scope())
    except BudgetExceeded:
        return
    raise AssertionError("BudgetExceeded must propagate")


def test_plan_accounts_graphql_replays():
    from main.safety.preflight import plan_authz_matrix
    base = plan_authz_matrix(2, 3, 5, 3)
    assert base.total == 6 + 24 + 30
    extended = plan_authz_matrix(2, 3, 5, 3, 0, 4)
    assert extended.total == base.total + 8
