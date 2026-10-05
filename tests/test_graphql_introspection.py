"""Tests: GraphQL introspection exposure probe (no network)."""
from apex_fuzzer.validation import graphql_introspection as gql


class _Resp:
    def __init__(self, status, text):
        self.status_code = status
        self.text = text


class FakeClient:
    def __init__(self, resp=None, exc=None):
        self.resp = resp
        self.exc = exc
        self.calls = []

    def get(self, url, params=None, timeout=10):
        self.calls.append(("GET", url, params))
        if self.exc is not None:
            raise self.exc
        return self.resp

    def request(self, method, url, json=None, timeout=10):
        self.calls.append((method, url, json))
        if self.exc is not None:
            raise self.exc
        return self.resp


_SCHEMA = ('{"data":{"__schema":{"queryType":{"name":"Query"},'
           '"mutationType":null,"types":[{"name":"Query"},'
           '{"name":"User"},{"name":"String"}]}}}')


def test_exposed_schema_discloses_types():
    res = gql.probe_introspection(
        FakeClient(_Resp(200, _SCHEMA)),
        "https://example.com/graphql", "POST")
    assert res.exposed is True
    assert res.types == ["Query", "User", "String"]
    assert "3 type(s)" in res.notes
    assert res.method == "POST"


def test_post_sends_json_body():
    client = FakeClient(_Resp(200, _SCHEMA))
    gql.probe_introspection(client, "https://example.com/graphql",
                            "POST")
    method, _, body = client.calls[0]
    assert method == "POST"
    assert "__schema" in body["query"]


def test_get_sends_query_param():
    client = FakeClient(_Resp(200, _SCHEMA))
    gql.probe_introspection(client, "https://example.com/graphql",
                            "GET")
    method, _, params = client.calls[0]
    assert method == "GET"
    assert "__schema" in params["query"]


def test_disabled_introspection_is_negative():
    res = gql.probe_introspection(
        FakeClient(_Resp(200, '{"data":{}}')),
        "https://example.com/graphql", "POST")
    assert res.exposed is False
    assert "disabled" in res.notes
    err = gql.probe_introspection(
        FakeClient(_Resp(200, '{"errors":[{"message":'
                              '"introspection disabled"}]}')),
        "https://example.com/graphql", "POST")
    assert err.exposed is False


def test_non_graphql_answer_is_inconclusive():
    res = gql.probe_introspection(
        FakeClient(_Resp(200, "<html>login</html>")),
        "https://example.com/graphql", "POST")
    assert res.exposed is None
    denied = gql.probe_introspection(
        FakeClient(_Resp(403, "blocked")),
        "https://example.com/graphql", "POST")
    assert denied.exposed is None


def test_transport_error_is_inconclusive():
    res = gql.probe_introspection(
        FakeClient(exc=RuntimeError("timeout")),
        "https://example.com/graphql", "POST")
    assert res.exposed is None


def test_budget_exceeded_propagates():
    from apex_fuzzer.budgets import BudgetExceeded
    import pytest
    with pytest.raises(BudgetExceeded):
        gql.probe_introspection(
            FakeClient(exc=BudgetExceeded("cap")),
            "https://example.com/graphql", "POST")


def test_plan_cost():
    from apex_fuzzer.safety.preflight import plan_graphql_introspection
    assert plan_graphql_introspection(4).total == 4


def test_type_cap():
    many = ('{"data":{"__schema":{"types":[' +
            ",".join(f'{{"name":"T{i}"}}' for i in range(300)) +
            "]}}}")
    res = gql.probe_introspection(
        FakeClient(_Resp(200, many)),
        "https://example.com/graphql", "POST")
    assert res.exposed is True
    assert len(res.types) == gql._MAX_TYPES
