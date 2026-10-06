"""GraphQL schema-driven field replay: advertised reads, victim IDs.

No network. Fake HTTP clients only. Mutations are never generated,
so none can replay; depth and batching probes stay out of scope.
"""
import json
from types import SimpleNamespace

from main.authorization import graphql_replay as gql_mod
from main.budgets import BudgetExceeded
from main.config import Config, ScopeConfig
from main.models import Endpoint
from main.reporting.coverage import CoverageTracker
from main.reporting.metrics import Metrics
from main.scope import Scope
from main.validation import graphql_schema as schema_mod
from main.validation.evidence import EvidenceStore


def _schema():
    def obj(name, fields):
        return {"kind": "OBJECT", "name": name, "fields": fields}

    def fld(name, args, ret):
        return {"name": name,
                "args": [{"name": a, "type": {"kind": "SCALAR",
                                              "name": "ID"}}
                         for a in args],
                "type": {"kind": "OBJECT", "name": ret}}

    return {"data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "types": [
                obj("Query", [
                    fld("user", ["id"], "User"),
                    fld("order", ["order_id"], "Order"),
                    {"name": "version", "args": [],
                     "type": {"kind": "SCALAR", "name": "String"}},
                    fld("search", ["q"], "User"),
                ]),
                obj("User", [
                    {"name": "id",
                     "type": {"kind": "SCALAR", "name": "ID"}},
                    {"name": "email",
                     "type": {"kind": "SCALAR", "name": "String"}},
                ]),
                obj("Order", [
                    {"name": "id",
                     "type": {"kind": "SCALAR", "name": "ID"}},
                ]),
                {"kind": "SCALAR", "name": "String", "fields": None},
            ]}}}


def _scope():
    return Scope(ScopeConfig(allowed_domains=["example.test"]))


def _endpoint():
    return Endpoint(url="https://example.test/graphql",
                    normalized_url="https://example.test/graphql",
                    method="POST", host="example.test", path="/graphql",
                    endpoint_type="graphql")


def test_parse_and_select_id_fields():
    parsed = schema_mod.parse_schema(json.dumps(_schema()))
    assert parsed["query_type"] == "Query"
    fields = schema_mod.select_id_fields(parsed)
    assert [(f.field, f.arg) for f in fields] == [
        ("user", "id"), ("order", "order_id")]
    user = fields[0]
    assert user.ret == "User"
    assert "__typename" not in user.subfields
    assert set(user.subfields) == {"id", "email"}


def test_scalar_and_unmatched_fields_skipped():
    parsed = schema_mod.parse_schema(json.dumps(_schema()))
    names = [f.field for f in schema_mod.select_id_fields(parsed)]
    assert "version" not in names  # no identifier arg
    assert "search" not in names  # q is not identifier-like
    assert schema_mod.select_id_fields(None) == []
    assert schema_mod.parse_schema("not json") is None
    assert schema_mod.parse_schema(json.dumps({"data": {}})) is None


def test_field_query_escapes_values():
    field = schema_mod.SchemaField(field="user", arg="id", ret="User",
                                   subfields=["id"])
    doc, label = schema_mod.build_field_query(field, 'u"x')
    assert label == "user(id)"
    assert json.dumps('u"x') in doc
    assert '"u\\"x"' in doc


def test_fetch_schema_paths():
    class Http:
        def __init__(self):
            self.calls = []

        def request(self, method, url, **kwargs):
            self.calls.append((method, kwargs.get("json")))
            return SimpleNamespace(status_code=200,
                                   text=json.dumps(_schema()),
                                   headers={})

        def get(self, url, **kwargs):
            self.calls.append(("GET", kwargs.get("params")))
            return SimpleNamespace(status_code=200,
                                   text=json.dumps(_schema()),
                                   headers={})

    http = Http()
    parsed = schema_mod.fetch_schema(
        http, "https://example.test/graphql", "POST")
    assert parsed["query_type"] == "Query"
    assert http.calls[0][0] == "POST"
    parsed = schema_mod.fetch_schema(
        http, "https://example.test/graphql", "GET")
    assert parsed["query_type"] == "Query"

    class Denied:
        def request(self, *a, **k):
            return SimpleNamespace(status_code=401, text="no",
                                   headers={})

    assert schema_mod.fetch_schema(
        Denied(), "https://example.test/graphql", "POST") is None


def test_budget_propagates_from_fetch():
    class Http:
        def request(self, *a, **k):
            raise BudgetExceeded("spent")

    try:
        schema_mod.fetch_schema(
            Http(), "https://example.test/graphql", "POST")
    except BudgetExceeded:
        return
    raise AssertionError("BudgetExceeded must propagate")


def _victim():
    return SimpleNamespace(param="id", value="u-victim", owner="owner",
                           owner_tenant="acme", source="response")


def _tester():
    return SimpleNamespace(name="attacker", tenant="acme",
                           auth_headers={"Authorization": "Bearer X"})


class _FieldHttp:
    """Owner baseline carries markers; tester sees the victim object."""

    def __init__(self, deny=False):
        self.calls = []
        self.deny = deny

    def request(self, method, url, **kwargs):
        auth = kwargs["headers"].get("Authorization")
        self.calls.append(auth)
        if self.deny:
            return SimpleNamespace(status_code=403, text="denied",
                                   headers={})
        if auth == "Bearer OWNER":
            return SimpleNamespace(
                status_code=200,
                text='{"data":{"user":{"__typename":"User",'
                     '"id":"u-victim","owner_id":"o1"}}}', headers={})
        return SimpleNamespace(
            status_code=200,
            text='{"data":{"user":{"__typename":"User",'
                 '"id":"u-victim","owner_id":"o1"}}}', headers={})


def _fields():
    parsed = schema_mod.parse_schema(json.dumps(_schema()))
    return schema_mod.select_id_fields(parsed)


def test_schema_field_replay_confirms():
    http = _FieldHttp()
    out = gql_mod.replay_schema_fields(
        http, _endpoint(), _fields(), [_victim()], _tester(),
        {"owner": {"Authorization": "Bearer OWNER"}}, scope=_scope(),
        ownership_fields=["owner_id"])
    assert len(out) == 1
    res = out[0]
    assert res.verdict == "strong_candidate", res.notes
    assert res.variable == "user(id)"
    assert "owner_id" in res.markers_matched
    assert len(http.calls) == 2  # owner baseline + tester replay


def test_denied_schema_field_is_negative():
    http = _FieldHttp(deny=True)
    out = gql_mod.replay_schema_fields(
        http, _endpoint(), _fields(), [_victim()], _tester(),
        {"owner": {"Authorization": "Bearer OWNER"}}, scope=_scope())
    assert out == [] or all(r.verdict != "strong_candidate" for r in out)


def test_unmatched_pool_param_sends_nothing():
    class Http:
        def request(self, *a, **k):
            raise AssertionError("no matching arg, must not send")

    victim = SimpleNamespace(param="unrelated", value="x", owner="o",
                             owner_tenant="", source="response")
    out = gql_mod.replay_schema_fields(
        Http(), _endpoint(), _fields(), [victim], _tester(),
        {"o": {}}, scope=_scope())
    assert out == []


def test_stage_emits_schema_bola_finding(tmp_path):
    from main.stages.validation import ProbeControls
    from main.stages.validation.authz_graphql import (
        graphql_schema_probe)

    class Http:
        def get(self, url, **kwargs):
            raise AssertionError("schema fetch uses POST")

        def request(self, method, url, **kwargs):
            if kwargs.get("json", {}).get("query", "").startswith(
                    "{__schema"):
                return SimpleNamespace(
                    status_code=200, text=json.dumps(_schema()),
                    headers={})
            body = '{"data":{"user":{"__typename":"User",' \
                   '"id":"u-victim","owner_id":"o1"}}}'
            return SimpleNamespace(status_code=200, text=body,
                                   headers={})

    cfg = Config()
    coverage = CoverageTracker()
    owner = SimpleNamespace(name="owner", tenant="acme",
                            auth_headers={"Authorization": "Bearer O"})
    out = graphql_schema_probe(
        [_endpoint()], [_victim()], [owner, _tester()],
        {"owner": {"Authorization": "Bearer O"}},
        EvidenceStore(tmp_path / "p"), Metrics(), coverage, Http(),
        None, cfg, _scope(), ProbeControls())
    assert len(out) == 1
    finding = out[0]
    assert finding.source == "graphql-bola"
    assert "graphql-schema" in finding.tags
    assert finding.validation_status == "strong_candidate"
    assert coverage.summary()["graphql"] == "candidate"


def test_reviews_mapping_unchanged():
    from main.models import Finding
    from main.reporting.reviews import finding_test_class
    assert finding_test_class(
        Finding(id="a", source="graphql-bola",
                tags=["bola", "graphql"])) == "bola"


def test_plan_accounts_schema_requests():
    from main.safety.preflight import plan_authz_matrix
    base = plan_authz_matrix(2, 3, 5, 3)
    assert base.total == 6 + 24 + 30
    extended = plan_authz_matrix(2, 3, 5, 3, schema_requests=7)
    assert extended.total == base.total + 7
