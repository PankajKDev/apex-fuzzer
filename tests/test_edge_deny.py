"""Edge/bot-wall guard: infrastructure answers are never verdicts.

Fake HTTP only. No network.
"""
from types import SimpleNamespace

from main.validation.differential import (
    DifferentialTester, looks_like_edge_deny)

EDGE_BODY = ("<HTML><HEAD><TITLE>Access Denied</TITLE></HEAD><BODY>"
             "<H1>Access Denied</H1> You don't have permission. "
             "Reference #18.76fd917. https://errors.edgesuite.net/abc</BODY>")
APP_DENY = '{"error": "forbidden for your role"}'
BOT_PAGE = ("<html><head><script src=\"/akam/13/pixel.js\">"
            "</script></head><body><div id=\"akamaighost\">"
            "checking browser</div></body></html>")


def _resp(status, text, headers=None):
    return SimpleNamespace(status_code=status, text=text,
                           headers=headers or {})


def test_edge_detector():
    assert looks_like_edge_deny(403, EDGE_BODY, {}) is True
    assert looks_like_edge_deny(
        403, "denied", {"Server": "AkamaiGHost"}) is True
    assert looks_like_edge_deny(403, APP_DENY, {}) is False
    assert looks_like_edge_deny(401, EDGE_BODY, {}) is False
    assert looks_like_edge_deny(200, BOT_PAGE, {}) is True
    assert looks_like_edge_deny(200, '{"id": 1}', {}) is False
    assert looks_like_edge_deny(403, "", {}) is False


def test_differential_all_edge_is_inconclusive():
    from main.config import Config

    class Http:
        def get(self, url, **kwargs):
            return _resp(403, EDGE_BODY)

    cfg = Config()
    tester = DifferentialTester.__new__(DifferentialTester)
    tester.cfg = cfg
    tester.http = Http()
    tester.contexts = [{"name": "anonymous", "headers": {}},
                       {"name": "user_a", "headers": {"Cookie": "s=a"}},
                       {"name": "user_b", "headers": {"Cookie": "s=b"}}]
    res = tester.probe("https://example.test/admin", "admin")
    assert res.verdict == "inconclusive"
    assert res.edge_denied is True
    assert "edge" in res.notes


def test_differential_edge_200s_are_not_bola():
    from main.config import Config

    class Http:
        def get(self, url, **kwargs):
            return _resp(200, BOT_PAGE)

    cfg = Config()
    tester = DifferentialTester.__new__(DifferentialTester)
    tester.cfg = cfg
    tester.http = Http()
    tester.contexts = [{"name": "user_a", "headers": {"Cookie": "s=a"}},
                       {"name": "user_b", "headers": {"Cookie": "s=b"}}]
    res = tester.probe("https://example.test/api/u", "api")
    assert res.verdict == "inconclusive"
    assert "edge" in res.notes


def test_differential_real_denial_still_negative_path():
    from main.validation.differential import DifferentialResult
    from main.validation.differential import ContextResult
    res = DifferentialResult(url="https://example.test/api/u",
                             endpoint_type="api")
    res.contexts = [ContextResult(name="anonymous", status=401),
                    ContextResult(name="user_a", status=200,
                                  body_hash="x", key_shape="s"),
                    ContextResult(name="user_b", status=403)]
    verdict, _ = DifferentialTester.evaluate(res)
    assert verdict == "inconclusive"
    assert res.edge_denied is False


def test_swap_tester_edge_voids_and_flags():
    from main.authorization.access_tests import swap_ids
    from main.authorization.harvest import HarvestedId

    class Http:
        def get(self, url, **kwargs):
            return _resp(403, EDGE_BODY)

    harvested = [HarvestedId(
        endpoint_url="https://example.test/api/u/1",
        normalized_url="https://example.test/api/u/1",
        param="id", value="1", owner="owner",
        shape='{"id": "s"}', body_hash="h",
        markers={"owner_id": "o1"})]
    tester = SimpleNamespace(name="tester", tenant="",
                             auth_headers={"Cookie": "s=t"})
    out = swap_ids(Http(), harvested, tester)
    assert out and out[0].edge_denied is True
    assert out[0].verdict != "strong_candidate"


def test_swap_edge_200_match_voided():
    from main.authorization.access_tests import swap_ids
    from main.authorization.harvest import HarvestedId
    from main.validation.differential import normalize_response

    baseline = normalize_response(_resp(200, BOT_PAGE))

    class Http:
        def get(self, url, **kwargs):
            return _resp(200, BOT_PAGE)

    harvested = [HarvestedId(
        endpoint_url="https://example.test/api/u/1",
        normalized_url="https://example.test/api/u/1",
        param="id", value="1", owner="owner",
        shape=baseline["key_shape"], body_hash=baseline["body_hash"],
        markers={})]
    tester = SimpleNamespace(name="tester", tenant="",
                             auth_headers={"Cookie": "s=t"})
    out = swap_ids(Http(), harvested, tester)
    assert out and out[0].match is False
    assert out[0].edge_denied is True


def test_write_replay_marks_edge():
    from main.authorization import write_replay as wr_mod

    class Http:
        def get(self, url, **kwargs):
            return _resp(200, '{"id":"v","name":"n"}')

        def request(self, method, url, **kwargs):
            return _resp(403, EDGE_BODY)

    endpoint = SimpleNamespace(
        url="https://example.test/submit",
        observed_requests=[{
            "identity": "attacker", "method": "POST",
            "url": "https://example.test/submit",
            "headers": {"Content-Type":
                        "application/x-www-form-urlencoded"},
            "post_data": "id=own&name=Bob", "content_type":
            "application/x-www-form-urlencoded"}])
    victim = SimpleNamespace(param="id", value="v", owner="owner",
                             owner_tenant="", source="response")
    tester = SimpleNamespace(name="attacker", tenant="",
                             auth_headers={"Cookie": "s=t"})
    out = wr_mod.replay_writes(Http(), endpoint, [victim], tester,
                               {"owner": {}})
    assert out and out[0].edge_denied is True
    assert out[0].verdict == "inconclusive"


def test_graphql_replay_voids_edge_match():
    from main.authorization import graphql_replay as gql_mod
    import json

    body = json.dumps({"query": "query GetUser($id: ID!) { user { id } }",
                       "variables": {"id": "a"}})

    class Http:
        def request(self, method, url, **kwargs):
            return _resp(200, BOT_PAGE)

    endpoint = SimpleNamespace(
        url="https://example.test/graphql",
        normalized_url="https://example.test/graphql",
        observed_requests=[{
            "identity": "attacker", "method": "POST",
            "url": "https://example.test/graphql",
            "headers": {"Content-Type": "application/json"},
            "post_data": body, "content_type": "application/json"}])
    victim = SimpleNamespace(param="id", value="v", owner="owner",
                             owner_tenant="", source="response")
    tester = SimpleNamespace(name="attacker", tenant="",
                             auth_headers={"Cookie": "s=t"})
    out = gql_mod.replay_operations(
        Http(), endpoint, [victim], tester, {"owner": {}})
    assert out and out[0].match is False
    assert out[0].edge_denied is True


def test_user_agent_default_and_override_and_validation():
    from main.config import Config
    from main.orchestrator import _HTTPClient

    assert "ApexFuzzer" in _HTTPClient().session.headers["User-Agent"]
    custom = _HTTPClient(user_agent="Mozilla/5.0 Test")
    assert custom.session.headers["User-Agent"] == "Mozilla/5.0 Test"
    cfg = Config()
    cfg.scan.user_agent = "bad\r\nX: 1"
    assert any("user_agent" in e for e in cfg.validate()["errors"])
    cfg.scan.user_agent = "x" * 201
    assert any("user_agent" in e for e in cfg.validate()["errors"])


def test_orchestrator_records_edge_inconclusive_not_negative(tmp_path):
    from main.config import Config, ScopeConfig
    from main.models import Endpoint
    from main.orchestrator import Orchestrator
    from main.profiles import get as get_profile
    from main.reporting.metrics import Metrics
    from main.reporting.coverage import CoverageTracker
    from main.scope import Scope
    from main.validation.differential import DifferentialTester

    cfg = Config()
    cfg.scope.allowed_domains = ["example.test"]
    orch = Orchestrator(cfg, tmp_path, profile=get_profile("standard"))
    orch.scope = Scope(ScopeConfig(allowed_domains=["example.test"]))

    class Http:
        def get(self, url, **kwargs):
            return _resp(403, EDGE_BODY)

    ep = Endpoint(url="https://example.test/admin", normalized_url="x",
                  method="GET", host="example.test", path="/admin",
                  endpoint_type="admin")
    diff = DifferentialTester.__new__(DifferentialTester)
    diff.cfg = cfg
    diff.http = Http()
    diff.contexts = [{"name": "anonymous", "headers": {}},
                     {"name": "user_a", "headers": {"Cookie": "s=a"}}]
    from main.validation.evidence import EvidenceStore
    from main.budgets import BudgetTracker
    coverage = CoverageTracker()
    found = orch._differential_probe(
        [ep], diff, EvidenceStore(tmp_path / "proofs"), Metrics(),
        BudgetTracker(cfg), coverage)
    assert found == []
    assert coverage.summary().get("authz") == "inconclusive"
