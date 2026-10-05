"""Header/cookie parameter probes: injection without touching identity.

No network. Fake HTTP clients and fake sqlmap runners only.
"""
from types import SimpleNamespace

from main.config import Config, ScopeConfig
from main.models import Endpoint, Finding, Parameter
from main.plugins.adapters import _candidate_from
from main.plugins.base import TestTarget, TestContext
from main.scope import Scope
from main.validation import mutate as mut_mod
from main.validation import observed_sqli as obs_mod
from main.validation import sqli as sqli_mod
from main.validation.base import Candidate
from main.validation.request_shape import (
    cookie_with_parameter, is_protected_parameter)


def _scope():
    return Scope(ScopeConfig(allowed_domains=["example.test"]))


def _finding(parameter="X-Custom-Id", headers=None):
    return Finding(id="hc1", source="nuclei", method="GET",
                   parameter=parameter,
                   endpoint_url="https://example.test/api/who",
                   matched_at="https://example.test/api/who",
                   request_headers=headers or {})


def test_protected_names_are_never_mutated():
    assert is_protected_parameter("header", "Authorization")
    assert is_protected_parameter("header", "Cookie")
    assert is_protected_parameter("header", "Host")
    assert is_protected_parameter("cookie", "sessionid")
    assert is_protected_parameter("cookie", "csrf_token")
    assert not is_protected_parameter("header", "X-Custom-Id")
    assert not is_protected_parameter("header", "Referer")
    assert not is_protected_parameter("cookie", "theme")
    assert not is_protected_parameter("query", "sessionid")


def test_cookie_rebuild_preserves_session_pair():
    headers = {"Cookie": "session=AAA-SECRET; theme=dark",
               "X-Trace": "t"}
    rebuilt = cookie_with_parameter(headers, "theme", "light")
    assert "session=AAA-SECRET" in rebuilt
    assert "theme=light" in rebuilt
    assert "X-Trace" not in rebuilt  # only the Cookie value is rebuilt


def test_sqli_header_boolean_difference_is_candidate():
    seen = []

    class Http:
        def get(self, url, **kwargs):
            seen.append(dict(kwargs.get("headers") or {}))
            marker = (kwargs.get("headers") or {}).get("X-Custom-Id", "")
            if 'AND "1"="1' in marker or "AND 1=1" in marker:
                return SimpleNamespace(status_code=200,
                                       text='{"rows":[1,2]}')
            return SimpleNamespace(status_code=200, text='{"rows":[]}')

    candidate = Candidate(
        finding=_finding(), test_class="sqli",
        endpoint_url="https://example.test/api/who", parameter="X-Custom-Id",
        parameter_location="header",
        request_headers={"X-Custom-Id": "7"})
    outcome = mut_mod.MutationEngine(Config(), Http()).prescreen_sqli(
        candidate)
    assert outcome is not None
    assert outcome.status == "strong_candidate"
    assert seen  # requests carried the injected header


def test_sqli_cookie_pair_is_candidate_and_session_survives():
    sent = []

    class Http:
        def get(self, url, **kwargs):
            sent.append(dict(kwargs.get("headers") or {}))
            cookie = (kwargs.get("headers") or {}).get("Cookie", "")
            if "AND 1=1" in cookie or "AND '1'='1" in cookie or \
                    'AND "1"="1' in cookie:
                return SimpleNamespace(status_code=200,
                                       text='{"rows":[1,2]}')
            return SimpleNamespace(status_code=200, text='{"rows":[]}')

    candidate = Candidate(
        finding=_finding(
            parameter="prefs",
            headers={"Cookie": "session=AAA-SECRET; prefs=dark"}),
        test_class="sqli", endpoint_url="https://example.test/api/who",
        parameter="prefs", parameter_location="cookie",
        request_headers={"Cookie": "session=AAA-SECRET; prefs=dark"})
    outcome = mut_mod.MutationEngine(Config(), Http()).prescreen_sqli(
        candidate)
    assert outcome is not None
    assert outcome.status == "strong_candidate"
    for headers in sent:
        assert "session=AAA-SECRET" in headers.get("Cookie", "")


def test_authorization_header_and_session_cookie_refuse_without_send():
    class Http:
        def get(self, *args, **kwargs):
            raise AssertionError("protected target must not send")

        def request(self, *args, **kwargs):
            raise AssertionError("protected target must not send")

    auth = Candidate(
        finding=_finding(parameter="Authorization"),
        test_class="sqli", endpoint_url="https://example.test/api/who",
        parameter="Authorization", parameter_location="header",
        request_headers={"Authorization": "Bearer XYZ"})
    out = mut_mod.MutationEngine(Config(), Http()).prescreen_sqli(auth)
    assert out is not None and out.status == "inconclusive"
    assert "never mutated" in out.notes

    sess = Candidate(
        finding=_finding(parameter="session",
                         headers={"Cookie": "session=AAA; prefs=dark"}),
        test_class="xss", endpoint_url="https://example.test/api/who",
        parameter="session", parameter_location="cookie",
        request_headers={"Cookie": "session=AAA; prefs=dark"})
    out = mut_mod.MutationEngine(Config(), Http()).prescreen_xss(sess)
    assert out is not None and out.status == "inconclusive"


def test_xss_cookie_reflection_is_candidate():
    class Http:
        def get(self, url, **kwargs):
            cookie = (kwargs.get("headers") or {}).get("Cookie", "")
            return SimpleNamespace(status_code=200,
                                   text=f"<div>prefs={cookie}</div>")

    candidate = Candidate(
        finding=_finding(parameter="prefs",
                         headers={"Cookie": "prefs=dark"}),
        test_class="xss", endpoint_url="https://example.test/api/who",
        parameter="prefs", parameter_location="cookie",
        request_headers={"Cookie": "prefs=dark"})
    outcome = mut_mod.MutationEngine(Config(), Http()).prescreen_xss(
        candidate)
    assert outcome is not None
    assert outcome.status == "strong_candidate"
    assert outcome.evidence["parameter_location"] == "cookie"


def test_non_get_header_probe_needs_state_ack():
    class Http:
        def request(self, *args, **kwargs):
            raise AssertionError("must not send without ack")

    candidate = Candidate(
        finding=_finding(), test_class="sqli",
        endpoint_url="https://example.test/api/who", parameter="X-Custom-Id",
        method="POST", parameter_location="header",
        request_headers={"X-Custom-Id": "7"})
    out = mut_mod.MutationEngine(Config(), Http()).prescreen_sqli(candidate)
    assert out is not None and out.status == "inconclusive"
    assert "allow_state_change" in out.notes


def test_candidate_derives_header_and_cookie_locations():
    ep = Endpoint(url="https://example.test/api/who",
                  normalized_url="https://example.test/api/who",
                  method="GET",
                  header_parameters=[Parameter(name="X-Custom-Id",
                                               location="header")])
    target = TestTarget("https://example.test/api/who",
                        parameter="X-Custom-Id", method="GET",
                        finding=_finding(), endpoint=ep, test_class="sqli")
    assert _candidate_from(target, "sqli").parameter_location == "header"
    ep2 = Endpoint(url="https://example.test/api/who",
                   normalized_url="https://example.test/api/who",
                   method="GET")
    target2 = TestTarget(
        "https://example.test/api/who", parameter="prefs", method="GET",
        finding=_finding(parameter="prefs",
                         headers={"Cookie": "session=AAA; prefs=dark"}),
        endpoint=ep2, test_class="xss")
    assert _candidate_from(target2, "xss").parameter_location == "cookie"


def test_observed_pins_header_and_cookie_shapes():
    ep = Endpoint(url="https://example.test/api/who",
                  normalized_url="https://example.test/api/who",
                  method="GET",
                  header_parameters=[Parameter(name="X-Custom-Id",
                                               location="header")])
    ep.observed_requests = [{
        "identity": "alice", "method": "GET",
        "url": "https://example.test/api/who",
        "headers": {"X-Custom-Id": "7"}, "post_data": None,
        "content_type": ""}]
    target = TestTarget("https://example.test/api/who",
                        parameter="X-Custom-Id", method="GET",
                        finding=_finding(), endpoint=ep, test_class="sqli")
    candidate = _candidate_from(target, "sqli", scope=_scope())
    assert candidate.observed_identity == "alice"
    assert candidate.request_headers["X-Custom-Id"] == "7"

    ep2 = Endpoint(url="https://example.test/api/who",
                   normalized_url="https://example.test/api/who",
                   method="GET")
    ep2.observed_requests = [{
        "identity": "alice", "method": "GET",
        "url": "https://example.test/api/who",
        "headers": {"Cookie": "session=AAA; prefs=dark"},
        "post_data": None, "content_type": ""}]
    target2 = TestTarget(
        "https://example.test/api/who", parameter="prefs", method="GET",
        finding=_finding(parameter="prefs",
                         headers={"Cookie": "session=AAA; prefs=dark"}),
        endpoint=ep2, test_class="xss")
    candidate2 = _candidate_from(target2, "xss", scope=_scope())
    assert candidate2.observed_identity == "alice"


def test_ambiguous_header_shapes_fail_closed():
    shapes = [
        {"identity": "alice", "method": "GET",
         "url": "https://example.test/api/who",
         "headers": {"X-Custom-Id": "1"}, "post_data": None,
         "content_type": ""},
        {"identity": "bob", "method": "GET",
         "url": "https://example.test/api/who",
         "headers": {"X-Custom-Id": "2"}, "post_data": None,
         "content_type": ""},
    ]
    ep = Endpoint(url="https://example.test/api/who",
                  normalized_url="https://example.test/api/who",
                  method="GET")
    ep.observed_requests = shapes
    matched, reason = obs_mod.select_observed_request(
        ep, "X-Custom-Id", "header",
        endpoint_url="https://example.test/api/who")
    assert matched is None
    assert "ambiguous" in reason


def test_sqlmap_stays_prescreen_only_for_headers(monkeypatch):
    monkeypatch.setattr(sqli_mod, "which", lambda _: "/usr/bin/sqlmap")
    calls = []
    monkeypatch.setattr(sqli_mod, "run", lambda *a, **k: (
        calls.append(a) or SimpleNamespace(stdout="", stderr="")))
    candidate = Candidate(
        finding=_finding(), test_class="sqli",
        endpoint_url="https://example.test/api/who", parameter="X-Custom-Id",
        parameter_location="header",
        request_headers={"X-Custom-Id": "7"})
    result = sqli_mod.SqliValidator(Config()).validate(candidate)
    assert result.status == "inconclusive"
    assert "prescreen-only" in result.notes
    assert not calls


def test_plugin_blocks_out_of_scope_header_target():
    from main.plugins.adapters import XssMutationPlugin
    cfg = Config()
    target = TestTarget("https://other.example/api/who",
                        parameter="X-Custom-Id", method="GET",
                        finding=_finding(), endpoint=None, test_class="xss")
    ctx = TestContext(cfg, http=SimpleNamespace(), scope=_scope())
    assert XssMutationPlugin().run(target, ctx).status == "blocked"
