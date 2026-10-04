"""MFA session transitions + OAuth transition checks.

No network, no browser. Fake HTTP clients only.
"""
from types import SimpleNamespace

from apex_fuzzer.auth.mfa_checks import check_transition
from apex_fuzzer.auth.oauth_checks import (
    find_authorize_urls, check_pkce_strip, check_redirect_oast)
from apex_fuzzer.budgets import BudgetExceeded


def _resp(status, text="", headers=None):
    return SimpleNamespace(status_code=status, text=text,
                           headers=headers or {})


def test_pre_mfa_reaching_protected_object_is_candidate():
    body = '{"id": 9, "email": "victim@example.test"}'

    class Http:
        def get(self, url, **kwargs):
            return _resp(200, body)

    out = check_transition(Http(), "https://example.test/admin/users",
                           {"Cookie": "s=pre"}, {"Cookie": "s=post"},
                           "pre", "post")
    assert out.verdict == "strong_candidate"
    assert out.pre_status == 200 and out.post_status == 200


def test_healthy_gate_is_a_genuine_negative():
    class Http:
        def get(self, url, **kwargs):
            cookie = (kwargs.get("headers") or {}).get("Cookie", "")
            if "pre" in cookie:
                return _resp(401, "login required")
            return _resp(200, '{"id": 9}')

    out = check_transition(Http(), "https://example.test/admin",
                           {"Cookie": "s=pre"}, {"Cookie": "s=post"},
                           "pre", "post")
    assert out.verdict == "tested_negative"


def test_divergent_content_is_inconclusive():
    class Http:
        def get(self, url, **kwargs):
            cookie = (kwargs.get("headers") or {}).get("Cookie", "")
            if "pre" in cookie:
                return _resp(200, "<html>login wall</html>")
            return _resp(200, '{"dashboard": true}')

    out = check_transition(Http(), "https://example.test/app",
                           {"Cookie": "s=pre"}, {"Cookie": "s=post"},
                           "pre", "post")
    assert out.verdict == "inconclusive"


def test_both_denied_is_inconclusive():
    class Http:
        def get(self, url, **kwargs):
            return _resp(403, "denied")

    out = check_transition(Http(), "https://example.test/app",
                           {"Cookie": "s=pre"}, {"Cookie": "s=post"},
                           "pre", "post")
    assert out.verdict == "inconclusive"


def test_budget_exhaustion_propagates():
    class Http:
        def get(self, *args, **kwargs):
            raise BudgetExceeded("budget exhausted")

    try:
        check_transition(Http(), "https://example.test/app", {}, {},
                         "pre", "post")
    except BudgetExceeded:
        return
    raise AssertionError("BudgetExceeded must propagate")


def test_authorize_url_analysis_flags_state_and_implicit():
    urls = [
        "https://auth.example.test/authorize?client_id=c1&"
        "redirect_uri=https%3A%2F%2Fapp.example.test%2Fcb&"
        "response_type=code&scope=openid",
        "https://auth.example.test/authorize?client_id=c2&"
        "redirect_uri=https%3A%2F%2Fother.example.test%2Fcb&"
        "response_type=token&state=xyz&scope=openid",
        "https://example.test/static/app.js",
    ]
    found = find_authorize_urls(urls, source="traffic")
    assert len(found) == 2
    assert found[0].has_state is False
    assert found[0].implicit_flow is False
    assert found[1].has_state is True
    assert found[1].implicit_flow is True
    assert find_authorize_urls([]) == []


def test_pkce_strip_candidate_when_code_issued():
    class Http:
        def get(self, url, **kwargs):
            assert "code_challenge" not in url
            return _resp(302, "",
                         {"Location": "https://app.example.test/cb?code=ABC"})

    url = ("https://auth.example.test/authorize?client_id=c1&"
           "redirect_uri=https%3A%2F%2Fapp.example.test%2Fcb&"
           "response_type=code&code_challenge=E9M&"
           "code_challenge_method=S256&state=s")
    out = check_pkce_strip(Http(), url, {"Cookie": "s=1"}, "user_a")
    assert out.verdict == "strong_candidate"
    assert out.evidence["had_code"] is True


def test_pkce_strip_inconclusive_without_code():
    class Http:
        def get(self, url, **kwargs):
            return _resp(400, "error=invalid_request")

    url = ("https://auth.example.test/authorize?client_id=c1&"
           "response_type=code&code_challenge=E9M&state=s")
    out = check_pkce_strip(Http(), url, {"Cookie": "s=1"}, "user_a")
    assert out.verdict == "inconclusive"


def test_pkce_strip_skips_challengeless_flows():
    class Http:
        def get(self, *args, **kwargs):
            raise AssertionError("no challenge: must not send")

    url = ("https://auth.example.test/authorize?client_id=c1&"
           "response_type=code&state=s")
    out = check_pkce_strip(Http(), url, {"Cookie": "s=1"}, "user_a")
    assert out.verdict == "inconclusive"


def test_redirect_oast_candidate_on_code_to_collector():
    cb = "http://127.0.0.1:9001/cb"

    class Http:
        def get(self, url, **kwargs):
            assert "redirect_uri=" in url
            return _resp(302, "", {"Location": f"{cb}/abc?code=XYZ"})

    url = ("https://auth.example.test/authorize?client_id=c1&"
           "redirect_uri=https%3A%2F%2Fapp.example.test%2Fcb&"
           "response_type=code&state=s")
    out = check_redirect_oast(Http(), url, {"Cookie": "s=1"}, "user_a", cb)
    assert out.verdict == "strong_candidate"


def test_redirect_oast_inconclusive_when_ignored():
    class Http:
        def get(self, url, **kwargs):
            return _resp(302, "",
                         {"Location": "https://app.example.test/cb?code=Q"})

    url = ("https://auth.example.test/authorize?client_id=c1&"
           "redirect_uri=https%3A%2F%2Fapp.example.test%2Fcb&"
           "response_type=code&state=s")
    out = check_redirect_oast(Http(), url, {"Cookie": "s=1"}, "user_a",
                              "http://127.0.0.1:9001/cb")
    assert out.verdict == "inconclusive"


def test_oauth_probes_never_follow_redirects():
    seen = []

    class Http:
        def get(self, url, **kwargs):
            seen.append(url)
            return _resp(302, "",
                         {"Location": "http://127.0.0.1:9001/cb?code=XYZ"})

    url = ("https://auth.example.test/authorize?client_id=c1&"
           "redirect_uri=https%3A%2F%2Fapp.example.test%2Fcb&"
           "response_type=code&state=s")
    check_redirect_oast(Http(), url, {"Cookie": "s=1"}, "user_a",
                        "http://127.0.0.1:9001/cb")
    from urllib.parse import parse_qsl, urlsplit
    assert len(seen) == 1
    query = dict(parse_qsl(urlsplit(seen[0]).query))
    assert query["redirect_uri"] == "http://127.0.0.1:9001/cb"
    assert query["client_id"] == "c1"
    assert not [u for u in seen if u.startswith("http://127.0.0.1")]
