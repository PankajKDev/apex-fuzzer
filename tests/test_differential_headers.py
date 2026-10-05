"""Tests: header/content-type signals in differential analysis."""
import json

from main.validation import differential as diff_mod
from main.validation.differential import DifferentialTester


class _Resp:
    def __init__(self, status, text, headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}


def _ctx(name, status, body, headers=None):
    n = diff_mod.normalize_response(_Resp(status, body, headers))
    return diff_mod.ContextResult(
        name=name, status=n["status"], length=n["length"],
        length_bucket=n["length_bucket"], key_shape=n["key_shape"],
        body_hash=n["body_hash"], content_type=n["content_type"],
        location=n["location"], auth_markers=n["auth_markers"])


def test_normalize_extracts_header_signals():
    n = diff_mod.normalize_response(_Resp(
        200, '{"id":1}',
        {"Content-Type": "application/json; charset=utf-8",
         "Location": "/login?next=/api",
         "Set-Cookie": "session=AAA; Path=/, theme=dark; Path=/",
         "WWW-Authenticate": 'Bearer realm="x"',
         "X-Request-Id": "abc"}))
    assert n["content_type"] == "application/json"
    assert n["location"] == "/login?next=/api"
    assert n["auth_markers"] == "session,theme,www-authenticate"


def test_cookie_values_never_retained():
    n = diff_mod.normalize_response(_Resp(
        200, "{}", {"Set-Cookie": "session=s3cret; Path=/",
                    "Cookie": "other=v"}))
    assert "s3cret" not in n["auth_markers"]
    assert n["auth_markers"] == "session"


def test_expires_dates_do_not_split_cookies():
    n = diff_mod.normalize_response(_Resp(
        200, "{}",
        {"Set-Cookie": "a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Path=/",
         }))
    assert n["auth_markers"] == "a"


def test_hash_match_wins_despite_ct_mismatch():
    body = json.dumps({"id": 1, "email": "a@b.c"})
    res = diff_mod.DifferentialResult(url="x", endpoint_type="api")
    res.contexts = [
        _ctx("user_a", 200, body, {"Content-Type": "application/json"}),
        _ctx("user_b", 200, body, {"Content-Type": "text/html"})]
    # byte-identical bodies (hash match) still prove shared data…
    verdict, _ = DifferentialTester.evaluate(res)
    assert verdict == "strong_candidate"


def test_shape_only_match_with_ct_mismatch_is_inconclusive():
    # same keys, same 1KB bucket, different bytes → shape branch
    b1 = json.dumps({"id": 1, "pad": "x" * 10})
    b2 = json.dumps({"id": 2, "pad": "y" * 500})
    res = diff_mod.DifferentialResult(url="x", endpoint_type="api")
    res.contexts = [
        _ctx("user_a", 200, b1, {"Content-Type": "application/json"}),
        _ctx("user_b", 200, b2, {"Content-Type": "text/html"})]
    verdict, notes = DifferentialTester.evaluate(res)
    assert verdict == "inconclusive"
    assert "content types diverge" in notes


def test_shape_match_without_ct_data_still_candidate():
    b1 = json.dumps({"id": 1, "pad": "x" * 10})
    b2 = json.dumps({"id": 2, "pad": "y" * 500})
    res = diff_mod.DifferentialResult(url="x", endpoint_type="api")
    res.contexts = [_ctx("user_a", 200, b1), _ctx("user_b", 200, b2)]
    verdict, _ = DifferentialTester.evaluate(res)
    assert verdict == "strong_candidate"


def test_anon_html_vs_authed_json_is_not_broken_access():
    res = diff_mod.DifferentialResult(url="x", endpoint_type="api")
    res.contexts = [
        _ctx("anonymous", 200, "<html>login</html>",
             {"Content-Type": "text/html"}),
        _ctx("user_a", 200, '{"id":1}',
             {"Content-Type": "application/json"})]
    verdict, notes = DifferentialTester.evaluate(res)
    assert verdict == "inconclusive"
    assert "login-wall" in notes


def test_anon_json_200_stays_candidate():
    res = diff_mod.DifferentialResult(url="x", endpoint_type="api")
    res.contexts = [
        _ctx("anonymous", 200, '{"id":1}',
             {"Content-Type": "application/json"}),
        _ctx("user_a", 200, '{"id":1}',
             {"Content-Type": "application/json"})]
    verdict, _ = DifferentialTester.evaluate(res)
    assert verdict == "strong_candidate"


def test_probe_carries_header_fields():
    from main.config import AuthContext, Config

    class Http:
        def get(self, url, headers=None, timeout=10):
            cookie = (headers or {}).get("Cookie", "")
            if "AAA" in cookie or "BBB" in cookie:
                return _Resp(200, '{"id":1}',
                             {"Content-Type": "application/json"})
            return _Resp(401, "")

    cfg = Config()
    cfg.auth.contexts = [AuthContext(name="user_a",
                                     headers={"Cookie": "session=AAA"}),
                         AuthContext(name="user_b",
                                     headers={"Cookie": "session=BBB"})]
    res = DifferentialTester(cfg, Http()).probe("https://e.com/api",
                                                "api")
    by_name = {c.name: c for c in res.contexts}
    assert by_name["user_a"].content_type == "application/json"
    assert by_name["anonymous"].content_type == ""
    assert res.verdict == "strong_candidate"
