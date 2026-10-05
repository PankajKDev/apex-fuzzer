"""Tests: redirect/error/latency differential signals (R/E/T)."""
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
        location=n["location"], auth_markers=n["auth_markers"],
        error_signature=n["error_signature"])


def test_error_signature_extraction():
    n = diff_mod.normalize_response(_Resp(
        500, "Traceback (most recent call last):\n  File 'app.py'"))
    assert n["error_signature"] == "python-traceback"
    n2 = diff_mod.normalize_response(_Resp(200, '{"ok":true}'))
    assert n2["error_signature"] == ""
    # healthy copy mentioning errors is not a signature
    n3 = diff_mod.normalize_response(_Resp(
        200, "0 errors found, all checks passed"))
    assert n3["error_signature"] == ""


def test_asymmetric_error_is_candidate():
    body = json.dumps({"id": 1})
    leak = ("Internal Server Error\n"
            "Traceback (most recent call last):\n  File 'app.py'")
    res = diff_mod.DifferentialResult(url="x", endpoint_type="api")
    res.contexts = [_ctx("user_a", 200, body),
                    _ctx("user_b", 200, leak)]
    verdict, notes = DifferentialTester.evaluate(res)
    assert verdict == "strong_candidate"
    assert "differential error disclosure" in notes
    assert "python-traceback" in notes


def test_symmetric_error_is_not_candidate():
    leak = "Traceback (most recent call last) oops"
    res = diff_mod.DifferentialResult(url="x", endpoint_type="api")
    res.contexts = [_ctx("user_a", 500, leak),
                    _ctx("user_b", 500, leak)]
    verdict, _ = DifferentialTester.evaluate(res)
    assert verdict == "inconclusive"


def test_redirect_divergence_is_candidate():
    res = diff_mod.DifferentialResult(url="x", endpoint_type="page")
    res.contexts = [
        _ctx("user_a", 302, "", {"Location": "/app/dashboard"}),
        _ctx("user_b", 302, "", {"Location": "/login?next=%2Fapp"})]
    verdict, notes = DifferentialTester.evaluate(res)
    assert verdict == "strong_candidate"
    assert "redirect divergence" in notes


def test_same_redirect_target_is_quiet():
    res = diff_mod.DifferentialResult(url="x", endpoint_type="page")
    res.contexts = [
        _ctx("user_a", 302, "", {"Location": "/login?u=a"}),
        _ctx("user_b", 302, "", {"Location": "/login?u=b"})]
    verdict, _ = DifferentialTester.evaluate(res)
    assert verdict == "inconclusive"


def test_anon_redirect_with_authed_200_is_healthy():
    res = diff_mod.DifferentialResult(url="x", endpoint_type="page")
    res.contexts = [
        _ctx("anonymous", 302, "", {"Location": "/login"}),
        _ctx("user_a", 200, '{"id":1}') ]
    verdict, notes = DifferentialTester.evaluate(res)
    assert verdict == "inconclusive"
    assert "enforced at redirect" in notes


def test_probe_records_latency():
    from main.config import AuthContext, Config

    class Http:
        def get(self, url, headers=None, timeout=10):
            return _Resp(200, '{"id":1}')

    cfg = Config()
    cfg.auth.contexts = [AuthContext(name="user_a",
                                     headers={"Cookie": "session=AAA"})]
    res = DifferentialTester(cfg, Http()).probe("https://e.com/api",
                                                "api")
    for c in res.contexts:
        assert c.elapsed_ms >= 0.0
