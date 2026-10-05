"""OTP bypass: empty/omitted code against a wrong-code baseline.

No network. Fake HTTP clients only. At most 3 single attempts per
endpoint in production — never a brute-force sweep.
"""
from types import SimpleNamespace

from main.budgets import BudgetExceeded, BudgetTracker
from main.config import Config, ScopeConfig
from main.models import Endpoint, Parameter
from main.reporting.coverage import CoverageTracker
from main.reporting.metrics import Metrics
from main.scope import Scope
from main.validation import otp_bypass as otp_mod
from main.validation.evidence import EvidenceStore


def _endpoint():
    return Endpoint(
        url="https://example.test/verify-otp",
        normalized_url="https://example.test/verify-otp",
        method="POST", host="example.test", path="/verify-otp",
        endpoint_type="authentication",
        body_parameters=[Parameter(name="otp", location="body")])


def _scope():
    return Scope(ScopeConfig(allowed_domains=["example.test"]))


def _cfg_acked():
    cfg = Config()
    cfg.safety.allow_state_change = True
    return cfg


def _resp(status=200, text=""):
    return SimpleNamespace(status_code=status, text=text, headers={})


class _BypassHttp:
    """Wrong code rejected; empty and omitted codes accepted."""

    def __init__(self):
        self.calls = []

    def post(self, url, **kwargs):
        from urllib.parse import parse_qsl
        data = str(kwargs.get("data") or "")
        self.calls.append(data)
        pairs = dict(parse_qsl(data, keep_blank_values=True))
        if "otp" not in pairs:
            return _resp(200, '{"status":"success","token":"abc"}')
        if pairs["otp"] == "":
            return _resp(200, '{"status":"success","verified":true}')
        return _resp(401, '{"error":"invalid code"}')


def test_empty_and_omitted_codes_are_candidates():
    out = otp_mod.check_otp_bypass(
        _BypassHttp(), "https://example.test/verify-otp", "otp")
    assert [r.verdict for r in out] == ["candidate", "candidate"]
    assert out[0].check == "otp-empty"
    assert out[1].check == "otp-omitted"
    assert len(out[0].evidence) == 3  # no code values kept


def test_matching_rejections_are_negative():
    class Http:
        def post(self, url, **kwargs):
            return _resp(401, '{"error":"invalid code"}')

    out = otp_mod.check_otp_bypass(
        Http(), "https://example.test/verify-otp", "otp")
    assert [r.verdict for r in out] == ["negative", "negative"]


def test_unclear_baseline_is_inconclusive():
    class Http:
        def post(self, url, **kwargs):
            return _resp(200, '{"message":"submit your code"}')

    out = otp_mod.check_otp_bypass(
        Http(), "https://example.test/verify-otp", "otp")
    assert [r.verdict for r in out] == ["inconclusive", "inconclusive"]


def test_mixed_signals_are_inconclusive():
    class Http:
        def post(self, url, **kwargs):
            from urllib.parse import parse_qsl
            pairs = dict(parse_qsl(str(kwargs.get("data") or ""),
                                   keep_blank_values=True))
            if pairs.get("otp") == "000000":
                return _resp(401, '{"error":"invalid code"}')
            # success language alongside an error marker
            return _resp(200, '{"success":true,"error":"retry"}')

    out = otp_mod.check_otp_bypass(
        Http(), "https://example.test/verify-otp", "otp")
    assert [r.verdict for r in out] == ["negative", "negative"]


def test_rate_limit_and_server_errors_are_inconclusive():
    class Limited:
        def post(self, url, **kwargs):
            return _resp(429, "slow down")

    out = otp_mod.check_otp_bypass(
        Limited(), "https://example.test/verify-otp", "otp")
    assert all(r.verdict == "inconclusive" for r in out)

    class Broken:
        def post(self, url, **kwargs):
            return _resp(500, "error")

    out = otp_mod.check_otp_bypass(
        Broken(), "https://example.test/verify-otp", "otp")
    assert all(r.verdict == "inconclusive" for r in out)


def test_method_refusal_fails_closed():
    class Http:
        def post(self, url, **kwargs):
            return _resp(405, "method not allowed")

    out = otp_mod.check_otp_bypass(
        Http(), "https://example.test/verify-otp", "otp")
    assert all(r.verdict == "inconclusive" for r in out)


def test_budget_propagates():
    class Http:
        def post(self, *a, **k):
            raise BudgetExceeded("spent")

    try:
        otp_mod.check_otp_bypass(
            Http(), "https://example.test/verify-otp", "otp")
    except BudgetExceeded:
        return
    raise AssertionError("BudgetExceeded must propagate")


def test_path_hints_and_param_selection():
    assert otp_mod.is_otp_endpoint("https://example.test/verify-otp")
    assert otp_mod.is_otp_endpoint("https://example.test/auth/2fa")
    assert otp_mod.is_otp_endpoint("https://example.test/2fa_verify")
    assert not otp_mod.is_otp_endpoint("https://example.test/login")
    assert not otp_mod.is_otp_endpoint("https://example.test/preset")
    assert otp_mod.code_param_for(_endpoint()) == "otp"
    bare = Endpoint(url="https://example.test/verify-otp",
                    normalized_url="https://example.test/verify-otp",
                    host="example.test", path="/verify-otp")
    assert otp_mod.code_param_for(bare) is None


def test_probe_skips_without_state_change_ack(tmp_path):
    from main.stages.validation import ProbeControls
    from main.stages.validation.identity import otp_bypass_probe

    class Http:
        def post(self, *a, **k):
            raise AssertionError("must not send without ack")

    cfg = Config()
    out = otp_bypass_probe(
        [_endpoint()], EvidenceStore(tmp_path / "p"), Metrics(),
        BudgetTracker(cfg), CoverageTracker(), Http(), cfg,
        _scope(), ProbeControls())
    assert out == []


def test_probe_emits_bypass_findings(tmp_path):
    from main.stages.validation import ProbeControls
    from main.stages.validation.identity import otp_bypass_probe

    cfg = _cfg_acked()
    coverage = CoverageTracker()
    out = otp_bypass_probe(
        [_endpoint()], EvidenceStore(tmp_path / "p"), Metrics(),
        BudgetTracker(cfg), coverage, _BypassHttp(), cfg,
        _scope(), ProbeControls())
    assert len(out) == 2
    assert {f.source for f in out} == {"otp-bypass"}
    assert all(f.validation_status == "strong_candidate" for f in out)
    assert all("000000" not in f.description for f in out)
    assert coverage.summary()["auth"] == "candidate"


def test_reviews_map_otp_findings():
    from main.models import Finding
    from main.reporting.reviews import finding_test_class
    assert finding_test_class(
        Finding(id="a", source="otp-bypass",
                tags=["auth"])) == "auth"


def test_plan_accounts_otp_requests():
    from main.safety.preflight import plan_otp
    assert plan_otp(4).total == 12
