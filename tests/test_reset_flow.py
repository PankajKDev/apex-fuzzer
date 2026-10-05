"""Password-reset flows: enumeration oracle + reset-link poisoning.

No network. Fake HTTP clients only. Identifier values never reach
evidence — only field names, statuses, and booleans.
"""
from types import SimpleNamespace

from main.config import Config, LoginIdentityConfig
from main.models import Endpoint, Parameter
from main.reporting.coverage import CoverageTracker
from main.reporting.metrics import Metrics
from main.validation import reset_flow as rf_mod
from main.validation.evidence import EvidenceStore
from main.budgets import BudgetExceeded


def _endpoint():
    return Endpoint(
        url="https://example.test/forgot-password",
        normalized_url="https://example.test/forgot-password",
        method="POST", host="example.test", path="/forgot-password",
        endpoint_type="authentication",
        body_parameters=[Parameter(name="email", location="body")])


def _scope():
    from main.config import ScopeConfig
    from main.scope import Scope
    return Scope(ScopeConfig(allowed_domains=["example.test"]))


def _cfg_with_login():
    cfg = Config()
    cfg.auth.login.identities = [
        LoginIdentityConfig(name="user_a",
                            username="alice@example.test")]
    return cfg


def _resp(status=200, text="", headers=None):
    return SimpleNamespace(status_code=status, text=text,
                           headers=headers or {})


def test_enumeration_difference_is_candidate():
    class Http:
        def post(self, url, **kwargs):
            data = str(kwargs.get("data") or "")
            if "nonexistent-alice" in data:
                return _resp(200, '{"message":"if registered, mailed"}')
            return _resp(200, '{"message":"reset link sent"}')

    out = rf_mod.check_reset_enumeration(
        Http(), "https://example.test/forgot-password", "email",
        "alice@example.test")
    assert out.verdict == "candidate"
    assert out.evidence["param"] == "email"
    assert "alice@" not in out.notes
    assert "alice@" not in str(out.evidence)


def test_identical_responses_are_negative():
    class Http:
        def post(self, url, **kwargs):
            return _resp(200, '{"message":"if registered, mailed"}')

    out = rf_mod.check_reset_enumeration(
        Http(), "https://example.test/forgot-password", "email",
        "alice@example.test")
    assert out.verdict == "negative"


def test_echo_only_length_difference_is_negative():
    class Http:
        def post(self, url, **kwargs):
            data = str(kwargs.get("data") or "")
            return _resp(200, f'{{"echo":"{data}"}}')

    # same shape, different bucket: input echo, not an oracle
    out = rf_mod.check_reset_enumeration(
        Http(), "https://example.test/forgot-password", "email",
        "alice@example.test")
    assert out.verdict == "negative"


def test_server_error_is_inconclusive():
    class Http:
        def post(self, url, **kwargs):
            return _resp(500, "error")

    out = rf_mod.check_reset_enumeration(
        Http(), "https://example.test/forgot-password", "email",
        "alice@example.test")
    assert out.verdict == "inconclusive"


def test_method_refusal_fails_closed():
    class Http:
        def post(self, url, **kwargs):
            return _resp(405, "method not allowed")

    out = rf_mod.check_reset_enumeration(
        Http(), "https://example.test/forgot-password", "email",
        "alice@example.test")
    assert out.verdict == "inconclusive"
    assert "POST" in out.notes


def test_poisoned_reset_link_is_candidate():
    class Http:
        def post(self, url, **kwargs):
            assert kwargs["headers"]["Host"] == "attacker.invalid"
            return _resp(
                200, '<a href="https://attacker.invalid/reset?token=abc">'
                     "reset</a>")

    out = rf_mod.check_reset_host_poison(
        Http(), "https://example.test/forgot-password", "email",
        "alice@example.test")
    assert out.verdict == "candidate"
    assert "abc" not in out.evidence["link"]
    assert out.evidence["link"].startswith("https://attacker.invalid")


def test_poisoned_redirect_is_candidate():
    class Http:
        def post(self, url, **kwargs):
            return _resp(302, "",
                         {"Location": "https://attacker.invalid/done"})

    out = rf_mod.check_reset_host_poison(
        Http(), "https://example.test/forgot-password", "email",
        "alice@example.test")
    assert out.verdict == "candidate"


def test_bare_reflection_is_inconclusive():
    class Http:
        def post(self, url, **kwargs):
            return _resp(200, "<p>host: attacker.invalid</p>")

    out = rf_mod.check_reset_host_poison(
        Http(), "https://example.test/forgot-password", "email",
        "alice@example.test")
    assert out.verdict == "inconclusive"


def test_ignored_override_is_negative():
    class Http:
        def post(self, url, **kwargs):
            return _resp(200, "<p>check your inbox</p>")

    out = rf_mod.check_reset_host_poison(
        Http(), "https://example.test/forgot-password", "email",
        "alice@example.test")
    assert out.verdict == "negative"


def test_budget_propagates():
    class Http:
        def post(self, *a, **k):
            raise BudgetExceeded("spent")

    try:
        rf_mod.check_reset_enumeration(
            Http(), "https://example.test/forgot-password", "email",
            "alice@example.test")
    except BudgetExceeded:
        pass
    else:
        raise AssertionError("BudgetExceeded must propagate")
    try:
        rf_mod.check_reset_host_poison(
            Http(), "https://example.test/forgot-password", "email",
            "alice@example.test")
    except BudgetExceeded:
        return
    raise AssertionError("BudgetExceeded must propagate")


def test_path_hints_and_param_selection():
    assert rf_mod.is_reset_endpoint(
        "https://example.test/forgot-password")
    assert rf_mod.is_reset_endpoint("https://example.test/auth/reset")
    assert rf_mod.is_reset_endpoint(
        "https://example.test/account/reset-request")
    assert not rf_mod.is_reset_endpoint("https://example.test/login")
    assert not rf_mod.is_reset_endpoint("https://example.test/preset")
    assert rf_mod.identifier_param_for(_endpoint()) == "email"
    bare = Endpoint(url="https://example.test/forgot-password",
                    normalized_url="https://example.test/forgot",
                    host="example.test", path="/forgot")
    assert rf_mod.identifier_param_for(bare) is None
    assert rf_mod.invalid_identifier(
        "alice@example.test") == "nonexistent-alice@example.test"
    assert rf_mod.invalid_identifier("alice").endswith("-apex")


def test_probe_skips_without_login_usernames(tmp_path):
    from main.budgets import BudgetTracker
    from main.stages.validation import ProbeControls
    from main.stages.validation.identity import reset_probe

    class Http:
        def post(self, *a, **k):
            raise AssertionError("must not send without identifiers")

    cfg = Config()
    coverage = CoverageTracker()
    out = reset_probe([_endpoint()], EvidenceStore(tmp_path / "p"),
                      Metrics(), BudgetTracker(cfg),
                      coverage, Http(), cfg, _scope(),
                      ProbeControls())
    assert out == []
    assert coverage.summary()["auth"] == "untestable"


def test_probe_emits_enumeration_finding(tmp_path):
    from main.budgets import BudgetTracker
    from main.stages.validation import ProbeControls
    from main.stages.validation.identity import reset_probe

    class Http:
        def post(self, url, **kwargs):
            data = str(kwargs.get("data") or "")
            if "attacker.invalid" in str(kwargs.get("headers")):
                return _resp(200, "<p>check your inbox</p>")
            if "nonexistent-alice" in data:
                return _resp(200, '{"message":"if registered, mailed"}')
            return _resp(200, '{"message":"reset link sent"}')

    coverage = CoverageTracker()
    cfg = _cfg_with_login()
    out = reset_probe([_endpoint()], EvidenceStore(tmp_path / "p"),
                      Metrics(), BudgetTracker(cfg), coverage, Http(),
                      cfg, _scope(), ProbeControls())
    assert len(out) == 1
    assert out[0].source == "reset-enum"
    assert out[0].validation_status == "strong_candidate"
    assert "alice@" not in out[0].description
    assert coverage.summary()["auth"] == "candidate"


def test_reviews_map_reset_findings():
    from main.models import Finding
    from main.reporting.reviews import finding_test_class
    assert finding_test_class(
        Finding(id="a", source="reset-enum",
                tags=["auth"])) == "auth"
    # existing mappings unchanged
    assert finding_test_class(
        Finding(id="b", source="authz-matrix")) == "authz"
    assert finding_test_class(
        Finding(id="c", source="jwt-confusion",
                tags=["jwt"])) == "jwt"


def test_plan_accounts_reset_requests():
    from main.safety.preflight import plan_reset
    assert plan_reset(4).total == 12
