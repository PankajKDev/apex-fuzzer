"""Tests: JWT confusion replay and header-layer probes."""
import base64
import json


def _jwt(header, payload):
    def enc(obj):
        raw = json.dumps(obj, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    return f"{enc(header)}.{enc(payload)}.sig"


GOOD = _jwt({"alg": "HS256", "typ": "JWT"},
            {"sub": "user_a", "exp": 4102444800})


class _Resp:
    def __init__(self, status, text, headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}


class FakeHttp:
    def __init__(self, script):
        self._script = list(script)
        self.calls = []

    def get(self, url, headers=None, **kw):
        self.calls.append((url, dict(headers or {})))
        action = self._script.pop(0) if self._script else ""
        if isinstance(action, Exception):
            raise action
        return action


def test_bearer_extraction_and_tamper_shapes():
    from main.validation.jwt_replay import bearer_token, tamper_variants
    assert bearer_token({"Authorization": "Bearer not.a.jwt"}) == ""
    assert bearer_token({"Authorization": f"Bearer {GOOD}"}) == GOOD
    assert bearer_token({}) == ""
    variants = tamper_variants(GOOD)
    assert [label for label, _ in variants] == ["alg-none",
                                                "empty-signature"]
    for _, token in variants:
        parts = token.split(".")
        assert len(parts) == 3 and parts[2] == ""
    assert tamper_variants("garbage") == []


def test_accepted_tampered_token_is_candidate():
    from main.validation.jwt_replay import jwt_confusion_probe
    body = '{"id": 1}'
    http = FakeHttp([_Resp(200, body), _Resp(200, body),
                     _Resp(200, body)])
    res = jwt_confusion_probe(
        http, "https://example.com/api/me",
        {"Authorization": f"Bearer {GOOD}"}, "user_a")
    assert res is not None and res.verdict == "accepted"
    assert "alg-none" in res.notes or "empty-signature" in res.notes
    sent = [headers.get("Authorization", "") for _, headers in
            http.calls[1:]]
    assert all("none" in token or token.endswith(".")
               for token in sent)


def test_denied_variants_are_negative():
    from main.validation.jwt_replay import jwt_confusion_probe
    http = FakeHttp([_Resp(200, '{"id": 1}'),
                     _Resp(401, "unauthorized"),
                     _Resp(403, "forbidden")])
    res = jwt_confusion_probe(
        http, "https://example.com/api/me",
        {"Authorization": f"Bearer {GOOD}"}, "user_a")
    assert res.verdict == "denied"


def test_expired_baseline_is_inconclusive():
    from main.validation.jwt_replay import jwt_confusion_probe
    http = FakeHttp([_Resp(401, "expired")])
    res = jwt_confusion_probe(
        http, "https://example.com/api/me",
        {"Authorization": f"Bearer {GOOD}"}, "user_a")
    assert res.verdict == "inconclusive"
    assert "expired" in res.notes or "401" in res.notes


def test_no_bearer_is_untestable():
    from main.validation.jwt_replay import jwt_confusion_probe
    assert jwt_confusion_probe(
        FakeHttp([]), "https://example.com/api/me",
        {"Cookie": "session=x"}, "user_a") is None


def test_budget_propagates():
    from main.budgets import BudgetExceeded
    from main.validation.jwt_replay import jwt_confusion_probe
    import pytest
    with pytest.raises(BudgetExceeded):
        jwt_confusion_probe(
            FakeHttp([BudgetExceeded("cap")]),
            "https://example.com/api/me",
            {"Authorization": f"Bearer {GOOD}"}, "user_a")


def test_host_redirect_is_candidate():
    from main.validation.header_probe import check_host_override
    http = FakeHttp([_Resp(302, "", {"Location":
                                     "https://attacker.invalid/in"})])
    res = check_host_override(http, "https://example.com/login")
    assert res.verdict == "candidate"
    assert "attacker.invalid" in res.notes
    sent_headers = http.calls[0][1]
    assert sent_headers.get("Host") == "attacker.invalid"


def test_host_body_echo_is_inconclusive():
    from main.validation.header_probe import check_host_override
    http = FakeHttp([_Resp(200, "welcome attacker.invalid user"),
                     _Resp(200, "welcome attacker.invalid user")])
    res = check_host_override(http, "https://example.com/")
    assert res.verdict == "inconclusive"


def test_host_ignored_is_negative():
    from main.validation.header_probe import check_host_override
    http = FakeHttp([_Resp(200, "welcome friend"),
                     _Resp(200, "welcome friend")])
    res = check_host_override(http, "https://example.com/")
    assert res.verdict == "negative"


def test_crlf_split_is_candidate():
    from main.validation.header_probe import check_crlf
    http = FakeHttp([_Resp(200, "ok", {"X-Apex-Probe": "apex"})])
    res = check_crlf(http, "https://example.com/s?q=1", "q")
    assert res.verdict == "candidate"
    sent_url = http.calls[0][0]
    assert "%0d%0a" in sent_url.lower() or "%0D%0A" in sent_url
    assert "q=" in sent_url


def test_crlf_clean_is_negative():
    from main.validation.header_probe import check_crlf
    http = FakeHttp([_Resp(200, "ok", {"Content-Type": "text/html"})])
    res = check_crlf(http, "https://example.com/s?q=1", "q")
    assert res.verdict == "negative"
    res2 = check_crlf(http, "https://example.com/s", "missing")
    assert res2.verdict == "inconclusive"


def test_crlf_budget_propagates():
    from main.budgets import BudgetExceeded
    from main.validation.header_probe import check_crlf
    import pytest
    with pytest.raises(BudgetExceeded):
        check_crlf(FakeHttp([BudgetExceeded("cap")]),
                   "https://example.com/s?q=1", "q")


def test_jwt_stage_maps_accepted_to_finding(tmp_path):
    from pathlib import Path
    from types import SimpleNamespace
    from main.budgets import BudgetTracker
    from main.config import Config
    from main.models import Endpoint
    from main.reporting.coverage import CoverageTracker
    from main.reporting.metrics import Metrics
    from main.scope import Scope
    from main.stages.validation import ProbeControls
    from main.stages.validation.identity import jwt_confusion_probe
    from main.validation.evidence import EvidenceStore
    out = Path(tmp_path)
    cfg = Config()
    body = '{"id": 1}'
    http = FakeHttp([_Resp(200, body), _Resp(200, body),
                     _Resp(200, body)])
    ep = Endpoint(url="https://example.com/api/me",
                  normalized_url="https://example.com/api/me",
                  host="example.com", path="/api/me", method="GET",
                  endpoint_type="api")
    coverage = CoverageTracker()
    found = jwt_confusion_probe(
        [ep], EvidenceStore(out / "proofs"), Metrics(),
        BudgetTracker(cfg), coverage, http, cfg, Scope(cfg.scope),
        ProbeControls(),
        [SimpleNamespace(name="user_a",
                         auth_headers={"Authorization":
                                       f"Bearer {GOOD}"})])
    assert len(found) == 1
    assert found[0].source == "jwt-confusion"
    assert found[0].severity == "high"
    assert coverage.summary()["jwt"] == "candidate"


def test_header_stage_maps_redirect_to_finding(tmp_path):
    from pathlib import Path
    from main.budgets import BudgetTracker
    from main.config import Config
    from main.models import Endpoint
    from main.reporting.coverage import CoverageTracker
    from main.reporting.metrics import Metrics
    from main.scope import Scope
    from main.stages.validation import ProbeControls
    from main.stages.validation.misconfig import header_probe
    from main.validation.evidence import EvidenceStore
    out = Path(tmp_path)
    cfg = Config()
    http = FakeHttp([_Resp(302, "", {"Location":
                                     "https://attacker.invalid/x"})])
    ep = Endpoint(url="https://example.com/login?next=/",
                  normalized_url="https://example.com/login",
                  host="example.com", path="/login", method="GET",
                  endpoint_type="page")
    coverage = CoverageTracker()
    found = header_probe(
        [ep], EvidenceStore(out / "proofs"), Metrics(),
        BudgetTracker(cfg), coverage, http, cfg, Scope(cfg.scope),
        ProbeControls())
    assert len(found) == 1
    assert found[0].source == "misconfig-host-header"
    assert coverage.summary()["host_header"] == "candidate"


def test_lead_hints_cover_auth_flows():
    from main.leads import INTERESTING_PATH_HINTS
    for seg in ("forgot", "reset", "otp", "oauth", "authorize",
                "verify"):
        assert seg in INTERESTING_PATH_HINTS


def test_review_mapping_covers_new_classes():
    from main.models import Finding
    from main.reporting.reviews import finding_test_class
    assert finding_test_class(
        Finding(id="a", source="jwt-confusion")) == "jwt"
    assert finding_test_class(
        Finding(id="b", source="misconfig-host-header")) == \
        "header_injection"
    assert finding_test_class(
        Finding(id="c", source="x", tags=["clickjacking"])) == \
        "clickjacking"
