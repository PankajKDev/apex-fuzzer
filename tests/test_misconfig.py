"""Tests: clickjacking + CSRF-token misconfiguration checks."""
from main.validation import misconfig as mod


def test_clickjacking_unprotected():
    verdict = mod.check_clickjacking(
        {"Content-Type": "text/html"}, "text/html",
        "https://example.com/page")
    assert verdict["verdict"] == "candidate"


def test_clickjacking_protected_variants():
    assert mod.check_clickjacking(
        {"X-Frame-Options": "DENY"}, "text/html",
        "https://example.com/")["verdict"] == "protected"
    assert mod.check_clickjacking(
        {"X-Frame-Options": "sameorigin"}, "text/html",
        "https://example.com/")["verdict"] == "protected"
    assert mod.check_clickjacking(
        {"Content-Security-Policy": "default-src 'self'; "
                                    "frame-ancestors 'none'"},
        "text/html", "https://example.com/")["verdict"] == "protected"
    allow = mod.check_clickjacking(
        {"X-Frame-Options": "ALLOW-FROM https://example.com"},
        "text/html", "https://example.com/")
    assert allow["verdict"] == "candidate"
    assert mod.check_clickjacking(
        {}, "application/json", "https://example.com/api")[
            "verdict"] is None


def test_csrf_tokenless_post_form():
    html = ('<form action="/transfer" method="post">'
            '<input type="text" name="amount">'
            '<input type="submit" value="go"></form>')
    verdict = mod.check_csrf_forms(html, "https://example.com/transfer")
    assert verdict["verdict"] == "candidate"
    assert len(verdict["forms"]) == 1


def test_csrf_tokened_and_get_forms_quiet():
    html = ('<form action="/transfer" method="POST">'
            '<input type="hidden" name="csrf_token" value="abc">'
            '<input type="text" name="amount"></form>'
            '<form action="/search" method="get">'
            '<input type="text" name="q"></form>')
    verdict = mod.check_csrf_forms(html, "https://example.com/")
    assert verdict["verdict"] == "protected"
    assert mod.check_csrf_forms("<p>no forms</p>",
                               "https://example.com/")["verdict"] is None


def test_token_name_variants():
    for name in ("csrfmiddlewaretoken", "authenticity_token",
                 "__RequestVerificationToken", "_csrf", "nonce"):
        html = (f'<form method="post"><input type="hidden" name="{name}">'
                "</form>")
        assert mod.check_csrf_forms(
            html, "https://example.com/")["verdict"] == "protected", name
    # generic "token" alone (e.g. OAuth fields) is not a CSRF defense
    html = ('<form method="post"><input type="hidden" name="token">'
            "</form>")
    assert mod.check_csrf_forms(
        html, "https://example.com/")["verdict"] == "candidate"


def test_probe_emits_and_grades(tmp_path):
    from main.budgets import BudgetTracker
    from main.config import Config
    from main.models import Endpoint
    from main.reporting.coverage import CoverageTracker
    from main.reporting.metrics import Metrics
    from main.scope import Scope
    from main.stages.validation import ProbeControls
    from main.stages.validation.misconfig import misconfig_probe
    from main.validation.evidence import EvidenceStore

    class Http:
        def __init__(self, headers, text):
            self._headers = headers
            self._text = text

        def get(self, url, **kw):
            class R:
                pass
            r = R()
            r.status_code = 200
            r.headers = dict(self._headers)
            r.text = self._text
            return r

    cfg = Config()
    page = Endpoint(url="https://example.com/app",
                    normalized_url="https://example.com/app",
                    host="example.com", path="/app", method="GET",
                    endpoint_type="page")
    api = Endpoint(url="https://example.com/api",
                   normalized_url="https://example.com/api",
                   host="example.com", path="/api", method="GET",
                   endpoint_type="api")
    body = ('<form action="/transfer" method="post">'
            '<input name="amount"></form>')
    http = Http({"content-type": "text/html"}, body)
    coverage = CoverageTracker()
    found = misconfig_probe(
        [page, api], EvidenceStore(tmp_path / "proofs"), Metrics(),
        BudgetTracker(cfg), coverage, http, cfg, Scope(cfg.scope),
        ProbeControls())
    sources = {f.source for f in found}
    assert sources == {"misconfig-clickjacking", "misconfig-csrf"}
    assert all(f.severity == "info" and
               f.validation_status == "strong_candidate" for f in found)
    assert coverage.summary()["clickjacking"] == "candidate"
    assert coverage.summary()["csrf"] == "candidate"


def test_probe_protected_is_negative(tmp_path):
    from main.budgets import BudgetTracker
    from main.config import Config
    from main.models import Endpoint
    from main.reporting.coverage import CoverageTracker
    from main.reporting.metrics import Metrics
    from main.scope import Scope
    from main.stages.validation import ProbeControls
    from main.stages.validation.misconfig import misconfig_probe
    from main.validation.evidence import EvidenceStore

    class Http:
        def get(self, url, **kw):
            class R:
                pass
            r = R()
            r.status_code = 200
            r.headers = {"X-Frame-Options": "DENY",
                         "content-type": "text/html"}
            r.text = ('<form method="post">'
                      '<input type="hidden" name="csrf_token"></form>')
            return r

    cfg = Config()
    page = Endpoint(url="https://example.com/app",
                    normalized_url="https://example.com/app",
                    host="example.com", path="/app", method="GET",
                    endpoint_type="page")
    coverage = CoverageTracker()
    found = misconfig_probe(
        [page], EvidenceStore(tmp_path / "proofs"), Metrics(),
        BudgetTracker(cfg), coverage, Http(), cfg, Scope(cfg.scope),
        ProbeControls())
    assert found == []
    assert coverage.summary()["clickjacking"] == "tested_negative"
    assert coverage.summary()["csrf"] == "tested_negative"


def test_plan_cost():
    from main.safety.preflight import plan_misconfig
    assert plan_misconfig(4).total == 4
