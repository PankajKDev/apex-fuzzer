"""Tests: blind-XSS OAST correlation (no network)."""
from main.models import Endpoint, Parameter


def _ep():
    return Endpoint(
        url="https://example.com/comment", normalized_url="x",
        host="example.com", path="/comment", method="POST",
        endpoint_type="page",
        body_parameters=[Parameter(name="text", location="body")])


class Provider:
    def __init__(self, hits=()):
        self._hits = list(hits)
        self.posts = []

    def available(self):
        return True

    def create_token(self):
        return "tok-1.oast.test"

    def correlation_key(self, url):
        return "tok-1"

    def poll(self, timeout=0, interval=0):
        return list(self._hits)


class Http:
    def __init__(self):
        self.posts = []

    def post(self, url, data=None, headers=None, timeout=10):
        self.posts.append((url, dict(data or {})))

        class R:
            status_code = 200
            text = "stored"
        return R()


def _run(ep=None, provider=None, identities=None):
    from types import SimpleNamespace
    from main.budgets import BudgetTracker
    from main.config import Config
    from main.reporting.coverage import CoverageTracker
    from main.reporting.metrics import Metrics
    from main.scope import Scope
    from main.stages.validation import ProbeControls
    from main.stages.validation.second_order import blind_xss_probe
    from main.validation.evidence import EvidenceStore
    import tempfile
    from pathlib import Path
    out = Path(tempfile.mkdtemp())
    cfg = Config()
    idents = identities if identities is not None else [
        SimpleNamespace(name="user_a",
                        auth_headers={"Cookie": "s=A"})]
    coverage = CoverageTracker()
    found = blind_xss_probe(
        [ep or _ep()], EvidenceStore(out / "proofs"), Metrics(),
        BudgetTracker(cfg), coverage, Http(), cfg, Scope(cfg.scope),
        ProbeControls(), idents,
        provider if provider is not None else Provider())
    return found, coverage


def test_callback_is_candidate_not_confirmed():
    found, coverage = _run(provider=Provider(
        hits=[{"type": "http", "full-id": "tok-1",
               "data": "tok-1 fetched"}]))
    assert len(found) == 1
    f = found[0]
    assert f.source == "blind-xss"
    assert f.validation_status == "strong_candidate"
    assert "tok-1.oast.test" in f.description or \
        "script-src" in f.description
    assert "NOT proven" in f.description
    assert coverage.summary()["second_order"] == "candidate"


def test_silence_is_inconclusive():
    found, coverage = _run(provider=Provider(hits=[]))
    assert found == []
    assert coverage.summary()["second_order"] == "inconclusive"


def test_no_provider_is_untestable():
    class Down:
        def available(self):
            return False
    found, coverage = _run(provider=Down())
    assert found == []
    assert coverage.summary()["second_order"] == "untestable"


def test_payload_shape():
    from main.budgets import BudgetTracker
    from main.config import Config
    from main.reporting.coverage import CoverageTracker
    from main.reporting.metrics import Metrics
    from main.scope import Scope
    from main.stages.validation import ProbeControls
    from main.stages.validation.second_order import blind_xss_probe
    from main.validation.evidence import EvidenceStore
    from types import SimpleNamespace
    from pathlib import Path
    import tempfile
    out = Path(tempfile.mkdtemp())
    cfg = Config()
    http = Http()
    blind_xss_probe(
        [_ep()], EvidenceStore(out / "proofs"), Metrics(),
        BudgetTracker(cfg), CoverageTracker(), http, cfg,
        Scope(cfg.scope), ProbeControls(),
        [SimpleNamespace(name="user_a", auth_headers={})],
        Provider())
    url, data = http.posts[0]
    assert url == "https://example.com/comment"
    assert data["text"].startswith('<script src="http')
    assert "tok-1" in data["text"]


def test_budget_blocked():
    from main.budgets import BudgetExceeded, BudgetTracker
    from main.config import Config
    from main.reporting.coverage import CoverageTracker
    from main.reporting.metrics import Metrics
    from main.scope import Scope
    from main.stages.validation import ProbeControls
    from main.stages.validation.second_order import blind_xss_probe
    from main.validation.evidence import EvidenceStore
    from types import SimpleNamespace
    from pathlib import Path
    import tempfile
    out = Path(tempfile.mkdtemp())
    cfg = Config()

    class Broke:
        def post(self, url, **kw):
            raise BudgetExceeded("cap")

    coverage = CoverageTracker()
    found = blind_xss_probe(
        [_ep()], EvidenceStore(out / "proofs"), Metrics(),
        BudgetTracker(cfg), coverage, Broke(), cfg,
        Scope(cfg.scope), ProbeControls(),
        [SimpleNamespace(name="user_a", auth_headers={})],
        Provider())
    assert found == []
    assert coverage.summary()["second_order"] == "blocked"
