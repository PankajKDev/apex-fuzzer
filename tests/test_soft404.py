"""Tests: soft-404 baseline clustering (no network)."""
from main.validation import soft404 as mod


class _Resp:
    def __init__(self, status, text, headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}


class FakeClient:
    def __init__(self, responses=None, exc=None):
        if responses is None:
            responses = []
        elif not isinstance(responses, list):
            responses = [responses]
        self._responses = list(responses)
        self.exc = exc
        self.urls = []

    def get(self, url, **kw):
        self.urls.append(url)
        if self.exc is not None:
            raise self.exc
        if len(self._responses) > 1:
            return self._responses.pop(0)
        return self._responses[0]


TEMPLATE = ("<html><head><title>Not Found</title></head>"
            "<body>Sorry, nothing here.</body></html>")


def test_consistent_template_baseline():
    client = FakeClient([_Resp(200, TEMPLATE)] * 4)
    base = mod.detect_soft404(client, "https://example.com/app")
    assert base is not None
    assert base.status == 200 and base.samples == 4
    assert base.title == "not found"
    assert all(u.startswith("https://example.com/apex-no-such-")
               for u in base.probe_urls)
    assert len({u for u in base.probe_urls}) == 4  # unique nonces
    assert mod.matches(base, _Resp(200, TEMPLATE)) is True
    assert mod.matches(base, _Resp(404, TEMPLATE)) is False
    assert mod.matches(base, _Resp(200, '{"id":1}')) is False


def test_varied_responses_yield_no_baseline():
    bodies = [TEMPLATE, TEMPLATE + "<!-- x -->", TEMPLATE, TEMPLATE]
    client = FakeClient([_Resp(200, b) for b in bodies])
    assert mod.detect_soft404(client, "https://example.com/") is None


def test_proper_404_baseline_matches_only_404s():
    bodies = ['{"error":"nope"}'] * 4
    client = FakeClient([_Resp(404, b) for b in bodies])
    base = mod.detect_soft404(client, "https://example.com/api")
    assert base is not None and base.status == 404
    assert mod.matches(base, _Resp(404, '{"error":"nope"}')) is True
    assert mod.matches(base, _Resp(200, '{"error":"nope"}')) is False


def test_probe_failure_is_not_a_baseline():
    client = FakeClient(exc=RuntimeError("timeout"))
    assert mod.detect_soft404(client, "https://example.com/") is None
    assert mod.matches(None, _Resp(200, TEMPLATE)) is False


def test_budget_propagates():
    from main.budgets import BudgetExceeded
    import pytest
    client = FakeClient(exc=BudgetExceeded("cap"))
    with pytest.raises(BudgetExceeded):
        mod.detect_soft404(client, "https://example.com/")


def test_title_normalization():
    assert mod._title_of("<TITLE>  Hello\nWorld </TITLE>") == "hello world"
    assert mod._title_of("no title here") == ""


def test_mapping_records_baseline_and_tags_hits(tmp_path):
    import json
    from main.config import Config
    from main.models import Endpoint
    from main.reporting.metrics import Metrics
    from main.stages.mapping import map_attack_surface
    from main.scope import Scope

    class Http:
        def get(self, url, **kw):
            class R:
                status_code = 200
                text = TEMPLATE
                headers = {"content-type": "text/html"}
            return R()

    cfg = Config()
    ep = Endpoint(url="https://example.com/app", normalized_url="x",
                  host="example.com", path="/app", method="GET")
    profile = type("P", (), {"param_mining": False,
                             "js_analysis": False})()
    page_ids = map_attack_surface(
        [ep], "example.com", tmp_path, Metrics(), Http(), cfg,
        profile, Scope(cfg.scope))
    assert page_ids == []
    artifact = json.loads((tmp_path / "soft404.json").read_text())
    assert artifact["baseline"]["status"] == 200
    assert artifact["matched_fetched_urls"] == [
        "https://example.com/app"]
