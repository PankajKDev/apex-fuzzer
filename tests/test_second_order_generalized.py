"""Second-order generalization: stored SQLi/CMDi/SSTI/traversal.

Lifecycle nonces correlate injection to render; class signals tied
to our nonce are candidates, completed sweeps without one are
genuine negatives for that error oracle. No network here.
"""
from types import SimpleNamespace

from main.budgets import BudgetExceeded, BudgetTracker
from main.config import Config, ScopeConfig
from main.models import Endpoint, Parameter
from main.reporting.coverage import CoverageTracker
from main.reporting.metrics import Metrics
from main.scope import Scope
from main.stages.validation import ProbeControls
from main.stages.validation.second_order import (
    second_order_generalized_probe)
from main.validation import second_order as so_mod
from main.validation.evidence import EvidenceStore


def test_payloads_carry_nonce_and_gate_traversal():
    nonce = so_mod.make_stored_nonce()
    assert nonce.startswith("apexso-")
    assert so_mod.make_stored_nonce() != nonce
    payloads = dict(so_mod.stored_payloads(nonce))
    assert set(payloads) == {"sqli", "cmdi", "ssti"}
    assert nonce in payloads["sqli"]
    assert nonce in payloads["cmdi"]
    assert nonce in payloads["ssti"] and "49" not in payloads["ssti"]
    assert "{{7*7}}" in payloads["ssti"]
    gated = dict(so_mod.stored_payloads(nonce, "m/marker.txt"))
    assert "traversal" in gated
    assert "m/marker.txt" in gated["traversal"]


def test_sqli_signal_needs_markers_and_nonce():
    nonce = "apexso-abc123"
    err = f"You have an error in your SQL syntax near '{nonce}'"
    assert so_mod.classify_stored_signal("sqli", err, nonce) == "signal"
    assert so_mod.classify_stored_signal(
        "sqli", "You have an error in your SQL syntax", nonce) == "absent"
    assert so_mod.classify_stored_signal(
        "sqli", f"stored {nonce} safely", nonce) == "stored-inert"
    assert so_mod.classify_stored_signal("sqli", "clean page",
                                         nonce) == "absent"


def test_cmdi_signal_needs_markers_and_nonce():
    nonce = "apexso-abc123"
    assert so_mod.classify_stored_signal(
        "cmdi", f"sh: {nonce}: command not found", nonce) == "signal"
    assert so_mod.classify_stored_signal(
        "cmdi", "sh: x: command not found", nonce) == "absent"
    assert so_mod.classify_stored_signal(
        "cmdi", f"saved {nonce}", nonce) == "stored-inert"


def test_ssti_needs_adjacent_arithmetic_without_braces():
    nonce = "apexso-abc123"
    assert so_mod.classify_stored_signal(
        "ssti", f"result 49 for {nonce} here", nonce) == "signal"
    assert so_mod.classify_stored_signal(
        "ssti", "{{7*7}}" + nonce, nonce) == "stored-inert"
    far = f"price $49. {'.' * 200} ref {nonce}"
    assert so_mod.classify_stored_signal("ssti", far, nonce) in (
        "stored-inert", "absent")


def test_traversal_needs_marker_content():
    assert so_mod.classify_stored_signal(
        "traversal", "file: MARKER-SECRET-123", "apexso-x",
        "MARKER-SECRET-123") == "signal"
    assert so_mod.classify_stored_signal(
        "traversal", "file: nothing", "apexso-x",
        "MARKER-SECRET-123") == "absent"


def _form(path="/submit"):
    return Endpoint(url=f"https://example.test{path}",
                    normalized_url=f"https://example.test{path}",
                    host="example.test", path=path, method="POST",
                    endpoint_type="page",
                    body_parameters=[Parameter(name="comment",
                                               location="body")])


def _page(path):
    return Endpoint(url=f"https://example.test{path}",
                    normalized_url=f"https://example.test{path}",
                    host="example.test", path=path, method="GET",
                    endpoint_type="page")


def _scope():
    return Scope(ScopeConfig(allowed_domains=["example.test"]))


class _Http:
    def __init__(self, renders):
        self.renders = renders
        self.posts = []
        self.gets = []

    def post(self, url, **kwargs):
        self.posts.append(url)
        return SimpleNamespace(status_code=200, text="stored",
                               headers={})

    def get(self, url, **kwargs):
        self.gets.append(url)
        body = self.renders.get(url, "")
        return SimpleNamespace(status_code=200, text=body, headers={})


def _run(endpoints, http, cfg=None, scope=None, tmp_path=None):
    from pathlib import Path
    out = Path(str(tmp_path)) if tmp_path else Path("/tmp/so-test")
    out.mkdir(parents=True, exist_ok=True)
    cfg = cfg or Config()
    coverage = CoverageTracker()
    found = second_order_generalized_probe(
        endpoints, EvidenceStore(out / "proofs"), Metrics(),
        BudgetTracker(cfg), coverage, http, cfg, scope or _scope(),
        ProbeControls(), [SimpleNamespace(name="tester",
                                          auth_headers={})])
    return found, coverage


def test_stage_emits_per_class_findings(tmp_path, monkeypatch):
    http = _Http({
        "https://example.test/view":
            "You have an error in your SQL syntax near 'apexso-aaa111'",
    })
    monkeypatch.setattr(so_mod, "make_stored_nonce",
                        lambda: "apexso-aaa111")
    found, coverage = _run([_form(), _page("/view")], http,
                           tmp_path=tmp_path)
    sources = {f.source for f in found}
    assert "second-order-sqli" in sources
    assert len(http.posts) == 3  # sqli + cmdi + ssti, no marker
    assert coverage.summary()["second_order"] == "candidate"


def test_clean_sweep_is_negative(tmp_path):
    http = _Http({"https://example.test/view": "<p>clean</p>"})
    found, coverage = _run([_form(), _page("/view")], http,
                           tmp_path=tmp_path)
    assert found == []
    assert coverage.summary()["second_order"] == "tested_negative"


def test_failed_renders_are_inconclusive(tmp_path):
    class Broke(_Http):
        def get(self, url, **kwargs):
            raise ConnectionError("down")

    found, coverage = _run([_form(), _page("/view")],
                           Broke({}), tmp_path=tmp_path)
    assert found == []
    assert coverage.summary()["second_order"] == "inconclusive"


def test_sink_hints_render_first(tmp_path):
    order = []

    class Http(_Http):
        def get(self, url, **kwargs):
            order.append(url)
            return super().get(url, **kwargs)

    http = Http({"https://example.test/about": "x",
                 "https://example.test/preview": "y"})
    _run([_form(), _page("/about"), _page("/preview")], http,
         tmp_path=tmp_path)
    assert order[0] == "https://example.test/preview"


def test_budget_propagates():
    class Http:
        def post(self, *a, **k):
            raise BudgetExceeded("spent")

    try:
        so_mod.inject_stored_payload(
            Http(), _form(), {}, "tester", "v")
    except BudgetExceeded:
        return
    raise AssertionError("BudgetExceeded must propagate")


def test_reviews_map_generalized_sources():
    from main.models import Finding
    from main.reporting.reviews import finding_test_class
    for source, cls in (("second-order-sqli", "sqli"),
                        ("second-order-cmdi", "cmdi"),
                        ("second-order-ssti", "ssti"),
                        ("second-order-traversal", "traversal")):
        assert finding_test_class(
            Finding(id="a", source=source)) == cls


def test_plan_accounts_generalized_cost():
    from main.safety.preflight import plan_second_order_generalized
    assert plan_second_order_generalized(2, 5, 4).total == 48
