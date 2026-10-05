"""Tests: operator review marks (feedback loop)."""
import json

from main.reporting.reviews import (
    REVIEW_FALSE, REVIEW_TRUE, finding_test_class, load_reviews,
    resolve_finding_triples)


def _write(path, lines):
    path.write_text("\n".join(
        l if isinstance(l, str) else json.dumps(l) for l in lines))


def test_load_and_triple_match(tmp_path):
    p = tmp_path / "reviews.jsonl"
    _write(p, [
        {"finding_id": "diff-abc", "verdict": "false_positive",
         "reason": "login wall", "test_class": "authz",
         "endpoint": "https://example.com/api/u/1", "parameter": "id"},
        {"verdict": REVIEW_TRUE, "finding_id": "nuc-1"},
        {"verdict": "maybe", "finding_id": "x"},
        "not json{",
        "",
    ])
    index = load_reviews(p)
    assert len(index) == 2
    assert index.verdict_for_finding("diff-abc")["verdict"] == \
        REVIEW_FALSE
    assert index.is_fp_triple("AUTHZ", "https://example.com/api/u/1",
                              "ID")
    assert not index.is_fp_triple("authz",
                                  "https://example.com/api/u/1", "other")
    # TP marks never suppress probing
    assert not index.is_fp_triple("", "", "")


def test_missing_file_is_empty_index(tmp_path):
    assert len(load_reviews(tmp_path / "reviews.jsonl")) == 0


def test_triple_canonicalization():
    import main.reporting.reviews as rev
    assert rev.canonical_test_class("BOLA") == "authz"
    assert rev.canonical_test_class("idor") == "authz"
    assert rev.canonical_test_class("SQLi") == "sqli"
    assert rev.canonical_triple_url(
        "https://EXAMPLE.com/api/u/1?id=9#frag") == \
        "https://example.com/api/u/1"
    idx = rev.ReviewIndex()
    idx.triples.add(("authz", "https://example.com/api/u/1", "id"))
    assert idx.is_fp_triple("bola", "https://example.com/api/u/1?x=1",
                            "ID")


def test_resolve_finding_id_to_triple():
    from main.models import Finding
    import main.reporting.reviews as rev
    f = Finding(id="diff-abc", source="differential",
                endpoint_url="https://example.com/api/u/1",
                parameter="id")
    idx = rev.ReviewIndex()
    idx.by_finding["diff-abc"] = {"verdict": "false_positive",
                                  "reason": ""}
    assert resolve_finding_triples(idx, [f]) == 1
    assert idx.is_fp_triple("authz", "https://example.com/api/u/1",
                            "id")


def test_finding_test_class_mapping():
    from main.models import Finding
    assert finding_test_class(
        Finding(id="a", source="prescreen-sqli")) == "sqli"
    assert finding_test_class(
        Finding(id="b", source="nuclei-x", tags=["CORS"])) == "cors"
    assert finding_test_class(Finding(id="c", source="mystery")) == ""


def test_apply_reviews_marks_findings(tmp_path):
    from main.models import Finding
    from main.orchestrator import Orchestrator
    _write(tmp_path / "reviews.jsonl", [
        {"finding_id": "diff-abc", "verdict": "false_positive",
         "reason": "login wall"}])
    f = Finding(id="diff-abc", source="differential")
    assert Orchestrator._apply_reviews([f], tmp_path) == 1
    assert "Operator review (false_positive): login wall" in \
        f.false_positive_notes
    assert f.raw["review"]["verdict"] == "false_positive"


def test_prescreen_skips_fp_triples(tmp_path):
    from main.budgets import BudgetTracker
    from main.config import Config
    from main.models import Endpoint, Parameter
    from main.orchestrator import Orchestrator
    from main.profiles import get as get_profile
    from main.reporting.coverage import CoverageTracker
    from main.reporting.metrics import Metrics
    from main.validation.evidence import EvidenceStore
    import main.reporting.reviews as rev
    cfg = Config()
    cfg.validation.enabled = True
    orch = Orchestrator(cfg, tmp_path, profile=get_profile("standard"))
    idx = rev.ReviewIndex()
    idx.triples.add(("sqli", "https://example.com/api/u/1", "id"))
    idx.triples.add(("xss", "https://example.com/api/u/1", "id"))
    ep = Endpoint(url="https://example.com/api/u/1",
                  normalized_url="https://example.com/api/u/1",
                  host="example.com", path="/api/u/1",
                  method="GET", endpoint_type="api",
                  query_parameters=[
                      Parameter(name="id", location="query")])
    coverage = CoverageTracker()
    out = orch._prescreen_sweep(
        [ep], [], EvidenceStore(tmp_path), Metrics(),
        BudgetTracker(cfg), coverage, object(), idx)
    assert out == []
    flat = json.dumps(coverage.to_dict())
    assert "operator-marked false positive" in flat


def test_plugin_loop_suppression_by_finding_id():
    from main.models import Finding
    from main.orchestrator import Orchestrator
    import main.reporting.reviews as rev
    idx = rev.ReviewIndex()
    idx.by_finding["diff-abc"] = {"verdict": "false_positive",
                                  "reason": "login wall"}
    f = Finding(id="diff-abc", source="differential",
                endpoint_url="https://example.com/other",
                parameter="other")
    reason = Orchestrator._fp_suppression_reason(f, "authz", idx)
    assert "diff-abc" in reason and "login wall" in reason
    # true-positive marks never suppress
    idx.by_finding["diff-abc"] = {"verdict": "true_positive",
                                  "reason": ""}
    assert Orchestrator._fp_suppression_reason(f, "authz", idx) == ""


def test_plugin_loop_suppression_by_rotating_swap_id():
    from main.models import Finding
    from main.orchestrator import Orchestrator
    import main.reporting.reviews as rev
    idx = rev.ReviewIndex()
    # swap IDs embed victim values, so they rotate per run: the
    # triple (not the ID) is what sticks (stored canonical form).
    idx.triples.add(("authz", "https://example.com/api/u/1", "id"))
    f = Finding(id="swap-NEWVICTIM", source="idor-swap",
                endpoint_url="https://example.com/api/u/1?id=9",
                parameter="id")
    reason = Orchestrator._fp_suppression_reason(f, "", idx)
    assert "authz https://example.com/api/u/1::id" in reason


def test_plugin_loop_no_suppression_without_marks():
    from main.models import Finding
    from main.orchestrator import Orchestrator
    import main.reporting.reviews as rev
    f = Finding(id="swap-x", source="idor-swap",
                endpoint_url="https://example.com/api/u/1",
                parameter="id")
    assert Orchestrator._fp_suppression_reason(
        f, "authz", rev.ReviewIndex()) == ""
    assert Orchestrator._fp_suppression_reason(f, "authz", None) == ""
