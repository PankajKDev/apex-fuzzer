"""Tests: SARIF export and finding explainer (no network)."""
import json


def _finding(**kw):
    base = {"id": "diff-abc", "source": "differential",
            "name": "BOLA/IDOR", "severity": "high",
            "confidence": "probable", "result_status": "candidate",
            "validation_status": "strong_candidate",
            "endpoint_url": "https://example.com/api/u/1",
            "matched_at": "https://example.com/api/u/1",
            "method": "GET", "parameter": "id",
            "description": "same shape for two users",
            "false_positive_notes": "check templates",
            "identity": "user_a+user_b",
            "raw": {"contexts": []},
            "evidence_dir": "output/example.com/proofs/finding-001"}
    base.update(kw)
    return base


def test_sarif_shape_and_levels():
    from main.reporting.sarif import export_sarif, level_for
    assert level_for("critical") == "error"
    assert level_for("high") == "error"
    assert level_for("medium") == "warning"
    assert level_for("low") == "note"
    assert level_for("bogus") == "note"
    log = export_sarif([_finding(),
                        _finding(id="n-2", source="nuclei-xss",
                                 severity="info",
                                 endpoint_url="https://e.com/x")],
                       "5.2.0")
    assert log["version"] == "2.1.0" and log["$schema"].startswith(
        "https://")
    run = log["runs"][0]
    assert run["tool"]["driver"]["name"] == "apex-fuzzer"
    assert run["tool"]["driver"]["version"] == "5.2.0"
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} == \
        {"differential", "nuclei-xss"}
    by_id = {r["partialFingerprints"]["finding-id/v1"]: r
             for r in run["results"]}
    assert by_id["diff-abc"]["level"] == "error"
    assert by_id["diff-abc"]["ruleId"] == "differential"
    assert by_id["diff-abc"]["locations"][0][
        "physicalLocation"]["artifactLocation"]["uri"] == \
        "https://example.com/api/u/1"
    assert by_id["diff-abc"]["properties"]["parameter"] == "id"
    assert by_id["n-2"]["level"] == "note"
    # malformed entries skipped, never fatal
    assert len(export_sarif([None, "x", _finding()],
                            "5.2.0")["runs"][0]["results"]) == 1


def test_write_sarif(tmp_path):
    from main.reporting.sarif import write_sarif
    dest = write_sarif(tmp_path, [_finding()], "5.2.0")
    assert dest.name == "sarif.json"
    assert json.loads(dest.read_text())["version"] == "2.1.0"


def test_explain_found_and_missing(tmp_path):
    from main.reporting.explain import explain_finding
    target = tmp_path / "example.com"
    target.mkdir()
    (target / "findings.jsonl").write_text(
        json.dumps(_finding()) + "\nnot json\n")
    text, found = explain_finding(target, "diff-abc")
    assert found is True
    for needle in ("BOLA/IDOR", "candidate", "high", "probable",
                   "https://example.com/api/u/1", "user_a+user_b",
                   "check templates", "Human checklist"):
        assert needle in text
    assert "Signals:" in text
    missing, found = explain_finding(target, "nope")
    assert found is False and "not found" in missing


def test_explain_searches_output_base(tmp_path):
    from main.reporting.explain import explain_in_output_base
    target = tmp_path / "example.com"
    target.mkdir()
    (target / "findings.jsonl").write_text(json.dumps(_finding()))
    text, found = explain_in_output_base(tmp_path, "diff-abc")
    assert found is True and "[example.com]" in text
    _, missing = explain_in_output_base(tmp_path, "nope")
    assert missing is False


def test_explain_cli_flag(tmp_path):
    from main.cli import build_parser
    args = build_parser().parse_args(["--explain", "diff-abc"])
    assert args.explain == "diff-abc"
