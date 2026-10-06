"""Hygiene batch: timestamps, HAR identity, regression/CI gates.

No network. UTC timestamps must not warn under -W error; HAR
shapes carry the configured identity; regression compares stable
finding IDs with threshold exit codes.
"""
import json
import warnings
from types import SimpleNamespace

from main.cli import ci_gate_error
from main.config import Config, apply_cli_overrides
from main.reporting import regression as reg_mod
from main.validation.evidence import EvidenceStore


def test_timestamp_has_no_deprecation_warning(tmp_path):
    from main.models import Finding
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        store = EvidenceStore(tmp_path / "p")
        finding = Finding(id="t1", source="test",
                          endpoint_url="https://example.test/",
                          matched_at="https://example.test/")
        sub = store.allocate(finding)
        store.record(finding, request_text="GET /",
                     response_text="ok")
    meta = json.loads((sub / "metadata.json").read_text())
    assert meta["timestamp"].endswith("Z")


def test_har_identity_tags_shapes():
    from main.discovery import har as har_mod
    data = {"log": {"entries": [{
        "request": {"method": "POST",
                    "url": "https://example.test/submit",
                    "headers": [{"name": "Content-Type",
                                 "value": "application/json"}],
                    "queryString": [],
                    "postData": {"mimeType": "application/json",
                                 "text": '{"a": 1}'}},
        "response": {"status": 200}}]}}
    default = har_mod.parse_har(data, None)
    assert default[0]["observed_requests"][0]["identity"] == "har"
    named = har_mod.parse_har(data, None, identity="user_a")
    assert named[0]["observed_requests"][0]["identity"] == "user_a"


def test_har_identity_config_and_validation(tmp_path):
    cfg = Config()
    assert cfg.har_identity == ""
    assert cfg.validate()["errors"] == []
    cfg.har_identity = "user_a"
    cfg.auth.contexts = [SimpleNamespace(name="user_a", headers={})]
    assert cfg.validate()["errors"] == []
    cfg.auth.contexts = []
    assert any("har_identity" in w
               for w in cfg.validate()["warnings"])
    bad = Config()
    bad.har_identity = "has\nnewline"
    assert any("har_identity" in e
               for e in bad.validate()["errors"])


def test_har_identity_cli_override():
    cfg = apply_cli_overrides(
        Config(), SimpleNamespace(har=None, har_identity="user_a",
                                  seed_urls=None))
    assert cfg.har_identity == "user_a"


def _row(id, severity="medium", status="strong_candidate"):
    return {"id": id, "severity": severity,
            "validation_status": status}


def test_compare_splits_new_gone_changed():
    base = {"a": _row("a"), "b": _row("b", "low"), "c": _row("c")}
    current = {"b": _row("b", "high"), "c": _row("c"), "d": _row("d")}
    out = reg_mod.compare_regressions(base, current)
    assert [r["id"] for r in out["new"]] == ["d"]
    assert [r["id"] for r in out["gone"]] == ["a"]
    assert [r["id"] for r in out["changed"]] == ["b"]
    assert out["changed"][0]["was"]["severity"] == "low"


def test_regression_exit_follows_threshold():
    assert reg_mod.regression_exit([_row("a", "high")], "medium") == 1
    assert reg_mod.regression_exit([_row("a", "low")], "medium") == 0
    assert reg_mod.regression_exit([], "info") == 0
    assert reg_mod.meets_threshold(_row("a", "info"), "bogus") is False


def test_baseline_path_prefers_nested_layout(tmp_path):
    nested = tmp_path / "base" / "h" / "findings.jsonl"
    nested.parent.mkdir(parents=True)
    nested.write_text("{}\n")
    assert reg_mod.baseline_path(tmp_path / "base", "h") == nested
    assert reg_mod.baseline_path(tmp_path / "base",
                                  "other") == tmp_path / "base" / \
        "findings.jsonl"


def test_run_regression_gate(tmp_path):
    base = tmp_path / "base" / "example.test"
    base.mkdir(parents=True)
    (base / "findings.jsonl").write_text(
        json.dumps(_row("old", "low")) + "\n")
    out = tmp_path / "out" / "example.test"
    out.mkdir(parents=True)
    (out / "findings.jsonl").write_text(
        json.dumps(_row("old", "low")) + "\n"
        + json.dumps(_row("new", "high")) + "\n")
    code = reg_mod.run_regression_gate(str(tmp_path / "base"),
                                       str(tmp_path / "out"),
                                       ["https://example.test"],
                                       "medium")
    assert code == 1
    artifact = json.loads((out / "regression.json").read_text())
    assert [r["id"] for r in artifact["new"]] == ["new"]
    assert [r["id"] for r in artifact["gone"]] == []
    clean = tmp_path / "out2" / "example.test"
    clean.mkdir(parents=True)
    (clean / "findings.jsonl").write_text(
        json.dumps(_row("old", "low")) + "\n")
    assert reg_mod.run_regression_gate(
        str(tmp_path / "base"), str(tmp_path / "out2"),
        ["https://example.test"], "medium") == 0
    assert reg_mod.run_regression_gate(
        str(tmp_path / "missing"), str(clean),
        ["https://example.test"], "medium") == 2


def test_ci_gate_requires_fail_on():
    assert ci_gate_error(SimpleNamespace(ci=True, fail_on=None))
    assert ci_gate_error(SimpleNamespace(ci=True,
                                         fail_on="high")) == ""
    assert ci_gate_error(SimpleNamespace(ci=False,
                                         fail_on=None)) == ""


def _graph(nodes):
    return {"nodes": [
        {"id": nid, "type": "endpoint" if nid.startswith("endpoint::")
         else "technology",
         "attrs": attrs} for nid, attrs in nodes], "edges": []}


def test_compare_graphs_tracks_endpoint_inventory():
    base = _graph([
        ("endpoint::https://example.test/a",
         {"url": "https://example.test/a", "method": "GET",
          "endpoint_type": "page"}),
        ("endpoint::https://example.test/gone",
         {"url": "https://example.test/gone", "method": "GET",
          "endpoint_type": "admin"}),
        ("tech:nginx", {}),
    ])
    current = _graph([
        ("endpoint::https://example.test/a",
         {"url": "https://example.test/a", "method": "GET",
          "endpoint_type": "page"}),
        ("endpoint::https://example.test/api/new",
         {"url": "https://example.test/api/new", "method": "POST",
          "endpoint_type": "api"}),
        ("tech:nginx", {}),
        ("tech:apache", {}),
    ])
    out = reg_mod.compare_graphs(base, current)
    assert [(r["url"], r["privileged"]) for r in
            out["added_endpoints"]] == [
        ("https://example.test/api/new", True)]
    assert [r["url"] for r in out["removed_endpoints"]] == [
        "https://example.test/gone"]
    assert out["other_changes"] == 0
    assert reg_mod.compare_graphs({}, {})["added_endpoints"] == []


def test_gate_merges_graph_delta(tmp_path):
    base = tmp_path / "base" / "example.test"
    base.mkdir(parents=True)
    (base / "findings.jsonl").write_text("")
    (base / "application_graph.json").write_text(json.dumps(_graph([
        ("endpoint::https://example.test/old",
         {"url": "https://example.test/old", "method": "GET",
          "endpoint_type": "page"})])))
    out = tmp_path / "out" / "example.test"
    out.mkdir(parents=True)
    (out / "findings.jsonl").write_text("")
    (out / "application_graph.json").write_text(json.dumps(_graph([
        ("endpoint::https://example.test/old",
         {"url": "https://example.test/old", "method": "GET",
          "endpoint_type": "page"}),
        ("endpoint::https://example.test/new",
         {"url": "https://example.test/new", "method": "GET",
          "endpoint_type": "page"})])))
    assert reg_mod.run_regression_gate(
        str(tmp_path / "base"), str(tmp_path / "out"),
        ["https://example.test"], "medium") == 0
    artifact = json.loads((out / "regression.json").read_text())
    assert [r["url"] for r in
            artifact["graph"]["added_endpoints"]] == [
        "https://example.test/new"]


def test_integrity_manifest_round_trip(tmp_path):
    from main.models import Finding
    from main.validation.evidence import EvidenceStore, verify_integrity
    store = EvidenceStore(tmp_path / "proofs")
    finding = Finding(id="t1", source="test",
                      endpoint_url="https://example.test/",
                      matched_at="https://example.test/")
    store.allocate(finding)
    store.record(finding, request_text="GET /", response_text="ok")
    dest = store.write_manifest()
    assert dest.name == "integrity.json"
    assert verify_integrity(tmp_path / "proofs") == {
        "ok": True, "mismatches": [], "reason": ""}


def test_integrity_detects_tampering(tmp_path):
    from main.models import Finding
    from main.validation.evidence import EvidenceStore, verify_integrity
    store = EvidenceStore(tmp_path / "proofs")
    finding = Finding(id="t1", source="test",
                      endpoint_url="https://example.test/",
                      matched_at="https://example.test/")
    sub = store.allocate(finding)
    store.record(finding, request_text="GET /", response_text="ok")
    store.write_manifest()
    (sub / "response.txt").write_text("forged")
    result = verify_integrity(tmp_path / "proofs")
    assert result["ok"] is False
    assert result["mismatches"] == ["finding-001/response.txt"]


def test_integrity_without_manifest_fails_closed(tmp_path):
    from main.validation.evidence import verify_integrity
    (tmp_path / "proofs").mkdir()
    result = verify_integrity(tmp_path / "proofs")
    assert result["ok"] is False
    assert "manifest" in result["reason"]
