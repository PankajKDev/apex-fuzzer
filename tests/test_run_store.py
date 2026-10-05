"""Tests for the SQLite run-audit store (no network)."""
import json
import sqlite3

from main.reporting.run_store import RunStore, SCHEMA_VERSION


def test_begin_record_finish_roundtrip(tmp_path):
    db = tmp_path / "apex.db"
    with RunStore(db) as store:
        run_id = store.begin_run("https://example.com", "example.com",
                                 "standard", "5.2.0",
                                 authorization_ref="ENG-1")
        assert run_id == 1
        n = store.record_denials(run_id, [
            {"url": "https://evil.com/", "method": "GET",
             "reason": "out_of_scope"},
            {"url": "https://example.com/logo.png", "method": "POST",
             "reason": "state_change_disabled"},
            "not-a-dict",
        ])
        assert n == 2
        store.finish_run(run_id)
        assert store.denial_counts(run_id) == {
            "out_of_scope": 1, "state_change_disabled": 1}
        run = store.latest_run("https://example.com")
        assert run["profile"] == "standard"
        assert run["authorization_ref"] == "ENG-1"
        assert run["finished_utc"] != ""
    # schema versioned + data survives reopen
    con = sqlite3.connect(str(db))
    assert con.execute(
        "SELECT version FROM schema_version").fetchone()[0] == \
        SCHEMA_VERSION
    assert con.execute(
        "SELECT COUNT(*) FROM scope_decisions").fetchone()[0] == 2
    con.close()


def test_empty_denials_and_unknown_target(tmp_path):
    with RunStore(tmp_path / "apex.db") as store:
        run_id = store.begin_run("https://example.com", "example.com",
                                 "passive", "5.2.0")
        assert store.record_denials(run_id, []) == 0
        assert store.denial_counts(run_id) == {}
        assert store.latest_run("https://missing.test") is None


def test_flush_run_audit_persists_denials(tmp_path):
    from main.config import Config
    from main.orchestrator import Orchestrator
    from main.profiles import get as get_profile
    import time
    orch = Orchestrator(Config(), tmp_path,
                        profile=get_profile("standard"))
    from main.stages.reporting import flush_run_audit
    flush_run_audit(tmp_path, "https://example.com", "example.com",
                    time.time(), [
                              {"url": "https://evil.com/", "method": "GET",
                               "reason": "out_of_scope"}],
                    orch.cfg, orch.profile, orch._last_endpoints)
    with RunStore(tmp_path / "apex.db") as store:
        run = store.latest_run("https://example.com")
        assert run is not None and run["tool_version"] != ""
        assert store.denial_counts(run["id"]) == {"out_of_scope": 1}


def test_endpoint_inventory_roundtrip(tmp_path):
    from main.models import Endpoint, Parameter
    eps = [Endpoint(url="https://example.com/api/u/1?x=1",
                    normalized_url="https://example.com/api/u/1?x=1",
                    host="example.com", path="/api/u/1", method="GET",
                    source=["recon", "har"],
                    endpoint_type="api",
                    query_parameters=[
                        Parameter(name="x", location="query",
                                  sample_value="s3cret")],
                    request_content_types=["application/json"])]
    with RunStore(tmp_path / "apex.db") as store:
        run_id = store.begin_run("https://example.com", "example.com",
                                 "standard", "5.2.0")
        assert store.record_endpoints(run_id, eps) == 1
        store.finish_run(run_id)
        rows = store.endpoints_for_run(run_id)
        assert len(rows) == 1
        row = rows[0]
        assert row["method"] == "GET"
        assert row["endpoint_type"] == "api"
        assert "har" in row["sources"]
        # names persist; sample values never do
        assert row["query_params"] == '["x"]'
        assert "s3cret" not in json.dumps(row)


def test_flush_persists_stashed_inventory(tmp_path):
    from main.config import Config
    from main.models import Endpoint
    from main.orchestrator import Orchestrator
    from main.profiles import get as get_profile
    import time
    orch = Orchestrator(Config(), tmp_path,
                        profile=get_profile("standard"))
    assert orch._last_endpoints == []
    orch._last_endpoints = [Endpoint(
        url="https://example.com/a", normalized_url="https://e.com/a",
        host="example.com", path="/a")]
    from main.stages.reporting import flush_run_audit
    flush_run_audit(tmp_path, "https://example.com", "example.com",
                    time.time(), [], orch.cfg, orch.profile,
                    orch._last_endpoints)
    with RunStore(tmp_path / "apex.db") as store:
        run = store.latest_run("https://example.com")
        rows = store.endpoints_for_run(run["id"])
        assert [r["normalized_url"] for r in rows] == \
            ["https://e.com/a"]
        assert json.loads(rows[0]["sources"]) == []


def test_flush_run_audit_never_fails_scan(tmp_path):
    from main.config import Config
    from main.orchestrator import Orchestrator
    from main.profiles import get as get_profile
    import time
    orch = Orchestrator(Config(), tmp_path,
                        profile=get_profile("standard"))
    # read-only directory: store cannot open, scan must continue
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0o500)
    try:
        from main.stages.reporting import flush_run_audit
        flush_run_audit(locked, "https://example.com",
                        "example.com", time.time(), [], orch.cfg,
                        orch.profile, orch._last_endpoints)
    finally:
        locked.chmod(0o700)


def _row(url, method="GET", etype="api", query="[]", body="[]",
         ct="[]"):
    return {"normalized_url": url, "method": method, "host": "e.com",
            "path": "/", "endpoint_type": etype, "sources": '["recon"]',
            "query_params": query, "body_params": body,
            "content_types": ct}


def test_endpoint_fingerprint_ignores_sources():
    from main.reporting.run_store import endpoint_fingerprint
    a = _row("https://e.com/a")
    b = dict(a, sources='["har"]')
    assert endpoint_fingerprint(a) == endpoint_fingerprint(b)
    c = dict(a, query_params='["id"]')
    assert endpoint_fingerprint(a) != endpoint_fingerprint(c)


def test_diff_new_changed_gone():
    from main.reporting.run_store import diff_endpoint_runs
    old = [_row("https://e.com/a"),
           _row("https://e.com/b", query='["id"]'),
           _row("https://e.com/gone")]
    new = [_row("https://e.com/a"),
           _row("https://e.com/b", query='["id", "verbose"]'),
           _row("https://e.com/fresh")]
    diff = diff_endpoint_runs(old, new)
    assert diff["baseline"] is False
    assert [r["normalized_url"] for r in diff["new"]] == \
        ["https://e.com/fresh"]
    assert [r["normalized_url"] for r in diff["gone"]] == \
        ["https://e.com/gone"]
    assert len(diff["changed"]) == 1
    assert diff["changed"][0]["url"] == "https://e.com/b"


def test_diff_empty_old_is_baseline():
    from main.reporting.run_store import diff_endpoint_runs
    diff = diff_endpoint_runs([], [_row("https://e.com/a")])
    assert diff["baseline"] is True
    assert diff["new"] == [] and diff["gone"] == [] \
        and diff["changed"] == []


def test_flush_writes_changes_against_previous_run(tmp_path):
    from main.config import Config
    from main.models import Endpoint
    from main.orchestrator import Orchestrator
    from main.profiles import get as get_profile
    from main.stages.reporting import flush_run_audit
    import time
    orch = Orchestrator(Config(), tmp_path,
                        profile=get_profile("standard"))
    orch._last_endpoints = [Endpoint(
        url="https://example.com/a", normalized_url="https://e.com/a",
        host="example.com", path="/a", endpoint_type="page")]
    first = flush_run_audit(tmp_path, "https://example.com",
                                  "example.com", time.time(), [],
                                  orch.cfg, orch.profile,
                                  orch._last_endpoints)
    assert first["baseline"] is True
    orch._last_endpoints = [Endpoint(
        url="https://example.com/a", normalized_url="https://e.com/a",
        host="example.com", path="/a", endpoint_type="api")]
    second = flush_run_audit(tmp_path, "https://example.com",
                                   "example.com", time.time(), [],
                                   orch.cfg, orch.profile,
                                   orch._last_endpoints)
    assert second["baseline"] is False
    assert len(second["changed"]) == 1
    assert second["against_run"] == 1
    on_disk = json.loads((tmp_path / "changes.json").read_text())
    assert len(on_disk["changed"]) == 1


def test_changes_block_renders_and_skips_baseline(tmp_path):
    from main.reporting.html import _changes_block, render_html
    assert _changes_block(None) == ""
    assert _changes_block({"baseline": True, "new": []}) == ""
    diff = {"baseline": False, "against_run": 1,
            "new": [_row("https://e.com/fresh")],
            "changed": [], "gone": []}
    block = _changes_block(diff)
    assert "Surface changes" in block and "fresh" in block
    out = tmp_path / "report.html"
    render_html(out, "e.com", [], [], {}, "info", tmp_path,
                changes=diff)
    assert "Surface changes" in out.read_text()
