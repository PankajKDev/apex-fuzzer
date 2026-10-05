"""Tests: external tools only receive scope-filtered inputs.

httpx/nuclei follow redirects themselves (outside the gate), so the
tool must never hand them an out-of-scope starting line. No network,
no binaries in any test.
"""
from main.config import Config
from main.orchestrator import Orchestrator
from main.profiles import get as get_profile


def _orch(tmp_path):
    cfg = Config()
    cfg.scope.allowed_domains = ["example.com"]
    return Orchestrator(cfg, tmp_path, profile=get_profile("standard"))


def test_scoped_input_filters_and_preserves_source(tmp_path):
    orch = _orch(tmp_path)
    (tmp_path / "raw.txt").write_text(
        "https://example.com/a\nhttps://evil.com/b\nnot-a-url\n")
    dest = orch._scoped_subprocess_input(tmp_path, "raw.txt",
                                         "probe-input.txt")
    assert dest.read_text() == "https://example.com/a\n"
    # source file intact for audit/resume
    assert "evil.com" in (tmp_path / "raw.txt").read_text()


def test_scoped_input_missing_source(tmp_path):
    orch = _orch(tmp_path)
    dest = orch._scoped_subprocess_input(tmp_path, "raw.txt",
                                         "probe-input.txt")
    assert dest.read_text() == ""


def test_probe_live_fallback_uses_filtered_set(tmp_path, monkeypatch):
    import main.orchestrator as orch_mod
    orch = _orch(tmp_path)
    (tmp_path / "raw.txt").write_text(
        "https://example.com/a\nhttps://evil.com/b\n")
    monkeypatch.setattr(orch_mod, "which", lambda *a, **k: None)
    live = tmp_path / "live.txt"
    orch._probe_live(tmp_path, live)
    assert live.read_text() == "https://example.com/a\n"


def test_probe_live_httpx_receives_filtered_file(tmp_path, monkeypatch):
    import main.orchestrator as orch_mod
    orch = _orch(tmp_path)
    (tmp_path / "raw.txt").write_text(
        "https://example.com/a\nhttps://evil.com/b\n")
    seen = {}

    class R:
        timed_out = False

    def fake_run(args, **kw):
        seen["args"] = list(args)
        (tmp_path / "live.txt").write_text("https://example.com/a\n")
        return R()

    monkeypatch.setattr(orch_mod, "which", lambda *a, **k: "/bin/httpx")
    monkeypatch.setattr(orch_mod, "run", fake_run)
    live = tmp_path / "live.txt"
    orch._probe_live(tmp_path, live)
    flag = seen["args"].index("-l")
    fed = open(seen["args"][flag + 1]).read()
    assert fed == "https://example.com/a\n"
    assert live.read_text() == "https://example.com/a\n"


def test_probe_live_empty_scope_writes_empty(tmp_path):
    orch = _orch(tmp_path)
    (tmp_path / "raw.txt").write_text("https://evil.com/b\n")
    live = tmp_path / "live.txt"
    orch._probe_live(tmp_path, live)
    assert live.read_text() == ""


def test_nuclei_scoped_input(tmp_path):
    from main.detection.nuclei import NucleiRunner
    cfg = Config()
    cfg.scope.allowed_domains = ["example.com"]
    runner = NucleiRunner(cfg, tmp_path)
    live = tmp_path / "live.txt"
    live.write_text("https://example.com/a\nhttps://evil.com/b\n")
    dest = runner.scoped_input(live)
    assert dest.name == "nuclei-input.txt"
    assert dest.read_text() == "https://example.com/a\n"


def test_nuclei_run_scan_not_ready_runs_nothing(tmp_path, monkeypatch):
    from main.detection import nuclei as nuclei_mod
    from main.detection.nuclei import NucleiRunner
    cfg = Config()
    cfg.scope.allowed_domains = ["example.com"]
    runner = NucleiRunner(cfg, tmp_path)
    live = tmp_path / "live.txt"
    live.write_text("https://example.com/a\n")
    monkeypatch.setattr(NucleiRunner, "check_ready", lambda self: False)

    def explode(*a, **k):
        raise AssertionError("no subprocess when not ready")

    monkeypatch.setattr(nuclei_mod, "run", explode)
    assert runner.run_scan(live) == []
