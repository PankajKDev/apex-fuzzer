"""Self-audit regression tests: the tool must not leak, escape,
or execute unsafely. No network. Tiny real subprocesses only
(/bin/echo-equivalent via sys.executable).
"""
import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

from main.browser.sessions import BrowserSession, SessionManager
from main.config import Config, ScopeConfig
from main.detection import nuclei as nuclei_mod
from main.models import Finding
from main.plugins.adapters import SqliPlugin
from main.plugins.base import TestTarget, TestContext
from main.scope import Scope, slug_filename, slug_host
from main.shell import _scrubbed_env, redact, redact_argv, run
from main.validation import sqli as sqli_mod
from main.validation import xss as xss_mod
from main.validation.base import Candidate


def _scope():
    return Scope(ScopeConfig(allowed_domains=["example.test"]))


# ── argv / env secrecy ──────────────────────────────────────────────
def test_redact_argv_masks_secret_values():
    logged = redact_argv(["tko-subs", "-domains", "h.txt",
                          "-takeover", "-githubtoken", "ghp_REAL123456"])
    assert "ghp_REAL123456" not in logged
    assert "-githubtoken ***" in logged
    assert "-domains h.txt" in logged


def test_redact_argv_masks_header_values():
    logged = redact_argv(["katana", "-H", "Cookie: session=ABCDEF123456"])
    assert "ABCDEF123456" not in logged
    assert "-H ***" in logged


def test_scrubbed_env_drops_secrets_keeps_path():
    env = _scrubbed_env({"PATH": "/usr/bin", "HOME": "/root",
                         "GEMINI_API_KEY": "x", "GITHUB_TOKEN": "y",
                         "APP_SECRET": "z", "DB_PASSWORD": "w"})
    assert env == {"PATH": "/usr/bin", "HOME": "/root"}


def test_child_process_cannot_see_secret_env():
    code = ("import os; print(os.environ.get("
            "'APEX_SELFTEST_TOKEN', 'absent'))")
    res = run([sys.executable, "-c", code], timeout=30,
              env={"APEX_SELFTEST_TOKEN": "s3cr3t-should-not-leak",
                   "PATH": os.environ.get("PATH", "/usr/bin")})
    assert res.stdout.strip() == "absent"


# ── path safety ─────────────────────────────────────────────────────
def test_slug_host_preserves_readable_hosts():
    assert slug_host("example.com") == "example.com"
    assert slug_host("127.0.0.1:18923") == "127.0.0.1:18923"


def test_slug_host_neutralizes_escape():
    assert slug_host("..") == "target"
    assert slug_host("") == "target"
    assert not slug_host("/etc/cron.d").startswith("/")
    assert ".." not in slug_host("../evil").split("/")


def test_slug_filename_neutralizes_traversal():
    # dots survive but slashes never do: always one path part,
    # never an exact dot-entry
    assert slug_filename("../../evil") == ".._.._evil"
    assert "/" not in slug_filename("../../evil")
    assert slug_filename("../../evil") not in ("", ".", "..")
    assert slug_filename("") == "unnamed"


def test_session_save_is_slugged_and_private(tmp_path):
    mgr = SessionManager(tmp_path)
    dest = mgr.save(BrowserSession(
        identity="../../evil", cookies=[{"name": "s", "value": "v"}]))
    assert dest.parent == tmp_path
    assert dest.name not in ("", ".", "..")
    assert "/" not in dest.name
    mode = stat.S_IMODE(os.stat(dest).st_mode)
    assert mode == 0o600


# ── tempdir isolation ───────────────────────────────────────────────
def test_sqlmap_avoids_shared_tmp_dir(monkeypatch, tmp_path):
    monkeypatch.setattr(sqli_mod, "which", lambda _: "/usr/bin/sqlmap")
    seen = {}

    def fake_run(args, timeout):
        for arg in args:
            if str(arg).startswith("--output-dir="):
                seen["dir"] = str(arg).split("=", 1)[1]
        return SimpleNamespace(stdout="", stderr="")
    monkeypatch.setattr(sqli_mod, "run", fake_run)
    finding = Finding(id="sq1", source="nuclei", method="GET",
                      parameter="q",
                      endpoint_url="https://example.test/search?q=1",
                      matched_at="https://example.test/search?q=1")
    target = TestTarget("https://example.test/search?q=1",
                        parameter="q", method="GET", finding=finding,
                        endpoint=None, test_class="sqli")
    ctx = TestContext(Config(), http=SimpleNamespace(),
                      scope=_scope())
    SqliPlugin().run(target, ctx)
    assert seen["dir"] != "/tmp/sqlmap"
    assert "apex-sqlmap-" in seen["dir"]
    assert not Path(seen["dir"]).exists()  # cleaned up after the run


def test_arjun_avoids_shared_tmp_dir(monkeypatch, tmp_path):
    import main.discovery.param_miner as miner
    monkeypatch.setattr(miner, "arjun_available", lambda: True)
    monkeypatch.setattr(
        miner, "run",
        lambda args, timeout: SimpleNamespace(timed_out=False,
                                             stdout="", stderr=""))
    out = miner.mine_hidden_params("https://example.test/?a=1",
                                   out_dir=None)
    assert out == {}
    assert not Path("/tmp/arjun-0.json").exists()


# ── tool-input guards ───────────────────────────────────────────────
def test_dalfox_rejects_flag_shaped_path(monkeypatch, tmp_path):
    monkeypatch.setattr(xss_mod, "which", lambda _: "/usr/bin/dalfox")

    def fake_run(args, timeout):
        if len(args) > 1 and args[1] in {"version", "--version"}:
            return SimpleNamespace(ok=True, stdout="Dalfox v2.13.0",
                                   stderr="")
        raise AssertionError("must not execute")

    monkeypatch.setattr(xss_mod, "run", fake_run)
    candidate = Candidate(
        finding=Finding(id="xss-test", source="test",
                        evidence_dir=str(tmp_path)),
        test_class="xss",
        endpoint_url="-x?q=hello", parameter="q")
    result = xss_mod.XssValidator(Config()).validate(candidate)
    assert result.status == "inconclusive"
    assert "plain http(s) URL" in result.notes


def test_ai_template_rejects_crlf_url():
    from main.models import Hypothesis
    bad = Hypothesis(hypothesis="x", endpoint="https://a.com/\r\nEvil: 1",
                     reason="y", test_class="xss", confidence=0.5)
    assert nuclei_mod.generate_template_for_hypothesis(
        bad, "https://a.com/\r\nEvil: 1") is None
    spaced = Hypothesis(hypothesis="x", endpoint="https://a.com/a b",
                        reason="y", test_class="xss", confidence=0.5)
    assert nuclei_mod.generate_template_for_hypothesis(
        spaced, "https://a.com/a b") is None


def test_ai_template_dir_is_cleaned(tmp_path):
    tdir = tmp_path / "ai-templates"
    tdir.mkdir()
    (tdir / "ai-gen-deadbeef.json").write_text("{}")
    runner = SimpleNamespace(
        output_dir=tmp_path,
        cfg=SimpleNamespace(scope=_scope()))
    out = nuclei_mod.run_hypothesis_templates(
        runner, [], tmp_path / "live.txt")
    assert out == []
    assert not (tdir / "ai-gen-deadbeef.json").exists()


def test_takeover_output_is_redacted():
    assert "ghp_REAL123456" not in redact(
        "CNAME x token=ghp_REAL123456 done")
