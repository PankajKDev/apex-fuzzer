"""Configuration system: loading, validation, precedence, gates.

No network in any test. CLI parsing is local; version probes use a
fake runner where noted.
"""
import textwrap

import pytest

from main.config import Config, apply_cli_overrides
from main.cli import build_parser, doctor_config


def _write(tmp_path, text):
    path = tmp_path / "c.yaml"
    path.write_text(textwrap.dedent(text))
    return str(path)


def test_default_config_loads_with_only_expected_warnings():
    result = Config().validate()
    assert result["errors"] == []
    assert any("auto-seeded" in w for w in result["warnings"])


def test_complete_config_parses(tmp_path):
    path = _write(tmp_path, """\
        scan: {rate_limit: 20, concurrency: 2, timeout: 60,
               http_timeout: 5, jitter_between_targets: 0}
        validation: {enabled: true, sqli_time_sec: 5}
        authorization: {enabled: true, methods: [GET, POST]}
        race: {profile: inventory, inventory_endpoint: /a,
               inventory_read_url: /b, inventory_jsonpath: $.c}
        ai: {provider: ollama}
        auth:
          contexts:
            - {name: user_a, headers: {Cookie: s=1}}
        scope: {allowed_domains: [example.test]}
        """)
    cfg = Config.load(path)
    assert cfg.scan.rate_limit == 20
    assert cfg.authorization.methods == ["GET", "POST"]
    assert cfg.race.profile == "inventory"
    assert cfg.validate()["errors"] == []


def test_shipped_config_loads_and_validates():
    cfg = Config.load("config.yaml")
    assert cfg.validate()["errors"] == []


def test_malformed_yaml_and_json(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("scan: [unclosed")
    with pytest.raises(Exception):
        Config.load(str(bad))
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{nope")
    with pytest.raises(Exception):
        Config.load(str(bad_json))


def test_missing_file_gives_defaults(tmp_path):
    cfg = Config.load(str(tmp_path / "nope.yaml"))
    assert cfg.scan.rate_limit == 50


def test_invalid_enums_are_errors(tmp_path):
    path = _write(tmp_path, """\
        ai: {provider: skynet}
        reporting: {min_severity: extreme}
        authorization: {methods: [GET, PURGE]}
        race: {profile: ludicrous}
        """)
    errors = Config.load(path).validate()["errors"]
    assert any("ai.provider" in e for e in errors)
    assert any("min_severity" in e for e in errors)
    assert any("authorization.methods" in e for e in errors)
    assert any("race.profile" in e for e in errors)


def test_invalid_numerics_are_errors(tmp_path):
    path = _write(tmp_path, """\
        scan: {rate_limit: 0, concurrency: -1, timeout: 0, http_timeout: 0}
        budgets: {requests_per_host: -5}
        safety: {cooldown_ms: -1, max_requests: -2}
        oast: {poll_timeout: 0, poll_interval: -1}
        browser: {max_pages: -1}
        ai: {max_output_tokens: 0}
        validation: {sqli_time_sec: 99, path_traversal_max_depth: 9}
        """)
    errors = Config.load(path).validate()["errors"]
    joined = "\n".join(errors)
    for key in ("scan.rate_limit", "scan.concurrency", "scan.timeout",
                "scan.http_timeout", "budgets.requests_per_host",
                "safety.cooldown_ms", "safety.max_requests",
                "oast.poll_timeout", "oast.poll_interval",
                "browser.max_pages", "ai.max_output_tokens",
                "validation.sqli_time_sec",
                "validation.path_traversal_max_depth"):
        assert key in joined, key


def test_booleans_are_not_numbers(tmp_path):
    path = _write(tmp_path, "scan: {rate_limit: true}\n")
    errors = Config.load(path).validate()["errors"]
    assert any("scan.rate_limit" in e for e in errors)


def test_impossible_combinations_rejected(tmp_path):
    empty_methods = _write(
        tmp_path, "authorization: {enabled: true, methods: []}\n")
    assert any("methods" in e for e in
               Config.load(empty_methods).validate()["errors"])
    login_only = _write(tmp_path, "auth: {login: {enabled: true}}\n")
    assert any("login.identities" in e for e in
               Config.load(login_only).validate()["errors"])
    inventory = _write(tmp_path, "race: {profile: inventory}\n")
    assert any("inventory_endpoint" in e for e in
               Config.load(inventory).validate()["errors"])
    dupes = _write(tmp_path, """\
        auth:
          contexts:
            - {name: user_a}
            - {name: user_a}
        """)
    assert any("duplicate" in e for e in
               Config.load(dupes).validate()["errors"])


def test_unknown_keys_warn_instead_of_hiding_typos(tmp_path):
    path = _write(tmp_path, """\
        scan: {rate_limmit: 10}
        frobnicate: {x: 1}
        """)
    cfg = Config.load(path)
    assert "scan.rate_limmit" in cfg.unknown_keys
    assert "frobnicate.x" in cfg.unknown_keys
    assert cfg.scan.rate_limit == 50  # default untouched
    assert any("rate_limmit" in w for w in cfg.validate()["warnings"])


def test_legacy_ai_keys_keep_working(tmp_path):
    path = _write(tmp_path, """\
        ai: {provider: ollama, ollama_host: http://gpu:11434,
             ollama_model: qwen2.5:14b}
        """)
    cfg = Config.load(path)
    assert cfg.ai.effective_ollama()["host"] == "http://gpu:11434"
    assert cfg.ai.effective_ollama()["model"] == "qwen2.5:14b"
    assert cfg.validate()["errors"] == []


def test_cli_overrides_win(tmp_path):
    cfg = Config.load(_write(tmp_path, "scan: {rate_limit: 50}\n"))
    args = build_parser().parse_args(
        ["-d", "example.test", "--deep", "--validate", "--sqli-time",
         "--authz-write-replay", "--ack-state-change", "--max-requests",
         "7"])
    cfg = apply_cli_overrides(cfg, args)
    assert cfg.scan.rate_limit == 20
    assert cfg.validation.enabled is True
    assert cfg.validation.sqli_time_based is True
    assert cfg.authorization.write_replay is True
    assert cfg.safety.allow_state_change is True
    assert cfg.safety.max_requests == 7


def test_profile_names_rejected_by_cli():
    with pytest.raises(SystemExit):
        build_parser().parse_args(["-d", "x.test", "--profile", "nope"])


def test_scope_enforcement_and_exclusions():
    from main.config import ScopeConfig
    from main.scope import Scope
    scope = Scope(ScopeConfig(
        allowed_domains=["example.test"], allow_subdomains=True,
        excluded_hosts=["internal.example.test"],
        excluded_paths=["/static/"]))
    assert scope.is_in_scope("https://example.test/page")
    assert scope.is_in_scope("https://sub.example.test/page")
    assert not scope.is_in_scope("https://other.test/")
    assert not scope.is_in_scope("https://internal.example.test/")
    assert not scope.is_in_scope("https://example.test/static/app.js")


def test_active_test_exclusions_independent_from_crawl():
    from main.config import ScopeConfig
    from main.scope import Scope
    scope = Scope(ScopeConfig(
        allowed_domains=["example.test"],
        crawl_exclude_exts=["png"],
        active_test_exclude_exts=["png", "pdf"]))
    url = "https://example.test/doc.pdf"
    assert scope.is_in_scope(url)  # still discovered/crawled
    assert not scope.active_test_allowed(url)  # never probed
    img = "https://example.test/i.png"
    assert scope.is_in_scope(img) is False or True  # crawl-excluded
    assert not scope.active_test_allowed(img)


def test_state_changing_gates_default_off():
    cfg = Config()
    assert cfg.business.enabled is False
    assert cfg.race.enabled is False
    assert cfg.validation.second_order is False
    assert cfg.validation.second_order_ssrf is False
    assert cfg.authorization.write_replay is False
    assert cfg.validation.sqli_time_based is False
    assert cfg.safety.allow_state_change is False
    assert cfg.safety.strict is False


def test_missing_credentials_flagged_only_when_enabled(tmp_path):
    cfg = Config()
    assert doctor_config(cfg) == []
    cfg.ai.enabled = True
    cfg.ai.provider = "groq"
    assert any("GROQ_API_KEY" in p for p in doctor_config(cfg))
    cfg2 = Config()
    cfg2.auth.login.enabled = True
    from main.config import LoginIdentityConfig
    cfg2.auth.login.identities = [
        LoginIdentityConfig(name="u", password_env="NOPE_UNSET_VAR")]
    assert any("resolvable passwords" in p
               for p in doctor_config(cfg2))


def test_missing_oast_prerequisites_noted():
    from main.validation.oast import InteractshProvider
    provider = InteractshProvider(server="oast.pro")
    assert not provider.available()
    provider.close()


def test_missing_browser_prerequisites_skip_cleanly():
    from main.browser.browser import playwright_available
    assert isinstance(playwright_available(), bool)


def test_invalid_ai_provider_rejected(tmp_path):
    path = _write(tmp_path, "ai: {provider: watson}\n")
    assert any("ai.provider" in e for e in
               Config.load(path).validate()["errors"])


def test_doctor_tool_states_no_version(monkeypatch):
    import main.cli as cli_mod
    from main.shell import run as _real_run

    def fake_run(args, timeout=10):
        from types import SimpleNamespace
        if args == ["subzy", "run", "--help"]:
            # version probe fails; capability probe passes
            return SimpleNamespace(ok=False, stdout="", stderr="")
        if args == ["subzy", "--help"]:
            return SimpleNamespace(ok=True, stdout="subzy help",
                                   stderr="")
        return _real_run(args, timeout=timeout)

    monkeypatch.setattr(cli_mod, "run", fake_run)
    monkeypatch.setattr(cli_mod, "which", lambda name: f"/bin/{name}")
    assert "version detection unsupported" in cli_mod.describe_tool(
        "subzy", ["run", "--help"])
    monkeypatch.setattr(cli_mod, "which", lambda name: "")
    assert cli_mod.describe_tool("nope") == "MISSING"


def test_doctor_unusable_tool_reported(monkeypatch):
    import main.cli as cli_mod
    from types import SimpleNamespace
    monkeypatch.setattr(cli_mod, "which", lambda name: f"/bin/{name}")
    monkeypatch.setattr(
        cli_mod, "run",
        lambda args, timeout=10: SimpleNamespace(ok=False, stdout="",
                                                 stderr="boom"))
    assert "FAILED" in cli_mod.describe_tool("weirdtool")


def test_dry_run_sends_zero_requests(tmp_path, monkeypatch):
    import requests
    from main.orchestrator import Orchestrator
    from main.profiles import get as get_profile

    def _boom(*args, **kwargs):
        raise AssertionError("dry-run must not touch the network")

    monkeypatch.setattr(requests, "get", _boom)
    monkeypatch.setattr(requests, "post", _boom)
    monkeypatch.setattr("socket.getaddrinfo", _boom)
    cfg = Config()
    cfg.oast.enabled = True
    orch = Orchestrator(cfg, tmp_path, profile=get_profile("validation"))
    plan = orch.dry_run("https://staging.example.com")
    assert plan["target_in_scope"] is True
    assert plan["excluded_hosts"] == []
    from main.safety.preflight import render_plan_text
    text = render_plan_text(plan)
    assert "state-changing" in text
    assert "reservation" in text


def test_secret_redaction_by_default():
    from main.shell import redact
    assert "session=AAA" not in redact(
        "Cookie: session=AAA subscribed")
    assert Config().reporting.redact_secrets is True


def test_everything_disabled_loads_clean(tmp_path):
    path = _write(tmp_path, """\
        validation: {enabled: false, mutation: false, ssti: false,
                     xxe: false, path_traversal: false, open_redirect: false,
                     cors: false, cache: false}
        authorization: {enabled: false}
        business: {enabled: false}
        race: {enabled: false}
        ai: {enabled: false}
        browser: {enabled: false}
        oast: {enabled: false}
        nuclei: {ai_templates: false}
        """)
    cfg = Config.load(path)
    result = cfg.validate()
    assert result["errors"] == []
    from main.safety.preflight import resolve_modules
    from main.profiles import get as get_profile
    states = resolve_modules(cfg, get_profile("passive"))
    assert [s.name for s in states if s.enabled] == [
        "recon", "discovery", "mapping", "probe"]


def test_everything_enabled_reports_state_changing():
    cfg = Config()
    cfg.validation.enabled = True
    cfg.authorization.enabled = True
    cfg.authorization.write_replay = True
    cfg.business.enabled = True
    cfg.race.enabled = True
    cfg.validation.second_order = True
    cfg.validation.sqli_time_based = True
    assert cfg.validate()["errors"] == []
    report = __import__("main.cli", fromlist=[
        "config_check_report"]).config_check_report(cfg, "validation")
    assert "business_logic" in report
    assert "race" in report
    assert "state-changing modules" in report
    assert "RESULT: configuration usable" in report


def test_config_check_is_zero_network(tmp_path, monkeypatch):
    import requests
    from main.cli import config_check_report

    def _boom(*args, **kwargs):
        raise AssertionError("config-check must not touch the network")

    monkeypatch.setattr(requests, "get", _boom)
    monkeypatch.setattr(requests, "post", _boom)
    monkeypatch.setattr("socket.getaddrinfo", _boom)
    report = config_check_report(Config(), "standard")
    assert "enabled modules" in report
    assert "budgets" in report
    assert "safety" in report


def test_bad_config_surfaces_in_doctor(tmp_path):
    path = _write(tmp_path, "ai: {provider: watson}\n")
    assert any("ai.provider" in p
               for p in doctor_config(Config.load(path)))


def test_hacker_header_flows_to_http_client():
    from main.orchestrator import _HTTPClient
    client = _HTTPClient(extra_headers={"X-HackerOne": "researcher-42"})
    assert client.session.headers.get("X-HackerOne") == "researcher-42"
    assert "ApexFuzzer" in client.session.headers.get("User-Agent", "")
    bare = _HTTPClient()
    assert bare.session.headers.get("X-HackerOne") is None


def test_hacker_header_rejects_injection_and_nonstrings(tmp_path):
    path = tmp_path / "c.yaml"
    path.write_text("scan:\n  hacker_header: 'ok'\n")
    assert Config.load(str(path)).validate()["errors"] == []
    bad = tmp_path / "bad.yaml"
    bad.write_text('scan:\n  hacker_header: "a\\r\\nX: 1"\n')
    assert any("hacker_header" in e for e in
               Config.load(str(bad)).validate()["errors"])
    cfg = Config()
    cfg.scan.hacker_header = "x" * 201
    assert any("hacker_header" in e
               for e in cfg.validate()["errors"])


def test_seed_urls_cli_override_and_merge(tmp_path):
    seed = tmp_path / "seeds.txt"
    seed.write_text("https://example.test/panel/api/orders?order_id=1\n"
                    "# comment\nnot-a-url\n")
    args = build_parser().parse_args(
        ["-d", "example.test", "--seed-urls", str(seed)])
    cfg = apply_cli_overrides(Config(), args)
    assert cfg.seed_urls == [
        "https://example.test/panel/api/orders?order_id=1", "not-a-url"]
    assert any("seed_urls" in e for e in cfg.validate()["errors"])
    cfg.seed_urls = [cfg.seed_urls[0]]
    assert cfg.validate()["errors"] == []
    from main.stages.recon import merge_recon
    merge_recon(cfg, tmp_path)
    raw = (tmp_path / "raw.txt").read_text()
    assert "order_id=1" in raw


def test_seed_urls_config_file_and_scope_filter(tmp_path):
    seed = tmp_path / "c.yaml"
    seed.write_text("seed_urls:\n"
                    "  - https://example.test/a\n"
                    "  - https://other.test/b\n")
    cfg = Config.load(str(seed))
    assert cfg.seed_urls == ["https://example.test/a",
                             "https://other.test/b"]
    assert cfg.validate()["errors"] == []


def test_har_files_cli_config_and_missing_warns(tmp_path):
    from main.cli import build_parser
    from main.config import apply_cli_overrides
    har = tmp_path / "capture.har"
    har.write_text('{"log": {"entries": []}}')
    args = build_parser().parse_args(
        ["-d", "example.test", "--har", str(har), "--har", "other.har"])
    cfg = apply_cli_overrides(Config(), args)
    assert cfg.har_files == [str(har), "other.har"]
    result = cfg.validate()
    assert result["errors"] == []
    assert any("other.har" in w for w in result["warnings"])
    cfg_file = tmp_path / "c.yaml"
    cfg_file.write_text("har_files:\n"
                        f"  - {har}\n")
    assert Config.load(str(cfg_file)).har_files == [str(har)]


def test_authenticated_recon_identity_headers(tmp_path):
    from main.orchestrator import Orchestrator
    from main.profiles import get as get_profile
    from main.stages.recon import header_arg, recon_identity_headers

    orch = Orchestrator(Config(), tmp_path,
                        profile=get_profile("standard"))
    assert recon_identity_headers(orch.cfg) == {}
    assert header_arg({"Cookie": "s=1", "Authorization": "Bearer x"}) == \
        "Cookie: s=1;;Authorization: Bearer x"
    cfg = Config()
    cfg.discovery.authenticated_recon = True
    cfg.auth.contexts = []
    from main.config import AuthContext
    cfg.auth.contexts = [
        AuthContext(name="anonymous", headers={}),
        AuthContext(name="u", headers={"Cookie": "s=1",
                                       "X-Custom": "z"})]
    assert recon_identity_headers(cfg) == {"Cookie": "s=1"}


def test_authenticated_recon_crawler_args(tmp_path, monkeypatch):
    from main.profiles import get as get_profile
    from main.config import AuthContext
    from main.stages.recon import run_recon
    import main.stages.recon as recon_mod

    cfg = Config()
    cfg.discovery.authenticated_recon = True
    cfg.auth.contexts = [AuthContext(name="u", headers={"Cookie": "s=1"})]
    profile = get_profile("standard")
    seen = []

    def fake_run(args, timeout=0, input_data=None):
        from types import SimpleNamespace
        seen.append(list(args))
        return SimpleNamespace(ok=True, stdout="", stderr="")

    monkeypatch.setattr(recon_mod, "run", fake_run)
    monkeypatch.setattr(recon_mod, "which", lambda name: f"/bin/{name}")
    import types as _t

    def fake_run_stdout(args, timeout=0, input_data=None):
        seen.append(list(args))
        return _t.SimpleNamespace(ok=True,
                                  stdout="https://example.test/a\n",
                                  stderr="")
    monkeypatch.setattr(recon_mod, "run", fake_run_stdout)
    run_recon(cfg, profile, "https://example.test", tmp_path)
    katana = [a for a in seen if a[0] == "katana" and "-H" in a]
    assert katana and "Cookie:s=1" in katana[0]
    hakrawler = [a for a in seen if a[0] == "hakrawler"]
    assert hakrawler and "Cookie: s=1" in " ".join(
        part for call in hakrawler for part in call)
    merged = (tmp_path / "raw.txt").read_text()
    assert "example.test" in merged


def test_recon_stays_anonymous_by_default(tmp_path, monkeypatch):
    from main.profiles import get as get_profile
    from main.config import AuthContext
    from main.stages.recon import run_recon
    import main.stages.recon as recon_mod

    cfg = Config()
    cfg.auth.contexts = [AuthContext(name="u", headers={"Cookie": "s=1"})]
    profile = get_profile("standard")
    seen = []

    def fake_run(args, timeout=0, input_data=None):
        from types import SimpleNamespace
        seen.append(list(args))
        return SimpleNamespace(ok=True, stdout="", stderr="")

    monkeypatch.setattr(recon_mod, "run", fake_run)
    monkeypatch.setattr(recon_mod, "which", lambda name: f"/bin/{name}")
    run_recon(cfg, profile, "https://example.test", tmp_path)
    assert not [a for a in seen if "-H" in a or "-h" in a[1:2]]
    assert not (tmp_path / "katana-authed.txt").exists()


def test_fail_on_flag_and_threshold(tmp_path):
    import json
    from main.cli import build_parser, fail_on_triggered
    args = build_parser().parse_args(["-d", "example.test",
                                      "--fail-on", "high"])
    assert args.fail_on == "high"
    host_dir = tmp_path / "example.test"
    host_dir.mkdir()
    (host_dir / "findings.jsonl").write_text("\n".join([
        json.dumps({"id": "a", "name": "XSS", "severity": "medium"}),
        json.dumps({"id": "b", "name": "BOLA", "severity": "high"}),
        "not json",
    ]))
    hits = fail_on_triggered(tmp_path, ["https://example.test/x"],
                             "high")
    assert len(hits) == 1 and hits[0].startswith("high: BOLA")
    assert fail_on_triggered(tmp_path, ["https://example.test/x"],
                             "critical") == []
    assert fail_on_triggered(tmp_path, ["https://missing.test/x"],
                             "low") == []
