"""CLI entry point."""
import argparse
import re
import sys
from pathlib import Path
from colorama import Fore, Style, init as _ca_init
from . import __version__
from .config import Config, apply_cli_overrides
from .logging_setup import setup_logging, get_logger
from .shell import which, run
from .orchestrator import Orchestrator
from .profiles import get as get_profile

_ca_init(autoreset=True)

BANNER = f"""{Fore.MAGENTA}
 █████╗ ██████╗ ███████╗██╗  ██╗    ███████╗██╗   ██╗███████╗███████╗███████╗██████╗
██╔══██╗██╔══██╗██╔════╝╚██╗██╔╝    ██╔════╝██║   ██║╚══███╔╝╚══███╔╝██╔════╝██╔══██╗
███████║██████╔╝█████╗   ╚███╔╝     █████╗  ██║   ██║  ███╔╝   ███╔╝ █████╗  ██████╔╝
██╔══██║██╔═══╝ ██╔══╝   ██╔██╗     ██╔══╝  ██║   ██║ ███╔╝   ███╔╝  ██╔══╝  ██╔══██╗
██║  ██║██║     ███████╗██╔╝ ██╗    ██║     ╚██████╔╝███████╗███████╗███████╗██║  ██║
╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝    ╚═╝      ╚═════╝ ╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝
                        ⚡ Apex-Fuzzer v{__version__} — evidence-driven assessment
{Style.RESET_ALL}"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="apex-fuzzer",
                                description="Evidence-driven security assessment",
                                add_help=False)
    p.add_argument("-d", "--domain", help="Single domain")
    p.add_argument("-f", "--file", help="File with one target per line")
    p.add_argument("--scope-check", default=None, action="append",
                   metavar="URL",
                   help="Explain the scope decision for URL(s) and exit "
                        "(repeatable; zero network; exit 1 if any denied)")
    p.add_argument("--explain", default=None, metavar="FINDING-ID",
                   help="Explain every signal behind a finding ID from "
                        "a previous run (searches --output; zero network)")
    p.add_argument("--seed-urls", default=None,
                   help="File with manual seed URLs (one per line), "
                        "merged into discovery for every target")
    p.add_argument("--har", default=None, action="append",
                   help="HAR 1.2 capture to import into the endpoint "
                        "pool (repeatable; inventory only, no replay)")
    p.add_argument("--har-identity", default=None,
                   help="Auth context name active during the --har "
                        "capture (default: unattributed 'har')")
    p.add_argument("-c", "--config", help="Path to config.yaml")
    p.add_argument("--fast", action="store_true")
    p.add_argument("--deep", action="store_true")
    p.add_argument("--validate", action="store_true")
    p.add_argument("--ai", action="store_true",
                   help="Enable AI hypothesis planning")
    p.add_argument("--ai-provider", default=None,
                   choices=["gemini", "groq", "ollama"],
                   help="AI backend (default: config ai.provider)")
    p.add_argument("--oast", action="store_true",
                   help="Enable Interactsh OAST blind-SSRF confirmation")
    p.add_argument("--oast-callback-url", default=None,
                   help="Static HTTP callback collector base URL (local labs)")
    p.add_argument("--differential", action="store_true",
                   help="Enable differential auth-context (BOLA/IDOR) tests")
    p.add_argument("--second-order", action="store_true",
                   help="Enable stored-XSS correlation (persists canaries)")
    p.add_argument("--second-order-ssrf", action="store_true",
                   help="Enable stored-SSRF OAST correlation "
                        "(persists callback URLs)")
    p.add_argument("--upload", action="store_true",
                   help="Enable file-upload workflow review "
                        "(persists benign files; test accounts only)")
    p.add_argument("--business-logic", action="store_true",
                   help="Enable business-logic mutation engine")
    p.add_argument("--sqli-time", action="store_true",
                   help="Opt in to sqlmap time-based (delay) confirmation; "
                        "holds DB connections open, heaviest SQLi check")
    p.add_argument("--race", action="store_true",
                   help="Enable race-condition engine (aggressive)")
    p.add_argument("--authz-write-replay", action="store_true",
                   help="Replay observed mutating requests with swapped "
                        "IDs (test accounts only; needs --ack-state-change)")
    p.add_argument("--browser", action="store_true",
                   help="Enable browser-driven discovery (needs playwright)")
    p.add_argument("--no-browser", action="store_true",
                   help="Disable browser-driven discovery")
    p.add_argument("--strict", action="store_true",
                   help="Fail closed: stateful modules need authorization")
    p.add_argument("--auth-ref", default=None,
                   help="Authorization reference (strict mode)")
    p.add_argument("--ack-state-change", action="store_true",
                   help="Acknowledge state-changing tests (strict mode)")
    p.add_argument("--dry-run", action="store_true",
                   help="Print the preflight plan; send zero requests")
    p.add_argument("--max-requests", type=int, default=None,
                   help="Global request cap (budget)")
    p.add_argument("--max-state-changes", type=int, default=None,
                   help="Cap for mutating requests (budget)")
    p.add_argument("--stop-on-candidate", action="store_true",
                   help="Halt sweeps after the first strong candidate")
    p.add_argument("--cooldown-ms", type=int, default=None,
                   help="Delay between stateful probes")
    p.add_argument("--no-js", action="store_true")
    p.add_argument("--min-sev", default=None,
                   choices=["info", "low", "medium", "high", "critical"])
    p.add_argument("--fail-on", default=None,
                   choices=["info", "low", "medium", "high", "critical"],
                   help="CI mode: exit 1 when any finding meets the "
                        "severity (bounty mode stays exit 0 with a "
                        "report; refusals always exit 2)")
    p.add_argument("--regression", default=None,
                   help="Baseline directory holding a prior run "
                        "(same per-host layout): compare findings by "
                        "stable ID, write regression.json, exit 1 on "
                        "new findings at the --fail-on threshold "
                        "(medium when unset)")
    p.add_argument("--ci", action="store_true",
                   help="CI guardrail: requires --fail-on (exit 2 "
                        "without it) so pipelines always gate")
    p.add_argument("--resume", action="store_true")
    p.add_argument("--output", default="output")
    p.add_argument("--profile", default="standard",
                   choices=["passive", "standard", "deep",
                            "api", "authenticated",
                            "validation", "leads"],
                   help="Testing profile")
    p.add_argument("--doctor", action="store_true")
    p.add_argument("--config-check", action="store_true",
                   help="Validate configuration and report the effective "
                        "plan without sending any request")
    p.add_argument("--update", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("-h", "--help", action="help")
    return p


def describe_tool(name: str, version_args=None) -> str:
    """Four-state tool report: verified, unversioned, missing, or broken.

    Version-probe failure never implies a broken tool: a passing `--help`
    (or equivalent harmless probe) reports the install as present with
    version detection unsupported. Network-free: local subprocess only.
    """
    path = which(name) or ""
    if not path:
        return "MISSING"
    probe = run([name] + list(version_args or ["--version"]), timeout=10)
    if probe.ok:
        first = ((probe.stdout or probe.stderr) or "").strip().splitlines()
        detail = first[0][:120] if first else "ok"
        return f"present at {path} ({detail})"
    fallback = run([name, "--help"], timeout=10)
    if fallback.ok:
        return (f"present at {path} (version detection unsupported; "
                f"help probe passed)")
    return (f"present at {path} BUT FAILED its self-check "
            f"(not usable until fixed)")


def doctor():
    import logging
    setup_logging(logging.INFO)
    log = get_logger("doctor")
    # per-tool version probes: most tools answer --version, but some
    # (e.g. subzy) only support a harmless help subcommand. A failed
    # version probe is never treated as proof the tool is broken.
    version_args = {
        "subzy": ["run", "--help"],
        "tko-subs": ["-h"],
        "linkfinder": ["--help"],
        "arjun": ["--help"],
    }
    tools = ["nuclei", "httpx", "katana", "waybackurls", "gauplus",
             "hakrawler", "uro", "subzy", "sqlmap", "dalfox", "go",
             "arjun", "tko-subs", "linkfinder", "interactsh-client"]
    missing = 0
    for t in tools:
        log.info("%s — %s", t, describe_tool(t, version_args.get(t)))
        if not which(t):
            missing += 1
    ps = Path.home() / "ParamSpider" / "paramspider.py"
    if ps.exists():
        log.info("ParamSpider — present")
    else:
        log.warning("ParamSpider — missing")
        missing += 1
    if missing:
        log.warning("%d tools missing — run --update", missing)
    else:
        log.info("all tools present")
    # config + credentials + module prerequisites (no network)
    problems = doctor_config()
    for p in problems:
        log.warning("config: %s", p)
    try:
        notes = Config.load("config.yaml").validate()["warnings"]
    except Exception:
        notes = []
    for note in notes:
        log.info("config note: %s", note)
    sys.exit(0 if missing == 0 and not problems else 1)


def config_check_report(cfg, profile_name: str) -> str:
    """Zero-network configuration report (see --config-check)."""
    import os
    from .profiles import get as get_profile
    from .safety.preflight import resolve_modules
    lines = [f"Configuration check (profile: {profile_name})"]
    result = cfg.validate()
    for message in result["errors"]:
        lines.append(f"  {message}")
    for message in result["warnings"]:
        lines.append(f"  {message}")
    if not result["errors"] and not result["warnings"]:
        lines.append("  configuration valid, no diagnostics")
    try:
        profile = get_profile(profile_name)
    except Exception as exc:
        return "\n".join(lines + [f"  ERROR: unknown profile: {exc}"])
    states = resolve_modules(cfg, profile)
    on = [s for s in states if s.enabled]
    off = [s for s in states if not s.enabled]
    lines.append(f"  enabled modules ({len(on)}): " +
                 (", ".join(f"{s.name}[{s.level}]" for s in on) or "none"))
    lines.append("  disabled modules:")
    for s in off:
        lines.append(f"    - {s.name}: {s.reason}")
    stateful = [s.name for s in on if s.level in ("stateful", "burst")]
    claiming = [s.name for s in on if s.level == "claiming"]
    lines.append("  state-changing modules: " +
                 (", ".join(stateful) or "none enabled"))
    if claiming:
        lines.append("  external claiming modules: " + ", ".join(claiming))
    if cfg.validation.enabled or getattr(profile, "run_validation", False):
        validators = []
        if which("sqlmap"):
            validators.append("sqlmap")
        if which("dalfox"):
            validators.append("dalfox")
        lines.append("  active validators available: " +
                     (", ".join(validators) or
                      "none (sqlmap/dalfox missing)"))
    oast_ready = []
    if cfg.oast.callback_url:
        oast_ready.append(f"static collector {cfg.oast.callback_url}")
    if which("interactsh-client"):
        oast_ready.append("interactsh-client present")
    lines.append("  OAST: " + ("; ".join(oast_ready) or
                               "no provider configured/present"))
    contexts = list(getattr(cfg.auth, "contexts", []) or [])
    authed = [c.name for c in contexts if c.name != "anonymous"
              and dict(getattr(c, "headers", None) or {})]
    lines.append(f"  auth contexts: {len(contexts)} configured, "
                 f"{len(authed)} with credentials "
                 f"({', '.join(authed) or 'anonymous only'})")
    if getattr(cfg.auth.login, "enabled", False):
        missing_pw = [i.name for i in
                      (cfg.auth.login.identities or [])
                      if not os.environ.get(i.password_env or "", "")]
        lines.append("  login minting: " +
                     ("missing passwords for: " + ", ".join(missing_pw)
                      if missing_pw else "password env vars present"))
    if cfg.ai.enabled:
        import os as _os
        keyed = bool(_os.environ.get("GEMINI_API_KEY") or
                     _os.environ.get("GROQ_API_KEY"))
        lines.append(f"  AI: provider={cfg.ai.provider} model={cfg.ai.model} "
                     f"credentials={'present' if keyed else 'MISSING'}")
    else:
        lines.append("  AI: disabled")
    try:
        from .browser.browser import playwright_available
        browser_ok = playwright_available()
    except Exception:
        browser_ok = False
    browser_state = ("Playwright importable" if browser_ok else
                     "Playwright NOT importable (browser stages will skip)")
    lines.append(f"  browser: {browser_state}")
    scope = cfg.scope
    if scope.allowed_domains:
        lines.append("  scope allowlist: " +
                     ", ".join(scope.allowed_domains))
    else:
        lines.append("  scope allowlist: (empty — first target auto-seeds)")
    if scope.excluded_hosts:
        lines.append("  scope excluded hosts: " +
                     ", ".join(scope.excluded_hosts))
    if scope.excluded_paths:
        lines.append("  scope excluded paths: " +
                     ", ".join(scope.excluded_paths))
    lines.append(f"  budgets: {cfg.budgets.requests_per_host}/host, "
                 f"{cfg.budgets.requests_per_endpoint}/endpoint, "
                 f"max_requests={cfg.safety.max_requests}, "
                 f"max_state_changes={cfg.safety.max_state_changes}")
    safety = cfg.safety
    lines.append(f"  safety: strict={'on' if safety.strict else 'off'}, "
                 f"authorization_ref="
                 f"{'set' if safety.authorization_ref else 'MISSING'}, "
                 f"allow_state_change={safety.allow_state_change}, "
                 f"module_allowlist={list(safety.allowed_modules) or 'any'}")
    if result["errors"]:
        lines.append(f"  RESULT: {len(result['errors'])} error(s) — "
                     f"fix before scanning")
    else:
        lines.append("  RESULT: configuration usable")
    return "\n".join(lines)


def scope_check_report(cfg, urls) -> tuple:
    """Explain the scope decision for each URL (zero network).

    Returns (text, denied_any). IP policy (private ranges, DNS) is
    enforced per request at send time and always applies on top.
    """
    from .scope import Scope
    scope = Scope(cfg.scope)
    lines = ["Scope check (zero network — IP policy applies at send):"]
    denied = False
    for url in urls or []:
        allowed, reason = scope.check(url)
        active = scope.active_test_allowed(url) if allowed else False
        lines.append(f"  {'ALLOW' if allowed else 'DENY'} "
                     f"{reason} {url}"
                     + ("" if not allowed else
                        f" (active-test: {'yes' if active else 'no'})"))
        denied = denied or not allowed
    lines.append(f"RESULT: {'DENIED' if denied else 'all allowed'}")
    return "\n".join(lines), denied


def doctor_config(cfg=None) -> list:
    """Validate config, credentials presence, and module
    prerequisites without sending any request. Returns problems."""
    import os
    problems = []
    try:
        cfg = cfg or Config.load("config.yaml")
    except Exception as e:
        return [f"config.yaml unreadable: {e}"]
    for message in cfg.validate()["errors"]:
        problems.append(f"config: {message}")
    if cfg.ai.enabled:
        if cfg.ai.provider == "gemini" and not (
                os.environ.get("GEMINI_API_KEY") or
                os.environ.get("GROQ_API_KEY")):
            problems.append("ai.enabled with provider gemini but both "
                            "GEMINI_API_KEY and GROQ_API_KEY are empty")
        if cfg.ai.provider == "groq" and \
                not os.environ.get("GROQ_API_KEY"):
            problems.append("ai.enabled with provider groq but "
                            "GROQ_API_KEY is empty")
        if cfg.ai.provider not in ("gemini", "groq", "ollama"):
            problems.append(f"unknown ai.provider "
                            f"'{cfg.ai.provider}'")
    if (cfg.race.enabled or cfg.business.enabled
            or cfg.validation.second_order
            or cfg.validation.second_order_ssrf
            or cfg.authorization.enabled) and not cfg.safety.strict:
        problems.append("stateful modules enabled without strict "
                        "mode — add safety.strict or --strict for "
                        "controlled targets")
    if cfg.auth.login.enabled and not cfg.browser.enabled:
        problems.append("auth.login.enabled but browser discovery is "
                        "off — login needs Chromium "
                        "(pip install 'apex-fuzzer[browser]')")
    empty_pw = [i.name for i in cfg.auth.login.identities
                if not os.environ.get(i.password_env or "", "")]
    if cfg.auth.login.enabled and empty_pw:
        problems.append("login identities without resolvable "
                        f"passwords: {', '.join(empty_pw)}")
    try:
        Path("output").mkdir(parents=True, exist_ok=True)
        probe = Path("output") / ".doctor-write-test"
        probe.write_text("ok")
        probe.unlink()
    except Exception as e:
        problems.append(f"output dir not writable: {e}")
    return problems


def update():
    import logging
    from .shell import run
    setup_logging(logging.INFO)
    log = get_logger("update")
    go_tools = {
        "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
        "waybackurls": "github.com/tomnomnom/waybackurls@latest",
        "gauplus": "github.com/bp0lr/gauplus@latest",
        "hakrawler": "github.com/hakluke/hakrawler@latest",
        "dalfox": "github.com/hahwul/dalfox/v2@latest",
        "subzy": "github.com/PentestPad/subzy@latest",
        "tko-subs": "github.com/anshumanbh/tko-subs@latest",
        "interactsh-client": ("github.com/projectdiscovery/"
                              "interactsh/cmd/interactsh-client@latest"),
    }
    for tool, path in go_tools.items():
        if which(tool):
            log.info("%s already installed", tool)
            continue
        log.info("installing %s", tool)
        run(["go", "install", "-v", path], timeout=600)
    # Arjun (hidden parameter mining) + LinkFinder (JS params) are PyPI
    for tool in ("arjun", "linkfinder"):
        if which(tool):
            log.info("%s already installed", tool)
            continue
        log.info("installing %s via pip", tool)
        run(["pip", "install", "--quiet", tool], timeout=300)
    run(["nuclei", "-update-templates"], timeout=300)
    log.info("update complete")
    sys.exit(0)


def load_dotenv(path: "Path | str" = ".env") -> int:
    """Minimal .env loader (stdlib only, no dependency).

    Reads KEY=VALUE lines (ignores blanks/comments, strips matching
    quotes) and sets variables that are not already exported. Returns
    the number of variables set. Missing file → 0, never an error.
    """
    import os
    p = Path(path)
    if not p.exists():
        return 0
    loaded = 0
    for line in p.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip()
        if not key or not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
            continue
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
            val = val[1:-1]
        if key not in os.environ:
            os.environ[key] = val
            loaded += 1
    return loaded


_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3,
                  "critical": 4}


def ci_gate_error(args) -> str:
    """Usage error when --ci runs without its --fail-on gate."""
    if getattr(args, "ci", False) and not getattr(args, "fail_on",
                                                  None):
        return "--ci requires --fail-on so the pipeline gates " \
               "on findings"
    return ""


def fail_on_triggered(output_base, targets,
                      threshold: str) -> list[str]:
    """Findings at/above threshold after a run (CI gating).

    Reads each target's findings.jsonl (the same artifacts the report
    renders). Returns "severity: name (id)" lines for triage logs;
    empty means the gate passes. Never raises on missing files.
    """
    import json as _json
    from .scope import slug_host
    hits: list[str] = []
    rank = _SEVERITY_RANK.get((threshold or "").lower(), 4)
    for target in targets or []:
        host = slug_host((str(target or "").replace("http://", "")
                          .replace("https://", "").split("/")[0]))
        path = Path(output_base or "output") / host / "findings.jsonl"
        try:
            lines = path.read_text(errors="ignore").splitlines()
        except OSError:
            continue
        for line in lines:
            try:
                finding = _json.loads(line)
            except ValueError:
                continue
            if not isinstance(finding, dict):
                continue
            sev = str(finding.get("severity", "info")).lower()
            if _SEVERITY_RANK.get(sev, 0) >= rank:
                hits.append(f"{sev}: "
                            f"{finding.get('name', '')} "
                            f"({finding.get('id', '')})")
    return hits


def main():
    import logging
    load_dotenv()
    parser = build_parser()
    args = parser.parse_args()
    if args.doctor:
        doctor()
    if args.update:
        update()
    level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(level)
    log = get_logger("cli")
    print(BANNER)
    cfg = apply_cli_overrides(Config.load(args.config), args)
    if getattr(args, "config_check", False):
        print(config_check_report(cfg, args.profile))
        result = cfg.validate()
        sys.exit(1 if result["errors"] else 0)
    if getattr(args, "scope_check", None):
        text, denied = scope_check_report(cfg, args.scope_check)
        print(text)
        sys.exit(1 if denied else 0)
    if getattr(args, "explain", None):
        from .reporting.explain import explain_in_output_base
        text, found = explain_in_output_base(args.output,
                                             args.explain)
        print(text)
        sys.exit(0 if found else 1)
    problems = cfg.validate()
    for message in problems["warnings"]:
        log.warning("%s", message)
    if problems["errors"]:
        for message in problems["errors"]:
            log.error("%s", message)
        log.error("configuration has %d error(s); fix before scanning "
                  "(see --config-check)", len(problems["errors"]))
        sys.exit(1)
    try:
        from .safety.preflight import resolve_modules
        states = resolve_modules(cfg, get_profile(args.profile))
        enabled = [s.name for s in states if s.enabled]
        log.info("effective modules (%d): %s", len(enabled),
                 ", ".join(enabled) or "discovery only")
    except Exception as exc:
        log.debug("module listing failed: %s", exc)
    targets = []
    if args.domain:
        targets.append(args.domain)
    if args.file:
        fpath = Path(args.file)
        if not fpath.exists():
            log.error("target file not found: %s", fpath)
            sys.exit(1)
        targets.extend(l.strip() for l in fpath.read_text().splitlines()
                       if l.strip())
    if not targets:
        parser.print_help()
        sys.exit(1)
    orch = Orchestrator(cfg, Path(args.output),
                        profile=get_profile(args.profile))
    if args.dry_run:
        # zero network: plan only, one summary per target
        from .safety.preflight import render_plan_text
        for t in targets:
            plan = orch.dry_run(t)
            print(render_plan_text(plan))
            if plan["refusal"]:
                log.error("dry-run refusal for %s: %s", t,
                          "; ".join(plan["refusal"]))
        sys.exit(0)
    from .safety.preflight import install_signal_handlers
    install_signal_handlers()
    from .safety.authorization import AuthorizationRefused, EXIT_REFUSED
    try:
        orch.run(targets, resume=args.resume)
    except AuthorizationRefused as e:
        log.error("refused: %s", "; ".join(e.reasons))
        log.error("refusals exit code %d: provide --auth-ref, "
                  "--ack-state-change, approved domains/modules and a "
                  "valid window, or drop --strict", EXIT_REFUSED)
        sys.exit(EXIT_REFUSED)
    if (error := ci_gate_error(args)):
        log.error("%s", error)
        sys.exit(2)
    if getattr(args, "regression", None):
        from .reporting.regression import run_regression_gate
        code = run_regression_gate(args.regression, args.output,
                                   targets,
                                   args.fail_on or "medium")
        if code:
            sys.exit(code)
    if getattr(args, "fail_on", None):
        hits = fail_on_triggered(args.output, targets, args.fail_on)
        if hits:
            log.error("--fail-on %s: %d finding(s) at/above threshold",
                      args.fail_on, len(hits))
            for hit in hits[:20]:
                log.error("  %s", hit)
            sys.exit(1)
        log.info("--fail-on %s: gate passes (no findings at/above)",
                 args.fail_on)


if __name__ == "__main__":
    main()
