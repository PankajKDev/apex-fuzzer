"""CLI entry point."""
import argparse
import re
import sys
from pathlib import Path
from colorama import Fore, Style, init as _ca_init
from . import __version__
from .config import Config, apply_cli_overrides
from .logging_setup import setup_logging, get_logger
from .shell import which, tool_version
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
    p.add_argument("--business-logic", action="store_true",
                   help="Enable business-logic mutation engine")
    p.add_argument("--race", action="store_true",
                   help="Enable race-condition engine (aggressive)")
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
    p.add_argument("--resume", action="store_true")
    p.add_argument("--output", default="output")
    p.add_argument("--profile", default="standard",
                   choices=["passive", "standard", "deep",
                            "api", "authenticated",
                            "validation"],
                   help="Testing profile")
    p.add_argument("--doctor", action="store_true")
    p.add_argument("--update", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("-h", "--help", action="help")
    return p


def doctor():
    import logging
    setup_logging(logging.INFO)
    log = get_logger("doctor")
    tools = ["nuclei", "httpx", "katana", "waybackurls", "gauplus",
             "hakrawler", "uro", "subzy", "sqlmap", "dalfox", "go",
             "arjun", "tko-subs", "linkfinder", "interactsh-client"]
    missing = 0
    for t in tools:
        if which(t):
            log.info("%s — %s", t, tool_version(t) or "ok")
        else:
            log.warning("%s — MISSING", t)
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
    sys.exit(0 if missing == 0 and not problems else 1)


def doctor_config(cfg=None) -> list:
    """Validate config, credentials presence, and module
    prerequisites without sending any request. Returns problems."""
    import os
    problems = []
    try:
        cfg = cfg or Config.load("config.yaml")
    except Exception as e:
        return [f"config.yaml unreadable: {e}"]
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


if __name__ == "__main__":
    main()
