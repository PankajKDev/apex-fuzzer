"""Active parameter mining with Arjun + passive LinkFinder (spec §1).

Arjun tests GET, POST (form) and JSON parameters against its ~26k
wordlist using binary-split anomaly detection. It surfaces hidden
parameters that exist server-side but are referenced nowhere in public
HTML or JS — the usual hiding place for IDOR, mass assignment and SSRF.

Arjun JSON output format (per method run)::

    {"https://host/path": {"params": ["a", "b"],
                          "method": "GET", "headers": {...}}}
"""
import json
import re
from pathlib import Path
from typing import Dict, List, Optional
from ..shell import run, which
from ..logging_setup import get_logger

log = get_logger("param_miner")

# location per arjun method: GET→query, POST/JSON/PUT→body
_METHOD_LOCATION = {"GET": "query", "POST": "body", "JSON": "body",
                    "XML": "body", "PUT": "body", "HEADERS": "header"}


def arjun_available() -> bool:
    return which("arjun") is not None


def parse_arjun_json(text: str, url: str) -> List[str]:
    """Parse one arjun -oJ file → list of parameter names for ``url``."""
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    entry = data.get(url)
    if not isinstance(entry, dict):
        # tolerate url-variant keys (stable-mode may normalize the url)
        for k, v in data.items():
            if isinstance(v, dict) and v.get("params"):
                entry = v
                break
    if not isinstance(entry, dict):
        return []
    params = entry.get("params") or []
    return [str(p) for p in params if p]


def mine_hidden_params(url: str, methods: Optional[List[str]] = None,
                       out_dir: Optional[Path] = None,
                       timeout: int = 180, stable: bool = False,
                       rate_limit: Optional[int] = None,
                       threads: int = 5) -> Dict[str, List[str]]:
    """Run Arjun against a single endpoint.

    Returns ``{method: [param, ...]}`` (only methods that found params,
    or an empty dict when arjun is missing / found nothing).
    """
    if not arjun_available():
        log.debug("arjun not installed — skipping hidden param mining")
        return {}
    methods = [m.upper() for m in (methods or ["GET"])]
    tmp_output = None
    if out_dir is None:
        import tempfile
        # Private per-call directory: never predictable /tmp paths
        # shared between local users (symlink/file races).
        tmp_output = tempfile.TemporaryDirectory(prefix="apex-arjun-")
        out_dir = Path(tmp_output.name)
    out_dir.mkdir(parents=True, exist_ok=True)
    result: Dict[str, List[str]] = {}
    try:
        for i, method in enumerate(methods):
            json_path = out_dir / f"arjun-{i}.json"
            if json_path.exists():
                json_path.unlink()
            args = ["arjun", "-u", url, "-m", method,
                    "-oJ", str(json_path),
                    "-t", str(threads), "-q"]
            if stable:
                args.append("--stable")
            if rate_limit:
                args += ["--rate-limit", str(rate_limit)]
            log.info("arjun: %s %s (timeout=%ds%s)", method, url, timeout,
                     ", stable" if stable else "")
            r = run(args, timeout=timeout)
            if r.timed_out:
                log.warning("arjun %s %s timed out", method, url)
            if json_path.exists():
                found = parse_arjun_json(
                    json_path.read_text(errors="ignore"), url)
                if found:
                    result[method] = found
                    log.info("arjun %s %s: %d hidden params: %s",
                             method, url, len(found),
                             ", ".join(found[:12]))
    finally:
        if tmp_output is not None:
            tmp_output.cleanup()
    return result


def linkfinder_params(js_files: List[Path], host: str,
                      out_dir: Path, timeout: int = 120) -> List[str]:
    """Passive JS parameter extraction via LinkFinder (spec §1, Gaia-style).

    Best-effort: LinkFinder writes under ``data/<host>/`` relative to its
    cwd, so we run it in a scratch dir and parse whatever txt/json it
    leaves there. Returns a deduplicated list of parameter names.
    """
    if not which("linkfinder") or not js_files:
        return []
    work = out_dir / "linkfinder"
    work.mkdir(parents=True, exist_ok=True)
    names: set = set()
    for js in js_files[:10]:
        if not Path(js).exists():
            continue
        r = run(["linkfinder", "-i", str(Path(js).resolve()), "-d", host],
                cwd=str(work), timeout=timeout)
        if r.timed_out:
            continue
    # defensive parse of whatever linkfinder produced
    for p in work.rglob("data/*/txt/*.txt"):
        for line in p.read_text(errors="ignore").splitlines():
            for m in re.finditer(r"[?&]([a-zA-Z_]\w*)=", line):
                names.add(m.group(1))
    for p in work.rglob("data/*/json/*.json"):
        try:
            data = json.loads(p.read_text(errors="ignore"))
        except json.JSONDecodeError:
            continue
        for name in data.get("parameters") or []:
            if isinstance(name, str):
                names.add(name)
    return sorted(n for n in names if 1 < len(n) <= 40)
