"""Recon stage: external enumeration → raw URL pool.

Runs ParamSpider, archive lookups, and live crawlers as subprocesses,
then merges every output (plus seed URLs and robots/sitemap harvests)
into scope-agnostic raw.txt. Scope filtering happens downstream at
endpoint build; subprocesses only ever start from the in-scope target.
"""
from pathlib import Path
from typing import List, Set
from urllib.parse import urljoin, urlparse

from ..discovery import api_specs as spec_mod
from ..discovery import robots as robots_mod
from ..discovery.classifier import classify
from ..logging_setup import get_logger
from ..models import Confidence, Endpoint, Parameter
from ..scope import Scope, target_hostname
from ..shell import run, which
from . import read_lines

log = get_logger("stages-recon")


def header_arg(headers: dict) -> str:
    """Join headers the way hakrawler's -h flag expects."""
    return ";;".join(f"{name}: {value}" for name, value in
                     (headers or {}).items())


def katana_rl(profile_name: str, rate_limit: int) -> int:
    """Katana request rate: leads mode stays at a quiet floor."""
    if profile_name == "leads":
        return 5
    return 30 if rate_limit >= 100 else 10


def is_public_archive_target(target: str) -> bool:
    """Avoid disclosing local/private lab targets to public archive tools."""
    import ipaddress
    hostname = target_hostname(target)
    if not hostname or hostname == "localhost" or hostname.endswith(
            ".localhost"):
        return False
    try:
        return ipaddress.ip_address(hostname).is_global
    except ValueError:
        return "." in hostname


def recon_identity_headers(cfg) -> dict:
    """Session headers for authenticated recon, or {} when off."""
    if not bool(getattr(cfg.discovery, "authenticated_recon", False)):
        return {}
    for context in list(getattr(cfg.auth, "contexts", []) or []):
        if getattr(context, "name", "") == "anonymous":
            continue
        headers = dict(getattr(context, "headers", None) or {})
        picked = {k: v for k, v in headers.items()
                  if k.lower() in ("cookie", "authorization")
                  and isinstance(v, str) and v.strip()}
        if picked:
            return picked
    log.info("recon: authenticated_recon on but no authenticated "
             "identity carries Cookie/Authorization — crawling "
             "anonymously")
    return {}


def merge_recon(cfg, out_dir: Path):
    """Merge recon files into raw.txt, applying crawl_exclude_exts."""
    excl = {e.lower() for e in cfg.scope.crawl_exclude_exts}
    raw: Set[str] = set()
    for u in (getattr(cfg, "seed_urls", None) or []):
        line = str(u).strip()
        if not line.startswith("http"):
            continue
        ext = Path(line.split("?")[0]).suffix.lstrip(".").lower()
        if ext and ext in excl:
            continue
        raw.add(line)
    # Preserve what a previous merge already banked: re-merging
    # (e.g. after the robots harvest lands) must only add.
    existing = out_dir / "raw.txt"
    if existing.exists():
        for line in existing.read_text(errors="ignore").splitlines():
            line = line.strip()
            if line.startswith("http"):
                raw.add(line)
    for f in ("param.txt", "wayback.txt", "gau.txt",
              "hakrawler.txt", "katana.txt",
              "hakrawler-authed.txt", "katana-authed.txt",
              "robots.txt.out", "sitemap.txt"):
        p = out_dir / f
        if not p.exists():
            continue
        for line in p.read_text(errors="ignore").splitlines():
            line = line.strip()
            if not line.startswith("http"):
                continue
            ext = Path(line.split("?")[0]).suffix.lstrip(".").lower()
            if ext and ext in excl:
                continue
            raw.add(line)
    (out_dir / "raw.txt").write_text("\n".join(sorted(raw)))


def run_recon(cfg, profile, target: str, out_dir: Path) -> List[str]:
    url = target if target.startswith("http") else f"http://{target}"
    host = target.replace("http://", "").replace(
        "https://", "").split("/")[0]
    jobs = []
    # Leads mode crawls shallow and slow: discovery without alarming
    # edge defenses. All other profiles keep the standard depth.
    quiet = profile.name == "leads"
    crawl_depth = "1" if quiet else "3"
    if quiet:
        log.info("recon: leads mode - quiet crawl (depth 1, "
                 "katana -rl 5), no active probes will follow")
    if is_public_archive_target(target):
        ps = Path.home() / "ParamSpider" / "paramspider.py"
        if ps.exists():
            jobs.append((["python3", str(ps), "-d", host,
                          "--level", "high", "--quiet", "-o",
                          str(out_dir / "param.txt")],
                         "paramspider", None, out_dir / "param.txt"))
        if which("waybackurls"):
            jobs.append((["waybackurls"], "waybackurls",
                         host + "\n", out_dir / "wayback.txt"))
        if which("gauplus"):
            jobs.append((["gauplus", "-subs"], "gauplus",
                         host + "\n", out_dir / "gau.txt"))
    else:
        log.info("recon: skipping public archive lookups for local or "
                 "non-public target %s", host)
    if which("hakrawler"):
        jobs.append((["hakrawler", "-d", crawl_depth, "-subs", "-u"],
                     "hakrawler", url + "\n", out_dir / "hakrawler.txt"))
    if which("katana"):
        rl = katana_rl(profile.name, cfg.scan.rate_limit)
        jobs.append((["katana", "-d", crawl_depth, "-silent",
                      "-rl", str(rl)],
                     "katana", url + "\n", out_dir / "katana.txt"))
    auth_headers = recon_identity_headers(cfg)
    if auth_headers:
        if which("hakrawler"):
            jobs.append((["hakrawler", "-d", crawl_depth, "-subs", "-u",
                          "-h", header_arg(auth_headers)],
                         "hakrawler-authed", url + "\n",
                         out_dir / "hakrawler-authed.txt"))
        if which("katana"):
            katana_args = ["katana", "-d", crawl_depth, "-silent",
                           "-rl", str(rl)]
            for name, value in auth_headers.items():
                katana_args.extend(["-H", f"{name}:{value}"])
            jobs.append((katana_args, "katana-authed", url + "\n",
                         out_dir / "katana-authed.txt"))

    import concurrent.futures

    def _run(job):
        args, name, inp, out_path = job
        r = run(args, timeout=cfg.scan.timeout, input_data=inp)
        if out_path and r.stdout:
            Path(out_path).write_text(r.stdout)
        return name

    with concurrent.futures.ThreadPoolExecutor(
            max_workers=cfg.scan.concurrency) as ex:
        for name in ex.map(_run, jobs):
            log.info("recon: %s done", name)

    merge_recon(cfg, out_dir)
    return read_lines(out_dir / "raw.txt")


def harvest_robots(client, base_url: str, out_dir: Path,
                   http_timeout: int):
    try:
        r = robots_mod.fetch_robots(client, base_url, http_timeout)
    except Exception as e:
        log.debug("robots harvest failed: %s", e)
        return
    if not r["paths"] and not r["sitemaps"]:
        return
    urls: Set[str] = set()
    for p in r["paths"]:
        urls.add(urljoin(base_url, p))
    for sm in r["sitemaps"][:5]:
        try:
            urls.update(robots_mod.fetch_sitemap(client, sm,
                                                 http_timeout))
        except Exception:
            continue
    if urls:
        (out_dir / "robots.txt.out").write_text("\n".join(sorted(urls)))
        log.info("robots/sitemap: %d URLs harvested", len(urls))


def harvest_api_specs(client, base_url: str, endpoints: List[Endpoint],
                      out_dir: Path, http_timeout: int, scope: Scope):
    try:
        specs = spec_mod.discover(client, base_url, http_timeout)
    except Exception as e:
        log.debug("api spec discovery failed: %s", e)
        return
    if not specs:
        return
    import json
    (out_dir / "api_specs.json").write_text(
        json.dumps(specs, indent=2))
    added = 0
    for spec in specs:
        base = spec.get("base", "") or base_url
        for ep in spec["endpoints"]:
            full = urljoin(base, ep["path"])
            if not scope.is_in_scope(full):
                continue
            from ..discovery.url_normalizer import normalize_url
            n = normalize_url(full)
            if any(e.normalized_url == n for e in endpoints):
                continue
            e = Endpoint(
                url=full, normalized_url=n,
                host=urlparse(full).hostname or "",
                path=ep["path"], method=ep["method"],
                source=["api_spec"],
                endpoint_type=classify(ep["path"]),
                operation_id=ep.get("operation_id", ""),
                summary=ep.get("summary", ""),
                description=ep.get("description", ""),
                tags=ep.get("tags", []),
                request_content_types=ep.get(
                    "request_content_types", []))
            for p in ep.get("parameters", []):
                parameter = Parameter(
                    name=p["name"], location=p.get("in", "query"),
                    source=["api_spec"],
                    confidence=Confidence.CONFIRMED.value)
                location = p.get("in", "query")
                if location == "body":
                    e.body_parameters.append(parameter)
                elif location == "header":
                    e.header_parameters.append(parameter)
                elif location not in ("path", "cookie"):
                    e.query_parameters.append(parameter)
            endpoints.append(e)
            added += 1
    log.info("api specs: %d endpoints added", added)


def scoped_subprocess_input(scope: Scope, out_dir: Path, src: str,
                            name: str) -> Path:
    """Write a scope-filtered input file for an external tool.

    Subprocesses (httpx, nuclei, …) follow redirects themselves,
    outside the gate — so they only ever receive in-scope lines.
    The unfiltered source file stays intact for audit/resume.
    """
    lines = read_lines(out_dir / src)
    kept = [u for u in lines if scope.is_in_scope(u)]
    dest = out_dir / name
    dest.write_text("\n".join(kept) + ("\n" if kept else ""))
    log.info("subprocess input: %d in-scope / %d total -> %s",
             len(kept), len(lines), name)
    return dest
