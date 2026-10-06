"""Endpoint-build stage: recon URLs → Endpoint inventory.

Normalizes and dedupes raw URLs, mines first-party JavaScript
(including source maps), merges browser-crawl traffic and HAR
captures through one entry contract, and retains observed request
shapes (runtime-only) for the validators.
"""
from pathlib import Path
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse, urlsplit

from ..discovery import har as har_mod
from ..discovery import parameters as param_mod
from ..discovery.javascript import JSAnalyzer, is_first_party
from ..discovery.url_normalizer import normalize_url
from ..logging_setup import get_logger
from ..models import (Confidence, Endpoint, Parameter, read_jsonl,
                      write_jsonl)

log = get_logger("stages-endpoints")


def build_endpoints(urls: List[str], host: str, out_dir: Path,
                     client, base_url: str, budgets, metrics, cfg,
                     profile, scope) -> List[Endpoint]:
    by_norm: Dict[str, Endpoint] = {}
    for u in urls:
        n = normalize_url(u)
        ep = by_norm.get(n)
        if ep is None:
            p = urlparse(n)
            ep = Endpoint(url=u, normalized_url=n,
                          host=p.hostname or "", path=p.path,
                          method="GET", source=["recon"])
            ep.query_parameters = param_mod.from_url(u)
            by_norm[n] = ep
        elif "recon" not in ep.source:
            ep.source.append("recon")

    js_urls = [e.url for e in by_norm.values()
               if e.url.lower().endswith(".js")
               or ".js?" in e.url.lower()]
    js_urls = [u for u in js_urls if is_first_party(u, host)]
    js_results: List[Dict] = []
    if js_urls and cfg.discovery.javascript and \
            profile.js_analysis:
        analyzer = JSAnalyzer(cfg, client, out_dir / "cache")
        for jurl in js_urls[:cfg.discovery.js_max_files]:
            result = analyzer.analyze(jurl)
            js_results.append(result)
            for ep in result["endpoints"]:
                add_js_endpoint(by_norm, host, ep["path"], scope)
            # deep source-map endpoints (spec §6)
            for sm in result.get("source_maps", []):
                for dep in (sm.get("details") or {}).get("endpoints", []):
                    add_js_endpoint(by_norm, host, dep["path"], scope,
                                    source="sourcemap")
                add_sourcemap_params(
                    by_norm, host,
                    (sm.get("details") or {}).get("params", []))
    if js_results:
        write_jsonl(out_dir / "js_analysis.jsonl", js_results)
    # ── browser-driven discovery (agent Phase 1) ───────────────────
    for entry in browser_discover(
            cfg, profile, scope, base_url, host, out_dir,
            budgets, metrics):
        merge_browser_entry(by_norm, host, entry)
    # ── HAR import (first-party captures: real endpoints + shapes) ──
    for entry in har_import(cfg, scope):
        merge_browser_entry(by_norm, host, entry)
    return list(by_norm.values())


def har_import(cfg, scope) -> List[Dict]:
    """Parse configured HAR files into merge-ready entry dicts.

    Inventory only: files are read from disk, never fetched; no
    request is sent. Missing/unreadable files log a skip.
    """
    out: List[Dict] = []
    identity = str(getattr(cfg, "har_identity", "") or "").strip() \
        or "har"
    for path in (getattr(cfg, "har_files", None) or []):
        data = har_mod.load_har_file(path)
        if data is None:
            log.info("har: skipping unreadable file %s", path)
            continue
        found = har_mod.parse_har(data, scope, identity=identity)
        log.info("har: %s → %d endpoints", path, len(found))
        out.extend(found)
    return out


def merge_browser_entry(by_norm: Dict[str, Endpoint], host: str,
                        entry: Dict):
    """Merge one discovered request/form into the pipeline.

    Shared by browser crawl and HAR import (both produce the same
    entry contract); the entry's ``source`` tag drives attribution.
    """
    url = entry.get("url", "")
    if not url:
        return
    sources = list(entry.get("source") or ["browser"])
    method = (entry.get("method") or "GET").upper()
    n = normalize_url(url)
    ep = by_norm.get(n)
    if ep is None:
        p = urlparse(n)
        ep = Endpoint(url=url, normalized_url=n,
                      host=p.hostname or host, path=p.path,
                      method=method, source=list(sources))
        by_norm[n] = ep
    else:
        for src in sources:
            if src not in ep.source:
                ep.source.append(src)
    new_params = []
    for name in entry.get("params") or []:
        new_params.append(Parameter(
            name=name, location="query", source=list(sources),
            confidence=Confidence.PROBABLE.value))
    for name, sample in (entry.get("body") or {}).items():
        new_params.append(Parameter(
            name=name, location="body", source=list(sources),
            sample_value=sample,
            confidence=Confidence.PROBABLE.value))
    for name in entry.get("inputs") or []:
        new_params.append(Parameter(
            name=name, location="body",
            source=[f"{sources[0]}:form"],
            confidence=Confidence.POSSIBLE.value))
    if entry.get("form_method") and ep.method == "GET":
        ep.method = entry["form_method"].upper()
    observed = list(getattr(ep, "observed_requests", []) or [])
    observed_keys = {
        (item.get("identity"), item.get("method"), item.get("url"),
         item.get("post_data"))
        for item in observed if isinstance(item, dict)}
    for request in entry.get("observed_requests") or []:
        if not isinstance(request, dict):
            continue
        key = (request.get("identity"), request.get("method"),
               request.get("url"), request.get("post_data"))
        if key in observed_keys or len(observed) >= 100:
            continue
        observed.append(dict(request))
        observed_keys.add(key)
    if observed:
        # Runtime-only material. Endpoint.to_dict deliberately omits it.
        ep.observed_requests = observed
    ep.query_parameters = param_mod.merge(
        ep.query_parameters, [p for p in new_params
                              if p.location == "query"])
    ep.body_parameters = param_mod.merge(
        ep.body_parameters, [p for p in new_params
                             if p.location != "query"])


def browser_discover(cfg, profile, scope, base_url: str, host: str,
                     out_dir: Path, budgets, metrics) -> List[Dict]:
    """Crawl with Chromium (GET navigations only), record traffic.

    Returns endpoint dicts for pipeline merge. Disabled, missing
    Playwright, or launch failure → [] with a log line.
    """
    if not (profile.browser or cfg.browser.enabled):
        return []
    from ..browser.browser import BrowserEngine, playwright_available
    if not playwright_available():
        log.info("browser: playwright not installed — skipping "
                 "(`pip install apex-fuzzer[browser]`)")
        return []
    from ..browser.network import (NetworkRecorder,
                                   authenticated_capture_request_allowed,
                                   safe_artifact_url)
    from ..browser.actions import snapshot_dom
    from ..browser.storage import StorageCapture
    from ..browser.sessions import SessionManager
    bcfg = cfg.browser
    entries: List[Dict] = []
    pages_visited = 0
    visited_urls: List[str] = []
    recorders = []
    try:
        with BrowserEngine(cfg, headless=bcfg.headless,
                           timeout_ms=bcfg.navigation_timeout_ms
                           ) as engine:
            ctx = engine.new_context()
            page = ctx.new_page()
            recorder = NetworkRecorder(
                scope=scope,
                max_requests=bcfg.max_pages * 50)
            recorders.append(recorder)
            if bcfg.capture_network:
                recorder.attach(page)
            seen, queue = set(), [(base_url, 0)]
            while queue and pages_visited < bcfg.max_pages:
                url, depth = queue.pop(0)
                if url in seen or depth > bcfg.max_depth:
                    continue
                if not scope.is_in_scope(url):
                    continue
                if not budgets.consume_test("browser", url):
                    log.warning("browser: action budget exhausted")
                    break
                seen.add(url)
                try:
                    page.goto(url, timeout=bcfg.navigation_timeout_ms)
                    pages_visited += 1
                    visited_urls.append(url)
                except Exception as e:
                    log.debug("browser: goto %s failed: %s", url, e)
                    continue
                if not bcfg.capture_dom:
                    continue
                try:
                    snap = snapshot_dom(page)
                except Exception:
                    continue
                for link in snap.get("links") or []:
                    full = resolve_link(url, link)
                    if full and full not in seen and \
                            scope.is_in_scope(full):
                        queue.append((full, depth + 1))
                for form in snap.get("forms") or []:
                    action = form.get("action") or url
                    full = resolve_link(url, action)
                    if not full or not scope.is_in_scope(full):
                        continue
                    entries.append({
                        "url": full,
                        "method": (form.get("method") or "GET").upper(),
                        "params": [], "body": {},
                        "inputs": [i.get("name", "")
                                   for i in form.get("inputs") or []
                                   if i.get("name")],
                        "form_method": (form.get("method")
                                       or "GET").upper()})
            if bcfg.capture_network:
                entries.extend(recorder.to_endpoints())
            if getattr(bcfg, "capture_authenticated_requests", False):
                for auth_context in cfg.auth.contexts or []:
                    if not (auth_context.storage_state or
                            auth_context.headers):
                        continue
                    auth_page = auth_browser_context = None
                    try:
                        auth_browser_context = engine.new_context(
                            storage_state=auth_context.storage_state,
                            identity=auth_context.name,
                            service_workers="block")
                        auth_page = auth_browser_context.new_page()
                        recorder_for_identity = NetworkRecorder(
                            scope=scope,
                            max_requests=bcfg.max_pages * 50,
                            identity=auth_context.name)
                        recorders.append(recorder_for_identity)
                        # This recorder is controlled by the dedicated
                        # opt-in flag, independently of anonymous network
                        # artifact capture.
                        recorder_for_identity.attach(auth_page)
                        current_navigation = [""]

                        def route_authenticated(route):
                            request = route.request
                            if authenticated_capture_request_allowed(
                                    request.method, request.url,
                                    current_navigation[0], scope):
                                headers = dict(request.headers or {})
                                headers.update(auth_context.headers or {})
                                route.continue_(headers=headers)
                            else:
                                route.abort()

                        auth_page.route("**/*", route_authenticated)
                        if hasattr(auth_page, "route_web_socket"):
                            auth_page.route_web_socket(
                                "**/*", lambda websocket: websocket.close())
                        else:
                            auth_page.add_init_script(
                                "window.WebSocket = class { "
                                "constructor() { throw new Error("
                                "'WebSocket disabled during capture'); } };")
                        for auth_url in visited_urls[:bcfg.max_pages]:
                            if not scope.is_in_scope(auth_url):
                                continue
                            if not budgets.consume_test("browser",
                                                        auth_url):
                                log.info("browser: authenticated capture "
                                         "action budget exhausted")
                                break
                            current_navigation[0] = auth_url
                            try:
                                auth_page.goto(
                                    auth_url,
                                    timeout=bcfg.navigation_timeout_ms)
                                pages_visited += 1
                            except Exception as exc:
                                log.debug(
                                    "browser: authenticated navigation "
                                    "for '%s' failed: %s",
                                    auth_context.name, exc)
                        entries.extend(
                            recorder_for_identity.to_endpoints())
                    except Exception as exc:
                        log.info("browser: authenticated capture skipped "
                                 "for '%s' (%s)",
                                 auth_context.name, type(exc).__name__)
                    finally:
                        if auth_page is not None:
                            try:
                                auth_page.close()
                            except Exception:
                                pass
                        if auth_browser_context is not None:
                            try:
                                auth_browser_context.close()
                            except Exception:
                                pass
            if bcfg.capture_websocket:
                for ws in recorder.websockets:
                    entries.append({"url": ws, "method": "WS",
                                    "params": [], "body": {}})
            (out_dir / "browser_urls.txt").write_text(
                "\n".join(sorted({safe_artifact_url(e["url"])
                                  for e in entries
                                  if e.get("url")})))
            import json as _json
            (out_dir / "browser_traffic.json").write_text(
                _json.dumps({
                    "identities": [r.identity for r in recorders],
                    "requests": [request.to_dict()
                                 for r in recorders
                                 for request in r.requests],
                    "websockets": list(dict.fromkeys(
                        safe_artifact_url(ws)
                        for r in recorders for ws in r.websockets)),
                    "navigations": list(dict.fromkeys(
                        safe_artifact_url(url)
                        for r in recorders for url in r.navigations)),
                }, indent=2))
            if bcfg.capture_storage:
                try:
                    capture = StorageCapture().capture(ctx, page)
                    mgr = SessionManager(out_dir / "sessions")
                    sess = mgr.from_capture(capture, "browser")
                    mgr.save(sess)
                    log.info("browser: session exported (%d cookies, "
                             "%d tokens)",
                             len(sess.cookies),
                             sum(len(v) for v in
                                 sess.tokens.values()))
                except Exception as e:
                    log.debug("browser: session export failed: %s", e)
            page.close()
            ctx.close()
    except RuntimeError as e:
        log.warning("browser discovery unavailable: %s", e)
        return []
    except Exception as e:
        log.warning("browser discovery failed: %s", e, exc_info=True)
        return []
    metrics.browser_pages = pages_visited
    try:
        metrics.browser_requests = sum(len(r.requests)
                                       for r in recorders)
    except Exception:
        pass
    log.info("browser: %d pages → %d endpoint entries",
             pages_visited, len(entries))
    return entries


def resolve_link(base: str, link: str) -> Optional[str]:
    if not link or link.startswith(("javascript:", "mailto:",
                                    "tel:", "#")):
        return None
    try:
        full = urljoin(base, link.strip()).split("#", 1)[0]
    except Exception:
        return None
    if not full.startswith(("http://", "https://")):
        return None
    if urlsplit(full).path.lower().endswith(
            (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp",
             ".ico", ".woff", ".woff2", ".css")):
        return None
    return full or None


def add_js_endpoint(by_norm: Dict[str, Endpoint], host: str,
                    path: str, scope,
                    source: str = "javascript"):
    if not path:
        return
    full = f"https://{host}{path}"
    if not scope.is_in_scope(full):
        return
    n = normalize_url(full)
    if n in by_norm:
        if source not in by_norm[n].source:
            by_norm[n].source.append(source)
        return
    by_norm[n] = Endpoint(
        url=full, normalized_url=n, host=host,
        path=path, method="GET",
        source=[source],
        query_parameters=param_mod.from_url(full))


def add_sourcemap_params(by_norm: Dict[str, Endpoint], host: str,
                         names: List[str]):
    """Attach source-map params to API endpoints (possible confidence)."""
    if not names:
        return
    seen: Set[str] = set()
    attached = 0
    for ep in by_norm.values():
        if ep.endpoint_type == "api" and attached < 30:
            for name in names:
                if name in seen:
                    continue
                seen.add(name)
                ep.query_parameters.append(Parameter(
                    name=name, location="query",
                    source=["sourcemap"],
                    confidence=Confidence.POSSIBLE.value))
                attached += 1
                if attached >= 30:
                    break


def load_endpoints(out_dir: Path) -> List[Endpoint]:
    loaded = []
    for d in read_jsonl(out_dir / "endpoints.jsonl"):
        kwargs = {k: v for k, v in d.items()
                  if k in Endpoint.__dataclass_fields__}
        for key in ("query_parameters", "body_parameters",
                    "header_parameters"):
            kwargs[key] = [Parameter(**p) if isinstance(p, dict) else p
                           for p in kwargs.get(key, []) or []]
        loaded.append(Endpoint(**kwargs))
    return loaded
