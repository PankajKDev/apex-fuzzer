"""Mapping stage: tech fingerprinting, classification, param mining.

Fetches live endpoints for technology signals, HTML forms, and page
IDs; classifies every endpoint; fingerprints the WAF; mines hidden
parameters with Arjun (plus opt-in LinkFinder); then builds the
incremental application model and graph.
"""
from pathlib import Path
from typing import Dict, List, Optional

from ..application.application_model import (Application,
                                              build_from_scan)
from ..graph.application_graph import (ApplicationGraph,
                                       build_from_application)
from ..discovery import parameters as param_mod
from ..discovery import param_miner
from ..discovery import technologies as tech_mod
from ..discovery.classifier import classify
from ..logging_setup import get_logger
from ..budgets import BudgetExceeded
from ..models import (Confidence, Endpoint, Parameter, read_jsonl,
                      write_jsonl)
from ..reporting.coverage import CoverageTracker
from ..reporting.metrics import Metrics
from ..checkpoints import Checkpoint
from ..validation.mutate import fingerprint_waf
from .recon import recon_identity_headers

log = get_logger("stages-mapping")


def map_attack_surface(endpoints: List[Endpoint], host: str,
                       out_dir: Path, metrics: Metrics, client,
                       cfg, profile, scope) -> list:
    """Fingerprint tech/WAF, harvest forms and page IDs, classify.

    Returns page-ID tuples for resource intel (runtime only).
    """
    tech_by_name = {}
    html_params: List[Parameter] = []
    all_headers: Dict[str, str] = {}
    page_ids: List[tuple] = []  # (url, param, value, source)
    passes: List[Optional[dict]] = [None]
    authed = recon_identity_headers(cfg)
    if authed:
        passes.append(authed)
    # soft-404 baseline first: unknown routes on template-serving
    # hosts would otherwise all look like live endpoints
    from ..validation.soft404 import detect_soft404, matches
    soft404 = None
    soft404_hits: List[str] = []
    if endpoints:
        try:
            from urllib.parse import urlsplit as _split
            first = _split(endpoints[0].url)
            base = f"{first.scheme or 'https'}://{first.hostname or ''}/"
            soft404 = detect_soft404(
                client, base, timeout=cfg.scan.http_timeout)
        except BudgetExceeded:
            log.debug("soft-404: budget blocked baseline probe")
            soft404 = None
        except Exception as e:
            log.debug("soft-404 detection failed: %s", e)
            soft404 = None
    for pass_headers in passes:
        for ep in [e for e in endpoints
                   if e.method == "GET"][:30]:
            fetch_kwargs = {"timeout": cfg.scan.http_timeout}
            if pass_headers:
                fetch_kwargs["headers"] = pass_headers
            try:
                r = client.get(ep.url, **fetch_kwargs)
                if soft404 is not None and matches(soft404, r):
                    soft404_hits.append(ep.url)
                set_cookies = []
                if r.headers.get("set-cookie"):
                    set_cookies = [r.headers.get("set-cookie")]
                for t in tech_mod.detect(r.headers, r.text[:200_000],
                                         set_cookies):
                    if t.name in tech_by_name:
                        cur = tech_by_name[t.name]
                        for e in t.evidence:
                            if e not in cur.evidence:
                                cur.evidence.append(e)
                    else:
                        tech_by_name[t.name] = t
                for k, v in (r.headers or {}).items():
                    all_headers.setdefault(k.lower(), v)
                if cfg.discovery.html_forms:
                    html_params.extend(param_mod.from_html(r.text))
                # Phase 5: harvest IDs from already-fetched bodies —
                # zero extra requests, feeds resource intel only
                try:
                    from ..application.resources import (
                        discover_ids_from_html, discover_ids_from_headers)
                    ctype = str((r.headers or {}).get(
                        "content-type", "")).lower()
                    if "html" in ctype:
                        for pname, pvalue in \
                                discover_ids_from_html(
                                    r.text or "").items():
                            page_ids.append(
                                (ep.url, pname, pvalue, "html"))
                    for pname, pvalue in discover_ids_from_headers(
                            r.headers or {}).items():
                        page_ids.append(
                            (ep.url, pname, pvalue, "headers"))
                except Exception as e:
                    log.debug("page-id harvest failed: %s", e)
            except Exception:
                continue
    # techs discovered from JS bundles (spec §7)
    for entry in read_jsonl(out_dir / "js_analysis.jsonl"):
        metrics.source_maps_found += len(entry.get("source_maps") or [])
        for t in entry.get("techs") or []:
            tech = tech_mod.Technology(
                name=t.get("name", ""),
                version=t.get("version"),
                confidence=t.get("confidence", "possible"),
                evidence=t.get("evidence", []),
                category=t.get("category", "other"))
            if tech.name in tech_by_name:
                for e in tech.evidence:
                    if e not in tech_by_name[t.name].evidence:
                        tech_by_name[t.name].evidence.append(e)
            else:
                tech_by_name[t.name] = tech
    for ep in endpoints:
        ep.endpoint_type = classify(ep.path or ep.normalized_url)
        if ep.host:
            ep.technology = list(tech_by_name.keys())
    for ep in endpoints:
        if ep.endpoint_type == "page":
            ep.body_parameters = param_mod.merge(ep.body_parameters,
                                                 html_params)
    # WAF fingerprint (drives the mutation engine, spec §4)
    waf = fingerprint_waf(all_headers)
    metrics.waf_detected = waf or ""
    if waf:
        log.info("WAF fingerprinted: %s", waf)
    metrics.technologies_detected = len(tech_by_name)
    metrics.js_files_analyzed = sum(
        1 for e in endpoints if "javascript" in e.source)
    write_jsonl(out_dir / "technologies.jsonl",
                list(tech_by_name.values()))
    import json as _json
    (out_dir / "soft404.json").write_text(_json.dumps(
        {"baseline": soft404.to_dict() if soft404 else None,
         "matched_fetched_urls": sorted(set(soft404_hits))},
        indent=2))
    if soft404_hits:
        log.info("soft-404: %d fetched URL(s) match the not-found "
                 "template", len(set(soft404_hits)))

    # ── active parameter mining: Arjun + LinkFinder (spec §1) ───────
    if profile.param_mining:
        mine_hidden_params(endpoints, host, out_dir, metrics,
                           all_headers, tech_by_name, cfg, scope)
    return page_ids


def build_app_state(endpoints: List[Endpoint], host: str,
                    out_dir: Path, ck: Checkpoint, resume: bool,
                    metrics: Metrics,
                    coverage: CoverageTracker, cfg):
    """Build (or resume-load) the incremental application model and
    its graph. Never requires perfect knowledge: endpoints, techs,
    identities and resources accumulate as producers run."""
    import json as _json
    app_path = out_dir / "application.json"
    graph_path = out_dir / "application_graph.json"
    cov_path = out_dir / "coverage.json"
    if resume and ck.is_complete("mapping") and app_path.exists():
        try:
            application = Application.from_dict(
                _json.loads(app_path.read_text()))
            graph = ApplicationGraph.load(graph_path) \
                if graph_path.exists() else \
                build_from_application(application)
            if cov_path.exists():
                loaded = CoverageTracker.from_dict(
                    _json.loads(cov_path.read_text()))
                coverage.status.update(loaded.status)
                coverage.detail.update(loaded.detail)
                coverage.counts.update(loaded.counts)
            log.info("application state resumed: %d endpoints, "
                     "%d resources, %d graph nodes",
                     len(application.endpoints),
                     len(application.resources), len(graph.nodes))
        except Exception as e:
            log.warning("app state resume failed (%s) — rebuilding", e)
            application, graph = fresh_app_state(
                endpoints, host, out_dir, ck, cfg)
    else:
        application, graph = fresh_app_state(
            endpoints, host, out_dir, ck, cfg)
    metrics.resources_discovered = len(application.resources)
    identities = application.identities
    metrics.identities_tested = len(identities)
    metrics.roles_tested = len({r.name for r in application.roles})
    metrics.tenants_tested = len({t.name for t in application.tenants})
    metrics.graph_nodes = len(graph.nodes)
    metrics.graph_edges = len(graph.edges)
    return application, graph


def fresh_app_state(endpoints: List[Endpoint], host: str,
                    out_dir: Path, ck: Checkpoint, cfg):
    techs = read_jsonl(out_dir / "technologies.jsonl")
    application = build_from_scan(host, endpoints, techs,
                                  cfg.auth.contexts)
    graph = build_from_application(application)
    (out_dir / "application.json").write_text(
        __import__("json").dumps(application.to_dict(), indent=2))
    graph.save(out_dir / "application_graph.json")
    if not (out_dir / "attack_chains.jsonl").exists():
        (out_dir / "attack_chains.jsonl").write_text("")
    ck.save_blob("application", application.to_dict())
    ck.save_blob("application_graph", graph.to_dict())
    log.info("application state built: %d endpoints, %d identities, "
             "%d resources, %d graph nodes/%d edges",
             len(application.endpoints), len(application.identities),
             len(application.resources),
             len(graph.nodes), len(graph.edges))
    return application, graph


def mine_hidden_params(endpoints: List[Endpoint], host: str,
                       out_dir: Path, metrics: Metrics,
                       all_headers: Dict[str, str],
                       tech_by_name: Dict, cfg, scope):
    if not cfg.discovery.arjun:
        return
    if not param_miner.arjun_available():
        log.info("arjun not installed — hidden param mining skipped "
                 "(pipx install arjun)")
        return
    eligible = [e for e in endpoints
                if e.method == "GET"
                and e.endpoint_type in ("api", "page", "authentication")]
    if cfg.discovery.arjun_require_existing_param:
        eligible = [e for e in eligible
                    if e.query_parameters or e.body_parameters]
    # endpoints that already have params are the highest-yield targets
    eligible.sort(key=lambda e: -(len(e.query_parameters)
                                  + len(e.body_parameters)))
    eligible = eligible[:cfg.discovery.arjun_max_endpoints]
    if not eligible:
        return
    log.info("arjun: mining %d endpoints (methods=%s)",
             len(eligible), ",".join(cfg.discovery.arjun_methods))
    for i, ep in enumerate(eligible):
        if not scope.active_test_allowed(ep.url):
            continue
        found = param_miner.mine_hidden_params(
            ep.url,
            methods=cfg.discovery.arjun_methods,
            out_dir=out_dir / "arjun",
            timeout=cfg.discovery.arjun_timeout,
            stable=cfg.discovery.arjun_stable,
            rate_limit=cfg.scan.rate_limit)
        new_params: List[Parameter] = []
        for method, names in found.items():
            loc = "query" if method == "GET" else "body"
            for name in names:
                if any(p.name == name and p.location == loc
                       for p in
                       (ep.query_parameters if loc == "query"
                        else ep.body_parameters)):
                    continue
                new_params.append(Parameter(
                    name=name, location=loc, source=["arjun"],
                    confidence=Confidence.PROBABLE.value))
        if new_params:
            for p in new_params:
                if p.location == "query":
                    ep.query_parameters = param_mod.merge(
                        ep.query_parameters, [p])
                else:
                    ep.body_parameters = param_mod.merge(
                        ep.body_parameters, [p])
            metrics.arjun_params_found += len(new_params)
            metrics.arjun_endpoints_mined += 1
            log.info("arjun: %s +%d params: %s", ep.url,
                     len(new_params),
                     ", ".join(p.name for p in new_params[:10]))

    # LinkFinder passive JS params (spec §1, Gaia-style) — best effort
    if cfg.discovery.linkfinder:
        from ..shell import which
        if which("linkfinder"):
            js_files = [out_dir / "cache" / f for f in
                        (out_dir / "cache").glob("*")
                        if f.is_file()] if (out_dir / "cache").exists() else []
            names = param_miner.linkfinder_params(
                [f for f in js_files if f.suffix in ("", ".js")],
                host, out_dir / "linkfinder")
            if names:
                attached = 0
                for ep in eligible:
                    for name in names:
                        if attached >= 30:
                            break
                        if any(p.name == name for p in
                               ep.query_parameters):
                            continue
                        ep.query_parameters.append(Parameter(
                            name=name, location="query",
                            source=["linkfinder"],
                            confidence=Confidence.POSSIBLE.value))
                        attached += 1
                log.info("linkfinder: attached %d JS params", attached)


def build_api_diff(out_dir: Path, endpoints) -> dict:
    """Spec-declared vs observed API surface (offline, never fails).

    Reads api_specs.json (when discovery fetched any) and diffs it
    against the mapped inventory into api_diff.json for the leads
    stage. Gaps are untested surface, never verdicts.
    """
    from ..discovery.api_diff import diff_api
    payload: dict = {"shadow": [], "unseen": [], "param_gaps": []}
    spec_file = Path(out_dir) / "api_specs.json"
    if spec_file.exists():
        try:
            import json as _json
            data = _json.loads(spec_file.read_text(errors="ignore")
                               or "[]")
            specs = data if isinstance(data, list) else []
            payload = diff_api(specs, endpoints)
        except Exception as exc:
            log.debug("api diff failed: %s", exc)
    try:
        import json as _json
        (Path(out_dir) / "api_diff.json").write_text(
            _json.dumps(payload, indent=2))
    except OSError as exc:
        log.debug("api diff persist failed: %s", exc)
    log.info("api diff: %d shadow, %d unseen, %d param gaps",
             len(payload["shadow"]), len(payload["unseen"]),
             len(payload["param_gaps"]))
    return payload
