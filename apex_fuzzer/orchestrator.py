"""The pipeline orchestrator — v5.2.

New stages (v5.2):
- Arjun hidden-parameter mining in mapping (spec §1)
- tko-subs confirmed subdomain takeover (spec §10)
- differential auth-context / BOLA / broken-access testing (spec §2)
- Interactsh OAST sweep + SSRF validation (spec §3)
- WAF fingerprint + mutation pre-screen (spec §4)
- AI loop closure: hypotheses feed back into deterministic testing
  (OAST / sqlmap / dalfox / differential / AI-generated nuclei)
  (spec §8)
- adaptive rate limiting on all direct HTTP (spec §9)
"""
import csv
import time
from pathlib import Path
from typing import List, Dict, Set, Optional
from .config import Config
from .scope import Scope, target_hostname
from .profiles import Profile, get as get_profile
from .models import (Endpoint, Parameter, Finding, Hypothesis,
                      write_jsonl, read_jsonl, Confidence,
                      ValidationStatus, stable_finding_id,
                      RESULT_STATUSES, ResultStatus)
from .logging_setup import get_logger, attach_file_handler
from .shell import run, which, AdaptiveRateLimiter
from .budgets import BudgetTracker, BudgetExceeded
from .checkpoints import Checkpoint
from .application.application_model import (Application,
                                            build_from_scan)
from .application.identities import from_auth_contexts
from .graph.application_graph import (ApplicationGraph,
                                      build_from_application)
from .reporting.coverage import CoverageTracker
from .plugins.base import (TestTarget, TestContext, run_plugins)
from .plugins import adapters as _plugin_adapters  # noqa: F401 (registry)
from .plugins.adapters import PLUGIN_ORDER
from .discovery.url_normalizer import normalize_url
from .discovery import parameters as param_mod
from .discovery import technologies as tech_mod
from .discovery import robots as robots_mod
from .discovery import api_specs as spec_mod
from .discovery import param_miner
from .discovery.javascript import JSAnalyzer, is_first_party, chunk_js
from .discovery.classifier import classify
from .detection.nuclei import (NucleiRunner, correlate,
                                run_hypothesis_templates)
from .validation.evidence import EvidenceStore
from .validation.base import Candidate
from .validation.sqli import SqliValidator
from .validation.xss import XssValidator
from .validation.ssrf import endpoint_from_url
from .validation.oast import (InteractshProvider, probe_endpoint,
                               ssrf_candidates, ssrf_candidate_score,
                               matching_interactions)
from .validation.differential import (DifferentialTester,
                                       has_idor_params,
                                       PRIVILEGED_TYPES)
from .validation.mutate import MutationEngine, fingerprint_waf
from .ai.planner import AIPlanner
from .reporting.metrics import Metrics
from .reporting.html import render_html
from .safety.preflight import (StopFlag, Pacer, get_interrupt_flag,
                               resolve_modules, dry_run_plan,
                               plan_differential,
                               plan_authz_matrix, plan_race,
                               plan_business, plan_second_order,
                               plan_second_order_ssrf, plan_oast)
from .safety.impact import max_level
from .safety.authorization import (
    Authorization, AuthorizationRefused, GATED_MODULES)

log = get_logger("orchestrator")

LIVE_CODES = "200,204,301,302,401,403,405,500,502,503,504"

# Endpoint types that give OAST sink candidates extra priority.
_OAST_PRIORITY_TYPES = ("proxy", "webhook", "callback", "import",
                        "export", "download", "api")

# invariant check → finding-tag classes that already cover the same
# verdict space (a violation there corroborates, never duplicates)
_INVARIANT_CLASSES = {
    "no_cross_user_read": {"bola", "idor", "tenant_isolation",
                           "authz"},
    "no_unauthorized_write": {"authz", "bfla"},
    "no_access_deleted": {"authz"},
    "no_modify_deleted": {"authz"},
    "no_self_promote": {"authz"},
    "no_expired_session": {"authz", "broken_auth"},
    "no_recharge_refunded": {"business_logic"},
    "quantity_non_negative": {"business_logic"},
    "price_stable": {"business_logic"},
    "refund_lte_payment": {"business_logic"},
    "single_use_token": {"business_logic"},
    "no_revert_completed": {"business_logic"},
}


class Orchestrator:
    def __init__(self, cfg: Config, base_output: Path,
                 profile: Optional[Profile] = None):
        self.cfg = cfg
        self.base_output = base_output
        self.scope = Scope(cfg.scope)
        self.profile = profile or get_profile("standard")
        self._active_waf: Optional[str] = None
        self._stop_flag = StopFlag()
        self._pacer = Pacer(0)
        self._safety_info: Optional[dict] = None
        self._harvest_pool: list = []
        self._page_ids: list = []
        self._last_matrix = None

    # =====================================================================
    def run(self, targets: List[str], resume: bool = False):
        from .safety.authorization import AuthorizationRefused
        for i, t in enumerate(targets):
            try:
                self._run_one(t, resume)
            except AuthorizationRefused:
                raise  # fail closed: never continue past a refusal
            except Exception as e:
                log.error("target %s failed: %s", t, e, exc_info=True)
            if i < len(targets) - 1:
                time.sleep(self.cfg.scan.jitter_between_targets)

    # =====================================================================
    def _run_one(self, target: str, resume: bool):
        host = (target.replace("http://", "")
                .replace("https://", "").split("/")[0])
        out_dir = self.base_output / host
        out_dir.mkdir(parents=True, exist_ok=True)
        attach_file_handler(log, out_dir / "scan.log")
        ck = Checkpoint(out_dir / "checkpoint.json")

        log.info("=== target: %s (profile: %s) ===",
                 target, self.profile.name)
        metrics = Metrics()
        started = time.time()

        if not self.cfg.scope.allowed_domains:
            # Scope matches URL hostnames, which never include ports.
            # Keep the port in the output directory but not in the scope
            # allowlist (e.g. localhost:8000 → localhost).
            self.cfg.scope.allowed_domains.append(
                target_hostname(target) or host)
            self.scope = Scope(self.cfg.scope)

        base_url = target if target.startswith("http") else f"https://{host}"
        limiter = AdaptiveRateLimiter(
            max(0.5, self.cfg.scan.rate_limit / 10.0))
        budgets = BudgetTracker(self.cfg)
        coverage = CoverageTracker()
        client = _HTTPClient(limiter=limiter, budgets=budgets)
        app_graph = ApplicationGraph()
        application: Optional[Application] = None
        stop = StopFlag()
        pacer = Pacer(getattr(self.cfg.safety, "cooldown_ms", 0))
        self._stop_flag = stop
        self._pacer = pacer

        # ── 0. PREFLIGHT (Milestone 1): strict gates fail closed here,
        # before any network activity. Non-strict scans only log.
        self._safety_info = self._preflight_or_refuse(
            target, out_dir, stop)

        # ── 1. RECON ────────────────────────────────────────────────────
        if resume and ck.is_complete("recon"):
            log.info("recon complete (resume)")
        else:
            ck.mark("recon", "running")
            metrics.urls_discovered = len(self._recon(target, out_dir))
            ck.mark("recon")

        # Robots / sitemap appended to raw URL pool (spec §6)
        if self.profile.robots and self.cfg.discovery.robots_sitemap:
            self._harvest_robots(client, base_url, out_dir)

        raw_urls = self._read_lines(out_dir / "raw.txt")
        scoped = [u for u in raw_urls if self.scope.is_in_scope(u)]
        log.info("in-scope URLs: %d / %d", len(scoped), len(raw_urls))

        # ── 2. ENDPOINT BUILD ───────────────────────────────────────────
        if resume and ck.is_complete("discovery"):
            endpoints = self._load_endpoints(out_dir)
        else:
            ck.mark("discovery", "running")
            endpoints = self._build_endpoints(scoped, host, out_dir,
                                              client, base_url, budgets,
                                              metrics)
            metrics.unique_endpoints = len(endpoints)
            metrics.parameters_discovered = sum(
                len(e.query_parameters) + len(e.body_parameters)
                for e in endpoints)
            write_jsonl(out_dir / "endpoints.jsonl", endpoints)
            ck.mark("discovery")

        # ── 3. API SPEC DISCOVERY ───────────────────────────────────────
        if (self.profile.api_specs and self.cfg.discovery.api_specs):
            if not (resume and ck.is_complete("mapping")):
                self._harvest_api_specs(client, base_url, endpoints, out_dir)

        # ── 4. MAPPING ──────────────────────────────────────────────────
        if resume and ck.is_complete("mapping"):
            log.info("mapping complete (resume)")
        else:
            ck.mark("mapping", "running")
            self._map_attack_surface(endpoints, host, out_dir, metrics,
                                     client)
            write_jsonl(out_dir / "endpoints.jsonl", endpoints)
            ck.mark("mapping")

        # ── 4b. APPLICATION MODEL + GRAPH (§4–5, built incrementally) ────
        application, app_graph = self._build_app_state(
            endpoints, host, out_dir, ck, resume, metrics, coverage)

        # ── 5. LIVE HOST PROBE  (BUGFIX A) ──────────────────────────────
        live_file = out_dir / "live.txt"
        if resume and ck.is_complete("probe"):
            log.info("live probe complete (resume)")
        else:
            ck.mark("probe", "running")
            self._probe_live(out_dir, live_file)
            metrics.live_hosts = len(self._read_lines(live_file))
            ck.mark("probe")
        log.info("live hosts: %d", metrics.live_hosts)

        # ── 6. SUBDOMAIN TAKEOVER  (BUGFIX B + tko-subs confirmed) ──────
        findings: List[Finding] = []
        if self.profile.run_subzy or self.profile.run_tko:
            findings += self._takeover_check(out_dir, host, metrics,
                                             coverage)

        # ── 7. NUCLEI ───────────────────────────────────────────────────
        nuclei = NucleiRunner(self.cfg, out_dir)
        # NOTE: takeover findings (tko/subzy) seed the list; nuclei findings
        # are appended below when that stage runs.
        if self.profile.run_nuclei:
            if resume and ck.is_complete("nuclei"):
                findings = [Finding.from_dict(d) for d in
                            read_jsonl(out_dir / "findings.jsonl")]
                # resume: re-derive floor coverage from stored findings
                fresh_nuclei = [f for f in findings
                                if f.source.startswith("nuclei")]
            else:
                ck.mark("nuclei", "running")
                raw_findings = nuclei.run_scan(live_file)
                metrics.nuclei_findings = len(raw_findings)
                deduped = correlate(raw_findings)
                metrics.nuclei_findings_after_dedup = len(deduped)
                deduped = [f for f in deduped
                           if self.scope.is_in_scope(f.matched_at)]
                findings = findings + deduped
                write_jsonl(out_dir / "findings.jsonl", findings)
                ck.mark("nuclei")
                fresh_nuclei = deduped
            # nuclei matches are candidates, never confirmations (§57)
            for f in fresh_nuclei:
                coverage.record(_classify_finding(f), "candidate",
                                f"nuclei template {f.template_id}")
        else:
            ck.mark("nuclei", "skipped")

        # ── 8. VALIDATION (+ differential + OAST) ───────────────────────
        evidence = EvidenceStore(out_dir / "proofs")
        # storage_state import: contexts declaring a file get its cookies
        # (static header config always wins; safe additive enrichment)
        from .browser.sessions import SessionManager
        try:
            SessionManager().apply_to_contexts(self.cfg.auth.contexts)
        except Exception as e:
            log.debug("session import failed: %s", e)
        # automated login minting (agent Phase 2): configured identities
        # without headers get a real session; MFA stops at a checkpoint
        self._login_identities(out_dir, metrics)
        run_validation = (self.profile.run_validation
                          or self.cfg.validation.enabled)
        run_second_order = (self.profile.second_order
                            or self.cfg.validation.second_order
                            or self.cfg.validation.second_order_ssrf)
        run_diff = (self.profile.differential
                    or self.cfg.validation.differential)
        run_oast = self.profile.oast or self.cfg.validation.ssrf
        if run_validation or run_diff or run_oast or run_second_order:
            ck.mark("validation", "running")
            findings = self._validate(findings, endpoints, evidence,
                                      metrics, client, out_dir,
                                      budgets, coverage,
                                      app_graph=app_graph, ck=ck)
            write_jsonl(out_dir / "findings.jsonl", findings)
            ck.mark("validation")
        else:
            ck.mark("validation", "skipped")

        # ── 8b. WORKFLOW DISCOVERY (agent Phase 4, offline) ─────────
        # Pure analysis over collected data — zero network, always safe.
        self._discover_workflows(out_dir, endpoints, application,
                                 app_graph, metrics, ck)

        # ── 8c. RESOURCE INTEL (agent Phase 5, offline) ──────────────
        # Lifecycle-aware records from everything collected so far.
        # Zero network: only cached files and in-memory sweep data.
        self._build_resource_intel(out_dir, endpoints, application,
                                   app_graph, metrics, ck)

        # ── 8d. INVARIANT DISCOVERY (agent Phase 6, offline) ─────────
        # Mine holding rules from matrix observations; second-opinion
        # re-evaluation that corroborates existing findings or emits
        # genuinely new ones — never duplicates.
        inv_findings = self._discover_invariants(
            out_dir, endpoints, evidence, metrics, coverage, findings)
        if inv_findings:
            findings += inv_findings
            write_jsonl(out_dir / "findings.jsonl", findings)

        # ── 9. AI (+ loop closure into deterministic testing) ───────────
        hypotheses: List[Hypothesis] = []
        planner = AIPlanner(self.cfg)
        for problem in planner.validate_config():
            log.warning("ai config: %s", problem)
        if (self.profile.run_ai or self.cfg.ai.enabled) and \
                planner.available():
            ck.mark("ai", "running")
            techs = read_jsonl(out_dir / "technologies.jsonl")
            eps = [e.to_dict() for e in endpoints]
            fs = [f.to_dict() for f in findings]
            hypotheses = planner.generate_hypotheses(techs, eps, fs)
            hypotheses += self._plan_js_chunks(planner, out_dir)
            metrics.hypotheses_generated = len(hypotheses)

            # loop closure (spec §8): feed hypotheses back into tests
            findings += self._validate_hypotheses(
                hypotheses, endpoints, evidence, metrics, client,
                nuclei, live_file)
            write_jsonl(out_dir / "hypotheses.jsonl", hypotheses)
            ck.mark("ai")
        else:
            ck.mark("ai", "skipped")

        # ── 10. REPORT ──────────────────────────────────────────────────
        ck.mark("report", "running")
        metrics.scan_duration_seconds = time.time() - started
        metrics.result_status_counts = {status: sum(
            1 for finding in findings
            if finding.result_status == status)
            for status in RESULT_STATUSES}
        metrics.write(out_dir / "metrics.json")
        (out_dir / "coverage.json").write_text(
            __import__("json").dumps(coverage.to_dict(), indent=2))
        ck.save_blob("coverage", coverage.to_dict())
        ck.save_blob("budgets", budgets.to_dict())
        render_html(out_dir / "report.html", target, findings,
                    [h.to_dict() for h in hypotheses],
                    metrics.to_dict(),
                    min_severity=self.cfg.reporting.min_severity,
                    output_dir=out_dir,
                    coverage=coverage.to_dict(),
                    safety_info=getattr(self, "_safety_info", None))
        ck.mark("report")
        log.info("done: %s (%.1fs)", host, metrics.scan_duration_seconds)

    # =====================================================================
    # PREFLIGHT + DRY-RUN (Milestone 1)
    # =====================================================================
    @staticmethod
    def _reserve_or_block(budgets, coverage, test_class: str, plan,
                          host: str = "") -> bool:
        """Reserve a sweep's worst-case cost up front. Failure records
        blocked coverage and skips the sweep — never a negative."""
        if budgets.reserve(plan.total, host):
            log.info("%s: reserved %d requests (base=%d mut=%d "
                     "burst=%d verify=%d)", plan.module, plan.total,
                     plan.baseline_requests, plan.mutation_requests,
                     plan.concurrency_requests,
                     plan.verification_requests)
            return True
        log.warning("%s: cannot reserve %d requests — skipping sweep "
                    "(budget)", plan.module, plan.total)
        coverage.record(test_class, "blocked",
                        f"could not reserve {plan.total} requests")
        return False
    def _halted(self) -> bool:
        """True when sweeps must stop: stop-on-candidate fired, or the
        operator interrupted (SIGINT/SIGTERM). Untested work keeps its
        not_tested status — halting never manufactures negatives."""
        local = getattr(self, "_stop_flag", None)
        if local is not None and local.is_set():
            return True
        try:
            return get_interrupt_flag().is_set()
        except Exception:
            return False

    def _paced(self):
        """Cooldown between stateful probes (no-op unless configured,
        and safe when _run_one never ran, e.g. direct unit calls)."""
        pacer = getattr(self, "_pacer", None)
        if pacer is not None:
            pacer.wait()

    def _note_candidate(self):
        if bool(getattr(self.cfg.safety, "stop_on_candidate", False)):
            flag = getattr(self, "_stop_flag", None)
            if flag is not None and not flag.is_set():
                flag.set()
                log.info("stop-on-candidate: halting remaining sweeps "
                         "(started findings are kept)")

    def _preflight_or_refuse(self, target: str, out_dir: Path,
                             stop: StopFlag) -> dict:
        """Resolve modules, check strict gates pre-network. Returns the
        safety-info block for the report. Raises AuthorizationRefused."""
        states = resolve_modules(self.cfg, self.profile)
        strict = bool(getattr(self.cfg.safety, "strict", False))
        level = max_level(states)
        auth = Authorization.from_safety_cfg(self.cfg)
        gated = [s.name for s in states
                 if s.enabled and s.name in GATED_MODULES]
        info = {"strict": strict, "max_impact": level,
                "modules": [{"name": s.name, "level": s.level,
                             "enabled": s.enabled} for s in states],
                "gated_modules": gated,
                "authorization": auth.describe(), "refusal": []}
        if strict:
            reasons = auth.check(target, gated)
            info["refusal"] = reasons
            if reasons:
                for r in reasons:
                    log.error("preflight refused: %s", r)
                raise AuthorizationRefused(reasons)
            log.info("preflight strict OK (impact=%s, gated=%s)",
                     level, ",".join(gated) or "none")
        else:
            if gated:
                log.warning("preflight: stateful modules %s run WITHOUT "
                            "authorization metadata (strict mode off) — "
                            "consider --strict for controlled targets",
                            ",".join(gated))
            log.info("preflight impact=%s (non-strict, gates advisory)",
                     level)
        return info

    def dry_run(self, target: str) -> dict:
        """Zero-network plan: modules, authorization, costs, exclusions."""
        host = (target.replace("http://", "")
                .replace("https://", "").split("/")[0])
        out_dir = self.base_output / host
        plan = dry_run_plan(target, self.cfg, self.profile, out_dir)
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
            import json as _json
            (out_dir / "preflight.json").write_text(
                _json.dumps(plan, indent=2))
        except Exception as e:
            log.debug("preflight save failed: %s", e)
        return plan

    # =====================================================================
    # STAGES
    # =====================================================================
    def _recon(self, target: str, out_dir: Path) -> List[str]:
        url = target if target.startswith("http") else f"http://{target}"
        host = target.replace("http://", "").replace(
            "https://", "").split("/")[0]
        jobs = []
        ps = Path.home() / "ParamSpider" / "paramspider.py"
        if ps.exists():
            jobs.append((["python3", str(ps), "-d", host, "--level", "high",
                          "--quiet", "-o", str(out_dir / "param.txt")],
                         "paramspider", None, out_dir / "param.txt"))
        if which("waybackurls"):
            jobs.append((["waybackurls"], "waybackurls",
                         host + "\n", out_dir / "wayback.txt"))
        if which("gauplus"):
            jobs.append((["gauplus", "-subs"], "gauplus",
                         host + "\n", out_dir / "gau.txt"))
        if which("hakrawler"):
            jobs.append((["hakrawler", "-d", "3", "-subs", "-u"],
                         "hakrawler", url + "\n", out_dir / "hakrawler.txt"))
        if which("katana"):
            rl = 30 if self.cfg.scan.rate_limit >= 100 else 10
            jobs.append((["katana", "-d", "3", "-silent", "-rl", str(rl)],
                         "katana", url + "\n", out_dir / "katana.txt"))

        import concurrent.futures
        def _run(job):
            args, name, inp, out_path = job
            r = run(args, timeout=self.cfg.scan.timeout, input_data=inp)
            if out_path and r.stdout:
                Path(out_path).write_text(r.stdout)
            return name

        with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.cfg.scan.concurrency) as ex:
            for name in ex.map(_run, jobs):
                log.info("recon: %s done", name)

        self._merge_recon(out_dir)
        return self._read_lines(out_dir / "raw.txt")

    def _merge_recon(self, out_dir: Path):
        """Merge recon files into raw.txt, applying crawl_exclude_exts."""
        excl = {e.lower() for e in self.cfg.scope.crawl_exclude_exts}
        raw: Set[str] = set()
        for f in ("param.txt", "wayback.txt", "gau.txt",
                  "hakrawler.txt", "katana.txt",
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

    def _harvest_robots(self, client, base_url: str, out_dir: Path):
        try:
            r = robots_mod.fetch_robots(client, base_url,
                                        self.cfg.scan.http_timeout)
        except Exception as e:
            log.debug("robots harvest failed: %s", e)
            return
        if not r["paths"] and not r["sitemaps"]:
            return
        from urllib.parse import urljoin
        urls: Set[str] = set()
        for p in r["paths"]:
            urls.add(urljoin(base_url, p))
        for sm in r["sitemaps"][:5]:
            try:
                urls.update(robots_mod.fetch_sitemap(
                    client, sm, self.cfg.scan.http_timeout))
            except Exception:
                continue
        if urls:
            (out_dir / "robots.txt.out").write_text("\n".join(sorted(urls)))
            log.info("robots/sitemap: %d URLs harvested", len(urls))

    def _harvest_api_specs(self, client, base_url: str,
                           endpoints: List[Endpoint], out_dir: Path):
        try:
            specs = spec_mod.discover(client, base_url,
                                      self.cfg.scan.http_timeout)
        except Exception as e:
            log.debug("api spec discovery failed: %s", e)
            return
        if not specs:
            return
        (out_dir / "api_specs.json").write_text(
            __import__("json").dumps(specs, indent=2))
        from urllib.parse import urljoin
        added = 0
        for spec in specs:
            base = spec.get("base", "") or base_url
            for ep in spec["endpoints"]:
                full = urljoin(base, ep["path"])
                if not self.scope.is_in_scope(full):
                    continue
                n = normalize_url(full)
                if any(e.normalized_url == n for e in endpoints):
                    continue
                e = Endpoint(
                    url=full, normalized_url=n,
                    host=__import__("urllib.parse", fromlist=["urlparse"])
                    .urlparse(full).hostname or "",
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

    def _build_endpoints(self, urls: List[str], host: str, out_dir: Path,
                         client, base_url: str, budgets, metrics
                         ) -> List[Endpoint]:
        by_norm: Dict[str, Endpoint] = {}
        from urllib.parse import urlparse
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
        if js_urls and self.cfg.discovery.javascript and \
                self.profile.js_analysis:
            analyzer = JSAnalyzer(self.cfg, client, out_dir / "cache")
            for jurl in js_urls[:self.cfg.discovery.js_max_files]:
                result = analyzer.analyze(jurl)
                js_results.append(result)
                for ep in result["endpoints"]:
                    self._add_js_endpoint(by_norm, host, ep["path"])
                # deep source-map endpoints (spec §6)
                for sm in result.get("source_maps", []):
                    for dep in (sm.get("details") or {}).get("endpoints", []):
                        self._add_js_endpoint(by_norm, host, dep["path"],
                                              source="sourcemap")
                    self._add_sourcemap_params(
                        by_norm, host,
                        (sm.get("details") or {}).get("params", []))
        if js_results:
            write_jsonl(out_dir / "js_analysis.jsonl", js_results)
        # ── browser-driven discovery (agent Phase 1) ───────────────────
        for entry in self._browser_discover(
                base_url, host, out_dir, budgets, metrics):
            self._merge_browser_entry(by_norm, host, entry)
        return list(by_norm.values())

    @staticmethod
    def _merge_browser_entry(by_norm: Dict[str, Endpoint], host: str,
                             entry: Dict):
        """Merge one browser-discovered request/form into the pipeline."""
        from urllib.parse import urlparse
        url = entry.get("url", "")
        if not url:
            return
        method = (entry.get("method") or "GET").upper()
        n = normalize_url(url)
        ep = by_norm.get(n)
        if ep is None:
            p = urlparse(n)
            ep = Endpoint(url=url, normalized_url=n,
                          host=p.hostname or host, path=p.path,
                          method=method, source=["browser"])
            by_norm[n] = ep
        elif "browser" not in ep.source:
            ep.source.append("browser")
        new_params = []
        for name in entry.get("params") or []:
            new_params.append(Parameter(
                name=name, location="query", source=["browser"],
                confidence=Confidence.PROBABLE.value))
        for name, sample in (entry.get("body") or {}).items():
            new_params.append(Parameter(
                name=name, location="body", source=["browser"],
                sample_value=sample,
                confidence=Confidence.PROBABLE.value))
        for name in entry.get("inputs") or []:
            new_params.append(Parameter(
                name=name, location="body", source=["browser:form"],
                confidence=Confidence.POSSIBLE.value))
        if entry.get("form_method") and ep.method == "GET":
            ep.method = entry["form_method"].upper()
        ep.query_parameters = param_mod.merge(
            ep.query_parameters, [p for p in new_params
                                  if p.location == "query"])
        ep.body_parameters = param_mod.merge(
            ep.body_parameters, [p for p in new_params
                                 if p.location != "query"])

    def _browser_discover(self, base_url: str, host: str, out_dir: Path,
                          budgets, metrics) -> List[Dict]:
        """Crawl with Chromium (GET navigations only), record traffic.

        Returns endpoint dicts for pipeline merge. Disabled, missing
        Playwright, or launch failure → [] with a log line.
        """
        if not (self.profile.browser or self.cfg.browser.enabled):
            return []
        from .browser.browser import BrowserEngine, playwright_available
        if not playwright_available():
            log.info("browser: playwright not installed — skipping "
                     "(`pip install apex-fuzzer[browser]`)")
            return []
        from .browser.network import NetworkRecorder
        from .browser.actions import snapshot_dom
        from .browser.storage import StorageCapture
        from .browser.sessions import SessionManager
        bcfg = self.cfg.browser
        entries: List[Dict] = []
        pages_visited = 0
        try:
            with BrowserEngine(self.cfg, headless=bcfg.headless,
                               timeout_ms=bcfg.navigation_timeout_ms
                               ) as engine:
                ctx = engine.new_context()
                page = ctx.new_page()
                recorder = NetworkRecorder(
                    scope=self.scope,
                    max_requests=bcfg.max_pages * 50)
                if bcfg.capture_network:
                    recorder.attach(page)
                seen, queue = set(), [(base_url, 0)]
                while queue and pages_visited < bcfg.max_pages:
                    url, depth = queue.pop(0)
                    if url in seen or depth > bcfg.max_depth:
                        continue
                    if not self.scope.is_in_scope(url):
                        continue
                    if not budgets.consume_test("browser", url):
                        log.warning("browser: action budget exhausted")
                        break
                    seen.add(url)
                    try:
                        page.goto(url, timeout=bcfg.navigation_timeout_ms)
                        pages_visited += 1
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
                        full = self._resolve_link(url, link)
                        if full and full not in seen and \
                                self.scope.is_in_scope(full):
                            queue.append((full, depth + 1))
                    for form in snap.get("forms") or []:
                        action = form.get("action") or url
                        full = self._resolve_link(url, action)
                        if not full or not self.scope.is_in_scope(full):
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
                if bcfg.capture_websocket:
                    for ws in recorder.websockets:
                        entries.append({"url": ws, "method": "WS",
                                        "params": [], "body": {}})
                (out_dir / "browser_urls.txt").write_text(
                    "\n".join(sorted({e["url"] for e in entries
                                      if e.get("url")})))
                import json as _json
                (out_dir / "browser_traffic.json").write_text(
                    _json.dumps(recorder.to_dict(), indent=2))
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
            metrics.browser_requests = len(recorder.requests)
        except Exception:
            pass
        log.info("browser: %d pages → %d endpoint entries",
                 pages_visited, len(entries))
        return entries

    @staticmethod
    def _resolve_link(base: str, link: str) -> Optional[str]:
        from urllib.parse import urljoin, urlsplit
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

    def _add_js_endpoint(self, by_norm: Dict[str, Endpoint], host: str,
                         path: str, source: str = "javascript"):
        if not path:
            return
        full = f"https://{host}{path}"
        if not self.scope.is_in_scope(full):
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

    @staticmethod
    def _add_sourcemap_params(by_norm: Dict[str, Endpoint], host: str,
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
                    if any(p.name == name for p in ep.query_parameters):
                        continue
                    seen.add(name)
                    ep.query_parameters.append(Parameter(
                        name=name, location="query",
                        source=["sourcemap"],
                        confidence=Confidence.POSSIBLE.value))
                    attached += 1
                    if attached >= 30:
                        break

    def _map_attack_surface(self, endpoints: List[Endpoint], host: str,
                            out_dir: Path, metrics: Metrics, client):
        tech_by_name = {}
        html_params: List[Parameter] = []
        all_headers: Dict[str, str] = {}
        page_ids: List[tuple] = []  # (url, param, value, source)
        for ep in [e for e in endpoints if e.method == "GET"][:30]:
            try:
                r = client.get(ep.url, timeout=self.cfg.scan.http_timeout)
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
                if self.cfg.discovery.html_forms:
                    html_params.extend(param_mod.from_html(r.text))
                # Phase 5: harvest IDs from already-fetched bodies —
                # zero extra requests, feeds resource intel only
                try:
                    from .application.resources import (
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
        self._page_ids = page_ids
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
                        if e not in tech_by_name[tech.name].evidence:
                            tech_by_name[tech.name].evidence.append(e)
                else:
                    tech_by_name[tech.name] = tech
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

        # ── active parameter mining: Arjun + LinkFinder (spec §1) ───────
        if self.profile.param_mining:
            self._mine_hidden_params(endpoints, host, out_dir, metrics,
                                     all_headers, tech_by_name)

    # ── APPLICATION MODEL + GRAPH (§4–5) ─────────────────────────────
    def _build_app_state(self, endpoints: List[Endpoint], host: str,
                         out_dir: Path, ck: Checkpoint, resume: bool,
                         metrics: Metrics,
                         coverage: CoverageTracker):
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
                application, graph = self._fresh_app_state(
                    endpoints, host, out_dir, ck)
        else:
            application, graph = self._fresh_app_state(
                endpoints, host, out_dir, ck)
        metrics.resources_discovered = len(application.resources)
        identities = application.identities
        metrics.identities_tested = len(identities)
        metrics.roles_tested = len({r.name for r in application.roles})
        metrics.tenants_tested = len({t.name for t in application.tenants})
        metrics.graph_nodes = len(graph.nodes)
        metrics.graph_edges = len(graph.edges)
        return application, graph

    def _fresh_app_state(self, endpoints: List[Endpoint], host: str,
                         out_dir: Path, ck: Checkpoint):
        techs = read_jsonl(out_dir / "technologies.jsonl")
        application = build_from_scan(host, endpoints, techs,
                                      self.cfg.auth.contexts)
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

    # ── ARJUN PARAM MINING (spec §1) ───────────────────────────────────
    def _mine_hidden_params(self, endpoints: List[Endpoint], host: str,
                            out_dir: Path, metrics: Metrics,
                            all_headers: Dict[str, str],
                            tech_by_name: Dict):
        if not self.cfg.discovery.arjun:
            return
        if not param_miner.arjun_available():
            log.info("arjun not installed — hidden param mining skipped "
                     "(pipx install arjun)")
            return
        eligible = [e for e in endpoints
                    if e.method == "GET"
                    and e.endpoint_type in ("api", "page", "authentication")]
        if self.cfg.discovery.arjun_require_existing_param:
            eligible = [e for e in eligible
                        if e.query_parameters or e.body_parameters]
        # endpoints that already have params are the highest-yield targets
        eligible.sort(key=lambda e: -(len(e.query_parameters)
                                      + len(e.body_parameters)))
        eligible = eligible[:self.cfg.discovery.arjun_max_endpoints]
        if not eligible:
            return
        log.info("arjun: mining %d endpoints (methods=%s)",
                 len(eligible), ",".join(self.cfg.discovery.arjun_methods))
        for i, ep in enumerate(eligible):
            if not self.scope.active_test_allowed(ep.url):
                continue
            found = param_miner.mine_hidden_params(
                ep.url,
                methods=self.cfg.discovery.arjun_methods,
                out_dir=out_dir / "arjun",
                timeout=self.cfg.discovery.arjun_timeout,
                stable=self.cfg.discovery.arjun_stable,
                rate_limit=self.cfg.scan.rate_limit)
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
        if self.cfg.discovery.linkfinder and which("linkfinder"):
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

    # ── PROBE LIVE  (BUGFIX A) ──────────────────────────────────────────
    def _probe_live(self, out_dir: Path, live_file: Path):
        raw = out_dir / "raw.txt"
        if not raw.exists() or raw.stat().st_size == 0:
            log.warning("nothing to probe — raw.txt empty")
            return
        if not which("httpx"):
            log.warning("httpx missing — falling back to raw.txt as live set")
            live_file.write_text(raw.read_text())
            return
        r = run([
            "httpx", "-silent",
            "-mc", LIVE_CODES,
            "-l", str(raw),
            "-o", str(live_file),
        ], timeout=self.cfg.scan.timeout * 2)
        if r.timed_out:
            log.warning("httpx timed out")
        if not live_file.exists():
            live_file.write_text("")

    # ── SUBDOMAIN TAKEOVER  (BUGFIX B + tko-subs confirmed, spec §10) ──
    def _takeover_check(self, out_dir: Path, host: str,
                        metrics: Metrics,
                        coverage: Optional[CoverageTracker] = None
                        ) -> List[Finding]:
        raw = out_dir / "raw.txt"
        if not raw.exists():
            return []
        hosts: Set[str] = set()
        from urllib.parse import urlparse
        for line in raw.read_text(errors="ignore").splitlines():
            try:
                h = urlparse(line.strip()).hostname
                if h and self.scope.is_in_scope(f"https://{h}/"):
                    hosts.add(h)
            except Exception:
                continue
        if not hosts:
            return []
        hosts_file = out_dir / "hosts.txt"
        hosts_file.write_text("\n".join(sorted(hosts)))

        # confirmed takeover via tko-subs -takeover (github/heroku tokens)
        if self.profile.run_tko and which("tko-subs"):
            tko_out = out_dir / "tko.csv"
            args = ["tko-subs", "-domains", str(hosts_file),
                    "-output", str(tko_out)]
            import os
            if os.environ.get("GITHUB_TOKEN"):
                args += ["-takeover",
                         "-githubtoken", os.environ["GITHUB_TOKEN"],
                         "-herokuusername",
                         os.environ.get("HEROKU_USERNAME", ""),
                         "-herokuapikey", os.environ.get("HEROKU_API_KEY", ""),
                         "-herokuappname",
                         os.environ.get("HEROKU_APP_NAME", "")]
            log.info("tko-subs: checking %d hosts (%s)",
                     len(hosts),
                     "confirmed takeover" if "-takeover" in args
                     else "fingerprint only")
            r = run(args, timeout=self.cfg.scan.timeout * 2)
            if r.stdout:
                (out_dir / "takeover.txt").write_text(r.stdout)
            if tko_out.exists():
                return self._parse_tko(tko_out, metrics, coverage)
        # fallback: subzy fingerprint (detection-only)
        if which("subzy"):
            log.info("subzy: checking %d hosts", len(hosts))
            r = run([
                "subzy", "run",
                "--targets", str(hosts_file),
                "--hide_fails", "--https",
                "--timeout", "10",
            ], timeout=self.cfg.scan.timeout * 2)
            if r.stdout:
                (out_dir / "takeover.txt").write_text(r.stdout)
        return []

    def _parse_tko(self, tko_csv: Path, metrics: Metrics,
                   coverage: Optional[CoverageTracker] = None
                   ) -> List[Finding]:
        """tko-subs CSV: Domain,CNAME,Provider,IsVulnerable,IsTakenOver,Resp"""
        findings: List[Finding] = []
        try:
            with open(tko_csv) as f:
                for row in csv.DictReader(f):
                    domain = (row.get("Domain") or "").strip()
                    vuln = (row.get("IsVulnerable") or "").lower()
                    taken = (row.get("IsTakenOver") or "").lower()
                    provider = row.get("Provider") or "unknown"
                    if not domain or vuln != "true":
                        continue
                    confirmed = taken == "true"
                    metrics.takeover_confirmed += 1
                    if coverage is not None:
                        coverage.record(
                            "takeover",
                            "confirmed" if confirmed else "candidate",
                            f"tko-subs: {domain} ({provider})")
                    findings.append(Finding(
                        id=f"takeover-{domain}",
                        source="tko-subs" if confirmed else "tko-subs-fp",
                        name=(f"Subdomain takeover CONFIRMED — {domain} "
                              f"({provider})" if confirmed
                              else f"Subdomain takeover candidate — "
                                   f"{domain} ({provider})"),
                        severity="high",
                        confidence=(Confidence.CONFIRMED.value
                                    if confirmed else
                                    Confidence.PROBABLE.value),
                        validation_status=(
                            ValidationStatus.CONFIRMED.value
                            if confirmed else
                            ValidationStatus.STRONG_CANDIDATE.value),
                        host=domain,
                        matched_at=f"https://{domain}/",
                        endpoint_url=f"https://{domain}/",
                        method="GET",
                        response_status=200 if not confirmed else None,
                        description=(
                            f"CNAME {row.get('CNAME', '')} points to an "
                            f"unclaimed {provider} resource."
                            + (" The resource was claimed during the scan "
                               "to confirm control." if confirmed else
                               " No takeover performed — fingerprint only.")),
                        tags=["subdomain-takeover", provider],
                        raw={"provider": provider,
                             "cname": row.get("CNAME", ""),
                             "response": (row.get("Response") or "")[:500]},
                    ))
        except Exception as e:
            log.warning("tko csv parse failed: %s", e)
        if findings:
            log.info("takeover: %d candidate(s)", len(findings))
        return findings

    # ── VALIDATION (spec §2/3/4/8) ─────────────────────────────────────
    def _validate(self, findings: List[Finding],
                  endpoints: List[Endpoint], evidence: EvidenceStore,
                  metrics: Metrics, client, out_dir: Path,
                  budgets: BudgetTracker, coverage: CoverageTracker,
                  app_graph=None, ck=None) -> List[Finding]:
        out: List[Finding] = []

        # 0) WAF fingerprint from a live probe (drives mutation choice)
        waf = metrics.waf_detected or ""
        if endpoints and not waf:
            try:
                r = client.get(endpoints[0].url,
                               timeout=self.cfg.scan.http_timeout)
                waf = fingerprint_waf(r.headers) or ""
                if waf:
                    metrics.waf_detected = waf
            except Exception:
                pass
        self._active_waf = waf or None

        techs = read_jsonl(out_dir / "technologies.jsonl")
        identities, _, _ = from_auth_contexts(self.cfg.auth.contexts)

        # 1) differential auth-context testing (spec §2)
        if (self.profile.differential or self.cfg.validation.differential):
            diff = DifferentialTester(self.cfg, client)
            out += self._differential_probe(endpoints, diff, evidence,
                                            metrics, budgets, coverage)

        # 1b) authz matrix: harvest → swap → per-method sweep (#1–2)
        if (self.profile.authz_matrix or self.cfg.authorization.enabled):
            out += self._authz_matrix_probe(endpoints, evidence,
                                            metrics, budgets, coverage,
                                            client, out_dir, identities,
                                            app_graph=app_graph)

        # 2) OAST sweep for blind SSRF (spec §3)
        oast_provider = self._maybe_register_oast()
        try:
            run_oast_sweep = (self.profile.oast
                              or self.cfg.validation.ssrf
                              or self.cfg.validation.enabled)
            if (run_oast_sweep and oast_provider and
                    oast_provider.available()):
                out += self._oast_sweep(endpoints, oast_provider,
                                        evidence, metrics, client, out_dir,
                                        budgets, coverage)

            # 3) per-finding plugins (§48: registry + TestResult)
            test_ctx = TestContext(
                self.cfg, http=client, scope=self.scope,
                budgets=budgets, oast_provider=oast_provider,
                waf=waf or None, technologies=techs,
                identities=identities, evidence=evidence,
                timeout=self.cfg.scan.http_timeout,
                browser_enabled=(self.profile.browser or
                                 self.cfg.browser.enabled))
            by_norm = {e.normalized_url: e for e in endpoints}
            for f in findings:
                test_class = _classify_finding(f)
                ep = self._finding_endpoint(f, by_norm)
                target = TestTarget(
                    f.matched_at,
                    endpoint_type=ep.endpoint_type if ep else "unknown",
                    parameter=f.parameter, method=f.method,
                    finding=f, endpoint=ep, test_class=test_class)
                applicable = []
                for plugin, res in run_plugins(target, test_ctx,
                                               PLUGIN_ORDER):
                    if res.status in ("skipped", "error"):
                        continue
                    if res.status == "blocked":
                        coverage.record(test_class, "blocked",
                                        f"{plugin.name} blocked")
                        continue
                    applicable.append((plugin, res))
                applied = bool(applicable)
                if applicable:
                    self._apply_plugin_results(
                        f, applicable, evidence, test_class, coverage)
                if applied:
                    metrics.validation_candidates += 1
                    if f.validation_status == "confirmed":
                        metrics.validated_confirmed += 1
                        self._note_candidate()
                    elif f.validation_status == "strong_candidate":
                        self._note_candidate()
                    elif f.validation_status == "false_positive":
                        metrics.false_positives += 1
                out.append(f)

            # 4) stored-XSS correlation (bounty item #3, opt-in: persists
            # canaries server-side)
            if (self.profile.second_order or
                    self.cfg.validation.second_order):
                out += self._second_order_probe(
                    endpoints, evidence, metrics, budgets, coverage,
                    client, identities)
            if self.cfg.validation.second_order_ssrf:
                out += self._second_order_ssrf_probe(
                    endpoints, evidence, metrics, budgets, coverage,
                    client, identities, oast_provider)
            # 5) business-logic mutations (opt-in: submits abuse values)
            if (self.profile.business_logic or
                    self.cfg.business.enabled):
                out += self._business_logic_probe(
                    endpoints, evidence, metrics, budgets, coverage,
                    client, identities)
            # 6) race engine (opt-in: synchronized bursts of
            # state-changing requests)
            if (self.profile.race or self.cfg.race.enabled):
                out += self._race_probe(
                    endpoints, evidence, metrics, budgets, coverage,
                    client, identities)
            # behavioral state accumulated above → persist the graph
            # (agent Phase 3: validation findings ride on observations)
            if app_graph is not None:
                try:
                    app_graph.save(out_dir / "application_graph.json")
                    if ck is not None:
                        ck.save_blob("application_graph",
                                     app_graph.to_dict())
                    metrics.graph_nodes = len(app_graph.nodes)
                    metrics.graph_edges = len(app_graph.edges)
                except Exception as e:
                    log.debug("graph persist failed: %s", e)
        finally:
            if oast_provider is not None:
                oast_provider.close()
        return out

    # ── AUTOMATED LOGIN (agent Phase 2) ──────────────────────────────
    def _login_identities(self, out_dir: Path, metrics: Metrics):
        """Mint sessions for login identities lacking headers.

        Only enriches auth contexts that exist by name and have no
        headers yet. MFA stops at a persisted checkpoint for the
        operator — never bypassed, never retried blindly.
        """
        login = self.cfg.auth.login
        if not login.enabled or not login.url or not login.identities:
            return
        if not self.scope.is_in_scope(login.url):
            log.warning("login: %s out of scope — skipping", login.url)
            return
        from .browser.browser import BrowserEngine, playwright_available
        if not playwright_available():
            log.info("login: playwright not installed — skipping")
            return
        from .auth.workflows import LoginManager, LoginIdentity
        from .browser.sessions import SessionManager
        mgr = LoginManager(login, scope=self.scope,
                           timeout_ms=self.cfg.browser.navigation_timeout_ms)
        by_name = {c.name: c for c in self.cfg.auth.contexts}
        try:
            with BrowserEngine(
                    self.cfg,
                    headless=self.cfg.browser.headless,
                    timeout_ms=self.cfg.browser.navigation_timeout_ms
                    ) as engine:
                for entry in login.identities:
                    if entry.name not in by_name:
                        log.debug("login: no auth context named '%s' — "
                                  "skipping (contexts are never auto-"
                                  "created)", entry.name)
                        continue
                    ctx = by_name[entry.name]
                    if ctx.headers:
                        continue
                    password = LoginIdentity(
                        name=entry.name, username=entry.username,
                        password_env=entry.password_env,
                        roles=list(entry.roles),
                        tenant=entry.tenant).resolve_password()
                    if not password:
                        log.warning(
                            "login '%s': %s is empty/unset — skipping",
                            entry.name,
                            entry.password_env or "(no password_env)")
                        continue
                    metrics.logins_attempted += 1
                    try:
                        bctx = engine.new_context(identity=entry.name)
                        page = bctx.new_page()
                    except Exception as e:
                        log.warning("login '%s': context failed: %s",
                                    entry.name, e)
                        continue
                    try:
                        status, payload = mgr.attempt(
                            page, bctx,
                            LoginIdentity(
                                name=entry.name,
                                username=entry.username,
                                password_env=entry.password_env,
                                roles=list(entry.roles),
                                tenant=entry.tenant),
                            password)
                    finally:
                        try:
                            page.close()
                        except Exception:
                            pass
                        try:
                            bctx.close()
                        except Exception:
                            pass
                    if status == "ok":
                        ident = payload.to_identity()
                        ctx.headers = dict(ident.auth_headers)
                        ctx.identity = ctx.identity or entry.name
                        if not ctx.roles:
                            ctx.roles = list(entry.roles)
                        if not ctx.tenant:
                            ctx.tenant = entry.tenant
                        metrics.logins_succeeded += 1
                        try:
                            SessionManager(
                                out_dir / "sessions").save(payload)
                        except Exception as e:
                            log.debug("login: session save failed: %s",
                                      e)
                        log.info("login '%s': context enriched "
                                 "(%d cookies)", entry.name,
                                 len(payload.cookies))
                    elif status == "mfa":
                        try:
                            payload.save(out_dir /
                                         f"mfa_{entry.name}.json")
                        except Exception as e:
                            log.debug("login: checkpoint save failed: %s",
                                      e)
                        log.warning(
                            "login '%s': MFA checkpoint at %s — complete "
                            "the challenge manually, then re-run with a "
                            "static session", entry.name, payload.url)
                    else:
                        log.warning("login '%s' failed: %s",
                                    entry.name, payload)
        except RuntimeError as e:
            log.warning("login unavailable: %s", e)
        except Exception as e:
            log.warning("login engine failed: %s", e, exc_info=True)

    @staticmethod
    def _finding_endpoint(f: Finding, by_norm: Dict[str, Endpoint]
                          ) -> Optional[Endpoint]:
        if not f.matched_at:
            return None
        try:
            return by_norm.get(normalize_url(f.matched_at))
        except Exception:
            return None

    @staticmethod
    def _apply_plugin_result(f: Finding, plugin, res, evidence,
                             test_class: str, coverage: CoverageTracker):
        """Apply one validator result (legacy/single-plugin helper)."""
        result_status = res.result_status
        if result_status == ResultStatus.VERIFIED_EFFECT.value:
            conf = "confirmed"
        elif result_status == ResultStatus.CANDIDATE.value:
            conf = "probable"
        elif result_status == ResultStatus.NEGATIVE.value:
            conf = "probable"
        else:
            conf = "unknown"
        if result_status is None:
            # Older/custom plugins may still return only the legacy status.
            result_status = {
                "confirmed": ResultStatus.VERIFIED_EFFECT.value,
                "candidate": ResultStatus.CANDIDATE.value,
                "negative": ResultStatus.NEGATIVE.value,
                "inconclusive": ResultStatus.INCONCLUSIVE.value,
            }.get(res.status, ResultStatus.INCONCLUSIVE.value)
        f.set_result_status(result_status)
        f.confidence = conf
        notes = "; ".join(res.observations)[:500]
        if getattr(plugin, "allocates_evidence", True):
            evidence.allocate(f)
            if res.evidence:
                f.raw = res.evidence
            evidence.record(f,
                            request_text=f"{f.method} {f.matched_at}",
                            response_headers=f.response_headers)
        else:
            # prescreen path: record notes without pre-allocating
            f.false_positive_notes = notes
            f.raw = {"evidence": res.evidence}
            evidence.record(
                f, request_text=f"{f.method} {f.matched_at}",
                response_text=notes)
        coverage.record_result(test_class, result_status,
                               notes or f"plugin {plugin.name}")

    @staticmethod
    def _plugin_result_status(res) -> str:
        """Normalize legacy and canonical plugin outcomes."""
        result_status = getattr(res, "result_status", None)
        if result_status in RESULT_STATUSES:
            return result_status
        return {
            "confirmed": ResultStatus.VERIFIED_EFFECT.value,
            "candidate": ResultStatus.CANDIDATE.value,
            "negative": ResultStatus.NEGATIVE.value,
            "inconclusive": ResultStatus.INCONCLUSIVE.value,
            "not_tested": ResultStatus.OBSERVATION.value,
        }.get(getattr(res, "status", ""),
              ResultStatus.INCONCLUSIVE.value)

    @staticmethod
    def _aggregate_plugin_status(statuses: List[str]) -> str:
        """Combine independent evidence without last-plugin-wins behavior.

        Positive and negative evidence conflicts become inconclusive. An
        inconclusive validator cannot erase a supported candidate; verified
        evidence wins over candidates when no negative evidence conflicts.
        """
        verified = ResultStatus.VERIFIED_EFFECT.value
        candidate = ResultStatus.CANDIDATE.value
        negative = ResultStatus.NEGATIVE.value
        inconclusive = ResultStatus.INCONCLUSIVE.value
        observation = ResultStatus.OBSERVATION.value
        observed = [s for s in statuses if s in RESULT_STATUSES]
        has_positive = verified in observed or candidate in observed
        if has_positive and negative in observed:
            return inconclusive
        if verified in observed:
            return verified
        if candidate in observed:
            return candidate
        if inconclusive in observed:
            return inconclusive
        if negative in observed:
            return negative
        return observation

    @staticmethod
    def _apply_plugin_results(f: Finding, plugin_results, evidence,
                              test_class: str, coverage: CoverageTracker):
        """Aggregate validator evidence while retaining each tool's record."""
        normalized = [(plugin, res,
                       Orchestrator._plugin_result_status(res))
                      for plugin, res in plugin_results]
        statuses = [f.result_status] + [status for _, _, status in normalized]
        aggregate = Orchestrator._aggregate_plugin_status(statuses)

        records = []
        note_parts = []
        for plugin, res, status in normalized:
            observations = list(getattr(res, "observations", []) or [])
            notes = "; ".join(str(note) for note in observations)[:500]
            note_parts.append(f"{plugin.name}: {notes or status}")
            records.append({
                "plugin": plugin.name,
                "result_status": status,
                "duration_seconds": getattr(res, "duration_seconds", 0.0),
                "observations": observations,
                "errors": list(getattr(res, "errors", []) or []),
                "evidence": dict(getattr(res, "evidence", {}) or {}),
            })

        f.set_result_status(aggregate)
        f.confidence = {
            ResultStatus.VERIFIED_EFFECT.value: "confirmed",
            ResultStatus.CANDIDATE.value: "probable",
            ResultStatus.NEGATIVE.value: "probable",
        }.get(aggregate, "unknown")
        combined_notes = " | ".join(note_parts)[:2000]
        if aggregate in (ResultStatus.NEGATIVE.value,
                         ResultStatus.INCONCLUSIVE.value):
            f.false_positive_notes = combined_notes

        # Preserve the original Nuclei/source record and attach each
        # validator's independent evidence under an additive key.
        if not isinstance(f.raw, dict):
            f.raw = {"source_raw": f.raw}
        f.raw["validator_results"] = records

        if any(getattr(plugin, "allocates_evidence", True)
               for plugin, _, _ in normalized) and not f.evidence_dir:
            evidence.allocate(f)
        evidence.record(
            f, request_text=f"{f.method} {f.matched_at}",
            response_text=combined_notes,
            response_headers=f.response_headers)
        coverage.record_result(
            test_class, aggregate,
            combined_notes or "aggregated plugin outcomes")

    def _differential_probe(self, endpoints: List[Endpoint],
                            diff: DifferentialTester,
                            evidence: EvidenceStore, metrics: Metrics,
                            budgets: BudgetTracker,
                            coverage: CoverageTracker
                            ) -> List[Finding]:
        targets = [e for e in endpoints
                   if e.endpoint_type in PRIVILEGED_TYPES
                   or (has_idor_params(e)
                       and e.endpoint_type != "static")]
        # per-resource endpoints (idor params) first — BOLA hides there
        targets.sort(key=lambda e: 0 if has_idor_params(e) else 1)
        targets = targets[:self.cfg.validation.differential_max_endpoints]
        if not targets:
            return []
        log.info("differential: probing %d endpoints "
                 "(contexts=%s)", len(targets),
                 [c["name"] for c in diff.contexts])
        if not self._reserve_or_block(
                budgets, coverage, "authz",
                plan_differential(len(targets), len(diff.contexts))):
            return []
        tenant_of = {c.name: (getattr(c, "tenant", "") or "")
                     for c in self.cfg.auth.contexts}
        findings: List[Finding] = []
        for ep in targets:
            if self._halted():
                log.info("differential: halted by stop control; "
                         "remaining targets stay untested")
                break
            if not self.scope.active_test_allowed(ep.url):
                continue
            if not budgets.consume_test("authz", ep.normalized_url):
                coverage.record("authz", "blocked",
                                f"budget: {ep.normalized_url}")
                continue
            try:
                res = diff.probe(ep.url, ep.endpoint_type,
                                 timeout=self.cfg.scan.http_timeout)
            except BudgetExceeded:
                coverage.record("authz", "blocked",
                                f"budget: {ep.normalized_url}")
                continue
            metrics.differential_probes += 1
            metrics.authorization_tests += 1
            authed = [c.name for c in res.contexts
                      if c.name != "anonymous"]
            if res.verdict != "strong_candidate":
                # tested, no authorization gap observed (§45)
                coverage.record("authz", "tested_negative",
                                f"{ep.normalized_url}: {res.notes}")
                if has_idor_params(ep):
                    coverage.record("idor", "tested_negative",
                                    ep.normalized_url)
                continue
            metrics.differential_candidates += 1
            metrics.authorization_confirmed += 1
            self._note_candidate()
            is_bola = "BOLA" in res.notes
            coverage.record("bola" if is_bola else "authz", "candidate",
                            res.notes)
            coverage.record("idor", "candidate", res.notes)
            f = Finding(
                id=stable_finding_id("diff", ep.normalized_url),
                source="differential",
                name=("BOLA/IDOR: identical access for two users "
                      f"({ep.path})" if is_bola
                      else f"Broken access control on {ep.path}"),
                severity="high",
                confidence=Confidence.PROBABLE.value,
                validation_status=ValidationStatus.STRONG_CANDIDATE.value,
                host=ep.host,
                matched_at=ep.url,
                endpoint_url=ep.url,
                method=ep.method,
                description=res.notes,
                tags=["bola", "idor", "authz", ep.endpoint_type],
                raw={"contexts": [vars(c) for c in res.contexts],
                     "endpoint_type": ep.endpoint_type},
                false_positive_notes=(
                    "Responses compared across auth contexts; volatile "
                    "keys (csrf/token/timestamp/nonce) excluded; length "
                    "bucketed to 1KB."),
                identity="+".join(authed),
                tenant="+".join(sorted({tenant_of.get(a, "")
                                        for a in authed} - {""})),
            )
            evidence.allocate(f)
            evidence.record(
                f,
                request_text=(
                    "GET " + ep.url + "\n--- per-context results ---\n" +
                    "\n".join(f"{c.name}: HTTP {c.status} "
                              f"(len={c.length}, shape={c.key_shape[:60] or 'n/a'}, "
                              f"hash={c.body_hash})"
                              for c in res.contexts)),
                response_text=res.notes)
            findings.append(f)
            log.info("differential: STRONG candidate on %s — %s",
                     ep.url, res.notes)
        return findings

    # ── AUTHZ MATRIX: harvest → swap → per-method sweep (#1–2) ──────
    def _authz_matrix_probe(self, endpoints: List[Endpoint],
                            evidence: EvidenceStore, metrics: Metrics,
                            budgets: BudgetTracker,
                            coverage: CoverageTracker, client,
                            out_dir: Path, identities,
                            app_graph=None) -> List[Finding]:
        from .authorization.harvest import harvest_ids
        from .authorization.matrix import (AuthorizationMatrix,
                                           describe_cell, evaluate_cell)
        from .authorization.access_tests import swap_ids, sweep_methods
        cfg_a = self.cfg.authorization
        if len(identities) < 2:
            coverage.record("authz", "untestable",
                            "fewer than 2 identities configured")
            return []
        targets = [e for e in endpoints
                   if e.endpoint_type in PRIVILEGED_TYPES
                   or (has_idor_params(e)
                       and e.endpoint_type != "static")]
        targets.sort(key=lambda e: 0 if has_idor_params(e) else 1)
        targets = targets[:cfg_a.max_endpoints]
        if not targets:
            return []
        log.info("authz-matrix: %d endpoints × %s as %d identities",
                 len(targets), cfg_a.methods,
                 len(identities))
        if not self._reserve_or_block(
                budgets, coverage, "authz",
                plan_authz_matrix(len(targets), len(identities),
                                  len(cfg_a.methods),
                                  cfg_a.max_ids_per_endpoint)):
            return []
        matrix = AuthorizationMatrix()
        findings: List[Finding] = []
        seen_cells = set()

        matrix = AuthorizationMatrix()
        findings: List[Finding] = []
        seen_cells = set()
        all_swaps: list = []
        owner_headers = {getattr(i, "name", "anonymous"):
                         dict(getattr(i, "auth_headers", None) or {})
                         for i in identities}

        def ownership_fields_for(endpoint):
            overrides = cfg_a.ownership_fields_by_endpoint or {}
            for selector in (endpoint.url, endpoint.normalized_url,
                             endpoint.path):
                if selector in overrides:
                    return list(overrides[selector] or [])
            return list(cfg_a.ownership_fields or [])

        # — pass 1: harvest object IDs from every target (global pool
        # enables cross-endpoint replay, not just same-endpoint swap) —
        pool = []
        for ep in targets:
            if self._halted():
                log.info("authz-harvest: halted by stop control; "
                         "remaining targets stay untested")
                break
            if not self.scope.active_test_allowed(ep.url):
                continue
            if not budgets.consume_test("authz", ep.normalized_url):
                coverage.record("authz", "blocked",
                                f"budget: {ep.normalized_url}")
                continue
            try:
                pool.extend(harvest_ids(
                    client, ep, identities,
                    timeout=self.cfg.scan.http_timeout,
                    max_ids_per_param=cfg_a.max_ids_per_endpoint,
                    ownership_fields=ownership_fields_for(ep)))
            except BudgetExceeded:
                coverage.record("authz", "blocked",
                                f"budget: {ep.normalized_url}")
                continue
        self._harvest_pool = pool

        def handle_swaps(swaps, ep):
            for sw in swaps:
                metrics.authorization_tests += 1
                cross_tenant = bool(
                    sw.tester_tenant and sw.owner_tenant and
                    sw.tester_tenant != sw.owner_tenant)
                if sw.verdict != "strong_candidate":
                    # precondition rule (§20): owner baseline was 200 by
                    # construction and the tester request completed —
                    # a denial/difference is a genuine negative
                    if 400 <= sw.status < 500 or sw.status == 200:
                        coverage.record(
                            "tenant_isolation" if cross_tenant else "bola",
                            "tested_negative",
                            f"{ep.normalized_url}::{sw.param}: "
                            f"{sw.tester}→{sw.status}")
                    continue
                metrics.authorization_confirmed += 1
                self._note_candidate()
                cls = ("tenant_isolation" if cross_tenant else "bola")
                coverage.record(cls, "candidate", sw.notes)
                coverage.record("idor", "candidate", sw.notes)
                # invariant corroboration (provenance in evidence, never
                # a duplicate finding — the swap verdict stays primary)
                from .logic.observations import (
                    observation_from_swap, evaluate_observation)
                inv_results = evaluate_observation(
                    observation_from_swap(sw))
                metrics.invariants_tested += len(inv_results)
                metrics.invariants_violated += sum(
                    1 for r in inv_results if r.violated)
                f = Finding(
                    id=stable_finding_id("swap", sw.endpoint_url, sw.param, sw.victim_value),
                    source="idor-swap",
                    name=(f"{'Cross-tenant read' if cross_tenant else 'BOLA'}: "
                          f"'{sw.tester}' reads '{sw.owner}''s "
                          f"'{sw.param}={sw.victim_value}' ({ep.path})"),
                    severity="high",
                    confidence=Confidence.PROBABLE.value,
                    validation_status=ValidationStatus.STRONG_CANDIDATE.value,
                    host=ep.host, matched_at=sw.endpoint_url,
                    endpoint_url=sw.endpoint_url, method="GET",
                    parameter=sw.param,
                    description=sw.notes,
                    tags=["bola", "idor", "authz",
                          "tenant-isolation" if cross_tenant else
                          "cross-user", ep.endpoint_type],
                    raw={"swap": sw.to_dict(),
                         "invariants": [r.to_dict()
                                        for r in inv_results]},
                    false_positive_notes=(
                        "Victim object harvested from the owner's own "
                        "session; replayed verbatim as a different "
                        "identity; response shape compared excluding "
                        "volatile keys."),
                    identity=sw.tester, tenant=sw.tester_tenant,
                    resource_key=(f"{ep.normalized_url}::{sw.param}"
                                  f"={sw.victim_value}"),
                )
                evidence.allocate(f)
                evidence.record(
                    f,
                    request_text=(f"GET {sw.endpoint_url}\n(as "
                                  f"{sw.tester}; owner: {sw.owner})"),
                    response_text=sw.notes)
                findings.append(f)
                log.info("authz-matrix: %s", sw.notes)

        for ep in targets:
            if self._halted():
                log.info("authz-swap: halted by stop control; "
                         "remaining targets stay untested")
                break
            self._paced()
            if not self.scope.active_test_allowed(ep.url):
                continue
            ep_params = {p.name for p in
                         list(ep.query_parameters or []) +
                         list(ep.body_parameters or [])}
            same = [h for h in pool
                    if h.normalized_url == ep.normalized_url
                    and getattr(h, "source", "response") == "response"]
            # — cross-endpoint candidates: pool IDs whose param exists here,
            # retargeted at this endpoint with an empty baseline (the swap
            # engine fetches the owner's baseline on the target first) —
            from .authorization.harvest import HarvestedId
            seen_x, cross = set(), []
            for h in pool:
                if getattr(h, "source", "response") != "response":
                    continue  # traffic/JS/HTML IDs enrich views only
                if h.normalized_url == ep.normalized_url:
                    continue
                if h.param not in ep_params:
                    continue
                key = (h.param, h.value, h.owner)
                if key in seen_x:
                    continue
                seen_x.add(key)
                cross.append(HarvestedId(
                    endpoint_url=ep.url, normalized_url=ep.normalized_url,
                    param=h.param, value=h.value, owner=h.owner,
                    owner_tenant=h.owner_tenant, shape="", body_hash=""))
            cross = cross[:cfg_a.max_ids_per_endpoint]
            # — swap same-endpoint victims, then cross-endpoint ones —
            for tester in identities:
                for batch in (same, cross):
                    if not batch:
                        continue
                    try:
                        swaps = swap_ids(
                            client, batch, tester,
                            timeout=self.cfg.scan.http_timeout,
                            matrix=matrix, owner_headers=owner_headers,
                            ownership_fields=ownership_fields_for(ep))
                        all_swaps.extend(swaps)
                        handle_swaps(swaps, ep)
                    except BudgetExceeded:
                        coverage.record("authz", "blocked",
                                        f"budget: {ep.normalized_url}")
                        break
            # — per-method sweep (BFLA coverage beyond GET) —
            # sweep-only observations (resource == "") — swap observations
            # are evaluated by the swap verdicts above, not re-judged here
            try:
                sweep_methods(client, ep, identities, cfg_a.methods,
                              timeout=self.cfg.scan.http_timeout,
                              matrix=matrix)
            except BudgetExceeded:
                coverage.record("authz", "blocked",
                                f"budget: {ep.normalized_url}")
                continue
            for cell_key, obs in matrix.cells().items():
                method, _, url = cell_key.partition("::")
                if url != ep.normalized_url or len(obs) < 2:
                    continue
                if cell_key in seen_cells:
                    continue
                seen_cells.add(cell_key)
                obs = [o for o in obs if not o.resource]
                if len(obs) < 2:
                    coverage.record("bfla", "inconclusive",
                                    f"{method} {url}: single-identity cell")
                    continue
                metrics.authorization_tests += 1
                verdict, notes, kind = evaluate_cell(
                    obs, ep.endpoint_type)
                if verdict != "strong_candidate":
                    if kind == "" and verdict == "inconclusive":
                        coverage.record("bfla", "tested_negative",
                                        f"{method} {url}: "
                                        f"{describe_cell(obs)}")
                    continue
                metrics.authorization_confirmed += 1
                self._note_candidate()
                coverage.record(kind or "authz", "candidate", notes)
                names = [o.identity for o in obs if o.status == 200]
                tenants = sorted({o.tenant for o in obs
                                  if o.status == 200 and o.tenant})
                f = Finding(
                    id=stable_finding_id("bfla", cell_key),
                    source="authz-matrix",
                    name=(f"BFLA/{kind.upper()}: {method} {ep.path} "
                          f"treats identities identically"),
                    severity="high",
                    confidence=Confidence.PROBABLE.value,
                    validation_status=ValidationStatus.STRONG_CANDIDATE.value,
                    host=ep.host, matched_at=ep.url,
                    endpoint_url=ep.url, method=method,
                    description=f"{notes} [{describe_cell(obs)}]",
                    tags=["bfla", kind, "authz", ep.endpoint_type],
                    raw={"observations": [o.to_dict() for o in obs]},
                    false_positive_notes=(
                        "Same method compared across identities with "
                        "semantic shape matching; verify the 200s are "
                        "not error pages sharing a template before "
                        "reporting."),
                    identity="+".join(names[:2]),
                    tenant="+".join(tenants),
                )
                evidence.allocate(f)
                evidence.record(
                    f,
                    request_text=(f"{method} {ep.url}\n--- matrix ---\n" +
                                  describe_cell(obs)),
                    response_text=notes)
                findings.append(f)
                log.info("authz-matrix: %s", notes)
        # ── Phase 7 views: extended matrix + role/tenant/resource/
        # action analytics over everything the sweeps observed ──────
        from .authz.matrix import build_extended
        from .authz.roles import (role_access_map,
                                  check_vertical_escalation)
        from .authz.tenants import tenant_view
        from .authz.resources import resource_access_map
        from .authz.actions import action_coverage
        extended = build_extended(matrix.observations, all_swaps)
        views = {
            "roles": role_access_map(extended.cells.values()),
            "vertical_escalations": check_vertical_escalation(
                matrix.observations),
            "tenants": tenant_view(pool, all_swaps),
            "resources": resource_access_map(
                pool, all_swaps, matrix.observations),
            "actions": action_coverage(
                extended.cells.values(), endpoints,
                cfg_a.methods),
        }
        for esc in views["vertical_escalations"]:
            coverage.record("authz", "candidate",
                            f"role gap: {esc['other_identity']} "
                            f"({esc['other_role']}) matches "
                            f"{esc['privileged_identity']} "
                            f"({esc['privileged_role']}) on "
                            f"{esc['method']} {esc['endpoint']}")
        artifact = matrix.to_dict()
        artifact["extended"] = extended.to_dict()
        artifact["views"] = views
        import json as _json
        (out_dir / "authorization_matrix.json").write_text(
            _json.dumps(artifact, indent=2))
        if app_graph is not None:
            from .authz.graph import sync_extended
            sync_extended(app_graph, pool)
        # ── behavioral state (agent Phase 3): observations → graph
        # edges, snapshots, and cross-run transitions ───────────────
        self._last_matrix = matrix
        if app_graph is not None:
            self._record_behavioral_state(app_graph, matrix, out_dir)
        return findings

    # ── BEHAVIORAL STATE (agent Phase 3) ─────────────────────────────
    @staticmethod
    def _record_behavioral_state(app_graph, matrix, out_dir: Path):
        """Sync matrix observations into the graph; snapshot every cell;
        link cross-run changes as transitions. Additive and idempotent."""
        from .state.graph import (sync_matrix_observations,
                                  record_transition)
        from .state.snapshots import StateSnapshot, SnapshotStore
        from .state.transitions import TransitionLog
        sync_matrix_observations(app_graph, matrix.observations)
        state_dir = out_dir / "state"
        store = SnapshotStore.load(state_dir / "snapshots.jsonl")
        tlog = TransitionLog.load(state_dir / "transitions.jsonl")
        for o in matrix.observations:
            snap = StateSnapshot.capture(
                identity=o.identity, endpoint=o.endpoint,
                method=o.method, status=o.status, shape=o.shape)
            prev = store.latest(o.identity, o.endpoint, o.method)
            store.add(snap)
            if prev is not None:
                t = tlog.record_if_changed(
                    prev, snap, via=snap.snapshot_id, actor=o.identity)
                if t is not None:
                    record_transition(app_graph, prev.snapshot_id,
                                      snap.snapshot_id, snap.snapshot_id,
                                      actor=o.identity)
        store.save(state_dir / "snapshots.jsonl")
        tlog.save(state_dir / "transitions.jsonl")

    # ── WORKFLOW DISCOVERY (agent Phase 4, offline) ────────────────
    def _discover_workflows(self, out_dir: Path, endpoints, application,
                            app_graph, metrics: Metrics, ck: Checkpoint):
        """Infer flows from collected data only — no requests sent.

        Sources: REST stem grouping, timestamp-ordered browser traffic,
        CRUD linkage, harvested value overlap. Persists workflows.json
        (+ mutation catalog), appends stored workflows to the
        application model, and links step chains in the graph.
        """
        from .workflows.discovery import discover_all
        from .workflows.mutations import mutation_catalog
        from .state.resources import ResourceTracker, \
            link_crud_from_endpoints
        from .state.graph import ensure_workflow
        import json as _json
        traffic: dict = {}
        traffic_file = out_dir / "browser_traffic.json"
        if traffic_file.exists():
            try:
                traffic = _json.loads(traffic_file.read_text())
            except Exception as e:
                log.debug("workflow discovery: bad traffic file: %s", e)
        # CRUD linkage from app resources × endpoint methods
        tracker = ResourceTracker()
        resources = []
        if application is not None:
            resources = getattr(application, "resources", []) or []
        link_crud_from_endpoints(tracker, resources, endpoints)
        flows = discover_all(
            endpoints=endpoints, traffic=traffic,
            resources=list(tracker.resources.values()),
            harvest_pool=list(getattr(self, "_harvest_pool", []) or []))
        payload = {"flows": [f.to_dict() for f in flows],
                   "mutations": mutation_catalog(flows)}
        (out_dir / "workflows.json").write_text(
            _json.dumps(payload, indent=2))
        if application is not None:
            try:
                stored = [f.to_stored() for f in flows]
                existing = {w.name for w in
                            getattr(application, "workflows", []) or []}
                application.workflows.extend(
                    w for w in stored if w.name not in existing)
                (out_dir / "application.json").write_text(
                    _json.dumps(application.to_dict(), indent=2))
                ck.save_blob("application", application.to_dict())
            except Exception as e:
                log.debug("workflow discovery: app persist failed: %s",
                          e)
        metrics.workflows_discovered = len(flows)
        if app_graph is not None:
            try:
                for f in flows:
                    ensure_workflow(app_graph, f.name,
                                    [s.name for s in f.steps])
            except Exception as e:
                log.debug("workflow discovery: graph link failed: %s",
                          e)
        log.info("workflows: %d discovered (%d observed)",
                 len(flows), sum(1 for f in flows if f.observed))

    # ── RESOURCE INTEL (agent Phase 5, offline) ──────────────────────
    def _build_resource_intel(self, out_dir: Path, endpoints, application,
                              app_graph, metrics: Metrics, ck: Checkpoint):
        """Lifecycle-aware resource records from all collected sources.

        Producers (all offline): harvest pool, stashed page IDs, JS
        cache, browser traffic, OpenAPI-declared params (already
        endpoints). Records never drive swap verdicts unless their
        source is an authenticated response (see source filter).
        """
        from .application.resources import (
            discover_ids_from_js, discover_ids_from_traffic)
        from .authorization.harvest import HarvestedId
        from .authz.resources import enrich_resource_records
        from .state.resources import (ResourceTracker,
                                      link_crud_from_endpoints)
        import json as _json
        pool = list(getattr(self, "_harvest_pool", []) or [])
        extra: list = []

        def _add(url: str, param: str, value: str, source: str):
            if not url or not param or not value:
                return
            try:
                norm = normalize_url(url)
            except Exception:
                norm = url
            if any(e.normalized_url == norm and e.param == param
                   and e.value == value for e in pool + extra):
                return
            extra.append(HarvestedId(
                endpoint_url=url, normalized_url=norm, param=param,
                value=value, owner="", owner_tenant="", shape="",
                body_hash=""))
            extra[-1].source = source

        # stashed page IDs (HTML/headers parsed during mapping)
        for url, param, value, source in \
                getattr(self, "_page_ids", []) or []:
            _add(url, param, value, source)
        # JS bundle cache (meta files carry the source URL)
        cache_dir = out_dir / "cache"
        if cache_dir.exists():
            for meta_file in sorted(cache_dir.glob("*.meta"))[:50]:
                try:
                    data_file = meta_file.with_name(
                        meta_file.name[:-len(".meta")])
                    if not data_file.exists():
                        continue
                    meta = _json.loads(meta_file.read_text())
                    url = str(meta.get("url", ""))
                    text = data_file.read_text(
                        errors="ignore")[:200_000]
                except Exception as e:
                    log.debug("resource intel: cache read failed: %s",
                              e)
                    continue
                if not url:
                    continue
                try:
                    found = discover_ids_from_js(text)
                except Exception:
                    continue
                for pname, pvalue in found.items():
                    _add(url, pname, pvalue, "javascript")
        # browser traffic URLs
        traffic_file = out_dir / "browser_traffic.json"
        if traffic_file.exists():
            try:
                traffic = _json.loads(traffic_file.read_text())
                reqs = traffic.get("requests", [])
            except Exception:
                reqs = []
            try:
                for url, pname, pvalue in discover_ids_from_traffic(
                        reqs):
                    _add(url, pname, pvalue, "traffic")
            except Exception as e:
                log.debug("resource intel: traffic parse failed: %s", e)
        # matrix observations (permissions) + CRUD linkage + enrich
        matrix = getattr(self, "_last_matrix", None)
        observations = list(getattr(matrix, "observations", []) or [])
        tracker = ResourceTracker()
        app_resources = []
        if application is not None:
            app_resources = getattr(application, "resources", []) or []
        link_crud_from_endpoints(tracker, app_resources, endpoints)
        combined = pool + extra
        records = enrich_resource_records(
            combined, observations, tracker, endpoints)
        (out_dir / "resources.json").write_text(
            _json.dumps({"records": records}, indent=2))
        if app_graph is not None and extra:
            try:
                from .authz.graph import sync_extended
                sync_extended(app_graph, extra)
                app_graph.save(out_dir / "application_graph.json")
                ck.save_blob("application_graph", app_graph.to_dict())
                metrics.graph_nodes = len(app_graph.nodes)
                metrics.graph_edges = len(app_graph.edges)
            except Exception as e:
                log.debug("resource intel: graph sync failed: %s", e)
        log.info("resources: %d enriched records (%d harvest, %d "
                 "supplementary)", len(records), len(pool), len(extra))

    # ── INVARIANT DISCOVERY (agent Phase 6, offline) ───────────────
    def _discover_invariants(self, out_dir: Path, endpoints,
                             evidence: EvidenceStore, metrics: Metrics,
                             coverage: CoverageTracker,
                             findings: List[Finding]) -> List[Finding]:
        """Mine holding rules from matrix observations, then run every
        invariant (built-in + discovered) as a second opinion.

        - holding + fires + existing finding in mapped classes →
          corroboration attached, no duplicate;
        - holding + fires + no such finding → new invariant finding;
        - holdings that hold → persisted as enforcement evidence.
        Zero network; findings only on observed violations.
        """
        from .logic.invariant_discovery import discover_invariants
        from .logic.invariant_engine import InvariantEngine
        from .logic.observations import observation_from_matrix_cell
        matrix = getattr(self, "_last_matrix", None)
        observations = list(getattr(matrix, "observations", []) or [])
        if not observations:
            log.debug("invariant discovery: no matrix observations")
            return []
        pool = list(getattr(self, "_harvest_pool", []) or [])
        discovered = discover_invariants(observations, pool)
        engine = InvariantEngine()
        for rule in discovered:
            engine.add(rule.invariant)
        obs_dicts = [observation_from_matrix_cell(o, pool)
                     for o in observations]
        new_findings: List[Finding] = []
        for obs in obs_dicts:
            for res in engine.evaluate(obs):
                metrics.invariants_tested += 1
                if not res.violated:
                    continue
                metrics.invariants_violated += 1
                covered = _INVARIANT_CLASSES.get(
                    self._check_of(engine, res.invariant_id), set())
                dup = next((f for f in findings
                            if covered & set(f.tags or [])), None)
                if dup is not None:
                    inv_list = dup.raw.setdefault("invariants", [])
                    if not any(e.get("invariant_id") == res.invariant_id
                               for e in inv_list):
                        inv_list.append({
                            "invariant_id": res.invariant_id,
                            "detail": res.detail,
                            "corroborated_by": "invariant-engine"})
                    continue
                f = Finding(
                    id=stable_finding_id(
                        "inv", res.invariant_id,
                        str(obs.get("endpoint", "")),
                        str(obs.get("actor", ""))),
                    source="invariant",
                    name=(f"Invariant violated: {res.invariant_id} "
                          f"on {obs.get('endpoint', '')}"),
                    severity="high",
                    confidence=Confidence.PROBABLE.value,
                    validation_status=ValidationStatus.STRONG_CANDIDATE.value,
                    host="", matched_at=obs.get("endpoint", ""),
                    endpoint_url=obs.get("endpoint", ""),
                    method="GET",
                    description=res.detail,
                    tags=["invariant", self._check_of(
                        engine, res.invariant_id)],
                    raw={"invariant_id": res.invariant_id,
                         "observation": obs},
                    false_positive_notes=(
                        "Second-opinion evaluation over recorded matrix "
                        "observations — same evidence the verdict passes "
                        "saw, judged by an independent rule. Confirm "
                        "interactively before reporting."),
                    identity=str(obs.get("actor", "")),
                )
                evidence.allocate(f)
                evidence.record(
                    f,
                    request_text=(f"invariant {res.invariant_id} "
                                  f"over recorded observations"),
                    response_text=res.detail)
                new_findings.append(f)
                for cls in sorted(covered) or ["authz"]:
                    coverage.record(cls, "candidate",
                                    f"invariant {res.invariant_id}: "
                                    f"{res.detail}")
                log.info("invariant: NEW violation %s — %s",
                         res.invariant_id, res.detail)
        import json as _json
        (out_dir / "invariants.json").write_text(_json.dumps(
            {"discovered": [r.to_dict() for r in discovered],
             "summary": engine.summary()}, indent=2))
        return new_findings

    @staticmethod
    def _check_of(engine, invariant_id: str) -> str:
        for inv in engine.invariants:
            if inv.id == invariant_id:
                return inv.check
        return ""

    # ── STORED-XSS CORRELATION (bounty item #3) ────────────────────────
    def _second_order_probe(self, endpoints: List[Endpoint],
                            evidence: EvidenceStore, metrics: Metrics,
                            budgets: BudgetTracker,
                            coverage: CoverageTracker, client,
                            identities) -> List[Finding]:
        from .validation.second_order import (inject_canary, find_renders)
        cfg_v = self.cfg.validation
        forms = [e for e in endpoints
                 if e.body_parameters
                 and self.scope.active_test_allowed(e.url)]
        forms = forms[:cfg_v.second_order_max_endpoints]
        renders = []
        for e in endpoints:
            if e.endpoint_type == "page" and \
                    self.scope.is_in_scope(e.url) and \
                    e.url not in renders:
                renders.append(e.url)
        renders = renders[:cfg_v.second_order_max_renders]
        if not forms or not renders:
            coverage.record("second_order", "untestable",
                            "no HTML forms or render candidates")
            return []
        injectors = [i for i in identities if i.name != "anonymous"] or \
            identities[:1]
        log.info("second-order: %d forms × %d renders as %s",
                 len(forms), len(renders),
                 [i.name for i in injectors[:1]])
        if not self._reserve_or_block(
                budgets, coverage, "second_order",
                plan_second_order(len(forms), len(renders))):
            return []
        findings: List[Finding] = []
        for ep in forms:
            if self._halted():
                log.info("second-order: halted by stop control; "
                         "remaining targets stay untested")
                break
            self._paced()
            inj = injectors[0]
            iname = getattr(inj, "name", "anonymous")
            iheaders = dict(getattr(inj, "auth_headers", None) or {})
            if not budgets.consume_test("second_order",
                                        ep.normalized_url):
                coverage.record("second_order", "blocked",
                                f"budget: {ep.normalized_url}")
                continue
            try:
                inj_res = inject_canary(client, ep, iheaders, iname,
                                        timeout=self.cfg.scan.http_timeout)
            except BudgetExceeded:
                coverage.record("second_order", "blocked",
                                f"budget: {ep.normalized_url}")
                continue
            metrics.second_order_tests += 1
            if not inj_res.fields:
                continue
            try:
                hits = find_renders(client, renders + [ep.url],
                                    inj_res.canary, ep.url,
                                    timeout=self.cfg.scan.http_timeout)
            except BudgetExceeded:
                coverage.record("second_order", "blocked",
                                f"budget: {ep.normalized_url}")
                continue
            dangerous = [h for h in hits
                         if h.context.startswith("dangerous:")]
            if dangerous:
                h = dangerous[0]
                metrics.second_order_candidates += 1
                self._note_candidate()
                coverage.record("second_order", "candidate",
                                f"{h.context} at {h.render_url}")
                f = Finding(
                    id=stable_finding_id("so", ep.normalized_url, h.render_url),
                    source="second-order",
                    name=(f"Stored XSS candidate: canary from "
                          f"{ep.path} renders {h.context} at "
                          f"{h.render_url}"),
                    severity="high",
                    confidence=Confidence.PROBABLE.value,
                    validation_status=ValidationStatus.STRONG_CANDIDATE.value,
                    host=ep.host, matched_at=h.render_url,
                    endpoint_url=h.render_url, method="GET",
                    description=(
                        f"Canary {inj_res.canary} injected via POST "
                        f"{ep.url} (fields: "
                        f"{', '.join(inj_res.fields)}) renders "
                        f"{h.detail} at {h.render_url}."),
                    tags=["stored-xss", "second-order", "xss"],
                    raw={"inject": inj_res.to_dict(),
                         "render": h.to_dict()},
                    false_positive_notes=(
                        "Inert unknown tag proves unescaped persistence; "
                        "confirm script execution with a benign payload "
                        "in a private session before reporting."),
                    identity=iname,
                )
                evidence.allocate(f)
                evidence.record(
                    f,
                    request_text=(f"POST {ep.url} "
                                  f"(fields: {inj_res.fields})\n"
                                  f"canary: {inj_res.canary}"),
                    response_text=(f"{h.detail}\n--- snippet ---\n"
                                   f"{h.snippet[:1500]}"))
                findings.append(f)
                log.info("second-order: STORED XSS at %s (%s)",
                         h.render_url, h.context)
            elif hits:
                coverage.record("second_order", "tested_negative",
                                f"{ep.normalized_url}: canary encoded")
            else:
                coverage.record("second_order", "inconclusive",
                                f"{ep.normalized_url}: no render observed")
        return findings

    def _second_order_ssrf_probe(self, endpoints: List[Endpoint],
                                 evidence: EvidenceStore, metrics: Metrics,
                                 budgets: BudgetTracker,
                                 coverage: CoverageTracker, client,
                                 identities, provider) -> List[Finding]:
        """Inject unique OAST URLs into URL-like fields and correlate later
        callbacks after in-scope render/worker trigger requests.

        This is separately opt-in because injections persist a callback URL.
        A missing callback is inconclusive: asynchronous processing and
        worker schedules make silence insufficient to prove a negative.
        """
        from urllib.parse import urlsplit
        from .validation.second_order import (
            make_ssrf_canary, second_order_ssrf_candidates)
        cfg_v = self.cfg.validation
        if provider is None or not provider.available():
            coverage.record("second_order_ssrf", "untestable",
                            "OAST provider unavailable")
            return []

        sinks = []
        endpoint_count = 0
        max_endpoints = max(0, cfg_v.second_order_max_endpoints)
        max_fields = max(0, cfg_v.second_order_ssrf_max_fields)
        for ep in endpoints:
            if (endpoint_count >= max_endpoints or
                    ep.method.upper() not in ("POST", "PUT", "PATCH") or
                    not self.scope.active_test_allowed(ep.url)):
                continue
            fields = second_order_ssrf_candidates(ep, max_fields)
            if not fields:
                continue
            endpoint_count += 1
            sinks.extend((ep, *candidate) for candidate in fields)
        if not sinks:
            coverage.record("second_order_ssrf", "untestable",
                            "no in-scope URL-like body fields found")
            return []

        trigger_scores = {}
        for sink_ep, *_ in sinks:
            for trigger_ep, score, rationale in _rank_ssrf_triggers(
                    sink_ep, endpoints):
                if self.scope.is_in_scope(trigger_ep.url):
                    prev = trigger_scores.get(trigger_ep.url)
                    if prev is None or score > prev[0]:
                        trigger_scores[trigger_ep.url] = (score, rationale)
        trigger_cap = max(0, cfg_v.second_order_max_renders)
        triggers = [url for url, _ in sorted(
            trigger_scores.items(), key=lambda row: (-row[1][0], row[0]))
            [:trigger_cap]]
        plan = plan_second_order_ssrf(len(sinks), len(triggers))
        if not self._reserve_or_block(
                budgets, coverage, "second_order_ssrf", plan):
            return []

        actors = [i for i in identities
                  if getattr(i, "name", "anonymous") != "anonymous"] \
            or list(identities or [])[:1]
        actor = actors[0] if actors else None
        identity = getattr(actor, "name", "anonymous")
        headers = dict(getattr(actor, "auth_headers", None) or {})
        submitted = []
        budget_blocked = False
        incomplete = False
        for ep, location, parameter, candidate_score, rationale in sinks:
            if self._halted():
                incomplete = True
                break
            if not budgets.consume_test(
                    "second_order_ssrf", ep.normalized_url,
                    limit=max_fields):
                coverage.record("second_order_ssrf", "blocked",
                                f"test budget: {ep.normalized_url}")
                budget_blocked = True
                continue
            callback_url = make_ssrf_canary(provider.create_token())
            callback_host = urlsplit(callback_url).hostname or ""
            key_builder = getattr(provider, "correlation_key", None)
            callback_key = (key_builder(callback_url)
                            if callable(key_builder) else callback_host)
            headers_for_request = dict(headers)
            data = {p.name: (p.sample_value or "test")
                    for p in ep.body_parameters if p.name}
            json_body = _nested_parameter_object(data)
            request_url = ep.url
            if location == "body":
                data[parameter.name] = callback_url
                _assign_nested(json_body, parameter.name, callback_url)
            elif location == "query":
                request_url = _append_query_parameter(
                    request_url, parameter.name, callback_url)
            elif location == "header":
                headers_for_request[parameter.name] = callback_url
            try:
                self._paced()
                method = ep.method.upper()
                request_kwargs = {"headers": headers_for_request,
                                  "timeout": self.cfg.scan.http_timeout}
                is_json = location == "body" and any(
                    "json" in ct.lower() for ct in ep.request_content_types)
                if location == "body":
                    request_kwargs["json" if is_json else "data"] = (
                        json_body if is_json else data)
                request_fn = getattr(client, "request", None)
                if callable(request_fn):
                    response = request_fn(method, request_url,
                                          **request_kwargs)
                elif method == "POST" and location == "body" and not is_json:
                    response = client.post(request_url, **request_kwargs)
                else:
                    raise RuntimeError("HTTP client lacks generic request support")
            except BudgetExceeded:
                coverage.record("second_order_ssrf", "blocked",
                                f"budget: {ep.normalized_url}"
                                f"::{parameter.name}")
                budget_blocked = True
                continue
            except Exception as exc:
                log.debug("second-order SSRF injection failed at %s: %s",
                          ep.url, exc)
                incomplete = True
                continue
            if response.status_code >= 400:
                incomplete = True
            metrics.second_order_ssrf_tests += 1
            trigger_urls = _materialize_trigger_urls(
                triggers, response, ep.url)
            submitted.append({
                "endpoint": ep, "parameter": parameter.name,
                "location": location,
                "candidate_score": candidate_score,
                "candidate_rationale": rationale,
                "method": method,
                "callback_url": callback_url,
                "callback_host": callback_host,
                "callback_key": callback_key,
                "status": response.status_code,
                "trigger_urls": trigger_urls,
            })

        submitted_triggers = list(dict.fromkeys(
            url for item in submitted for url in item["trigger_urls"]))
        for trigger_url in submitted_triggers:
            if self._halted():
                incomplete = True
                break
            if not self.scope.is_in_scope(trigger_url):
                continue
            try:
                self._paced()
                response = client.get(
                    trigger_url, headers=headers,
                    timeout=self.cfg.scan.http_timeout)
                if response.status_code >= 400:
                    incomplete = True
            except BudgetExceeded:
                budget_blocked = True
                incomplete = True
                coverage.record("second_order_ssrf", "blocked",
                                f"trigger request budget: {trigger_url}")
                break
            except Exception as exc:
                log.debug("second-order SSRF trigger failed at %s: %s",
                          trigger_url, exc)
                incomplete = True

        interactions = []
        if submitted:
            try:
                interactions = provider.poll(
                    timeout=self.cfg.oast.poll_timeout,
                    interval=self.cfg.oast.poll_interval)
            except Exception as exc:
                log.debug("second-order SSRF OAST polling failed: %s", exc)
                incomplete = True

        findings: List[Finding] = []
        for item in submitted:
            ep = item["endpoint"]
            matched = matching_interactions(
                interactions, item["callback_key"])
            if matched:
                metrics.second_order_ssrf_confirmed += 1
                self._note_candidate()
                coverage.record(
                    "second_order_ssrf", "confirmed",
                    f"OAST callback for {ep.normalized_url}"
                    f"::{item['parameter']}")
                f = Finding(
                    id=stable_finding_id(
                        "second_order_ssrf", ep.normalized_url,
                        item["parameter"]),
                    source="second-order-ssrf",
                    name=(f"Stored server-side fetch confirmed: {ep.path}"
                          f"::{item['parameter']} triggered an OAST callback"),
                    severity="medium",
                    confidence=Confidence.CONFIRMED.value,
                    validation_status=ValidationStatus.CONFIRMED.value,
                    host=ep.host, matched_at=ep.url,
                    endpoint_url=ep.url, method=item["method"],
                    parameter=item["parameter"],
                    description=(
                        f"A unique callback URL stored through {item['method']} "
                        f"{ep.url} in {item['location']} input "
                        f"'{item['parameter']}' received an out-of-band "
                        f"interaction after {len(item['trigger_urls'])} "
                        "related in-scope trigger routes. "
                        "This proves a server-side fetch, but does not by "
                        "itself prove access to internal resources."),
                    tags=["ssrf", "second-order", "oast",
                          ep.endpoint_type],
                    raw={"callback_host": item["callback_host"],
                         "callback_url": item["callback_url"],
                         "trigger_urls": item["trigger_urls"],
                         "candidate_score": item["candidate_score"],
                         "candidate_rationale": item["candidate_rationale"],
                         "interactions": matched[:10]},
                    false_positive_notes=(
                        "A unique DNS/HTTP callback confirms a server-side "
                        "fetch of the injected URL. No internal resources "
                        "were requested or accessed."),
                    identity=identity,
                )
                evidence.allocate(f)
                evidence.record(
                    f,
                    request_text=(
                        f"{item['method']} {ep.url}\n{item['location']}"
                        f"::{item['parameter']}="
                        f"{item['callback_url']}\n"
                        + "\n".join(f"GET {url}" for url in
                                   item["trigger_urls"])),
                    response_text="\n".join(
                        _interaction_line(it) for it in matched[:10]))
                findings.append(f)
            else:
                coverage.record(
                    "second_order_ssrf",
                    "blocked" if budget_blocked else "inconclusive",
                    f"no callback observed for {ep.normalized_url}"
                    f"::{item['parameter']} after polling")
        if incomplete and not submitted:
            coverage.record("second_order_ssrf", "inconclusive",
                            "injection or trigger flow was incomplete")
        return findings

    # ── BUSINESS-LOGIC MUTATIONS (stateful slice) ──────────────────────
    def _business_logic_probe(self, endpoints: List[Endpoint],
                              evidence: EvidenceStore, metrics: Metrics,
                              budgets: BudgetTracker,
                              coverage: CoverageTracker, client,
                              identities) -> List[Finding]:
        from .logic.business_logic import (BusinessLogicTester,
                                           candidate_params)
        cfg_b = self.cfg.business
        scored = [(e, candidate_params(e, cfg_b.max_params))
                  for e in endpoints
                  if e.endpoint_type != "static"
                  and self.scope.active_test_allowed(e.url)]
        scored = [(e, c) for e, c in scored if c][:cfg_b.max_endpoints]
        if not scored:
            coverage.record("business_logic", "untestable",
                            "no transactional parameters")
            return []
        actors = [i for i in identities if i.name != "anonymous"] or \
            identities[:1]
        actor = actors[0]
        aname = getattr(actor, "name", "anonymous")
        atenant = getattr(actor, "tenant", "") or ""
        tester = BusinessLogicTester(self.cfg, client)
        log.info("business-logic: %d endpoints as %s",
                 len(scored), aname)
        if not self._reserve_or_block(
                budgets, coverage, "business_logic",
                plan_business(len(scored), cfg_b.max_params)):
            return []
        findings: List[Finding] = []
        for ep, cands in scored:
            if not budgets.consume_test("business_logic",
                                        ep.normalized_url):
                coverage.record("business_logic", "blocked",
                                f"budget: {ep.normalized_url}")
                continue
            for cand in cands:
                if self._halted():
                    log.info("business-logic: halted by stop control; "
                             "remaining targets stay untested")
                    break
                self._paced()
                try:
                    results = tester.probe(
                        ep, cand, actor,
                        timeout=self.cfg.scan.http_timeout)
                except BudgetExceeded:
                    coverage.record("business_logic", "blocked",
                                    f"budget: {ep.normalized_url}")
                    break
                for res in results:
                    metrics.business_logic_tests += 1
                    if res.verdict == "strong_candidate":
                        metrics.business_logic_candidates += 1
                        self._note_candidate()
                        metrics.invariants_violated += len(res.violations)
                        coverage.record("business_logic", "candidate",
                                        res.notes)
                        inv = res.violations[0]["invariant_id"] \
                            if res.violations else "invariant"
                        # readback verification: echo is not proof —
                        # re-observe clean state before confirming
                        ver = self._verify_business_effect(
                            client, ep, cand, res, actor)
                        status, conf = (
                            ValidationStatus.STRONG_CANDIDATE.value,
                            Confidence.PROBABLE.value)
                        extra_tags: list = []
                        suffix = ""
                        if ver["status"] == "verified":
                            status = ValidationStatus.CONFIRMED.value
                            conf = Confidence.CONFIRMED.value
                            metrics.effects_verified += 1
                            extra_tags.append("verified-effect")
                            suffix = " [verified effect]"
                            log.info("business-logic verified: %s",
                                     ver["detail"])
                        elif ver["status"] == "refuted":
                            # positive proof of NO persistence: the
                            # echo-only candidate cannot stand
                            status = ValidationStatus.INCONCLUSIVE.value
                            conf = Confidence.UNKNOWN.value
                            suffix = " [effect not persisted]"
                        f = Finding(
                            id=stable_finding_id("bl", ep.normalized_url, cand.param, str(res.mutated)),
                            source="business-logic",
                            name=(f"Business logic: {cand.param}="
                                  f"{res.mutated} accepted, violates "
                                  f"{inv} ({ep.path})" + suffix),
                            severity="high",
                            confidence=conf,
                            validation_status=status,
                            host=ep.host, matched_at=ep.url,
                            endpoint_url=ep.url, method=ep.method,
                            parameter=cand.param,
                            description=res.notes + (
                                f" Verification: {ver['detail']}"
                                if ver["detail"] else ""),
                            tags=["business-logic", cand.kind,
                                  ep.endpoint_type] + extra_tags,
                            raw={"business": res.to_dict(),
                                 "verification": ver},
                            false_positive_notes=(
                                "Acceptance is echo-based (mutated value "
                                "reflected with HTTP 200) — a proxy for "
                                "server-side effect, not proof of it. "
                                + ("Persistence CONFIRMED by clean "
                                   "re-read; see verification evidence."
                                   if ver["status"] == "verified"
                                   else "Confirm the persisted state "
                                   "before reporting.")),
                            identity=aname, tenant=atenant,
                            resource_key=(f"{ep.normalized_url}::"
                                          f"{cand.param}"),
                        )
                        evidence.allocate(f)
                        evidence.record(
                            f,
                            request_text=(
                                f"{ep.method} {ep.url} "
                                f"({cand.param}={res.mutated})"),
                            response_text=res.notes + (
                                f"\n--- verification ---\n{ver['detail']}"
                                if ver["detail"] else ""))
                        findings.append(f)
                        log.info("business-logic: %s", res.notes)
                    elif res.baseline_status != 200:
                        coverage.record("business_logic", "inconclusive",
                                        f"{ep.normalized_url}: "
                                        f"{res.notes}")
                    else:
                        coverage.record("business_logic", "tested_negative",
                                        f"{ep.normalized_url}::"
                                        f"{cand.param}: {res.notes}")
        metrics.invariants_tested += tester.evaluations
        return findings

    # ── RACE ENGINE (stateful slice, opt-in) ───────────────────────────
    def _verify_business_effect(self, client, ep, cand, res,
                                actor) -> dict:
        """Readback verification for one accepted mutation.

        Returns {"status": verified|refuted|inconclusive, "detail",
        "evidence"}. Order: user assertions (explicit read URL wins) →
        token-reuse sequential check → generic persistence readback.
        POST endpoints without an after_read have no safe re-read
        (re-POSTing is another write) → inconclusive, finding stands.
        """
        from urllib.parse import urljoin
        from .verify.base import (verify_persisted, verify_token_reuse)
        from .verify.assertions import (matching_assertions,
                                        evaluate_assertions)
        timeout = self.cfg.scan.http_timeout
        headers = dict(getattr(actor, "auth_headers", None) or {})
        blank = {"status": "inconclusive", "detail": "", "evidence": {}}

        def _wrap(v):
            return {"status": v.status, "detail": v.detail,
                    "evidence": v.evidence}

        # 1) user-supplied assertions (explicit readback contract)
        matched = matching_assertions(
            getattr(self.cfg.business, "assertions", []) or [],
            ep.path, cand.param, ep.method)
        for a in matched:
            after = (a.get("after_read") or "").strip()
            if not after:
                continue
            read_url = after if after.startswith("http") else \
                urljoin(ep.url, after)
            try:
                r = client.get(read_url, headers=headers,
                               timeout=timeout)
            except Exception as e:
                return {"status": "inconclusive",
                        "detail": f"assertion readback failed: {e}"[:200],
                        "evidence": {}}
            if r.status_code != 200:
                return {"status": "inconclusive",
                        "detail": f"assertion readback → "
                                  f"HTTP {r.status_code}",
                        "evidence": {}}
            verdict, detail, ev = evaluate_assertions(
                [a], r.text or "")
            if verdict == "passed":
                # invariant holds on re-read: violation did NOT persist
                return {"status": "refuted",
                        "detail": f"assertion holds on re-read: {detail}",
                        "evidence": {**ev, "read_url": read_url}}
            if verdict == "failed":
                return {"status": "verified",
                        "detail": f"assertion violated on re-read: "
                                  f"{detail}",
                        "evidence": {**ev, "read_url": read_url}}
            return {"status": "inconclusive", "detail": detail,
                    "evidence": ev}
        # 2) token-reuse: sequential double-submit is self-contained
        if cand.kind == "token_reuse":
            params = {p.name: (p.sample_value or "1") for p in
                      list(ep.query_parameters or []) +
                      list(ep.body_parameters or []) if p.name}
            has_body = bool(ep.body_parameters)
            v = verify_token_reuse(
                client, "POST" if has_body else "GET", ep.url,
                params if has_body else {},
                headers, timeout,
                query=None if has_body else params)
            return _wrap(v)
        # 3) generic persistence: safe re-read exists only for GET
        # endpoints (re-POSTing baseline would be another write).
        # The mutated param is stripped: a clean re-read observes
        # persisted state instead of re-applying the mutation.
        has_body = bool(ep.body_parameters)
        if has_body:
            return blank
        from urllib.parse import (urlsplit, urlunsplit, parse_qsl,
                                  urlencode)
        parts = urlsplit(ep.url)
        q = [(k, v) for k, v in
             parse_qsl(parts.query, keep_blank_values=True)
             if k != cand.param]
        read_url = urlunsplit(
            (parts.scheme, parts.netloc, parts.path,
             urlencode(q, doseq=True), ""))
        v = verify_persisted(client, read_url, headers, cand.param,
                             res.mutated, timeout)
        return _wrap(v)

    def _verify_race_idempotent(self, client, ep, body,
                                headers) -> dict:
        """Sequential idempotency re-check for a divergent burst.

        Only runs when the request carries an idempotency key
        (Idempotency-Key header or *idempotency* body field) — without
        one, there is nothing well-defined to re-check, so verification
        stays inconclusive and the candidate stands as-is.
        """
        from .verify.base import verify_idempotency
        timeout = self.cfg.scan.http_timeout
        key_name = ""
        for hk in headers:
            if hk.lower() == "idempotency-key":
                key_name = hk
                break
        if not key_name:
            for bk in body:
                if "idempotency" in bk.lower():
                    key_name = bk
                    break
        if not key_name:
            return {"status": "inconclusive",
                    "detail": "no idempotency key present — nothing "
                              "well-defined to re-check",
                    "evidence": {}}
        v = verify_idempotency(client, "POST", ep.url, body, headers,
                               key_name, timeout)
        return {"status": v.status, "detail": v.detail,
                "evidence": v.evidence}

    def _verify_race_single_use(self, client, ep, body, headers,
                                key_name: str) -> dict:
        """Sequentially re-submit a token-like value after a race signal."""
        from .verify.base import verify_token_reuse
        v = verify_token_reuse(client, "POST", ep.url, body, headers,
                               key_name, self.cfg.scan.http_timeout)
        return {"status": v.status, "detail": v.detail,
                "evidence": v.evidence}

    def _read_race_inventory(self, client, ep, headers) -> dict:
        """Read a configured inventory field before/after a reservation race."""
        from urllib.parse import urljoin
        from .logic.race import inventory_value
        raw_url = (self.cfg.race.inventory_read_url or "").strip()
        if not raw_url:
            return {"status": "inconclusive",
                    "detail": "race.inventory_read_url is required"}
        read_url = (raw_url if raw_url.startswith(("http://", "https://"))
                    else urljoin(ep.url, raw_url))
        if not self.scope.is_in_scope(read_url):
            return {"status": "inconclusive",
                    "detail": "inventory read URL is out of scope",
                    "read_url": read_url}
        try:
            self._paced()
            response = client.get(read_url, headers=headers,
                                  timeout=self.cfg.scan.http_timeout)
        except BudgetExceeded:
            return {"status": "blocked",
                    "detail": "inventory read blocked by request budget",
                    "read_url": read_url}
        except Exception as e:
            return {"status": "inconclusive",
                    "detail": f"inventory read failed: {e}"[:200],
                    "read_url": read_url}
        if response.status_code != 200:
            return {"status": "inconclusive",
                    "detail": f"inventory read → HTTP {response.status_code}",
                    "read_url": read_url}
        value = inventory_value(response.text or "",
                                self.cfg.race.inventory_jsonpath)
        if value is None:
            return {"status": "inconclusive",
                    "detail": "inventory JSONPath did not select one number",
                    "read_url": read_url}
        return {"status": "read", "value": value,
                "read_url": read_url}

    # ── RACE ENGINE (stateful slice, opt-in) ───────────────────────────
    def _race_probe(self, endpoints: List[Endpoint],
                    evidence: EvidenceStore, metrics: Metrics,
                    budgets: BudgetTracker,
                    coverage: CoverageTracker, client,
                    identities) -> List[Finding]:
        from .logic.race import run_race, single_use_field
        cfg_r = self.cfg.race
        profile = (cfg_r.profile or "generic").lower()
        if profile not in ("generic", "single_use", "idempotency",
                           "inventory"):
            coverage.record("race", "untestable",
                            f"unknown race profile: {profile}")
            return []
        targets = [e for e in endpoints
                   if e.body_parameters and e.endpoint_type != "static"
                   and self.scope.active_test_allowed(e.url)]
        actors = [i for i in identities if i.name != "anonymous"] or \
            identities[:1]
        actor = actors[0]
        aname = getattr(actor, "name", "anonymous")
        atenant = getattr(actor, "tenant", "") or ""
        aheaders = dict(getattr(actor, "auth_headers", None) or {})
        if profile == "single_use":
            targets = [e for e in targets if single_use_field({
                p.name: p.sample_value for p in e.body_parameters
                if p.name and p.sample_value})]
        elif profile == "idempotency":
            targets = [e for e in targets if
                       any("idempotency" in p.name.lower()
                           and p.sample_value for p in e.body_parameters
                           if p.name)
                       or any("idempotency" in k.lower() and v
                              for k, v in aheaders.items())]
        elif profile == "inventory":
            selector = (cfg_r.inventory_endpoint or "").strip()
            if not selector or not cfg_r.inventory_read_url or \
                    not cfg_r.inventory_jsonpath:
                coverage.record(
                    "race", "untestable",
                    "inventory profile requires inventory_endpoint, "
                    "inventory_read_url, and inventory_jsonpath")
                return []
            targets = [e for e in targets
                       if e.path == selector or e.url == selector or
                       e.path.endswith(selector)]
        targets = targets[:cfg_r.max_endpoints]
        if not targets:
            coverage.record("race", "untestable",
                            f"no POST-able endpoints match {profile} profile")
            return []
        log.info("race: %d endpoints ×%d/%d as %s", len(targets),
                 cfg_r.concurrency, cfg_r.rounds, aname)
        if not self._reserve_or_block(
                budgets, coverage, "race",
                plan_race(len(targets), cfg_r.concurrency,
                          cfg_r.rounds)):
            return []
        findings: List[Finding] = []
        for ep in targets:
            if self._halted():
                log.info("race: halted by stop control; "
                         "remaining targets stay untested")
                break
            self._paced()
            if not budgets.consume_test("race", ep.normalized_url):
                coverage.record("race", "blocked",
                                f"budget: {ep.normalized_url}")
                continue
            body = {p.name: (p.sample_value or "1")
                    for p in ep.body_parameters if p.name}
            inventory_before = None
            if profile == "inventory":
                before = self._read_race_inventory(client, ep, aheaders)
                if before.get("status") != "read":
                    before_status = ("blocked" if
                                     before.get("status") == "blocked"
                                     else "inconclusive")
                    coverage.record("race", before_status,
                                    before.get("detail", "inventory read failed"))
                    continue
                inventory_before = before["value"]
                if inventory_before <= 0:
                    coverage.record("race", "untestable",
                                    "inventory precondition requires stock > 0")
                    continue
            try:
                res = run_race(client, "POST", ep.url, body, aheaders,
                               concurrency=cfg_r.concurrency,
                               rounds=cfg_r.rounds,
                               timeout=self.cfg.scan.http_timeout,
                               profile=profile)
            except BudgetExceeded:
                coverage.record("race", "blocked",
                                f"budget: {ep.normalized_url}")
                continue
            inventory_verification = None
            if profile == "inventory":
                after = self._read_race_inventory(client, ep, aheaders)
                completed = all(
                    not rr.errors and len(rr.statuses) == cfg_r.concurrency
                    and all(200 <= status < 300 or 400 <= status < 500
                            for status in rr.statuses)
                    for rr in res.round_results)
                accepted = sum(
                    1 for rr in res.round_results for status in rr.statuses
                    if 200 <= status < 300)
                if after.get("status") != "read":
                    if (after.get("status") == "blocked" and
                            accepted > inventory_before):
                        res.verdict = "strong_candidate"
                    else:
                        res.verdict = "inconclusive"
                    res.notes = "inventory post-read failed: " + \
                        after.get("detail", "unknown error")
                    inventory_verification = {
                        "status": "inconclusive", "detail": res.notes,
                        "evidence": {"before": inventory_before}}
                elif after["value"] < 0:
                    from .logic.observations import (evaluate_observation,
                                                      violated)
                    obs = {"action": "write", "resource": ep.url,
                           "quantity_after": after["value"]}
                    res.violations = [v.to_dict() for v in
                                      violated(evaluate_observation(obs))]
                    res.verdict = "strong_candidate"
                    res.notes = (f"inventory fell below zero: "
                                 f"{after['value']}")
                    inventory_verification = {
                        "status": "verified", "detail": res.notes,
                        "evidence": {"before": inventory_before,
                                     "after": after["value"],
                                     "accepted": accepted,
                                     "read_url": after.get("read_url")}}
                elif accepted > inventory_before:
                    res.verdict = "strong_candidate"
                    res.notes = (f"{accepted} reservations accepted with "
                                 f"starting inventory {inventory_before}; "
                                 "post-read did not prove a negative balance")
                    inventory_verification = {
                        "status": "inconclusive", "detail": res.notes,
                        "evidence": {"before": inventory_before,
                                     "after": after["value"],
                                     "accepted": accepted,
                                     "read_url": after.get("read_url")}}
                elif completed and after["value"] >= 0:
                    res.verdict = "negative"
                    res.notes = (f"inventory remained non-negative "
                                 f"({inventory_before} → {after['value']}); "
                                 "completed requests respected available stock")
                    inventory_verification = {
                        "status": "refuted", "detail": res.notes,
                        "evidence": {"before": inventory_before,
                                     "after": after["value"],
                                     "accepted": accepted,
                                     "read_url": after.get("read_url")}}
                else:
                    res.verdict = "inconclusive"
                    res.notes = "inventory race responses were incomplete or ambiguous"
                    inventory_verification = {
                        "status": "inconclusive", "detail": res.notes,
                        "evidence": {"before": inventory_before,
                                     "after": after["value"],
                                     "accepted": accepted}}
            metrics.race_tests += 1
            if res.verdict == "strong_candidate":
                metrics.race_candidates += 1
                self._note_candidate()
                metrics.invariants_tested += 1
                metrics.invariants_violated += len(res.violations)
                coverage.record("race", "candidate", res.notes)
                if inventory_verification is not None:
                    ver = inventory_verification
                elif profile == "single_use":
                    ver = self._verify_race_single_use(
                        client, ep, body, aheaders,
                        single_use_field(body))
                else:
                    ver = self._verify_race_idempotent(
                        client, ep, body, aheaders)
                status, conf = (
                    ValidationStatus.STRONG_CANDIDATE.value,
                    Confidence.PROBABLE.value)
                extra_tags: list = []
                if ver["status"] == "verified":
                    status = ValidationStatus.CONFIRMED.value
                    conf = Confidence.CONFIRMED.value
                    metrics.effects_verified += 1
                    extra_tags.append("verified-effect")
                    log.info("race verified: %s", ver["detail"])
                f = Finding(
                    id=stable_finding_id("race", ep.normalized_url),
                    source="race",
                    name=(f"Race condition: {cfg_r.concurrency}× POST "
                          f"{ep.path} processed concurrently with "
                          f"divergent results"
                          + (" [verified effect]"
                             if ver["status"] == "verified" else "")),
                    severity="high",
                    confidence=conf,
                    validation_status=status,
                    host=ep.host, matched_at=ep.url,
                    endpoint_url=ep.url, method="POST",
                    description=res.notes + (
                        f" Verification: {ver['detail']}"
                        if ver["detail"] else ""),
                    tags=["race", "business-logic", ep.endpoint_type] +
                    extra_tags,
                    raw={"race": res.to_dict(),
                         "verification": ver},
                    false_positive_notes=(
                        "Divergent IDs across a synchronized burst "
                        "indicate duplicate processing; rule out "
                        "request-specific randomness (timestamps, "
                        "nonces) before reporting."
                        + (" Sequential idempotency re-check CONFIRMED "
                           "double processing; see verification evidence."
                           if ver["status"] == "verified" else "")),
                    identity=aname, tenant=atenant,
                )
                evidence.allocate(f)
                evidence.record(
                    f,
                    request_text=(f"{cfg_r.concurrency}× POST {ep.url} "
                                  f"through a start barrier, "
                                  f"{cfg_r.rounds} rounds"),
                    response_text=res.notes + (
                        f"\n--- verification ---\n{ver['detail']}"
                        if ver["detail"] else ""))
                findings.append(f)
                log.info("race: %s", res.notes)
            elif res.verdict == "negative":
                coverage.record("race", "tested_negative",
                                f"{ep.normalized_url}: {res.notes}")
            else:
                coverage.record("race", "inconclusive",
                                f"{ep.normalized_url}: {res.notes}")
        return findings

    def _maybe_register_oast(self) -> Optional[InteractshProvider]:
        want = (self.profile.oast or self.cfg.validation.ssrf
                or self.cfg.validation.enabled
                or self.cfg.validation.second_order_ssrf)
        if not want or not self.cfg.oast.enabled:
            return None
        provider = InteractshProvider(
            server=self.cfg.oast.server,
            api_base=self.cfg.oast.api_base,
            timeout=self.cfg.scan.http_timeout,
            callback_url=self.cfg.oast.callback_url)
        if provider.register():
            return provider
        log.info("OAST unavailable — SSRF blind probes will not be "
                 "confirmed out-of-band")
        return None

    def _oast_sweep(self, endpoints: List[Endpoint],
                    provider: InteractshProvider,
                    evidence: EvidenceStore, metrics: Metrics,
                    client, out_dir: Path,
                    budgets: BudgetTracker,
                    coverage: CoverageTracker) -> List[Finding]:
        ranked_targets = []
        for endpoint in endpoints:
            if (endpoint.endpoint_type == "static" or
                    not self.scope.active_test_allowed(endpoint.url)):
                continue
            parameters = (list(endpoint.query_parameters) +
                          list(endpoint.body_parameters) +
                          list(endpoint.header_parameters))
            candidates = ssrf_candidates(parameters, endpoint)
            if not candidates:
                continue
            field_score = max(ssrf_candidate_score(p, endpoint)[0]
                              for p in candidates)
            route_bonus = int(endpoint.endpoint_type in
                              _OAST_PRIORITY_TYPES)
            ranked_targets.append((field_score + route_bonus, endpoint))
        ranked_targets.sort(key=lambda row: (-row[0], row[1].url))
        targets = [endpoint for _, endpoint in ranked_targets][:
                   self.cfg.oast.max_endpoints]
        if not targets:
            return []
        log.info("oast: sweeping %d SSRF-suspect endpoints",
                 len(targets))
        if not self._reserve_or_block(
                budgets, coverage, "ssrf",
                plan_oast(len(targets),
                          self.cfg.oast.max_params_per_endpoint)):
            return []
        findings: List[Finding] = []
        for ep in targets:
            if self._halted():
                log.info("oast: halted by stop control; "
                         "remaining targets stay untested")
                break
            if not budgets.consume_test(
                    "ssrf", ep.normalized_url,
                    limit=self.cfg.oast.max_endpoints):
                coverage.record("ssrf", "blocked",
                                f"budget: {ep.normalized_url}")
                continue
            try:
                res = probe_endpoint(
                    client, ep, provider,
                    poll_timeout=self.cfg.oast.poll_timeout,
                    poll_interval=self.cfg.oast.poll_interval,
                    max_params=self.cfg.oast.max_params_per_endpoint)
            except BudgetExceeded:
                coverage.record("ssrf", "blocked",
                                f"budget: {ep.normalized_url}")
                continue
            metrics.oast_endpoints_probed += 1
            if res is None or not res.confirmed:
                detail = (res.notes if res else "no probe was sent")
                coverage.record(
                    "ssrf", "inconclusive",
                    f"{ep.normalized_url}: no correlated callback; {detail}")
                continue
            metrics.oast_confirmed += 1
            self._note_candidate()
            coverage.record("ssrf", "confirmed",
                            f"OAST callback on '{res.parameter}'")
            f = Finding(
                id=stable_finding_id("oast", ep.normalized_url),
                source="oast-sweep",
                name=(f"Blind SSRF confirmed via OAST on "
                      f"'{res.parameter}' ({ep.path})"),
                severity="medium",
                confidence=Confidence.CONFIRMED.value,
                validation_status=ValidationStatus.CONFIRMED.value,
                host=ep.host,
                matched_at=ep.url,
                endpoint_url=ep.url,
                method=ep.method,
                parameter=res.parameter,
                description=(
                    "The server fetched our unique out-of-band Interactsh "
                    f"callback on parameter '{res.parameter}' "
                    f"using {res.payload}."),
                tags=["ssrf", "oast", ep.endpoint_type],
                raw={"interactions": res.interactions[:10],
                     "callback_host": res.callback_host,
                     "request_method": res.request_method,
                     "request_url": res.request_url,
                     "parameter_location": res.parameter_location,
                     "response_status": res.response_status,
                     "response_length": res.response_length,
                     "response_time_ms": res.response_time_ms},
                false_positive_notes=(
                    "Confirmed via unique out-of-band Interactsh "
                    "callback (DNS/HTTP/SMTP), not response shape. "
                    "Unique callback host per request eliminates cross-probe "
                    "correlation."),
                identity="anonymous",
            )
            evidence.allocate(f)
            evidence.record(
                f,
                request_text=(f"{res.request_method} {res.request_url}\n"
                              f"{res.parameter_location}::{res.parameter}="
                              f"{res.payload or ''}"),
                response_text="\n".join(
                    _interaction_line(i) for i in res.interactions[:10]))
            findings.append(f)
            log.info("oast: CONFIRMED SSRF on %s param=%s",
                     ep.url, res.parameter)
        return findings

    # ── AI LOOP CLOSURE (spec §8) ──────────────────────────────────────
    def _plan_js_chunks(self, planner: AIPlanner, out_dir: Path
                        ) -> List[Hypothesis]:
        """Feed structurally-chunked JS to the planner and merge."""
        budget = self.cfg.ai.js_chunk_budget
        if budget <= 0:
            return []
        entries = read_jsonl(out_dir / "js_analysis.jsonl")
        # largest bundles first — that's where the routes hide
        entries.sort(key=lambda e: -int(e.get("raw_length") or 0))
        out: List[Hypothesis] = []
        seen: Set[tuple] = set()
        for entry in entries:
            text = (out_dir / "cache").exists() and \
                self._cached_js_text(out_dir, entry.get("url", ""))
            if not text:
                continue
            for chunk in chunk_js(text, max_chunk=12000)[:2]:
                if len(out) + 1 > budget * 3:
                    break
                for h in planner.plan_js_chunk(entry.get("url", ""), chunk):
                    key = (h.endpoint, h.test_class)
                    if key in seen:
                        continue
                    seen.add(key)
                    h.notes = f"from JS chunk of {entry.get('url')}"
                    out.append(h)
                budget -= 1
                if budget <= 0:
                    return out[:40]
        return out[:40]

    @staticmethod
    def _cached_js_text(out_dir: Path, url: str) -> str:
        import re as _re
        key = _re.sub(r"[^A-Za-z0-9_.-]", "_", url or "")[:180]
        p = out_dir / "cache" / key
        if p.exists():
            return p.read_text(errors="ignore")
        return ""

    def _validate_hypotheses(self, hypotheses: List[Hypothesis],
                             endpoints: List[Endpoint],
                             evidence: EvidenceStore, metrics: Metrics,
                             client, nuclei: NucleiRunner,
                             live_file: Path) -> List[Finding]:
        """Feed AI hypotheses back into deterministic testing."""
        new_findings: List[Finding] = []
        by_norm = {e.normalized_url: e for e in endpoints}

        def find_ep(url: str) -> Optional[Endpoint]:
            if not url:
                return None
            try:
                n = normalize_url(url)
            except Exception:
                n = url
            ep = by_norm.get(n)
            if ep is None and not url.startswith("http"):
                # planner may return bare paths
                for e in endpoints:
                    if e.path and e.path.rstrip("/") == \
                            url.rstrip("/"):
                        ep = e
                        break
            return ep

        # route by test class, prioritized by confidence
        per_class: Dict[str, List[Hypothesis]] = {}
        for h in hypotheses:
            per_class.setdefault(h.test_class, []).append(h)
        for cls, items in per_class.items():
            items.sort(key=lambda h: -h.confidence)
            items = items[:self.cfg.ai.max_hypothesis_tests]
            for h in items:
                try:
                    self._route_hypothesis(
                        h, find_ep(h.endpoint), by_norm, evidence,
                        client, new_findings, nuclei, live_file)
                except Exception as e:
                    log.warning("hypothesis test failed (%s): %s",
                                h.test_class, e)
                    h.notes = f"test error: {e}"[:200]

        # classes with no dedicated validator (ssti, traversal, xxe, ...)
        # become Nuclei gate templates (spec §5c)
        new_findings += self._gate_remaining_hypotheses(
            hypotheses, evidence, nuclei, live_file)

        metrics.hypotheses_validated = sum(
            1 for h in hypotheses if h.status == "validated")
        if metrics.hypotheses_validated:
            log.info("ai loop closure: %d hypotheses validated",
                     metrics.hypotheses_validated)
        return new_findings

    def _gate_remaining_hypotheses(self, hypotheses: List[Hypothesis],
                                   evidence: EvidenceStore,
                                   nuclei: NucleiRunner,
                                   live_file: Path) -> List[Finding]:
        """Run AI-generated Nuclei gates for hypotheses no deterministic
        validator claimed. A gate hit promotes the hypothesis to
        validated (still requiring manual confirmation — gates check
        predicted response behaviour, they don't exploit)."""
        if not getattr(self.cfg.nuclei, "ai_templates", True):
            return []
        if not self.profile.run_nuclei or not live_file.exists():
            return []
        pending = [h for h in hypotheses
                   if h.status == "hypothesized" and h.endpoint
                   and str(h.endpoint).startswith("http")
                   and self.scope.is_in_scope(str(h.endpoint))]
        if not pending:
            return []
        gate_findings = run_hypothesis_templates(nuclei, pending, live_file)
        if not gate_findings:
            for h in pending:
                h.status = "inconclusive"
                h.notes = "AI gate template ran: no predicted behaviour"
            return []
        by_url: Dict[str, List[Hypothesis]] = {}
        for h in pending:
            by_url.setdefault(str(h.endpoint), []).append(h)
        out: List[Finding] = []
        for gf in gate_findings:
            for h in by_url.get(gf.matched_at, []):
                if h.status == "validated":
                    continue
                h.status = "validated"
                h.notes = (f"AI gate template {gf.template_id} matched "
                           f"predicted behaviour at {gf.matched_at}")
                gf.source = "ai+nuclei-gate"
                gf.description = h.hypothesis
                evidence.allocate(gf)
                evidence.record(gf,
                                request_text=f"GET {gf.matched_at}",
                                response_text=h.notes)
                out.append(gf)
                break
        return out

    def _route_hypothesis(self, h: Hypothesis, ep: Optional[Endpoint],
                          by_norm: Dict[str, Endpoint],
                          evidence: EvidenceStore, client,
                          new_findings: List[Finding],
                          nuclei: NucleiRunner, live_file: Path):
        url = h.endpoint
        cls = h.test_class.lower()

        def promote(status: str, notes: str, severity: str,
                    validation_status: str, source: str,
                    name: str, finding_raw: Optional[Dict] = None):
            h.status = status
            h.notes = notes
            if status != "validated":
                return
            f = Finding(
                id=stable_finding_id(f"ai-{cls}", url or h.hypothesis),
                source=source, name=name, severity=severity,
                confidence=Confidence.PROBABLE.value,
                validation_status=validation_status,
                host=(url or "").split("//")[-1].split("/")[0],
                matched_at=url or "", endpoint_url=url,
                description=h.hypothesis,
                tags=[cls, "ai-driven"],
                raw=finding_raw or {},
            )
            evidence.allocate(f)
            evidence.record(f, request_text=f"GET {url}",
                            response_text=notes)
            new_findings.append(f)

        # ssrf → OAST
        if cls == "ssrf":
            provider = self._hypothesis_oast()
            if not provider:
                h.notes = "skipped: OAST provider unavailable"
                return
            try:
                target = ep or (endpoint_from_url(url) if url and
                                url.startswith("http") else None)
                if target is None:
                    h.notes = "skipped: no resolvable endpoint"
                    return
                res = probe_endpoint(
                    client, target, provider,
                    poll_timeout=self.cfg.oast.poll_timeout,
                    poll_interval=self.cfg.oast.poll_interval,
                    max_params=self.cfg.oast.max_params_per_endpoint)
            finally:
                provider.close()
            if res and res.confirmed:
                promote("validated",
                        f"OAST callback on '{res.parameter}'",
                        "medium", ValidationStatus.CONFIRMED.value,
                        "ai+oast",
                        f"AI-hypothesized SSRF confirmed via OAST "
                        f"({h.hypothesis[:80]})",
                        {"interactions": res.interactions[:10],
                         "parameter": res.parameter,
                         "payload": res.payload,
                         "callback_host": res.callback_host,
                         "request_method": res.request_method,
                         "request_url": res.request_url,
                         "parameter_location": res.parameter_location})
            else:
                h.status = "rejected"
                h.notes = "no OAST callback received"
            return

        # sqli → mutation pre-screen then sqlmap
        if cls == "sqli" and url:
            candidate = Candidate(
                finding=Finding(id="probe", source="ai+sqli"),
                test_class="sqli", endpoint_url=url,
                method="GET")
            if ep:
                q = ep.query_parameters[0] if ep.query_parameters else None
                if q:
                    candidate.parameter = q.name
            outcome = None
            if self.cfg.validation.mutation:
                engine = MutationEngine(self.cfg, client,
                                        self._waf_hint())
                outcome = engine.prescreen_sqli(candidate)
            if outcome is None and which("sqlmap"):
                outcome = SqliValidator(self.cfg).validate(candidate)
            if outcome and outcome.status in ("confirmed",
                                              "strong_candidate"):
                promote("validated", outcome.notes,
                        "high", outcome.status, "ai+sqli",
                        f"AI-hypothesized SQLi ({h.hypothesis[:80]})",
                        outcome.evidence)
            elif outcome:
                h.status = "rejected"
                h.notes = outcome.notes or "no injection signal"
            else:
                h.notes = "skipped: no sqlmap/mutation engine available"
            return

        # xss → mutation pre-screen then dalfox
        if cls == "xss" and url:
            candidate = Candidate(
                finding=Finding(id="probe", source="ai+xss"),
                test_class="xss", endpoint_url=url, method="GET")
            outcome = None
            if self.cfg.validation.mutation:
                engine = MutationEngine(self.cfg, client, self._waf_hint())
                outcome = engine.prescreen_xss(candidate)
            if outcome is None and which("dalfox"):
                outcome = XssValidator(self.cfg).validate(candidate)
            if outcome and outcome.status in ("confirmed",
                                              "strong_candidate"):
                promote("validated", outcome.notes, "medium",
                        outcome.status, "ai+xss",
                        f"AI-hypothesized XSS ({h.hypothesis[:80]})",
                        outcome.evidence)
            elif outcome:
                h.status = "rejected"
                h.notes = outcome.notes or "no XSS signal"
            else:
                h.notes = "skipped: no dalfox/mutation engine available"
            return

        # idor / authz / bola → differential tester
        if cls in ("idor", "authz", "bola") and url:
            diff = DifferentialTester(self.cfg, client)
            etype = ep.endpoint_type if ep else "unknown"
            res = diff.probe(url, etype,
                             timeout=self.cfg.scan.http_timeout)
            if res.verdict == "strong_candidate":
                promote("validated", res.notes, "high",
                        ValidationStatus.STRONG_CANDIDATE.value,
                        "ai+differential",
                        f"AI-hypothesized IDOR/authz ({h.hypothesis[:80]})",
                        {"contexts": [vars(c) for c in res.contexts]})
            else:
                h.status = "inconclusive" if res.notes else "rejected"
                h.notes = res.notes or "no auth differential observed"
            return

        h.notes = f"no deterministic validator wired for class '{cls}'"

    def _hypothesis_oast(self) -> Optional[InteractshProvider]:
        if not self.cfg.oast.enabled:
            return None
        provider = InteractshProvider(
            server=self.cfg.oast.server, api_base=self.cfg.oast.api_base,
            timeout=self.cfg.scan.http_timeout,
            callback_url=self.cfg.oast.callback_url)
        return provider if provider.register() else None

    def _waf_hint(self) -> Optional[str]:
        return getattr(self, "_active_waf", None)

    def _load_endpoints(self, out_dir: Path) -> List[Endpoint]:
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

    @staticmethod
    def _read_lines(p: Path) -> List[str]:
        if not p.exists():
            return []
        return [l.strip() for l in p.read_text(errors="ignore").splitlines()
                if l.strip()]


def _interaction_line(i: Dict) -> str:
    proto = i.get("proto") or i.get("type", "?")
    return f"[{proto}] " + " ".join(str(v)[:120] for v in i.values()
                                    if isinstance(v, str))[:240]


def _append_query_parameter(url: str, name: str, value: str) -> str:
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
    parts = urlsplit(url)
    query = parse_qsl(parts.query, keep_blank_values=True)
    query.append((name, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path,
                       urlencode(query, doseq=True), parts.fragment))


def _nested_parameter_object(values: Dict[str, str]) -> Dict:
    """Convert OpenAPI dotted property names into a JSON object."""
    out: Dict = {}
    for name, value in values.items():
        _assign_nested(out, name, value)
    return out


def _assign_nested(out: Dict, name: str, value) -> None:
    import re
    parts = re.findall(r"[^.\[\]]+|\[\d*\]", name)
    cursor = out
    for index, raw in enumerate(parts):
        is_last = index == len(parts) - 1
        if raw.startswith("["):
            if not isinstance(cursor, list):
                return
            slot = raw[1:-1]
            pos = int(slot) if slot.isdigit() else 0
            while len(cursor) <= pos:
                cursor.append({})
            if is_last:
                cursor[pos] = value
            elif not isinstance(cursor[pos], (dict, list)):
                cursor[pos] = [] if parts[index + 1].startswith("[") else {}
            cursor = cursor[pos]
        else:
            if not isinstance(cursor, dict):
                return
            if is_last:
                cursor[raw] = value
            else:
                next_is_array = parts[index + 1].startswith("[")
                if not isinstance(cursor.get(raw), (dict, list)):
                    cursor[raw] = [] if next_is_array else {}
                cursor = cursor[raw]


def _rank_ssrf_triggers(sink: Endpoint, endpoints: List[Endpoint]):
    """Rank safe GET routes that can plausibly process a stored sink value."""
    import re
    sink_path = (sink.path or "").lower().rstrip("/") or "/"
    sink_tokens = set(re.findall(r"[a-z0-9]+", sink_path))
    sink_context = " ".join([sink.summary, sink.description,
                             sink.operation_id, *sink.tags]).lower()
    sink_terms = set(re.findall(r"[a-z0-9]+", sink_context))
    trigger_terms = {"job", "task", "status", "result", "preview", "render",
                     "process", "worker", "history", "detail", "file", "image"}
    ranked = []
    for candidate in endpoints:
        if candidate.method.upper() != "GET" or candidate.endpoint_type == "static":
            continue
        path = (candidate.path or "").lower().rstrip("/") or "/"
        tokens = set(re.findall(r"[a-z0-9]+", path))
        context = " ".join([candidate.summary, candidate.description,
                            candidate.operation_id, *candidate.tags]).lower()
        context_tokens = set(re.findall(r"[a-z0-9]+", context))
        score = 0
        rationale = []
        if path == sink_path:
            score += 8
            rationale.append("same resource route")
        overlap = sink_tokens & tokens - {"api", "v1", "v2", "v3"}
        if overlap:
            score += min(5, len(overlap) * 2)
            rationale.append("shared resource path: " + ", ".join(sorted(overlap)))
        if context_tokens & trigger_terms:
            score += 3
            rationale.append("documented processing or result route")
        if tokens & trigger_terms:
            score += 2
            rationale.append("processing or result path segment")
        if sink_terms & context_tokens:
            score += 2
            rationale.append("shared OpenAPI operation context")
        if score >= 3:
            ranked.append((candidate, score, "; ".join(rationale)))
    return sorted(ranked, key=lambda item: (-item[1], item[0].url))


def _materialize_trigger_urls(templates: List[str], response, base_url: str):
    """Fill documented `{id}` trigger paths from a create response."""
    import json
    import re
    from urllib.parse import urljoin, urlsplit
    values = {}
    try:
        payload = json.loads(getattr(response, "text", "") or "")
        if isinstance(payload, dict):
            values.update({str(k).lower(): str(v) for k, v in payload.items()
                           if isinstance(v, (str, int))})
            for key in ("data", "result", "job", "task", "resource"):
                nested = payload.get(key)
                if isinstance(nested, dict):
                    values.update({str(k).lower(): str(v)
                                   for k, v in nested.items()
                                   if isinstance(v, (str, int))})
    except (TypeError, ValueError):
        pass
    location = ""
    for key, value in (getattr(response, "headers", {}) or {}).items():
        if str(key).lower() == "location":
            location = urljoin(base_url, str(value))
            break
    location_id = urlsplit(location).path.rstrip("/").split("/")[-1]
    if location_id and location_id.lower() not in {
            "", "status", "result", "preview", "history"}:
        values.setdefault("id", location_id)
        values.setdefault("jobid", location_id)
        values.setdefault("taskid", location_id)
    materialized = []
    for template in templates:
        unresolved = False
        def replace(match):
            nonlocal unresolved
            key = match.group(1).lower()
            value = values.get(key)
            if value is None and key.endswith("id"):
                value = values.get("id")
            if value is None:
                unresolved = True
                return match.group(0)
            return value
        url = re.sub(r"\{([^{}]+)\}", replace, template)
        if not unresolved:
            materialized.append(url)
    return materialized


def _classify_finding(f: Finding) -> str:
    name = (f.name or "").lower() + " " + (f.template_id or "").lower()
    if "sqli" in name or "sql" in name:
        return "sqli"
    if "xss" in name:
        return "xss"
    if "ssrf" in name:
        return "ssrf"
    if "ssti" in name:
        return "ssti"
    if "traversal" in name or "lfi" in name:
        return "path_traversal"
    if "redirect" in name:
        return "open_redirect"
    if "idor" in name or "bola" in name:
        return "idor"
    return "unknown"


class _HTTPClient:
    def __init__(self, limiter: Optional[AdaptiveRateLimiter] = None,
                 budgets: Optional[BudgetTracker] = None):
        import requests
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "ApexFuzzer/5.2 (+authorized-testing)"})
        self.limiter = limiter
        self.budgets = budgets

    def _budget_ok(self, url: str, mutating: bool = False):
        if not self.budgets:
            return
        from urllib.parse import urlparse as _up
        try:
            host = _up(url).hostname or ""
        except Exception:
            host = ""
        if mutating:
            if not self.budgets.consume_mutation(host, url):
                raise BudgetExceeded(f"mutation budget exceeded for {host}")
            return
        if not self.budgets.consume_request(host, url):
            raise BudgetExceeded(f"budget exceeded for {host}")

    def get(self, url, **kw):
        if self.limiter:
            self.limiter.before_request()
        self._budget_ok(url)
        r = self.session.get(url, allow_redirects=False, **kw)
        if self.limiter:
            self.limiter.after_response(r.status_code)
        return r

    def post(self, url, **kw):
        if self.limiter:
            self.limiter.before_request()
        self._budget_ok(url, mutating=True)
        r = self.session.post(url, allow_redirects=False, **kw)
        if self.limiter:
            self.limiter.after_response(r.status_code)
        return r

    def request(self, method, url, **kw):
        """Generic verb (PUT/PATCH/DELETE…) with limiter + budget gates."""
        if self.limiter:
            self.limiter.before_request()
        self._budget_ok(url, mutating=method.upper() != "GET")
        r = self.session.request(method.upper(), url,
                                 allow_redirects=False, **kw)
        if self.limiter:
            self.limiter.after_response(r.status_code)
        return r
