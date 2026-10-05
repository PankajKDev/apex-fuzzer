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
import ipaddress
import time
from pathlib import Path
from typing import List, Dict, Set, Optional
from .config import Config
from .scope import Scope, target_hostname
from .profiles import Profile, get as get_profile
from .models import (Endpoint, Parameter, Finding, Hypothesis,
                     write_jsonl, read_jsonl, Confidence,
                     ValidationStatus, stable_finding_id)
from .logging_setup import get_logger, attach_file_handler
from .shell import which, AdaptiveRateLimiter
from .budgets import BudgetTracker
from .checkpoints import Checkpoint
from .http import HTTPClient
from .stages.recon import (harvest_api_specs, harvest_robots, merge_recon,
                           run_recon)
from .stages.mapping import build_app_state, map_attack_surface
from .stages.intel import (build_resource_intel, discover_invariants,
                           discover_workflows, record_behavioral_state)
from .stages.reporting import render_report
from .stages.validation import ProbeControls
from .stages.validation.coordinator import run_validation
from .stages.endpoints import build_endpoints
from .stages.scanning import (probe_live, run_nuclei_stage,
                              takeover_check)
from .application.application_model import Application
from .graph.application_graph import ApplicationGraph
from .reporting.coverage import CoverageTracker
from .plugins import adapters as _plugin_adapters  # noqa: F401 (registry)
from .discovery.url_normalizer import normalize_url
from .discovery.javascript import chunk_js
from .detection.nuclei import NucleiRunner, run_hypothesis_templates
from .validation.evidence import EvidenceStore
from .validation.base import Candidate
from .validation.sqli import SqliValidator
from .validation.xss import XssValidator
from .validation.ssrf import endpoint_from_url
from .validation.oast import (InteractshProvider, probe_endpoint)
from .validation.differential import DifferentialTester
from .validation.mutate import MutationEngine
from .ai.planner import AIPlanner
from .reporting.metrics import Metrics
from .safety.preflight import (StopFlag, Pacer, get_interrupt_flag,
                               resolve_modules, dry_run_plan)
from .safety.impact import max_level
from .safety.authorization import (
    Authorization, AuthorizationRefused, GATED_MODULES)

log = get_logger("orchestrator")




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
        self._last_endpoints: list = []

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
        extra_headers = {}
        hacker_header = str(getattr(self.cfg.scan, "hacker_header", "")
                            or "").strip()
        if hacker_header:
            extra_headers["X-HackerOne"] = hacker_header
        configured_ua = str(getattr(self.cfg.scan, "user_agent", "")
                            or "").strip()
        # Local-lab mode is a pure hostname check (no DNS, pre-network):
        # loopback literals stay testable while public targets keep the
        # private-range block (redirects to 169.254.x, 10/8, … stay dead).
        lab_host = (target_hostname(target) or "").lower().strip("[]")
        try:
            lab_target = lab_host in ("localhost", "::1") or not ipaddress.ip_address(
                lab_host).is_global
        except ValueError:
            lab_target = lab_host == "localhost"
        client = HTTPClient(limiter=limiter, budgets=budgets,
                             extra_headers=extra_headers,
                             user_agent=configured_ua,
                             scope=self.scope,
                             allow_private_targets=lab_target,
                             allow_state_change=bool(
                                 self.cfg.safety.allow_state_change),
                             approved_cidrs=list(
                                 self.cfg.safety.approved_cidrs or []))
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
            metrics.urls_discovered = len(
                run_recon(self.cfg, self.profile, target, out_dir))
            ck.mark("recon")

        # Robots / sitemap appended to raw URL pool (spec §6).
        # Harvest runs after recon, so re-merge: robots.txt.out would
        # otherwise sit on disk while endpoints build without it.
        if self.profile.robots and self.cfg.discovery.robots_sitemap:
            harvest_robots(client, base_url, out_dir,
                             self.cfg.scan.http_timeout)
            merge_recon(self.cfg, out_dir)

        raw_urls = self._read_lines(out_dir / "raw.txt")
        metrics.urls_discovered = len(raw_urls)
        scoped = [u for u in raw_urls if self.scope.is_in_scope(u)]
        log.info("in-scope URLs: %d / %d", len(scoped), len(raw_urls))

        # ── 2. ENDPOINT BUILD ───────────────────────────────────────────
        if resume and ck.is_complete("discovery"):
            endpoints = self._load_endpoints(out_dir)
        else:
            ck.mark("discovery", "running")
            endpoints = build_endpoints(
                scoped, host, out_dir, client, base_url, budgets,
                metrics, self.cfg, self.profile, self.scope)
            metrics.unique_endpoints = len(endpoints)
            metrics.parameters_discovered = sum(
                len(e.query_parameters) + len(e.body_parameters)
                for e in endpoints)
            write_jsonl(out_dir / "endpoints.jsonl", endpoints)
            ck.mark("discovery")

        # ── 3. API SPEC DISCOVERY ───────────────────────────────────────
        if (self.profile.api_specs and self.cfg.discovery.api_specs):
            if not (resume and ck.is_complete("mapping")):
                harvest_api_specs(client, base_url, endpoints,
                                    out_dir,
                                    self.cfg.scan.http_timeout,
                                    self.scope)

        # ── 4. MAPPING ──────────────────────────────────────────────────
        if resume and ck.is_complete("mapping"):
            log.info("mapping complete (resume)")
        else:
            ck.mark("mapping", "running")
            self._page_ids = map_attack_surface(
                endpoints, host, out_dir, metrics, client,
                self.cfg, self.profile, self.scope)
            write_jsonl(out_dir / "endpoints.jsonl", endpoints)
            ck.mark("mapping")
        # Runtime inventory snapshot for the audit store (flushed with
        # the run record; JSONL stays the system of record). Stashed
        # on both fresh and resume paths so a resumed mapping never
        # diffs as all-gone.
        self._last_endpoints = list(endpoints or [])

        # ── 4b. APPLICATION MODEL + GRAPH (§4–5, built incrementally) ────
        application, app_graph = build_app_state(
            endpoints, host, out_dir, ck, resume, metrics, coverage,
            self.cfg)

        # ── 5. LIVE HOST PROBE  (BUGFIX A) ──────────────────────────────
        live_file = out_dir / "live.txt"
        if resume and ck.is_complete("probe"):
            log.info("live probe complete (resume)")
        else:
            ck.mark("probe", "running")
            probe_live(self.cfg, self.scope, out_dir, live_file)
            metrics.live_hosts = len(self._read_lines(live_file))
            ck.mark("probe")
        log.info("live hosts: %d", metrics.live_hosts)

        # ── 6. SUBDOMAIN TAKEOVER  (BUGFIX B + tko-subs confirmed) ──────
        findings: List[Finding] = []
        if self.profile.run_subzy or self.profile.run_tko:
            findings += takeover_check(
                self.cfg, self.profile, self.scope, out_dir, host,
                metrics, coverage)

        # ── 7. NUCLEI ───────────────────────────────────────────────────
        nuclei = NucleiRunner(self.cfg, out_dir)
        # NOTE: takeover findings (tko/subzy) seed the list; nuclei findings
        # are appended below when that stage runs.
        findings, fresh_nuclei = run_nuclei_stage(
            self.cfg, self.profile, self.scope, out_dir, live_file,
            nuclei, findings, metrics, coverage, ck, resume)

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
        run_validation_enabled = (self.profile.run_validation
                                  or self.cfg.validation.enabled)
        run_second_order = (self.profile.second_order
                            or self.cfg.validation.second_order
                            or self.cfg.validation.second_order_ssrf)
        run_diff = (self.profile.differential
                    or self.cfg.validation.differential)
        run_oast = self.profile.oast or self.cfg.validation.ssrf
        if run_validation_enabled or run_diff or run_oast or run_second_order:
            ck.mark("validation", "running")
            result = run_validation(
                findings, endpoints, evidence, metrics, client,
                out_dir, budgets, coverage, self.cfg, self.scope,
                self.profile, ProbeControls.from_orchestrator(self),
                app_graph=app_graph, ck=ck)
            findings = result.findings
            self._active_waf = result.active_waf
            self._harvest_pool = result.harvest_pool
            self._last_matrix = result.matrix
            if app_graph is not None and result.matrix is not None:
                record_behavioral_state(app_graph, result.matrix,
                                        out_dir)
            write_jsonl(out_dir / "findings.jsonl", findings)
            ck.mark("validation")
        else:
            ck.mark("validation", "skipped")

        # ── 8b. WORKFLOW DISCOVERY (agent Phase 4, offline) ─────────
        # Pure analysis over collected data — zero network, always safe.
        discover_workflows(out_dir, endpoints, application,
                           app_graph, metrics, ck, self._harvest_pool)

        # ── 8c. RESOURCE INTEL (agent Phase 5, offline) ──────────────
        # Lifecycle-aware records from everything collected so far.
        # Zero network: only cached files and in-memory sweep data.
        build_resource_intel(
            out_dir, endpoints, application, app_graph, metrics, ck,
            self._harvest_pool, self._page_ids, self._last_matrix)

        # ── 8d. INVARIANT DISCOVERY (agent Phase 6, offline) ─────────
        # Mine holding rules from matrix observations; second-opinion
        # re-evaluation that corroborates existing findings or emits
        # genuinely new ones — never duplicates.
        inv_findings = discover_invariants(
            out_dir, endpoints, evidence, metrics, coverage, findings,
            self._last_matrix, self._harvest_pool)
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

        # ── 9b. LEAD COLLECTION (offline, always runs) ──────────────
        # Pure ranking over collected artifacts: zero network. Leads
        # mode exists for this output; every other profile gets it as
        # a free work list alongside findings.
        # ── 10. REPORT ──────────────────────────────────────────────────
        render_report(out_dir, target, host, started, findings,
                      hypotheses, metrics, coverage, budgets, ck,
                      self.cfg, self.profile, client,
                      getattr(self, "_safety_info", None), endpoints,
                      self._last_endpoints)




    # =====================================================================
    # PREFLIGHT + DRY-RUN (Milestone 1)
    # =====================================================================
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













    # ── VALIDATION (spec §2/3/4/8) ─────────────────────────────────────

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





    # ── BEHAVIORAL STATE (agent Phase 3) ─────────────────────────────

    # ── WORKFLOW DISCOVERY (agent Phase 4, offline) ────────────────

    # ── STORED-XSS CORRELATION (bounty item #3) ────────────────────────







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
        if url and not self.scope.active_test_allowed(url):
            h.status = "inconclusive"
            h.notes = "skipped: hypothesized target is not active-test " \
                "eligible"
            return

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


_HTTPClient = HTTPClient
