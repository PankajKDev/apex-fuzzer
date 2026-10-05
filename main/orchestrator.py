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
from typing import List, Optional
from .config import Config
from .scope import Scope, slug_host, target_hostname
from .profiles import Profile, get as get_profile
from .models import (Finding, Hypothesis, write_jsonl, read_jsonl)
from .logging_setup import get_logger, attach_file_handler
from .shell import AdaptiveRateLimiter
from .budgets import BudgetTracker
from .checkpoints import Checkpoint
from .http import HTTPClient
from .chains.builder import build_attack_chains
from .stages.recon import (harvest_api_specs, harvest_robots, merge_recon,
                           run_recon)
from .stages.mapping import build_app_state, map_attack_surface
from .stages.intel import (build_resource_intel, discover_invariants,
                           discover_workflows, record_behavioral_state)
from .stages.reporting import render_report
from .stages.validation import ProbeControls
from .stages.validation.coordinator import run_validation
from .stages.auth import login_identities
from .stages.ai_loop import plan_js_chunks, validate_hypotheses
from .stages.endpoints import build_endpoints, load_endpoints
from .stages.scanning import (probe_live, run_nuclei_stage,
                              takeover_check)
from .application.application_model import Application
from .graph.application_graph import ApplicationGraph
from .reporting.coverage import CoverageTracker
from .plugins import adapters as _plugin_adapters  # noqa: F401 (registry)
from .detection.nuclei import NucleiRunner
from .validation.evidence import EvidenceStore
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
        host = slug_host((target.replace("http://", "")
                          .replace("https://", "").split("/")[0]))
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
            endpoints = load_endpoints(out_dir)
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
        login_identities(out_dir, metrics, self.cfg, self.scope)
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
            hypotheses += plan_js_chunks(planner, out_dir, self.cfg)
            metrics.hypotheses_generated = len(hypotheses)

            # loop closure (spec §8): feed hypotheses back into tests
            findings += validate_hypotheses(
                hypotheses, endpoints, evidence, metrics, client,
                nuclei, live_file, self.cfg, self.scope,
                self.profile, self._active_waf)
            write_jsonl(out_dir / "hypotheses.jsonl", hypotheses)
            ck.mark("ai")
        else:
            ck.mark("ai", "skipped")

        # ── 9b. LEAD COLLECTION (offline, always runs) ──────────────
        # Pure ranking over collected artifacts: zero network. Leads
        # mode exists for this output; every other profile gets it as
        # a free work list alongside findings.
        # ── 9c. ATTACK CHAINS (agent Phase 19, offline) ─────────────
        # Deterministic finding→capability→impact hypotheses (ATO
        # first). Zero network, always runs; chains hypothesize,
        # never confirm, and never alter finding counts.
        build_attack_chains(out_dir, findings, metrics)
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
        host = slug_host((target.replace("http://", "")
                          .replace("https://", "").split("/")[0]))
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






    def _read_lines(self, p: Path) -> List[str]:
        if not p.exists():
            return []
        return [l.strip() for l in p.read_text(errors="ignore").splitlines()
                if l.strip()]


_HTTPClient = HTTPClient
