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
                     ValidationStatus, stable_finding_id,
                     RESULT_STATUSES)
from .logging_setup import get_logger, attach_file_handler
from .shell import which, AdaptiveRateLimiter
from .budgets import BudgetTracker
from .checkpoints import Checkpoint
from .http import HTTPClient
from .stages.recon import (harvest_api_specs, harvest_robots, merge_recon,
                           recon_identity_headers, run_recon)
from .stages.validation import ProbeControls
from .stages.validation.coordinator import run_validation
from .stages.endpoints import build_endpoints
from .stages.scanning import (probe_live, run_nuclei_stage,
                              takeover_check)
from .application.application_model import (Application,
                                            build_from_scan)
from .graph.application_graph import (ApplicationGraph,
                                      build_from_application)
from .reporting.coverage import CoverageTracker
from .plugins import adapters as _plugin_adapters  # noqa: F401 (registry)
from .discovery.url_normalizer import normalize_url
from .discovery import parameters as param_mod
from .discovery import technologies as tech_mod
from .discovery import param_miner
from .discovery.javascript import chunk_js
from .discovery.classifier import classify
from .detection.nuclei import NucleiRunner, run_hypothesis_templates
from .validation.evidence import EvidenceStore
from .validation.base import Candidate
from .validation.sqli import SqliValidator
from .validation.xss import XssValidator
from .validation.ssrf import endpoint_from_url
from .validation.oast import (InteractshProvider, probe_endpoint)
from .validation.differential import DifferentialTester
from .validation.mutate import MutationEngine, fingerprint_waf
from .ai.planner import AIPlanner
from .reporting.metrics import Metrics
from .reporting.html import render_html
from .safety.preflight import (StopFlag, Pacer, get_interrupt_flag,
                               resolve_modules, dry_run_plan)
from .safety.impact import max_level
from .safety.authorization import (
    Authorization, AuthorizationRefused, GATED_MODULES)

log = get_logger("orchestrator")


def takeover_notes_from_file(path) -> List[str]:
    """Vulnerable-host lines from subzy stdout.

    Subzy prints banner/config lines even with zero hits; only lines
    naming a vulnerable host become leads. Pure file read, no network.
    """
    import re as _re
    notes: List[str] = []
    try:
        text = Path(path).read_text(errors="ignore")
    except OSError:
        return []
    for line in text.splitlines():
        clean = _re.sub(r"\x1b\[[0-9;]*m", "", line).strip()
        # subzy prints banner/config lines even with zero hits; only
        # lines naming a vulnerable host become leads. Flag
        # descriptions (e.g. --hide_fails) mention "vulnerable" too,
        # so lines documenting a CLI flag are excluded.
        if clean and "vuln" in clean.lower() and "(--" not in clean:
            notes.append(clean)
        if len(notes) >= 20:
            break
    return notes

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
            self._map_attack_surface(endpoints, host, out_dir, metrics,
                                     client)
            write_jsonl(out_dir / "endpoints.jsonl", endpoints)
            ck.mark("mapping")
        # Runtime inventory snapshot for the audit store (flushed with
        # the run record; JSONL stays the system of record). Stashed
        # on both fresh and resume paths so a resumed mapping never
        # diffs as all-gone.
        self._last_endpoints = list(endpoints or [])

        # ── 4b. APPLICATION MODEL + GRAPH (§4–5, built incrementally) ────
        application, app_graph = self._build_app_state(
            endpoints, host, out_dir, ck, resume, metrics, coverage)

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
                self._record_behavioral_state(app_graph, result.matrix,
                                              out_dir)
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

        # ── 9b. LEAD COLLECTION (offline, always runs) ──────────────
        # Pure ranking over collected artifacts: zero network. Leads
        # mode exists for this output; every other profile gets it as
        # a free work list alongside findings.
        from .leads import collect_leads, write_leads
        takeover_notes = takeover_notes_from_file(out_dir / "takeover.txt")
        tech_dicts = read_jsonl(out_dir / "technologies.jsonl")
        leads = collect_leads(endpoints, tech_dicts, takeover_notes)
        write_leads(out_dir / "leads.jsonl", leads)
        metrics.leads_total = len(leads)
        log.info("leads: %d ranked follow-ups -> leads.jsonl", len(leads))
        from .reporting.burp import export_burp
        burp_summary = export_burp(out_dir, endpoints, leads)
        log.info("burp: %d requests + sitemap + checklist -> burp/",
                 burp_summary["requests"])

        # ── 10. REPORT ──────────────────────────────────────────────────
        self._apply_reviews(findings, out_dir)
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
        changes = self._flush_run_audit(
            out_dir, target, host, started,
            getattr(client, "scope_denials", None) or []) or {}
        render_html(out_dir / "report.html", target, findings,
                    [h.to_dict() for h in hypotheses],
                    metrics.to_dict(),
                    min_severity=self.cfg.reporting.min_severity,
                    output_dir=out_dir,
                    coverage=coverage.to_dict(),
                    safety_info=getattr(self, "_safety_info", None),
                    leads=leads,
                    burp=burp_summary,
                    changes=changes or None)
        ck.mark("report")
        log.info("done: %s (%.1fs)", host, metrics.scan_duration_seconds)

    @staticmethod
    def _apply_reviews(findings: List[Finding],
                       out_dir: Path) -> int:
        """Attach operator review marks to findings (report-time).

        Marks surface in ``false_positive_notes`` (rendered by the
        HTML report) and ``raw.review`` (persisted to findings.jsonl),
        so triage decisions stick across runs via stable finding IDs.
        Returns the number of marked findings.
        """
        from .reporting.reviews import load_reviews
        index = load_reviews(out_dir / "reviews.jsonl")
        if not len(index):
            return 0
        marked = 0
        for f in findings or []:
            record = index.verdict_for_finding(getattr(f, "id", ""))
            if not record:
                continue
            verdict, reason = record["verdict"], record["reason"]
            note = f"Operator review ({verdict})" + \
                   (f": {reason}" if reason else "")
            existing = str(getattr(f, "false_positive_notes", "") or "")
            f.false_positive_notes = (
                f"{existing} [{note}]" if existing else note)
            try:
                f.raw["review"] = record
            except (TypeError, AttributeError):
                pass
            marked += 1
        if marked:
            log.info("reviews: %d finding(s) marked", marked)
        return marked


    def _flush_run_audit(self, out_dir: Path, target: str, host: str,
                           started_epoch: float,
                           denials) -> dict:
        """Persist the run + scope-gate audit trail to apex.db.

        Best-effort by design: a store failure logs and never fails
        the scan (artifacts on disk stay the system of record).
        Returns the endpoint-change diff (for the report), or {}.
        """
        try:
            from datetime import datetime, timezone
            from . import __version__
            from .reporting.run_store import (
                RunStore, diff_endpoint_runs)
            import json as _json
            started_utc = datetime.fromtimestamp(
                started_epoch, tz=timezone.utc).isoformat(
                    timespec="seconds")
            with RunStore(out_dir / "apex.db") as store:
                previous = store.latest_run(target)
                if previous is not None and \
                        not previous.get("finished_utc"):
                    # an interrupted run leaves partial inventory:
                    # never diff against it, wait for a clean baseline
                    previous = None
                run_id = store.begin_run(
                    target, host,
                    profile=getattr(self.profile, "name", "standard"),
                    tool_version=str(__version__),
                    authorization_ref=str(
                        self.cfg.safety.authorization_ref or ""),
                    started_utc=started_utc)
                stored = store.record_denials(run_id, denials)
                inventoried = store.record_endpoints(
                    run_id, list(getattr(self, "_last_endpoints",
                                         None) or []))
                previous_rows = [] if previous is None else \
                    store.endpoints_for_run(previous["id"])
                current_rows = store.endpoints_for_run(run_id)
                changes = diff_endpoint_runs(previous_rows,
                                             current_rows)
                changes["against_run"] = (previous or {}).get("id")
                (out_dir / "changes.json").write_text(
                    _json.dumps(changes, indent=2))
                store.finish_run(run_id)
            if stored:
                log.info("audit: %d scope denial(s) -> apex.db",
                         stored)
            log.debug("audit: %d endpoint(s) -> apex.db", inventoried)
            if not changes.get("baseline"):
                log.info("changes: %d new, %d changed, %d gone "
                         "(vs run %s) -> changes.json",
                         len(changes["new"]), len(changes["changed"]),
                         len(changes["gone"]), changes["against_run"])
            else:
                log.info("changes: baseline established (%d endpoints) "
                         "-> changes.json", len(current_rows))
            return changes
        except Exception as e:
            log.debug("run audit skipped: %s", e)
            return {}

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









    def _map_attack_surface(self, endpoints: List[Endpoint], host: str,
                            out_dir: Path, metrics: Metrics, client):
        tech_by_name = {}
        html_params: List[Parameter] = []
        all_headers: Dict[str, str] = {}
        page_ids: List[tuple] = []  # (url, param, value, source)
        passes: List[Optional[dict]] = [None]
        authed = recon_identity_headers(self.cfg)
        if authed:
            passes.append(authed)
        for pass_headers in passes:
            for ep in [e for e in endpoints
                       if e.method == "GET"][:30]:
                fetch_kwargs = {"timeout": self.cfg.scan.http_timeout}
                if pass_headers:
                    fetch_kwargs["headers"] = pass_headers
                try:
                    r = client.get(ep.url, **fetch_kwargs)
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
