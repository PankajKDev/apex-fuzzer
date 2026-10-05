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
from .budgets import BudgetTracker, BudgetExceeded
from .checkpoints import Checkpoint
from .http import HTTPClient
from .stages.recon import (harvest_api_specs, harvest_robots, merge_recon,
                           recon_identity_headers, run_recon)
from .stages.validation import ProbeControls, reserve_or_block
from .stages.endpoints import build_endpoints
from .stages.scanning import (probe_live, run_nuclei_stage,
                              takeover_check)
from .stages.validation.cache import cache_probe
from .stages.validation.differential import differential_probe
from .stages.validation.identity import mfa_transition_probe, oauth_probe
from .stages.validation.introspection import graphql_introspection_probe
from .stages.validation.oast import oast_sweep
from .stages.validation.plugins import (apply_plugin_results,
                                         finding_endpoint)
from .stages.validation.prescreen import prescreen_sweep
from .reporting.coverage import classify_finding
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
from .discovery import param_miner
from .discovery.javascript import chunk_js
from .discovery.classifier import classify
from .detection.nuclei import NucleiRunner, run_hypothesis_templates
from .validation.evidence import EvidenceStore, interaction_line
from .validation.base import Candidate
from .validation.sqli import SqliValidator
from .validation.xss import XssValidator
from .validation.ssrf import endpoint_from_url
from .validation.oast import (InteractshProvider, probe_endpoint,
                               matching_interactions)
from .validation.ssrf_triggers import (
    append_query_parameter, assign_nested, materialize_trigger_urls,
    nested_parameter_object, rank_ssrf_triggers)
from .validation.differential import (DifferentialTester,
                                       has_idor_params,
                                       PRIVILEGED_TYPES)
from .validation.mutate import MutationEngine, fingerprint_waf
from .ai.planner import AIPlanner
from .reporting.metrics import Metrics
from .reporting.html import render_html
from .safety.preflight import (StopFlag, Pacer, get_interrupt_flag,
                               resolve_modules, dry_run_plan,
                               plan_authz_matrix, plan_race,
                               plan_business, plan_second_order,
                               plan_second_order_ssrf)
from .safety.impact import max_level
from .safety.gate import ScopeRefused
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

    @staticmethod
    def _fp_suppression_reason(f, test_class, reviews) -> str:
        """Why this finding must skip plugin re-validation, or "".

        Finding-ID marks stick across runs via stable IDs; triple
        marks catch findings whose IDs rotate per run (swap findings
        embed victim values). Either suppresses — the probe already
        ran and a human ruled it out.
        """
        if reviews is None:
            return ""
        mark = reviews.verdict_for_finding(getattr(f, "id", ""))
        if mark and mark.get("verdict") == "false_positive":
            reason = mark.get("reason", "")
            return (f"operator-marked false positive ({f.id})"
                    + (f": {reason}" if reason else ""))
        from .reporting.reviews import finding_test_class
        cls = test_class or finding_test_class(f)
        url = normalize_url(getattr(f, "endpoint_url", "") or
                            getattr(f, "matched_at", "") or "")
        param = getattr(f, "parameter", "") or ""
        if cls and url and reviews.is_fp_triple(cls, url, param):
            from .reporting.reviews import (canonical_test_class,
                                            canonical_triple_url)
            return (f"operator-marked false positive "
                    f"({canonical_test_class(cls)} "
                    f"{canonical_triple_url(url)}::{param.strip().lower()})")
        return ""

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
    def _validate(self, findings: List[Finding],
                  endpoints: List[Endpoint], evidence: EvidenceStore,
                  metrics: Metrics, client, out_dir: Path,
                  budgets: BudgetTracker, coverage: CoverageTracker,
                  app_graph=None, ck=None) -> List[Finding]:
        out: List[Finding] = []
        # Operator review marks (reviews.jsonl): FP triples suppress
        # repeat prescreen probing; finding-ID marks link via triples.
        from .reporting.reviews import load_reviews, resolve_finding_triples
        reviews = load_reviews(out_dir / "reviews.jsonl")
        if len(reviews):
            linked = resolve_finding_triples(reviews, findings)
            log.info("reviews: %d mark(s), %d FP triple(s) (%d linked)",
                     len(reviews), len(reviews.triples), linked)
        controls = ProbeControls.from_orchestrator(self)

        # Open redirects are checked only during an explicitly enabled
        # validation run, never merely because OAST/differential was selected.
        if ((self.profile.run_validation or self.cfg.validation.enabled)
                and self.cfg.validation.open_redirect):
            from .validation.open_redirect import probe_open_redirects
            out += probe_open_redirects(
                endpoints, client, evidence, metrics, coverage, self.scope,
                max_endpoints=self.cfg.validation.open_redirect_max_endpoints,
                max_params=self.cfg.validation.open_redirect_max_params,
                timeout=self.cfg.scan.http_timeout)

        # GraphQL introspection exposure (schema disclosure inventory).
        if (self.profile.run_validation or self.cfg.validation.enabled):
            out += graphql_introspection_probe(
                endpoints, evidence, metrics, budgets, coverage, client,
                self.cfg, self.scope, controls)

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

        # CORS needs an explicitly configured cookie-authenticated identity;
        # anonymous header reflection is not treated as a bounty finding.
        if ((self.profile.run_validation or self.cfg.validation.enabled)
                and self.cfg.validation.cors):
            from .validation.cors import probe_cors
            cors_findings = probe_cors(
                endpoints, client, evidence, metrics, coverage, self.scope,
                identities,
                max_endpoints=self.cfg.validation.cors_max_endpoints,
                max_identities=self.cfg.validation.cors_max_identities,
                timeout=self.cfg.scan.http_timeout)
            if self.cfg.validation.cors_browser:
                from .validation.cors_browser import confirm_cors_readability
                identities_by_name = {item.name: item for item in identities}
                for finding in cors_findings:
                    if not budgets.consume_test(
                            "browser", finding.endpoint_url, limit=1):
                        finding.raw["browser_confirmation"] = {
                            "status": "blocked",
                            "reason": "browser action budget exhausted"}
                        continue
                    identity = identities_by_name.get(finding.identity)
                    if identity is None:
                        result = {
                            "status": "unavailable",
                            "reason": "candidate identity is unavailable"}
                    else:
                        result = confirm_cors_readability(
                            finding, identity, self.cfg,
                            timeout_ms=self.cfg.browser.navigation_timeout_ms)
                    finding.raw["browser_confirmation"] = result
                    if result.get("status") != "confirmed":
                        continue
                    finding.validation_status = ValidationStatus.CONFIRMED.value
                    finding.confidence = Confidence.CONFIRMED.value
                    finding.tags.append("cors-browser-readable")
                    finding.description += (
                        " Chromium confirmed that a cross-origin page could "
                        "read the successful response while the configured "
                        "cookie was sent. The response body was not retained.")
                    evidence.record(
                        finding,
                        request_text=(
                            f"GET {finding.endpoint_url}\n"
                            f"Origin: {result.get('origin', finding.raw.get('origin', ''))}\n"
                            f"[browser identity: {finding.identity}; cookie value omitted]\n"),
                        response_text=(
                            f"Chromium fetch status: "
                            f"{result.get('response_status')}\n"
                            f"[body readable; {result.get('response_length')} "
                            "characters; body omitted]\n"),
                        response_headers=finding.response_headers)
                    metrics.validated_confirmed += 1
                    coverage.record(
                        "cors", "confirmed",
                        "Chromium read a successful cross-origin response "
                        "with the configured cookie present")
            out += cors_findings

        # 1) differential auth-context testing (spec §2)
        if (self.profile.differential or self.cfg.validation.differential):
            diff = DifferentialTester(self.cfg, client)
            out += differential_probe(endpoints, diff, evidence,
                                      metrics, budgets, coverage,
                                      self.cfg, self.scope, controls)

        # 1b) MFA session transitions (pre- vs post-MFA test sessions)
        if (self.profile.differential or self.cfg.validation.differential
                or self.profile.authz_matrix
                or self.cfg.authorization.enabled):
            out += mfa_transition_probe(
                endpoints, evidence, metrics, budgets, coverage, client,
                self.cfg, self.scope, controls, identities)

        # 1b) web-cache deception (unique keys, read-only) ─────────
        if ((self.profile.run_validation or self.cfg.validation.enabled)
                and self.cfg.validation.cache):
            out += cache_probe(endpoints, evidence, metrics,
                                 budgets, coverage, client, self.cfg,
                                 self.scope, controls, identities)

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
                out += oast_sweep(endpoints, oast_provider,
                                    evidence, metrics, client, out_dir,
                                    budgets, coverage, self.cfg,
                                    self.scope, controls)

            # 2b) OAuth transitions (passive analysis + bounded probes)
            if (self.profile.differential
                    or self.cfg.validation.differential
                    or self.profile.authz_matrix
                    or self.cfg.authorization.enabled):
                out += oauth_probe(
                    endpoints, out_dir, evidence, metrics, budgets,
                    coverage, client, self.cfg, self.scope, controls,
                    identities, oast_provider)

            # 2c) lead-independent prescreen sweep: endpoints x params
            # feed the mutation prescreens directly so findings do not
            # depend on Nuclei leads; hits re-enter the plugin loop below
            if ((self.profile.run_validation
                    or self.cfg.validation.enabled)
                    and self.cfg.validation.mutation):
                findings += prescreen_sweep(
                    endpoints, findings, evidence, metrics, budgets,
                    coverage, client, self.cfg, self.scope, controls,
                    self._active_waf, reviews)

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
                test_class = classify_finding(f)
                suppressed = self._fp_suppression_reason(
                    f, test_class, reviews)
                if suppressed:
                    coverage.mark_untestable(test_class, suppressed)
                    log.info("plugins: skipping %s (%s)", f.id,
                             suppressed)
                    continue
                ep = finding_endpoint(f, by_norm)
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
                    apply_plugin_results(
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
            log.info("authz-matrix: no privileged/identifier endpoints "
                     "discovered — nothing to test")
            return []
        log.info("authz-matrix: %d endpoints × %s as %d identities",
                 len(targets), cfg_a.methods,
                 len(identities))
        write_replays = 0
        write_gated = bool(getattr(cfg_a, "write_replay", False)) and \
            bool(getattr(getattr(self.cfg, "safety", None),
                         "allow_state_change", False))
        if write_gated:
            write_replays = (len(targets) *
                             cfg_a.max_ids_per_endpoint *
                             max(0, len(identities) - 1))
        graphql_replays = (len(targets) * cfg_a.max_ids_per_endpoint *
                           max(0, len(identities) - 1))
        if not reserve_or_block(
                budgets, coverage, "authz",
                plan_authz_matrix(len(targets), len(identities),
                                  len(cfg_a.methods),
                                  cfg_a.max_ids_per_endpoint,
                                  write_replays, graphql_replays)):
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
                    # a denial/difference is a genuine negative. Edge or
                    # bot-wall answers never reached the app, so they stay
                    # inconclusive instead.
                    if getattr(sw, "edge_denied", False):
                        coverage.record(
                            "tenant_isolation" if cross_tenant else "bola",
                            "inconclusive",
                            f"{ep.normalized_url}::{sw.param}: "
                            f"{sw.tester} hit edge infrastructure")
                        continue
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
            # — MTN-pattern write replay (opt-in): attacker's observed
            # mutating shape with the victim's ID, verified via readback —
            if write_gated and self.scope.active_test_allowed(ep.url):
                self._paced()
                try:
                    findings.extend(self._authz_write_replay(
                        ep, pool, identities, owner_headers, evidence,
                        metrics, coverage, client, ep_params))
                except BudgetExceeded:
                    coverage.record("authz", "blocked",
                                    f"budget: {ep.normalized_url}")
                    continue
        # ── operation-aware GraphQL replay (read side; mutations are
        # never replayed) over endpoints with observed query operations
        try:
            findings.extend(self._authz_graphql_probe(
                endpoints, pool, identities, owner_headers, evidence,
                metrics, coverage, client, matrix))
        except BudgetExceeded:
            coverage.record("authz", "blocked", "graphql replay budget")
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

    # ── BOLA WRITE REPLAY (MTN pattern, opt-in) ──────────────────────
    def _authz_write_replay(self, ep, pool, identities, owner_headers,
                            evidence, metrics, coverage, client,
                            ep_params) -> List[Finding]:
        """Replay attacker shapes with victim IDs; readback decides."""
        from .authorization.write_replay import replay_writes
        cfg_a = self.cfg.authorization
        findings: List[Finding] = []
        for tester in identities or []:
            tester_name = getattr(tester, "name", "anonymous")
            victims = [h for h in pool
                       if getattr(h, "param", "") in (ep_params or set())
                       and getattr(h, "source", "response") == "response"
                       and getattr(h, "owner", "") not in ("", tester_name)]
            if not victims:
                continue
            results = replay_writes(
                client, ep, victims, tester, owner_headers,
                timeout=self.cfg.scan.http_timeout,
                max_ids=cfg_a.max_ids_per_endpoint, scope=self.scope)
            for res in results:
                if res.verdict not in ("strong_candidate", "confirmed"):
                    if getattr(res, "edge_denied", False):
                        coverage.record(
                            "bola", "inconclusive",
                            f"{ep.normalized_url}::{res.param}: "
                            f"{tester_name} hit edge infrastructure")
                        continue
                    # completed denial with a finished request is a
                    # genuine negative (same precondition rule as swaps);
                    # timeouts and 5xx stay unrecorded, never negative
                    if 400 <= res.status < 500:
                        coverage.record(
                            "bola", "tested_negative",
                            f"{ep.normalized_url}::{res.param}: "
                            f"{tester_name}→{res.status}")
                    continue
                metrics.authorization_tests += 1
                metrics.authorization_confirmed += 1
                self._note_candidate()
                cross_tenant = bool(
                    res.tester_tenant and res.owner_tenant and
                    res.tester_tenant != res.owner_tenant)
                cls = ("tenant_isolation" if cross_tenant else "bola")
                if res.verdict == "confirmed":
                    coverage.record(cls, "confirmed", res.notes)
                    status = ValidationStatus.CONFIRMED.value
                    conf = Confidence.CONFIRMED.value
                    extra = ["verified-effect"]
                    suffix = " [verified effect]"
                else:
                    coverage.record(cls, "candidate", res.notes)
                    coverage.record("idor", "candidate", res.notes)
                    status = ValidationStatus.STRONG_CANDIDATE.value
                    conf = Confidence.PROBABLE.value
                    extra = []
                    suffix = ""
                f = Finding(
                    id=stable_finding_id("bolawrite", res.endpoint_url,
                                         res.method, res.param,
                                         res.victim_value),
                    source="bola-write",
                    name=(f"BOLA write: '{res.tester}' modifies "
                          f"'{res.owner}''s '{res.param}="
                          f"{res.victim_value}' ({ep.path})" + suffix),
                    severity="high",
                    confidence=conf,
                    validation_status=status,
                    host=ep.host, matched_at=res.endpoint_url,
                    endpoint_url=res.endpoint_url, method=res.method,
                    parameter=res.param,
                    description=res.notes,
                    tags=["bola", "idor", "authz",
                          "tenant-isolation" if cross_tenant else
                          "cross-user", ep.endpoint_type] + extra,
                    raw={"write_replay": res.to_dict()},
                    false_positive_notes=(
                        "Victim ID harvested from the owner's own session; "
                        "the attacker's own observed mutating request was "
                        "replayed with only the identifier swapped. "
                        "Confirmation requires a clean readback showing "
                        "the attacker's values newly persisted — confirm "
                        "interactively before reporting."),
                    identity=res.tester, tenant=res.tester_tenant,
                    resource_key=(f"{ep.normalized_url}::{res.param}"
                                  f"={res.victim_value}"),
                )
                evidence.allocate(f)
                evidence.record(
                    f,
                    request_text=(f"{res.method} {res.endpoint_url}\n(as "
                                  f"{res.tester}; owner: {res.owner}; "
                                  f"readback: {res.readback})"),
                    response_text=res.notes)
                findings.append(f)
                log.info("authz-write-replay: %s", res.notes)
        return findings

    # ── GRAPHQL OPERATION REPLAY (read side, query ops only) ────────
    def _authz_graphql_probe(self, endpoints, pool, identities,
                             owner_headers, evidence, metrics, coverage,
                             client, matrix) -> List[Finding]:
        """Replay observed query operations with victim variables."""
        from .authorization.graphql_replay import replay_operations
        from .validation.graphql import (is_mutation_operation,
                                         parse_graphql_body)
        cfg_a = self.cfg.authorization
        findings: List[Finding] = []
        gql_targets = []
        for ep in endpoints or []:
            if len(gql_targets) >= cfg_a.max_endpoints:
                break
            if not self.scope.active_test_allowed(ep.url):
                continue
            for shape in list(getattr(ep, "observed_requests", [])
                              or []):
                if not isinstance(shape, dict):
                    continue
                if str(shape.get("method") or "").upper() != "POST":
                    continue
                parsed = parse_graphql_body(shape.get("post_data"))
                if parsed is None or is_mutation_operation(
                        parsed["query"]):
                    continue
                gql_targets.append(ep)
                break
        if not gql_targets:
            log.info("authz-graphql: no observed GraphQL query operations "
                     "— nothing to replay")
        for ep in gql_targets:
            if self._halted():
                log.info("authz-graphql: halted by stop control")
                break
            self._paced()
            for tester in identities or []:
                tester_name = getattr(tester, "name", "anonymous")
                victims = [h for h in pool
                           if getattr(h, "source", "response") == "response"
                           and getattr(h, "owner", "") not in
                           ("", tester_name)]
                if not victims:
                    continue
                try:
                    results = replay_operations(
                        client, ep, victims, tester, owner_headers,
                        timeout=self.cfg.scan.http_timeout,
                        max_ids=cfg_a.max_ids_per_endpoint,
                        scope=self.scope, matrix=matrix,
                        ownership_fields=list(
                            cfg_a.ownership_fields or []))
                except BudgetExceeded:
                    coverage.record("authz", "blocked",
                                    f"budget: {ep.normalized_url}")
                    break
                for res in results:
                    metrics.authorization_tests += 1
                    cross_tenant = bool(
                        res.tester_tenant and res.owner_tenant and
                        res.tester_tenant != res.owner_tenant)
                    if getattr(res, "edge_denied", False):
                        coverage.record(
                            "tenant_isolation" if cross_tenant
                            else "bola", "inconclusive",
                            f"{ep.normalized_url}::{res.variable}: "
                            f"{tester_name} hit edge infrastructure")
                        continue
                    if res.verdict != "strong_candidate":
                        if 400 <= res.status < 500 or res.status == 200:
                            coverage.record(
                                "tenant_isolation" if cross_tenant
                                else "bola", "tested_negative",
                                f"{ep.normalized_url}::{res.variable}: "
                                f"{tester_name}→{res.status}")
                        continue
                    metrics.authorization_confirmed += 1
                    self._note_candidate()
                    cls = ("tenant_isolation" if cross_tenant else "bola")
                    coverage.record(cls, "candidate", res.notes)
                    coverage.record("idor", "candidate", res.notes)
                    kind_label = "Cross-tenant GraphQL read" \
                        if cross_tenant else "GraphQL BOLA"
                    f = Finding(
                        id=stable_finding_id(
                            "graphql", res.endpoint_url, res.operation,
                            res.variable, res.victim_value),
                        source="graphql-bola",
                        name=(f"{kind_label}: "
                              f"'{res.tester}' reads '{res.owner}''s "
                              f"'{res.variable}={res.victim_value}' "
                              f"({ep.path})"),
                        severity="high",
                        confidence=Confidence.PROBABLE.value,
                        validation_status=ValidationStatus.
                        STRONG_CANDIDATE.value,
                        host=ep.host, matched_at=res.endpoint_url,
                        endpoint_url=res.endpoint_url, method="POST",
                        parameter=res.variable,
                        description=res.notes,
                        tags=["bola", "idor", "authz", "graphql",
                              "tenant-isolation" if cross_tenant else
                              "cross-user", ep.endpoint_type],
                        raw={"graphql": res.to_dict()},
                        false_positive_notes=(
                            "Victim variable harvested from the owner's own "
                            "session; the same observed operation document "
                            "replayed with only that variable swapped. "
                            "Mutation operations are never replayed. "
                            "Confirm interactively before reporting."),
                        identity=res.tester, tenant=res.tester_tenant,
                        resource_key=(f"{ep.normalized_url}::"
                                      f"{res.variable}={res.victim_value}"),
                    )
                    evidence.allocate(f)
                    evidence.record(
                        f,
                        request_text=(f"POST {res.endpoint_url}\n"
                                      f"operation {res.operation}\n(as "
                                      f"{res.tester}; owner: {res.owner})"),
                        response_text=res.notes)
                    findings.append(f)
                    log.info("authz-graphql: %s", res.notes)
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
        if not reserve_or_block(
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
            for trigger_ep, score, rationale in rank_ssrf_triggers(
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
        if not reserve_or_block(
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
            json_body = nested_parameter_object(data)
            request_url = ep.url
            if location == "body":
                data[parameter.name] = callback_url
                assign_nested(json_body, parameter.name, callback_url)
            elif location == "query":
                request_url = append_query_parameter(
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
            except ScopeRefused as exc:
                # Gate denial (a BudgetExceeded subclass): the injection
                # never ran — blocked, never incomplete/negative.
                coverage.record("second_order_ssrf", "blocked",
                                f"scope-gate {exc.reason}: "
                                f"{ep.normalized_url}::{parameter.name}")
                budget_blocked = True
                continue
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
            trigger_urls = materialize_trigger_urls(
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
        # token reflection in trigger bodies is a non-upgrading readback
        # signal: it shows processed content came back, not just a fetch
        trigger_reflects: Dict[str, bool] = {}
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
                else:
                    try:
                        text = response.text or ""
                    except Exception:
                        text = ""
                    keys = [item["callback_key"] for item in submitted
                            if item["callback_key"] and
                            item["callback_key"] in text]
                    if keys:
                        trigger_reflects[trigger_url] = True
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
                        "itself prove access to internal resources."
                        + (" One or more trigger responses reflect the "
                           "callback token (possible processed-content "
                           "readback: confirm manually)."
                           if any(trigger_reflects.get(url)
                                  for url in item["trigger_urls"]) else "")),
                    tags=["ssrf", "second-order", "oast",
                          ep.endpoint_type],
                    raw={"callback_host": item["callback_host"],
                         "callback_url": item["callback_url"],
                         "trigger_urls": item["trigger_urls"],
                         "trigger_reflects_token": sorted(
                             url for url in item["trigger_urls"]
                             if trigger_reflects.get(url)),
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
                        interaction_line(it) for it in matched[:10]))
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
        if not reserve_or_block(
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
        if not reserve_or_block(
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
