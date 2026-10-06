"""Validation coordinator: runs every enabled probe in order.

Owns stage sequencing, review marks, the OAST provider lifecycle, and
the per-finding plugin loop. Returns a ValidationResult carrying the
combined findings plus run state the coordinator persists
(WAF hint, harvest pool, authz matrix).
"""
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from ...budgets import BudgetTracker
from ...logging_setup import get_logger
from ...models import (Confidence, Endpoint, Finding, ValidationStatus)
from ...plugins import adapters as _plugin_adapters  # noqa (registry)
from ...plugins.adapters import PLUGIN_ORDER
from ...plugins.base import (TestTarget, TestContext, run_plugins)
from ...reporting.coverage import CoverageTracker, classify_finding
from ...validation.evidence import EvidenceStore
from ...reporting.metrics import Metrics
from ...reporting.reviews import (fp_suppression_reason, load_reviews,
                                  resolve_finding_triples)
from ...validation.cors import probe_cors
from ...validation.differential import DifferentialTester
from ...validation.mutate import fingerprint_waf
from ...validation.open_redirect import probe_open_redirects
from . import ProbeControls
from .authz import authz_matrix_probe
from .business import business_logic_probe
from .cache import cache_probe
from .differential import differential_probe
from .identity import (jwt_confusion_probe, mfa_transition_probe,
                        oauth_probe, otp_bypass_probe, reset_probe)
from .introspection import graphql_introspection_probe
from .misconfig import (csrf_browser_probe, header_probe, hpp_probe,
                         html_injection_probe, info_disclosure_probe,
                         misconfig_probe)
from .postmessage import postmessage_probe
from .oast import maybe_register_oast, oast_sweep
from .plugins import apply_plugin_results, finding_endpoint
from .prescreen import deser_probe, prescreen_sweep
from .race import race_probe
from .second_order import (blind_xss_probe, second_order_generalized_probe,
                             second_order_probe,
                             second_order_ssrf_probe)
from .upload import upload_probe
from .websocket import websocket_probe

log = get_logger("stages-validation")


@dataclass
class ValidationResult:
    findings: List[Finding] = field(default_factory=list)
    active_waf: Optional[str] = None
    harvest_pool: list = field(default_factory=list)
    matrix: object = None


def run_validation(findings: List[Finding],
                   endpoints: List[Endpoint], evidence: EvidenceStore,
                   metrics: Metrics, client, out_dir: Path,
                   budgets: BudgetTracker, coverage: CoverageTracker,
                   cfg, scope, profile, controls: ProbeControls,
                   app_graph=None, ck=None) -> ValidationResult:
    out: List[Finding] = []
    # Operator review marks (reviews.jsonl): FP triples suppress
    # repeat prescreen probing; finding-ID marks link via triples.
    reviews = load_reviews(out_dir / "reviews.jsonl")
    if len(reviews):
        linked = resolve_finding_triples(reviews, findings)
        log.info("reviews: %d mark(s), %d FP triple(s) (%d linked)",
                 len(reviews), len(reviews.triples), linked)

    # Open redirects are checked only during an explicitly enabled
    # validation run, never merely because OAST/differential was selected.
    if ((profile.run_validation or cfg.validation.enabled)
            and cfg.validation.open_redirect):
        out += probe_open_redirects(
            endpoints, client, evidence, metrics, coverage, scope,
            max_endpoints=cfg.validation.open_redirect_max_endpoints,
            max_params=cfg.validation.open_redirect_max_params,
            timeout=cfg.scan.http_timeout)

    # GraphQL introspection exposure (schema disclosure inventory).
    if (profile.run_validation or cfg.validation.enabled):
        out += graphql_introspection_probe(
            endpoints, evidence, metrics, budgets, coverage, client,
            cfg, scope, controls)

    # Passive misconfiguration sweep (framing + form tokens).
    if (profile.run_validation or cfg.validation.enabled):
        out += misconfig_probe(
            endpoints, evidence, metrics, budgets, coverage, client,
            cfg, scope, controls)
        out += header_probe(
            endpoints, evidence, metrics, budgets, coverage, client,
            cfg, scope, controls)
        out += info_disclosure_probe(
            endpoints, evidence, metrics, budgets, coverage, client,
            cfg, scope, controls)
        out += hpp_probe(
            endpoints, evidence, metrics, budgets, coverage, client,
            cfg, scope, controls)
        out += html_injection_probe(
            endpoints, evidence, metrics, budgets, coverage, client,
            cfg, scope, controls)
        out += postmessage_probe(
            out_dir, evidence, coverage, cfg, controls)
        out += reset_probe(
            endpoints, evidence, metrics, budgets, coverage, client,
            cfg, scope, controls)
        out += otp_bypass_probe(
            endpoints, evidence, metrics, budgets, coverage, client,
            cfg, scope, controls)

    # 0) WAF fingerprint from a live probe (drives mutation choice)
    waf = metrics.waf_detected or ""
    if endpoints and not waf:
        try:
            r = client.get(endpoints[0].url,
                           timeout=cfg.scan.http_timeout)
            waf = fingerprint_waf(r.headers) or ""
            if waf:
                metrics.waf_detected = waf
        except Exception:
            pass
    active_waf = waf or None

    from ...application.identities import from_auth_contexts
    from ...models import read_jsonl
    techs = read_jsonl(out_dir / "technologies.jsonl")
    identities, _, _ = from_auth_contexts(cfg.auth.contexts)

    # CORS needs an explicitly configured cookie-authenticated identity;
    # anonymous header reflection is not treated as a bounty finding.
    if ((profile.run_validation or cfg.validation.enabled)
            and cfg.validation.cors):
        cors_findings = probe_cors(
            endpoints, client, evidence, metrics, coverage, scope,
            identities,
            max_endpoints=cfg.validation.cors_max_endpoints,
            max_identities=cfg.validation.cors_max_identities,
            timeout=cfg.scan.http_timeout)
        if cfg.validation.cors_browser:
            from ...validation.cors_browser import (
                confirm_cors_readability)
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
                        finding, identity, cfg,
                        timeout_ms=cfg.browser.navigation_timeout_ms)
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

    # WebSocket handshake layer (auth boundary + origin validation
    # over recorded ws addresses; no frames are spoken).
    if (profile.run_validation or cfg.validation.enabled):
        out += websocket_probe(
            out_dir, evidence, metrics, budgets, coverage, client,
            cfg, scope, controls, identities)

    # CSRF cross-site execution proof over this run's tokenless-form
    # findings (opt-in Chromium + state-change ack; needs a victim
    # session from the configured identities).
    if (profile.run_validation or cfg.validation.enabled):
        csrf_targets = [f for f in out
                        if f.source == "misconfig-csrf"]
        if csrf_targets:
            out += csrf_browser_probe(
                csrf_targets, evidence, metrics, budgets, coverage,
                client, cfg, scope, controls, identities)

    # 1) differential auth-context testing (spec §2)
    if (profile.differential or cfg.validation.differential):
        diff = DifferentialTester(cfg, client)
        out += differential_probe(endpoints, diff, evidence,
                                  metrics, budgets, coverage,
                                  cfg, scope, controls)
        out += jwt_confusion_probe(endpoints, evidence, metrics,
                                   budgets, coverage, client, cfg,
                                   scope, controls, identities)

    # 1b) MFA session transitions (pre- vs post-MFA test sessions)
    if (profile.differential or cfg.validation.differential
            or profile.authz_matrix
            or cfg.authorization.enabled):
        out += mfa_transition_probe(
            endpoints, evidence, metrics, budgets, coverage, client,
            cfg, scope, controls, identities)

    # 1b) web-cache deception (unique keys, read-only) ─────────
    if ((profile.run_validation or cfg.validation.enabled)
            and cfg.validation.cache):
        out += cache_probe(endpoints, evidence, metrics,
                           budgets, coverage, client, cfg,
                           scope, controls, identities)

    # 1b) authz matrix: harvest → swap → per-method sweep (#1–2)
    harvest_pool: list = []
    matrix = None
    if (profile.authz_matrix or cfg.authorization.enabled):
        matrix_out, matrix, pool = authz_matrix_probe(
            endpoints, evidence, metrics, budgets, coverage,
            client, out_dir, identities, cfg, scope,
            controls, app_graph=app_graph)
        out += matrix_out
        harvest_pool = pool

    # 2) OAST sweep for blind SSRF (spec §3)
    oast_provider = maybe_register_oast(cfg, profile)
    try:
        run_oast_sweep = (profile.oast
                          or cfg.validation.ssrf
                          or cfg.validation.enabled)
        if (run_oast_sweep and oast_provider and
                oast_provider.available()):
            out += oast_sweep(endpoints, oast_provider,
                              evidence, metrics, client, out_dir,
                              budgets, coverage, cfg,
                              scope, controls)

        # 2b) OAuth transitions (passive analysis + bounded probes)
        if (profile.differential
                or cfg.validation.differential
                or profile.authz_matrix
                or cfg.authorization.enabled):
            out += oauth_probe(
                endpoints, out_dir, evidence, metrics, budgets,
                coverage, client, cfg, scope, controls,
                identities, oast_provider)

        # 2c) lead-independent prescreen sweep: endpoints x params
        # feed the mutation prescreens directly so findings do not
        # depend on Nuclei leads; hits re-enter the plugin loop below
        if ((profile.run_validation
                or cfg.validation.enabled)
                and cfg.validation.mutation):
            findings += prescreen_sweep(
                endpoints, findings, evidence, metrics, budgets,
                coverage, client, cfg, scope, controls,
                active_waf, reviews)
            findings += deser_probe(
                endpoints, evidence, metrics, budgets,
                coverage, client, cfg, scope, controls)

        # 3) per-finding plugins (§48: registry + TestResult)
        test_ctx = TestContext(
            cfg, http=client, scope=scope,
            budgets=budgets, oast_provider=oast_provider,
            waf=active_waf, technologies=techs,
            identities=identities, evidence=evidence,
            timeout=cfg.scan.http_timeout,
            browser_enabled=(profile.browser or
                             cfg.browser.enabled))
        by_norm = {e.normalized_url: e for e in endpoints}
        for f in findings:
            test_class = classify_finding(f)
            suppressed = fp_suppression_reason(
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
                    controls.noted()
                elif f.validation_status == "strong_candidate":
                    controls.noted()
                elif f.validation_status == "false_positive":
                    metrics.false_positives += 1
            out.append(f)

        # 4) stored-XSS correlation (bounty item #3, opt-in: persists
        # canaries server-side)
        if (profile.second_order or
                cfg.validation.second_order):
            out += second_order_probe(
                endpoints, evidence, metrics, budgets, coverage,
                client, cfg, scope, controls, identities)
            out += second_order_generalized_probe(
                endpoints, evidence, metrics, budgets, coverage,
                client, cfg, scope, controls, identities)
            out += blind_xss_probe(
                endpoints, evidence, metrics, budgets, coverage,
                client, cfg, scope, controls, identities,
                oast_provider)
        if cfg.validation.second_order_ssrf:
            out += second_order_ssrf_probe(
                endpoints, evidence, metrics, budgets, coverage,
                client, cfg, scope, controls, identities,
                oast_provider)
        # 5) business-logic mutations (opt-in: submits abuse values)
        if (profile.business_logic or
                cfg.business.enabled):
            out += business_logic_probe(
                endpoints, evidence, metrics, budgets, coverage,
                client, cfg, scope, controls, identities)
        # 6) race engine (opt-in: synchronized bursts of
        # state-changing requests)
        if (profile.race or cfg.race.enabled):
            out += race_probe(
                endpoints, evidence, metrics, budgets, coverage,
                client, cfg, scope, controls, identities)
        # 7) file-upload review (opt-in: persists benign files)
        if cfg.validation.upload:
            out += upload_probe(
                endpoints, evidence, metrics, budgets, coverage,
                client, cfg, scope, controls)
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
    return ValidationResult(findings=out, active_waf=active_waf,
                            harvest_pool=harvest_pool, matrix=matrix)
