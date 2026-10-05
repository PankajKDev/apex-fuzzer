"""AI loop closure: hypotheses feed back into deterministic testing."""
from pathlib import Path
from typing import Dict, List, Optional

from ..ai.planner import AIPlanner
from ..detection.nuclei import (NucleiRunner, run_hypothesis_templates)
from ..logging_setup import get_logger
from ..models import (Confidence, Endpoint, Finding, Hypothesis,
                      ValidationStatus, stable_finding_id)
from ..reporting.metrics import Metrics
from ..validation.evidence import EvidenceStore
from ..shell import which
from ..validation.base import Candidate
from ..validation.mutate import MutationEngine
from ..validation.oast import probe_endpoint
from ..validation.ssrf import endpoint_from_url
from ..validation.sqli import SqliValidator
from ..validation.xss import XssValidator
from ..discovery.javascript import chunk_js
from ..discovery.url_normalizer import normalize_url
from ..models import read_jsonl

log = get_logger("stages-ai")


def plan_js_chunks(planner: AIPlanner, out_dir: Path,
                   cfg) -> List[Hypothesis]:
    """Feed structurally-chunked JS to the planner and merge."""
    budget = cfg.ai.js_chunk_budget
    if budget <= 0:
        return []
    entries = read_jsonl(out_dir / "js_analysis.jsonl")
    # largest bundles first — that's where the routes hide
    entries.sort(key=lambda e: -int(e.get("raw_length") or 0))
    out: List[Hypothesis] = []
    seen: set = set()
    for entry in entries:
        text = (out_dir / "cache").exists() and \
            cached_js_text(out_dir, entry.get("url", ""))
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


def cached_js_text(out_dir: Path, url: str) -> str:
    import re as _re
    key = _re.sub(r"[^A-Za-z0-9_.-]", "_", url or "")[:180]
    p = out_dir / "cache" / key
    if p.exists():
        return p.read_text(errors="ignore")
    return ""


def validate_hypotheses(hypotheses: List[Hypothesis],
                        endpoints: List[Endpoint],
                        evidence: EvidenceStore, metrics: Metrics,
                        client, nuclei: NucleiRunner,
                        live_file: Path, cfg, scope, profile,
                        waf_hint=None) -> List[Finding]:
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
        items = items[:cfg.ai.max_hypothesis_tests]
        for h in items:
            try:
                route_hypothesis(
                    h, find_ep(h.endpoint), by_norm, evidence,
                    client, new_findings, nuclei, live_file,
                    cfg, scope, waf_hint)
            except Exception as e:
                log.warning("hypothesis test failed (%s): %s",
                            h.test_class, e)
                h.notes = f"test error: {e}"[:200]

    # classes with no dedicated validator (ssti, traversal, xxe, ...)
    # become Nuclei gate templates (spec §5c)
    new_findings += gate_remaining_hypotheses(
        hypotheses, evidence, nuclei, live_file, cfg, profile, scope)
    metrics.hypotheses_validated = sum(
        1 for h in hypotheses if h.status == "validated")
    if metrics.hypotheses_validated:
        log.info("ai loop closure: %d hypotheses validated",
                 metrics.hypotheses_validated)
    return new_findings


def gate_remaining_hypotheses(hypotheses: List[Hypothesis],
                              evidence: EvidenceStore,
                              nuclei: NucleiRunner,
                              live_file: Path, cfg, profile,
                              scope) -> List[Finding]:
    """Run AI-generated Nuclei gates for hypotheses no deterministic
    validator claimed. A gate hit promotes the hypothesis to
    validated (still requiring manual confirmation — gates check
    predicted response behaviour, they don't exploit)."""
    if not getattr(cfg.nuclei, "ai_templates", True):
        return []
    if not profile.run_nuclei or not live_file.exists():
        return []
    pending = [h for h in hypotheses
               if h.status == "hypothesized" and h.endpoint
               and str(h.endpoint).startswith("http")
               and scope.is_in_scope(str(h.endpoint))]
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


def route_hypothesis(h: Hypothesis, ep: Optional[Endpoint],
                     by_norm: Dict[str, Endpoint],
                     evidence: EvidenceStore, client,
                     new_findings: List[Finding],
                     nuclei: NucleiRunner, live_file: Path,
                     cfg, scope, waf_hint=None):
    url = h.endpoint
    cls = h.test_class.lower()
    if url and not scope.active_test_allowed(url):
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
        provider = hypothesis_oast(cfg)
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
                poll_timeout=cfg.oast.poll_timeout,
                poll_interval=cfg.oast.poll_interval,
                max_params=cfg.oast.max_params_per_endpoint)
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
        if cfg.validation.mutation:
            engine = MutationEngine(cfg, client, waf_hint)
            outcome = engine.prescreen_sqli(candidate)
        if outcome is None and which("sqlmap"):
            outcome = SqliValidator(cfg).validate(candidate)
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
        if cfg.validation.mutation:
            engine = MutationEngine(cfg, client, waf_hint)
            outcome = engine.prescreen_xss(candidate)
        if outcome is None and which("dalfox"):
            outcome = XssValidator(cfg).validate(candidate)
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
        from ..validation.differential import DifferentialTester
        diff = DifferentialTester(cfg, client)
        etype = ep.endpoint_type if ep else "unknown"
        res = diff.probe(url, etype,
                         timeout=cfg.scan.http_timeout)
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


def hypothesis_oast(cfg):
    """OAST provider for AI-hypothesized SSRF (registered on demand)."""
    from ..validation.oast import InteractshProvider
    if not cfg.oast.enabled:
        return None
    provider = InteractshProvider(
        server=cfg.oast.server, api_base=cfg.oast.api_base,
        timeout=cfg.scan.http_timeout,
        callback_url=cfg.oast.callback_url)
    return provider if provider.register() else None
