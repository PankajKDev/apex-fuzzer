"""Web-cache deception probe (unique keys, read-only)."""
from typing import List

from ...budgets import BudgetExceeded, BudgetTracker
from ...logging_setup import get_logger
from ...models import (Confidence, Endpoint, Finding, ValidationStatus,
                       stable_finding_id)
from ...reporting.coverage import CoverageTracker
from ...validation.evidence import EvidenceStore
from ...reporting.metrics import Metrics
from ...safety.preflight import plan_cache
from ...validation.cache import probe_deception
from ...validation.differential import PRIVILEGED_TYPES, has_idor_params
from . import ProbeControls, reserve_or_block

log = get_logger("stages-validation")


def cache_probe(endpoints: List[Endpoint],
                evidence: EvidenceStore, metrics: Metrics,
                budgets: BudgetTracker,
                coverage: CoverageTracker, client, cfg, scope,
                controls: ProbeControls,
                identities) -> List[Finding]:
    """Detect personalized bodies served from cache to anonymous."""
    cfg_v = cfg.validation
    victims = [i for i in identities or []
               if getattr(i, "name", "") != "anonymous"
               and dict(getattr(i, "auth_headers", None) or {})]
    if not victims:
        log.info("cache: no authenticated test session configured — "
                 "nothing to compare")
        return []
    targets = [e for e in endpoints
               if (getattr(e, "method", "GET") or "GET").upper()
               == "GET"
               and (e.endpoint_type in PRIVILEGED_TYPES
                    or (has_idor_params(e)
                        and e.endpoint_type != "static"))]
    targets = targets[:max(0, cfg_v.cache_max_endpoints)]
    if not targets:
        log.info("cache: no cacheable privileged endpoints "
                 "discovered — nothing to probe")
        return []
    log.info("cache: probing %d endpoints", len(targets))
    if not reserve_or_block(
            budgets, coverage, "cache", plan_cache(len(targets))):
        return []
    findings: List[Finding] = []
    victim = victims[0]
    victim_headers = dict(getattr(victim, "auth_headers", None) or {})
    victim_name = getattr(victim, "name", "tester")
    for ep in targets:
        if controls.halted():
            log.info("cache: halted by stop control")
            break
        if not scope.active_test_allowed(ep.url):
            continue
        controls.paced()
        try:
            res = probe_deception(
                client, ep.url, victim_headers, victim_name,
                timeout=cfg.scan.http_timeout)
        except BudgetExceeded:
            coverage.record("cache", "blocked",
                            f"budget: {ep.normalized_url}")
            continue
        if res.verdict == "confirmed":
            metrics.validated_confirmed += 1
            controls.noted()
            coverage.record("cache", "confirmed", res.notes)
            f = Finding(
                id=stable_finding_id("cache", ep.normalized_url,
                                     victim_name),
                source="cache-deception",
                name=(f"Web-cache deception: anonymous reads "
                      f"'{victim_name}''s cached response ({ep.path})"),
                severity="high",
                confidence=Confidence.CONFIRMED.value,
                validation_status=ValidationStatus.CONFIRMED.value,
                host=ep.host, matched_at=ep.url,
                endpoint_url=ep.url, method="GET",
                description=res.notes + " Every probe used a unique "
                                "cache key; no shared entry was written.",
                tags=["cache", "cache-deception", "authz",
                      ep.endpoint_type, "verified-effect"],
                raw={"cache": res.to_dict()},
                false_positive_notes=(
                    "Anonymous baseline, victim fetch, and anonymous "
                    "re-read all completed; the re-read carried a "
                    "cache HIT for the victim body. Confirm the cached "
                    "content is actually sensitive before reporting."),
                identity=victim_name,
            )
            evidence.allocate(f)
            evidence.record(
                f,
                request_text=(f"GET {res.cache_key_url}\n(as "
                              f"{victim_name}, then anonymous)"),
                response_text=res.notes)
            findings.append(f)
            log.info("cache: %s", res.notes)
        elif res.verdict == "tested_negative":
            coverage.record("cache", "tested_negative",
                            f"{ep.normalized_url}: {res.notes}")
        else:
            coverage.record("cache", "inconclusive",
                            f"{ep.normalized_url}: {res.notes}")
    return findings
