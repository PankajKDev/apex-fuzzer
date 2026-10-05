"""Identity-transition probes: MFA sessions and OAuth flows."""
from typing import List
from urllib.parse import urlsplit

from ...budgets import BudgetExceeded, BudgetTracker
from ...logging_setup import get_logger
from ...models import (Confidence, Endpoint, Finding, ValidationStatus,
                       stable_finding_id)
from ...reporting.coverage import CoverageTracker
from ...validation.evidence import EvidenceStore
from ...reporting.metrics import Metrics
from ...safety.preflight import plan_differential
from ...validation.differential import PRIVILEGED_TYPES, has_idor_params
from . import ProbeControls, reserve_or_block

log = get_logger("stages-validation")


def mfa_transition_probe(endpoints: List[Endpoint],
                         evidence: EvidenceStore, metrics: Metrics,
                         budgets: BudgetTracker,
                         coverage: CoverageTracker, client, cfg, scope,
                         controls: ProbeControls,
                         identities) -> List[Finding]:
    """Compare privileged URLs under pre- vs post-MFA test sessions."""
    from ...auth.mfa_checks import check_transition
    pending_names = {c.name for c in cfg.auth.contexts
                     if getattr(c, "mfa_pending", False)}
    pres = [i for i in identities or []
            if getattr(i, "name", "") in pending_names
            and dict(getattr(i, "auth_headers", None) or {})]
    fulls = [i for i in identities or []
             if getattr(i, "name", "") not in pending_names
             and getattr(i, "name", "") != "anonymous"
             and dict(getattr(i, "auth_headers", None) or {})]
    if not pres or not fulls:
        log.info("mfa-transition: needs one mfa_pending and one "
                 "completed test session — skipping")
        return []
    targets = [e for e in endpoints
               if e.endpoint_type in PRIVILEGED_TYPES
               or (has_idor_params(e)
                   and e.endpoint_type != "static")][:10]
    if not targets:
        log.info("mfa-transition: no privileged endpoints "
                 "discovered — nothing to compare")
        return []
    log.info("mfa-transition: %d endpoints (%s vs %s)",
             len(targets), pres[0].name, fulls[0].name)
    if not reserve_or_block(
            budgets, coverage, "mfa",
            plan_differential(len(targets), 2)):
        return []
    findings: List[Finding] = []
    pre, post = pres[0], fulls[0]
    pre_headers = dict(getattr(pre, "auth_headers", None) or {})
    post_headers = dict(getattr(post, "auth_headers", None) or {})
    for ep in targets:
        if controls.halted():
            log.info("mfa-transition: halted by stop control")
            break
        if not scope.active_test_allowed(ep.url):
            continue
        try:
            res = check_transition(
                client, ep.url, pre_headers, post_headers,
                getattr(pre, "name", "pre"),
                getattr(post, "name", "post"),
                timeout=cfg.scan.http_timeout)
        except BudgetExceeded:
            coverage.record("mfa", "blocked",
                            f"budget: {ep.normalized_url}")
            continue
        metrics.authorization_tests += 1
        if res.verdict == "strong_candidate":
            metrics.authorization_confirmed += 1
            controls.noted()
            coverage.record("mfa", "candidate", res.notes)
            f = Finding(
                id=stable_finding_id("mfa", ep.normalized_url,
                                     pre.name, post.name),
                source="mfa-transition",
                name=(f"MFA bypass: pre-MFA session '{pre.name}' "
                      f"reaches privileged resource ({ep.path})"),
                severity="high",
                confidence=Confidence.PROBABLE.value,
                validation_status=ValidationStatus.
                STRONG_CANDIDATE.value,
                host=ep.host, matched_at=ep.url,
                endpoint_url=ep.url, method="GET",
                description=res.notes,
                tags=["mfa", "authz", "session", ep.endpoint_type],
                raw={"transition": res.to_dict()},
                false_positive_notes=(
                    "Both sessions are operator-supplied test sessions; "
                    "the pre-MFA response is shape-compared against the "
                    "post-MFA response, so shared login pages cannot "
                    "confirm. Confirm interactively before reporting."),
                identity=pre.name,
                tenant=getattr(pre, "tenant", "") or "",
            )
            evidence.allocate(f)
            evidence.record(
                f,
                request_text=(f"GET {ep.url}\n(pre-MFA: {pre.name}; "
                              f"post-MFA: {post.name})"),
                response_text=res.notes)
            findings.append(f)
            log.info("mfa-transition: %s", res.notes)
        elif res.verdict == "tested_negative":
            coverage.record("mfa", "tested_negative",
                            f"{ep.normalized_url}: {res.notes}")
        else:
            coverage.record("mfa", "inconclusive",
                            f"{ep.normalized_url}: {res.notes}")
    return findings


def oauth_probe(endpoints: List[Endpoint], out_dir, evidence: EvidenceStore,
                metrics: Metrics, budgets: BudgetTracker,
                coverage: CoverageTracker, client, cfg, scope,
                controls: ProbeControls, identities,
                oast_provider=None) -> List[Finding]:
    """Passive authorize-URL analysis plus bounded active probes."""
    from ...auth.oauth_checks import (find_authorize_urls,
                                      check_pkce_strip,
                                      check_redirect_oast)
    findings: List[Finding] = []
    seen_urls: List[str] = []
    traffic_file = out_dir / "browser_traffic.json"
    if traffic_file.exists():
        try:
            import json as _json
            data = _json.loads(traffic_file.read_text(
                errors="ignore") or "{}")
            for req in data.get("requests", []) or []:
                url = req.get("url", "") if isinstance(req, dict) \
                    else ""
                if url:
                    seen_urls.append(url)
        except Exception as exc:
            log.debug("oauth traffic read failed: %s", exc)
    for ep in endpoints or []:
        if getattr(ep, "method", "GET").upper() == "GET" and ep.url:
            seen_urls.append(ep.url)
    authz_urls = find_authorize_urls(seen_urls, source="traffic")[:5]
    if not authz_urls:
        log.info("oauth: no authorize URLs observed in traffic or "
                 "endpoints — nothing to check")
        return []
    allow_state = bool(getattr(getattr(cfg, "safety", None),
                               "allow_state_change", False))
    testers = [i for i in identities or []
               if getattr(i, "name", "") != "anonymous"
               and dict(getattr(i, "auth_headers", None) or {})]
    active_urls = [a for a in authz_urls
                   if scope.active_test_allowed(a.url)]
    if testers and active_urls and not reserve_or_block(
            budgets, coverage, "oauth",
            plan_differential(len(active_urls), 2)):
        return findings
    for authz in authz_urls:
        try:
            host = urlsplit(authz.url).hostname or ""
        except (TypeError, ValueError):
            continue
        if not authz.has_state:
            coverage.record("oauth", "candidate",
                            f"{authz.url[:120]}: missing state")
            findings.append(Finding(
                id=stable_finding_id("oauth", "nostate", authz.url),
                source="oauth-passive",
                name="OAuth login without state parameter",
                severity="medium",
                confidence=Confidence.PROBABLE.value,
                validation_status=ValidationStatus.
                STRONG_CANDIDATE.value,
                host=host, matched_at=authz.url,
                endpoint_url=authz.url, method="GET",
                description=("Authorization endpoint omits `state`: "
                             "the login flow is open to CSRF. Observed "
                             "passively; confirm the state parameter is "
                             "absent across fresh flows."),
                tags=["oauth", "auth", "csrf"],
                raw={"authorize": authz.to_dict()},
                false_positive_notes=(
                    "Passive observation only; some providers bind "
                    "CSRF protection to nonce/PKCE instead of state."),
            ))
        if authz.implicit_flow:
            coverage.record("oauth", "candidate",
                            f"{authz.url[:120]}: implicit flow")
            findings.append(Finding(
                id=stable_finding_id("oauth", "implicit", authz.url),
                source="oauth-passive",
                name="OAuth implicit flow exposes tokens in URL",
                severity="medium",
                confidence=Confidence.PROBABLE.value,
                validation_status=ValidationStatus.
                STRONG_CANDIDATE.value,
                host=host, matched_at=authz.url,
                endpoint_url=authz.url, method="GET",
                description=("`response_type` includes token: access "
                             "tokens travel in URL fragments where logs "
                             "and Referer headers can leak them."),
                tags=["oauth", "auth", "token-leak"],
                raw={"authorize": authz.to_dict()},
                false_positive_notes=(
                    "Passive observation only; confirm tokens are "
                    "actually issued to the fragment."),
            ))
        if not testers or not scope.active_test_allowed(
                authz.url):
            continue
        tester = testers[0]
        tester_headers = dict(getattr(tester, "auth_headers", None)
                              or {})
        tester_name = getattr(tester, "name", "tester")
        if authz.has_pkce:
            controls.paced()
            try:
                res = check_pkce_strip(
                    client, authz.url, tester_headers, tester_name,
                    timeout=cfg.scan.http_timeout)
            except BudgetExceeded:
                coverage.record("oauth", "blocked",
                                f"budget: {authz.url[:120]}")
                continue
            metrics.authorization_tests += 1
            if res.verdict == "strong_candidate":
                metrics.authorization_confirmed += 1
                controls.noted()
                coverage.record("oauth", "candidate", res.notes)
                findings.append(Finding(
                    id=stable_finding_id("oauth", "nopkce", authz.url),
                    source="oauth-pkce",
                    name="OAuth PKCE not enforced",
                    severity="medium",
                    confidence=Confidence.PROBABLE.value,
                    validation_status=ValidationStatus.
                    STRONG_CANDIDATE.value,
                    host=host, matched_at=authz.url,
                    endpoint_url=authz.url, method="GET",
                    description=res.notes + " No code was redeemed "
                                    "and no redirect was followed.",
                    tags=["oauth", "auth", "pkce"],
                    raw={"probe": res.to_dict()},
                    false_positive_notes=(
                        "The authorize answer was observed, never "
                        "redeemed. Confirm the code validates without "
                        "a verifier before reporting."),
                    identity=tester_name,
                ))
            else:
                coverage.record("oauth", "inconclusive",
                                f"{authz.url[:120]}: {res.notes}")
        if oast_provider is not None and oast_provider.available() \
                and allow_state:
            controls.paced()
            try:
                callback = oast_provider.create_token()
                res = check_redirect_oast(
                    client, authz.url, tester_headers, tester_name,
                    callback, timeout=cfg.scan.http_timeout)
            except BudgetExceeded:
                coverage.record("oauth", "blocked",
                                f"budget: {authz.url[:120]}")
                continue
            metrics.authorization_tests += 1
            if res.verdict == "strong_candidate":
                metrics.authorization_confirmed += 1
                controls.noted()
                coverage.record("oauth", "candidate", res.notes)
                findings.append(Finding(
                    id=stable_finding_id("oauth", "redirect",
                                         authz.url),
                    source="oauth-redirect",
                    name=("OAuth redirect_uri not validated "
                          "(code-disclosure chain)"),
                    severity="medium",
                    confidence=Confidence.PROBABLE.value,
                    validation_status=ValidationStatus.
                    STRONG_CANDIDATE.value,
                    host=host, matched_at=authz.url,
                    endpoint_url=authz.url, method="GET",
                    description=res.notes + " The redirect was "
                                    "observed, never followed; no code "
                                    "was redeemed.",
                    tags=["oauth", "auth", "open-redirect"],
                    raw={"probe": res.to_dict()},
                    false_positive_notes=(
                        "Location observed only. Confirm an attacker "
                        "receiver actually gets a usable code."),
                    identity=tester_name,
                ))
            else:
                coverage.record("oauth", "inconclusive",
                                f"{authz.url[:120]}: {res.notes}")
    for f in findings:
        evidence.allocate(f)
        evidence.record(
            f, request_text=f"GET {f.endpoint_url}",
            response_text=(f.description or "")[:2000])
    return findings
