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
from ...safety.preflight import (plan_differential, plan_jwt,
                                  plan_otp, plan_reset)
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


def jwt_confusion_probe(endpoints: List[Endpoint],
                        evidence: EvidenceStore, metrics: Metrics,
                        budgets: BudgetTracker,
                        coverage: CoverageTracker, client, cfg, scope,
                        controls: ProbeControls,
                        identities) -> List[Finding]:
    """Replay caller-owned Bearer tokens with neutralized signatures."""
    from ...validation.jwt_replay import (
        bearer_token, jwt_confusion_probe as _replay)
    targets = [e for e in endpoints or []
               if (getattr(e, "method", "GET") or "GET").upper() == "GET"
               and getattr(e, "endpoint_type", "") == "api"
               and scope.active_test_allowed(e.url)][:10]
    if not targets:
        log.info("jwt: no in-scope API endpoints — nothing to compare")
        return []
    authed = [i for i in identities or []
              if bearer_token(
                  dict(getattr(i, "auth_headers", None) or {}))]
    if not authed:
        log.info("jwt: no identity carries a Bearer JWT — skipping")
        return []
    if not reserve_or_block(
            budgets, coverage, "jwt",
            plan_jwt(len(targets), len(authed))):
        return []
    findings: List[Finding] = []
    for ep in targets:
        if controls.halted():
            log.info("jwt: halted by stop control")
            break
        for ident in authed:
            headers = dict(getattr(ident, "auth_headers", None) or {})
            name = getattr(ident, "name", "tester")
            if not budgets.consume_test("jwt", ep.normalized_url,
                                        limit=3):
                coverage.record("jwt", "blocked",
                                f"budget: {ep.normalized_url}")
                break
            try:
                res = _replay(
                    client, ep.url, headers, name,
                    timeout=cfg.scan.http_timeout)
            except BudgetExceeded:
                coverage.record("jwt", "blocked",
                                f"budget: {ep.normalized_url}")
                break
            if res is None or res.verdict == "untestable":
                continue
            metrics.authorization_tests += 1
            if res.verdict == "accepted":
                metrics.authorization_confirmed += 1
                controls.noted()
                coverage.record("jwt", "candidate", res.notes)
                f = Finding(
                    id=stable_finding_id("jwt", ep.normalized_url,
                                         name),
                    source="jwt-confusion",
                    name=(f"JWT signature not enforced ({ep.path})"),
                    severity="high",
                    confidence=Confidence.PROBABLE.value,
                    validation_status=ValidationStatus.
                    STRONG_CANDIDATE.value,
                    host=ep.host, matched_at=ep.url,
                    endpoint_url=ep.url, method="GET",
                    description=res.notes + " Confirm with a second "
                                    "account and check whether key "
                                    "confusion (e.g. RSA-as-HMAC) "
                                    "applies before reporting.",
                    tags=["jwt", "auth", "authz", ep.endpoint_type],
                    raw={"jwt": res.to_dict()},
                    false_positive_notes=(
                        "The tampered token was served like the "
                        "baseline. Rule out shared caches, static "
                        "responses, and middleware that ignores the "
                        "token entirely (200 on garbage input means "
                        "no check ran at all)."),
                    identity=name,
                )
                evidence.allocate(f)
                evidence.record(
                    f,
                    request_text=(f"GET {ep.url}\n(as {name}; "
                                  f"signature-neutralized Bearer)"),
                    response_text=res.notes)
                findings.append(f)
                log.info("jwt: %s", res.notes)
            elif res.verdict == "denied":
                coverage.record("jwt", "tested_negative",
                                f"{ep.normalized_url}: {res.notes}")
            else:
                coverage.record("jwt", "inconclusive",
                                f"{ep.normalized_url}: {res.notes}")
    return findings


_MAX_RESET_ENDPOINTS = 10


def reset_probe(endpoints: List[Endpoint],
                evidence: EvidenceStore, metrics: Metrics,
                budgets: BudgetTracker,
                coverage: CoverageTracker, client, cfg, scope,
                controls: ProbeControls) -> List[Finding]:
    """Password-reset enumeration + reset-link poisoning checks.

    Test identifiers come from ``auth.login.identities`` usernames
    only — without an operator-supplied account the flow stays
    untestable and nothing is sent.
    """
    from ...validation.reset_flow import (
        check_reset_enumeration, check_reset_host_poison,
        identifier_param_for, reset_targets)
    identifiers = [str(getattr(i, "username", "") or "").strip()
                   for i in
                   getattr(getattr(cfg.auth, "login", None),
                           "identities", None) or []]
    identifiers = [i for i in identifiers if i]
    if not identifiers:
        log.info("reset: no auth.login.identities usernames "
                 "configured — skipping (test account required)")
        coverage.record("auth", "untestable",
                        "no login usernames configured")
        return []
    targets = [e for e in reset_targets(endpoints or [])
               if scope.active_test_allowed(e.url)][: _MAX_RESET_ENDPOINTS]
    if not targets:
        log.info("reset: no in-scope reset-path endpoints — "
                 "nothing to check")
        return []
    if not reserve_or_block(
            budgets, coverage, "auth",
            plan_reset(len(targets))):
        return []
    findings: List[Finding] = []
    valid = identifiers[0]
    for ep in targets:
        if controls.halted():
            log.info("reset: halted by stop control")
            break
        param = identifier_param_for(ep)
        if param is None:
            coverage.record("auth", "untestable",
                            f"{ep.normalized_url}: no identifier field")
            continue
        if not budgets.consume_test("auth", ep.normalized_url,
                                    limit=3):
            coverage.record("auth", "blocked",
                            f"budget: {ep.normalized_url}")
            continue
        try:
            enum = check_reset_enumeration(
                client, ep.url, param, valid,
                timeout=cfg.scan.http_timeout)
            poison = check_reset_host_poison(
                client, ep.url, param, valid,
                timeout=cfg.scan.http_timeout)
        except BudgetExceeded:
            coverage.record("auth", "blocked",
                            f"budget: {ep.normalized_url}")
            continue
        for res, source, title, fp in (
                (enum, "reset-enum",
                 "Password-reset user enumeration",
                 "Differential responses can also come from "
                 "anti-automation or rate-limit pages reflecting "
                 "input length. Confirm the oracle repeats with "
                 "fresh unknown identifiers before reporting."),
                (poison, "reset-poison",
                 "Password-reset link poisoning",
                 "A reflected host proves server-side trust, not "
                 "delivery. Confirm the poisoned link is actually "
                 "mailed (test inbox) before reporting.")):
            if res.verdict == "candidate":
                controls.noted()
                coverage.record("auth", "candidate",
                                f"{ep.normalized_url}::{param}: "
                                f"{res.notes}")
                f = Finding(
                    id=stable_finding_id("reset", source,
                                         ep.normalized_url, param),
                    source=source,
                    name=f"{title} ({ep.path})",
                    severity="medium",
                    confidence=Confidence.PROBABLE.value,
                    validation_status=ValidationStatus.
                    STRONG_CANDIDATE.value,
                    host=ep.host, matched_at=ep.url,
                    endpoint_url=ep.url, method="POST",
                    parameter=param,
                    description=res.notes,
                    tags=["auth", "password-reset",
                          ep.endpoint_type],
                    raw={source: res.to_dict()},
                    false_positive_notes=(
                        f"{res.notes}. {fp}"),
                    identity="tester",
                )
                evidence.allocate(f)
                evidence.record(
                    f,
                    request_text=(f"POST {ep.url}\n"
                                  f"(identifier field: {param}; "
                                  f"value withheld)"),
                    response_text=res.notes)
                findings.append(f)
                log.info("reset: %s on %s", source, ep.url)
            elif res.verdict == "negative":
                coverage.record("auth", "tested_negative",
                                f"{ep.normalized_url}::{param}: "
                                f"{res.notes}")
            else:
                coverage.record("auth", "inconclusive",
                                f"{ep.normalized_url}::{param}: "
                                f"{res.notes}")
    return findings


_MAX_OTP_ENDPOINTS = 10


def otp_bypass_probe(endpoints: List[Endpoint],
                     evidence: EvidenceStore, metrics: Metrics,
                     budgets: BudgetTracker,
                     coverage: CoverageTracker, client, cfg, scope,
                     controls: ProbeControls) -> List[Finding]:
    """Empty/omitted OTP code against a wrong-code baseline.

    Attempts count against lockout counters, so this probe runs only
    behind ``safety.allow_state_change`` (``--ack-state-change``)
    with test accounts. At most 3 single attempts per endpoint —
    never a brute-force sweep.
    """
    from ...validation.otp_bypass import (
        check_otp_bypass, code_param_for, otp_targets)
    if not getattr(getattr(cfg, "safety", None),
                   "allow_state_change", False):
        log.info("otp: needs --ack-state-change (attempts count "
                 "against lockout counters) — skipping")
        return []
    targets = [e for e in otp_targets(endpoints or [])
               if scope.active_test_allowed(e.url)][: _MAX_OTP_ENDPOINTS]
    if not targets:
        log.info("otp: no in-scope OTP-path endpoints — "
                 "nothing to check")
        return []
    if not reserve_or_block(
            budgets, coverage, "auth",
            plan_otp(len(targets))):
        return []
    findings: List[Finding] = []
    for ep in targets:
        if controls.halted():
            log.info("otp: halted by stop control")
            break
        param = code_param_for(ep)
        if param is None:
            coverage.record("auth", "untestable",
                            f"{ep.normalized_url}: no code field")
            continue
        if not budgets.consume_test("auth", ep.normalized_url,
                                    limit=3):
            coverage.record("auth", "blocked",
                            f"budget: {ep.normalized_url}")
            continue
        try:
            results = check_otp_bypass(
                client, ep.url, param,
                timeout=cfg.scan.http_timeout)
        except BudgetExceeded:
            coverage.record("auth", "blocked",
                            f"budget: {ep.normalized_url}")
            continue
        for res in results:
            if res.verdict == "candidate":
                controls.noted()
                coverage.record("auth", "candidate",
                                f"{ep.normalized_url}::{param}: "
                                f"{res.notes}")
                f = Finding(
                    id=stable_finding_id("otp", res.check,
                                         ep.normalized_url, param),
                    source="otp-bypass",
                    name=(f"OTP verification bypass ({res.check}) "
                          f"({ep.path})"),
                    severity="medium",
                    confidence=Confidence.PROBABLE.value,
                    validation_status=ValidationStatus.
                    STRONG_CANDIDATE.value,
                    host=ep.host, matched_at=ep.url,
                    endpoint_url=ep.url, method="POST",
                    parameter=param,
                    description=res.notes,
                    tags=["auth", "otp", "mfa-bypass",
                          ep.endpoint_type],
                    raw={"otp": res.to_dict()},
                    false_positive_notes=(
                        f"{res.notes}. Acceptance is judged by "
                        f"success language in the response — rule out "
                        f"generic 200 pages and shared templates, "
                        f"confirm with a second test account, and "
                        f"re-test under a real pre-OTP session "
                        f"(this probe runs anonymous). Attempts "
                        f"count against lockout counters: use test "
                        f"accounts only."),
                    identity="tester",
                )
                evidence.allocate(f)
                evidence.record(
                    f,
                    request_text=(f"POST {ep.url}\n"
                                  f"(code field: {param}; "
                                  f"value withheld)"),
                    response_text=res.notes)
                findings.append(f)
                log.info("otp: %s on %s", res.check, ep.url)
            elif res.verdict == "negative":
                coverage.record("auth", "tested_negative",
                                f"{ep.normalized_url}::{param}: "
                                f"{res.notes}")
            else:
                coverage.record("auth", "inconclusive",
                                f"{ep.normalized_url}::{param}: "
                                f"{res.notes}")
    return findings
