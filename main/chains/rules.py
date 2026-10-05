"""ATO kill-chain rules over recorded findings.

Each rule matches finding combinations that together describe an
account-takeover path and emits an AttackChain hypothesis. Rules
read finding sources, tags, paths, and hosts only — no network, no
guessing. Single-finding chains exist only where one finding is
itself the kill primitive (poisoned reset link); every chain lists
the missing links that keep it a hypothesis.
"""
from typing import Dict, List
from urllib.parse import urlsplit

from ..models import stable_finding_id
from .models import HYPOTHESIZED, POSSIBLE, PROBABLE, AttackChain, ChainStep

_AUTH_PATH_PARTS = ("login", "signin", "session", "account", "auth",
                    "password", "token", "user", "oauth", "sso",
                    "register", "profile")


def _sources(finding) -> str:
    return str(getattr(finding, "source", "") or "").lower()


def _tags(finding) -> List[str]:
    return [str(t).lower() for t in
            getattr(finding, "tags", None) or []]


def _host(finding) -> str:
    return str(getattr(finding, "host", "") or "")


def _path(finding) -> str:
    url = str(getattr(finding, "endpoint_url", "") or
              getattr(finding, "matched_at", "") or "")
    try:
        return urlsplit(url).path.lower()
    except ValueError:
        return ""


def _auth_surface(finding) -> bool:
    if "authentication" in _tags(finding):
        return True
    parts = set(_path(finding).split("/"))
    return bool(parts & set(_AUTH_PATH_PARTS))


def _confirmed(finding) -> bool:
    return str(getattr(finding, "validation_status", "")) == "confirmed"


def _by_sources(findings, *needles) -> list:
    return [f for f in findings or []
            if any(n in _sources(f) for n in needles)]


def _describe(finding) -> str:
    return (f"{_sources(finding)} on "
            f"{getattr(finding, 'endpoint_url', '') or '?'} "
            f"({getattr(finding, 'id', '')})")


def _chain(rule: str, name: str, host: str, members: list,
           capability: str, confidence: str,
           missing: List[str]) -> AttackChain:
    ids = sorted({str(getattr(f, "id", "")) for f in members
                  if getattr(f, "id", "")})
    steps = [ChainStep(kind="finding", text=_describe(f),
                       finding_id=str(getattr(f, "id", "")))
             for f in members]
    steps.append(ChainStep(kind="capability", text=capability))
    steps.append(ChainStep(
        kind="impact",
        text="account takeover: attacker operates the victim account"))
    steps.extend(ChainStep(kind="missing", text=m) for m in missing)
    return AttackChain(
        id=stable_finding_id("chain", rule, host, *ids),
        rule=rule, name=name, host=host, finding_ids=ids,
        confidence=confidence, status=HYPOTHESIZED,
        steps=steps, missing_links=list(missing))


def _same_host(groups: Dict[str, list], *lists) -> list:
    """Yield (host, members) where every list has a finding on host."""
    hosts = set(groups.keys())
    for extra in lists:
        per_host: Dict[str, list] = {}
        for f in extra:
            per_host.setdefault(_host(f), []).append(f)
        hosts &= set(per_host.keys())
    out = []
    for host in sorted(hosts):
        members = list(groups[host])
        for extra in lists:
            members.extend(f for f in extra if _host(f) == host)
        out.append((host, members))
    return out


def _group_by_host(findings) -> Dict[str, list]:
    groups: Dict[str, list] = {}
    for f in findings or []:
        groups.setdefault(_host(f), []).append(f)
    return groups


def rule_reset_poison(findings) -> List[AttackChain]:
    """A poisoned reset link is itself the ATO primitive."""
    out = []
    for f in _by_sources(findings, "reset-poison"):
        out.append(_chain(
            "reset-poison", "Password-reset poisoning → account takeover",
            _host(f), [f],
            "attacker-controlled reset link mailed to the victim",
            POSSIBLE,
            ["Confirm the poisoned link is actually mailed (test inbox)",
             "Redeem interactively with a test account; never automate "
             "token use"]))
    return out


def rule_reset_enum_assists(findings) -> List[AttackChain]:
    """Enumerated account + poisoned reset link on the same host."""
    poison = _group_by_host(_by_sources(findings, "reset-poison"))
    out = []
    for host, members in _same_host(
            poison, _by_sources(findings, "reset-enum")):
        out.append(_chain(
            "reset-enum-assists",
            "Enumerated account + poisoned reset → account takeover",
            host, members,
            "valid victim identifier known; reset link attacker-controlled",
            PROBABLE,
            ["Confirm the poisoned link is actually mailed (test inbox)",
             "Redeem interactively with a test account; never automate "
             "token use"]))
    return out


def rule_xss_session_theft(findings) -> List[AttackChain]:
    """XSS on authentication surface → session theft."""
    out = []
    for f in _by_sources(findings, "xss", "second-order", "blind-xss"):
        if not _auth_surface(f):
            continue
        out.append(_chain(
            "xss-session-theft",
            "XSS on authentication surface → session theft",
            _host(f), [f],
            "script executes in a victim session and exfiltrates it",
            POSSIBLE,
            ["Confirm script execution in a real session context",
             "Check HttpOnly/SameSite on session cookies — theft may "
             "be blocked even with injection"]))
    return out


def rule_oauth_token_theft(findings) -> List[AttackChain]:
    """OAuth flaw + open redirect on the same host → token theft."""
    oauth = _group_by_host(_by_sources(
        findings, "oauth-pkce", "oauth-redirect"))
    out = []
    for host, members in _same_host(
            oauth, _by_sources(findings, "open-redirect")):
        out.append(_chain(
            "oauth-token-theft",
            "OAuth flaw + open redirect → code/token theft",
            host, members,
            "authorization code or token delivered to attacker URI",
            PROBABLE,
            ["Confirm the provider redirects codes/tokens to the "
             "poisoned URI with a test account",
             "Never redeem codes or tokens automatically"]))
    return out


def rule_reset_plus_otp(findings) -> List[AttackChain]:
    """Reset flow + OTP bypass on the same host: full ATO, no password."""
    resets = _group_by_host(_by_sources(
        findings, "reset-enum", "reset-poison"))
    out = []
    for host, members in _same_host(
            resets, _by_sources(findings, "otp-bypass")):
        out.append(_chain(
            "reset-plus-otp",
            "Password reset + OTP bypass → account takeover",
            host, members,
            "second factor removed; reset flow yields the account",
            PROBABLE,
            ["Confirm end-to-end with test accounts only",
             "Redeem interactively; never automate token use"]))
    return out


def rule_sqli_auth_bypass(findings) -> List[AttackChain]:
    """SQL injection on authentication surface → auth bypass."""
    out = []
    for f in _by_sources(findings, "sqli"):
        if not _auth_surface(f):
            continue
        out.append(_chain(
            "sqli-auth-bypass",
            "SQL injection on login → authentication bypass",
            _host(f), [f],
            "injection alters the authentication query outcome",
            PROBABLE if _confirmed(f) else POSSIBLE,
            ["Confirm the injection bypasses authentication logic, "
             "not just error text",
             "No data extraction — behavior proof only"]))
    return out


def rule_cors_session_read(findings) -> List[AttackChain]:
    """CORS misconfig + cross-user read on the same host."""
    cors = _group_by_host(_by_sources(findings, "cors"))
    out = []
    for host, members in _same_host(
            cors, _by_sources(findings, "idor-swap", "bola",
                              "graphql-bola", "differential")):
        out.append(_chain(
            "cors-session-read",
            "CORS + cross-user read → cross-origin session theft",
            host, members,
            "victim session reads attacker-origin JavaScript requests",
            POSSIBLE,
            ["Confirm a victim session visits the attacker origin",
             "Confirm cookies are sent (SameSite=None + Secure); "
             "browser proof decides readability"]))
    return out


RULES = (rule_reset_poison, rule_reset_enum_assists,
         rule_xss_session_theft, rule_oauth_token_theft,
         rule_reset_plus_otp, rule_sqli_auth_bypass,
         rule_cors_session_read)
