"""Quiet lead finder (read-only).

Collects *leads* — discovered-but-untested attack surface — purely from
artifacts the discovery stages already wrote (endpoints, technologies,
takeover fingerprints). Sends zero requests by design: this module only
reads in-memory objects.

A lead is not a vulnerability verdict. Each lead names the follow-up
(profile/flag) that would test it, so a leads-mode run produces a work
list instead of findings.
"""
from typing import Any, Dict, List

from .application.resources import IDENTIFIER_NAMES
from .models import stable_finding_id
from .validation.differential import IDOR_PARAM_NAMES

# Parameter names whose values are commonly URLs fetched server-side.
URL_PARAM_NAMES = {
    "url", "uri", "link", "redirect", "redirect_url", "redirect_uri",
    "next", "return", "return_url", "callback", "callback_url",
    "webhook", "webhook_url", "webhookurl", "image_url", "file_url",
    "feed", "fetch", "target", "dest", "destination", "u", "r",
}

# Path segments worth a human look even with zero parameters:
# /panel, /inv, /api ... — robots/sitemap paths on login-walled apps
# are often the whole inventory. Auth-flow segments (reset, OTP,
# OAuth) get manual-review leads: those flows need test accounts
# and app-specific knowledge no probe can assume.
INTERESTING_PATH_HINTS = {
    "panel", "admin", "login", "invite", "inv", "api", "internal",
    "debug", "console", "dashboard", "account", "auth", "manage",
    "private", "register", "settings", "config",
    "forgot", "forgot-password", "reset", "password-reset", "recover",
    "recovery", "otp", "verify", "2fa", "mfa", "oauth", "authorize",
    "sso", "callback",
}

# Parameter names that commonly control redirects.
REDIRECT_PARAM_NAMES = {
    "next", "redirect", "redirect_url", "redirect_uri", "return",
    "return_url", "continue", "dest", "destination", "r", "u",
    "callback",
}

_PRIORITY_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}

MAX_LEADS = 100


def _params(endpoint: Any) -> List[Any]:
    seen: List[Any] = []
    for attr in ("query_parameters", "body_parameters",
                 "header_parameters"):
        for param in list(getattr(endpoint, attr, None) or []):
            name = getattr(param, "name", "") or ""
            if name and all(getattr(p, "name", "") != name
                            for p in seen):
                seen.append(param)
    return seen


def _is_id_param(name: str) -> bool:
    lowered = (name or "").lower().replace("-", "_")
    return lowered in IDOR_PARAM_NAMES or lowered in IDENTIFIER_NAMES


def _is_url_param(name: str) -> bool:
    return (name or "").lower().replace("-", "_") in URL_PARAM_NAMES


def _is_redirect_param(name: str) -> bool:
    return (name or "").lower().replace("-", "_") in REDIRECT_PARAM_NAMES


def collect_leads(endpoints: List[Any], technologies: List[Dict],
                  takeover_notes: List[str]) -> List[Dict]:
    """Rank discovered-but-untested surface. No network, pure ranking."""
    leads: List[Dict] = []

    def add(kind: str, priority: str, url: str, reason: str,
            followup: str, param: str = "",
            confidence: str = "possible") -> None:
        leads.append({
            "id": stable_finding_id("lead", kind, url, param),
            "kind": kind,
            "priority": priority,
            "url": url,
            "param": param,
            "reason": reason,
            "suggested_followup": followup,
            "confidence": confidence,
        })

    for endpoint in endpoints or []:
        url = getattr(endpoint, "normalized_url", "") or \
            getattr(endpoint, "url", "")
        if not url:
            continue
        endpoint_type = str(getattr(endpoint, "endpoint_type", "unknown"))
        params = _params(endpoint)
        id_params = [getattr(p, "name", "") for p in params
                     if _is_id_param(getattr(p, "name", ""))]
        url_params = [getattr(p, "name", "") for p in params
                      if _is_url_param(getattr(p, "name", ""))]
        redirect_params = [getattr(p, "name", "") for p in params
                           if _is_redirect_param(getattr(p, "name", ""))]

        if endpoint_type in ("admin", "authentication"):
            add("privileged-endpoint", "high", url,
                f"endpoint typed {endpoint_type}; access control untested",
                "differential + authz-matrix (needs 2 test identities)",
                confidence="probable")
        if id_params:
            add("id-param", "high", url,
                f"identifier-like parameters: {', '.join(id_params[:3])}",
                "--profile validation (BOLA swap needs auth contexts)",
                param=id_params[0])
        if endpoint_type == "graphql":
            add("graphql-operation", "medium", url,
                "GraphQL endpoint; operation/variable replay untested",
                "--profile validation (graphql-bola replay)")
        if url_params and endpoint_type in (
                "proxy", "webhook", "callback", "import", "export",
                "download", "api", "unknown", "page"):
            add("url-param", "high", url,
                f"URL-like parameters: {', '.join(url_params[:3])}",
                "--oast (blind-SSRF sweep with callback confirmation)",
                param=url_params[0])
        if endpoint_type == "redirect" or redirect_params:
            add("redirect-sink", "medium", url,
                "redirect behavior or redirect-like parameters untested",
                "--profile validation (bounded open-redirect checks)",
                param=redirect_params[0] if redirect_params else "")
        if endpoint_type == "upload":
            add("upload-surface", "medium", url,
                "upload endpoint; file-type handling untested (manual)",
                "manual file-upload review (out of normal scans)")
        segments = [seg.lower() for seg in
                    (getattr(endpoint, "path", "") or "").split("/")
                    if seg]
        hits = [seg for seg in segments
                if seg in INTERESTING_PATH_HINTS]
        if hits and endpoint_type not in ("admin", "authentication"):
            add("interesting-path", "medium", url,
                "path suggests hidden functionality: " +
                ", ".join(hits[:3]),
                "Repeater: fetch by hand, map it, retest with a "
                "session (auth/IDOR/BFLA)")
        forms = getattr(endpoint, "forms", None) or []
        if forms and not id_params:
            add("html-form", "medium", url,
                f"{len(forms)} HTML form(s) with untested inputs",
                "--second-order (stored-XSS correlation, opt-in)")
        if len(params) >= 5 and not id_params and not url_params:
            add("param-rich", "info", url,
                f"{len(params)} parameters, none identifier/URL-like",
                "capped arjun mining (discovery.arjun_max_endpoints)")

    for tech in technologies or []:
        name = tech.get("name", "") if isinstance(tech, dict) else str(tech)
        version = tech.get("version", "") if isinstance(tech, dict) else ""
        if name and version:
            add("versioned-tech", "low", "",
                f"{name} {version} fingerprinted; template match untested",
                "--profile standard (nuclei community + bb templates)")

    for note in takeover_notes or []:
        add("takeover-fingerprint", "medium", str(note),
            "dangling-service fingerprint; ownership unclaimed",
            "manual claim review (tko-subs -takeover needs tokens)")

    leads.sort(key=lambda lead: (_PRIORITY_RANK.get(lead["priority"], 4),
                                 lead["url"], lead["kind"]))
    return leads[:MAX_LEADS]


def write_leads(path, leads: List[Dict]) -> None:
    """Persist leads as JSONL (stable ids, sorted by priority)."""
    import json
    lines = [json.dumps(lead, sort_keys=True) for lead in leads]
    with open(str(path), "w") as handle:
        handle.write("\n".join(lines) + ("\n" if lines else ""))
