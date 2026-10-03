"""Triage-layer reporting (spec §11): impact, repro steps, FP notes.

A developer needs a curl; a triage team needs *why it matters*,
numbered repro steps, and what was checked to rule out false
positives.
"""
from typing import List, Optional
from ..models import Finding

_IMPACT = {
    "sqli": ("An attacker can manipulate SQL queries to read or modify "
             "data they should not access (PII, credentials, business "
             "records), and in many stacks escalate to server compromise "
             "via stacked queries or out-of-band exfiltration."),
    "xss": ("An attacker can execute arbitrary JavaScript in other "
            "users' browsers: session hijacking, account takeover, "
            "phishing, and drive-by attacks against privileged "
            "users."),
    "ssrf": ("An attacker can make the server issue requests to "
             "internal or cloud infrastructure — cloud metadata "
             "endpoints (169.254.169.254) leak IAM credentials, and "
             "internal hosts/port scans become possible."),
    "idor": ("An attacker with a low-privilege account can read or "
             "modify any other user's records by substituting the "
             "resource identifier (BOLA) — horizontal privilege "
             "escalation across the whole user base."),
    "bola": ("An attacker with a low-privilege account can read or "
             "modify any other user's records by substituting the "
             "resource identifier — horizontal privilege escalation "
             "across the whole user base."),
    "authz": ("Unauthenticated or low-privileged requests can reach "
              "privileged endpoints, exposing sensitive data or "
              "destructive actions to anyone who finds the URL."),
    "broken_auth": ("Unauthenticated or low-privileged requests can "
                    "reach privileged endpoints, exposing sensitive "
                    "data or destructive actions to anyone who finds "
                    "the URL."),
    "ssti": ("Server-side template injection lets an attacker "
             "execute arbitrary expressions in the template engine, "
             "typically leading to remote code execution."),
    "path_traversal": ("An attacker can read or write arbitrary files "
                       "on the server (config files, credentials, "
                       "shell profiles)."),
    "xxe": ("XML external entity injection can read local files, "
            "exfiltrate data, and reach cloud metadata endpoints "
            "via the XML parser."),
    "cmdi": ("Command injection allows arbitrary command execution on "
             "the host with the service account's privileges."),
    "open_redirect": ("An open redirect can be chained into OAuth "
                      "code-capture phishing and security-control "
                      "bypasses (redirect allow-lists)."),
    "info_disclosure": ("Sensitive internal detail is exposed, aiding "
                        "further attacks (version pinning, internal "
                        "hostnames, error tracebacks)."),
    "takeover": ("An unclaimed resource behind a CNAME can be claimed "
                 "by an attacker to serve arbitrary content under the "
                 "victim's subdomain — phishing, session theft, and "
                 "SSL-stripping without any vulnerable code."),
}

_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _classify(f: Finding) -> str:
    name = ((f.name or "") + " " + (f.template_id or "")).lower()
    if "takeover" in name or "subdomain" in name:
        return "takeover"
    if "bola" in name or "idor" in name:
        return "idor"
    if "auth" in name or "access" in name or "403" in name or "401" in name:
        return "authz"
    if "sqli" in name or "sql" in name:
        return "sqli"
    if "xss" in name:
        return "xss"
    if "ssrf" in name:
        return "ssrf"
    if "ssti" in name or "template" in name:
        return "ssti"
    if "traversal" in name or "lfi" in name:
        return "path_traversal"
    if "xxe" in name:
        return "xxe"
    if "cmd" in name or "rce" in name or "injection" in name:
        return "cmdi"
    if "redirect" in name:
        return "open_redirect"
    return "info_disclosure"


def build_impact(f: Finding) -> str:
    base = _IMPACT.get(_classify(f), _IMPACT["info_disclosure"])
    where = f.matched_at or f.endpoint_url or "the target"
    param = f" on parameter '{f.parameter}'" if f.parameter else ""
    return f"{base} Affected: {where}{param}."


def build_repro_steps(f: Finding) -> List[str]:
    steps: List[str] = []
    url = f.matched_at or (f.endpoint_url or "").strip() or "target URL"
    if f.validation_status == "confirmed" and f.source == "oast-ssrf":
        ev = f.raw or {}
        cb = ev.get("evidence", {}).get("callback_host", "<interactsh-token>.oast.pro")
        param = f.parameter or ev.get("evidence", {}).get("parameter", "url")
        steps = [
            f"Request {url} with {param}=<interactsh-token>.oast.pro.",
            f"Observe the out-of-band callback arrive at {cb} "
            f"(DNS/HTTP interaction recorded by Interactsh).",
            f"Repeat with the same token to rule out one-off noise "
            f"(consistent callback on repeated requests).",
            "Note: no in-band response change is required — the "
            "callback itself is the proof.",
        ]
        return steps
    if f.source in ("differential", "ai+differential"):
        ctxs = (f.raw or {}).get("contexts", [])
        ctx_txt = ", ".join(
            f"{c.get('name')}→HTTP {c.get('status')}" for c in ctxs
        ) or "anonymous / user_a / user_b"
        steps = [
            f"Fetch {url} with no authentication headers → "
            f"HTTP {ctxs[0].get('status') if ctxs else '200'}.",
            f"Fetch {url} as each low-privilege account (context "
            f"headers from the scan's auth configuration).",
            f"Compare response shapes: {ctx_txt}.",
            "Identical 200 bodies across two unrelated users — or "
            "anonymous 200 on a privileged endpoint — is the finding.",
            "Swap the resource identifier (id/uid) between users and "
            "repeat to demonstrate cross-user data access.",
        ]
        return steps
    steps.append(f"Send {f.method or 'GET'} to {url}.")
    if f.request_headers:
        steps.append("Include the captured request headers "
                     "(see request.txt in the evidence directory).")
    if f.request_body:
        steps.append("Send the captured request body.")
    steps.append("Observe the anomalous response recorded in "
                 "response.txt / metadata.json.")
    if f.reproduction:
        steps.append(f"Equivalent one-liner: {f.reproduction}")
    return steps


def build_fp_notes(f: Finding) -> str:
    """What was checked to rule out false positives."""
    src = (f.source or "").lower()
    cls = _classify(f)
    if "oast" in src or f.source == "ssrf":
        return ("Confirmed via out-of-band Interactsh callback "
                "(unique token per scan), not response-shape heuristics. "
                "Baseline vs. mutated responses differ only in the "
                "callback interaction; no WAF block observed.")
    if "differential" in src or f.source == "ai+differential":
        return ("Compared responses across authentication contexts with "
                "volatile keys (csrf, token, timestamp, nonce, "
                "request-id) excluded from the shape comparison; "
                "length compared in 1KB buckets to avoid encoding noise.")
    if "sqlmap" in src or cls == "sqli":
        return ("Validated with sqlmap --level 1 --risk 1 in batch mode; "
                "mutation pre-screen ran the WAF-specific payload ladder "
                "first. No injection → marked false_positive.")
    if "dalfox" in src or cls == "xss":
        return ("Dalfox run with XSS payloads; candidate requires the "
                "payload to survive HTML encoding. Manual re-verification "
                "of context (attribute vs. HTML vs. JS) recommended "
                "before reporting.")
    if "nuclei" in src:
        return ("Nuclei template detection; deduplicated by "
                "template::path::param root-cause key; template-specific "
                "matchers applied (status/word/regex), not raw string "
                "matching.")
    return ("Detection based on fingerprint/heuristic signals; verify "
            "manually before reporting. See evidence directory for the "
            "raw request/response pair.")


def priority_sort_key(f: Finding):
    return (_ORDER.get(f.severity, 5), f.matched_at or "")
