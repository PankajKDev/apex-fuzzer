"""Differential auth-context testing — BOLA / IDOR / broken access (spec §2).

Fetches the same endpoint under each configured auth context, normalizes
the responses, and flags:

- **BOLA/IDOR candidate**: two different authenticated users both get
  HTTP 200 with the *same* response shape (identical JSON keys, or
  identical body hash) for a per-resource endpoint.
- **Broken access control**: anonymous gets HTTP 200 on an endpoint the
  classifier typed as ``admin`` or ``api``.

This is the highest-paying bug class most homegrown pipelines never test
(OWASP API Security Top 10, #1 BOLA).
"""
import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple
from ..budgets import BudgetExceeded
from ..logging_setup import get_logger

log = get_logger("differential")

VOLATILE_KEYS = {
    "csrf", "csrftoken", "_token", "token", "timestamp", "date", "datetime",
    "nonce", "request_id", "requestid", "x-request-id", "cache_key",
    "csrfmiddlewaretoken", "session_id", "refresh_token", "expires_at",
}

LENGTH_BUCKET = 1024  # response length is compared in 1KB buckets

# Edge/bot-wall deny signatures. A WAF edge denial means the request
# never reached the application, so it can never support a negative
# verdict (or a same-shape match). Matching is deliberately narrow: a
# bare "access denied" from the app itself is NOT an edge signal.
_EDGE_BODY_MARKERS = ("edgesuite.net", "akamaighost", "akamaiedge",
                      "perimeterx", "incapsula", "challenge-platform",
                      "bot manager", "request blocked by")
_EDGE_SERVER_MARKERS = ("akamai", "edgesuite", "cloudflare", "incapsula")


def looks_like_edge_deny(status: int, text: str,
                         headers=None) -> bool:
    """True when a response is edge/bot-wall infrastructure, not the app."""
    try:
        body = (text or "")[:2000].lower()
    except (TypeError, ValueError):
        return False
    server = ""
    try:
        for name, value in (headers or {}).items():
            if str(name).lower() == "server" and isinstance(value, str):
                server = value.lower()
                break
    except (AttributeError, TypeError):
        pass
    edge_body = any(marker in body for marker in _EDGE_BODY_MARKERS)
    edge_server = any(marker in server for marker in _EDGE_SERVER_MARKERS)
    if status == 403 and (edge_body or edge_server):
        return True
    # bot-challenge pages served as 200 (sensor HTML, JS challenges)
    # shared by every identity are infrastructure, not application state
    if status == 200 and ("edgesuite" in body or "akamaighost" in body):
        return True
    return False

# endpoint types where an anonymous 200 is meaningful
PRIVILEGED_TYPES = ("admin", "api", "authentication")

# parameter names that smell like resource identifiers (IDOR surface)
IDOR_PARAM_NAMES = {
    "id", "uuid", "uid", "user_id", "userid", "account_id", "order_id",
    "invoice_id", "email", "username", "slug", "ref", "ref_id",
    "customer_id", "card_id", "transaction_id", "txn_id",
}


@dataclass
class ContextResult:
    name: str
    status: int = 0
    length: int = 0
    length_bucket: int = 0
    key_shape: str = ""
    body_hash: str = ""
    error: str = ""
    edge_denied: bool = False


@dataclass
class DifferentialResult:
    url: str
    endpoint_type: str
    contexts: List[ContextResult] = field(default_factory=list)
    verdict: str = "inconclusive"
    notes: str = ""
    edge_denied: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "endpoint_type": self.endpoint_type,
            "verdict": self.verdict,
            "notes": self.notes,
            "edge_denied": self.edge_denied,
            "contexts": [vars(c) for c in self.contexts],
        }


def _json_key_shape(value: Any, depth: int = 0) -> Any:
    """Structural fingerprint of a JSON document (volatile keys dropped)."""
    if depth > 3:
        return "..."
    if isinstance(value, dict):
        keys = [k for k in value.keys()
                if k.lower() not in VOLATILE_KEYS]
        return {k: _json_key_shape(value[k], depth + 1) for k in
                sorted(keys)}
    if isinstance(value, list):
        if not value:
            return []
        sample = _json_key_shape(value[0], depth + 1)
        return [sample, f"len={len(value)}"]
    return "scalar"


def normalize_response(r) -> Dict[str, Any]:
    """Status + sorted JSON keys + length bucket + body hash."""
    body = r.text or ""
    length = len(body)
    shape = ""
    try:
        data = json.loads(body)
        shape = json.dumps(_json_key_shape(data), sort_keys=True)
    except (ValueError, TypeError):
        # not JSON — fall back to a coarse body hash of the first 8KB
        shape = ""
    body_hash = hashlib.sha256(
        re.sub(r"\s+", " ", body[:8192]).encode("utf-8", "replace")
    ).hexdigest()[:16]
    return {
        "status": r.status_code,
        "length": length,
        "length_bucket": length // LENGTH_BUCKET,
        "key_shape": shape,
        "body_hash": body_hash,
    }


def has_idor_params(endpoint) -> bool:
    for p in list(getattr(endpoint, "query_parameters", []) or []) + \
             list(getattr(endpoint, "body_parameters", []) or []):
        if p.name.lower() in IDOR_PARAM_NAMES:
            return True
    return False


def _endpoint_is_differential_target(endpoint, endpoint_type: str) -> bool:
    if endpoint_type in PRIVILEGED_TYPES:
        return True
    return has_idor_params(endpoint)


class DifferentialTester:
    def __init__(self, cfg, http):
        self.cfg = cfg
        self.http = http
        # anonymous context is implicit
        self.contexts = [{"name": "anonymous", "headers": {}}]
        auth_cfg = getattr(cfg, "auth", None)
        for ctx in (auth_cfg.contexts if auth_cfg else []):
            if ctx.name == "anonymous":
                continue
            self.contexts.append({"name": ctx.name,
                                  "headers": dict(ctx.headers or {})})

    @property
    def has_two_authenticated(self) -> bool:
        return sum(1 for c in self.contexts if c["name"] != "anonymous") >= 2

    def probe(self, url: str, endpoint_type: str = "unknown",
              timeout: int = 10) -> DifferentialResult:
        res = DifferentialResult(url=url, endpoint_type=endpoint_type)
        for ctx in self.contexts:
            cr = ContextResult(name=ctx["name"])
            try:
                r = self.http.get(url, headers=ctx["headers"],
                                  timeout=timeout)
                n = normalize_response(r)
                cr.status = n["status"]
                cr.length = n["length"]
                cr.length_bucket = n["length_bucket"]
                cr.key_shape = n["key_shape"]
                cr.body_hash = n["body_hash"]
                try:
                    cr.edge_denied = looks_like_edge_deny(
                        r.status_code, r.text or "",
                        getattr(r, "headers", None))
                except Exception:
                    cr.edge_denied = False
            except BudgetExceeded:
                # budget exhaustion is infrastructure, never a negative —
                # propagate so the caller records BLOCKED coverage
                raise
            except Exception as e:
                cr.error = str(e)[:200]
            res.contexts.append(cr)
        res.verdict, res.notes = self.evaluate(res)
        return res

    @staticmethod
    def evaluate(res: DifferentialResult) -> Tuple[str, str]:
        by_name = {c.name: c for c in res.contexts}
        anon = by_name.get("anonymous")
        authed = [c for c in res.contexts if c.name != "anonymous"]

        # Edge/bot-wall responses never reached the application: no
        # verdict built on them is sound. All denied → inconclusive;
        # identically edge-flagged 200s are shared infrastructure pages.
        answered = [c for c in res.contexts if not c.error]
        if answered and all(getattr(c, "edge_denied", False)
                            for c in answered):
            res.edge_denied = True
            return ("inconclusive",
                    "edge/bot-wall denied every context; the application "
                    "was never reached")

        # BOLA: two users, both 200, same response shape
        if len(authed) >= 2:
            a, b = authed[0], authed[1]
            edge_pages = bool(getattr(a, "edge_denied", False)
                              or getattr(b, "edge_denied", False))
            if a.status == 200 and b.status == 200 and not edge_pages:
                if a.body_hash == b.body_hash and a.body_hash:
                    return ("strong_candidate",
                            f"identical response body across "
                            f"{a.name} and {b.name} — BOLA/IDOR candidate")
                if (a.key_shape and a.key_shape == b.key_shape
                        and a.length_bucket == b.length_bucket):
                    return ("strong_candidate",
                            f"same response shape across {a.name} and "
                            f"{b.name} — BOLA/IDOR candidate")
            elif edge_pages and a.status == 200 and b.status == 200:
                return ("inconclusive",
                        "both sessions served the same edge/bot-wall page; "
                        "the application was never reached")

        # Proper authz signal: user_a 200, user_b 4xx → healthy
        if len(authed) >= 2:
            a, b = authed[0], authed[1]
            if a.status == 200 and b.status in (401, 403):
                return ("inconclusive",
                        "authorization differential observed "
                        f"({a.name}={a.status}, {b.name}={b.status})")

        # Broken access: anonymous 200 on privileged endpoint
        if (anon is not None and anon.status == 200
                and res.endpoint_type in PRIVILEGED_TYPES
                and not getattr(anon, "edge_denied", False)):
            note = f"unauthenticated access to privileged endpoint " \
                   f"({res.endpoint_type})"
            if len(authed) >= 1 and authed[0].status == 200:
                note += " — same result as authenticated users"
            return ("strong_candidate", note)

        # anonymous 401/403 while an authed user gets 200 → auth works
        if anon is not None and anon.status in (401, 403):
            for a in authed:
                if a.status == 200:
                    return ("inconclusive",
                            "auth enforced; authorization not tested "
                            "(single authenticated context)")
        return ("inconclusive", "")
