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

# redirect statuses compared as authorization signals (R)
_REDIRECT_STATUSES = (301, 302, 303, 307, 308)


def _location_path(location: str) -> str:
    """Redirect target path for cross-context comparison.

    Query strings carry per-session echoes, so only the path decides
    divergence. Empty when the target has no usable path.
    """
    try:
        from urllib.parse import urlsplit
        return urlsplit(location or "").path or ""
    except (TypeError, ValueError):
        return ""

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
    # Header signals (values never retained: cookie values and
    # tracing headers vary per session and may carry secrets).
    content_type: str = ""
    location: str = ""
    auth_markers: str = ""
    # Application-error disclosure + observed latency (R/E/T inputs).
    error_signature: str = ""
    elapsed_ms: float = 0.0


@dataclass
class DifferentialResult:
    url: str
    endpoint_type: str
    contexts: List[ContextResult] = field(default_factory=list)
    verdict: str = "inconclusive"
    notes: str = ""
    edge_denied: bool = False
    # Confirmation re-probe outcome (single-sample candidates stay
    # candidates but are never reported as confirmed without a repeat).
    confirmed: bool = False
    confirmation_notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "endpoint_type": self.endpoint_type,
            "verdict": self.verdict,
            "notes": self.notes,
            "edge_denied": self.edge_denied,
            "confirmed": self.confirmed,
            "confirmation_notes": self.confirmation_notes,
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


def _header_value(headers, wanted: str) -> str:
    try:
        for name, value in (headers or {}).items():
            if str(name).lower() == wanted and isinstance(value, str):
                return value
    except (AttributeError, TypeError):
        pass
    return ""


def _media_type(content_type: str) -> str:
    """Bare media type, lowercased, parameters stripped."""
    return str(content_type or "").split(";")[0].strip().lower()


def _auth_markers(headers) -> str:
    """Session-relevant header presence without values.

    Cookie names (sorted) plus a www-authenticate flag. Values are
    per-session volatile and may carry secrets — never retained.
    """
    try:
        items = list((headers or {}).items())
    except (AttributeError, TypeError):
        return ""
    names = set()
    challenged = False
    for name, value in items:
        low = str(name).lower()
        if low == "set-cookie" and isinstance(value, str):
            # cookie names only: values are per-session volatile and
            # may carry secrets. The lookahead keeps Expires dates
            # (which contain commas) from splitting pairs apart.
            for m in re.finditer(
                    r"(?:^|,)\s*([A-Za-z0-9!#$%&'*+\-.^_`|~]+)=",
                    value):
                names.add(m.group(1))
        elif low == "www-authenticate":
            challenged = True
    bits = sorted(n for n in names if n)
    if challenged:
        bits.append("www-authenticate")
    return ",".join(bits)


# Application-error disclosure markers (family, substring). Narrow by
# design: framework tracebacks and debug pages, not generic words
# like "error" that appear in healthy copy. A match labels the
# response; asymmetry across contexts is the signal, never the marker
# alone.
_APP_ERROR_MARKERS = (
    ("python-traceback", "traceback (most recent call last)"),
    ("java-stack", ".java:"),
    ("java-exception", "exception in thread"),
    ("dotnet-error", "server error in '/' application"),
    ("dotnet-exception", "system.web.httpexception"),
    ("php-fatal", "fatal error"),
    ("php-warning", ".php on line"),
    ("django-debug", "django debug"),
    ("laravel-debug", "whoops, looks like something went wrong"),
    ("sql-error", "sqlstate"),
    ("sql-error", "syntax error"),
    ("sql-error", "ora-"),
    ("sql-error", "pg::"),
    ("stack-trace", "stack trace"),
)


def _app_error_signature(text: str) -> str:
    """Framework-error family disclosed in a body, or "".

    Case-insensitive substring match over the first 8KB. Returns the
    family label for evidence; the differential (one context leaks,
    the other does not) is evaluated by the caller.
    """
    try:
        sample = (text or "")[:8192].lower()
    except (TypeError, ValueError):
        return ""
    for family, marker in _APP_ERROR_MARKERS:
        if marker in sample:
            return family
    return ""


def normalize_response(r) -> Dict[str, Any]:
    """Status + sorted JSON keys + length bucket + body hash + headers."""
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
    headers = getattr(r, "headers", None)
    return {
        "status": r.status_code,
        "length": length,
        "length_bucket": length // LENGTH_BUCKET,
        "key_shape": shape,
        "body_hash": body_hash,
        "content_type": _media_type(_header_value(headers,
                                                  "content-type")),
        "location": _header_value(headers, "location")[:2000],
        "auth_markers": _auth_markers(headers),
        "error_signature": _app_error_signature(body),
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


def _known_ct_mismatch(a, b) -> bool:
    """True when both content types are known and differ.

    Missing data never vetoes: header-dropping proxies exist, and a
    missing signal must not erase a shape match.
    """
    ca = getattr(a, "content_type", "") or ""
    cb = getattr(b, "content_type", "") or ""
    return bool(ca and cb and ca != cb)


def _anon_html_vs_authed_api(anon, authed) -> bool:
    """Anonymous HTML 200 against authenticated API content.

    The classic login-wall shadow: the app serves its login page with
    200 to anonymous users while test users receive real API bodies.
    Only fires on positive evidence (an authed non-HTML content type);
    unknown types never veto.
    """
    act = getattr(anon, "content_type", "") or ""
    if "html" not in act:
        return False
    for a in authed or []:
        ct = getattr(a, "content_type", "") or ""
        if ct and "html" not in ct:
            return True
    return False


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

    def _fetch_one(self, url: str, ctx, timeout: int) -> ContextResult:
        import time as _time
        cr = ContextResult(name=ctx["name"])
        try:
            _t0 = _time.perf_counter()
            r = self.http.get(url, headers=ctx["headers"],
                              timeout=timeout)
            cr.elapsed_ms = (_time.perf_counter() - _t0) * 1000.0
            n = normalize_response(r)
            cr.status = n["status"]
            cr.length = n["length"]
            cr.length_bucket = n["length_bucket"]
            cr.key_shape = n["key_shape"]
            cr.body_hash = n["body_hash"]
            cr.content_type = n["content_type"]
            cr.location = n["location"]
            cr.auth_markers = n["auth_markers"]
            cr.error_signature = n["error_signature"]
            try:
                cr.edge_denied = looks_like_edge_deny(
                    r.status_code, r.text or "",
                    getattr(r, "headers", None))
            except Exception:
                cr.edge_denied = False
        except BudgetExceeded:
            # budget/gate exhaustion is infrastructure, never a
            # negative — propagate so the caller records BLOCKED
            raise
        except Exception as e:
            cr.error = str(e)[:200]
        return cr

    def probe(self, url: str, endpoint_type: str = "unknown",
              timeout: int = 10) -> DifferentialResult:
        res = DifferentialResult(url=url, endpoint_type=endpoint_type)
        for ctx in self.contexts:
            res.contexts.append(self._fetch_one(url, ctx, timeout))
        res.verdict, res.notes = self.evaluate(res)
        if res.verdict == "strong_candidate":
            self._confirm(res, timeout)
        return res

    def _confirm(self, res: DifferentialResult, timeout: int) -> None:
        """One confirmation pass over the same contexts.

        A completed contradictory repeat downgrades to inconclusive
        (single-sample dynamics: A/B tests, timestamps, balancer
        variance). A repeat that cannot run (budget/gate) keeps the
        candidate as single-sample evidence — an inconclusive tool
        never erases a candidate.
        """
        repeat = DifferentialResult(url=res.url,
                                    endpoint_type=res.endpoint_type)
        try:
            for ctx in self.contexts:
                repeat.contexts.append(
                    self._fetch_one(res.url, ctx, timeout))
        except BudgetExceeded as e:
            res.confirmed = False
            res.confirmation_notes = (
                f"single-sample: confirmation blocked ({e})")
            res.notes += f" [{res.confirmation_notes}]"
            return
        verdict, notes = self.evaluate(repeat)
        if verdict == "strong_candidate":
            res.confirmed = True
            res.confirmation_notes = (
                "candidate reproduced on confirmation repeat (2/2 runs)")
        else:
            res.confirmed = False
            res.confirmation_notes = (
                f"confirmation repeat disagreed ({notes or verdict}); "
                f"single-sample dynamics suspected")
            res.verdict, res.notes = ("inconclusive",
                                      f"{res.notes} "
                                      f"[{res.confirmation_notes}]")

    @staticmethod
    def evaluate(res: DifferentialResult) -> Tuple[str, str]:
        by_name = {c.name: c for c in res.contexts}
        anon = by_name.get("anonymous")
        authed = [c for c in res.contexts if c.name != "anonymous"]

        # Incomplete data is never a negative: errored contexts mean
        # the comparison did not run, not that authorization held.
        failed = [c.name for c in res.contexts if c.error]
        if failed:
            return ("inconclusive",
                    f"incomplete contexts ({', '.join(failed)}); "
                    f"comparison did not run")

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
                    # byte-identical bodies expose the same data no
                    # matter what the headers claim
                    return ("strong_candidate",
                            f"identical response body across "
                            f"{a.name} and {b.name} — BOLA/IDOR candidate")
                if (a.key_shape and a.key_shape == b.key_shape
                        and a.length_bucket == b.length_bucket):
                    if _known_ct_mismatch(a, b):
                        return ("inconclusive",
                                f"same response shape across {a.name} and "
                                f"{b.name} but content types diverge "
                                f"({a.content_type or '?'} vs "
                                f"{b.content_type or '?'}); shadowing or "
                                f"negotiation suspected, not proven access")
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

        # Differential error disclosure (E): same status, exactly one
        # side leaks a framework error signature.
        if len(authed) >= 2:
            a, b = authed[0], authed[1]
            edge = bool(getattr(a, "edge_denied", False)
                        or getattr(b, "edge_denied", False))
            siga = getattr(a, "error_signature", "") or ""
            sigb = getattr(b, "error_signature", "") or ""
            if (a.status == b.status and a.status and not edge
                    and bool(siga) != bool(sigb)):
                leaker, sig = (a, siga) if siga else (b, sigb)
                other = b if leaker is a else a
                return ("strong_candidate",
                        f"differential error disclosure: {leaker.name} "
                        f"leaks {sig} (HTTP {leaker.status}) while "
                        f"{other.name} does not")

        # Authorization redirect divergence (R): both sessions
        # redirected, but to different paths (login vs resource).
        if len(authed) >= 2:
            a, b = authed[0], authed[1]
            if (a.status in _REDIRECT_STATUSES
                    and b.status in _REDIRECT_STATUSES
                    and not getattr(a, "edge_denied", False)
                    and not getattr(b, "edge_denied", False)):
                pa = _location_path(getattr(a, "location", ""))
                pb = _location_path(getattr(b, "location", ""))
                if pa and pb and pa != pb:
                    return ("strong_candidate",
                            f"authorization redirect divergence: "
                            f"{a.name} → {pa}, {b.name} → {pb}")

        # Broken access: anonymous 200 on privileged endpoint
        if (anon is not None and anon.status == 200
                and res.endpoint_type in PRIVILEGED_TYPES
                and not getattr(anon, "edge_denied", False)):
            if _anon_html_vs_authed_api(anon, authed):
                return ("inconclusive",
                        "anonymous 200 is an HTML page while "
                        "authenticated contexts receive API content — "
                        "login-wall shadowing, not proven access")
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
        # anonymous redirected while an authed user gets 200 → the
        # login wall holds at redirect level (healthy, not a gap)
        anon_location = anon.location if anon is not None else ""
        if anon is not None and anon.status in _REDIRECT_STATUSES \
                and anon_location:
            for a in authed:
                if a.status == 200:
                    return ("inconclusive",
                            "anonymous redirected to login wall while "
                            "authenticated users proceed; auth enforced "
                            "at redirect")
        return ("inconclusive", "")
