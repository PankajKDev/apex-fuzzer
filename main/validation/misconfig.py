"""Passive misconfiguration detectors (read-only response analysis).

Two high-frequency writeup classes with cheap, safe signals:

- clickjacking: HTML responses without framing protections
  (X-Frame-Options or CSP frame-ancestors).
- CSRF exposure: state-changing forms without token-bearing fields.

Both yield informational candidates only — no impact is demonstrated
by a header or a form shape. Anything state-changing stays a manual
follow-up.
"""
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List

# hidden-field names that carry anti-CSRF tokens (substring match,
# lowercased). Deliberately narrow: generic "token" alone would flag
# OAuth/PWA fields that are not CSRF defenses.
_TOKEN_SUBSTRINGS = ("csrf", "xsrf", "_token", "authenticity_token",
                     "requestverificationtoken", "form_token",
                     "sectoken", "anticsrf", "nonce")

_FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.I | re.S)
_ATTR_RE = re.compile(r"""(\w+)\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)""")
_INPUT_RE = re.compile(r"<input\b([^>]*)>", re.I)
_STATE_CHANGING = ("POST", "PUT", "PATCH", "DELETE")


@dataclass
class HtmlForm:
    action: str = ""
    method: str = "GET"
    inputs: List[Dict[str, str]] = field(default_factory=list)

    def has_token(self) -> bool:
        for item in self.inputs:
            name = str(item.get("name", "") or "").lower()
            if any(marker in name for marker in _TOKEN_SUBSTRINGS):
                return True
        return False


def _attrs(tag: str) -> Dict[str, str]:
    out = {}
    for m in _ATTR_RE.finditer(tag or ""):
        value = m.group(2).strip("\"'")
        out[m.group(1).lower()] = value
    return out


def parse_forms(html: str) -> List[HtmlForm]:
    """Extract form actions/methods/inputs (bounded, fail-closed)."""
    forms = []
    try:
        text = html or ""
    except (TypeError, ValueError):
        return []
    for m in list(_FORM_RE.finditer(text))[:25]:
        attrs = _attrs(m.group(1))
        inputs = []
        for im in list(_INPUT_RE.finditer(m.group(2)))[:50]:
            iattrs = _attrs(im.group(0))
            if iattrs.get("name"):
                inputs.append({
                    "name": iattrs["name"][:120],
                    "type": iattrs.get("type", "text")[:40],
                })
        forms.append(HtmlForm(action=attrs.get("action", "")[:500],
                              method=(attrs.get("method", "GET") or
                                      "GET").upper(),
                              inputs=inputs))
    return forms


def _is_html(content_type: str) -> bool:
    ctype = str(content_type or "").lower()
    return "html" in ctype or "xhtml" in ctype


def _frame_ancestors(csp: str) -> str:
    for part in str(csp or "").split(";"):
        if part.strip().lower().startswith("frame-ancestors"):
            return part.strip()[:300]
    return ""


def check_clickjacking(headers, content_type: str,
                       url: str) -> Dict[str, Any]:
    """Framing-protection verdict for one response.

    Returns {protected, evidence, notes}. Non-HTML responses are out
    of scope for this check (None verdict).
    """
    if not _is_html(content_type or ""):
        return {"verdict": None, "notes": "non-HTML response"}
    get = {}
    try:
        for name, value in (headers or {}).items():
            get[str(name).lower()] = value
    except (AttributeError, TypeError):
        pass
    xfo = str(get.get("x-frame-options", "") or "").strip().upper()
    fa = _frame_ancestors(get.get("content-security-policy", ""))
    if fa:
        return {"verdict": "protected",
                "evidence": f"frame-ancestors: {fa}",
                "notes": "CSP frame-ancestors restricts framing"}
    if xfo in ("DENY", "SAMEORIGIN"):
        return {"verdict": "protected",
                "evidence": f"X-Frame-Options: {xfo}",
                "notes": "framing denied or same-origin only"}
    if xfo.startswith("ALLOW-FROM"):
        return {"verdict": "candidate",
                "evidence": f"X-Frame-Options: {xfo}",
                "notes": "ALLOW-FROM is obsolete and unevenly "
                         "enforced; treat as unprotected"}
    return {"verdict": "candidate",
            "evidence": "no X-Frame-Options or CSP frame-ancestors",
            "notes": f"HTML response at {url} sets no framing "
                     "protection"}


def forms_without_tokens(html: str) -> List[HtmlForm]:
    """State-changing forms lacking any token-bearing field."""
    return [f for f in parse_forms(html)
            if f.method in _STATE_CHANGING and not f.has_token()]


def check_csrf_forms(html: str, url: str) -> Dict[str, Any]:
    """CSRF-exposure verdict for one page body."""
    forms = parse_forms(html)
    mutating = [f for f in forms if f.method in _STATE_CHANGING]
    if not mutating:
        return {"verdict": None, "notes": "no state-changing forms",
                "forms": []}
    exposed = [f for f in mutating if not f.has_token()]
    if not exposed:
        return {"verdict": "protected",
                "notes": f"all {len(mutating)} state-changing form(s) "
                         "carry token fields",
                "forms": []}
    return {"verdict": "candidate",
            "notes": f"{len(exposed)}/{len(mutating)} state-changing "
                     f"form(s) without token fields at {url}",
            "forms": exposed}
