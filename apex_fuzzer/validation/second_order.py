"""Stored-XSS correlation (bounty item #3).

Two-phase workflow with a full chain of evidence:

    inject canary → discover render points → classify context → finding

The canary carries an *inert* unknown tag (``<axsl>``) — if it survives
unescaped into a render point, HTML injection is proven without ever
persisting a working payload. Context classification:

- inside ``<script>`` / event-handler attribute / ``javascript:`` URI
  → dangerous sink;
- raw ``<axsl>`` in HTML → unescaped reflection (candidate);
- only ``&lt;axsl&gt;`` present → properly encoded (negative).

Per §57 a reflected marker alone is never XSS; a *stored* marker that
survives encoding into an active sink is a strong candidate with the
inject request and the render snippet attached.
"""
import random
import re
import string
from dataclasses import dataclass, field
from typing import Any, Dict, List
from ..budgets import BudgetExceeded
from ..logging_setup import get_logger

log = get_logger("second_order")

INERT_TAG = "axsl"

_SCRIPT_RE = re.compile(r"<script\b[^>]*>(.*?)</script>",
                        re.I | re.S)


def make_canary() -> str:
    rand = "".join(random.choice(string.ascii_lowercase + string.digits)
                   for _ in range(6))
    return f"ax{rand}<{INERT_TAG}>ax"


def second_order_ssrf_candidates(endpoint, max_fields: int = 3):
    """Return (location, parameter, score, rationale) sink candidates."""
    from .oast import ssrf_candidate_score
    locations = ("body_parameters", "query_parameters", "header_parameters")
    candidates = []
    for attr in locations:
        location = attr.removesuffix("_parameters")
        for param in list(getattr(endpoint, attr, []) or []):
            score, rationale = ssrf_candidate_score(param, endpoint)
            if score:
                candidates.append((location, param, score, rationale))
    candidates.sort(key=lambda row: (-row[2], locations.index(
        row[0] + "_parameters"), row[1].name.lower()))
    return candidates[:max(0, max_fields)]


def second_order_ssrf_fields(endpoint, max_fields: int = 3):
    """Compatibility helper returning only selected parameter objects."""
    return [candidate[1] for candidate in
            second_order_ssrf_candidates(endpoint, max_fields)]


def make_ssrf_canary(callback_host: str) -> str:
    """Build a unique callback URL under the registered OAST hostname."""
    from urllib.parse import urlsplit
    parsed = urlsplit("//" + (callback_host or ""))
    host = parsed.hostname or ""
    parts = host.split(".", 1)
    if len(parts) != 2 or not all(parts):
        raise ValueError("callback host is empty")
    rand = "".join(random.choice(string.ascii_lowercase + string.digits)
                   for _ in range(10))
    # Keep the provider's registered correlation label first; Interactsh
    # supports a per-interaction nonce as the following DNS label.
    unique_host = f"{parts[0]}.so{rand}.{parts[1]}"
    return f"http://{unique_host}/stored/{rand}"


def classify_context(html: str, canary: str) -> Dict[str, Any]:
    """Decide whether a stored canary is exploitable where rendered."""
    raw_tag = f"<{INERT_TAG}>"
    if raw_tag in html:
        for m in _SCRIPT_RE.finditer(html):
            if raw_tag in m.group(1):
                return {"dangerous": True, "context": "script",
                        "detail": "canary inside <script> block"}
        # enclosing-tag analysis for each occurrence
        for m in re.finditer(re.escape(raw_tag), html):
            tag_start = html.rfind("<", 0, m.start())
            tag_end = html.find(">", m.end())
            if tag_start < 0 or tag_end < m.end():
                continue
            tag_text = html[tag_start:tag_end]
            if re.search(r"\bon\w+\s*=", tag_text, re.I):
                return {"dangerous": True, "context": "event_handler",
                        "detail": "canary inside an event-handler attribute"}
            if re.search(r"(?:href|src|xlink:href)\s*=\s*[\"']?\s*"
                         r"javascript:", tag_text, re.I):
                return {"dangerous": True, "context": "javascript_uri",
                        "detail": "canary inside a javascript: URI"}
        return {"dangerous": True, "context": "raw_html",
                "detail": "canary reflected unescaped in HTML"}
    if f"&lt;{INERT_TAG}&gt;" in html or \
            f"&lt;{INERT_TAG}" in html:
        return {"dangerous": False, "context": "encoded",
                "detail": "canary HTML-entity-encoded"}
    return {"dangerous": False, "context": "absent",
            "detail": "canary not present in response"}


@dataclass
class InjectionResult:
    endpoint_url: str
    identity: str
    canary: str
    fields: List[str] = field(default_factory=list)
    status: int = 0
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"endpoint_url": self.endpoint_url,
                "identity": self.identity, "canary": self.canary,
                "fields": self.fields, "status": self.status,
                "notes": self.notes}


@dataclass
class RenderHit:
    render_url: str
    inject_url: str
    context: str
    detail: str
    snippet: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"render_url": self.render_url,
                "inject_url": self.inject_url, "context": self.context,
                "detail": self.detail, "snippet": self.snippet[:2000]}


def inject_canary(http, endpoint, identity_headers: Dict[str, str],
                  identity_name: str, timeout: int = 10) -> InjectionResult:
    """POST a form with the canary in every body parameter."""
    canary = make_canary()
    params = list(getattr(endpoint, "body_parameters", []) or [])
    if not params:
        return InjectionResult(endpoint_url=endpoint.url,
                               identity=identity_name, canary=canary,
                               notes="no body parameters to inject")
    data = {p.name: canary for p in params if p.name}
    try:
        r = http.post(endpoint.url, data=data, headers=identity_headers,
                      timeout=timeout)
        status = r.status_code
        notes = f"POST {len(data)} fields, HTTP {status}"
    except BudgetExceeded:
        raise
    except Exception as e:
        return InjectionResult(
            endpoint_url=endpoint.url, identity=identity_name,
            canary=canary, fields=sorted(data),
            notes=f"inject failed: {e}"[:200])
    return InjectionResult(endpoint_url=endpoint.url,
                           identity=identity_name, canary=canary,
                           fields=sorted(data), status=status, notes=notes)


def find_renders(http, render_urls: List[str], canary: str,
                 inject_url: str, timeout: int = 10) -> List[RenderHit]:
    """GET render candidates, classify every canary occurrence."""
    hits: List[RenderHit] = []
    for url in render_urls:
        try:
            r = http.get(url, timeout=timeout)
        except BudgetExceeded:
            raise
        except Exception as e:
            log.debug("render fetch %s failed: %s", url, e)
            continue
        if r.status_code != 200 or not r.text:
            continue
        verdict = classify_context(r.text, canary)
        if verdict["context"] == "absent":
            continue
        idx = r.text.find(f"<{INERT_TAG}>")
        if idx < 0:
            idx = r.text.find(canary[:8])
        start = max(0, idx - 300)
        hits.append(RenderHit(
            render_url=url, inject_url=inject_url,
            context=("dangerous:" + verdict["context"]
                     if verdict["dangerous"]
                     else verdict["context"]),
            detail=verdict["detail"],
            snippet=r.text[start:start + 900]))
        if verdict["dangerous"]:
            log.info("stored XSS: canary from %s renders %s at %s",
                     inject_url, verdict["context"], url)
    return hits
