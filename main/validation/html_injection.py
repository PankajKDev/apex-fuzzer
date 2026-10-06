"""HTML injection prescreen: inert structural tags, parse proof.

Sends unique inert tags (a block marker plus a link probe) and parses
the response HTML: the tag present as a real element proves tag
injection (phishing/defacement primitive); entity-encoded, stripped,
or absent tags with completed probes are genuine negatives. Script
execution is never attempted — that stays with the XSS engine.
Only presence as an element counts; text reflection alone proves
nothing.
"""
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qsl, urlsplit, urlunsplit, urlencode

from ..budgets import BudgetExceeded
from ..logging_setup import get_logger

log = get_logger("html-injection")

# .invalid never resolves: a reflected link proves injection without
# ever reaching an attacker host.
_PROBE_HOST = "apex-html.invalid"


class _TagCollector(HTMLParser):
    """Collect start tags with their attributes (script/style bodies
    arrive as data, never as tags — script context stays excluded)."""

    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.tags: List[Tuple[str, Dict[str, str]]] = []

    def handle_starttag(self, tag, attrs):
        try:
            self.tags.append((tag.lower(), {
                str(k).lower(): str(v or "") for k, v in attrs}))
        except (TypeError, ValueError, AttributeError):
            pass


def _probes(nonce: str) -> List[Tuple[str, str, Dict[str, str]]]:
    """(label, payload, expected element description)."""
    return [
        ("block",
         f"<apexhtml id=\"apex-{nonce}\">",
         {"tag": "apexhtml", "attr": "id", "value": f"apex-{nonce}"}),
        ("link",
         f"<a href=\"https://{_PROBE_HOST}/{nonce}\">apex</a>",
         {"tag": "a", "attr": "href",
          "value": f"https://{_PROBE_HOST}/{nonce}"}),
    ]


def _elements(body: str) -> List[Tuple[str, Dict[str, str]]]:
    collector = _TagCollector()
    try:
        collector.feed(body[:500_000])
        collector.close()
    except Exception:
        return []
    return collector.tags


def _element_present(text: str,
                     expected: Dict[str, str]) -> bool:
    """Our unique element parsed from the response HTML."""
    want_tag = str(expected.get("tag", ""))
    want_attr = str(expected.get("attr", ""))
    want_value = str(expected.get("value", ""))
    if not (want_tag and want_attr and want_value):
        return False
    for tag, attrs in _elements(text):
        if tag != want_tag:
            continue
        if attrs.get(want_attr, "") == want_value:
            return True
    return False


@dataclass
class HtmlProbeResult:
    url: str
    param: str
    verdict: str = "inconclusive"
    notes: str = ""
    status: int = 0
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"url": self.url, "param": self.param,
                "verdict": self.verdict, "notes": self.notes,
                "status": self.status, "evidence": dict(self.evidence)}


def check_html_injection(client, url: str, param: str,
                         timeout: int = 10) -> HtmlProbeResult:
    """Baseline GET plus one inert-tag GET per probe shape."""
    from ..validation.differential import normalize_response
    res = HtmlProbeResult(url=url, param=param)
    try:
        parts = urlsplit(url or "")
    except ValueError:
        res.notes = "URL is unrepresentable"
        return res
    if parts.scheme.lower() not in ("http", "https"):
        res.notes = "URL is not http(s)"
        return res
    try:
        query = parse_qsl(parts.query, keep_blank_values=True)
    except (TypeError, ValueError):
        res.notes = "query string is unparseable"
        return res
    if not any(key == param for key, _ in query):
        res.notes = f"parameter {param!r} not in query string"
        return res
    import secrets as _secrets
    nonce = _secrets.token_hex(4)
    urls = []
    for _, payload, _ in _probes(nonce):
        replaced = [(k, payload if k == param else v)
                    for k, v in query]
        urls.append(urlunsplit(
            (parts.scheme, parts.netloc, parts.path,
             urlencode(replaced, doseq=True), "")))
    try:
        r_base = client.get(url, timeout=timeout)
        probed = [client.get(target, timeout=timeout) for target in urls]
    except BudgetExceeded:
        raise
    except Exception as exc:
        res.notes = f"request failed: {exc}"[:200]
        return res
    if any(getattr(r, "status_code", 0) >= 500
           for r in [r_base] + probed):
        res.notes = "server error: no injection signal"
        return res
    try:
        base_norm = normalize_response(r_base)
    except Exception as exc:
        res.notes = f"response comparison failed: {exc}"[:200]
        return res
    res.status = int(base_norm.get("status", 0) or 0)
    for (label, _, expected), probe in zip(_probes(nonce), probed):
        text = getattr(probe, "text", "") or ""
        if _element_present(text, expected):
            res.verdict = "candidate"
            res.notes = (f"inert {label} tag injected via "
                         f"{param!r} parsed as an element")
            res.evidence = {"param": param, "shape": label,
                            "nonce": nonce}
            return res
    res.verdict = "negative"
    res.notes = (f"inert tags via {param!r} neutralized or not "
                 f"reflected ({res.status})")
    return res
