"""Header-layer probes: Host override and CRLF injection.

Both send bounded read-only GETs and read the response — no state
changes, no redirect following, no cache writes. Findings need a
response-side effect (redirect target, split header), never a bare
reflection.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

from ..budgets import BudgetExceeded
from ..logging_setup import get_logger

log = get_logger("header-probe")

# .invalid never resolves: reflected occurrences prove server-side
# trust without ever reaching an attacker host.
EVIL_HOST = "attacker.invalid"
CRLF_MARKER = "x-apex-probe"
CRLF_TOKEN = "apex-crlf-probe"


@dataclass
class HeaderProbeResult:
    url: str
    check: str = ""
    # candidate | negative | inconclusive
    verdict: str = "inconclusive"
    notes: str = ""
    status: int = 0
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"url": self.url, "check": self.check,
                "verdict": self.verdict, "notes": self.notes,
                "status": self.status, "evidence": dict(self.evidence)}


def _headers_dict(response) -> Dict[str, str]:
    try:
        return {str(k): str(v) for k, v in
                (getattr(response, "headers", None) or {}).items()}
    except (AttributeError, TypeError):
        return {}


def check_host_override(client, url: str,
                        timeout: int = 10) -> HeaderProbeResult:
    """Override Host (and XFH) and watch redirect targets + body."""
    res = HeaderProbeResult(url=url, check="host-override")
    for header_name in ("Host", "X-Forwarded-Host"):
        try:
            r = client.get(url, headers={header_name: EVIL_HOST},
                           timeout=timeout)
        except BudgetExceeded:
            raise
        except Exception as e:
            res.notes = f"request failed: {e}"[:200]
            return res
        res.status = getattr(r, "status_code", 0) or 0
        headers = _headers_dict(r)
        location = ""
        for name, value in headers.items():
            if name.lower() == "location":
                location = value
                break
        if res.status in (301, 302, 303, 307, 308) and \
                EVIL_HOST in location:
            res.verdict = "candidate"
            res.notes = f"redirect target follows {header_name} " \
                        f"({location[:200]})"
            res.evidence = {"header": header_name,
                            "location": location[:500],
                            "status": res.status}
            return res
        text = str(getattr(r, "text", "") or "")
        if EVIL_HOST in text:
            res.notes = f"{header_name} reflected in response body " \
                        f"without redirect impact"
            res.evidence = {"header": header_name,
                            "reflected": True,
                            "status": res.status}
            # reflection alone proves no impact — keep looking at
            # the next header rather than claiming
            continue
    if res.verdict != "candidate" and not res.notes:
        res.verdict = "negative"
        res.notes = "override ignored: no redirect or reflection"
    elif res.verdict != "candidate":
        res.verdict = "inconclusive"
    return res


def crlf_probe_url(url: str, param: str) -> Optional[str]:
    """Rewrite one query parameter to a CRLF probe value."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    query = parse_qsl(parts.query, keep_blank_values=True)
    if not any(k == param for k, _ in query):
        return None
    marker = f"apex%0d%0a{CRLF_MARKER}%3A+{CRLF_TOKEN}"
    # NOTE: built without urlencode, which would double-encode the %
    # escapes into harmless literals server-side.
    others = urlencode([(k, v) for k, v in query if k != param],
                       doseq=True)
    sep = "&" if others else ""
    from urllib.parse import quote
    query_string = f"{others}{sep}{quote(param, safe='')}={marker}"
    return urlunsplit((parts.scheme, parts.netloc, parts.path,
                       query_string, ""))


def check_crlf(client, url: str, param: str,
               timeout: int = 10) -> HeaderProbeResult:
    """Inject a CRLF marker; a split response header confirms."""
    res = HeaderProbeResult(url=url, check="crlf")
    probe_url = crlf_probe_url(url, param)
    if probe_url is None:
        res.notes = f"parameter {param!r} not in query string"
        return res
    try:
        r = client.get(probe_url, timeout=timeout)
    except BudgetExceeded:
        raise
    except Exception as e:
        res.notes = f"request failed: {e}"[:200]
        return res
    res.status = getattr(r, "status_code", 0) or 0
    for name, value in _headers_dict(r).items():
        if name.lower() == CRLF_MARKER or CRLF_TOKEN in value:
            res.verdict = "candidate"
            res.notes = f"response splitting confirmed " \
                        f"({name}: {value[:200]})"
            res.evidence = {"header": name, "value": value[:500],
                            "status": res.status}
            return res
    if res.status >= 500:
        res.notes = f"HTTP {res.status}: error, no split observed"
        return res
    res.verdict = "negative"
    res.notes = "no split header in response"
    return res


def query_param_names(url: str) -> List[str]:
    try:
        return [k for k, _ in
                parse_qsl(urlsplit(url).query, keep_blank_values=True)
                if k]
    except ValueError:
        return []
