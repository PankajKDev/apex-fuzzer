"""Verbose-error and disclosing-header checks (informational).

Read-only GETs only: one fetch of the endpoint itself (response
headers) plus one fetch of a nonexistent child path (404-handler
error disclosure). Findings are informational candidates — error
text and banners aid fingerprinting but prove no exploitability.
Bodies are never persisted; evidence keeps marker families and
header names (plus truncated banner values, never secrets).
"""
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit

from ..logging_setup import get_logger

log = get_logger("info-disclosure")

# Stack-trace / debug-page families. Fixed marker strings label the
# evidence; raw response text is never kept.
_TRACE_FAMILIES = [
    ("python-traceback", r"traceback \(most recent call last\)"),
    ("java", r"nullpointerexception|\bat java\.|log4j"),
    ("dotnet", r"server error in '/' application|"
                r"system\.nullreferenceexception|"
                r"\bat system\."),
    ("php", r"fatal error:|parse error:|"
             r"\.php on line \d+|stack trace:|whoops"),
    ("ruby", r"actioncontroller::|\.rb:\d+:in"),
    ("node", r"referenceerror:|typeerror: |"
              r"\bat process\.|node\.js"),
    ("debug-page", r"django.*technical.*500|debug\s*=\s*true|"
                   r"debug mode|laravel.*whoops|xdebug"),
    ("generic-stack", r"stack trace|stacktrace|"
                       r"exception in thread"),
]
_TRACE_RES = [(family, re.compile(pattern, re.I))
              for family, pattern in _TRACE_FAMILIES]

# Headers whose presence discloses stack details.
_DISCLOSING_HEADERS = ("x-powered-by", "x-aspnet-version",
                       "x-aspnetmvc-version", "x-generator",
                       "x-runtime", "x-version")
_DEBUG_PREFIXES = ("x-debug", "x-profile", "x-drupal",
                   "x-varnish", "x-cache")

_VERSION_RE = re.compile(r"\d+\.\d+")


def check_verbose_error(body: str) -> Dict[str, Any]:
    """Stack-trace / debug-page / SQL-error disclosure in one body."""
    text = body or ""
    for family, rx in _TRACE_RES:
        if rx.search(text):
            return {"verdict": "candidate", "family": family,
                    "notes": f"{family} markers in error response"}
    try:
        from ..validation.mutate import sqli_error_families
        dbms = sqli_error_families(text)
    except Exception:
        dbms = []
    if dbms:
        return {"verdict": "candidate", "family": f"sql-{dbms[0]}",
                "notes": f"database error text ({dbms[0]}) in response"}
    return {"verdict": "negative", "family": "",
            "notes": "no error markers in response"}


def check_disclosing_headers(headers: Any) -> Dict[str, Any]:
    """Version banners and framework/debug headers."""
    get: Dict[str, str] = {}
    try:
        for name, value in (headers or {}).items():
            get[str(name).lower()] = str(value or "")
    except (AttributeError, TypeError):
        return {"verdict": "negative", "disclosures": [],
                "notes": "no headers to inspect"}
    disclosures: List[str] = []
    server = get.get("server", "")
    if server and _VERSION_RE.search(server):
        disclosures.append(f"server: {server[:120]}")
    for name in _DISCLOSING_HEADERS:
        if get.get(name, "").strip():
            disclosures.append(f"{name}: {get[name][:120]}")
    for name, value in get.items():
        if value.strip() and name.startswith(_DEBUG_PREFIXES):
            disclosures.append(f"{name}: {value[:120]}")
    if disclosures:
        return {"verdict": "candidate", "disclosures": disclosures,
                "notes": f"{len(disclosures)} disclosing header(s): "
                         f"{', '.join(d.split(':')[0] for d in disclosures)}"}
    return {"verdict": "negative", "disclosures": [],
            "notes": "no version banner or framework/debug headers"}


def not_found_child(url: str) -> Optional[str]:
    """A nonexistent child path of the URL (query dropped).

    Probes the 404 handler without touching parameters or sending
    anything the application could act on.
    """
    try:
        parts = urlsplit(url or "")
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or \
            not parts.hostname:
        return None
    path = (parts.path or "/").rstrip("/") + "/apex-nonexistent-probe"
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))
