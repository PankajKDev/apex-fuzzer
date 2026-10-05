"""Storage capture: cookies, web storage, token extraction (Phase 1).

Pure helpers (unit-testable without a browser) plus a thin capture
layer over a Playwright context/page. Extracted material feeds
sessions.py, which turns it into HTTP-client credentials.
"""
import re
from typing import Any, Dict, List, Tuple
from ..logging_setup import get_logger

log = get_logger("browser-storage")

_JWT_RE = re.compile(
    r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")
_BEARER_RE = re.compile(r"[Bb]earer\s+([A-Za-z0-9_\-\.~+/=]{12,})")
_CSRF_COOKIE_HINT = re.compile(r"csrf|xsrf", re.I)
_CSRF_META_NAMES = {"csrf-token", "csrf_token", "xsrf-token", "_csrf",
                    "__csrf"}


def cookies_to_dict(cookies: List[Dict[str, Any]]) -> Dict[str, str]:
    return {c.get("name", ""): c.get("value", "")
            for c in cookies or [] if c.get("name")}


def build_cookie_header(cookies: List[Dict[str, Any]]) -> str:
    return "; ".join(f"{k}={v}" for k, v in
                     cookies_to_dict(cookies).items())


def parse_storage_state(state: Dict[str, Any]
                        ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Split a Playwright storage_state into (cookies, origins)."""
    state = state or {}
    return list(state.get("cookies") or []), {
        o.get("origin", ""): o for o in (state.get("origins") or [])
        if isinstance(o, dict)}


def _scan_text(text: str, found: Dict[str, List[str]]):
    if not isinstance(text, str) or not text:
        return
    for m in _JWT_RE.finditer(text):
        if m.group(0) not in found["jwt"]:
            found["jwt"].append(m.group(0))
    for m in _BEARER_RE.finditer(text):
        if m.group(1) not in found["bearer"]:
            found["bearer"].append(m.group(1))


def extract_tokens(cookies: List[Dict[str, Any]],
                   local_storage: Dict[str, str] | None = None,
                   session_storage: Dict[str, str] | None = None,
                   html: str = "") -> Dict[str, List[str]]:
    """Find JWT / bearer / CSRF material across all client stores."""
    found: Dict[str, List[str]] = {"jwt": [], "bearer": [], "csrf": []}
    for c in cookies or []:
        name, val = c.get("name", ""), c.get("value", "")
        _scan_text(val, found)
        if _CSRF_COOKIE_HINT.search(name) and val:
            found["csrf"].append(f"{name}={val[:60]}")
    for store in (local_storage or {}, session_storage or {}):
        for k, v in store.items():
            _scan_text(f"{k}={v}", found)
    _scan_text(html or "", found)
    return found


def extract_csrf_from_html(html: str) -> List[str]:
    """CSRF tokens from <meta> tags and hidden inputs (pure helper)."""
    out: List[str] = []
    for m in re.finditer(
            r'<meta\b[^>]*?\bname\s*=\s*["\']([^"\']+)["\'][^>]*?'
            r"\bcontent\s*=\s*[\"']([^\"']+)[\"']", html or "", re.I):
        if m.group(1).lower() in _CSRF_META_NAMES and m.group(2):
            out.append(m.group(2))
    for m in re.finditer(
            r'<input\b[^>]*?\bname\s*=\s*["\']([^"\']*(?:csrf|token)[^"\']*)'
            r'["\'][^>]*?\bvalue\s*=\s*["\']([^"\']+)["\']',
            html or "", re.I):
        out.append(m.group(2))
    return out


def read_web_storage(page) -> Dict[str, Dict[str, str]]:
    """Dump localStorage + sessionStorage of the page's origin."""
    out = {"local_storage": {}, "session_storage": {}}
    try:
        out["local_storage"] = dict(page.evaluate(
            "() => Object.assign({}, window.localStorage)") or {})
    except Exception as e:
        log.debug("localStorage read failed: %s", e)
    try:
        out["session_storage"] = dict(page.evaluate(
            "() => Object.assign({}, window.sessionStorage)") or {})
    except Exception as e:
        log.debug("sessionStorage read failed: %s", e)
    return out


class StorageCapture:
    """Capture everything a context knows, in one call."""

    def capture(self, context, page=None) -> Dict[str, Any]:
        try:
            cookies = list(context.cookies() or [])
        except Exception as e:
            log.debug("cookie capture failed: %s", e)
            cookies = []
        stores = {"local_storage": {}, "session_storage": {}}
        html = ""
        if page is not None:
            stores = read_web_storage(page)
            try:
                html = page.content() or ""
            except Exception as e:
                log.debug("page content read failed: %s", e)
        try:
            state = context.storage_state() or {}
        except Exception as e:
            log.debug("storage_state export failed: %s", e)
            state = {}
        tokens = extract_tokens(cookies, stores["local_storage"],
                                stores["session_storage"], html)
        tokens["csrf"].extend(t for t in extract_csrf_from_html(html)
                              if t not in tokens["csrf"])
        return {"cookies": cookies,
                "cookie_header": build_cookie_header(cookies),
                "local_storage": stores["local_storage"],
                "session_storage": stores["session_storage"],
                "tokens": tokens,
                "storage_state": state}
