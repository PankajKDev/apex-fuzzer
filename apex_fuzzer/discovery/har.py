"""HAR import: first-party traffic captures → endpoint inventory.

Parses HAR 1.2 files (``log.entries[].request``) into the same entry
dicts the browser crawl produces (``{url, method, params, body,
observed_requests}``), so the existing pipeline merge, scope filter,
and observed-request consumers (sqlmap raw replay, write replay,
GraphQL replay) work unchanged.

Secrecy rules (HAR files carry real sessions):
- Cookie/Authorization headers are dropped from retained material.
- Body/query sample values are blanked (samples persist to
  ``endpoints.jsonl``); exact bytes stay runtime-only in
  ``observed_requests`` and are never written to artifacts.
- URL userinfo and fragments are stripped; oversized bodies (>1 MB)
  keep inventory (params) but no retained bytes (fail closed).

Import is inventory only: no request is sent and nothing is replayed.
"""
import json
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import parse_qsl, urlsplit
from ..logging_setup import get_logger
from ..browser.network import _SKIP_EXTS

log = get_logger("har")

# Identity carriers never enter retained request material.
_DROPPED_HEADERS = frozenset(
    {"cookie", "authorization", "proxy-authorization"})
_MAX_ENTRIES = 500
_MAX_OBSERVED_PER_GROUP = 10
_MAX_BODY_CHARS = 1_000_000


def load_har_file(path) -> Dict[str, Any] | None:
    """Read a HAR file; missing/invalid → None (caller logs the skip)."""
    try:
        return json.loads(Path(path).read_text(encoding="utf-8",
                                               errors="replace"))
    except (OSError, ValueError, UnicodeError) as e:
        log.debug("har unreadable %s: %s", path, e)
        return None


def _scrub_url(url: str) -> str:
    """Strip userinfo + fragment; unparseable → ''."""
    try:
        parts = urlsplit(url or "")
        netloc = parts.netloc.rsplit("@", 1)[-1]
        return parts._replace(netloc=netloc, fragment="").geturl()
    except (TypeError, ValueError):
        return ""


def _har_headers(pairs) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for item in pairs or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", ""))
        if not name or name.lower() in _DROPPED_HEADERS:
            continue
        out.setdefault(name, str(item.get("value", ""))[:2000])
    return out


def _query_names(url: str, query_string) -> List[str]:
    names: List[str] = []
    for item in query_string or []:
        if isinstance(item, dict) and item.get("name"):
            name = str(item["name"])
            if name and name not in names:
                names.append(name)
    if not names:
        try:
            for key, _ in parse_qsl(urlsplit(url).query,
                                    keep_blank_values=True):
                if key and key not in names:
                    names.append(key)
        except (TypeError, ValueError):
            pass
    return names


def _body_fields(post_data, headers: Dict[str, str]) -> Dict[str, str]:
    """Field names with blanked samples (provenance unknown)."""
    if not isinstance(post_data, dict):
        return {}
    ctype = str(post_data.get("mimeType", "") or "").lower()
    if not ctype:
        ctype = str(headers.get("Content-Type", "") or
                    headers.get("content-type", "")).lower()
    if "multipart/" in ctype:
        try:
            from ..browser.network import parse_multipart
            fields, _ = parse_multipart(post_data.get("text", ""),
                                        {"content-type": ctype})
            return fields
        except Exception:
            return {}
    if "json" in ctype:
        try:
            data = json.loads(post_data.get("text", "") or "{}")
            if isinstance(data, dict):
                return {str(k): "" for k in data.keys()}
        except (TypeError, ValueError):
            pass
        return {}
    try:
        text = post_data.get("text", "") or ""
        if not isinstance(text, str):
            return {}
        names = [k for k, _ in parse_qsl(text, keep_blank_values=True)
                 if k]
        return {name: "" for name in dict.fromkeys(names)}
    except (TypeError, ValueError):
        return {}


def parse_har(data: Dict[str, Any],
              scope=None,
              max_entries: int = _MAX_ENTRIES) -> List[Dict[str, Any]]:
    """HAR dict → browser-contract entry dicts (no network, no replay)."""
    entries: List[Dict[str, Any]] = []
    by_key: Dict[Any, Dict[str, Any]] = {}
    try:
        raw = (data or {}).get("log", {}).get("entries", [])
    except AttributeError:
        return []
    if not isinstance(raw, list):
        return []
    for item in raw:
        if len(entries) >= max_entries:
            break
        if not isinstance(item, dict):
            continue
        req = item.get("request") or {}
        if not isinstance(req, dict):
            continue
        url = _scrub_url(str(req.get("url", "")))
        if not url.startswith(("http://", "https://")):
            continue
        if scope is not None and not scope.is_in_scope(url):
            continue
        try:
            if urlsplit(url).path.lower().endswith(tuple(_SKIP_EXTS)):
                continue
        except (TypeError, ValueError):
            continue
        method = str(req.get("method", "GET") or "GET").upper()
        headers = _har_headers(req.get("headers"))
        params = _query_names(url, req.get("queryString"))
        post_data = req.get("postData") if isinstance(
            req.get("postData"), dict) else None
        body = _body_fields(post_data, headers)
        key = (method, url)
        entry = by_key.get(key)
        if entry is None:
            entry = {"url": url, "method": method, "params": [],
                     "body": {}, "observed_requests": [],
                     "source": ["har"]}
            by_key[key] = entry
            entries.append(entry)
        for name in params:
            if name not in entry["params"]:
                entry["params"].append(name)
        entry["body"].update(
            {k: v for k, v in body.items() if k not in entry["body"]})
        observed = entry["observed_requests"]
        if len(observed) >= _MAX_OBSERVED_PER_GROUP:
            continue
        text = (post_data or {}).get("text", "")
        if not isinstance(text, str):
            text = ""
        retained = text if len(text) <= _MAX_BODY_CHARS else None
        if text and retained is None:
            continue  # oversized: inventory kept, bytes dropped
        retained = retained or None
        seen = {(o.get("method"), o.get("post_data")) for o in observed}
        if (method, retained) in seen:
            continue
        try:
            status = int((item.get("response") or {}).get("status", 0))
        except (TypeError, ValueError):
            status = 0
        observed.append({
            "url": url, "method": method, "headers": headers,
            "post_data": retained or None,
            "content_type": str((post_data or {}).get("mimeType", "")),
            "multipart": [], "identity": "har",
            "resource_type": "", "status": status or None})
    return entries
