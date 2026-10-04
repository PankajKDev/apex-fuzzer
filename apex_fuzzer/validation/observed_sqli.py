"""Single observed-request selection and raw serialization for SQLi.

The browser pipeline retains exact request shapes at runtime on
``Endpoint.observed_requests`` (``{url, method, headers, post_data,
content_type, identity, ...}``). This helper lets the SQLi plugins reuse
one retained shape instead of rebuilding a request from URL templates.

Safety contract (bounded, fail-closed):

- one finding keeps one candidate parameter; the observed request is
  used only when that exact parameter is present in the retained shape;
- at most one sqlmap run per finding; never fan out across identities;
- the observed URL must match the candidate endpoint (same scheme, host,
  effective port, and path)
  and pass the provided scope's ``active_test_allowed`` check;
- only text-representable ``GET/POST/PUT/PATCH`` shapes are supported;
  multipart, binary/undecodable, oversized, or otherwise
  unrepresentable requests are unsupported (inconclusive, no send);
- ambiguous matches (several distinct requests/identities for one
  endpoint+parameter) fail closed with a documented reason;
- identity names flow into runtime/evidence metadata only; header/body
  values and credentials never leave the ephemeral 0600 raw file.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qsl, urlsplit


SUPPORTED_METHODS = {"GET", "POST", "PUT", "PATCH"}
_HOP_HEADERS = {"host", "content-length", "connection",
                "transfer-encoding"}
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_MAX_RAW_BODY_BYTES = 1_000_000


def _parse_url(url: Any) -> Optional[Any]:
    try:
        parts = urlsplit(str(url or ""))
    except (TypeError, ValueError):
        return None
    if parts.scheme.lower() not in ("http", "https"):
        return None
    if not parts.hostname or parts.username is not None or \
            parts.password is not None:
        return None
    try:
        _ = parts.port
    except ValueError:
        return None
    return parts


def _endpoint_key(url: str) -> Optional[Tuple[str, str, int, str]]:
    parts = _parse_url(url)
    if parts is None:
        return None
    scheme = parts.scheme.lower()
    port = parts.port or (443 if scheme == "https" else 80)
    return (scheme, (parts.hostname or "").lower(), port, parts.path or "/")


def _content_type_of(observed: Dict[str, Any]) -> str:
    for name, value in (observed.get("headers") or {}).items():
        if str(name).lower() == "content-type":
            return str(value)
    return str(observed.get("content_type") or "")


def _headers_signature(observed: Dict[str, Any]) -> Tuple[Tuple[str, str], ...]:
    headers = observed.get("headers") or {}
    if not isinstance(headers, dict):
        return (("[invalid headers]", repr(headers)),)
    return tuple(sorted((str(name).lower(), str(value))
                        for name, value in headers.items()))


def _supported_body_content_type(content_type: str) -> bool:
    media_type = (content_type or "").split(";", 1)[0].strip().lower()
    return (media_type == "application/x-www-form-urlencoded" or
            media_type == "application/json" or media_type.endswith("+json") or
            media_type in {"application/xml", "text/xml"} or
            media_type.endswith("+xml") or
            media_type == "multipart/form-data")


def _post_data_text(post_data: Any) -> Tuple[Optional[str], str]:
    """Return (text, reason). ``text`` is None when there is no body."""
    if post_data is None:
        return None, ""
    if isinstance(post_data, (bytes, bytearray)):
        raw = bytes(post_data)
        if len(raw) > _MAX_RAW_BODY_BYTES:
            return None, "observed body exceeds the local size limit"
        try:
            text = raw.decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            return None, "observed body is not UTF-8 text"
        if "\x00" in text:
            return None, "observed body is binary"
        return text, ""
    if isinstance(post_data, str):
        if len(post_data.encode("utf-8")) > _MAX_RAW_BODY_BYTES:
            return None, "observed body exceeds the local size limit"
        if "\x00" in post_data:
            return None, "observed body is binary"
        return post_data, ""
    return None, "observed body shape is unrepresentable"


def _body_has_parameter(content_type: str, body_text: Optional[str],
                        parameter: str) -> bool:
    if body_text is None or not body_text.strip():
        return False
    ctype = (content_type or "").lower()
    if "multipart/" in ctype:
        # text fields only: file parts, duplicates, and binary bodies
        # fail closed inside the multipart helper
        try:
            from .multipart import (multipart_field_value,
                                    boundary_from_content_type)
            boundary_from_content_type(content_type)
            multipart_field_value(body_text.encode("utf-8"), content_type,
                                  parameter)
        except (ValueError, TypeError, UnicodeEncodeError):
            return False
        return True
    if "json" in ctype:
        try:
            data = json.loads(body_text)
        except (ValueError, TypeError):
            return False
        return _json_has_path(data, parameter)
    if "xml" in ctype:
        try:
            from .request_shape import xml_body_parameter_value
            from types import SimpleNamespace
        except ImportError:
            return False
        probe = SimpleNamespace(request_body=body_text,
                                request_content_type=content_type)
        try:
            xml_body_parameter_value(probe, parameter)
        except ValueError:
            return False
        return True
    if ctype.split(";", 1)[0].strip() != \
            "application/x-www-form-urlencoded":
        return False
    pairs = parse_qsl(body_text, keep_blank_values=True)
    return any(name == parameter for name, _ in pairs)


def _json_has_path(data: Any, parameter: str) -> bool:
    import re
    parts = re.findall(r"[^.\[\]]+|\[\d*\]", parameter or "")
    if not parts:
        return False
    current: Any = data
    for raw in parts:
        if raw.startswith("["):
            if not isinstance(current, list):
                return False
            slot = raw[1:-1]
            pos = int(slot) if slot.isdigit() else 0
            if pos >= len(current):
                return False
            current = current[pos]
        else:
            if not isinstance(current, dict) or raw not in current:
                return False
            current = current[raw]
    return True


def _query_has_parameter(url: str, parameter: str) -> bool:
    try:
        query = urlsplit(url).query
    except (TypeError, ValueError):
        return False
    return any(name == parameter for name, _ in
               parse_qsl(query, keep_blank_values=True))


def _headers_have_parameter(entry: Dict[str, Any], parameter: str) -> bool:
    headers = entry.get("headers")
    if not isinstance(headers, dict):
        return False
    wanted = str(parameter or "").strip().lower()
    if not wanted:
        return False
    return any(isinstance(name, str) and name.strip().lower() == wanted
               for name in headers)


def _cookie_has_parameter(entry: Dict[str, Any], parameter: str) -> bool:
    try:
        from .request_shape import cookie_pairs
        pairs = cookie_pairs(entry.get("headers"))
    except (ValueError, TypeError):
        return False
    wanted = str(parameter or "").strip().lower()
    return any(name.lower() == wanted for name, _ in pairs)


def _valid_identity(value: Any) -> Optional[str]:
    if value is None:
        return "anonymous"
    text = str(value)
    if not text or len(text) > 200 or "\n" in text or "\r" in text:
        return None
    return text


def select_observed_request(endpoint: Any, parameter: Optional[str],
                            parameter_location: str = "query",
                            scope=None,
                            endpoint_url: str = "") -> Tuple[
                                Optional[Dict[str, Any]], str]:
    """Pick at most one retained request for one endpoint+parameter.

    Returns ``(request, reason)``. ``request`` is None unless exactly one
    distinct retained shape matches; ``reason`` documents the outcome
    without credential/body values. ``request`` is the original runtime
    dict (not a copy) so the caller can serialize it exactly once.
    """
    if not parameter:
        return None, "no candidate parameter was identified"
    observed = list(getattr(endpoint, "observed_requests", []) or [])
    if not observed:
        return None, "no observed requests were retained"
    target_url = endpoint_url or getattr(endpoint, "url", "") or ""
    target_key = _endpoint_key(target_url)
    if target_key is None:
        return None, "candidate endpoint URL is unrepresentable"
    location = (parameter_location or "query").lower()

    matches = []
    skipped_scope = 0
    skipped_shape = 0
    for entry in observed:
        if not isinstance(entry, dict):
            skipped_shape += 1
            continue
        req_url = entry.get("url")
        req_method = str(entry.get("method") or "GET").upper()
        if not isinstance(req_url, str) or _parse_url(req_url) is None:
            skipped_shape += 1
            continue
        if scope is not None:
            try:
                allowed = scope.active_test_allowed(req_url)
            except Exception:
                allowed = False
            if not allowed:
                skipped_scope += 1
                continue
        if _endpoint_key(req_url) != target_key:
            continue
        if req_method not in SUPPORTED_METHODS:
            skipped_shape += 1
            continue
        identity = _valid_identity(entry.get("identity", "anonymous"))
        if identity is None:
            skipped_shape += 1
            continue
        if location == "query":
            if not _query_has_parameter(req_url, parameter):
                continue
            if req_method == "GET":
                body_text, problem = _post_data_text(entry.get("post_data"))
                if problem:
                    skipped_shape += 1
                    continue
                if body_text:
                    skipped_shape += 1
                    continue
        elif location == "body":
            if req_method == "GET":
                if entry.get("post_data"):
                    skipped_shape += 1
                continue
            ctype = _content_type_of(entry)
            if not _supported_body_content_type(ctype):
                skipped_shape += 1
                continue
            body_text, problem = _post_data_text(entry.get("post_data"))
            if problem:
                skipped_shape += 1
                continue
            if not _body_has_parameter(ctype, body_text, parameter):
                continue
        elif location == "header":
            if not _headers_have_parameter(entry, parameter):
                continue
        elif location == "cookie":
            if not _cookie_has_parameter(entry, parameter):
                continue
        else:
            return None, f"parameter location {location!r} is not supported"
        matches.append(entry)

    if not matches:
        if skipped_shape:
            return None, (
                "unsupported observed request shape for this endpoint; "
                "fail closed without sending")
        detail = f"no matching observed request for parameter {parameter!r}"
        if skipped_scope:
            detail += f" ({skipped_scope} out-of-scope retained request(s))"
        return None, detail
    if len(matches) > 1:
        identities = {str(m.get("identity", "anonymous")) for m in matches}
        shapes = {(str(m.get("identity")), str(m.get("method")),
                   str(m.get("url")),
                   _content_type_of(m),
                   _headers_signature(m),
                   repr(m.get("post_data"))) for m in matches}
        if len(shapes) == 1:
            return matches[0], "matched one distinct observed request shape"
        return None, (
            "ambiguous observed requests: "
            f"{len(matches)} match(es) across {len(identities)} "
            "identit(ies); fail closed without guessing")
    return matches[0], "matched one observed request"


def serialize_observed_to_raw(observed: Dict[str, Any]) -> str:
    """Render one retained request as sqlmap ``-r`` file text.

    Raises ``ValueError`` with a safe (secret-free) reason when the
    request cannot be represented faithfully as text.
    """
    method = str(observed.get("method") or "GET").upper()
    if method not in SUPPORTED_METHODS:
        raise ValueError(f"unsupported observed method {method}")
    url = observed.get("url")
    parts = _parse_url(url)
    if parts is None:
        raise ValueError("observed URL is unrepresentable")
    headers = observed.get("headers") or {}
    if not isinstance(headers, dict):
        raise ValueError("observed headers are unrepresentable")
    clean: Dict[str, str] = {}
    for name, value in headers.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise ValueError("observed headers are unrepresentable")
        if not _HEADER_NAME_RE.fullmatch(name.strip()):
            raise ValueError("observed header name is unrepresentable")
        if "\r" in value or "\n" in value:
            raise ValueError("observed header value is unrepresentable")
        if name.strip().lower() in _HOP_HEADERS:
            continue
        clean[name.strip()] = value.strip()
    content_type = _content_type_of(observed)
    if "\r" in content_type or "\n" in content_type:
        raise ValueError("observed content type is unrepresentable")
    # multipart is supported only for text-only bodies: binary file
    # content fails UTF-8 decoding in _post_data_text above and never
    # reaches serialization
    body_text, problem = _post_data_text(observed.get("post_data"))
    if problem:
        raise ValueError(problem)
    body = body_text or ""
    if body and method != "GET" and not _supported_body_content_type(
            content_type):
        raise ValueError("observed body content type is unsupported")
    if method == "GET" and body:
        raise ValueError("GET body shape is unsupported")
    if "\x00" in body:
        raise ValueError("observed body is binary")

    host = (parts.hostname or "").lower()
    port = parts.port
    default_port = 443 if parts.scheme.lower() == "https" else 80
    host_header = host if not port or port == default_port else \
        f"{host}:{port}"
    path = parts.path or "/"
    target = path + (("?" + parts.query) if parts.query else "")
    lines = [f"{method} {target} HTTP/1.1", f"Host: {host_header}"]
    has_content_type = any(name.lower() == "content-type"
                           for name in clean)
    for name, value in clean.items():
        if name.lower() == "host":
            continue
        lines.append(f"{name}: {value}")
    if content_type and not has_content_type:
        lines.append(f"Content-Type: {content_type.strip()}")
    return "\r\n".join(lines) + "\r\n\r\n" + body


def sqlmap_args_for_raw(raw_file: str, parameter: str,
                        out_dir: str, time_based: bool = False,
                        time_sec: int = 2) -> list:
    """Low-risk sqlmap argv for a raw-request file (no enumeration).

    Boolean + error + UNION by default; time-based joins only under
    explicit opt-in (delay payloads hold DB connections open). Stacked
    queries stay excluded (possible writes).
    """
    args = [
        "sqlmap", "-r", raw_file, "--batch",
        "-p", parameter, "--level", "1", "--risk", "1",
        "--technique", "BEUT" if time_based else "BEU",
        f"--output-dir={out_dir}", "--timeout", "10",
        "--retries", "0", "--threads", "1",
    ]
    if time_based:
        args.extend(["--time-sec", str(max(1, min(int(time_sec), 10)))])
    return args


def redact_url(url: str) -> str:
    """Redact an endpoint URL for evidence/notes (no credentials)."""
    try:
        from ..models import _redact_url_values
        return _redact_url_values(url)
    except (ImportError, AttributeError, TypeError, ValueError):
        return "[INVALID URL]"
