"""Network interception + request recording (Phase 1).

Attaches to a Playwright page (or context) and records every HTTP
request/response plus WebSocket URLs. `to_endpoints()` converts the
recording into endpoint dicts the existing pipeline merges like any
other discovery source — no separate endpoint database.
"""
import time
import hashlib
import re
from dataclasses import dataclass, field
from email.parser import BytesParser
from email.policy import default as _email_policy
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from ..logging_setup import get_logger

log = get_logger("browser-net")

_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
_SECRET_FIELD = re.compile(
    r"(?:authorization|cookie|token|secret|password|api[-_]?key|csrf|session)",
    re.I)
_SKIP_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
              ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp4", ".webm",
              ".mp3", ".wav", ".css", ".map"}


@dataclass
class RecordedRequest:
    url: str
    method: str
    headers: Dict[str, str] = field(default_factory=dict)
    # Exact observed bytes when the browser exposes a buffer (multipart
    # file uploads); otherwise the observed text. Runtime-only.
    post_data: Any = None
    resource_type: str = ""
    status: Optional[int] = None
    timestamp: float = 0.0
    identity: str = "anonymous"

    def _multipart_parts(self) -> List[Dict[str, Any]]:
        if not is_multipart_content(self.headers or {}):
            return []
        _, parts = parse_multipart(self.post_data, self.headers or {})
        return parts

    def runtime_dict(self) -> Dict[str, Any]:
        """Exact observed request, retained only in memory for scan logic."""
        return {"url": self.url, "method": self.method,
                "headers": dict(self.headers), "post_data": self.post_data,
                "content_type": _header(self.headers, "content-type"),
                "multipart": self._multipart_parts(),
                "identity": self.identity,
                "resource_type": self.resource_type, "status": self.status}

    def to_dict(self) -> Dict[str, Any]:
        """Persist safe shape metadata without bodies or secret values."""
        headers = {key: ("[REDACTED]" if _SECRET_FIELD.search(key) else value)
                   for key, value in self.headers.items()}
        body = _body_bytes(self.post_data)
        return {"url": safe_artifact_url(self.url), "method": self.method,
                "headers": headers, "post_data": None,
                "post_data_length": len(body),
                "multipart": self._multipart_parts(),
                "resource_type": self.resource_type, "status": self.status,
                "timestamp": self.timestamp, "identity": self.identity}


def _header(headers: Dict[str, str], wanted: str) -> str:
    for name, value in (headers or {}).items():
        if str(name).lower() == wanted.lower():
            return str(value)
    return ""


def safe_artifact_url(url: str) -> str:
    try:
        parts = urlsplit(url)
        # Userinfo and fragments can carry credentials too. Strip both from
        # persisted artifacts; fragments are not sent to the server anyway.
        netloc = parts.netloc.rsplit("@", 1)[-1]
        query = [(key, "[REDACTED]" if _SECRET_FIELD.search(key) else value)
                 for key, value in
                 parse_qsl(parts.query, keep_blank_values=True)]
        return urlunsplit((parts.scheme, netloc, parts.path,
                           urlencode(query, doseq=True), ""))
    except (TypeError, ValueError):
        return "[INVALID URL]"


class NetworkRecorder:
    def __init__(self, scope=None, max_requests: int = 5000,
                 identity: str = "anonymous"):
        self.scope = scope
        self.max_requests = max_requests
        self.identity = identity or "anonymous"
        self.requests: List[RecordedRequest] = []
        self.websockets: List[str] = []
        self.navigations: List[str] = []
        self.redirects: List[List[str]] = []

    # ── playwright hooks ─────────────────────────────────────────────
    def attach(self, page_or_context):
        page_or_context.on("request", self._on_request)
        page_or_context.on("response", self._on_response)
        try:
            page_or_context.on("websocket", self._on_websocket)
        except Exception:
            pass  # older bindings may lack the event on some targets

    def _on_request(self, request):
        try:
            url = request.url
        except Exception:
            return
        if len(self.requests) >= self.max_requests:
            return
        try:
            headers = dict(request.headers or {})
        except Exception:
            headers = {}
        post_data = None
        try:
            buffered = getattr(request, "post_data_buffer", None)
            if callable(buffered):
                buffered = buffered()
            if isinstance(buffered, (bytes, bytearray)):
                post_data = bytes(buffered)
            else:
                post_data = request.post_data
        except Exception:
            try:
                post_data = request.post_data
            except Exception:
                post_data = None
        self.requests.append(RecordedRequest(
            url=url, method=(request.method or "GET").upper(),
            headers=headers, post_data=post_data,
            resource_type=getattr(request, "resource_type", "") or "",
            timestamp=time.time(), identity=self.identity))

    def _on_response(self, response):
        try:
            url, status = response.url, response.status
        except Exception:
            return
        for rec in reversed(self.requests[-50:]):
            if rec.url == url and rec.status is None:
                rec.status = status
                break

    def _on_websocket(self, ws):
        try:
            url = ws.url
        except Exception:
            return
        if url and url not in self.websockets:
            self.websockets.append(url)
            log.debug("websocket discovered: %s", url)

    # ── conversion into the existing endpoint pipeline ───────────────
    def to_endpoints(self) -> List[Dict[str, Any]]:
        """Recorded traffic → [{url, method, params}] for pipeline merge.

        Only in-scope http(s) URLs; static-asset noise dropped. POST
        form bodies are parsed into body params. Multipart bodies
        contribute field names only: file contents are never stored and
        no multipart request is replayed here.
        """
        from ..discovery.url_normalizer import normalize_url  # noqa
        out: List[Dict[str, Any]] = []
        by_key = {}
        seen_requests = set()
        for rec in self.requests:
            if not rec.url.startswith(("http://", "https://")):
                continue
            if self.scope is not None and \
                    not self.scope.is_in_scope(rec.url):
                continue
            path = urlsplit(rec.url).path.lower()
            if any(path.endswith(e) for e in _SKIP_EXTS):
                continue
            key = (rec.method, rec.url.split("#", 1)[0])
            entry = by_key.get(key)
            if entry is None:
                entry = {"url": rec.url, "method": rec.method,
                         "params": [], "body": {}, "observed_requests": []}
                by_key[key] = entry
                out.append(entry)
            if rec.method in _SAFE_METHODS:
                entry["params"] = list(dict.fromkeys(
                    entry["params"] + _query_names(rec.url)))
            elif rec.post_data:
                body_fields = _form_names(rec.post_data, rec.headers)
                if rec.identity != "anonymous":
                    body_fields = {name: "" for name in body_fields}
                entry["body"].update(body_fields)
            body_hash = hashlib.sha256(
                _body_bytes(rec.post_data)
            ).hexdigest()
            request_key = (rec.identity, rec.method, rec.url, body_hash)
            identity_count = sum(
                1 for request in entry["observed_requests"]
                if request.get("identity") == rec.identity)
            if request_key not in seen_requests and \
                    identity_count < 10:
                entry["observed_requests"].append(rec.runtime_dict())
                seen_requests.add(request_key)
        log.info("network: %d requests → %d endpoints (%d websockets)",
                 len(self.requests), len(out), len(self.websockets))
        return out

    def to_dict(self) -> Dict[str, Any]:
        return {"requests": [r.to_dict() for r in self.requests],
                "websockets": list(self.websockets),
                "navigations": list(self.navigations)}


def authenticated_capture_request_allowed(method: str, request_url: str,
                                          navigation_url: str,
                                          scope=None) -> bool:
    """Allow only read methods to the in-scope origin being crawled."""
    if (method or "").upper() not in _SAFE_METHODS:
        return False
    request_origin = _origin(request_url)
    if request_origin is None or request_origin != _origin(navigation_url):
        return False
    return scope is None or scope.is_in_scope(request_url)


def _origin(url: str):
    try:
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https") or not parts.hostname:
            return None
        port = parts.port or (443 if scheme == "https" else 80)
        return scheme, parts.hostname.lower(), port
    except (TypeError, ValueError):
        return None


_MAX_MULTIPART_BYTES = 1_000_000
_MAX_MULTIPART_PARTS = 50

def _body_bytes(post_data) -> bytes:
    if post_data is None:
        return b""
    if isinstance(post_data, (bytes, bytearray)):
        return bytes(post_data)
    return str(post_data).encode("utf-8", errors="replace")


def is_multipart_content(headers: Dict[str, str]) -> bool:
    return "multipart/" in _header(headers, "content-type").lower()


def _multipart_boundary(headers: Dict[str, str]) -> bytes:
    ctype = _header(headers, "content-type")
    match = re.search(r'boundary=([^;]+)', ctype, re.I)
    if not match:
        raise ValueError("multipart boundary was not observed")
    token = match.group(1).strip().strip('"')
    if not token or len(token) > 200:
        raise ValueError("multipart boundary is unsupported")
    return token.encode("latin-1", errors="replace")


def parse_multipart(post_data, headers: Dict[str, str]):
    """Extract safe multipart shape metadata without file contents.

    Returns (body_fields, parts) where body_fields maps field name to a
    safe sample ("" for file parts and secret-like names) and parts lists
    {name, filename, content_type, size}. Fail-closed: malformed,
    oversized, or ambiguous bodies yield ({}, []).
    """
    try:
        raw = _body_bytes(post_data)
    except Exception:
        return {}, []
    if not raw or len(raw) > _MAX_MULTIPART_BYTES:
        return {}, []
    content_type = _header(headers or {}, "content-type")
    try:
        _multipart_boundary(headers or {})
        prefix = ("Content-Type: " + content_type +
                  "\r\nMIME-Version: 1.0\r\n\r\n").encode(
                      "latin-1", errors="replace")
        message = BytesParser(policy=_email_policy).parsebytes(prefix + raw)
    except (TypeError, ValueError, LookupError):
        return {}, []
    # Use the standard MIME parser so delimiter-like bytes inside a file do
    # not get mistaken for a part boundary. Malformed/truncated multipart
    # input is inconclusive rather than partially interpreted.
    if not message.is_multipart() or message.defects:
        return {}, []
    body_fields: Dict[str, str] = {}
    parts: List[Dict[str, Any]] = []
    for part in message.iter_parts():
        if len(parts) >= _MAX_MULTIPART_PARTS:
            break
        if part.defects:
            return {}, []
        if part.get_content_disposition() != "form-data":
            continue
        field_name = part.get_param("name", header="content-disposition")
        if not isinstance(field_name, str):
            continue
        if not field_name or len(field_name) > 200:
            continue
        filename = (part.get_filename() or "")[:256]
        is_file = part.get_filename() is not None
        content = part.get_payload(decode=True) or b""
        raw_part_content_type = part.get("Content-Type")
        part_content_type = (part.get_content_type()[:128]
                             if raw_part_content_type else "")
        if field_name not in body_fields:
            if is_file or _SECRET_FIELD.search(field_name):
                body_fields[field_name] = ""
            else:
                try:
                    text = content.decode("utf-8", errors="replace")
                except Exception:
                    text = ""
                body_fields[field_name] = text[:100]
        parts.append({"name": field_name, "filename": filename,
                      "content_type": part_content_type,
                      "size": len(content)})
    return body_fields, parts


def _query_names(url: str) -> List[str]:
    from urllib.parse import parse_qsl
    try:
        return [k for k, _ in
                parse_qsl(urlsplit(url).query, keep_blank_values=True)
                if k]
    except Exception:
        return []


def _form_names(post_data, headers: Dict[str, str]) -> Dict[str, str]:
    """Parse a POST body into {name: sample} for endpoint building.

    Multipart bodies contribute field names only; file bytes and
    secret-like values are replaced with "". Unknown shapes fail
    closed to {}.
    """
    from urllib.parse import parse_qsl
    ctype = _header(headers, "content-type").lower()
    if "multipart/" in ctype:
        fields, _ = parse_multipart(post_data, headers or {})
        return fields
    if "json" in ctype:
        try:
            import json as _json
            text = post_data
            if isinstance(text, (bytes, bytearray)):
                text = bytes(text).decode("utf-8", errors="replace")
            data = _json.loads(text or "{}")
            if isinstance(data, dict):
                return {str(k): str(v)[:100] for k, v in data.items()}
        except Exception:
            return {}
        return {}
    try:
        text = post_data
        if isinstance(text, (bytes, bytearray)):
            text = bytes(text).decode("utf-8", errors="replace")
        return {k: v[:100] for k, v in
                parse_qsl(text or "", keep_blank_values=True) if k}
    except Exception:
        return {}
