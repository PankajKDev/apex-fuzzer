"""Network interception + request recording (Phase 1).

Attaches to a Playwright page (or context) and records every HTTP
request/response plus WebSocket URLs. `to_endpoints()` converts the
recording into endpoint dicts the existing pipeline merges like any
other discovery source — no separate endpoint database.
"""
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit
from ..logging_setup import get_logger

log = get_logger("browser-net")

_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
_SKIP_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
              ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp4", ".webm",
              ".mp3", ".wav", ".css", ".map"}


@dataclass
class RecordedRequest:
    url: str
    method: str
    headers: Dict[str, str] = field(default_factory=dict)
    post_data: Optional[str] = None
    resource_type: str = ""
    status: Optional[int] = None
    timestamp: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {"url": self.url, "method": self.method,
                "headers": self.headers, "post_data": self.post_data,
                "resource_type": self.resource_type, "status": self.status,
                "timestamp": self.timestamp}


class NetworkRecorder:
    def __init__(self, scope=None, max_requests: int = 5000):
        self.scope = scope
        self.max_requests = max_requests
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
        try:
            post_data = request.post_data
        except Exception:
            post_data = None
        self.requests.append(RecordedRequest(
            url=url, method=(request.method or "GET").upper(),
            headers=headers, post_data=post_data,
            resource_type=getattr(request, "resource_type", "") or "",
            timestamp=time.time()))

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
        form bodies are parsed into body params.
        """
        from ..discovery.url_normalizer import normalize_url  # noqa
        out: List[Dict[str, Any]] = []
        seen = set()
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
            if key in seen:
                continue
            seen.add(key)
            entry: Dict[str, Any] = {"url": rec.url, "method": rec.method,
                                     "params": [], "body": {}}
            if rec.method in _SAFE_METHODS:
                entry["params"] = _query_names(rec.url)
            elif rec.post_data:
                entry["body"] = _form_names(rec.post_data,
                                            rec.headers)
            out.append(entry)
        log.info("network: %d requests → %d endpoints (%d websockets)",
                 len(self.requests), len(out), len(self.websockets))
        return out

    def to_dict(self) -> Dict[str, Any]:
        return {"requests": [r.to_dict() for r in self.requests],
                "websockets": list(self.websockets),
                "navigations": list(self.navigations)}


def _query_names(url: str) -> List[str]:
    from urllib.parse import parse_qsl
    try:
        return [k for k, _ in
                parse_qsl(urlsplit(url).query, keep_blank_values=True)
                if k]
    except Exception:
        return []


def _form_names(post_data: str, headers: Dict[str, str]) -> Dict[str, str]:
    """Parse a POST body into {name: sample} for endpoint building."""
    from urllib.parse import parse_qsl
    ctype = (headers.get("content-type", "") or "").lower()
    if "json" in ctype:
        try:
            import json as _json
            data = _json.loads(post_data or "{}")
            if isinstance(data, dict):
                return {str(k): str(v)[:100] for k, v in data.items()}
        except Exception:
            return {}
        return {}
    try:
        return {k: v[:100] for k, v in
                parse_qsl(post_data or "", keep_blank_values=True) if k}
    except Exception:
        return {}
