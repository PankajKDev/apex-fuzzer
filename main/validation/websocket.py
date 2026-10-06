"""WebSocket handshake layer: auth boundary + origin validation.

A WebSocket handshake IS an HTTP request: the client sends Upgrade
headers over the shared gated HTTP client and reads the status. A
101 with the upgrade echoed means the handshake was accepted; anything
else (401/403/400) is the server refusing it. No frames are ever
spoken — there is no message-layer testing here, only:
  - auth boundary: anonymous vs authenticated handshake outcomes;
  - origin validation: an evil Origin on an otherwise authed-only
    endpoint (cross-site WebSocket hijacking primitive).

Plain requests transports this safely: allow_redirects=False upstream
means no redirect is followed, and scope/budget gates apply per
request like every other probe.
"""
import base64
import secrets
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit

from ..budgets import BudgetExceeded
from ..logging_setup import get_logger

log = get_logger("websocket")

# .invalid never resolves: acceptance proves server-side trust without
# ever reaching an attacker host.
EVIL_ORIGIN = "https://apex-ws.invalid"

_MAX_ENDPOINTS = 10


def ws_http_url(ws_url: str) -> Optional[str]:
    """Map a ws(s) URL to its http(s) handshake equivalent."""
    try:
        parts = urlsplit(ws_url or "")
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in ("ws", "wss"):
        return None
    if not parts.hostname or parts.username is not None or \
            parts.password is not None:
        return None
    http_scheme = "https" if scheme == "wss" else "http"
    netloc = parts.hostname
    try:
        port = parts.port
    except ValueError:
        return None
    default = 443 if http_scheme == "https" else 80
    if port and port != default:
        netloc += f":{port}"
    return urlunsplit((http_scheme, netloc, parts.path or "/",
                       parts.query, ""))


def _handshake_headers(extra: Optional[Dict[str, str]] = None,
                       origin: Optional[str] = None) -> Dict[str, str]:
    key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
    headers = {"Upgrade": "websocket", "Connection": "Upgrade",
               "Sec-WebSocket-Key": key,
               "Sec-WebSocket-Version": "13"}
    if origin:
        headers["Origin"] = origin
    for name, value in (extra or {}).items():
        if isinstance(name, str) and isinstance(value, str) \
                and name.strip():
            headers[name.strip()] = value.strip()
    return headers


@dataclass
class WsHandshakeResult:
    url: str
    identity: str = ""
    status: int = 0
    accepted: bool = False
    notes: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"url": self.url, "identity": self.identity,
                "status": self.status, "accepted": self.accepted,
                "notes": self.notes, "evidence": dict(self.evidence)}


def check_ws_handshake(client, http_url: str,
                       identity_headers: Optional[Dict[str, str]] = None,
                       identity_name: str = "tester",
                       origin: Optional[str] = None,
                       timeout: int = 10) -> WsHandshakeResult:
    """One handshake attempt: 101+upgrade echoed means accepted."""
    res = WsHandshakeResult(url=http_url, identity=identity_name)
    try:
        r = client.get(http_url,
                       headers=_handshake_headers(identity_headers,
                                                  origin),
                       timeout=timeout)
    except BudgetExceeded:
        raise
    except Exception as exc:
        res.notes = f"handshake failed: {exc}"[:200]
        return res
    res.status = getattr(r, "status_code", 0) or 0
    headers = {}
    try:
        for name, value in (getattr(r, "headers", None) or {}).items():
            headers[str(name).lower()] = str(value or "")
    except (AttributeError, TypeError):
        pass
    upgrade = headers.get("upgrade", "")
    accepted = res.status == 101 and "websocket" in upgrade.lower() \
        and "sec-websocket-accept" in headers
    res.accepted = bool(accepted)
    res.evidence = {"status": res.status,
                    "upgrade": upgrade[:120],
                    "origin": origin or ""}
    outcome = ("accepted (101)" if accepted
               else f"refused ({res.status})")
    res.notes = f"handshake {outcome} as {identity_name}"
    return res


def ws_targets(websockets: List[str]) -> List[str]:
    """Deduplicated handshake URLs from recorded ws(s) addresses."""
    out = []
    for raw in websockets or []:
        mapped = ws_http_url(raw) if isinstance(raw, str) else None
        if mapped and mapped not in out:
            out.append(mapped)
    return out[:_MAX_ENDPOINTS]
