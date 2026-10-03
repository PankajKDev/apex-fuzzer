"""Browser sessions: capture, persist, reuse via HTTP (Phase 1).

A BrowserSession is the bridge between the browser and the existing
header-based auth system: cookies/tokens captured in Chromium become
an Identity whose auth_headers flow straight into _HTTPClient,
DifferentialTester, and the authz matrix. Storage-state files declared
in auth contexts are imported the same way.
"""
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from ..models import Identity
from ..logging_setup import get_logger
from .storage import (cookies_to_dict, build_cookie_header, extract_tokens,
                      parse_storage_state)

log = get_logger("browser-sessions")

LOGIN_URL_HINTS = ("login", "signin", "sign-in", "auth", "oauth",
                   "sso", "account/login")
LOGIN_FORM_HINTS = ('type="password"', "type='password'", 'name="password"')


class BrowserSession:
    def __init__(self, identity: str, role: str = "",
                 tenant: str = "",
                 cookies: Optional[List[Dict[str, Any]]] = None,
                 headers: Optional[Dict[str, str]] = None,
                 tokens: Optional[Dict[str, List[str]]] = None,
                 storage_state: Optional[Dict[str, Any]] = None,
                 created_ts: float = 0.0, expires_in: int = 3600):
        self.identity = identity
        self.role = role
        self.tenant = tenant
        self.cookies = cookies or []
        self.headers = headers or {}
        self.tokens = tokens or {"jwt": [], "bearer": [], "csrf": []}
        self.storage_state = storage_state
        self.created_ts = created_ts or time.time()
        self.expires_in = expires_in

    def is_expired(self, now: float | None = None) -> bool:
        return (now or time.time()) - self.created_ts > self.expires_in

    def to_identity(self) -> Identity:
        headers = dict(self.headers)
        cookie_header = build_cookie_header(self.cookies)
        if cookie_header:
            headers["Cookie"] = cookie_header
        for jwt in (self.tokens.get("jwt") or [])[:1]:
            headers.setdefault("Authorization", f"Bearer {jwt}")
            break
        return Identity(name=self.identity,
                        roles=[self.role] if self.role else [],
                        tenant=self.tenant or None,
                        auth_headers=headers,
                        notes=f"browser session for '{self.identity}'")

    def to_dict(self) -> Dict[str, Any]:
        return {"identity": self.identity, "role": self.role,
                "tenant": self.tenant, "cookies": self.cookies,
                "headers": self.headers, "tokens": self.tokens,
                "storage_state": self.storage_state,
                "created_ts": self.created_ts,
                "expires_in": self.expires_in}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "BrowserSession":
        return cls(identity=d.get("identity", ""),
                   role=d.get("role", ""), tenant=d.get("tenant", ""),
                   cookies=d.get("cookies") or [],
                   headers=d.get("headers") or {},
                   tokens=d.get("tokens") or {},
                   storage_state=d.get("storage_state"),
                   created_ts=d.get("created_ts", 0.0),
                   expires_in=int(d.get("expires_in") or 3600))


def looks_logged_out(url: str, html: str) -> bool:
    """Heuristic logout/login-redirect detection (pure, testable)."""
    path = (url or "").lower()
    if any(h in path for h in LOGIN_URL_HINTS):
        return True
    body = (html or "").lower()
    return any(h in body for h in LOGIN_FORM_HINTS)


class SessionManager:
    """Create sessions from live contexts or storage-state files."""

    def __init__(self, state_dir: Optional[Path] = None):
        self.state_dir = Path(state_dir) if state_dir else None
        if self.state_dir is not None:
            self.state_dir.mkdir(parents=True, exist_ok=True)

    def from_capture(self, capture: Dict[str, Any], identity: str,
                     role: str = "", tenant: str = "",
                     expires_in: int = 3600) -> BrowserSession:
        return BrowserSession(
            identity=identity, role=role, tenant=tenant,
            cookies=capture.get("cookies") or [],
            headers={}, tokens=capture.get("tokens") or {},
            storage_state=capture.get("storage_state"),
            expires_in=expires_in)

    def from_storage_file(self, path: str | Path, identity: str,
                          role: str = "", tenant: str = "",
                          expires_in: int = 3600) -> BrowserSession:
        data = json.loads(Path(path).read_text())
        cookies, _ = parse_storage_state(data)
        tokens = extract_tokens(cookies)
        return BrowserSession(
            identity=identity, role=role, tenant=tenant, cookies=cookies,
            headers={}, tokens=tokens, storage_state=data,
            expires_in=expires_in)

    def save(self, session: BrowserSession, path: Optional[Path] = None
             ) -> Path:
        dest = Path(path) if path else \
            (self.state_dir / f"{session.identity}.json")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps(session.to_dict(), indent=2))
        return dest

    def load(self, path: str | Path) -> BrowserSession:
        return BrowserSession.from_dict(
            json.loads(Path(path).read_text()))

    def apply_to_contexts(self, auth_contexts) -> int:
        """Fill Cookie headers from declared storage_state files.

        Only touches contexts that declare storage_state AND have no
        headers yet — static header config always wins. Returns the
        number of contexts enriched.
        """
        enriched = 0
        for ctx in auth_contexts or []:
            state_file = getattr(ctx, "storage_state", None)
            if not state_file:
                continue
            if getattr(ctx, "headers", None):
                continue
            try:
                session = self.from_storage_file(
                    state_file, getattr(ctx, "name", "browser"),
                    tenant=getattr(ctx, "tenant", "") or "")
                cookie = build_cookie_header(session.cookies)
                if cookie:
                    ctx.headers = {"Cookie": cookie}
                    enriched += 1
                    log.info("session: enriched '%s' from %s",
                             ctx.name, state_file)
            except Exception as e:
                log.warning("session: cannot import %s: %s",
                            state_file, e)
        return enriched
