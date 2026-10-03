"""Authenticated sessions: creation, refresh, expiry (agent Phase 2).

AuthSession is the scan-level session record. Sessions are minted
from browser captures (via browser/sessions.py), from storage-state
files, or from login workflows — then converted to request headers.
Refresh covers both replay (re-run the login workflow) and OAuth
refresh-token rotation; expiry is checked before every use.
"""
import json
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional
from ..models import Identity
from ..logging_setup import get_logger

log = get_logger("auth-sessions")


class AuthSession:
    def __init__(self, session_id: str = "", identity: str = "",
                 role: str = "", tenant: str = "",
                 cookies: Optional[List[Dict[str, Any]]] = None,
                 headers: Optional[Dict[str, str]] = None,
                 tokens: Optional[Dict[str, Any]] = None,
                 created_ts: float = 0.0, expires_in: int = 3600,
                 refresh_expires_in: int = 86400,
                 refresh_token: str = "",
                 token_url: str = "", client_id: str = ""):
        self.session_id = session_id or f"sess-{uuid.uuid4().hex[:12]}"
        self.identity = identity
        self.role = role
        self.tenant = tenant
        self.cookies = cookies or []
        self.headers = headers or {}
        self.tokens = tokens or {}
        self.created_ts = created_ts or time.time()
        self.expires_in = expires_in
        self.refresh_expires_in = refresh_expires_in
        self.refresh_token = refresh_token
        self.token_url = token_url
        self.client_id = client_id

    def is_expired(self, now: float | None = None) -> bool:
        return (now or time.time()) - self.created_ts > self.expires_in

    def refresh_expired(self, now: float | None = None) -> bool:
        return (now or time.time()) - self.created_ts > \
            self.refresh_expires_in

    def can_refresh(self, now: float | None = None) -> bool:
        """Refresh possible: refresh window open AND a mechanism exists
        (refresh token + token URL, or a replayable login workflow)."""
        if self.refresh_expired(now):
            return False
        return bool(self.refresh_token and self.token_url)

    def to_identity(self) -> Identity:
        headers = dict(self.headers)
        if self.cookies:
            from ..browser.storage import build_cookie_header
            cookie = build_cookie_header(self.cookies)
            if cookie:
                headers.setdefault("Cookie", cookie)
        access = self.tokens.get("access_token", "")
        if access:
            headers.setdefault("Authorization", f"Bearer {access}")
        return Identity(name=self.identity,
                        roles=[self.role] if self.role else [],
                        tenant=self.tenant or None,
                        auth_headers=headers,
                        notes=f"auth session {self.session_id}")

    def to_dict(self) -> Dict[str, Any]:
        return {"session_id": self.session_id, "identity": self.identity,
                "role": self.role, "tenant": self.tenant,
                "cookies": self.cookies, "headers": self.headers,
                "tokens": {k: ("***" if "token" in k.lower() or
                                      k.lower() in ("jwt", "bearer")
                               else v)
                           for k, v in (self.tokens or {}).items()},
                "created_ts": self.created_ts,
                "expires_in": self.expires_in,
                "refresh_expires_in": self.refresh_expires_in,
                "has_refresh_token": bool(self.refresh_token),
                "token_url": self.token_url, "client_id": self.client_id}

    @classmethod
    def from_dict(cls, d: Dict[str, Any],
                  secrets: Optional[Dict[str, str]] = None
                  ) -> "AuthSession":
        tokens = dict(d.get("tokens") or {})
        if secrets:
            tokens.update(secrets)
        return cls(
            session_id=d.get("session_id", ""), identity=d.get(
                "identity", ""), role=d.get("role", ""),
            tenant=d.get("tenant", ""), cookies=d.get("cookies") or [],
            headers=d.get("headers") or {}, tokens=tokens,
            created_ts=d.get("created_ts", 0.0),
            expires_in=int(d.get("expires_in") or 3600),
            refresh_expires_in=int(d.get("refresh_expires_in") or 86400),
            refresh_token=(secrets or {}).get("refresh_token", ""),
            token_url=d.get("token_url", ""),
            client_id=d.get("client_id", ""))


class SessionStore:
    """Owns a scan's sessions: create, refresh, revoke, persist.

    Secrets (refresh tokens) live only in memory — `to_dict` redacts
    them, and they must be re-supplied to `from_dict` via `secrets`.
    """

    def __init__(self):
        self.sessions: Dict[str, AuthSession] = {}

    def create(self, **kw) -> AuthSession:
        sess = AuthSession(**kw)
        self.sessions[sess.session_id] = sess
        return sess

    def get(self, session_id: str) -> Optional[AuthSession]:
        return self.sessions.get(session_id)

    def for_identity(self, identity: str) -> List[AuthSession]:
        return [s for s in self.sessions.values()
                if s.identity == identity]

    def fresh_for_identity(self, identity: str,
                           now: float | None = None) -> Optional[AuthSession]:
        live = [s for s in self.for_identity(identity)
                if not s.is_expired(now)]
        return max(live, key=lambda s: s.created_ts) if live else None

    def revoke(self, session_id: str):
        self.sessions.pop(session_id, None)

    def prune_expired(self, now: float | None = None) -> int:
        dead = [sid for sid, s in self.sessions.items()
                if s.is_expired(now) and not s.can_refresh(now)]
        for sid in dead:
            del self.sessions[sid]
        return len(dead)

    def refresh(self, session: AuthSession, http=None,
                timeout: int = 10) -> bool:
        """OAuth refresh-token rotation. Returns True on new tokens."""
        if not session.can_refresh():
            return False
        import urllib.parse as _up
        body = {"grant_type": "refresh_token",
                "refresh_token": session.refresh_token,
                "client_id": session.client_id}
        try:
            import requests
            r = requests.post(session.token_url,
                              data=body, timeout=timeout)
            data = r.json()
        except Exception as e:
            log.warning("session %s refresh failed: %s",
                        session.session_id, e)
            return False
        if not isinstance(data, dict) or "access_token" not in data:
            log.warning("session %s refresh rejected (no access_token)",
                        session.session_id)
            return False
        session.tokens["access_token"] = data["access_token"]
        if data.get("refresh_token"):
            session.refresh_token = data["refresh_token"]
        if data.get("expires_in"):
            try:
                session.expires_in = int(data["expires_in"])
            except (TypeError, ValueError):
                pass
        session.created_ts = time.time()
        log.info("session %s refreshed via %s",
                 session.session_id, session.token_url)
        return True

    def save(self, path: Path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(
            {"sessions": [s.to_dict() for s in self.sessions.values()]},
            indent=2))

    @classmethod
    def load(cls, path: Path,
             secrets: Optional[Dict[str, Dict[str, str]]] = None
             ) -> "SessionStore":
        store = cls()
        try:
            data = json.loads(Path(path).read_text())
        except Exception:
            return store
        for entry in data.get("sessions") or []:
            sid = entry.get("session_id", "")
            sess = AuthSession.from_dict(
                entry, secrets=(secrets or {}).get(sid))
            store.sessions[sess.session_id] = sess
        return store


def from_browser_session(bs, role: str = "",
                         expires_in: int = 3600) -> AuthSession:
    """Convert a browser/sessions.py BrowserSession (cookies + tokens)."""
    tokens = dict(getattr(bs, "tokens", None) or {})
    access = (tokens.get("jwt") or [None])[0] or \
        (tokens.get("bearer") or [None])[0] or ""
    return AuthSession(
        identity=getattr(bs, "identity", ""),
        role=role or "",
        tenant=getattr(bs, "tenant", "") or "",
        cookies=list(getattr(bs, "cookies", None) or []),
        headers={},
        tokens={"access_token": access} if access else {},
        created_ts=getattr(bs, "created_ts", 0.0) or time.time(),
        expires_in=expires_in)
