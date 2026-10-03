"""OAuth 2.0 flow modeling: PKCE, codes, leakage (agent Phase 2).

Models authorization-code flows passively and builds the artifacts
the Phase 10 security engine will actively test (redirect URIs,
state/nonce, code replay, token substitution). The one active-adjacent
behavior here is *detection*: finding tokens/codes where they should
never appear (URLs sent to third parties, referers, logs).
"""
import hashlib
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import (urlsplit, urlunsplit, parse_qsl, urlencode,
                          urlparse)
from ..logging_setup import get_logger

log = get_logger("auth-oauth")


def pkce_pair() -> tuple:
    """RFC 7636 S256 pair: (verifier, challenge)."""
    verifier = secrets.token_urlsafe(48)[:64]
    challenge = hashlib.sha256(verifier.encode()).digest()
    import base64
    challenge_b64 = base64.urlsafe_b64encode(challenge).decode().rstrip(
        "=")
    return verifier, challenge_b64


@dataclass
class OAuthFlow:
    name: str = ""
    authorization_url: str = ""
    token_url: str = ""
    client_id: str = ""
    redirect_uri: str = ""
    scope: str = ""
    state: str = ""
    nonce: str = ""
    code_verifier: str = ""
    code_challenge: str = ""
    code_challenge_method: str = "S256"
    codes_seen: List[str] = field(default_factory=list)
    created_ts: float = 0.0

    def authorize_url(self, extra: Optional[Dict[str, str]] = None
                      ) -> str:
        parts = urlsplit(self.authorization_url)
        q = parse_qsl(parts.query, keep_blank_values=True)
        q.extend([("client_id", self.client_id),
                  ("redirect_uri", self.redirect_uri),
                  ("response_type", "code"),
                  ("scope", self.scope),
                  ("state", self.state or secrets.token_urlsafe(16))])
        if self.nonce:
            q.append(("nonce", self.nonce))
        if self.code_challenge:
            q.append(("code_challenge", self.code_challenge))
            q.append(("code_challenge_method",
                      self.code_challenge_method))
        q.extend(sorted((extra or {}).items()))
        return urlunsplit((parts.scheme, parts.netloc, parts.path,
                           urlencode(q, doseq=True), ""))

    def note_code(self, code: str) -> bool:
        """Track an authorization code. Returns False on *reuse* —
        codes are single-use by spec; reuse is observable evidence."""
        if code in self.codes_seen:
            return False
        self.codes_seen.append(code)
        return True

    def to_dict(self) -> Dict[str, Any]:
        d = {"name": self.name,
             "authorization_url": self.authorization_url,
             "token_url": self.token_url, "client_id": self.client_id,
             "redirect_uri": self.redirect_uri, "scope": self.scope,
             "state": self.state, "nonce": self.nonce,
             "code_challenge_method": self.code_challenge_method,
             "codes_seen_count": len(self.codes_seen),
             "created_ts": self.created_ts or time.time()}
        return d


def new_pkce_flow(name: str = "", **kw) -> OAuthFlow:
    verifier, challenge = pkce_pair()
    return OAuthFlow(name=name, code_verifier=verifier,
                     code_challenge=challenge, **kw)


def find_token_leaks(requests, first_party: str = "") -> List[Dict[str, Any]]:
    """Detect authorization codes/tokens in third-party-bound traffic.

    ``requests`` are dicts/objects with .url/.headers (e.g. recorded
    browser traffic). A code or token leaving the first-party host —
    query, fragment, or Referer — is worth a finding on its own.
    """
    import re
    leaks: List[Dict[str, Any]] = []
    fp = (first_party or "").lower()
    secret_re = re.compile(
        r"(?:[?&#](?:code|access_token|id_token|refresh_token)="
        r"|eyJ[A-Za-z0-9_\-]{10,}\.)")
    for req in requests or []:
        url = req.get("url") if isinstance(req, dict) else \
            getattr(req, "url", "")
        if not url or not secret_re.search(url):
            continue
        try:
            host = (urlparse(url).hostname or "").lower()
        except Exception:
            continue
        if fp and (host == fp or host.endswith("." + fp)):
            continue
        headers = req.get("headers") if isinstance(req, dict) else \
            getattr(req, "headers", {}) or {}
        leaks.append({"url": url[:300], "host": host,
                      "referer": str(headers.get("referer", ""))[:200]})
    return leaks
