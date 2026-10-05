"""JWT parsing + passive claim modeling (agent Phase 2).

Decodes and models tokens found in traffic/storage. Analysis is
strictly passive — flags describe *configuration observations*, never
vulnerabilities. Active tests (algorithm confusion, claim tampering,
weak validation) belong to the Phase 10 security engine, which must
produce behavioral evidence per finding.
"""
import base64
import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from ..logging_setup import get_logger

log = get_logger("auth-jwt")


def _b64url_decode(segment: str) -> Optional[dict]:
    try:
        padded = segment + "=" * (-len(segment) % 4)
        return json.loads(base64.urlsafe_b64decode(padded).decode(
            "utf-8", "replace"))
    except Exception:
        return None


@dataclass
class JwtClaims:
    raw: str = ""
    header: Dict[str, Any] = field(default_factory=dict)
    payload: Dict[str, Any] = field(default_factory=dict)
    algorithm: str = ""
    key_id: str = ""
    token_type: str = ""
    issuer: str = ""
    audience: Any = None
    subject: str = ""
    expires_at: Optional[int] = None
    not_before: Optional[int] = None
    issued_at: Optional[int] = None
    observations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"algorithm": self.algorithm, "key_id": self.key_id,
                "token_type": self.token_type, "issuer": self.issuer,
                "audience": self.audience, "subject": self.subject,
                "expires_at": self.expires_at,
                "not_before": self.not_before,
                "issued_at": self.issued_at,
                "observations": self.observations,
                "payload_keys": sorted(self.payload.keys())}

    def is_expired(self, now: float | None = None,
                   leeway: int = 30) -> Optional[bool]:
        if self.expires_at is None:
            return None
        return (now or time.time()) > self.expires_at + leeway

    def usable_now(self, now: float | None = None) -> Optional[bool]:
        now = now or time.time()
        if self.expires_at is not None and now > self.expires_at + 30:
            return False
        if self.not_before is not None and now < self.not_before - 30:
            return False
        return True


def parse_jwt(token: str) -> Optional[JwtClaims]:
    """Decode a compact JWT. Returns None for non-JWT input."""
    token = (token or "").strip().strip("'\"")
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header = _b64url_decode(parts[0])
    payload = _b64url_decode(parts[1])
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    claims = JwtClaims(
        raw=token, header=header, payload=payload,
        algorithm=str(header.get("alg", "")),
        key_id=str(header.get("kid", "")),
        token_type=str(header.get("typ", "")),
        issuer=str(payload.get("iss", "")),
        audience=payload.get("aud"),
        subject=str(payload.get("sub", "")))
    for key, attr in (("exp", "expires_at"), ("nbf", "not_before"),
                      ("iat", "issued_at")):
        val = payload.get(key)
        if isinstance(val, (int, float)):
            setattr(claims, attr, int(val))
    claims.observations = _observe(claims)
    return claims


def _observe(claims: JwtClaims) -> List[str]:
    """Passive configuration observations — not findings."""
    out: List[str] = []
    if claims.algorithm.lower() == "none":
        out.append("algorithm is 'none' (unsigned token accepted by "
                   "format — server enforcement untested)")
    if claims.algorithm.upper().startswith("HS") and claims.key_id:
        out.append("symmetric HS* algorithm with kid header "
                   "(key-confusion surface — untested)")
    if claims.expires_at is None:
        out.append("no exp claim (lifetime enforced server-side, if at "
                   "all — untested)")
    for priv in ("admin", "role", "roles", "permissions", "is_staff",
                 "is_admin", "scope"):
        if priv in claims.payload:
            out.append(f"privilege-adjacent claim present: {priv}")
    return out


def find_jwts(text: str) -> List[str]:
    import re
    return re.findall(
        r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\."
        r"[A-Za-z0-9_\-]{10,}", text or "")
