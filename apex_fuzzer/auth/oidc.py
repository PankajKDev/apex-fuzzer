"""OIDC thin layer over OAuth modeling (agent Phase 2).

Discovery-document fetch, passive issuer validation, nonce tracking,
and ID-token parsing via auth/jwt.py. Active claims attacks
(audience/issuer confusion, algorithm games) belong to Phase 10.
"""
from typing import Any, Dict, List, Optional
from ..logging_setup import get_logger
from .jwt import parse_jwt, JwtClaims

log = get_logger("auth-oidc")


def fetch_discovery(issuer: str, timeout: int = 10
                    ) -> Dict[str, Any]:
    """GET <issuer>/.well-known/openid-configuration. Empty on failure."""
    import requests
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    try:
        r = requests.get(url, timeout=timeout)
        data = r.json()
        return data if isinstance(data, dict) else {}
    except Exception as e:
        log.debug("OIDC discovery %s failed: %s", url, e)
        return {}


def check_issuer(discovery: Dict[str, Any],
                 expected_issuer: str) -> List[str]:
    """Passive mismatch notes (observations, not findings)."""
    out: List[str] = []
    got = str(discovery.get("issuer", ""))
    if not got:
        out.append("discovery document has no issuer")
    elif got.rstrip("/") != expected_issuer.rstrip("/"):
        out.append(f"issuer mismatch: expected {expected_issuer}, "
                   f"document says {got}")
    return out


class NonceTracker:
    """One nonce per authentication request; flags replays."""

    def __init__(self):
        self.issued: Dict[str, float] = {}
        self.consumed: List[str] = []

    def issue(self, nonce: str):
        import time
        self.issued[nonce] = time.time()

    def consume(self, nonce: str) -> bool:
        """True on first valid use; False on replay or unknown."""
        if nonce in self.consumed or nonce not in self.issued:
            return False
        self.consumed.append(nonce)
        return True


def parse_id_token(raw: str) -> Optional[JwtClaims]:
    return parse_jwt(raw)
