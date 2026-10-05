"""JWT confusion probes (alg confusion, stripped signatures).

Replays an authorized identity's own Bearer token with the signature
neutralized and compares against the baseline. Only the test
account's own token is ever mutated — no foreign tokens, no key
guessing, no brute force. A tampered token served like the baseline
is a candidate; a denial is a genuine negative.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ..auth.jwt import parse_jwt
from ..budgets import BudgetExceeded
from ..logging_setup import get_logger

log = get_logger("jwt-replay")


def _b64url_encode(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _encode_segment(obj: dict) -> str:
    import json as _json
    return _b64url_encode(_json.dumps(obj, separators=(",", ":"),
                                     ensure_ascii=False).encode("utf-8"))


def bearer_token(headers) -> str:
    """First JWT-shaped Bearer token in headers, or ''."""
    try:
        items = list((headers or {}).items())
    except (AttributeError, TypeError):
        return ""
    for name, value in items:
        if str(name).lower() != "authorization":
            continue
        text = str(value or "")
        prefix, _, token = text.partition(" ")
        if prefix.lower() != "bearer" or not token.strip():
            continue
        if parse_jwt(token.strip()) is not None:
            return token.strip()
    return ""


def tamper_variants(token: str) -> List[Tuple[str, str]]:
    """Bounded confusion variants: (label, mutated token)."""
    claims = parse_jwt(token)
    if claims is None:
        return []
    try:
        header = dict(claims.header)
        payload = dict(claims.payload)
    except (TypeError, ValueError, AttributeError):
        return []
    variants = []
    none_header = dict(header)
    none_header["alg"] = "none"
    variants.append(("alg-none",
                     f"{_encode_segment(none_header)}."
                     f"{_encode_segment(payload)}."))
    variants.append(("empty-signature",
                     f"{_encode_segment(header)}."
                     f"{_encode_segment(payload)}."))
    return variants


@dataclass
class JwtProbeResult:
    url: str
    identity: str = ""
    # accepted | denied | inconclusive | untestable
    verdict: str = "inconclusive"
    notes: str = ""
    status: int = 0
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"url": self.url, "identity": self.identity,
                "verdict": self.verdict, "notes": self.notes,
                "status": self.status, "evidence": dict(self.evidence)}


def _swap_bearer(headers, token: str) -> Dict[str, str]:
    swapped = {}
    try:
        items = list((headers or {}).items())
    except (AttributeError, TypeError):
        return swapped
    for name, value in items:
        if str(name).lower() == "authorization":
            swapped[name] = f"Bearer {token}"
        else:
            swapped[name] = value
    return swapped


def jwt_confusion_probe(client, url: str, identity_headers: Dict,
                        identity_name: str = "tester",
                        timeout: int = 10) -> Optional[JwtProbeResult]:
    """Replay caller-owned Bearer variants; compare with baseline."""
    from ..validation.differential import normalize_response
    original = bearer_token(identity_headers)
    if not original:
        return None
    res = JwtProbeResult(url=url, identity=identity_name)
    try:
        base = client.get(url, headers=dict(identity_headers),
                          timeout=timeout)
    except BudgetExceeded:
        raise
    except Exception as e:
        res.notes = f"baseline failed: {e}"[:200]
        return res
    base_norm = normalize_response(base)
    if base_norm["status"] != 200:
        res.notes = f"baseline HTTP {base_norm['status']}: session " \
                    f"expired or endpoint not authorized for this " \
                    f"identity — nothing to compare"
        return res
    for label, mutated in tamper_variants(original):
        try:
            r = client.get(url, headers=_swap_bearer(identity_headers,
                                                     mutated),
                           timeout=timeout)
        except BudgetExceeded:
            raise
        except Exception as e:
            res.notes = f"{label} request failed: {e}"[:200]
            return res
        norm = normalize_response(r)
        if norm["status"] in (401, 403):
            continue  # this variant correctly rejected
        if norm["status"] == 200 and (
                norm["body_hash"] == base_norm["body_hash"] or
                (norm["key_shape"] and
                 norm["key_shape"] == base_norm["key_shape"])):
            res.verdict = "accepted"
            res.status = 200
            res.notes = f"tampered token ({label}) served like the " \
                        f"baseline — signature may not be enforced"
            res.evidence = {"variant": label,
                            "baseline_hash": base_norm["body_hash"],
                            "replay_hash": norm["body_hash"]}
            return res
    res.verdict = "denied"
    res.notes = "confusion variants rejected or diverged"
    return res
