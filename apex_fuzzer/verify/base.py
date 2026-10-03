"""State verification: prove persistence, don't trust reflection.

A mutation that echoes back is a *candidate signal*, not an effect.
These verifiers independently re-observe server state after the
fact and return one of three outcomes:

- verified   — the effect persisted server-side (readback shows it)
- refuted    — a clean re-read proves the effect did NOT persist
- inconclusive — verification was impossible (no readback path,
  failed requests, unparseable state)

Only `verified` upgrades a finding (to confirmed). `refuted`
downgrades an echo-only candidate to inconclusive — with the reason
recorded, never silently. Anything else leaves the finding exactly
as the engine produced it.
"""
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from ..logging_setup import get_logger

log = get_logger("verify")

VERIFIED = "verified"
REFUTED = "refuted"
INCONCLUSIVE = "inconclusive"


@dataclass
class VerificationResult:
    status: str = INCONCLUSIVE
    detail: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"status": self.status, "detail": self.detail,
                "evidence": self.evidence}


class StateVerifier:
    """Interface for endpoint-specific verification (Terra M2.4).

    Custom verifiers subclass this and get discovered by name.
    Generic scanners must stay conservative: verify only generic,
    safely-observable properties; complex workflows belong in
    user-supplied profiles (assertions config).
    """
    name = "base"

    def verify(self, *, http, endpoint_url: str, method: str,
               headers: Dict[str, str], timeout: int,
               context: Dict[str, Any]) -> VerificationResult:
        raise NotImplementedError


def _get(http, url: str, headers: Dict[str, str],
         timeout: int) -> Optional[Any]:
    try:
        r = http.get(url, headers=headers, timeout=timeout)
    except Exception as e:
        log.debug("verify GET %s failed: %s", url, e)
        return None
    if r.status_code != 200:
        return None
    return r


def verify_persisted(http, read_url: str, headers: Dict[str, str],
                     field_hint: str, mutated_value: Any,
                     timeout: int = 10) -> VerificationResult:
    """Re-read clean state and check the mutated value stuck.

    `field_hint` is the parameter/field name to look for; the check
    passes only when its persisted value equals the mutated one.
    """
    r = _get(http, read_url, headers, timeout)
    if r is None:
        return VerificationResult(
            INCONCLUSIVE, "readback request failed or non-200")
    try:
        data = json.loads(r.text or "")
    except (ValueError, TypeError):
        return VerificationResult(
            INCONCLUSIVE, "readback body is not JSON")
    found = _find_field(data, field_hint)
    if found is _MISSING:
        return VerificationResult(
            INCONCLUSIVE,
            f"field '{field_hint}' absent from readback")
    if str(found) == str(mutated_value):
        return VerificationResult(
            VERIFIED,
            f"mutated value {mutated_value!r} persisted in "
            f"field '{field_hint}' on clean re-read",
            evidence={"read_url": read_url,
                      "persisted_value": str(found)})
    return VerificationResult(
        REFUTED,
        f"clean re-read shows {found!r}, not the mutated "
        f"{mutated_value!r} — echo did not persist",
        evidence={"read_url": read_url,
                  "persisted_value": str(found)})


_MISSING = object()


def _find_field(data: Any, name: str) -> Any:
    """First case-insensitive key match, walked one level deep
    through dicts and short lists."""
    lname = name.lower()
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(k, str) and k.lower() == lname:
                return v
        for v in data.values():
            if isinstance(v, dict):
                hit = _find_field(v, name)
                if hit is not _MISSING:
                    return hit
            elif isinstance(v, list):
                for item in v[:10]:
                    hit = _find_field(item, name)
                    if hit is not _MISSING:
                        return hit
    elif isinstance(data, list):
        for item in data[:10]:
            hit = _find_field(item, name)
            if hit is not _MISSING:
                return hit
    return _MISSING


def verify_idempotency(http, method: str, url: str,
                       body: Dict[str, str], headers: Dict[str, str],
                       key_name: str, timeout: int = 10
                       ) -> VerificationResult:
    """Submit the same idempotency key twice, sequentially.

    Both accepted with *different* object IDs = verified double
    processing. Second rejected/deduplicated = correctly handled
    (returns refuted-as-duplicate-bug, i.e. NOT verified — the
    caller keeps its existing verdict).
    """
    from ..authorization.harvest import extract_ids_from_body
    seen_ids: List[str] = []
    bodies: List[str] = []
    for attempt in (1, 2):
        try:
            if method.upper() == "POST":
                r = http.post(url, data=body, headers=headers,
                              timeout=timeout)
            else:
                r = http.request(method, url, headers=headers,
                                 timeout=timeout)
        except Exception as e:
            return VerificationResult(
                INCONCLUSIVE,
                f"idempotency resubmit {attempt} failed: {e}"[:200])
        if r.status_code != 200:
            return VerificationResult(
                INCONCLUSIVE if attempt == 1 else REFUTED,
                f"resubmit {attempt} → HTTP {r.status_code} "
                f"({'baseline unusable' if attempt == 1 else 'duplicate correctly rejected'})",
                evidence={"attempt": attempt,
                          "status": r.status_code})
        ids = sorted(set(extract_ids_from_body(r.text or "").values()))
        bodies.append((r.text or "")[:500])
        seen_ids.append(ids)
    if seen_ids[0] and seen_ids[0] == seen_ids[1]:
        return VerificationResult(
            INCONCLUSIVE,
            "both submits accepted with identical object IDs — "
            "indistinguishable from correct idempotent replay",
            evidence={"ids": seen_ids[0]})
    if seen_ids[0] != seen_ids[1]:
        return VerificationResult(
            VERIFIED,
            f"same {key_name} accepted twice with different objects "
            f"({seen_ids[0]} vs {seen_ids[1]}) — idempotency not enforced",
            evidence={"first_ids": seen_ids[0],
                      "second_ids": seen_ids[1]})
    return VerificationResult(
        INCONCLUSIVE, "no comparable object IDs in either response")


def verify_token_reuse(http, method: str, url: str,
                       body: Dict[str, str], headers: Dict[str, str],
                       timeout: int = 10,
                       query: Optional[Dict[str, str]] = None
                       ) -> VerificationResult:
    """Sequential double-submit of a single-use value.

    Two identical 200s with matching shape = verified reuse. Any
    rejection or divergence on the second submit = correctly
    single-use (refuted as a bug — caller keeps prior verdict).
    """
    from ..validation.differential import normalize_response
    from urllib.parse import (urlsplit, urlunsplit, parse_qsl, urlencode)

    def _fire():
        if method.upper() == "POST":
            return http.post(url, data=body, headers=headers,
                             timeout=timeout)
        parts = urlsplit(url)
        # query replaces (not extends): it carries the full baseline
        # parameter set, so stale duplicates never gate the verdict
        q = sorted((query or {}).items())
        target = urlunsplit(
            (parts.scheme, parts.netloc, parts.path,
             urlencode(q, doseq=True), ""))
        return http.get(target, headers=headers, timeout=timeout)

    class _R:
        def __init__(self, st, tx):
            self.status_code = st
            self.text = tx

    norms = []
    for attempt in (1, 2):
        try:
            r = _fire()
        except Exception as e:
            return VerificationResult(
                INCONCLUSIVE, f"reuse submit {attempt} failed: {e}"[:200])
        try:
            norms.append(normalize_response(_R(r.status_code,
                                              r.text or "")))
        except Exception:
            return VerificationResult(
                INCONCLUSIVE, "reuse response unparseable")
    n1, n2 = norms
    if n1.get("status") != 200:
        return VerificationResult(INCONCLUSIVE, "baseline submit not 200")
    if n2.get("status") != 200:
        return VerificationResult(
            REFUTED, f"second submit → HTTP {n2.get('status')}: "
                      "single-use correctly enforced")
    same = bool(n1.get("body_hash")) and \
        n1["body_hash"] == n2.get("body_hash")
    if same:
        return VerificationResult(
            VERIFIED, "single-use value accepted twice with identical "
                      "response shape",
            evidence={"body_hash": n1["body_hash"]})
    return VerificationResult(
        INCONCLUSIVE, "second submit 200 but shape differs — "
                      "ambiguous, not proof of reuse")
