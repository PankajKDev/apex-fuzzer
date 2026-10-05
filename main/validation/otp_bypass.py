"""OTP verification bypass: empty/omitted code against a wrong-code baseline.

Sends at most 3 verification attempts per endpoint (one wrong code,
one empty code, one omitted code) — a single attempt each, never a
brute-force sweep. Runs only behind ``safety.allow_state_change``
(``--ack-state-change``): attempts count against lockout counters,
so test accounts only. Nothing is redeemed; sessions are never
mutated beyond the verification attempts themselves.
"""
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from ..budgets import BudgetExceeded
from ..logging_setup import get_logger

log = get_logger("otp-bypass")

# Path segments that mark an OTP verification surface.
OTP_PATH_HINTS = ("otp", "verify", "2fa", "mfa", "totp", "passcode")

# Code fields an OTP form plausibly submits. Unknown shapes fail
# closed: the probe never guesses field names.
OTP_CODE_PARAMS = ("otp", "code", "token", "pin", "passcode",
                   "verification_code", "verify_code", "2fa_code",
                   "mfa_code", "otp_code")

# One well-formed but wrong code. A single attempt only.
WRONG_CODE = "000000"

# Rejection language vs acceptance language. Acceptance needs a
# success marker with no rejection marker; anything mixed is
# inconclusive, never a candidate.
_REJECT_MARKERS = ("invalid", "incorrect", "wrong", "failed",
                   "failure", "error", "expired", "mismatch",
                   "denied", "unauthorized", "try again",
                   "not match", "does not match")
_SUCCESS_MARKERS = ("success", "verified", "welcome", "authenticated")


@dataclass
class OtpBypassResult:
    url: str
    check: str = ""
    # candidate | negative | inconclusive
    verdict: str = "inconclusive"
    notes: str = ""
    status: int = 0
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"url": self.url, "check": self.check,
                "verdict": self.verdict, "notes": self.notes,
                "status": self.status, "evidence": dict(self.evidence)}


def is_otp_endpoint(url: str) -> bool:
    """True when a path segment names an OTP verification flow.

    Compound segments (``verify-otp``, ``2fa_verify``) match on
    their parts; plain substrings (``preset``) never match.
    """
    try:
        segments = [seg.lower() for seg in
                    urlsplit(url or "").path.split("/") if seg]
    except ValueError:
        return False
    parts = set()
    for seg in segments:
        parts.update(re.split(r"[-_]", seg))
    return any(part in OTP_PATH_HINTS for part in parts)


def code_param_for(endpoint: Any) -> Optional[str]:
    """First known code field on the endpoint, else None."""
    seen = []
    for attr in ("body_parameters", "query_parameters"):
        for param in list(getattr(endpoint, attr, None) or []):
            name = getattr(param, "name", "") or ""
            if name and name not in seen:
                seen.append(name)
    for name in seen:
        if str(name).lower().replace("-", "_") in OTP_CODE_PARAMS:
            return name
    return None


def _markers(text: str) -> Dict[str, bool]:
    lowered = (text or "").lower()
    return {"rejected": any(m in lowered for m in _REJECT_MARKERS),
            "accepted": any(m in lowered for m in _SUCCESS_MARKERS)}


def _post_code(client, url: str, param: Optional[str],
               value: Optional[str], timeout: int = 10):
    from urllib.parse import urlencode
    pairs = [] if param is None or value is None else [(param, value)]
    body = urlencode(pairs)
    return client.post(
        url, data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=timeout)


def check_otp_bypass(client, url: str, param: str,
                     timeout: int = 10) -> List[OtpBypassResult]:
    """Wrong-code baseline, then empty-code and omitted-code probes.

    A probe counts as bypass only when the baseline is a clear
    rejection and the probe is a clear acceptance (2xx + success
    marker, no rejection marker). Matching rejections are genuine
    negatives; rate limits, server errors, and mixed signals stay
    inconclusive.
    """
    out = [OtpBypassResult(url=url, check="otp-empty"),
           OtpBypassResult(url=url, check="otp-omitted")]
    try:
        r_base = _post_code(client, url, param, WRONG_CODE,
                            timeout=timeout)
        r_empty = _post_code(client, url, param, "",
                             timeout=timeout)
        r_omitted = _post_code(client, url, None, None,
                               timeout=timeout)
    except BudgetExceeded:
        raise
    except Exception as exc:
        for res in out:
            res.notes = f"request failed: {exc}"[:200]
        return out
    statuses = [getattr(r, "status_code", 0) or 0
                for r in (r_base, r_empty, r_omitted)]
    if any(s == 405 for s in statuses):
        for res in out:
            res.notes = "verification endpoint does not accept " \
                        "POST; refusing to guess another shape"
        return out
    if any(s == 429 for s in statuses):
        for res in out:
            res.notes = "rate limited (429): attempts are throttled, " \
                        "no bypass signal"
        return out
    if any(s >= 500 for s in statuses):
        for res in out:
            res.notes = "server error: no bypass signal"
        return out
    base_marks = _markers(getattr(r_base, "text", "") or "")
    base_rejected = r_base.status_code in (400, 401, 403, 404, 422) \
        or (r_base.status_code == 200 and base_marks["rejected"]
            and not base_marks["accepted"])
    if not base_rejected:
        for res in out:
            res.notes = "wrong-code baseline is not a clear " \
                        "rejection; the oracle is unusable"
        return out
    for res, probe in zip(out, (r_empty, r_omitted)):
        res.status = getattr(probe, "status_code", 0) or 0
        marks = _markers(getattr(probe, "text", "") or "")
        if res.status == 200 and marks["accepted"] \
                and not marks["rejected"]:
            res.verdict = "candidate"
            res.notes = (f"verification accepted without a valid code "
                         f"({res.check}) while a wrong code is rejected")
            res.evidence = {"check": res.check,
                            "baseline_status": r_base.status_code,
                            "probe_status": res.status}
            continue
        res.verdict = "negative"
        res.notes = (f"probe rejected like the wrong-code baseline "
                     f"({res.status})")
    return out


def otp_targets(endpoints: List[Any]) -> List[Any]:
    """In-scope OTP-path endpoints; pure selection, no network."""
    return [e for e in endpoints or []
            if is_otp_endpoint(getattr(e, "url", "") or "")]
