"""MFA session-transition checks (test sessions only).

Hunter methodology (MFA-bypass writeups): obtain a session that has
authenticated but not yet completed MFA, then ask whether it can already
reach privileged resources. A pre-MFA session that sees the same
protected object as the post-MFA session is a session-issuance flaw.

Safety contract (bounded, fail-closed):
- read-only GETs against operator-supplied test sessions; nothing is
  submitted, no challenge is answered, MFA is never bypassed or
  auto-retried (a challenge is simply observed as a denial).
- a flaw needs equivalent responses (status + shape + hash) from both
  sessions; any difference in what the sessions see is inconclusive,
  never a finding on its own beyond the recorded comparison.
- completed denials with finished requests are genuine negatives,
  mirroring the swap precondition rule.
"""
from dataclasses import dataclass
from typing import Dict, Optional

from ..budgets import BudgetExceeded
from ..logging_setup import get_logger

log = get_logger("mfa_checks")

# responses that prove nothing either way
_DENIED = {401, 403}


@dataclass
class MfaCheckResult:
    endpoint_url: str
    pre_identity: str
    post_identity: str
    pre_status: int = 0
    post_status: int = 0
    verdict: str = "inconclusive"
    notes: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {"endpoint_url": self.endpoint_url,
                "pre_identity": self.pre_identity,
                "post_identity": self.post_identity,
                "pre_status": self.pre_status,
                "post_status": self.post_status,
                "verdict": self.verdict, "notes": self.notes}


def _login_redirected(status: Optional[int], headers) -> bool:
    if status not in (301, 302, 303, 307, 308):
        return False
    try:
        location = ""
        for name, value in (headers or {}).items():
            if str(name).lower() == "location" and isinstance(value, str):
                location = value.lower()
                break
        from ..auth.workflows import looks_like_mfa  # local import
        return "login" in location or looks_like_mfa(location, "")
    except Exception:
        return False


def check_transition(http, endpoint_url: str, pre_headers: Dict[str, str],
                     post_headers: Dict[str, str], pre_name: str,
                     post_name: str, timeout: int = 10) -> MfaCheckResult:
    """Compare one privileged URL under pre- vs post-MFA test sessions."""
    from ..validation.differential import normalize_response
    res = MfaCheckResult(endpoint_url=endpoint_url, pre_identity=pre_name,
                         post_identity=post_name)
    try:
        pre = http.get(endpoint_url, headers=pre_headers, timeout=timeout)
    except BudgetExceeded:
        raise
    except Exception as exc:
        log.debug("mfa pre-session fetch failed: %s", exc)
        res.notes = "pre-MFA request failed without a response"
        return res
    try:
        post = http.get(endpoint_url, headers=post_headers, timeout=timeout)
    except BudgetExceeded:
        raise
    except Exception as exc:
        log.debug("mfa post-session fetch failed: %s", exc)
        res.notes = "post-MFA request failed without a response"
        return res
    res.pre_status = getattr(pre, "status_code", 0) or 0
    res.post_status = getattr(post, "status_code", 0) or 0
    pre_denied = res.pre_status in _DENIED or _login_redirected(
        res.pre_status, getattr(pre, "headers", None))
    post_denied = res.post_status in _DENIED or _login_redirected(
        res.post_status, getattr(post, "headers", None))
    if pre_denied and not post_denied and res.post_status == 200:
        res.verdict = "tested_negative"
        res.notes = (f"healthy MFA gate: '{pre_name}' is denied "
                     f"({res.pre_status}) while '{post_name}' reaches the "
                     f"resource ({res.post_status})")
        return res
    if res.pre_status != 200 or res.post_status != 200:
        res.notes = (f"sessions disagree without a readable baseline "
                     f"({pre_name}→{res.pre_status}, "
                     f"{post_name}→{res.post_status})")
        return res
    try:
        pre_norm = normalize_response(pre)
        post_norm = normalize_response(post)
    except Exception:
        res.notes = "responses could not be normalized safely"
        return res
    same = (pre_norm.get("status") == post_norm.get("status")
            and pre_norm.get("key_shape") == post_norm.get("key_shape")
            and pre_norm.get("body_hash") == post_norm.get("body_hash"))
    if same:
        res.verdict = "strong_candidate"
        res.notes = (f"pre-MFA session '{pre_name}' sees the same protected "
                     f"object as post-MFA '{post_name}' "
                     f"(shape={pre_norm.get('key_shape', '')[:80] or 'n/a'})")
    else:
        res.notes = (f"sessions see different content "
                     f"({pre_name} vs {post_name}); no issuance flaw proven")
    return res
