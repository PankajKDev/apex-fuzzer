"""Password-reset flow checks: enumeration oracle + reset-link poisoning.

Both checks use operator-supplied test identifiers only (login
usernames from ``auth.login.identities``) — never invented addresses.
A reset request emails the operator's own test inbox; nothing is
redeemed, followed, or submitted beyond the reset request itself.
Identifier *values* stay runtime-only; evidence keeps field names,
statuses, and booleans.
"""
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from ..budgets import BudgetExceeded
from ..logging_setup import get_logger

log = get_logger("reset-flow")

# Path segments that mark a password-reset submission surface. OTP
# flows are a separate writeup item and stay out of this module.
RESET_PATH_HINTS = ("forgot", "forgot-password", "reset",
                    "password-reset", "recover", "recovery")

# Identifier fields a reset form plausibly submits.
RESET_IDENTIFIER_PARAMS = ("email", "email_address", "username",
                           "user", "account", "login")

# .invalid never resolves: reflected occurrences prove server-side
# trust without ever reaching an attacker host.
EVIL_HOST = "attacker.invalid"

_HREF_RE = re.compile(r"""href\s*=\s*["']([^"']+)["']""",
                      re.IGNORECASE)
_LINK_HINTS = ("reset", "forgot", "recover", "password", "token")


@dataclass
class ResetFlowResult:
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


def is_reset_endpoint(url: str) -> bool:
    """True when a path segment names a password-reset flow.

    Compound segments (``forgot-password``, ``reset-request``) match
    on their parts; plain substrings (``preset``) never match.
    """
    import re
    try:
        segments = [seg.lower() for seg in
                    urlsplit(url or "").path.split("/") if seg]
    except ValueError:
        return False
    parts = set()
    for seg in segments:
        parts.update(re.split(r"[-_]", seg))
    return any(part in RESET_PATH_HINTS for part in parts)


def identifier_param_for(endpoint: Any) -> Optional[str]:
    """First known identifier field on the endpoint, else None.

    Unknown shapes fail closed: the probe never guesses field names.
    """
    seen = []
    for attr in ("body_parameters", "query_parameters"):
        for param in list(getattr(endpoint, attr, None) or []):
            name = getattr(param, "name", "") or ""
            if name and name not in seen:
                seen.append(name)
    for name in seen:
        if str(name).lower().replace("-", "_") \
                in RESET_IDENTIFIER_PARAMS:
            return name
    return None


def invalid_identifier(valid: str) -> str:
    """A well-formed but clearly-nonexistent sibling identifier."""
    text = str(valid or "")
    if "@" in text:
        return f"nonexistent-{text}"
    return f"{text}-nonexistent-apex"


def _post_form(client, url: str, param: str, value: str,
               headers: Optional[Dict[str, str]] = None,
               timeout: int = 10):
    from urllib.parse import urlencode
    body = urlencode([(param, value)])
    merged = {"Content-Type": "application/x-www-form-urlencoded"}
    merged.update(headers or {})
    return client.post(url, data=body, headers=merged,
                       timeout=timeout)


def check_reset_enumeration(client, url: str, param: str,
                            valid: str,
                            timeout: int = 10) -> ResetFlowResult:
    """Same reset request with a known vs unknown identifier.

    A shape/status difference is a user-enumeration oracle
    (candidate). Identical completed responses are a genuine
    negative; server errors stay inconclusive, never negative.
    Pure length differences with identical shapes are input echo,
    not an oracle.
    """
    from ..validation.differential import normalize_response
    res = ResetFlowResult(url=url, check="reset-enum")
    try:
        r_valid = _post_form(client, url, param, valid,
                             timeout=timeout)
        r_invalid = _post_form(client, url, param,
                               invalid_identifier(valid),
                               timeout=timeout)
    except BudgetExceeded:
        raise
    except Exception as exc:
        res.notes = f"request failed: {exc}"[:200]
        return res
    if r_valid.status_code == 405 or r_invalid.status_code == 405:
        res.notes = "reset endpoint does not accept POST; refusing " \
                    "to guess another submission shape"
        return res
    if r_valid.status_code >= 500 or r_invalid.status_code >= 500:
        res.notes = (f"server error ({r_valid.status_code}/"
                     f"{r_invalid.status_code}): no oracle signal")
        return res
    try:
        norm_valid = normalize_response(r_valid)
        norm_invalid = normalize_response(r_invalid)
    except Exception as exc:
        res.notes = f"response comparison failed: {exc}"[:200]
        return res
    res.status = int(norm_valid.get("status", 0) or 0)
    invalid_status = norm_invalid.get("status")
    if res.status != invalid_status:
        differs = True
        detail = f"status {res.status} vs {invalid_status}"
    elif norm_valid.get("key_shape") != norm_invalid.get("key_shape"):
        differs = True
        detail = "response structure differs"
    elif norm_valid.get("body_hash") != norm_invalid.get("body_hash"):
        # same status and structure, different bytes: rule out pure
        # input echo (plain and urlencoded forms) before calling it
        # an oracle.
        from urllib.parse import quote
        scrubbed = invalid_identifier(valid)
        needles = sorted(
            {valid, scrubbed, quote(valid, safe=""),
             quote(scrubbed, safe="")},
            key=len, reverse=True)

        def _scrubbed(text: str) -> str:
            for needle in needles:
                if needle:
                    text = text.replace(needle, "\x00")
            return text

        differs = _scrubbed(r_valid.text or "") != _scrubbed(
            r_invalid.text or "")
        detail = "response content differs beyond input echo"
    else:
        differs = False
        detail = ""
    if differs:
        res.verdict = "candidate"
        res.notes = (f"reset responses differ for a known vs unknown "
                     f"identifier field ({detail})")
        res.evidence = {"param": param,
                        "valid_status": res.status,
                        "invalid_status": invalid_status,
                        "shapes_differ": True}
        return res
    res.verdict = "negative"
    res.notes = (f"identical reset responses for known vs unknown "
                 f"identifier ({res.status})")
    return res


def check_reset_host_poison(client, url: str, param: str,
                            valid: str,
                            timeout: int = 10) -> ResetFlowResult:
    """Submit a reset request with an attacker Host header.

    A redirect or reset-link pointing at the evil host is a
    poisoning candidate. Bare reflection without link context
    stays inconclusive; no reflection is a genuine negative.
    """
    res = ResetFlowResult(url=url, check="reset-poison")
    try:
        r = _post_form(client, url, param, valid,
                       headers={"Host": EVIL_HOST,
                                "X-Forwarded-Host": EVIL_HOST},
                       timeout=timeout)
    except BudgetExceeded:
        raise
    except Exception as exc:
        res.notes = f"request failed: {exc}"[:200]
        return res
    res.status = getattr(r, "status_code", 0) or 0
    if res.status >= 500:
        res.notes = f"HTTP {res.status}: error, no poison signal"
        return res
    headers = {}
    try:
        for name, value in (getattr(r, "headers", None) or {}).items():
            headers[str(name)] = str(value)
    except (AttributeError, TypeError):
        pass
    for name, value in headers.items():
        if name.lower() == "location" and EVIL_HOST in value:
            res.verdict = "candidate"
            res.notes = f"reset response redirects to {EVIL_HOST} " \
                        f"({value[:200]})"
            res.evidence = {"location": value[:500],
                            "status": res.status}
            return res
    text = str(getattr(r, "text", "") or "")
    links = [m for m in _HREF_RE.findall(text)
             if EVIL_HOST in m and
             any(hint in m.lower() for hint in _LINK_HINTS)]
    if links:
        res.verdict = "candidate"
        res.notes = f"reset link points at {EVIL_HOST}"
        try:
            shown = urlsplit(links[0])._replace(
                query="", fragment="").geturl()
        except ValueError:
            shown = EVIL_HOST
        res.evidence = {"link": shown[:500],
                        "status": res.status}
        return res
    if EVIL_HOST in text:
        res.notes = "evil host reflected without reset-link context; " \
                    "no poisoning impact shown"
        res.evidence = {"reflected": True, "status": res.status}
        return res
    res.verdict = "negative"
    res.notes = "override ignored: no redirect, link, or reflection"
    return res


def reset_targets(endpoints: List[Any]) -> List[Any]:
    """In-scope reset-path endpoints; pure selection, no network."""
    return [e for e in endpoints or []
            if is_reset_endpoint(getattr(e, "url", "") or "")]
