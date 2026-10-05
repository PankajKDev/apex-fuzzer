"""HTTP Parameter Pollution: duplicated query parameters.

Three read-only GETs per parameter: the observed baseline, the same
URL with the parameter duplicated carrying a benign distinct value,
and a control duplication repeating the original value. The control
separates server-side precedence effects from pure input echo: when
the duplicate and the control match after blanking the second
occurrence, the server echoes input without acting on it.
Inconsistent handling beyond echo is a candidate — duplicated
parameters are a classic filter/WAF-bypass primitive. Identical
handling is a genuine negative; server errors stay inconclusive.
"""
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlsplit, urlunsplit, urlencode

from ..budgets import BudgetExceeded
from ..logging_setup import get_logger

log = get_logger("param-pollution")

# Benign second value: distinct enough to observe precedence, inert
# enough to change nothing server-side on its own.
DUP_VALUE = "apex-pollution-probe"


@dataclass
class HppResult:
    url: str
    param: str
    # candidate | negative | inconclusive
    verdict: str = "inconclusive"
    notes: str = ""
    status: int = 0
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"url": self.url, "param": self.param,
                "verdict": self.verdict, "notes": self.notes,
                "status": self.status, "evidence": dict(self.evidence)}


def polluted_url(url: str, param: str,
                 second: Optional[str] = None) -> Optional[str]:
    """Append a second occurrence of one query parameter.

    ``second=None`` repeats the observed first value (control);
    otherwise the given distinct value is appended.
    """
    try:
        parts = urlsplit(url or "")
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or \
            not parts.hostname:
        return None
    try:
        query = parse_qsl(parts.query, keep_blank_values=True)
    except (TypeError, ValueError):
        return None
    if not any(key == param for key, _ in query):
        return None
    first = next(v for k, v in query if k == param)
    query.append((param, first if second is None else second))
    return urlunsplit((parts.scheme, parts.netloc, parts.path,
                       urlencode(query, doseq=True), ""))


def _blank_second_occurrence(text: str, param: str) -> str:
    """Blank the value of the second `param=` occurrence.

    Lets the duplicate and the control be compared on everything
    except the differing second value itself: equal remainders mean
    pure input echo, not server-side precedence.
    """
    pattern = re.compile(re.escape(param) + r"=([^&\s\"'<>]*)")
    seen = {"n": 0}

    def _sub(match: "re.Match") -> str:
        seen["n"] += 1
        return f"{param}=\x00" if seen["n"] == 2 else match.group(0)

    return pattern.sub(_sub, text or "")


def check_hpp(client, url: str, param: str,
              timeout: int = 10) -> HppResult:
    """Baseline GET vs duplicated-parameter GET vs repeat control."""
    from ..validation.differential import normalize_response
    res = HppResult(url=url, param=param)
    dup = polluted_url(url, param, DUP_VALUE)
    control = polluted_url(url, param)
    if dup is None or control is None:
        res.notes = f"parameter {param!r} not in query string"
        return res
    try:
        r_base = client.get(url, timeout=timeout)
        r_dup = client.get(dup, timeout=timeout)
        r_control = client.get(control, timeout=timeout)
    except BudgetExceeded:
        raise
    except Exception as exc:
        res.notes = f"request failed: {exc}"[:200]
        return res
    statuses = [getattr(r, "status_code", 0) or 0
                for r in (r_base, r_dup, r_control)]
    if any(s >= 500 for s in statuses):
        res.notes = "server error: no pollution signal"
        return res
    try:
        norms = [normalize_response(r)
                 for r in (r_base, r_dup, r_control)]
    except Exception as exc:
        res.notes = f"response comparison failed: {exc}"[:200]
        return res
    res.status = int(norms[1].get("status", 0) or 0)
    base, probing, ctrl = norms
    if (probing.get("status") == base.get("status")
            and probing.get("key_shape") == base.get("key_shape")
            and probing.get("body_hash") == base.get("body_hash")):
        res.verdict = "negative"
        res.notes = (f"duplicated parameter {param!r} handled "
                     f"identically ({res.status})")
        return res
    # The duplicate moved the response: check the move survives
    # blanking the second occurrence (a pure echo does not).
    if _blank_second_occurrence(getattr(r_dup, "text", "") or "",
                                param) == \
            _blank_second_occurrence(getattr(r_control, "text", "") or "",
                                     param) and \
            ctrl.get("status") == probing.get("status"):
        res.verdict = "negative"
        res.notes = (f"duplicated parameter {param!r} only echoes "
                     f"input ({res.status})")
        return res
    res.verdict = "candidate"
    res.notes = (f"duplicated parameter {param!r} handled "
                 f"inconsistently beyond input echo")
    res.evidence = {"param": param,
                    "base_status": base.get("status"),
                    "dup_status": res.status}
    return res


def query_params(url: str) -> List[str]:
    """Observed query parameter names in first-seen order."""
    try:
        return [key for key, _ in parse_qsl(
            urlsplit(url or "").query, keep_blank_values=True) if key]
    except ValueError:
        return []
