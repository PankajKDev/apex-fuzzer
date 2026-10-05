"""Coverage model (§44–45): per-class test status, honestly tracked.

Every class is exactly one of: confirmed | candidate | tested_negative |
inconclusive | blocked | untestable | not_tested | not_applicable.
Precedence on merge: confirmed > candidate > inconclusive > blocked >
tested_negative > untestable > not_tested > not_applicable.

Only observed evidence moves a class: a probed endpoint with no signal
is tested_negative; a class no engine touched stays not_tested. Absence
of findings is never presented as proof of security — the report lists
untested classes explicitly.
"""
from typing import Any, Dict, List, Optional
from ..logging_setup import get_logger
from ..models import Finding

log = get_logger("coverage")

CONFIRMED = "confirmed"
CANDIDATE = "candidate"
TESTED_NEGATIVE = "tested_negative"
INCONCLUSIVE = "inconclusive"
BLOCKED = "blocked"
UNTESTABLE = "untestable"
NOT_TESTED = "not_tested"
NOT_APPLICABLE = "not_applicable"

# detection classes from the Definition of Done (§61)
KNOWN_CLASSES = [
    "sqli", "xss", "ssrf", "csrf", "cors", "bola", "bfla", "jwt",
    "oauth", "graphql", "websocket", "upload", "prototype_pollution",
    "request_smuggling", "cache", "host_header", "mass_assignment",
    "parameter_pollution", "method_override", "second_order",
    "business_logic", "race", "idor", "authz", "mfa", "ssti", "xxe", "cmdi",
    "second_order_ssrf",
    "path_traversal", "open_redirect", "info_disclosure", "takeover",
    "tenant_isolation", "clickjacking",
]

_PRECEDENCE = [CONFIRMED, CANDIDATE, INCONCLUSIVE, BLOCKED,
               TESTED_NEGATIVE, UNTESTABLE, NOT_TESTED, NOT_APPLICABLE]

_RESULT_TO_COVERAGE = {
    "observation": NOT_TESTED,
    "candidate": CANDIDATE,
    "verified_effect": CONFIRMED,
    "negative": TESTED_NEGATIVE,
    "inconclusive": INCONCLUSIVE,
}


def classify_finding(f: Finding) -> str:
    """Finding → coverage test class, by name/template text."""
    name = (f.name or "").lower() + " " + (f.template_id or "").lower()
    if "sqli" in name or "sql" in name:
        return "sqli"
    if "xss" in name:
        return "xss"
    if "ssrf" in name:
        return "ssrf"
    if "ssti" in name or "server-side template" in name or \
            "server side template" in name:
        return "ssti"
    if "xxe" in name or "xml external entity" in name:
        return "xxe"
    if ("traversal" in name or "lfi" in name
            or "file inclusion" in name):
        return "path_traversal"
    if "redirect" in name:
        return "open_redirect"
    if "idor" in name or "bola" in name:
        return "idor"
    return "unknown"


class CoverageTracker:
    def __init__(self, known: Optional[List[str]] = None):
        self.known = list(known or KNOWN_CLASSES)
        self.status: Dict[str, str] = {}
        self.detail: Dict[str, str] = {}
        self.counts: Dict[str, int] = {}

    def record(self, test_class: str, status: str,
               detail: str = "") -> str:
        """Merge one observation; returns the resulting status."""
        test_class = (test_class or "unknown").lower()
        if status not in _PRECEDENCE:
            raise ValueError(f"unknown coverage status: {status}")
        cur = self.status.get(test_class, NOT_TESTED)
        if _PRECEDENCE.index(status) < _PRECEDENCE.index(cur):
            self.status[test_class] = status
            if detail:
                self.detail[test_class] = detail[:300]
        self.counts[test_class] = self.counts.get(test_class, 0) + 1
        return self.status.get(test_class, NOT_TESTED)

    def record_result(self, test_class: str, result_status: str,
                      detail: str = "") -> str:
        """Record a canonical result using the established coverage terms.

        Execution outcomes (blocked, skipped, error) remain explicit calls
        to record(); they are not vulnerability-result categories.
        """
        try:
            coverage_status = _RESULT_TO_COVERAGE[result_status]
        except KeyError:
            raise ValueError(
                f"unknown result status: {result_status}")
        return self.record(test_class, coverage_status, detail)

    def mark_untestable(self, test_class: str, reason: str):
        self.record(test_class, UNTESTABLE, reason)

    def summary(self) -> Dict[str, str]:
        return {c: self.status.get(c, NOT_TESTED) for c in self.known}

    def untested(self) -> List[str]:
        """Classes with no meaningful test: not_tested or inconclusive."""
        return [c for c in self.known
                if self.status.get(c, NOT_TESTED) in (NOT_TESTED,
                                                       INCONCLUSIVE)]

    def tested(self) -> List[str]:
        return [c for c in self.known
                if self.status.get(c, NOT_TESTED) not in (NOT_TESTED,)]

    def to_dict(self) -> Dict[str, Any]:
        return {"status": dict(self.status), "detail": dict(self.detail),
                "counts": dict(self.counts), "known": list(self.known)}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CoverageTracker":
        t = cls(known=d.get("known"))
        t.status = dict(d.get("status") or {})
        t.detail = dict(d.get("detail") or {})
        t.counts = dict(d.get("counts") or {})
        return t
