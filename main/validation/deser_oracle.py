"""Deserialization error oracle: type confusion on JSON endpoints.

One scalar control plus one array and one object probe per
parameter, all as JSON POST bodies. Deserialization exception text
on a probe while the control stays clean is a candidate (error
oracle only — it proves a deserializer choked, never gadget
reachability or code execution). Always POSTs, so state-change
authorization is required. Bodies carry inert marker strings.
"""
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List

from ..budgets import BudgetExceeded
from ..logging_setup import get_logger

log = get_logger("deser-oracle")

# (family, pattern) pairs. Matches stay candidate-level: exception
# text alone never confirms gadget reachability.
_DESER_FAMILIES = [
    ("jackson", r"MismatchedInputException|JsonMappingException|"
                r"Cannot deserialize|UnrecognizedPropertyException"),
    ("gson", r"JsonSyntaxException|Expected BEGIN_OBJECT|"
             r"JsonParseException"),
    ("php", r"unserialize\(\)|__PHP_Incomplete_Class|"
            r"allowed_classes"),
    ("pickle", r"UnpicklingError|STACK_GLOBAL|_pickle"),
    ("yaml", r"ConstructorError|"
              r"could not determine a constructor"),
    ("java", r"InvalidClassException|NotSerializableException|"
             r"StreamCorruptedException"),
    ("dotnet", r"SerializationException|BinaryFormatter"),
    ("ruby-marshal", r"incompatible marshal|Marshal\.load"),
]
_DESER_RES = [(family, re.compile(pattern, re.I))
              for family, pattern in _DESER_FAMILIES]


@dataclass
class DeserOracleResult:
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


def deser_error_markers(text: str) -> List[str]:
    """Sorted deserializer families whose exception text appears."""
    if not text:
        return []
    window = text[:200_000]
    return sorted({family for family, rx in _DESER_RES
                   if rx.search(window)})


def check_deser_oracle(client, url: str, param: str,
                       timeout: int = 10) -> DeserOracleResult:
    """Scalar control, then array/object type-confusion probes."""
    import json as _json
    res = DeserOracleResult(url=url, param=param)

    def _post(payload: Any):
        return client.post(
            url, data=_json.dumps({param: payload}),
            headers={"Content-Type": "application/json"},
            timeout=timeout)

    try:
        r_control = _post("apex-scalar")
        r_array = _post(["apex-array-probe"])
        r_object = _post({"apex": "object-probe"})
    except BudgetExceeded:
        raise
    except Exception as exc:
        res.notes = f"request failed: {exc}"[:200]
        return res
    statuses = [getattr(r, "status_code", 0) or 0
                for r in (r_control, r_array, r_object)]
    if any(s == 405 for s in statuses):
        res.notes = "endpoint does not accept POST; refusing to " \
                    "guess another submission shape"
        return res
    if any(s >= 500 for s in statuses):
        res.notes = "server error: no deserialization signal"
        return res
    if deser_error_markers(getattr(r_control, "text", "") or ""):
        res.notes = "control response already carries deserializer " \
                    "markers; error-text verdicts are unsafe"
        return res
    for label, probe in (("array", r_array), ("object", r_object)):
        markers = deser_error_markers(getattr(probe, "text", "") or "")
        if markers:
            res.verdict = "candidate"
            res.status = getattr(probe, "status_code", 0) or 0
            res.notes = (f"deserializer exception on {label} input "
                         f"for {param!r} "
                         f"({', '.join(markers)})")
            res.evidence = {"param": param, "shape": label,
                            "families": markers,
                            "status": res.status}
            return res
    res.verdict = "negative"
    res.notes = (f"no deserializer markers on type-confusion input "
                 f"for {param!r}")
    return res
