"""Lifecycle rules: which state transitions are legal (agent P3).

Lifecycles declare the valid transitions per resource type;
check_transition answers allowed/denied with a reason. Unknown
states or unknown resource types are *inconclusive*, never violations
— the scanner must not invent rules for behavior it has not modeled.
Phase 17 will mine these rules from observed traffic; Phase 3 ships
sane, explicit defaults.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Tuple
from ..logging_setup import get_logger

log = get_logger("state-lifecycle")


@dataclass
class Lifecycle:
    resource_type: str
    states: List[str] = field(default_factory=list)
    allowed: Dict[str, List[str]] = field(default_factory=dict)
    terminal: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"resource_type": self.resource_type,
                "states": self.states, "allowed": self.allowed,
                "terminal": self.terminal}

    @classmethod
    def from_dict(cls, d: dict) -> "Lifecycle":
        return cls(resource_type=d.get("resource_type", ""),
                   states=d.get("states") or [],
                   allowed=d.get("allowed") or {},
                   terminal=d.get("terminal") or [])


GENERIC_CRUD = Lifecycle(
    resource_type="object",
    states=["absent", "active", "deleted"],
    allowed={"absent": ["active"], "active": ["deleted"],
             "deleted": []},
    terminal=["deleted"])

ORDER_FLOW = Lifecycle(
    resource_type="order",
    states=["draft", "pending", "paid", "completed", "cancelled",
            "refunded"],
    allowed={"draft": ["pending", "cancelled"],
             "pending": ["paid", "cancelled"],
             "paid": ["completed", "refunded"],
             "completed": [], "cancelled": [], "refunded": []},
    terminal=["completed", "cancelled", "refunded"])

INVITATION_FLOW = Lifecycle(
    resource_type="invitation",
    states=["created", "sent", "accepted", "expired", "revoked"],
    allowed={"created": ["sent", "revoked"], "sent": ["accepted",
                                                      "expired",
                                                      "revoked"],
             "accepted": [], "expired": [], "revoked": []},
    terminal=["accepted", "expired", "revoked"])

DEFAULT_LIFECYCLES: Dict[str, Lifecycle] = {
    "object": GENERIC_CRUD,
    "order": ORDER_FLOW,
    "invitation": INVITATION_FLOW,
}


def check_transition(lifecycle: Lifecycle | None, from_state: str,
                     to_state: str) -> Tuple[str, str]:
    """allowed | denied | inconclusive, plus a human reason."""
    if lifecycle is None:
        return ("inconclusive",
                "no lifecycle modeled for this resource type")
    if from_state not in lifecycle.states or \
            to_state not in lifecycle.states:
        return ("inconclusive",
                f"unmodeled state(s): {from_state} → {to_state}")
    if to_state in lifecycle.allowed.get(from_state, []):
        return ("allowed", f"{from_state} → {to_state} is valid")
    if from_state in lifecycle.terminal:
        return ("denied", f"{from_state} is terminal; transition to "
                          f"{to_state} violates the lifecycle")
    return ("denied", f"{from_state} → {to_state} is not a valid "
                      f"transition")
