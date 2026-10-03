"""Security invariant engine (§16).

An invariant is a named predicate over a normalized *observation* dict::

    {"actor": "user_a", "actor_tenant": "t1", "action": "read",
     "resource_owner": "user_b", "resource_tenant": "t1",
     "state_before": "active", "state_after": "deleted",
     "quantity_before": 2, "quantity_after": 1,
     "payment": 100, "refund": 120, "price_changed": False,
     "self_promotion": False, "token_single_use": True, "token_reused": False}

Built-in checks cover the spec's example invariants; custom checks can
be registered and custom Invariants defined (user-supplied invariants
arrive via config in Phase 5 — the registry API is stable now).
"""
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Tuple
from ..logging_setup import get_logger

log = get_logger("invariants")

CheckFn = Callable[[Dict[str, Any], Dict[str, Any]], Tuple[bool, str]]

_REGISTRY: Dict[str, CheckFn] = {}


def register_check(name: str, fn: CheckFn):
    _REGISTRY[name] = fn


def _get(obs: Dict[str, Any], key: str, default=None):
    return obs.get(key, default)


def _check_no_cross_user_read(obs, params) -> Tuple[bool, str]:
    if _get(obs, "action") not in ("read", "export"):
        return False, ""
    actor, owner = _get(obs, "actor"), _get(obs, "resource_owner")
    if not actor or not owner or actor == owner:
        return False, ""
    if _get(obs, "actor_is_admin"):
        return False, ""
    return True, (f"{actor} read {owner}'s resource "
                  f"({_get(obs, 'resource', '')})")


def _check_no_unauthorized_write(obs, params) -> Tuple[bool, str]:
    if _get(obs, "action") not in ("write", "update", "create", "delete"):
        return False, ""
    if _get(obs, "authorized", True):
        return False, ""
    return True, (f"{_get(obs, 'actor')} performed {_get(obs, 'action')} "
                  f"without permission on {_get(obs, 'resource', '')}")


def _check_no_modify_deleted(obs, params) -> Tuple[bool, str]:
    if _get(obs, "state_before") == "deleted" and \
            _get(obs, "action") in ("write", "update", "delete", "publish"):
        return True, "modification applied to a deleted object"
    return False, ""


def _check_no_self_promote(obs, params) -> Tuple[bool, str]:
    if _get(obs, "self_promotion"):
        return True, f"{_get(obs, 'actor')} escalated its own privileges"
    return False, ""


def _check_quantity_non_negative(obs, params) -> Tuple[bool, str]:
    q = _get(obs, "quantity_after")
    if q is not None and q < 0:
        return True, f"quantity became negative ({q})"
    return False, ""


def _check_price_stable(obs, params) -> Tuple[bool, str]:
    if _get(obs, "price_changed") and not _get(obs, "price_authorized"):
        return True, "price changed without authorization"
    return False, ""


def _check_refund_lte_payment(obs, params) -> Tuple[bool, str]:
    pay, ref = _get(obs, "payment"), _get(obs, "refund")
    if pay is not None and ref is not None and ref > pay:
        return True, f"refund {ref} exceeds payment {pay}"
    return False, ""


def _check_single_use_token(obs, params) -> Tuple[bool, str]:
    if _get(obs, "token_single_use") and _get(obs, "token_reused"):
        return True, "single-use token accepted twice"
    return False, ""


def _check_no_revert_completed(obs, params) -> Tuple[bool, str]:
    if _get(obs, "state_before") == "completed" and \
            _get(obs, "state_after") not in ("completed", None) and \
            not _get(obs, "revert_authorized"):
        return True, (f"completed workflow moved to "
                      f"{_get(obs, 'state_after')} without authorization")
    return False, ""


def _check_no_access_deleted(obs, params) -> Tuple[bool, str]:
    # observation contract: {action, state_before, actor, resource}
    if _get(obs, "state_before") == "deleted" and \
            _get(obs, "action") in ("read", "export"):
        return True, (f"{_get(obs, 'actor')} accessed deleted object "
                      f"{_get(obs, 'resource', '')}")
    return False, ""


def _check_no_expired_session(obs, params) -> Tuple[bool, str]:
    # observation contract: {session_expired: bool, status, actor,
    # endpoint_type}; violation needs a SUCCEEDED protected request —
    # mere expiry with denial is enforcement, not a bug
    if _get(obs, "session_expired") and \
            _get(obs, "status") == 200 and \
            _get(obs, "endpoint_type", "api") in (
                "api", "admin", "authentication"):
        return True, (f"{_get(obs, 'actor')} performed a protected "
                       f"request with an expired session")
    return False, ""


def _check_no_recharge_refunded(obs, params) -> Tuple[bool, str]:
    # observation contract: {state_before, action, actor, resource}
    if _get(obs, "state_before") == "refunded" and \
            _get(obs, "action") in ("charge", "pay", "capture",
                                     "write", "update"):
        return True, (f"{_get(obs, 'resource', '')} was charged again "
                      f"after refund")
    return False, ""


for _name, _fn in {
    "no_cross_user_read": _check_no_cross_user_read,
    "no_unauthorized_write": _check_no_unauthorized_write,
    "no_modify_deleted": _check_no_modify_deleted,
    "no_self_promote": _check_no_self_promote,
    "quantity_non_negative": _check_quantity_non_negative,
    "price_stable": _check_price_stable,
    "refund_lte_payment": _check_refund_lte_payment,
    "single_use_token": _check_single_use_token,
    "no_revert_completed": _check_no_revert_completed,
    "no_access_deleted": _check_no_access_deleted,
    "no_expired_session": _check_no_expired_session,
    "no_recharge_refunded": _check_no_recharge_refunded,
}.items():
    register_check(_name, _fn)

BUILTIN_IDS = sorted(_REGISTRY.keys())

# params keys honored centrally as scoping filters (all checks,
# including future/custom ones): an invariant with params scoping
# only evaluates in-scope observations, and reports the skip
# explicitly instead of silently passing.
_SCOPE_KEYS = ("resource", "endpoint", "actor", "tenant")


def _in_scope(inv, observation: Dict[str, Any]) -> Tuple[bool, str]:
    for key in _SCOPE_KEYS:
        wanted = (inv.params or {}).get(key)
        if wanted in (None, ""):
            continue
        if key == "tenant":
            got = observation.get("resource_tenant",
                                  observation.get("actor_tenant"))
        else:
            got = observation.get(key)
        if got != wanted:
            return False, f"out of scope ({key}={got!r}, rule pins " \
                          f"{wanted!r})"
    return True, ""


@dataclass
class Invariant:
    id: str
    description: str
    check: str
    severity: str = "high"
    params: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "description": self.description,
                "check": self.check, "severity": self.severity,
                "params": self.params}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Invariant":
        return cls(id=d.get("id", ""), description=d.get("description", ""),
                   check=d.get("check", ""),
                   severity=d.get("severity", "high"),
                   params=d.get("params") or {})


@dataclass
class InvariantResult:
    invariant_id: str
    violated: bool
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"invariant_id": self.invariant_id,
                "violated": self.violated, "detail": self.detail}


def default_invariants() -> List[Invariant]:
    return [
        Invariant(id="inv-cross-user-read",
                  description="User A cannot read User B's private object.",
                  check="no_cross_user_read"),
        Invariant(id="inv-unauthorized-write",
                  description="User without permission cannot modify object.",
                  check="no_unauthorized_write"),
        Invariant(id="inv-modify-deleted",
                  description="Deleted object cannot be modified.",
                  check="no_modify_deleted"),
        Invariant(id="inv-self-promote",
                  description="Unauthorized user cannot promote themselves.",
                  check="no_self_promote"),
        Invariant(id="inv-quantity",
                  description="Quantity cannot become negative.",
                  check="quantity_non_negative"),
        Invariant(id="inv-price",
                  description="Price cannot change without authorization.",
                  check="price_stable"),
        Invariant(id="inv-refund",
                  description="Refund cannot exceed payment.",
                  check="refund_lte_payment"),
        Invariant(id="inv-token-reuse",
                  description="A single-use token cannot be reused.",
                  check="single_use_token"),
        Invariant(id="inv-revert",
                  description="A completed workflow cannot be reverted "
                              "without authorization.",
                  check="no_revert_completed"),
        Invariant(id="inv-access-deleted",
                  description="A deleted object cannot be accessed.",
                  check="no_access_deleted"),
        Invariant(id="inv-expired-session",
                  description="An expired session cannot perform "
                              "protected actions.",
                  check="no_expired_session"),
        Invariant(id="inv-recharge",
                  description="A refunded transaction cannot be charged "
                              "again.",
                  check="no_recharge_refunded"),
    ]


def evaluate(inv: Invariant, observation: Dict[str, Any]
             ) -> InvariantResult:
    fn = _REGISTRY.get(inv.check)
    if fn is None:
        log.warning("unknown invariant check: %s", inv.check)
        return InvariantResult(inv.id, False,
                               detail=f"unknown check '{inv.check}'")
    ok, reason = _in_scope(inv, observation)
    if not ok:
        return InvariantResult(inv.id, False, detail=reason)
    try:
        violated, detail = fn(observation, inv.params)
    except Exception as e:
        return InvariantResult(inv.id, False, detail=f"check error: {e}")
    return InvariantResult(inv.id, bool(violated), detail=detail or "")


def evaluate_all(invariants: List[Invariant],
                 observation: Dict[str, Any]) -> List[InvariantResult]:
    return [evaluate(inv, observation) for inv in invariants]
