"""Role-centric authorization views (agent Phase 7).

Groups tested cells by role to expose vertical escalation: a lower
role receiving the same privileged object as an admin role, through
any method. Uses the same shape-equality semantics as the engine
(same_object) — status codes alone never decide.
"""
from typing import Any, Dict, List
from ..authorization.matrix import same_object, AuthorizationObservation
from ..logging_setup import get_logger

log = get_logger("authz-roles")

PRIVILEGED_ROLE_HINTS = ("admin", "root", "staff", "superuser",
                         "owner")


def _norm_role(role: str) -> str:
    return (role or "").strip().lower() or "(no-role)"


def role_access_map(cells) -> Dict[str, Dict[str, Dict[str, str]]]:
    """{role: {endpoint: {method: status}}} from extended cells."""
    out: Dict[str, Dict[str, Dict[str, str]]] = {}
    for c in cells:
        role = _norm_role(getattr(c, "role", ""))
        ep = getattr(c, "endpoint", "")
        method = getattr(c, "method", "GET") or "GET"
        out.setdefault(role, {}).setdefault(ep, {})[method] = \
            getattr(c, "status", "not_tested")
    return out


def is_privileged_role(role: str) -> bool:
    r = (role or "").lower()
    return any(h in r for h in PRIVILEGED_ROLE_HINTS)


def check_vertical_escalation(
        observations: List[AuthorizationObservation]) -> List[Dict[str, Any]]:
    """Find (endpoint, method) cells where a non-privileged role gets
    the same 200 object as a privileged role. Returns evidence dicts
    (analytic data — finding creation stays with the verdict passes
    to avoid duplicates)."""
    by_cell: Dict[tuple, List[AuthorizationObservation]] = {}
    for o in observations or []:
        if int(getattr(o, "status", 0) or 0) != 200:
            continue
        by_cell.setdefault((getattr(o, "endpoint", ""),
                            getattr(o, "method", "GET")), []).append(o)
    out: List[Dict[str, Any]] = []
    for (endpoint, method), obs in by_cell.items():
        priv = [o for o in obs if is_privileged_role(
            getattr(o, "role", ""))]
        others = [o for o in obs if not is_privileged_role(
            getattr(o, "role", ""))]
        for p in priv:
            for o in others:
                if p.identity != o.identity and same_object(p, o):
                    out.append({
                        "endpoint": endpoint, "method": method,
                        "privileged_identity": p.identity,
                        "privileged_role": getattr(p, "role", ""),
                        "other_identity": o.identity,
                        "other_role": getattr(o, "role", "") or "(no-role)",
                        "kind": "vertical_escalation"})
                    log.info("authz-roles: %s (%s) matches %s (%s) "
                             "on %s %s", o.identity,
                             getattr(o, "role", ""), p.identity,
                             getattr(p, "role", ""), method, endpoint)
    return out
