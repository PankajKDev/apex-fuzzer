"""Extended authorization matrix (agent Phase 7).

The engine-level AuthorizationMatrix records raw observations
(identity × endpoint × method). This view adds the dimensions the
spec requires — role, tenant, resource — with one explicit status
per cell, using the coverage vocabulary throughout (candidate,
confirmed, tested_negative, inconclusive, blocked, not_tested,
untestable) so no second status language exists. Display helpers
render the Phase 7 names (negative/tested).
"""
from typing import Any, Dict, List, Optional
from ..logging_setup import get_logger

log = get_logger("authz-matrix")

DISPLAY = {"tested_negative": "negative", "not_tested": "not_tested",
           "candidate": "candidate", "confirmed": "confirmed",
           "inconclusive": "inconclusive", "blocked": "blocked",
           "untestable": "untestable"}


def display_status(status: str) -> str:
    return DISPLAY.get(status, status)


class AuthzCell:
    def __init__(self, identity: str, role: str = "", tenant: str = "",
                 resource: str = "", endpoint: str = "",
                 method: str = "GET", status: str = "not_tested",
                 detail: str = ""):
        self.identity = identity
        self.role = role
        self.tenant = tenant
        self.resource = resource
        self.endpoint = endpoint
        self.method = method
        self.status = status
        self.detail = detail

    def key(self) -> tuple:
        return (self.identity, self.role, self.tenant, self.resource,
                self.endpoint, self.method)

    def to_dict(self) -> Dict[str, Any]:
        return {"identity": self.identity, "role": self.role,
                "tenant": self.tenant, "resource": self.resource,
                "endpoint": self.endpoint, "method": self.method,
                "status": self.status,
                "display": display_status(self.status),
                "detail": self.detail}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AuthzCell":
        return cls(
            identity=d.get("identity", ""), role=d.get("role", ""),
            tenant=d.get("tenant", ""), resource=d.get("resource", ""),
            endpoint=d.get("endpoint", ""), method=d.get("method", "GET"),
            status=d.get("status", "not_tested"),
            detail=d.get("detail", ""))


class ExtendedMatrix:
    """Full identity × role × tenant × resource × endpoint × method."""

    def __init__(self):
        self.cells: Dict[tuple, AuthzCell] = {}

    def set(self, cell: AuthzCell) -> AuthzCell:
        key = cell.key()
        cur = self.cells.get(key)
        if cur is None:
            self.cells[key] = cell
            return cell
        # merge by precedence: worse (more severe) status wins
        order = ["not_tested", "untestable", "tested_negative",
                 "inconclusive", "blocked", "candidate", "confirmed"]
        try:
            if order.index(cell.status) > order.index(cur.status):
                self.cells[key] = cell
                return cell
        except ValueError:
            pass
        return cur

    def get(self, **kw) -> Optional[AuthzCell]:
        for cell in self.cells.values():
            if all(getattr(cell, k, None) == v
                   for k, v in kw.items()):
                return cell
        return None

    def query(self, **kw) -> List[AuthzCell]:
        return [c for c in self.cells.values()
                if all(getattr(c, k, None) == v for k, v in kw.items())]

    def status_counts(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for cell in self.cells.values():
            out[cell.status] = out.get(cell.status, 0) + 1
        return out

    def to_dict(self) -> Dict[str, Any]:
        return {"cells": [c.to_dict() for c in self.cells.values()]}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ExtendedMatrix":
        m = cls()
        for entry in d.get("cells") or []:
            try:
                cell = AuthzCell.from_dict(entry)
                m.cells[cell.key()] = cell
            except Exception:
                continue
        return m


def build_extended(observations, swap_results=None,
                   default_status: str = "not_tested") -> ExtendedMatrix:
    """Fold engine observations + swap verdicts into explicit cells.

    - swap strong_candidate → candidate cell (resource set)
    - swap completed denial/difference → tested_negative cell
    - sweep observation 200 → candidate only when a verdict says so;
      here recorded as tested_negative unless denied patterns show
      enforcement gaps (conservative: presence of a 200 is NOT a
      finding — verdicts live in evaluate_cell, Phase 7 only maps
      completed probes to explicit statuses)
    """
    matrix = ExtendedMatrix()
    for o in observations or []:
        ident = getattr(o, "identity", "")
        if not ident:
            continue
        status = default_status
        detail = ""
        code = int(getattr(o, "status", 0) or 0)
        if code == 200:
            status, detail = "tested_negative", \
                "probed, no gap established by verdict pass"
        elif code in (401, 403, 404):
            status, detail = "tested_negative", \
                f"denied ({code}) — enforced for this cell"
        elif code == 0:
            status, detail = "inconclusive", "request never completed"
        matrix.set(AuthzCell(
            identity=ident, role=getattr(o, "role", "") or "",
            tenant=getattr(o, "tenant", "") or "",
            resource=getattr(o, "resource", "") or "",
            endpoint=getattr(o, "endpoint", ""),
            method=getattr(o, "method", "GET") or "GET",
            status=status, detail=detail))
    for sw in swap_results or []:
        verdict = getattr(sw, "verdict", "")
        status = "candidate" if verdict == "strong_candidate" else \
            ("tested_negative"
             if getattr(sw, "status", 0) in (200, 401, 403, 404)
             else "inconclusive")
        matrix.set(AuthzCell(
            identity=getattr(sw, "tester", ""),
            tenant=getattr(sw, "tester_tenant", "") or "",
            resource=str(getattr(sw, "victim_value", "")),
            endpoint=getattr(sw, "endpoint_url", ""),
            method="GET", status=status,
            detail=getattr(sw, "notes", "")))
    return matrix
