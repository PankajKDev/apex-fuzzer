"""Tenant-centric authorization views (agent Phase 7).

Answers: which resources belong to which tenant, and which of them
were accessed from outside. Ownership comes from harvest records
(owner's own session); access comes from swap verdicts. Cells alone
cannot answer this — swap observations are recorded under the
*tester* identity — so both inputs are required.
"""
from typing import Any, Dict, List


def tenant_view(harvested, swaps=None) -> Dict[str, Any]:
    """{tenants, owned_resources, accessed_by_outsiders,
    cross_tenant_access}."""
    owned: Dict[str, List[str]] = {}
    for h in harvested or []:
        tenant = getattr(h, "owner_tenant", "") or ""
        value = str(getattr(h, "value", ""))
        if tenant and value and value not in owned.setdefault(
                tenant, []):
            owned[tenant].append(value)
    accessed: Dict[str, List[Dict[str, Any]]] = {}
    cross: List[Dict[str, Any]] = []
    for sw in swaps or []:
        ot, tt = getattr(sw, "owner_tenant", "") or "", getattr(
            sw, "tester_tenant", "") or ""
        if ot and tt and ot != tt and \
                getattr(sw, "verdict", "") == "strong_candidate":
            entry = {"resource": str(getattr(sw, "victim_value", "")),
                     "owner": getattr(sw, "owner", ""),
                     "owner_tenant": ot,
                     "tester": getattr(sw, "tester", ""),
                     "tester_tenant": tt,
                     "endpoint": getattr(sw, "endpoint_url", "")}
            cross.append(entry)
            accessed.setdefault(ot, []).append(
                {"resource": entry["resource"], "by": entry["tester"]})
    tenants = sorted(set(owned) | set(accessed))
    return {"tenants": tenants,
            "owned_resources": {t: sorted(owned.get(t, []))
                                for t in tenants},
            "accessed_by_outsiders": accessed,
            "cross_tenant_access": cross}
