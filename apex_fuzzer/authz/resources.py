"""Resource-centric access map (agent Phase 7).

Per resource: who owns it (harvest), who accessed it (swap verdicts
+ matrix observations carrying a resource), and through which
endpoints. This is the object-level view the BOLA verdicts summarize
as findings.
"""
from typing import Any, Dict, List


def resource_access_map(harvested, swaps=None,
                        observations=None) -> Dict[str, Any]:
    """{resource_key: {owner, owner_tenant, exposed_by, accessed_by}}.

    resource_key mirrors models.Resource (`<endpoint>::<param>=<value>`
    is too instance-specific for grouping; the map keys on
    `<endpoint>::<param>` and lists observed values separately).
    """
    resources: Dict[str, Dict[str, Any]] = {}

    def _entry(key: str) -> Dict[str, Any]:
        return resources.setdefault(key, {
            "owner": "", "owner_tenant": "", "exposed_by": [],
            "values": [], "accessed_by": []})

    for h in harvested or []:
        ep = getattr(h, "normalized_url", "") or \
            getattr(h, "endpoint_url", "")
        key = f"{ep}::{getattr(h, 'param', '')}"
        e = _entry(key)
        e["owner"] = e["owner"] or getattr(h, "owner", "")
        e["owner_tenant"] = e["owner_tenant"] or getattr(
            h, "owner_tenant", "")
        value = str(getattr(h, "value", ""))
        if value and value not in e["values"]:
            e["values"].append(value)
        url = getattr(h, "endpoint_url", "")
        if url and url not in e["exposed_by"]:
            e["exposed_by"].append(url)
    for sw in swaps or []:
        if getattr(sw, "verdict", "") != "strong_candidate":
            continue
        ep = getattr(sw, "endpoint_url", "")
        base = ep.split("?", 1)[0]
        key = f"{base}::{getattr(sw, 'param', '')}"
        e = _entry(key)
        who = {"identity": getattr(sw, "tester", ""),
               "tenant": getattr(sw, "tester_tenant", "") or ""}
        if who not in e["accessed_by"]:
            e["accessed_by"].append(who)
    for o in observations or []:
        resource = getattr(o, "resource", "") or ""
        if not resource or int(getattr(o, "status", 0) or 0) != 200:
            continue
        ep = getattr(o, "endpoint", "")
        key = f"{ep}::?"
        e = _entry(key)
        who = {"identity": getattr(o, "identity", ""),
               "tenant": getattr(o, "tenant", "") or ""}
        if who not in e["accessed_by"]:
            e["accessed_by"].append(who)
    return resources
