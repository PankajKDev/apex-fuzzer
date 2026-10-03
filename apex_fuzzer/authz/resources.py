"""Resource-centric access map (agent Phase 7).

Per resource: who owns it (harvest), who accessed it (swap verdicts
+ matrix observations carrying a resource), and through which
endpoints. This is the object-level view the BOLA verdicts summarize
as findings.

Phase 5 adds `enrich_resource_records`: lifecycle state, field
inventory, permission sets (who successfully read), and GraphQL
typename preference — composed from pieces the sweeps already
produced, no new requests.
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


def enrich_resource_records(pool, observations=None, tracker=None,
                            endpoints=None) -> List[Dict[str, Any]]:
    """Lifecycle-aware records (Phase 5): type (GraphQL typename
    preferred, else name heuristic), identifiers, owner/tenant,
    permissions (identities with a 200 observation on an exposing
    endpoint), field inventory, lifecycle state + history, CRUD links.

    Pure composition over sweep outputs — no requests.
    """
    from ..application.resources import _guess_type
    from urllib.parse import urlsplit

    def _base(url: str) -> str:
        try:
            parts = urlsplit(url or "")
            return parts.netloc.lower() + parts.path.rstrip("/") if \
                parts.netloc else (url or "").split("?", 1)[0]
        except Exception:
            return (url or "").split("?", 1)[0]

    # permissions straight from observations: any identity with a 200
    # on this endpoint's base URL could read here (query strings vary
    # between harvest, swap and sweep records — compare bases, not
    # full normalized URLs)
    permitted_by_base: Dict[str, set] = {}
    for o in observations or []:
        try:
            if int(getattr(o, "status", 0) or 0) != 200:
                continue
        except (TypeError, ValueError):
            continue
        ident = getattr(o, "identity", "")
        if ident:
            permitted_by_base.setdefault(
                _base(getattr(o, "endpoint", "")), set()).add(ident)
    if tracker is not None:
        for h in pool or []:
            norm = getattr(h, "normalized_url", "") or \
                getattr(h, "endpoint_url", "")
            key = f"{norm}::{getattr(h, 'param', '')}"
            hint = (getattr(h, "resource_type_hint", "") or "").strip()
            tracker.track(
                key, hint or _guess_type(getattr(h, "param", ""), ""),
                owner=getattr(h, "owner", ""),
                tenant=getattr(h, "owner_tenant", "") or "")
            # owner baseline was HTTP 200 by construction (harvest only
            # records 200s; traffic/JS/page records are observations of
            # existence) → the object is alive as far as observed
            tracker.observe(key, "active",
                            via=f"observed:{getattr(h, 'source', '')}")
    states: Dict[str, Any] = {}
    if tracker is not None:
        states = getattr(tracker, "resources", {}) or {}
    ep_params: Dict[str, set] = {}
    for ep in endpoints or []:
        norm = getattr(ep, "normalized_url", "")
        names = {p.name for p in
                 list(getattr(ep, "query_parameters", []) or []) +
                 list(getattr(ep, "body_parameters", []) or [])
                 if getattr(p, "name", "")}
        if norm:
            # keyed by base URL: normalized URLs carry query strings
            # that vary per record, fields do not
            ep_params.setdefault(_base(norm), set()).update(names)
    records: List[Dict[str, Any]] = []
    for h in pool or []:
        norm = getattr(h, "normalized_url", "") or \
            getattr(h, "endpoint_url", "")
        key = f"{norm}::{getattr(h, 'param', '')}"
        if any(r["key"] == key for r in records):
            continue
        hint = (getattr(h, "resource_type_hint", "") or "").strip()
        rtype = hint if hint else _guess_type(
            getattr(h, "param", ""), "")
        permitted = sorted(permitted_by_base.get(_base(norm), set()))
        st = states.get(key)
        records.append({
            "key": key,
            "resource_type": rtype,
            "identifiers": {getattr(h, "param", ""):
                            str(getattr(h, "value", ""))},
            "owner": getattr(h, "owner", ""),
            "tenant": getattr(h, "owner_tenant", "") or "",
            "permissions": {"read_by": permitted},
            "fields": sorted(ep_params.get(_base(norm), set())),
            "lifecycle": {
                "state": getattr(st, "state", "active"),
                "history": list(getattr(st, "history", []) or []),
                "crud": dict(getattr(st, "crud", {}) or {}),
            },
            "exposed_by": [norm] if norm else [],
            "source": getattr(h, "source", "response"),
        })
    return records
