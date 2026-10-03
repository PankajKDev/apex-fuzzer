"""Authz views → graph edges (agent Phase 7).

Ownership and tenancy as first-class edges: harvested owners link
identity -OWNS-> resource and tenant -CONTAINS-> resource; resources
link -EXPOSED_BY-> the endpoints that served them. Consumed by the
Phase 19 chain engine and the AI loop — no new requests, pure
modeling over data the sweeps already produced.
"""
from typing import Any, Dict, List
from ..graph.application_graph import nid
from ..logging_setup import get_logger

log = get_logger("authz-graph")


def sync_extended(graph, harvested, resource_map=None) -> int:
    """Write ownership/tenancy/exposure edges. Returns edges added."""
    before = len(graph.edges)
    for h in harvested or []:
        owner = getattr(h, "owner", "")
        tenant = getattr(h, "owner_tenant", "") or ""
        value = str(getattr(h, "value", ""))
        ep = getattr(h, "normalized_url", "") or \
            getattr(h, "endpoint_url", "")
        if not value or not ep:
            continue
        rid = nid("resource", ep, getattr(h, "param", ""), value)
        if rid not in graph.nodes:
            graph.add_node(rid, "resource", value,
                           {"owner": owner or None,
                            "tenant": tenant or None,
                            "endpoint": ep})
        if owner:
            iid = nid("identity", owner)
            if iid not in graph.nodes:
                graph.add_node(iid, "identity", owner)
            graph.add_edge(iid, rid, "OWNS")
        if tenant:
            tid = nid("tenant", tenant)
            if tid not in graph.nodes:
                graph.add_node(tid, "tenant", tenant)
            graph.add_edge(tid, rid, "CONTAINS")
        eid = nid("endpoint", ep)
        if eid in graph.nodes:
            graph.add_edge(rid, eid, "EXPOSED_BY")
    link_shared_identifiers(graph, harvested or [])
    added = len(graph.edges) - before
    log.debug("authz-graph: %d edges added", added)
    return added


def _meaningful(value: str) -> bool:
    """Twin of the workflows dependency rule: short/generic values
    collide everywhere and prove no relationship."""
    v = (value or "").strip()
    if len(v) < 4:
        return False
    return v.lower() not in {"true", "false", "null", "undefined",
                             "none", "nil", "yes", "no", "on", "off"}


def link_shared_identifiers(graph, harvested) -> int:
    """Link resource nodes sharing an identifier value (e.g. an order
    carrying its owner's user_id): deterministic single edge per pair
    (sorted IDs), annotated with the shared key=value. Direction is
    unknown, so edges point from the lexicographically smaller node
    with a `symmetric: True` attribute — stable across runs."""
    by_value: Dict[str, list] = {}
    for h in harvested or []:
        value = str(getattr(h, "value", ""))
        if not _meaningful(value):
            continue
        ep = getattr(h, "normalized_url", "") or \
            getattr(h, "endpoint_url", "")
        rid = nid("resource", ep, getattr(h, "param", ""), value)
        if rid in graph.nodes:
            by_value.setdefault(value, []).append(rid)
    before = len(graph.edges)
    for value, rids in by_value.items():
        unique = sorted(set(rids))
        if len(unique) < 2:
            continue
        for i in range(len(unique)):
            for j in range(i + 1, len(unique)):
                graph.add_edge(unique[i], unique[j], "DEPENDS_ON",
                               {"via_value": value, "symmetric": True})
    return len(graph.edges) - before
