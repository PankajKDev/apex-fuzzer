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
    added = len(graph.edges) - before
    log.debug("authz-graph: %d edges added", added)
    return added
