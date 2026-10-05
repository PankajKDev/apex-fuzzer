"""Behavioral graph builders on top of ApplicationGraph (agent P3).

No parallel graph implementation (Rule 2): every helper below mutates
a shared ApplicationGraph using the extended Phase 3 vocabulary.
Static structure comes from build_from_application; these functions
add what only testing can observe — who accessed what, how, and what
changed as a result.
"""
from typing import List, Optional
from ..graph.application_graph import ApplicationGraph, nid
from ..logging_setup import get_logger

log = get_logger("state-graph")


def ensure_identity(graph: ApplicationGraph, name: str,
                    tenant: str = "", role: str = "") -> str:
    iid = nid("identity", name)
    if iid not in graph.nodes:
        graph.add_node(iid, "identity", name,
                       {"tenant": tenant or None})
    if role:
        rid = nid("role", role)
        if rid not in graph.nodes:
            graph.add_node(rid, "role", role)
        graph.add_edge(iid, rid, "BELONGS_TO")
    if tenant:
        tid = nid("tenant", tenant)
        if tid not in graph.nodes:
            graph.add_node(tid, "tenant", tenant)
        graph.add_edge(iid, tid, "BELONGS_TO")
    return iid


def ensure_endpoint(graph: ApplicationGraph, normalized_url: str,
                    url: str = "", method: str = "GET",
                    endpoint_type: str = "unknown") -> str:
    eid = nid("endpoint", normalized_url)
    if eid not in graph.nodes:
        graph.add_node(eid, "endpoint", url or normalized_url,
                       {"method": method, "endpoint_type": endpoint_type,
                        "url": url})
    return eid


def ensure_session(graph: ApplicationGraph, identity_id: str,
                   session_id: str) -> str:
    sid = nid("session", session_id)
    if sid not in graph.nodes:
        graph.add_node(sid, "session", session_id)
        graph.add_edge(identity_id, sid, "AUTHENTICATED_AS")
    return sid


def record_observation(graph: ApplicationGraph, identity: str,
                       endpoint_norm: str, method: str, status: int,
                       shape: str = "", tenant: str = "",
                       role: str = "", resource: str = "",
                       endpoint_url: str = "") -> str:
    """One tested (identity × endpoint × method) cell → graph edges.

    Returns the observation node id. 200s produce CAN_ACCESS plus
    READS (safe methods) or WRITES; denials produce no access edge —
    absence of evidence is not evidence of a wall, it is just
    unobserved access.
    """
    iid = ensure_identity(graph, identity, tenant, role)
    eid = ensure_endpoint(graph, endpoint_norm, endpoint_url, method)
    oid = nid("observation", identity, method, endpoint_norm,
              resource or "-")
    if oid not in graph.nodes:
        graph.add_node(oid, "observation",
                       f"{identity} {method} {endpoint_norm}",
                       {"status": status, "shape": (shape or "")[:120],
                        "method": method,
                        "resource": resource or None})
        graph.add_edge(iid, oid, "PRODUCES")
        graph.add_edge(oid, eid, "READS" if method in
                       ("GET", "HEAD", "OPTIONS") else "WRITES")
    if status == 200:
        graph.add_edge(iid, eid, "CAN_ACCESS",
                       {"method": method,
                        "resource": resource or None})
    return oid


def record_transition(graph: ApplicationGraph, from_state_id: str,
                      to_state_id: str, via_observation_id: str,
                      actor: str = "") -> str:
    tid = nid("transition", from_state_id, to_state_id,
              via_observation_id)
    for sid in (from_state_id, to_state_id):
        if sid not in graph.nodes:
            graph.add_node(sid, "state", sid)
    if tid not in graph.nodes:
        graph.add_node(tid, "transition",
                       f"{from_state_id} → {to_state_id}",
                       {"actor": actor})
        graph.add_edge(from_state_id, tid, "TRANSITIONS")
        graph.add_edge(tid, to_state_id, "TRANSITIONS")
        if via_observation_id in graph.nodes:
            graph.add_edge(via_observation_id, tid, "TRIGGERS")
    return tid


def sync_matrix_observations(graph: ApplicationGraph,
                             observations) -> int:
    """AuthorizationMatrix observations → behavioral edges. Returns the
    number of observation nodes created."""
    made = 0
    for o in observations or []:
        ident = getattr(o, "identity", "")
        ep = getattr(o, "endpoint", "")
        if not ident or not ep:
            continue
        record_observation(
            graph, ident, ep, getattr(o, "method", "GET") or "GET",
            int(getattr(o, "status", 0) or 0),
            shape=getattr(o, "shape", "") or "",
            tenant=getattr(o, "tenant", "") or "",
            role=getattr(o, "role", "") or "",
            resource=getattr(o, "resource", "") or "")
        made += 1
    log.debug("state-graph: synced %d observations", made)
    return made


def ensure_workflow(graph: ApplicationGraph, name: str,
                    steps: List[str]) -> str:
    """Register an observed step sequence: workflow -PRECEDES-> chain."""
    wid = nid("workflow", name)
    if wid not in graph.nodes:
        graph.add_node(wid, "workflow", name)
    prev: Optional[str] = None
    for step in steps:
        sid = nid("workflow_step", name, step)
        if sid not in graph.nodes:
            graph.add_node(sid, "workflow_step", step,
                           {"workflow": name})
            graph.add_edge(wid, sid, "CONTAINS")
        if prev is not None:
            graph.add_edge(prev, sid, "PRECEDES")
        prev = sid
    return wid
