"""Application graph (§5) — persisted as JSON.

Node types: domain host service endpoint parameter technology identity
role tenant resource workflow session secret finding.

Edge types: HOSTS CALLS AUTHENTICATES_TO OWNS BELONGS_TO CAN_ACCESS READS
WRITES CREATES DELETES REDIRECTS_TO FETCHES USES GENERATES DEPENDS_ON
LEADS_TO EXPOSED_BY CONTAINS.

This is the foundation for authorization testing (Phase 3) and attack
chains (Phase 9). Phase 1 builds the structural skeleton from the
application model; later phases add behavioral edges (CAN_ACCESS from
matrix observations, LEADS_TO from chains).
"""
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from ..logging_setup import get_logger

log = get_logger("appgraph")

NODE_TYPES = {"domain", "host", "service", "endpoint", "parameter",
              "technology", "identity", "role", "tenant", "resource",
              "workflow", "session", "secret", "finding",
              # agent Phase 3 (behavioral): additive, old artifacts unaffected
              "state", "transition", "request", "response",
              "observation", "token", "resource_field",
              "workflow_step",
              # Phase 24 (JS intel): client-declared feature flags
              "feature_flag"}

EDGE_TYPES = {"HOSTS", "CALLS", "AUTHENTICATES_TO", "OWNS", "BELONGS_TO",
              "CAN_ACCESS", "READS", "WRITES", "CREATES", "DELETES",
              "REDIRECTS_TO", "FETCHES", "USES", "GENERATES", "DEPENDS_ON",
              "LEADS_TO", "EXPOSED_BY", "CONTAINS",
              # agent Phase 3 (behavioral): additive
              "AUTHENTICATED_AS", "UPDATES", "TRANSITIONS", "PRECEDES",
              "REQUIRES", "PRODUCES", "CONSUMES", "TRIGGERS", "STORES",
              "RENDERS", "INVALIDATES", "REQUIRES_STATE", "CHANGES_STATE"}


def nid(kind: str, *parts: str) -> str:
    return f"{kind}:" + "::".join(str(p) for p in parts)


class ApplicationGraph:
    def __init__(self):
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Dict[str, Any]] = []

    # ── mutation ─────────────────────────────────────────────────────
    def add_node(self, node_id: str, node_type: str, label: str = "",
                 attrs: Optional[Dict[str, Any]] = None) -> str:
        if node_type not in NODE_TYPES:
            raise ValueError(f"unknown node type: {node_type}")
        cur = self.nodes.get(node_id)
        if cur is None:
            self.nodes[node_id] = {"id": node_id, "type": node_type,
                                   "label": label or node_id,
                                   "attrs": attrs or {}}
        else:
            for k, v in (attrs or {}).items():
                cur["attrs"].setdefault(k, v)
        return node_id

    def add_edge(self, src: str, dst: str, edge_type: str,
                 attrs: Optional[Dict[str, Any]] = None):
        if edge_type not in EDGE_TYPES:
            raise ValueError(f"unknown edge type: {edge_type}")
        if src not in self.nodes or dst not in self.nodes:
            raise KeyError(f"edge endpoint missing: {src} -> {dst}")
        for e in self.edges:
            if e["src"] == src and e["dst"] == dst and \
                    e["type"] == edge_type:
                return
        self.edges.append({"src": src, "dst": dst, "type": edge_type,
                           "attrs": attrs or {}})

    # ── queries ──────────────────────────────────────────────────────
    def nodes_of_type(self, node_type: str) -> List[Dict[str, Any]]:
        return [n for n in self.nodes.values() if n["type"] == node_type]

    def neighbors(self, node_id: str, edge_type: Optional[str] = None,
                  direction: str = "out") -> List[Dict[str, Any]]:
        out = []
        for e in self.edges:
            if edge_type and e["type"] != edge_type:
                continue
            other = None
            if direction in ("out", "both") and e["src"] == node_id:
                other = e["dst"]
            elif direction in ("in", "both") and e["dst"] == node_id:
                other = e["src"]
            if other is not None and other in self.nodes:
                out.append(self.nodes[other])
        return out

    def endpoints_exposing_resource(self, resource_id: str
                                    ) -> List[Dict[str, Any]]:
        # edges are stored resource -EXPOSED_BY-> endpoint
        return self.neighbors(resource_id, "EXPOSED_BY", direction="out")

    def resources_of_tenant(self, tenant_id: str) -> List[Dict[str, Any]]:
        return [n for n in self.nodes_of_type("resource")
                if n["attrs"].get("tenant") == tenant_id
                or tenant_id in (n["attrs"].get("tenants") or [])]

    # ── persistence ──────────────────────────────────────────────────
    def to_dict(self) -> Dict[str, Any]:
        return {"nodes": list(self.nodes.values()), "edges": self.edges}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ApplicationGraph":
        g = cls()
        for n in d.get("nodes") or []:
            g.nodes[n["id"]] = {"id": n["id"], "type": n.get("type", ""),
                                "label": n.get("label", n["id"]),
                                "attrs": n.get("attrs") or {}}
        g.edges = list(d.get("edges") or [])
        return g

    def save(self, path: Path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2))

    @classmethod
    def load(cls, path: Path) -> "ApplicationGraph":
        return cls.from_dict(json.loads(Path(path).read_text()))


def build_from_application(app) -> ApplicationGraph:
    """Structural skeleton: domains/hosts/endpoints/params/techs,
    identities→roles→tenants, resources EXPOSED_BY endpoints."""
    g = ApplicationGraph()
    d = app.to_dict() if hasattr(app, "to_dict") else app

    for root in d.get("root_domains") or []:
        g.add_node(nid("domain", root), "domain", root)
    for host in d.get("hosts") or []:
        hid = nid("host", host)
        g.add_node(hid, "host", host)
        for root in d.get("root_domains") or []:
            if host == root or host.endswith("." + root):
                g.add_edge(nid("domain", root), hid, "HOSTS")
    for t in d.get("technologies") or []:
        tid = nid("tech", t.get("name", ""))
        g.add_node(tid, "technology", t.get("name", ""),
                   {"category": t.get("category", "other")})

    for ep in d.get("endpoints") or []:
        norm = ep.get("normalized_url", "")
        eid = nid("endpoint", norm)
        g.add_node(eid, "endpoint", ep.get("path") or norm,
                   {"method": ep.get("method", "GET"),
                    "endpoint_type": ep.get("endpoint_type", "unknown"),
                    "url": ep.get("url", "")})
        host = ep.get("host", "")
        if host and nid("host", host) in g.nodes:
            g.add_edge(nid("host", host), eid, "CALLS")
        for tech_name in ep.get("technology") or []:
            tid = nid("tech", tech_name)
            if tid in g.nodes:
                g.add_edge(eid, tid, "USES")
        for plist in (ep.get("query_parameters") or []) + \
                     (ep.get("body_parameters") or []):
            pid = nid("param", norm, plist.get("location", ""),
                      plist.get("name", ""))
            g.add_node(pid, "parameter", plist.get("name", ""),
                       {"location": plist.get("location", ""),
                        "source": plist.get("source", [])})
            g.add_edge(eid, pid, "USES")

    for ident in d.get("identities") or []:
        iid = nid("identity", ident.get("name", ""))
        g.add_node(iid, "identity", ident.get("name", ""),
                   {"tenant": ident.get("tenant")})
        for r in ident.get("roles") or []:
            rid = nid("role", r)
            if rid not in g.nodes:
                g.add_node(rid, "role", r)
            g.add_edge(iid, rid, "BELONGS_TO")
        tenant = ident.get("tenant")
        if tenant:
            tid = nid("tenant", tenant)
            if tid not in g.nodes:
                g.add_node(tid, "tenant", tenant)
            g.add_edge(iid, tid, "BELONGS_TO")

    for res in d.get("resources") or []:
        rid = nid("resource", res.get("key", ""))
        g.add_node(rid, "resource", res.get("key", ""),
                   {"resource_type": res.get("resource_type", "object"),
                    "tenant": res.get("tenant"),
                    "owner": res.get("owner")})
        for url in res.get("exposed_by") or []:
            eid = nid("endpoint", url)
            if eid in g.nodes:
                g.add_edge(rid, eid, "EXPOSED_BY")
        if res.get("owner"):
            oid = nid("identity", res["owner"])
            if oid in g.nodes:
                g.add_edge(oid, rid, "OWNS")
    log.debug("graph built: %d nodes, %d edges",
              len(g.nodes), len(g.edges))
    return g
