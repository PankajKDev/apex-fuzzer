"""Workflow discovery from observed structure (agent Phase 4).

No traffic timestamps are invented and no flows are hallucinated:
every Flow cites the evidence that justifies its order — REST stem
grouping, timestamp-ordered browser traffic, CRUD linkage, or
harvested value overlap. Confidence is observed only for sequences
that literally happened; everything else is inferred.
"""
import re
from typing import Any, Dict, List
from .model import Flow, FlowStep
from ..logging_setup import get_logger

log = get_logger("workflows-discovery")

_ID_SEG = re.compile(r"^(?:\d+|[0-9a-fA-F-]{8,}|[A-Za-z0-9_\-]{16,})$")
_METHOD_ORDER = ["POST", "GET", "PUT", "PATCH", "DELETE"]


def _stem(path: str) -> str:
    parts = []
    for seg in (path or "/").split("/"):
        if not seg:
            continue
        parts.append("{}" if _ID_SEG.match(seg) else seg.lower())
    return "/" + "/".join(parts)


def _group_key(path: str) -> str:
    """Collection/member folding: a trailing /{} addresses one member
    of the collection, so both group under the collection stem."""
    stem = _stem(path)
    if stem.endswith("/{}"):
        stem = stem[: -len("/{}")]
    return stem or "/"


def discover_rest_flows(endpoints) -> List[Flow]:
    """Group endpoints by ID-normalized stem; stems spanning ≥2 CRUD
    verbs become lifecycle flows in canonical method order."""
    groups: Dict[str, list] = {}
    for ep in endpoints or []:
        path = getattr(ep, "path", "") or "/"
        method = (getattr(ep, "method", "GET") or "GET").upper()
        if method not in _METHOD_ORDER:
            continue
        groups.setdefault(_group_key(path), []).append((method, ep))
    flows: List[Flow] = []
    for stem, members in groups.items():
        verbs = sorted({m for m, _ in members},
                       key=_METHOD_ORDER.index)
        if len(verbs) < 2:
            continue
        steps: List[FlowStep] = []
        prev = ""
        for verb in verbs:
            rep = next(ep for m, ep in members if m == verb)
            name = f"{verb} {stem}"
            params = list(getattr(rep, "query_parameters", []) or []) + \
                list(getattr(rep, "body_parameters", []) or [])
            step = FlowStep(
                name=name, endpoint=getattr(rep, "url", ""),
                normalized_url=getattr(rep, "normalized_url", ""),
                method=verb, parameters=params,
                requires=[prev] if prev else [],
                evidence=f"REST stem grouping: {verb} seen on {stem}")
            steps.append(step)
            prev = name
        flows.append(Flow(
            name=f"{stem} lifecycle", steps=steps, observed=False,
            confidence="inferred",
            evidence=f"{len(verbs)} CRUD verbs on stem {stem}"))
    return flows


def discover_traffic_flows(traffic: Dict[str, Any],
                           gap_seconds: int = 60) -> List[Flow]:
    """Timestamp-ordered browser traffic → observed navigation chains.

    Requests are sorted by capture time and split on idle gaps; each
    chain of ≥2 document/API requests is a flow that literally
    happened, in that order, in one crawl session.
    """
    reqs = sorted((traffic or {}).get("requests", []),
                  key=lambda r: r.get("timestamp", 0))
    chains: List[List[dict]] = []
    current: List[dict] = []
    last_ts = None
    for r in reqs:
        url = r.get("url", "")
        if not url.startswith(("http://", "https://")):
            continue
        ts = r.get("timestamp", 0) or 0
        if current and last_ts is not None and ts - last_ts > gap_seconds:
            chains.append(current)
            current = []
        current.append(r)
        last_ts = ts
    if current:
        chains.append(current)
    flows: List[Flow] = []
    for i, chain in enumerate(chains):
        docs = [r for r in chain
                if (r.get("resource_type") or "") in
                ("document", "xhr", "fetch", "")]
        if len(docs) < 2:
            continue
        steps = []
        for r in docs:
            steps.append(FlowStep(
                name=f"{(r.get('method', 'GET') or 'GET').upper()} "
                     f"{r.get('url', '')[:80]}",
                endpoint=r.get("url", ""),
                normalized_url=r.get("url", "").split("?", 1)[0],
                method=(r.get("method", "GET") or "GET").upper(),
                requires=[steps[-1].name] if steps else [],
                evidence="browser traffic order"))
        flows.append(Flow(
            name=f"crawl chain #{i + 1}", steps=steps, observed=True,
            confidence="observed",
            evidence=f"{len(steps)} requests in capture order"))
    return flows


def discover_crud_flows(resources) -> List[Flow]:
    """Resource CRUD linkage (state/resources.py) → lifecycle flows."""
    order = ["create", "read", "update", "delete"]
    flows: List[Flow] = []
    items = resources.values() if hasattr(resources, "values") else \
        (resources or [])
    if hasattr(items, "values"):
        items = list(items.values())
    for res in items:
        crud = getattr(res, "crud", None) or (res.get("crud") or {})
        present = [a for a in order if crud.get(a)]
        if len(present) < 2:
            continue
        key = getattr(res, "resource_key", "?")
        steps, prev = [], ""
        for action in present:
            name = f"{action} {key}"
            steps.append(FlowStep(
                name=name, endpoint=crud[action],
                normalized_url=crud[action].split("?", 1)[0],
                method={"create": "POST", "read": "GET",
                        "update": "PUT",
                        "delete": "DELETE"}[action],
                requires=[prev] if prev else [],
                evidence=f"CRUD linkage on {key}"))
            prev = name
        flows.append(Flow(
            name=f"{key} lifecycle", steps=steps, observed=False,
            confidence="inferred",
            evidence=f"CRUD actions linked: {', '.join(present)}"))
    return flows


def discover_dependency_flows(endpoints,
                              harvest_pool) -> List[Flow]:
    """Harvested value overlap → 2-step producer→consumer flows."""
    from .dependencies import find_dependencies
    flows: List[Flow] = []
    for link in find_dependencies(endpoints, harvest_pool):
        producer, consumer = link["producer"], link["consumer"]
        flows.append(Flow(
            name=f"{link['via_param']} flow",
            steps=[
                FlowStep(name=f"produce {link['via_param']}",
                         endpoint=producer, normalized_url=producer,
                         method="GET", evidence=link["evidence"]),
                FlowStep(name=f"consume {link['via_param']}",
                         endpoint=consumer, normalized_url=consumer,
                         method="GET",
                         consumes=[link["via_param"]],
                         requires=[f"produce {link['via_param']}"],
                         evidence=link["evidence"])],
            observed=False, confidence="inferred",
            evidence=link["evidence"]))
    return flows


def _signature(flow: Flow) -> tuple:
    return tuple((s.normalized_url, s.method) for s in flow.steps)


def discover_all(endpoints=None, traffic=None, resources=None,
                 harvest_pool=None, max_flows: int = 50) -> List[Flow]:
    """Run every producer; dedupe by step signature (observed wins)."""
    found: List[Flow] = []
    found.extend(discover_rest_flows(endpoints))
    found.extend(discover_traffic_flows(traffic or {}))
    found.extend(discover_crud_flows(resources))
    found.extend(discover_dependency_flows(endpoints, harvest_pool))
    rank = {"observed": 0, "inferred": 1, "hypothesized": 2}
    best: Dict[tuple, Flow] = {}
    for flow in found:
        sig = _signature(flow)
        cur = best.get(sig)
        if cur is None or rank.get(flow.confidence, 2) < rank.get(
                cur.confidence, 2):
            best[sig] = flow
    out = sorted(best.values(),
                 key=lambda f: (rank.get(f.confidence, 2), f.name))
    log.info("workflows: %d flows (%d observed)",
             len(out), sum(1 for f in out if f.observed))
    return out[:max_flows]
