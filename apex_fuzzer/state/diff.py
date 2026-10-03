"""Diffing for snapshots and graphs (agent Phase 3).

Pure functions. Snapshot diffs drive transition detection; graph
diffs are the comparison primitive the Phase 22 regression engine
will build on (new/removed endpoints, permission changes).
"""
from typing import Any, Dict


def diff_snapshots(before, after) -> Dict[str, Any]:
    """Field-level diff between two snapshots of the same cell."""
    changes: Dict[str, Any] = {}
    for field in ("status", "shape", "cookies_digest",
                  "storage_digest"):
        old, new = getattr(before, field, None), getattr(after, field,
                                                           None)
        if old != new:
            changes[field] = {"before": old, "after": new}
    return {"cell": after.key() if hasattr(after, "key") else "",
            "changed": bool(changes), "changes": changes}


def diff_graphs(old: Dict[str, Any],
                new: Dict[str, Any]) -> Dict[str, Any]:
    """Added/removed nodes and edges between two graph dicts."""
    old_nodes = {n.get("id") for n in old.get("nodes", [])
                 if isinstance(n, dict)}
    new_nodes = {n.get("id") for n in new.get("nodes", [])
                 if isinstance(n, dict)}

    def _ekey(e: Dict[str, Any]) -> tuple:
        return (e.get("src"), e.get("dst"), e.get("type"))

    old_edges = {_ekey(e) for e in old.get("edges", [])
                 if isinstance(e, dict)}
    new_edges = {_ekey(e) for e in new.get("edges", [])
                 if isinstance(e, dict)}
    added_nodes = sorted(new_nodes - old_nodes)
    removed_nodes = sorted(old_nodes - new_nodes)
    added_edges = sorted(new_edges - old_edges)
    removed_edges = sorted(old_edges - new_edges)
    return {"added_nodes": added_nodes, "removed_nodes": removed_nodes,
            "added_edges": [list(e) for e in added_edges],
            "removed_edges": [list(e) for e in removed_edges],
            "changed": bool(added_nodes or removed_nodes or
                            added_edges or removed_edges)}


def summarize(diff: Dict[str, Any]) -> str:
    parts = []
    for key in ("added_nodes", "removed_nodes", "added_edges",
                "removed_edges"):
        items = diff.get(key) or []
        if items:
            parts.append(f"{key}={len(items)}")
    return ", ".join(parts) or "no changes"
