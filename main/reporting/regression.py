"""Baseline regression: new/gone/changed findings vs a prior run.

Compares current findings.jsonl records against a baseline directory
(same per-host layout) by stable finding ID. Severity changes on a
surviving ID count as changed; anything else identical is silent.
Exit policy lives with the caller; this module only classifies.
"""
from pathlib import Path
from typing import Dict, List

_PRIVILEGED_TYPES = ("admin", "api", "authentication")

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3,
                  "critical": 4}


def _read_findings(path: Path) -> Dict[str, dict]:
    try:
        lines = Path(path).read_text(errors="ignore").splitlines()
    except OSError:
        return {}
    out = {}
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            import json as _json
            row = _json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict) and row.get("id"):
            out[str(row["id"])] = row
    return out


def baseline_path(baseline: Path, host: str) -> Path:
    """Baseline findings file: per-host layout first, flat fallback."""
    nested = Path(baseline) / host / "findings.jsonl"
    if nested.exists():
        return nested
    return Path(baseline) / "findings.jsonl"


def compare_regressions(baseline: Dict[str, dict],
                        current: Dict[str, dict]
                        ) -> Dict[str, List[dict]]:
    """Split current-vs-baseline into new/gone/changed records."""
    new = [current[i] for i in current if i not in baseline]
    gone = [baseline[i] for i in baseline if i not in current]
    changed = []
    for fid in current:
        if fid not in baseline:
            continue
        old, new_row = baseline[fid], current[fid]
        if str(old.get("severity", "")) != \
                str(new_row.get("severity", "")) or \
                str(old.get("validation_status", "")) != \
                str(new_row.get("validation_status", "")):
            changed.append({"id": fid,
                            "was": {"severity": old.get("severity"),
                                    "validation_status": old.get(
                                        "validation_status")},
                            "now": {"severity": new_row.get("severity"),
                                    "validation_status": new_row.get(
                                        "validation_status")}})
    return {"new": new, "gone": gone, "changed": changed}


def meets_threshold(finding: dict, threshold: str) -> bool:
    """True when a finding meets the severity gate (fail-on family)."""
    rank = _SEVERITY_RANK.get(str(finding.get("severity", "")).lower(),
                              -1)
    floor = _SEVERITY_RANK.get(str(threshold or "").lower(), 4)
    return rank >= floor


def regression_exit(new: List[dict], threshold: str) -> int:
    """Exit 1 when any NEW finding meets the threshold, else 0."""
    return 1 if any(meets_threshold(f, threshold) for f in new) else 0


def _endpoint_rows(graph: dict, ids: List[str]) -> List[dict]:
    """Endpoint node details for added/removed id lists."""
    nodes = {}
    for node in graph.get("nodes", []) or []:
        if isinstance(node, dict) and node.get("id"):
            nodes[str(node["id"])] = node
    rows = []
    for nid in ids:
        if not nid.startswith("endpoint::"):
            continue
        node = nodes.get(nid, {})
        attrs = node.get("attrs", {}) if isinstance(node, dict) else {}
        etype = str(attrs.get("endpoint_type", "unknown"))
        rows.append({"url": str(attrs.get("url", "") or nid[10:]),
                     "method": str(attrs.get("method", "GET")),
                     "endpoint_type": etype,
                     "privileged": etype in _PRIVILEGED_TYPES})
    return rows


def compare_graphs(baseline_graph: dict,
                   current_graph: dict) -> Dict[str, list]:
    """Endpoint inventory delta between two application graphs.

    Added/removed endpoint nodes with privilege flags; non-endpoint
    churn (techs, params) is summarized by count only. Graph deltas
    are inventory, never verdicts — they do not affect exit codes.
    """
    from ..state.diff import diff_graphs
    diff = diff_graphs(baseline_graph or {}, current_graph or {})
    return {"added_endpoints": _endpoint_rows(
                current_graph or {}, diff.get("added_nodes", [])),
            "removed_endpoints": _endpoint_rows(
                baseline_graph or {}, diff.get("removed_nodes", [])),
            "other_changes": len(diff.get("added_edges", [])) + len(
                diff.get("removed_edges", []))}


def run_regression_gate(baseline_dir: str, output_base: str,
                        targets: List[str], threshold: str) -> int:
    """Compare each target against its baseline; write artifacts.

    Returns a process exit code (0 clean, 1 new findings at
    threshold, 2 when the baseline is unreadable). Never raises.
    """
    import json as _json
    from ..logging_setup import get_logger
    log = get_logger("regression")
    worst = 0
    for target in targets or []:
        host = (str(target or "").replace("http://", "")
                .replace("https://", "").split("/")[0])
        base_file = baseline_path(Path(baseline_dir), host)
        if not base_file.exists():
            log.error("--regression: no baseline for %s at %s",
                      target, base_file)
            worst = max(worst, 2)
            continue
        current = _read_findings(
            Path(output_base or "output") / host / "findings.jsonl")
        result = compare_regressions(_read_findings(base_file), current)
        result["graph"] = compare_graphs(
            _read_graph(base_file.parent), _read_graph(
                Path(output_base or "output") / host))
        out_path = Path(output_base or "output") / host / \
            "regression.json"
        try:
            out_path.write_text(_json.dumps(
                {key: value for key, value in result.items()}, indent=2))
        except OSError as exc:
            log.error("--regression: cannot write %s: %s", out_path,
                      exc)
            worst = max(worst, 2)
            continue
        log.info("--regression %s: %d new, %d gone, %d changed, "
                 "%d+%d endpoints",
                 target, len(result["new"]), len(result["gone"]),
                 len(result["changed"]),
                 len(result["graph"]["added_endpoints"]),
                 len(result["graph"]["removed_endpoints"]))
        worst = max(worst, regression_exit(result["new"], threshold))
    return worst


def _read_graph(out_dir: Path) -> dict:
    """Load an application graph artifact; empty dict when absent."""
    import json as _json
    try:
        data = _json.loads((Path(out_dir) / "application_graph.json"
                            ).read_text(errors="ignore") or "{}")
    except (ValueError, OSError):
        return {}
    return data if isinstance(data, dict) else {}
