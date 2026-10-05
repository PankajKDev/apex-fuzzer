"""Producer/consumer dependency analysis (agent Phase 4).

Finds ordering constraints without traffic timestamps: a value
harvested from endpoint A's response that appears as a parameter of
endpoint B means B plausibly depends on A. Short/generic values
("1", "true", …) are ignored — they collide everywhere and prove
nothing. Each dependency carries the evidence that justifies it.
"""
from typing import Any, Dict, List
from ..logging_setup import get_logger

log = get_logger("workflows-deps")

# values too generic to prove a producer/consumer link
_NOISE_VALUES = {"", "0", "1", "2", "true", "false", "null",
                 "undefined", "none", "nil", "yes", "no", "on", "off"}


def _meaningful(value: str) -> bool:
    v = (value or "").strip()
    if len(v) < 4:
        return False
    return v.lower() not in _NOISE_VALUES


def endpoint_param_values(endpoint) -> Dict[str, str]:
    """All concrete parameter values visible on an endpoint."""
    out: Dict[str, str] = {}
    for p in list(getattr(endpoint, "query_parameters", []) or []) + \
            list(getattr(endpoint, "body_parameters", []) or []):
        sample = (getattr(p, "sample_value", "") or "").strip()
        if sample:
            out.setdefault(getattr(p, "name", ""), sample)
    return out


def find_dependencies(endpoints, harvest_pool) -> List[Dict[str, Any]]:
    """Value-overlap links: harvested value of A == param value of B.

    Returns [{producer, consumer, via_param, value, evidence}].
    Self-links excluded; duplicates collapsed.
    """
    by_value: Dict[str, List] = {}
    for h in harvest_pool or []:
        value = str(getattr(h, "value", ""))
        if not _meaningful(value):
            continue
        by_value.setdefault(value, []).append(h)
    out: List[Dict[str, Any]] = []
    seen = set()
    for ep in endpoints or []:
        norm = getattr(ep, "normalized_url", "")
        for pname, pvalue in endpoint_param_values(ep).items():
            if not _meaningful(pvalue):
                continue
            for h in by_value.get(pvalue.strip(), []):
                producer = getattr(h, "normalized_url", "")
                if not producer or producer == norm:
                    continue
                key = (producer, norm, pname)
                if key in seen:
                    continue
                seen.add(key)
                out.append({
                    "producer": producer,
                    "consumer": norm,
                    "via_param": pname,
                    "value": pvalue.strip()[:80],
                    "evidence": f"value '{pvalue.strip()[:40]}' "
                                f"harvested from {producer} appears as "
                                f"parameter '{pname}' on {norm}"})
    log.debug("workflows-deps: %d links", len(out))
    return out


def prerequisite_map(flows) -> Dict[str, List[str]]:
    """step name → names that must precede it, merged across flows."""
    merged: Dict[str, List[str]] = {}
    for flow in flows or []:
        steps = getattr(flow, "steps", []) or []
        for step in steps:
            name = getattr(step, "name", "")
            for req in getattr(step, "requires", []) or []:
                if req not in merged.setdefault(name, []):
                    merged[name].append(req)
    return merged
