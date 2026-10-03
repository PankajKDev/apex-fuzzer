"""Ownership comparison + generic-response guard (Terra M2.5).

A shape/hash match alone is a medium-confidence signal: two different
objects behind the same template collide silently. This module raises
the bar before a BOLA verdict:

1. Generic responses (`{"ok": true}`, empty arrays, pagination-only
   shells, error wrappers) can never be evidence — for either side.
2. When the owner's response carried stable identifiers, the tester's
   response must carry the SAME values. Same shape + different owner
   markers = different object = no finding.
3. With no markers on either side, the shape match stands alone and
   the finding says so explicitly (medium confidence).
"""
import json
from typing import Any, Dict, List, Tuple
from ..logging_setup import get_logger

log = get_logger("authz-compare")

DEFAULT_OWNERSHIP_FIELDS = [
    "owner_id", "user_id", "account_id", "tenant_id", "created_by",
    "owner", "email",
]

_GENERIC_TOP_KEYS = {"ok", "success", "status", "message", "code",
                     "error", "errors"}
_PAGINATION_KEYS = {"page", "per_page", "total", "pages", "limit",
                    "offset", "count"}


def is_generic_response(body_text: str) -> Tuple[bool, str]:
    """True when a body is too content-free to identify an object."""
    try:
        data = json.loads(body_text or "")
    except (ValueError, TypeError):
        return False, ""
    if data is None or data is False:
        return True, "empty/null body"
    if isinstance(data, list):
        if not data:
            return True, "empty array"
        return False, ""
    if not isinstance(data, dict):
        return False, ""
    if not data:
        return True, "empty object"
    keys = {str(k).lower() for k in data.keys()}
    if keys and keys <= _GENERIC_TOP_KEYS:
        return True, f"generic status shell (keys: {sorted(keys)})"
    if keys and keys <= (_GENERIC_TOP_KEYS | _PAGINATION_KEYS |
                         {"data", "items", "results"}):
        payload = {k: v for k, v in data.items()
                   if str(k).lower() not in _PAGINATION_KEYS
                   and str(k).lower() not in _GENERIC_TOP_KEYS}
        if not payload:
            return True, "pagination shell with no payload"
        for v in payload.values():
            if v not in ([], {}, "", None, 0):
                return False, ""
        return True, "pagination shell with empty payload"
    return False, ""


def _tester_identifiers(body_text: str) -> Dict[str, str]:
    """Flat identifier map from a tester response (best effort)."""
    from ..authorization.harvest import extract_ids_from_body
    try:
        return dict(extract_ids_from_body(body_text or ""))
    except Exception:
        return {}


def _extract_named_fields(body_text: str,
                          names: List[str]) -> Dict[str, str]:
    """Pull explicitly configured field names straight from raw JSON.

    The generic extractor only knows identifier-like keys; a user who
    declares `ownership_fields: [department]` means that exact key,
    so it is scanned directly (string or numeric scalar values).
    """
    import re
    out: Dict[str, str] = {}
    text = body_text or ""
    for name in names or []:
        if not name:
            continue
        m = re.search(r'"' + re.escape(name) +
                      r'"\s*:\s*"([^"]{1,200}"?)', text)
        if m:
            out[name] = m.group(1).rstrip('"')
            continue
        m = re.search(r'"' + re.escape(name) +
                      r'"\s*:\s*(-?\d+(?:\.\d+)?)', text)
        if m:
            out[name] = m.group(1)
    return out


def compare_access(owner_markers: Dict[str, str], tester_body: str,
                   ownership_fields: List[str] | None = None,
                   exclude: str = "") -> Dict[str, Any]:
    """Decide how much a shape match is worth.

    `exclude` is the swapped parameter itself: its equality in both
    responses is tautological (the tester supplied it) and proves
    nothing, while disagreement on any OTHER shared key proves a
    different object behind the same template.

    Returns {"level": "high"|"medium"|"none", "matched": [...],
    "detail": str}. `high` needs an ownership-field value present in
    BOTH responses and equal; `medium` means consistent-but-provable
    only by shape; `none` means generic content or contradictory
    markers.
    """
    fields = [f.lower() for f in
              (ownership_fields if ownership_fields is not None
               else DEFAULT_OWNERSHIP_FIELDS)]
    generic, why = is_generic_response(tester_body)
    if generic:
        return {"level": "none", "matched": [],
                "detail": f"tester response is generic ({why}) — "
                          "not evidence of access"}
    owner_markers = dict(owner_markers or {})
    if not owner_markers:
        return {"level": "medium", "matched": [],
                "detail": "no ownership markers in baseline — "
                          "shape match stands alone"}
    tester_ids = _tester_identifiers(tester_body)
    tester_ids.update(_extract_named_fields(tester_body, fields))
    if not tester_ids:
        return {"level": "none", "matched": [],
                "detail": "tester response carries no identifiers — "
                          "cannot confirm same object"}
    excl = (exclude or "").lower()

    def _owned(key: str) -> bool:
        return key.lower() in fields

    agreed = sorted(
        k for k, v in owner_markers.items()
        if k.lower() != excl and _owned(k)
        and tester_ids.get(k) == v)
    if agreed:
        return {"level": "high", "matched": agreed,
                "detail": f"ownership markers agree: "
                          f"{', '.join(agreed)}"}
    # Contradiction on anything but the swapped parameter voids the
    # match — even when other identifiers agree.
    contradicted = sorted(
        k for k, v in owner_markers.items()
        if k.lower() != excl and k in tester_ids
        and tester_ids[k] != v)
    if contradicted:
        return {"level": "none", "matched": [],
                "detail": "identifier values differ between owner and "
                          f"tester responses ({', '.join(contradicted)}) "
                          "— different object, same template"}
    # Equal identifiers elsewhere are consistent with access but may
    # be request reflection — medium, and the finding must say so.
    equal = sorted(
        k for k, v in owner_markers.items()
        if k.lower() != excl and k in tester_ids
        and tester_ids[k] == v)
    if equal:
        return {"level": "medium", "matched": equal,
                "detail": f"resource identifiers agree "
                          f"({', '.join(equal)}); reflection not ruled "
                          f"out — shape match stands with caveat"}
    return {"level": "medium", "matched": [],
            "detail": "no comparable ownership fields — shape match "
                      "stands alone"}
