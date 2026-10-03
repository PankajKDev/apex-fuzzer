"""Action coverage per endpoint (agent Phase 7).

Which HTTP methods were actually tested where, with what outcome —
and which configured methods never got a probe (undocumented-action
surface for follow-up). Built from extended cells, not new requests.
"""
from typing import Any, Dict


def action_coverage(cells, endpoints=None,
                    configured_methods=None) -> Dict[str, Any]:
    """{endpoint: {methods: {METHOD: status}, untested_methods: [...]}}."""
    by_ep: Dict[str, Dict[str, str]] = {}
    for c in cells:
        ep = getattr(c, "endpoint", "")
        if not ep:
            continue
        method = (getattr(c, "method", "GET") or "GET").upper()
        # best (most severe) status wins per method
        order = ["not_tested", "untestable", "tested_negative",
                 "inconclusive", "blocked", "candidate", "confirmed"]
        cur = by_ep.setdefault(ep, {}).get(method, "not_tested")
        status = getattr(c, "status", "not_tested")
        try:
            if order.index(status) > order.index(cur):
                by_ep[ep][method] = status
        except ValueError:
            pass
    configured = [m.upper() for m in (configured_methods or [])]
    out: Dict[str, Any] = {}
    eps = list({getattr(e, "normalized_url", "") for e in
                (endpoints or []) if getattr(e, "normalized_url", "")})
    for ep in sorted(set(list(by_ep) + eps)):
        methods = dict(by_ep.get(ep, {}))
        out[ep] = {"methods": methods,
                   "untested_methods": [m for m in configured
                                        if m not in methods]}
    return out
