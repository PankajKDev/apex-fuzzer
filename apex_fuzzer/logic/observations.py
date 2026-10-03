"""Invariant observation producers — the missing link (§16).

The invariant registry has been dormant because nothing fed it
observations. These builders translate engine outputs (swap results,
business-logic mutations, race outcomes) into the normalized
observation dicts the checks consume. Authz-matrix swap matches also
get their invariant evaluation attached as finding provenance
(corroboration, never duplicate findings).
"""
from typing import Any, Dict, List, Tuple
from .invariants import (Invariant, InvariantResult, evaluate,
                         default_invariants)
from ..logging_setup import get_logger

log = get_logger("observations")

_DEFAULTS = None


def _defaults() -> List[Invariant]:
    global _DEFAULTS
    if _DEFAULTS is None:
        _DEFAULTS = default_invariants()
    return _DEFAULTS


def evaluate_observation(obs: Dict[str, Any],
                         invariants: List[Invariant] | None = None
                         ) -> List[InvariantResult]:
    from .invariants import evaluate_all
    return evaluate_all(invariants or _defaults(), obs)


def violated(results: List[InvariantResult]) -> List[InvariantResult]:
    return [r for r in results if r.violated]


def observation_from_swap(sw, action: str = "read") -> Dict[str, Any]:
    """A confirmed cross-user read, in invariant terms."""
    return {"actor": getattr(sw, "tester", ""),
            "actor_tenant": getattr(sw, "tester_tenant", "") or None,
            "action": action,
            "resource": f"{getattr(sw, 'param', '')}="
                        f"{getattr(sw, 'victim_value', '')}",
            "resource_owner": getattr(sw, "owner", ""),
            "resource_tenant": getattr(sw, "owner_tenant", "") or None,
            "actor_is_admin": False}


def observation_from_business(endpoint_url: str, identity: str,
                              param: str, mutated: Any,
                              echoed: bool, status: int,
                              identity_tenant: str = "",
                              extra: Dict[str, Any] | None = None
                              ) -> Dict[str, Any]:
    """A business-logic mutation outcome, in invariant terms."""
    obs: Dict[str, Any] = {"actor": identity,
                           "actor_tenant": identity_tenant or None,
                           "action": "write",
                           "resource": f"{endpoint_url}::{param}",
                           "authorized": True}
    name = param.lower()
    if isinstance(mutated, int) and echoed and \
            any(k in name for k in ("qty", "quantity", "count", "number",
                                    "limit", "stock", "balance")):
        obs["quantity_after"] = mutated
    if isinstance(mutated, (int, float)) and echoed and \
            any(k in name for k in ("price", "amount", "total", "cost",
                                    "fee", "payment", "refund")):
        if "refund" in name:
            obs["refund"] = mutated
        else:
            obs["price_changed"] = True
    if extra:
        obs.update(extra)
    return obs


def observation_from_race(endpoint_url: str, token_single_use: bool,
                          token_reused: bool) -> Dict[str, Any]:
    return {"actor": "race-engine",
            "action": "replay",
            "resource": endpoint_url,
            "token_single_use": token_single_use,
            "token_reused": token_reused}
