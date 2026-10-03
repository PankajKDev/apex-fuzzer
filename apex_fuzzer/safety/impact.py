"""Target-impact classification (Milestone 1).

Every testing module declares the highest impact level it can reach.
Preflight resolves the enabled set to a maximum level and validates
operator authorization once, before any network activity.
"""
from dataclasses import dataclass
from typing import Dict, List

PASSIVE = "passive"
READ_ONLY = "read-only"
ACTIVE = "active"
STATEFUL = "stateful"
BURST = "burst"
CLAIMING = "claiming"

_LEVEL_RANK = [PASSIVE, READ_ONLY, ACTIVE, STATEFUL, BURST, CLAIMING]

# Modules that only run inside their own stage are still listed so
# dry-run output is complete. Levels describe worst-case behavior:
# - authz-matrix sends state-changing verbs (empty bodies) → stateful
# - differential/OAST/plugins only read or fire-and-observe → active
# - takeover claiming actually creates provider resources → claiming
MODULE_LEVELS: Dict[str, str] = {
    "recon": READ_ONLY,
    "discovery": READ_ONLY,
    "mapping": READ_ONLY,
    "probe": READ_ONLY,
    "browser": READ_ONLY,
    "nuclei": ACTIVE,
    "differential": ACTIVE,
    "oast": ACTIVE,
    "validation": ACTIVE,
    "authz_matrix": STATEFUL,
    "second_order": STATEFUL,
    "business_logic": STATEFUL,
    "login": STATEFUL,
    "race": BURST,
    "takeover_claim": CLAIMING,
    "takeover_fingerprint": READ_ONLY,
    "ai": PASSIVE,
}


@dataclass
class ModuleState:
    name: str
    level: str
    enabled: bool
    reason: str = ""


def max_level(states: List[ModuleState]) -> str:
    """Highest level among ENABLED modules (passive when none run)."""
    rank = 0
    for s in states:
        if s.enabled:
            rank = max(rank, _LEVEL_RANK.index(s.level))
    return _LEVEL_RANK[rank]


def needs_authorization(level: str) -> bool:
    """Levels that fail closed under strict mode without auth metadata."""
    return level in (STATEFUL, BURST, CLAIMING)
