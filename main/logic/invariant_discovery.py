"""Invariant discovery: mine holding rules from observed behavior.

Reads matrix observations (and the harvest pool) and proposes scoped
invariants — but ONLY holdings backed by consistent evidence: an
endpoint where cross-identity requests were denied and no two
unrelated identities ever received the same object. Anything less
than that bar emits nothing; discovery hypothesizes nothing.

Each holding carries its evidence (observations examined, denials,
distinct identities) and confidence. Holdings document enforced
behavior for the report and become the regression baseline:
a holding that fires later is either a discovery bug or a real
regression — both worth surfacing.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List
from .invariants import Invariant
from ..logging_setup import get_logger

log = get_logger("invariant-discovery")


def _rule_id(endpoint: str) -> str:
    from ..models import stable_finding_id
    return stable_finding_id("inv-holding", endpoint)


@dataclass
class DiscoveredRule:
    invariant: Invariant
    confidence: str = "medium"  # high | medium
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"invariant": self.invariant.to_dict(),
                "confidence": self.confidence,
                "evidence": self.evidence}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "DiscoveredRule":
        return cls(invariant=Invariant.from_dict(d.get("invariant")
                                                 or {}),
                   confidence=d.get("confidence", "medium"),
                   evidence=d.get("evidence") or {})


def _obs_identities(obs) -> List[str]:
    return sorted({getattr(o, "identity", "") for o in obs or []})


def discover_holdings(observations, harvest_pool=None
                      ) -> List[DiscoveredRule]:
    """Enforced cross-user/tenant read rules, evidenced per endpoint."""
    by_endpoint: Dict[str, list] = {}
    for o in observations or []:
        ep = getattr(o, "endpoint", "")
        if ep:
            by_endpoint.setdefault(ep, []).append(o)
    out: List[DiscoveredRule] = []
    for endpoint, obs in sorted(by_endpoint.items()):
        identities = [o for o in (i for i in
                                  _obs_identities(obs) if i)]
        authed = [i for i in identities if i != "anonymous"]
        if len(authed) < 2:
            continue  # single identity proves nothing about isolation
        denied = [o for o in obs
                  if int(getattr(o, "status", 0) or 0) in
                  (401, 403, 404)
                  and getattr(o, "identity", "") != "anonymous"]
        if not denied:
            continue  # nobody was ever refused — no enforcement shown
        # same object served to two unrelated identities voids holding
        hashes: Dict[str, set] = {}
        for o in obs:
            if int(getattr(o, "status", 0) or 0) != 200:
                continue
            h = getattr(o, "body_hash", "") or ""
            if h:
                hashes.setdefault(h, set()).add(
                    getattr(o, "identity", ""))
        if any(len(names) > 1 for names in hashes.values()):
            continue
        tenants = sorted({getattr(o, "tenant", "") or ""
                          for o in obs} - {""})
        n = len(obs)
        confidence = "high" if n >= 4 and len(denied) >= 2 else "medium"
        scope = {"endpoint": endpoint}
        out.append(DiscoveredRule(
            invariant=Invariant(
                id=_rule_id(endpoint),
                description=f"Cross-user reads enforced on {endpoint}: "
                            f"{len(denied)} denials across "
                            f"{len(authed)} identities, no shared "
                            f"object observed"
                            + (f" (tenants: {', '.join(tenants)})"
                               if tenants else "") + ".",
                check="no_cross_user_read",
                severity="medium", params=scope),
            confidence=confidence,
            evidence={"endpoint": endpoint,
                      "observations_examined": n,
                      "identities": authed,
                      "denials": len(denied),
                      "tenants": tenants}))
    log.info("invariant-discovery: %d holdings from %d endpoints",
             len(out), len(by_endpoint))
    return out


def discover_invariants(observations, harvest_pool=None,
                        resources=None) -> List[DiscoveredRule]:
    """Full discovery pass (v1: holdings only — see module docstring)."""
    return discover_holdings(observations, harvest_pool)
