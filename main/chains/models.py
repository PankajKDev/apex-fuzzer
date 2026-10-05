"""Attack-chain data model: finding → capability → impact.

Chains are deterministic hypotheses over recorded findings — zero
network, always ``hypothesized``, never confirmed. A chain links
the findings that enable each step, names the impact, and lists the
missing links an operator must verify by hand. Chains never become
findings and never alter finding counts.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List


HYPOTHESIZED = "hypothesized"
POSSIBLE = "possible"
PROBABLE = "probable"


@dataclass
class ChainStep:
    # finding | capability | impact | missing
    kind: str
    text: str
    finding_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind, "text": self.text,
                "finding_id": self.finding_id}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ChainStep":
        d = d or {}
        return cls(kind=str(d.get("kind", "")),
                   text=str(d.get("text", "")),
                   finding_id=str(d.get("finding_id", "")))


@dataclass
class AttackChain:
    id: str
    rule: str
    name: str
    impact: str = "account-takeover"
    confidence: str = POSSIBLE
    status: str = HYPOTHESIZED
    host: str = ""
    finding_ids: List[str] = field(default_factory=list)
    steps: List[ChainStep] = field(default_factory=list)
    missing_links: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "rule": self.rule, "name": self.name,
                "impact": self.impact, "confidence": self.confidence,
                "status": self.status, "host": self.host,
                "finding_ids": list(self.finding_ids),
                "steps": [s.to_dict() for s in self.steps],
                "missing_links": list(self.missing_links)}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AttackChain":
        d = d or {}
        return cls(
            id=str(d.get("id", "")),
            rule=str(d.get("rule", "")),
            name=str(d.get("name", "")),
            impact=str(d.get("impact", "account-takeover")),
            confidence=str(d.get("confidence", POSSIBLE)),
            status=str(d.get("status", HYPOTHESIZED)),
            host=str(d.get("host", "")),
            finding_ids=[str(i) for i in
                         d.get("finding_ids", []) or []],
            steps=[ChainStep.from_dict(s) for s in
                   d.get("steps", []) or []],
            missing_links=[str(m) for m in
                           d.get("missing_links", []) or []])
