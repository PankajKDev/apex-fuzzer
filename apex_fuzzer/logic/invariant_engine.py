"""Invariant engine: registry + evaluation log (agent Phase 6).

Centralizes what probes previously did ad hoc: hold a set of
invariants (built-ins, discovered, custom), evaluate observations,
and keep a complete log of every evaluation — violations and holds
alike. Holds are first-class output (enforcement evidence for the
report and the regression baseline), not discarded noise.
"""
import time
from typing import Any, Dict, List, Optional
from .invariants import (Invariant, InvariantResult, evaluate,
                         default_invariants)
from ..logging_setup import get_logger

log = get_logger("invariant-engine")


class EvaluationRecord:
    def __init__(self, invariant_id: str, violated: bool,
                 detail: str = "", observation_ref: str = "",
                 ts: float = 0.0):
        self.invariant_id = invariant_id
        self.violated = violated
        self.detail = detail
        self.observation_ref = observation_ref
        self.ts = ts or time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {"invariant_id": self.invariant_id,
                "violated": self.violated, "detail": self.detail,
                "observation_ref": self.observation_ref, "ts": self.ts}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "EvaluationRecord":
        return cls(invariant_id=d.get("invariant_id", ""),
                   violated=bool(d.get("violated", False)),
                   detail=d.get("detail", ""),
                   observation_ref=d.get("observation_ref", ""),
                   ts=d.get("ts", 0.0))


class InvariantEngine:
    def __init__(self, invariants: Optional[List[Invariant]] = None):
        self.invariants: List[Invariant] = list(
            invariants if invariants is not None
            else default_invariants())
        self.log: List[EvaluationRecord] = []

    def add(self, inv: Invariant):
        if all(i.id != inv.id for i in self.invariants):
            self.invariants.append(inv)

    def evaluate(self, observation: Dict[str, Any],
                 observation_ref: str = "") -> List[InvariantResult]:
        results = []
        for inv in self.invariants:
            res = evaluate(inv, observation)
            results.append(res)
            self.log.append(EvaluationRecord(
                invariant_id=inv.id, violated=res.violated,
                detail=res.detail, observation_ref=observation_ref))
            if res.violated:
                log.info("invariant violated: %s — %s", inv.id,
                         res.detail)
        return results

    def violations(self) -> List[EvaluationRecord]:
        return [r for r in self.log if r.violated]

    def holdings(self) -> List[EvaluationRecord]:
        return [r for r in self.log if not r.violated
                and "out of scope" not in r.detail
                and "unknown check" not in r.detail
                and not r.detail.startswith("check error")]

    def summary(self) -> Dict[str, Any]:
        by_inv: Dict[str, Dict[str, int]] = {}
        for r in self.log:
            entry = by_inv.setdefault(
                r.invariant_id, {"evaluations": 0, "violations": 0})
            entry["evaluations"] += 1
            entry["violations"] += 1 if r.violated else 0
        return {"evaluations": len(self.log),
                "violations": len(self.violations()),
                "by_invariant": by_inv}

    def to_dict(self) -> Dict[str, Any]:
        return {"invariants": [i.to_dict() for i in self.invariants],
                "log": [r.to_dict() for r in self.log]}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "InvariantEngine":
        engine = cls(invariants=[
            Invariant.from_dict(i) for i in (d.get("invariants") or [])])
        for entry in d.get("log") or []:
            try:
                engine.log.append(EvaluationRecord.from_dict(entry))
            except Exception:
                continue
        return engine
