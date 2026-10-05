"""State transitions: before → after linked by the request (agent P3).

A transition is recorded only when the same (identity, endpoint,
method) cell observably changes between two snapshots — status or
shape moved. Flapping between identical states records nothing.
"""
import json
import time
from pathlib import Path
from typing import Any, Dict, List
from ..logging_setup import get_logger

log = get_logger("state-transitions")


class Transition:
    def __init__(self, from_id: str, to_id: str, via: str = "",
                 actor: str = "", ts: float = 0.0):
        self.from_id = from_id
        self.to_id = to_id
        self.via = via
        self.actor = actor
        self.ts = ts or time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {"from": self.from_id, "to": self.to_id,
                "via": self.via, "actor": self.actor, "ts": self.ts}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Transition":
        return cls(from_id=d.get("from", ""), to_id=d.get("to", ""),
                   via=d.get("via", ""), actor=d.get("actor", ""),
                   ts=d.get("ts", 0.0))


class TransitionLog:
    def __init__(self):
        self.transitions: List[Transition] = []

    def record_if_changed(self, before, after, via: str = "",
                          actor: str = "") -> Transition | None:
        """Compare two snapshots of the same cell; record on change."""
        if before is None or after is None:
            return None
        if before.status == after.status and \
                before.shape == after.shape:
            return None
        t = Transition(from_id=before.snapshot_id, to_id=after.snapshot_id,
                       via=via, actor=actor or after.identity)
        self.transitions.append(t)
        log.info("state: %s %s %s: %s → %s",
                 after.identity, after.method, after.endpoint,
                 before.status, after.status)
        return t

    def successors(self, snapshot_id: str) -> List[Transition]:
        return [t for t in self.transitions if t.from_id == snapshot_id]

    def save(self, path: Path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            for t in self.transitions:
                f.write(json.dumps(t.to_dict()) + "\n")

    @classmethod
    def load(cls, path: Path) -> "TransitionLog":
        blog = cls()
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        blog.transitions.append(
                            Transition.from_dict(json.loads(line)))
                    except Exception:
                        continue
        except FileNotFoundError:
            pass
        return blog
