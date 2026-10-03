"""Point-in-time state snapshots (agent Phase 3).

A snapshot freezes what one identity observed at one endpoint with one
method: status, response shape, cookie jar digest, storage digest.
Snapshots persist to JSONL so resumed scans (and the Phase 22
regression engine) can compare behavior across runs. A snapshot is a
fact, never a verdict.
"""
import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from ..logging_setup import get_logger

log = get_logger("state-snapshots")


def _digest(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", "replace")
                          ).hexdigest()[:16]


class StateSnapshot:
    def __init__(self, snapshot_id: str = "", identity: str = "",
                 endpoint: str = "", method: str = "GET",
                 status: int = 0, shape: str = "",
                 cookies_digest: str = "", storage_digest: str = "",
                 ts: float = 0.0):
        self.snapshot_id = snapshot_id or (
            f"snap-{_digest(f'{identity}|{method}|{endpoint}|{ts or time.time()}')}")
        self.identity = identity
        self.endpoint = endpoint
        self.method = method
        self.status = status
        self.shape = shape
        self.cookies_digest = cookies_digest
        self.storage_digest = storage_digest
        self.ts = ts or time.time()

    @classmethod
    def capture(cls, identity: str, endpoint: str, method: str,
                status: int, shape: str = "",
                cookies: str = "", storage: str = "") -> "StateSnapshot":
        return cls(identity=identity, endpoint=endpoint, method=method,
                   status=status, shape=shape,
                   cookies_digest=_digest(cookies) if cookies else "",
                   storage_digest=_digest(storage) if storage else "")

    def key(self) -> str:
        return f"{self.identity}::{self.method}::{self.endpoint}"

    def to_dict(self) -> Dict[str, Any]:
        return {"snapshot_id": self.snapshot_id,
                "identity": self.identity, "endpoint": self.endpoint,
                "method": self.method, "status": self.status,
                "shape": self.shape,
                "cookies_digest": self.cookies_digest,
                "storage_digest": self.storage_digest, "ts": self.ts}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "StateSnapshot":
        return cls(**{k: d.get(k, "") if k not in
                       ("status", "ts") else d.get(k, 0)
                       for k in ("snapshot_id", "identity", "endpoint",
                                 "method", "status", "shape",
                                 "cookies_digest", "storage_digest",
                                 "ts")})


class SnapshotStore:
    def __init__(self):
        self.snapshots: List[StateSnapshot] = []

    def add(self, snap: StateSnapshot):
        self.snapshots.append(snap)
        return snap

    def latest(self, identity: str, endpoint: str,
               method: str = "") -> Optional[StateSnapshot]:
        cands = [s for s in self.snapshots
                 if s.identity == identity and s.endpoint == endpoint
                 and (not method or s.method == method)]
        return max(cands, key=lambda s: s.ts) if cands else None

    def save(self, path: Path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            for s in self.snapshots:
                f.write(json.dumps(s.to_dict()) + "\n")

    @classmethod
    def load(cls, path: Path) -> "SnapshotStore":
        store = cls()
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        store.snapshots.append(
                            StateSnapshot.from_dict(json.loads(line)))
                    except Exception:
                        continue
        except FileNotFoundError:
            pass
        return store
