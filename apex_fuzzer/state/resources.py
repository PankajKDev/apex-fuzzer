"""Resource lifecycle state: what each object is, right now (P3).

Models.Resource describes an object; ResourceState tracks its
*observed* lifecycle — current state plus the history that got it
there, with the CRUD endpoint refs that caused each step. Unknown
states are kept verbatim (never coerced): the lifecycle rules in
lifecycle.py decide what is legal, this module only records.
"""
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from ..logging_setup import get_logger

log = get_logger("state-resources")


class ResourceState:
    def __init__(self, resource_key: str, resource_type: str = "object",
                 state: str = "unknown", owner: str = "",
                 tenant: str = "",
                 history: Optional[List[Dict[str, Any]]] = None,
                 crud: Optional[Dict[str, str]] = None):
        self.resource_key = resource_key
        self.resource_type = resource_type
        self.state = state
        self.owner = owner
        self.tenant = tenant
        self.history = history or []
        self.crud = crud or {}  # create/read/update/delete → endpoint urls

    def observe(self, state: str, via: str = "", ts: float = 0.0):
        if state != self.state:
            self.history.append({"from": self.state, "to": state,
                                 "via": via, "ts": ts or time.time()})
            log.info("resource %s: %s → %s (%s)", self.resource_key,
                     self.state, state, via or "observed")
            self.state = state

    def link_crud(self, action: str, endpoint_url: str):
        if action in ("create", "read", "update", "delete"):
            self.crud[action] = endpoint_url

    def to_dict(self) -> Dict[str, Any]:
        return {"resource_key": self.resource_key,
                "resource_type": self.resource_type, "state": self.state,
                "owner": self.owner, "tenant": self.tenant,
                "history": self.history, "crud": self.crud}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ResourceState":
        return cls(
            resource_key=d.get("resource_key", ""),
            resource_type=d.get("resource_type", "object"),
            state=d.get("state", "unknown"), owner=d.get("owner", ""),
            tenant=d.get("tenant", ""), history=d.get("history") or [],
            crud=d.get("crud") or {})


class ResourceTracker:
    def __init__(self):
        self.resources: Dict[str, ResourceState] = {}

    def track(self, resource_key: str, resource_type: str = "object",
              owner: str = "", tenant: str = "") -> ResourceState:
        cur = self.resources.get(resource_key)
        if cur is None:
            cur = ResourceState(resource_key, resource_type, owner=owner,
                                tenant=tenant)
            self.resources[resource_key] = cur
        return cur

    def observe(self, resource_key: str, state: str, via: str = "",
                **kw) -> ResourceState:
        cur = self.track(resource_key, **kw)
        cur.observe(state, via)
        return cur

    def of_tenant(self, tenant: str) -> List[ResourceState]:
        return [r for r in self.resources.values()
                if r.tenant == tenant]

    def save(self, path: Path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            for r in self.resources.values():
                f.write(json.dumps(r.to_dict()) + "\n")

    @classmethod
    def load(cls, path: Path) -> "ResourceTracker":
        tracker = cls()
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        r = ResourceState.from_dict(json.loads(line))
                        tracker.resources[r.resource_key] = r
                    except Exception:
                        continue
        except FileNotFoundError:
            pass
        return tracker
