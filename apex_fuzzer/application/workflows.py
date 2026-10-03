"""Stateful workflow schema (§14). Phase 1 defines the schema so scan
artifacts stay forward-compatible; the workflow *engine* (sequence
recording, replay, invariant checks over transitions) arrives in
Phase 5 and consumes these exact shapes.
"""
from dataclasses import asdict
from typing import Any, Dict, List, Optional
from ..models import Parameter


class WorkflowStep:
    def __init__(self, name: str, endpoint: str = "", method: str = "GET",
                 parameters: Optional[List[Parameter]] = None,
                 expect_state: str = ""):
        self.name = name
        self.endpoint = endpoint
        self.method = method
        self.parameters = parameters or []
        self.expect_state = expect_state

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self) if hasattr(self, "__dataclass_fields__") else {
            "name": self.name, "endpoint": self.endpoint,
            "method": self.method, "expect_state": self.expect_state}
        d["parameters"] = [p.to_dict() for p in self.parameters]
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "WorkflowStep":
        params = [Parameter(**{k: v for k, v in p.items()
                               if k in Parameter.__dataclass_fields__})
                  for p in (d.get("parameters") or [])]
        return cls(name=d.get("name", ""), endpoint=d.get("endpoint", ""),
                   method=d.get("method", "GET"), parameters=params,
                   expect_state=d.get("expect_state", ""))


class Workflow:
    def __init__(self, name: str, steps: Optional[List[WorkflowStep]] = None,
                 observed: bool = False):
        self.name = name
        self.steps = steps or []
        self.observed = observed

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "observed": self.observed,
                "steps": [s.to_dict() for s in self.steps]}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Workflow":
        return cls(name=d.get("name", ""),
                   steps=[WorkflowStep.from_dict(s)
                          for s in (d.get("steps") or [])],
                   observed=bool(d.get("observed", False)))
