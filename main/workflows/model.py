"""Workflow runtime model (agent Phase 4).

`application/workflows.py` is the persisted storage schema — this
module is the analysis model built by discovery: steps bound to
concrete requests, resource production/consumption, preconditions,
and evidence. `to_stored()` converts back for persistence, so the
stored shapes from Phase 1 stay the single on-disk format.
"""
from typing import Any, Dict, List, Optional
from ..application.workflows import Workflow as StoredWorkflow
from ..application.workflows import WorkflowStep as StoredStep
from ..models import Parameter
from ..logging_setup import get_logger

log = get_logger("workflows-model")


class FlowStep:
    """One ordered step: endpoint + method + bound params + I/O."""

    def __init__(self, name: str, endpoint: str = "",
                 normalized_url: str = "", method: str = "GET",
                 parameters: Optional[List[Parameter]] = None,
                 produces: Optional[List[str]] = None,
                 consumes: Optional[List[str]] = None,
                 requires: Optional[List[str]] = None,
                 evidence: str = ""):
        self.name = name
        self.endpoint = endpoint
        self.normalized_url = normalized_url or endpoint
        self.method = method
        self.parameters = parameters or []
        self.produces = produces or []  # resource keys created here
        self.consumes = consumes or []  # resource keys required here
        self.requires = requires or []  # step names that must precede
        self.evidence = evidence

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "endpoint": self.endpoint,
                "normalized_url": self.normalized_url,
                "method": self.method,
                "parameters": [p.to_dict() for p in self.parameters],
                "produces": self.produces, "consumes": self.consumes,
                "requires": self.requires, "evidence": self.evidence}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "FlowStep":
        params = [Parameter(**{k: v for k, v in p.items()
                               if k in Parameter.__dataclass_fields__})
                  for p in (d.get("parameters") or [])]
        return cls(
            name=d.get("name", ""), endpoint=d.get("endpoint", ""),
            normalized_url=d.get("normalized_url",
                                 d.get("endpoint", "")),
            method=d.get("method", "GET"), parameters=params,
            produces=d.get("produces") or [],
            consumes=d.get("consumes") or [],
            requires=d.get("requires") or [],
            evidence=d.get("evidence", ""))

    def to_stored(self) -> StoredStep:
        return StoredStep(name=self.name, endpoint=self.endpoint,
                          method=self.method,
                          parameters=list(self.parameters))


class Flow:
    """An ordered, evidenced multi-step sequence."""

    def __init__(self, name: str, steps: Optional[List[FlowStep]] = None,
                 observed: bool = False, confidence: str = "possible",
                 evidence: str = ""):
        self.name = name
        self.steps = steps or []
        self.observed = observed
        self.confidence = confidence  # observed | inferred | hypothesized
        self.evidence = evidence

    def step_names(self) -> List[str]:
        return [s.name for s in self.steps]

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name,
                "steps": [s.to_dict() for s in self.steps],
                "observed": self.observed,
                "confidence": self.confidence, "evidence": self.evidence}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Flow":
        return cls(
            name=d.get("name", ""),
            steps=[FlowStep.from_dict(s) for s in (d.get("steps") or [])],
            observed=bool(d.get("observed", False)),
            confidence=d.get("confidence", "possible"),
            evidence=d.get("evidence", ""))

    def to_stored(self) -> StoredWorkflow:
        return StoredWorkflow(
            name=self.name,
            steps=[s.to_stored() for s in self.steps],
            observed=self.observed)
