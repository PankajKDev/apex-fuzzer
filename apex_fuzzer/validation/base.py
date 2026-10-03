"""Generic validation framework."""
from dataclasses import dataclass, field
from typing import Optional, Dict, Any
from ..models import Finding
from ..logging_setup import get_logger

log = get_logger("validator")


@dataclass
class Candidate:
    finding: Finding
    test_class: str
    endpoint_url: str
    parameter: Optional[str] = None
    method: str = "GET"
    baseline_response: Optional[Dict[str, Any]] = None
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body: Optional[str] = None


@dataclass
class ValidationOutcome:
    status: str
    confidence: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    notes: str = ""


class Validator:
    name = "base"
    test_class = "generic"

    def __init__(self, cfg):
        self.cfg = cfg

    def can_handle(self, candidate: Candidate) -> bool:
        return candidate.test_class == self.test_class

    def validate(self, candidate: Candidate) -> ValidationOutcome:
        raise NotImplementedError
