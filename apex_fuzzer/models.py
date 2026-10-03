"""Structured data models — the spine of the pipeline."""
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from enum import Enum
import json


class EndpointType(str, Enum):
    PAGE = "page"; API = "api"; GRAPHQL = "graphql"
    UPLOAD = "upload"; DOWNLOAD = "download"; REDIRECT = "redirect"
    WEBHOOK = "webhook"; CALLBACK = "callback"
    AUTH = "authentication"; ADMIN = "admin"
    EXPORT = "export"; IMPORT = "import"; PROXY = "proxy"
    STATIC = "static"; UNKNOWN = "unknown"


class Confidence(str, Enum):
    CONFIRMED = "confirmed"; PROBABLE = "probable"
    POSSIBLE = "possible"; UNKNOWN = "unknown"


class ValidationStatus(str, Enum):
    NOT_TESTED = "not_tested"; CONFIRMED = "confirmed"
    STRONG_CANDIDATE = "strong_candidate"
    INCONCLUSIVE = "inconclusive"; FALSE_POSITIVE = "false_positive"


@dataclass
class Parameter:
    name: str
    location: str
    source: List[str] = field(default_factory=list)
    sample_value: Optional[str] = None
    confidence: str = Confidence.POSSIBLE.value

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Endpoint:
    url: str
    normalized_url: str
    method: str = "GET"
    host: str = ""
    path: str = ""
    query_parameters: List[Parameter] = field(default_factory=list)
    body_parameters: List[Parameter] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    content_type: str = ""
    source: List[str] = field(default_factory=list)
    authentication_required: Optional[bool] = None
    technology: List[str] = field(default_factory=list)
    endpoint_type: str = EndpointType.UNKNOWN.value
    status_code: Optional[int] = None
    response_size: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["query_parameters"] = [p.to_dict() for p in self.query_parameters]
        d["body_parameters"] = [p.to_dict() for p in self.body_parameters]
        return d


@dataclass
class Technology:
    name: str
    version: Optional[str] = None
    confidence: str = Confidence.POSSIBLE.value
    evidence: List[str] = field(default_factory=list)
    # which test families this technology should gate (frontend, gateway,
    # auth, cloud, waf, server, other)
    category: str = "other"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    id: str
    source: str
    template_id: Optional[str] = None
    name: str = ""
    severity: str = "info"
    confidence: str = Confidence.UNKNOWN.value
    validation_status: str = ValidationStatus.NOT_TESTED.value
    host: str = ""
    matched_at: str = ""
    endpoint_url: Optional[str] = None
    parameter: Optional[str] = None
    method: str = "GET"
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body: Optional[str] = None
    response_status: Optional[int] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_snippet: Optional[str] = None
    evidence_dir: Optional[str] = None
    reproduction: Optional[str] = None
    description: str = ""
    tags: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)
    root_cause_key: Optional[str] = None
    # triage-layer fields (spec §11)
    impact: str = ""
    reproduction_steps: List[str] = field(default_factory=list)
    false_positive_notes: str = ""
    # application-aware attribution (§61 evidence requirements)
    identity: str = ""
    tenant: str = ""
    resource_key: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Finding":
        known = {k: v for k, v in d.items() if k in cls.__dataclass_fields__}
        return cls(**known)


@dataclass
class Hypothesis:
    hypothesis: str
    endpoint: Optional[str]
    reason: str
    test_class: str
    confidence: float
    required_context: str = "unauthenticated"
    status: str = "hypothesized"
    # populated when the orchestrator feeds the hypothesis back into
    # deterministic testing (oast / sqlmap / differential / nuclei)
    notes: str = ""
    # evidence contract (§43): what would prove/disprove this hypothesis
    expected_signal: str = ""
    required_evidence: str = ""
    observation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ── application-aware models (Phase 1 foundation) ─────────────────────

@dataclass
class Identity:
    """A testable user: credentials/headers, roles, tenant membership."""
    name: str
    roles: List[str] = field(default_factory=list)
    tenant: Optional[str] = None
    auth_headers: Dict[str, str] = field(default_factory=dict)
    # Playwright storage-state file (Phase 2 browser sessions)
    storage_state: Optional[str] = None
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Identity":
        known = {k: v for k, v in d.items() if k in cls.__dataclass_fields__}
        return cls(**known)


@dataclass
class Role:
    name: str
    permissions: List[str] = field(default_factory=list)
    tenant: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Role":
        known = {k: v for k, v in d.items() if k in cls.__dataclass_fields__}
        return cls(**known)


@dataclass
class Tenant:
    name: str
    identifiers: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Tenant":
        known = {k: v for k, v in d.items() if k in cls.__dataclass_fields__}
        return cls(**known)


@dataclass
class Resource:
    """A server-side object addressable through parameters (id, uuid,
    tenant_id, …). Key is stable: '<endpoint>::<location>:<param>'."""
    key: str
    resource_type: str = "object"
    identifiers: Dict[str, str] = field(default_factory=dict)
    owner: Optional[str] = None
    tenant: Optional[str] = None
    exposed_by: List[str] = field(default_factory=list)
    discovered_from: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Resource":
        known = {k: v for k, v in d.items() if k in cls.__dataclass_fields__}
        return cls(**known)


# test-result statuses (§51) — infrastructure states are never mapped to
# vulnerability negatives by the orchestrator
RESULT_CONFIRMED = "confirmed"
RESULT_CANDIDATE = "candidate"
RESULT_NEGATIVE = "negative"
RESULT_INCONCLUSIVE = "inconclusive"
RESULT_BLOCKED = "blocked"
RESULT_SKIPPED = "skipped"
RESULT_ERROR = "error"


@dataclass
class TestResult:
    # not a pytest test case (imported into test modules)
    __test__ = False
    status: str = RESULT_INCONCLUSIVE
    evidence: Dict[str, Any] = field(default_factory=dict)
    observations: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    requests_used: int = 0
    duration_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AttackChain:
    """A finding-enabled finding sequence (populated by the Phase 9 chain
    engine; schema defined in Phase 1 so artifacts stay stable)."""
    id: str
    nodes: List[Dict[str, Any]] = field(default_factory=list)
    edges: List[Dict[str, Any]] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    impact: str = ""
    confidence: str = Confidence.UNKNOWN.value

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AttackChain":
        known = {k: v for k, v in d.items() if k in cls.__dataclass_fields__}
        return cls(**known)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def write_jsonl(path, items):
    with open(path, "w") as f:
        for it in items:
            f.write(json.dumps(
                it.to_dict() if hasattr(it, "to_dict") else it) + "\n")


def read_jsonl(path) -> List[dict]:
    out = []
    if not path.exists():
        return out
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out
