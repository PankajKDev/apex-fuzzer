"""Authorization observation store (§11, bounty items #1–2).

Every (identity × endpoint × method) probe lands here as an
AuthorizationObservation with the semantic response fingerprint —
never just the status code. Verdicts compare shapes across identities,
tenants and methods. Persisted to ``authorization_matrix.json``.
"""
import json
from pathlib import Path
from typing import Any, Dict, List
from ..logging_setup import get_logger

log = get_logger("authz")


class AuthorizationObservation:
    def __init__(self, identity: str, role: str = "",
                 tenant: str = "", endpoint: str = "",
                 resource: str = "", method: str = "GET",
                 status: int = 0, shape: str = "", body_hash: str = "",
                 length_bucket: int = 0, evidence: str = ""):
        self.identity = identity
        self.role = role
        self.tenant = tenant
        self.endpoint = endpoint
        self.resource = resource
        self.method = method
        self.status = status
        self.shape = shape
        self.body_hash = body_hash
        self.length_bucket = length_bucket
        self.evidence = evidence

    def to_dict(self) -> Dict[str, Any]:
        return {"identity": self.identity, "role": self.role,
                "tenant": self.tenant, "endpoint": self.endpoint,
                "resource": self.resource, "method": self.method,
                "status": self.status, "shape": self.shape,
                "body_hash": self.body_hash,
                "length_bucket": self.length_bucket,
                "evidence": self.evidence}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AuthorizationObservation":
        return cls(**{k: d.get(k, "") if k not in
                       ("status", "length_bucket") else
                       int(d.get(k) or 0)
                       for k in ("identity", "role", "tenant", "endpoint",
                                 "resource", "method", "status", "shape",
                                 "body_hash", "length_bucket", "evidence")})


class AuthorizationMatrix:
    def __init__(self):
        self.observations: List[AuthorizationObservation] = []

    def record(self, obs: AuthorizationObservation):
        for cur in self.observations:
            if (cur.identity, cur.endpoint, cur.method,
                    cur.resource) == (obs.identity, obs.endpoint,
                                      obs.method, obs.resource):
                return cur
        self.observations.append(obs)
        return obs

    def query(self, endpoint: str = "", method: str = "",
              identity: str = "") -> List[AuthorizationObservation]:
        out = self.observations
        if endpoint:
            out = [o for o in out if o.endpoint == endpoint]
        if method:
            out = [o for o in out if o.method == method]
        if identity:
            out = [o for o in out if o.identity == identity]
        return out

    def cells(self) -> Dict[str, List[AuthorizationObservation]]:
        """Group observations by (endpoint, method) for verdict passes."""
        groups: Dict[str, List[AuthorizationObservation]] = {}
        for o in self.observations:
            groups.setdefault(f"{o.method}::{o.endpoint}", []).append(o)
        return groups

    def to_dict(self) -> Dict[str, Any]:
        return {"observations": [o.to_dict() for o in self.observations]}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AuthorizationMatrix":
        m = cls()
        for o in d.get("observations") or []:
            try:
                m.observations.append(AuthorizationObservation.from_dict(o))
            except Exception:
                continue
        return m

    def save(self, path: Path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2))

    @classmethod
    def load(cls, path: Path) -> "AuthorizationMatrix":
        return cls.from_dict(json.loads(Path(path).read_text()))


def same_object(a: AuthorizationObservation,
                b: AuthorizationObservation) -> bool:
    """Semantic equality: both 200 with identical body, or identical
    shape in the same length bucket. Status alone never decides (§57)."""
    if a.status != 200 or b.status != 200:
        return False
    if a.body_hash and a.body_hash == b.body_hash:
        return True
    return bool(a.shape) and a.shape == b.shape and \
        a.length_bucket == b.length_bucket


def describe_cell(obs: List[AuthorizationObservation]) -> str:
    return ", ".join(f"{o.identity}→{o.status}" for o in obs)


def evaluate_cell(obs: List[AuthorizationObservation],
                  endpoint_type: str = "") -> tuple:
    """Verdict for one (endpoint, method) cell across identities.

    Returns (verdict, notes, kind) where kind is one of bola / bfla /
    broken_access / tenant_isolation / "" (no finding).
    """
    by_name = {o.identity: o for o in obs}
    anon = by_name.get("anonymous")
    authed = [o for o in obs if o.identity != "anonymous"]
    if len(authed) < 1:
        return "inconclusive", "", ""

    # cross-tenant: same object served to two different tenants
    tenants = {}
    for o in authed:
        if o.status == 200 and o.tenant:
            tenants.setdefault(o.tenant, []).append(o)
    tkeys = list(tenants.keys())
    if len(tkeys) >= 2:
        a, b = tenants[tkeys[0]][0], tenants[tkeys[1]][0]
        if same_object(a, b):
            return ("strong_candidate",
                    f"tenant isolation failure: '{a.identity}' "
                    f"(tenant {tkeys[0]}) and '{b.identity}' (tenant "
                    f"{tkeys[1]}) received the same object",
                    "tenant_isolation")

    # cross-user, same shape → BOLA (resource) or BFLA (method/role gap)
    if len(authed) >= 2:
        a, b = authed[0], authed[1]
        if same_object(a, b):
            if a.tenant and b.tenant and a.tenant != b.tenant:
                kind = "tenant_isolation"
                what = (f"cross-tenant object access: '{a.identity}' "
                        f"reads '{b.identity}''s object")
            elif "admin" in (a.role + b.role).lower() or \
                    "admin" in (a.identity + b.identity).lower():
                kind = "bfla"
                what = (f"function/role gap: '{a.identity}' and "
                        f"'{b.identity}' receive identical privileged "
                        f"responses")
            else:
                kind = "bola"
                what = (f"BOLA: '{a.identity}' and '{b.identity}' "
                        f"receive the identical object")
            return ("strong_candidate", what, kind)
        # healthy differential: one allowed, one denied
        if a.status == 200 and b.status in (401, 403, 404):
            return ("inconclusive",
                    f"authorization enforced ({a.identity}={a.status}, "
                    f"{b.identity}={b.status})", "")

    # broken access per method: anonymous denied, someone allowed
    if anon is not None and anon.status in (401, 403):
        for o in authed:
            if o.status == 200 and endpoint_type in (
                    "admin", "api", "authentication"):
                return ("strong_candidate",
                        f"BFLA/broken access: anonymous denied "
                        f"({anon.status}) but '{o.identity}' reaches "
                        f"privileged endpoint via {o.method}", "bfla")
    return ("inconclusive", "", "")
