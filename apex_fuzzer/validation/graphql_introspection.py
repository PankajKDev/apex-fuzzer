"""GraphQL introspection exposure probe (schema disclosure).

Many production GraphQL APIs leave ``__schema`` introspection enabled,
disclosing every type, field, and mutation to anonymous callers. This
probe sends one minimal introspection document per GraphQL endpoint:

- ``exposed=True`` → schema disclosure candidate (sensitivity needs
  human review; exposure alone is not a vulnerability).
- ``exposed=False`` → a valid GraphQL response without ``__schema``
  (introspection disabled — the healthy state, a genuine negative).
- ``exposed=None`` → inconclusive (non-GraphQL answer, error status,
  or undecodable body — never a negative).

Budgets, scope, and the state-change gate are enforced by the shared
HTTP client outside this module; ``BudgetExceeded`` (including gate
refusals) propagates for BLOCKED coverage upstream.
"""
import json as _json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..budgets import BudgetExceeded
from ..logging_setup import get_logger

log = get_logger("graphql-introspection")

# Minimal disclosure proof: type inventory only, no field details.
INTROSPECTION_QUERY = \
    "{__schema{queryType{name}mutationType{name}types{name}}}"
_MAX_ENDPOINTS = 10
_MAX_TYPES = 200
_MAX_BODY_BYTES = 1_000_000


@dataclass
class IntrospectionResult:
    endpoint_url: str
    method: str
    # True = schema disclosed; False = valid GraphQL answer without it;
    # None = inconclusive (never a negative).
    exposed: Optional[bool] = None
    types: List[str] = field(default_factory=list)
    status: int = 0
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"endpoint_url": self.endpoint_url, "method": self.method,
                "exposed": self.exposed, "types": list(self.types),
                "status": self.status, "notes": self.notes}


def _parse_schema(body: str) -> Optional[Dict[str, Any]]:
    """Extract the __schema object, or None when absent/unparseable."""
    try:
        if len(body.encode("utf-8")) > _MAX_BODY_BYTES:
            return None
        data = _json.loads(body or "")
    except (ValueError, TypeError, UnicodeError):
        return None
    if not isinstance(data, dict):
        return None
    inner = data.get("data")
    if not isinstance(inner, dict):
        return None
    schema = inner.get("__schema")
    return schema if isinstance(schema, dict) else None


def is_graphql_response(body: str) -> bool:
    """True for a valid GraphQL-shaped envelope (data and/or errors)."""
    try:
        data = _json.loads(body or "")
    except (ValueError, TypeError):
        return False
    return isinstance(data, dict) and \
        ("data" in data or "errors" in data)


def probe_introspection(client, endpoint_url: str, method: str,
                        timeout: int = 10) -> IntrospectionResult:
    """Send one introspection document; classify the answer."""
    res = IntrospectionResult(endpoint_url=endpoint_url,
                              method=(method or "GET").upper())
    try:
        if res.method == "GET":
            r = client.get(endpoint_url,
                           params={"query": INTROSPECTION_QUERY},
                           timeout=timeout)
        else:
            r = client.request(res.method, endpoint_url,
                               json={"query": INTROSPECTION_QUERY},
                               timeout=timeout)
    except BudgetExceeded:
        raise
    except Exception as e:
        res.notes = f"request failed: {e}"[:200]
        return res
    res.status = getattr(r, "status_code", 0) or 0
    text = getattr(r, "text", "") or ""
    if res.status != 200:
        res.notes = f"HTTP {res.status}: no schema signal"
        return res
    schema = _parse_schema(text)
    if schema is not None:
        try:
            names = [str(t.get("name", ""))
                     for t in (schema.get("types") or [])
                     if isinstance(t, dict) and t.get("name")]
        except (AttributeError, TypeError):
            names = []
        res.exposed = True
        res.types = names[:_MAX_TYPES]
        res.notes = (f"introspection enabled: {len(names)} type(s) "
                     f"disclosed ({', '.join(names[:10])}"
                     f"{'…' if len(names) > 10 else ''})")
        return res
    if is_graphql_response(text):
        res.exposed = False
        res.notes = "valid GraphQL response without __schema: " \
                    "introspection disabled"
    else:
        res.notes = "non-GraphQL answer: endpoint type unconfirmed"
    return res
