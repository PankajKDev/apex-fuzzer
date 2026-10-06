"""Schema-driven GraphQL field enumeration (read side).

Fetches one bounded introspection document per GraphQL endpoint and
derives testable read operations from the advertised schema: Query
fields that take identifier-like arguments and return objects with
scalar subfields. Mutations are never generated; depth and batching
probes are out of scope (request amplification risks). Field
documents built here feed the ownership-graded replay engine.
"""
import json as _json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ..budgets import BudgetExceeded
from ..logging_setup import get_logger
from ..validation.differential import IDOR_PARAM_NAMES

log = get_logger("graphql-schema")

# One document: Query root plus every object type's fields, with
# argument and wrapper types unwrapped to depth 3 (covers [ID!]!).
FULL_SCHEMA_QUERY = (
    "{__schema{queryType{name}types{kind name "
    "fields{name args{name type{kind name "
    "ofType{kind name ofType{kind name}}}}}}}}"
)

_MAX_ENDPOINTS = 10
_MAX_TYPES = 200
_MAX_FIELDS = 5
_MAX_SUBFIELDS = 5
_MAX_BODY_BYTES = 1_000_000

_SCALAR_KINDS = {"SCALAR", "ENUM"}


@dataclass
class SchemaField:
    """One testable Query field: identifier arg, object return."""
    field: str
    arg: str
    ret: str
    subfields: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"field": self.field, "arg": self.arg,
                "ret": self.ret, "subfields": list(self.subfields)}


def _named_type(node: Any, depth: int = 0) -> str:
    """Unwrap NON_NULL/LIST wrappers to the named type."""
    current = node if isinstance(node, dict) else {}
    while depth < 5:
        name = current.get("name")
        if name:
            return str(name)
        child = current.get("ofType")
        if not isinstance(child, dict):
            return ""
        current = child
        depth += 1
    return ""


def fetch_schema(client, endpoint_url: str, method: str,
                 timeout: int = 10) -> Optional[Dict[str, Any]]:
    """Fetch and parse the full schema, or None when unavailable."""
    method = (method or "POST").upper()
    try:
        if method == "GET":
            r = client.get(endpoint_url,
                           params={"query": FULL_SCHEMA_QUERY},
                           timeout=timeout)
        else:
            r = client.request(method, endpoint_url,
                               json={"query": FULL_SCHEMA_QUERY},
                               timeout=timeout)
    except BudgetExceeded:
        raise
    except Exception as exc:
        log.debug("schema fetch %s failed: %s", endpoint_url, exc)
        return None
    if getattr(r, "status_code", 0) != 200:
        return None
    try:
        return parse_schema(getattr(r, "text", "") or "")
    except (ValueError, TypeError):
        return None


def parse_schema(body: str) -> Optional[Dict[str, Any]]:
    """Schema dict → {query: {field: {args, ret}}, scalars: {...}}."""
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
    if not isinstance(schema, dict):
        return None
    type_fields: Dict[str, Dict[str, dict]] = {}
    scalars: Dict[str, List[str]] = {}
    for entry in (schema.get("types") or [])[:_MAX_TYPES]:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if not name or str(name).startswith("__"):
            continue
        fields: Dict[str, dict] = {}
        scalar_subs: List[str] = []
        for fdef in (entry.get("fields") or []):
            if not isinstance(fdef, dict):
                continue
            fname = fdef.get("name")
            if not fname or str(fname).startswith("__"):
                continue
            ret = _named_type(fdef.get("type"))
            args = []
            for arg in (fdef.get("args") or []):
                if not isinstance(arg, dict) or not arg.get("name"):
                    continue
                args.append((str(arg["name"]),
                             _named_type(arg.get("type"))))
            fields[str(fname)] = {"args": args, "ret": ret}
            if entry.get("kind") == "OBJECT" and ret in ("String",
                                                         "Int", "Float",
                                                         "Boolean", "ID"):
                scalar_subs.append(str(fname))
        type_fields[str(name)] = fields
        if scalar_subs:
            scalars[str(name)] = scalar_subs[:_MAX_SUBFIELDS + 5]
    query_type = ""
    query_ref = schema.get("queryType") or {}
    if isinstance(query_ref, dict):
        query_type = str(query_ref.get("name") or "")
    return {"query": type_fields.get(query_type, {}),
            "query_type": query_type, "scalars": scalars}


def _is_id_arg(name: str) -> bool:
    return str(name or "").strip().lower() in IDOR_PARAM_NAMES


def select_id_fields(parsed: Optional[Dict[str, Any]],
                     max_fields: int = _MAX_FIELDS) -> List[SchemaField]:
    """Query fields taking identifier args and returning objects."""
    out: List[SchemaField] = []
    if not parsed:
        return out
    scalars = parsed.get("scalars") or {}
    for fname, fdef in (parsed.get("query") or {}).items():
        if len(out) >= max(0, max_fields):
            break
        args = [name for name, _ in (fdef.get("args") or [])
                if _is_id_arg(name)]
        if not args:
            continue
        ret = str(fdef.get("ret") or "")
        subs = list(scalars.get(ret) or [])
        if not subs:
            continue
        out.append(SchemaField(field=str(fname), arg=args[0], ret=ret,
                              subfields=subs[:_MAX_SUBFIELDS]))
    return out


def build_field_query(schema_field: SchemaField,
                      victim_value: str) -> Tuple[str, str]:
    """Render one field document with the victim value inlined.

    Returns (document, label). Values are JSON-encoded literals;
    only the selected identifier argument moves — the shape is
    otherwise fixed, mirroring the observed-operation replay rule.
    """
    subs = " ".join(["__typename"] + list(
        schema_field.subfields or []))
    document = (
        f"query ApexProbe{{apex0: {schema_field.field}("
        f"{schema_field.arg}:{_json.dumps(str(victim_value))})"
        f"{{{subs}}}}}")
    label = f"{schema_field.field}({schema_field.arg})"
    return document, label
