"""GraphQL operation helpers: variable paths, mutation guard, names.

Hunter methodology for GraphQL authorization: replay the *same observed
operation document* with only one variable swapped to a victim's value,
as a different identity. Query operations are read-only by contract;
anything shaped like a mutation is never replayed.
"""
import json as _json
import re
from typing import Any, Dict, List, Optional, Tuple

_MAX_VARIABLES = 50
_MAX_BODY_BYTES = 1_000_000

_STRING_RE = re.compile(r'"(?:[^"\\]|\\.)*"')
_COMMENT_RE = re.compile(r"#[^\n]*")
_MUTATION_RE = re.compile(r"\bmutation\b", re.I)
_QUERY_RE = re.compile(r"\b(query|subscription)\b", re.I)


def parse_graphql_body(body: Any) -> Optional[Dict[str, Any]]:
    """Parse a GraphQL POST body, or None when it is not one."""
    if isinstance(body, (bytes, bytearray)):
        try:
            body = bytes(body).decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            return None
    if not isinstance(body, str) or not body.strip():
        return None
    if len(body.encode("utf-8")) > _MAX_BODY_BYTES:
        return None
    try:
        data = _json.loads(body)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    query = data.get("query")
    if not isinstance(query, str) or not query.strip():
        return None
    variables = data.get("variables", {})
    if variables is not None and not isinstance(variables, dict):
        return None
    return {"query": query, "variables": variables or {},
            "operationName": data.get("operationName")}


def _structural_query(query: str) -> str:
    """Query text with string literals and comments blanked.

    The mutation keyword is structural: it counts only outside string
    literals (an operation named GetMutationHistory is not a mutation).
    """
    text = _STRING_RE.sub('""', query)
    return _COMMENT_RE.sub("", text)


def is_mutation_operation(query: str) -> bool:
    """True when the operation document performs a mutation."""
    return bool(_MUTATION_RE.search(_structural_query(query or "")))


def operation_kind(query: str) -> str:
    """Best-effort operation kind: mutation, subscription, or query."""
    structural = _structural_query(query or "")
    if _MUTATION_RE.search(structural):
        return "mutation"
    if _QUERY_RE.search(structural):
        match = _QUERY_RE.search(structural)
        return (match.group(1) if match else "query").lower()
    return "query"


def variable_paths(variables: Dict[str, Any]) -> List[str]:
    """Dotted leaf paths of scalar variables, capped and fail-closed."""
    paths: List[str] = []

    def walk(node: Any, prefix: str, depth: int = 0) -> None:
        if len(paths) >= _MAX_VARIABLES:
            return
        if depth > 6:
            raise ValueError("GraphQL variables are nested too deeply")
        if isinstance(node, dict):
            for key, item in node.items():
                if not isinstance(key, str) or not key:
                    raise ValueError("GraphQL variable name is unsupported")
                name = f"{prefix}.{key}" if prefix else str(key)
                if isinstance(item, dict):
                    walk(item, name, depth + 1)
                elif isinstance(item, list):
                    for entry in item[:10]:
                        walk(entry, name, depth + 1)
                elif isinstance(item, (str, int, float)) and \
                        not isinstance(item, bool):
                    paths.append(name)
        elif isinstance(node, list):
            for entry in node[:10]:
                walk(entry, prefix, depth + 1)

    if not isinstance(variables, dict):
        raise ValueError("GraphQL variables are not an object")
    walk(variables, "")
    return paths


def normalize_parameter(body_text: Any, parameter: str) -> Optional[str]:
    """Map a bare variable name to its `variables.<path>` form.

    Full `variables.<path>` names pass through when the path exists.
    Anything else yields None (never guess).
    """
    parsed = parse_graphql_body(body_text)
    if parsed is None or not parameter:
        return None
    try:
        paths = variable_paths(parsed["variables"])
    except ValueError:
        return None
    if parameter in paths or parameter.startswith("variables."):
        full = parameter if parameter.startswith("variables.") \
            else f"variables.{parameter}"
        if full[len("variables."):] in paths:
            return full
        return None
    leaf = str(parameter).strip()
    matches = [path for path in paths
               if path == leaf or path.endswith(f".{leaf}")]
    if len(matches) == 1:
        return f"variables.{matches[0]}"
    return None


def variable_leaf(parameter: str) -> str:
    """Leaf segment of a (possibly `variables.`-prefixed) path."""
    text = str(parameter or "")
    if text.startswith("variables."):
        text = text[len("variables."):]
    return text.split(".")[-1] if text else ""


def set_variable(body_text: str, full_path: str,
                 value: str) -> Tuple[str, bool]:
    """Return (rebuilt_body, changed). Only the selected variable moves.

    The query document, operation name, and peer variables are preserved.
    """
    parsed = parse_graphql_body(body_text)
    if parsed is None:
        raise ValueError("GraphQL body cannot be parsed safely")
    path = full_path[len("variables."):] if \
        full_path.startswith("variables.") else full_path
    import re as _re2
    parts = _re2.findall(r"[^.\[\]]+|\[\d*\]", path)
    if not parts:
        raise ValueError("GraphQL variable path is empty")
    variables = parsed["variables"]
    current: Any = variables
    for index, raw in enumerate(parts):
        last = index == len(parts) - 1
        if raw.startswith("["):
            if not isinstance(current, list):
                raise ValueError("GraphQL variable path misses")
            slot = raw[1:-1]
            pos = int(slot) if slot.isdigit() else 0
            if pos >= len(current):
                raise ValueError("GraphQL variable path misses")
            if last:
                current[pos] = value
            else:
                current = current[pos]
            continue
        if not isinstance(current, dict) or raw not in current:
            raise ValueError("GraphQL variable path misses")
        if last:
            current[raw] = value
        else:
            current = current[raw]
    rebuilt = {"query": parsed["query"], "variables": variables}
    if parsed.get("operationName") is not None:
        rebuilt["operationName"] = parsed["operationName"]
    return _json.dumps(rebuilt, separators=(",", ":"),
                       ensure_ascii=False), True
