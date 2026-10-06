"""Operation-aware GraphQL BOLA replay (read side).

Hunter methodology: replay the *same observed operation document* with
only one variable swapped to a victim's value, as a different identity.
The owner baseline is fetched first on the same operation, and the
tester response is graded by ownership comparison.

Safety contract (bounded, fail-closed):
- query/subscription operations only; anything shaped like a mutation
  is never replayed (no writes from this module).
- the operation document, operation name, and peer variables replay
  verbatim; only the selected variable moves.
- victim values come from the authenticated harvest pool; the variable
  matches by leaf or dotted suffix, never by guessing.
- ambiguous shapes (>1 distinct tester shape for one operation and
  variable) fail closed; binary/malformed/non-JSON shapes are skipped.
- verdicts mirror the GET swap engine: graded matches become
  strong_candidate, completed denials are genuine negatives, and
  generic/contradictory bodies void the match.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ..budgets import BudgetExceeded
from ..logging_setup import get_logger

log = get_logger("graphql_replay")


@dataclass
class GraphqlReplayResult:
    endpoint_url: str
    operation: str
    variable: str
    victim_value: str
    owner: str
    tester: str
    owner_tenant: str = ""
    tester_tenant: str = ""
    status: int = 0
    match: bool = False
    verdict: str = "inconclusive"
    notes: str = ""
    markers_matched: List[str] = field(default_factory=list)
    generic_response: bool = False
    owner_snippet: str = ""
    tester_snippet: str = ""
    edge_denied: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {"endpoint_url": self.endpoint_url,
                "operation": self.operation, "variable": self.variable,
                "victim_value": self.victim_value, "owner": self.owner,
                "tester": self.tester,
                "owner_tenant": self.owner_tenant,
                "tester_tenant": self.tester_tenant,
                "status": self.status, "match": self.match,
                "verdict": self.verdict, "notes": self.notes,
                "markers_matched": list(self.markers_matched),
                "generic_response": self.generic_response,
                "owner_snippet": self.owner_snippet,
                "tester_snippet": self.tester_snippet,
                "edge_denied": self.edge_denied}


def _shape_operation(shape: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Parse one retained shape into a replayable operation, or None."""
    from ..validation.graphql import (is_mutation_operation,
                                      parse_graphql_body)
    if str(shape.get("method") or "GET").upper() != "POST":
        return None
    headers = shape.get("headers")
    content_type = ""
    if isinstance(headers, dict):
        for name, value in headers.items():
            if isinstance(name, str) and name.strip().lower() == \
                    "content-type" and isinstance(value, str):
                content_type = value
                break
    if not content_type:
        content_type = str(shape.get("content_type") or "")
    if "json" not in content_type.lower():
        return None
    parsed = parse_graphql_body(shape.get("post_data"))
    if parsed is None:
        return None
    if is_mutation_operation(parsed["query"]):
        return None
    return {"parsed": parsed, "content_type": content_type,
            "headers": dict(headers) if isinstance(headers, dict) else {}}


def _operation_key(parsed: Dict[str, Any]) -> str:
    name = parsed.get("operationName") or ""
    return f"{name}::{parsed['query']}"


def _victim_paths(variables: Dict[str, Any], pool_param: str) -> List[str]:
    """Variable paths a pool parameter may legally address."""
    from ..validation.graphql import variable_paths
    try:
        paths = variable_paths(variables)
    except ValueError:
        return []
    wanted = str(pool_param or "").strip()
    if not wanted:
        return []
    if wanted.startswith("variables."):
        wanted = wanted[len("variables."):]
    exact = [path for path in paths
             if path == wanted or path.endswith(f".{wanted}")]
    if exact:
        return exact
    leaf = wanted.split(".")[-1]
    return [path for path in paths if path.split(".")[-1] == leaf]


def replay_operations(http, endpoint: Any, victims: List[Any], tester: Any,
                      owner_headers: Dict[str, Dict[str, str]],
                      timeout: int = 10, max_ids: int = 3,
                      scope=None, matrix=None,
                      ownership_fields: Optional[List[str]] = None
                      ) -> List[GraphqlReplayResult]:
    """Replay query operations with victim variables; grade the response."""
    from ..validation.graphql import set_variable, variable_leaf
    out: List[GraphqlReplayResult] = []
    tester_name = getattr(tester, "name", "anonymous")
    tester_tenant = getattr(tester, "tenant", "") or ""
    tester_headers = dict(getattr(tester, "auth_headers", None) or {})
    shapes = [s for s in
              list(getattr(endpoint, "observed_requests", []) or [])
              if isinstance(s, dict) and
              str(s.get("identity", "anonymous")) == tester_name]
    if not shapes:
        return out
    tried = 0
    seen = set()
    for victim in victims or []:
        if tried >= max_ids:
            break
        owner = getattr(victim, "owner", "")
        if not owner or owner == tester_name:
            continue
        pool_param = getattr(victim, "param", "")
        value = getattr(victim, "value", "")
        if not pool_param or not value:
            continue
        owner_tenant = getattr(victim, "owner_tenant", "") or ""
        # candidate (operation, variable) pairs for this victim value
        options: List[Tuple[Dict[str, Any], str]] = []
        for shape in shapes:
            url = shape.get("url")
            if not isinstance(url, str):
                continue
            if scope is not None:
                try:
                    if not scope.active_test_allowed(url):
                        continue
                except Exception:
                    continue
            parsed_op = _shape_operation(shape)
            if parsed_op is None:
                continue
            for path in _victim_paths(parsed_op["parsed"]["variables"],
                                      pool_param):
                options.append((shape, f"variables.{path}"))
        # one distinct shape per (operation, variable); ambiguity fails
        # closed instead of guessing across captures
        by_key: Dict[str, list] = {}
        for shape, full_path in options:
            parsed = _shape_operation(shape)
            if parsed is None:
                continue
            by_key.setdefault(
                (_operation_key(parsed["parsed"]), full_path),
                []).append(shape)
        for (op_key, full_path), candidates in sorted(by_key.items()):
            if tried >= max_ids:
                break
            key = (op_key, full_path, value, owner)
            if key in seen:
                continue
            seen.add(key)
            distinct = {(str(s.get("method")), str(s.get("url")),
                         repr(s.get("post_data"))) for s in candidates}
            if len(distinct) > 1:
                log.debug("graphql replay ambiguous for %s; skipping",
                          full_path)
                continue
            shape = candidates[0]
            url = str(shape.get("url"))
            operation = op_key.split("::", 1)[0] or "anonymous"
            tried += 1
            # owner baseline on the SAME operation first
            try:
                owner_body, _ = set_variable(
                    _shape_text(shape), full_path, value)
            except (ValueError, TypeError) as exc:
                log.debug("graphql baseline build failed: %s", exc)
                continue
            try:
                headers = _replay_headers(shape, owner_headers.get(owner))
                base = http.request("POST", url, headers=headers,
                                    data=owner_body, timeout=timeout)
            except BudgetExceeded:
                raise
            except Exception as exc:
                log.debug("graphql baseline %s as %s failed: %s",
                          url, owner, exc)
                continue
            if base.status_code != 200:
                continue
            # tester replay: identical operation, victim variable
            resp = _fetch_replay(
                http, url, _replay_headers(shape, tester_headers),
                owner_body, timeout, tester_name)
            if resp is None:
                continue
            res = _grade_replay(
                base, resp, url=url, operation=operation,
                full_path=full_path, value=value, owner=owner,
                tester_name=tester_name, tester_tenant=tester_tenant,
                owner_tenant=owner_tenant,
                ownership_fields=ownership_fields, matrix=matrix,
                endpoint=endpoint, exclude=variable_leaf(full_path))
            if res is None:
                continue
            out.append(res)
    return out


def _fetch_replay(http, url: str, headers: Dict[str, str], data: str,
                  timeout: int, who: str):
    """POST one replay; None on transport failure (BudgetExceeded rises)."""
    try:
        return http.request("POST", url, headers=headers, data=data,
                            timeout=timeout)
    except BudgetExceeded:
        raise
    except Exception as exc:
        log.debug("graphql replay %s as %s failed: %s", url, who, exc)
        return None


def _grade_replay(base, resp, url: str, operation: str, full_path: str,
                  value: str, owner: str, tester_name: str,
                  tester_tenant: str, owner_tenant: str,
                  ownership_fields: Optional[List[str]],
                  matrix, endpoint, exclude: str
                  ) -> Optional[GraphqlReplayResult]:
    """Grade one owner-vs-tester pair with ownership comparison.

    Returns None only when the baseline is ungradable (no shape or
    hash); every completed comparison yields a result (match, void,
    or no-access notes) so callers record genuine negatives.
    """
    from ..validation.differential import (looks_like_edge_deny,
                                           normalize_response)
    from ..authz.compare import compare_access, is_generic_response
    from ..authorization.harvest import (extract_ids_from_body,
                                         extract_named_fields)
    from ..authorization.matrix import AuthorizationObservation
    from ..shell import redact
    try:
        baseline = normalize_response(base)
    except Exception:
        return None
    shape_sig = baseline.get("key_shape", "")
    body_hash = baseline.get("body_hash", "")
    if not shape_sig and not body_hash:
        return None
    try:
        markers = dict(extract_ids_from_body(base.text or ""))
        markers.update(extract_named_fields(
            base.text or "", ownership_fields or []))
    except Exception:
        markers = {}
    try:
        owner_generic, _ = is_generic_response(base.text or "")
    except Exception:
        owner_generic = False
    try:
        norm = normalize_response(resp)
    except Exception:
        return None
    match = norm.get("status") == 200 and (
        (norm.get("body_hash") and
         norm["body_hash"] == body_hash) or
        (norm.get("key_shape") and norm["key_shape"] == shape_sig))
    comparison = {"level": "medium", "matched": [],
                  "detail": "shape match stands alone"}
    tester_snippet = ""
    try:
        tester_edge = looks_like_edge_deny(
            norm.get("status", 0), resp.text or "",
            getattr(resp, "headers", None))
    except Exception:
        tester_edge = False
    if match:
        if tester_edge:
            match = False
            comparison = {"level": "none", "matched": [],
                          "detail": "tester hit edge/bot-wall "
                                    "infrastructure, not the app"}
        else:
            comparison = compare_access(
                markers, resp.text or "", ownership_fields,
                exclude=exclude, owner_generic=owner_generic)
            try:
                tester_snippet = redact((resp.text or "")[:500])
            except Exception:
                tester_snippet = ""
            if comparison["level"] == "none":
                match = False
    res = GraphqlReplayResult(
        endpoint_url=url, operation=operation,
        variable=full_path, victim_value=value, owner=owner,
        tester=tester_name, owner_tenant=owner_tenant,
        tester_tenant=tester_tenant,
        status=norm.get("status", 0), match=bool(match),
        markers_matched=comparison.get("matched", []),
        generic_response=comparison["level"] == "none" and
        "generic" in comparison.get("detail", ""),
        edge_denied=bool(tester_edge))
    try:
        res.owner_snippet = redact((base.text or "")[:500])
    except Exception:
        res.owner_snippet = ""
    res.tester_snippet = tester_snippet
    if match:
        if tester_tenant and owner_tenant and \
                tester_tenant != owner_tenant:
            res.verdict = "strong_candidate"
            res.notes = (f"cross-tenant GraphQL read: "
                         f"'{tester_name}' (tenant {tester_tenant}) "
                         f"reads '{value}' via {operation}."
                         f"{full_path} owned by '{owner}' "
                         f"(tenant {owner_tenant}). "
                         f"{comparison['detail']}")
        else:
            res.verdict = "strong_candidate"
            res.notes = (f"GraphQL BOLA: '{tester_name}' reads "
                         f"'{owner}''s '{full_path}={value}' via "
                         f"operation '{operation}'. "
                         f"{comparison['detail']}")
    elif comparison["level"] == "none" and \
            norm.get("status") == 200:
        res.notes = ("shape matched but voided: "
                     f"{comparison['detail']}")
    else:
        res.notes = (f"no cross-access ({tester_name}→"
                     f"{norm.get('status')})")
    if matrix is not None:
        try:
            matrix.record(AuthorizationObservation(
                identity=tester_name, tenant=tester_tenant,
                endpoint=getattr(endpoint, "normalized_url", url),
                resource=value, method="POST",
                status=norm.get("status", 0),
                shape=norm.get("key_shape", ""),
                body_hash=norm.get("body_hash", ""),
                length_bucket=norm.get("length_bucket", 0),
                evidence=res.notes))
        except Exception as exc:
            log.debug("graphql matrix record failed: %s", exc)
    return res


def _shape_text(shape: Dict[str, Any]) -> str:
    body = shape.get("post_data")
    if isinstance(body, (bytes, bytearray)):
        try:
            return bytes(body).decode("utf-8")
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError("GraphQL body is not UTF-8 text") from exc
    if isinstance(body, str):
        return body
    raise ValueError("GraphQL body shape is unrepresentable")


def _replay_headers(shape: Dict[str, Any],
                    identity_headers: Optional[Dict[str, str]]
                    ) -> Dict[str, str]:
    """Shape headers with hop-by-hop entries dropped and the acting
    identity's headers winning."""
    headers: Dict[str, str] = {}
    raw = shape.get("headers")
    if isinstance(raw, dict):
        for name, value in raw.items():
            if not isinstance(name, str) or not isinstance(value, str):
                continue
            if not name.strip() or name.strip().lower() in {
                    "host", "content-length", "connection",
                    "transfer-encoding"}:
                continue
            headers[name.strip()] = value.strip()
    for name, value in (identity_headers or {}).items():
        if isinstance(name, str) and isinstance(value, str) \
                and name.strip():
            headers[name.strip()] = value.strip()
    if not any(key.lower() == "content-type" for key in headers):
        headers["Content-Type"] = "application/json"
    return headers


def replay_schema_fields(http, endpoint: Any, schema_fields: list,
                         victims: List[Any], tester: Any,
                         owner_headers: Dict[str, Dict[str, str]],
                         timeout: int = 10, max_ids: int = 3,
                         scope=None, matrix=None,
                         ownership_fields: Optional[List[str]] = None
                         ) -> List[GraphqlReplayResult]:
    """Replay schema-generated field documents with victim IDs.

    Same verdict contract as operation replay (graded matches become
    strong_candidate, completed denials are genuine negatives), but
    the documents come from the advertised schema instead of observed
    traffic: one identifier argument moves per document, nothing else.
    Mutations are never generated upstream, so none can replay here.
    """
    import json as _json
    from ..validation.graphql_schema import build_field_query
    out: List[GraphqlReplayResult] = []
    tester_name = getattr(tester, "name", "anonymous")
    tester_tenant = getattr(tester, "tenant", "") or ""
    tester_headers = dict(getattr(tester, "auth_headers", None) or {})
    url = str(getattr(endpoint, "url", "") or "")
    if not url:
        return out
    if scope is not None:
        try:
            if not scope.active_test_allowed(url):
                return out
        except Exception:
            return out
    tried = 0
    seen = set()
    for victim in victims or []:
        if tried >= max_ids:
            break
        owner = getattr(victim, "owner", "")
        if not owner or owner == tester_name:
            continue
        leaf = str(getattr(victim, "param", "") or "").split(".")[-1]
        value = getattr(victim, "value", "")
        if not leaf or not value:
            continue
        owner_tenant = getattr(victim, "owner_tenant", "") or ""
        for schema_field in schema_fields or []:
            if tried >= max_ids:
                break
            arg = str(getattr(schema_field, "arg", "") or "")
            if not arg or arg.lower() != leaf.lower():
                continue
            field_name = str(getattr(schema_field, "field", "") or "")
            key = (field_name, arg, value, owner)
            if key in seen:
                continue
            seen.add(key)
            document, label = build_field_query(schema_field, value)
            body = _json.dumps({"query": document})
            tried += 1
            # owner baseline on the SAME generated document first
            try:
                base = http.request(
                    "POST", url,
                    headers=_replay_headers(
                        {}, (owner_headers or {}).get(owner)),
                    data=body, timeout=timeout)
            except BudgetExceeded:
                raise
            except Exception as exc:
                log.debug("graphql schema baseline %s as %s failed: %s",
                          url, owner, exc)
                continue
            if base.status_code != 200:
                continue
            resp = _fetch_replay(
                http, url, _replay_headers({}, tester_headers),
                body, timeout, tester_name)
            if resp is None:
                continue
            res = _grade_replay(
                base, resp, url=url, operation=f"schema:{field_name}",
                full_path=f"{field_name}({arg})", value=value,
                owner=owner, tester_name=tester_name,
                tester_tenant=tester_tenant, owner_tenant=owner_tenant,
                ownership_fields=ownership_fields, matrix=matrix,
                endpoint=endpoint, exclude=arg)
            if res is None:
                continue
            out.append(res)
    return out
