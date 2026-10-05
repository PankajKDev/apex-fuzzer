"""Cross-user object-ID harvesting (bounty item #1).

Crawls as each configured identity, parses JSON responses for
identifier-like keys, and records (endpoint, param, value, owner)
tuples. The swap tester then replays each victim object as a different
identity — the highest-probability BOLA/tenant-isolation loop in
bug-bounty work. No browser needed: pure HTTP + response parsing.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List
from ..application.resources import IDENTIFIER_NAMES
from ..logging_setup import get_logger

log = get_logger("harvest")


@dataclass
class HarvestedId:
    endpoint_url: str
    normalized_url: str
    param: str
    value: str
    owner: str
    owner_tenant: str = ""
    shape: str = ""
    body_hash: str = ""
    source: str = "response"
    # all identifiers in the owner's response (ownership evidence)
    markers: Dict[str, str] = field(default_factory=dict)
    # redacted snippet of the owner's response (evidence, no secrets)
    snippet: str = ""
    # GraphQL __typename when the response is a GraphQL payload
    resource_type_hint: str = ""
    owner_generic: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {"endpoint_url": self.endpoint_url,
                "normalized_url": self.normalized_url,
                "param": self.param, "value": self.value,
                "owner": self.owner, "owner_tenant": self.owner_tenant,
                "shape": self.shape, "body_hash": self.body_hash,
                "source": self.source, "markers": dict(self.markers),
                "snippet": self.snippet,
                "resource_type_hint": self.resource_type_hint,
                "owner_generic": self.owner_generic}


def _walk_json(value: Any, out: Dict[str, str], depth: int = 0):
    """Collect identifier-like keys with scalar values from JSON."""
    if depth > 4:
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if isinstance(k, str) and k.lower() in IDENTIFIER_NAMES and \
                    isinstance(v, (str, int)) and str(v):
                out.setdefault(k, str(v))
            else:
                _walk_json(v, out, depth + 1)
    elif isinstance(value, list):
        for item in value[:20]:
            _walk_json(item, out, depth + 1)


def extract_ids_from_body(body: str) -> Dict[str, str]:
    """Parse a response body for identifier values. Never raises."""
    import json as _json
    try:
        data = _json.loads(body or "")
    except (ValueError, TypeError):
        return {}
    out: Dict[str, str] = {}
    _walk_json(data, out)
    return out


def extract_named_fields(body: str, names: List[str]) -> Dict[str, str]:
    """Extract configured ownership fields from JSON at any nesting depth."""
    import json as _json
    wanted = {str(name).lower() for name in (names or []) if name}
    if not wanted:
        return {}
    try:
        data = _json.loads(body or "")
    except (ValueError, TypeError):
        return {}
    out: Dict[str, str] = {}

    def walk(value, depth=0):
        if depth > 8:
            return
        if isinstance(value, dict):
            for key, item in value.items():
                if (str(key).lower() in wanted and
                        isinstance(item, (str, int, float)) and
                        not isinstance(item, bool)):
                    out.setdefault(str(key), str(item))
                else:
                    walk(item, depth + 1)
        elif isinstance(value, list):
            for item in value[:50]:
                walk(item, depth + 1)

    walk(data)
    return out


def harvest_ids(http, endpoint, identities, timeout: int = 10,
                max_ids_per_param: int = 3,
                ownership_fields: List[str] | None = None
                ) -> List[HarvestedId]:
    """GET ``endpoint`` as each identity; learn object IDs from JSON.

    ``identities`` are Identity objects (name/auth_headers/tenant).
    Returns harvest records including the owner's response shape for
    later swap comparison.
    """
    from ..validation.differential import normalize_response
    out: List[HarvestedId] = []
    seen = set()
    for ident in identities or []:
        name = getattr(ident, "name", "anonymous")
        headers = dict(getattr(ident, "auth_headers", None) or {})
        tenant = getattr(ident, "tenant", "") or ""
        try:
            r = http.get(endpoint.url, headers=headers, timeout=timeout)
        except Exception as e:
            log.debug("harvest %s as %s failed: %s",
                      endpoint.url, name, e)
            continue
        if r.status_code != 200:
            continue
        try:
            norm = normalize_response(r)
        except Exception:
            continue
        from ..application.resources import discover_ids_from_graphql
        try:
            import json as _json2
            _, typename = discover_ids_from_graphql(
                _json2.loads(r.text or "{}"))
        except Exception:
            typename = ""
        ids = extract_ids_from_body(r.text or "")
        body_markers = dict(ids)
        body_markers.update(extract_named_fields(
            r.text or "", ownership_fields or []))
        from ..authz.compare import is_generic_response
        owner_generic, _ = is_generic_response(r.text or "")
        for param, value in ids.items():
            key = (endpoint.normalized_url, param, value, name)
            if key in seen:
                continue
            seen.add(key)
            if sum(1 for h in out
                   if h.normalized_url == endpoint.normalized_url
                   and h.param == param and h.owner == name) \
                    >= max_ids_per_param:
                continue
            from ..shell import redact
            out.append(HarvestedId(
                endpoint_url=endpoint.url,
                normalized_url=endpoint.normalized_url,
                param=param, value=value, owner=name,
                owner_tenant=tenant, shape=norm.get("key_shape", ""),
                body_hash=norm.get("body_hash", ""),
                markers=dict(body_markers),
                snippet=redact((r.text or "")[:500]),
                resource_type_hint=typename,
                owner_generic=owner_generic))
    if out:
        log.info("harvest: %d ids from %s", len(out), endpoint.url)
    return out
