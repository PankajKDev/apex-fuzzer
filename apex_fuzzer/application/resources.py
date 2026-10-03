"""Resource discovery for the application graph (§13, Phase 1 slice).

Phase 1 builds Resource records from identifier-like *parameters* on
known endpoints (query + body). Learning IDs from response bodies,
JS, GraphQL and browser traffic arrives with Phase 3 — the model and
the graph edges are deliberately stable already so those producers
only append.

The probe-targeting set in ``validation.differential`` is intentionally
separate: it decides *where to send requests*, this module decides
*what the application contains*.
"""
import re
from typing import Dict, List, Tuple
from ..models import Resource

# identifier-like parameter names (superset of the differential probe set:
# graph modeling is broader than probe targeting)
IDENTIFIER_NAMES = {
    "id", "uuid", "guid", "uid", "user_id", "userid",
    "account_id", "accountid", "organization_id", "org_id",
    "tenant_id", "tenantid", "workspace_id", "project_id",
    "order_id", "invoice_id", "document_id", "doc_id", "file_id",
    "customer_id", "card_id", "transaction_id", "txn_id",
    "owner_id", "owner", "created_by", "creator_id", "member_id",
    "email", "username", "slug", "ref", "ref_id",
}

_TENANT_HINT = re.compile(r"tenant|org|workspace|account", re.I)
_OWNER_HINT = re.compile(r"^(user|owner|member|creator)_?id$", re.I)


def _guess_type(param_name: str, endpoint_type: str) -> str:
    n = param_name.lower()
    if n in ("email", "username", "user_id", "userid", "uid"):
        return "user"
    if "tenant" in n or "org" in n or "workspace" in n or "account" in n:
        return "tenant"
    if "project" in n:
        return "project"
    if "order" in n or "invoice" in n or "transaction" in n or "txn" in n:
        return "order"
    if "file" in n or "document" in n or "doc" in n:
        return "document"
    return "object"


def extract_resources(endpoints) -> List[Resource]:
    """One Resource per identifier-like parameter occurrence."""
    out: List[Resource] = []
    seen = set()
    for ep in endpoints or []:
        params = list(getattr(ep, "query_parameters", []) or []) + \
            list(getattr(ep, "body_parameters", []) or [])
        for p in params:
            name = (p.name or "")
            if name.lower() not in IDENTIFIER_NAMES:
                continue
            key = f"{ep.normalized_url}::{p.location}:{name}"
            if key in seen:
                continue
            seen.add(key)
            tenant = None
            if _TENANT_HINT.search(name):
                tenant = name
            owner = None
            if _OWNER_HINT.match(name):
                owner = name
            out.append(Resource(
                key=key,
                resource_type=_guess_type(
                    name, getattr(ep, "endpoint_type", "")),
                identifiers={name: p.sample_value or ""},
                owner=owner,
                tenant=tenant,
                exposed_by=[ep.normalized_url],
                discovered_from=["parameters"]))
    return out


# ── Phase 5: multi-source ID discovery ────────────────────────────────
# Each returns {identifier_name: value}. Values follow the same
# meaningfulness rule as dependencies (short/generic ⇒ noise).

_HIDDEN_INPUT_RE = re.compile(
    r'<input\b[^>]*?\bname\s*=\s*["\']([^"\']+)["\'][^>]*?'
    r"\bvalue\s*=\s*[\"']([^\"']{2,120})[\"']", re.I)
_DATA_ATTR_RE = re.compile(
    r"\bdata-([a-zA-Z_][\w-]*)\s*=\s*[\"']([^\"']{2,120})[\"']", re.I)
_HREF_ID_RE = re.compile(
    r'href\s*=\s*["\']([^"\']+)["\']', re.I)
# a path segment counts as an ID when it is not a plain dictionary
# word: it contains a digit or a separator (ord_5522, u-4242, UUIDs)
_ID_SEG_RE = re.compile(r"^(?=.*[\d_\-])[A-Za-z0-9_\-]{4,64}$")
_JS_KV_RE = re.compile(
    r'["\']([A-Za-z_][\w]*)["\']\s*:\s*["\']([^"\']{2,120})["\']')
_JS_URL_RE = re.compile(
    r"['\"](/[A-Za-z0-9_\-/{}.:]+(?:\?[A-Za-z0-9_\-=&%.]+)?)['\"]")


def _is_identifier_name(name: str) -> bool:
    return (name or "").lower().replace("-", "_") in IDENTIFIER_NAMES


def _is_meaningful_value(value: str) -> bool:
    v = (value or "").strip()
    if len(v) < 4:
        return False
    return v.lower() not in {"true", "false", "null", "undefined",
                             "none", "nil", "yes", "no", "on", "off"}


def discover_ids_from_html(html: str) -> Dict[str, str]:
    """Hidden inputs, data-* attributes and /path/ID hrefs carrying
    identifier-like names."""
    out: Dict[str, str] = {}
    text = html or ""
    for m in _HIDDEN_INPUT_RE.finditer(text):
        if _is_identifier_name(m.group(1)) and \
                _is_meaningful_value(m.group(2)):
            out.setdefault(m.group(1), m.group(2))
    for m in _DATA_ATTR_RE.finditer(text):
        name = m.group(1).replace("-", "_")
        if _is_identifier_name(name) and \
                _is_meaningful_value(m.group(2)):
            out.setdefault(name, m.group(2))
    for m in _HREF_ID_RE.finditer(text):
        for seg in m.group(1).split("?")[0].split("/"):
            if _ID_SEG_RE.match(seg or ""):
                out.setdefault("path_id", seg)
                break
    return out


def discover_ids_from_headers(headers) -> Dict[str, str]:
    """Identifier-named headers (X-User-Id, …) plus IDs in Location."""
    out: Dict[str, str] = {}
    hdrs = headers or {}
    items = hdrs.items() if hasattr(hdrs, "items") else []
    for k, v in items:
        name = str(k or "").lower().replace("-", "_")
        name = re.sub(r"^x_", "", name)
        if _is_identifier_name(name) and \
                _is_meaningful_value(str(v or "")):
            out.setdefault(name, str(v))
    loc = ""
    try:
        loc = hdrs.get("location", "") or hdrs.get("Location", "")
    except Exception:
        loc = ""
    if loc:
        for m in _HREF_ID_RE.finditer(f'href="{loc}"'):
            for seg in m.group(1).split("?")[0].split("/"):
                if _ID_SEG_RE.match(seg or ""):
                    out.setdefault("path_id", seg)
                    break
    return out


def discover_ids_from_js(js_text: str) -> Dict[str, str]:
    """`"id": "value"` pairs and /path?query strings in JS bundles."""
    out: Dict[str, str] = {}
    text = js_text or ""
    for m in _JS_KV_RE.finditer(text):
        if _is_identifier_name(m.group(1)) and \
                _is_meaningful_value(m.group(2)):
            out.setdefault(m.group(1), m.group(2))
    from urllib.parse import urlsplit, parse_qsl
    for m in _JS_URL_RE.finditer(text):
        try:
            q = parse_qsl(urlsplit(m.group(1)).query,
                          keep_blank_values=True)
        except Exception:
            continue
        for k, v in q:
            if _is_identifier_name(k) and _is_meaningful_value(v):
                out.setdefault(k, v)
    return out


def discover_ids_from_graphql(data) -> Tuple[Dict[str, str], str]:
    """Walk a GraphQL `data` payload: identifiers + __typename."""
    ids: Dict[str, str] = {}
    typenames: List[str] = []

    def _walk(value, depth: int = 0):
        if depth > 5:
            return
        if isinstance(value, dict):
            for k, v in value.items():
                if k == "__typename" and isinstance(v, str) and v:
                    typenames.append(v)
                elif isinstance(k, str) and _is_identifier_name(k) \
                        and isinstance(v, (str, int)) \
                        and _is_meaningful_value(str(v)):
                    ids.setdefault(k, str(v))
                else:
                    _walk(v, depth + 1)
        elif isinstance(value, list):
            for item in value[:20]:
                _walk(item, depth + 1)

    _walk(data if isinstance(data, (dict, list)) else {})
    return ids, typenames[0] if typenames else ""


def discover_ids_from_traffic(requests) -> List[Tuple[str, str, str]]:
    """Identifier query values in recorded request URLs →
    (source_url, param, value) triples."""
    from urllib.parse import urlsplit, parse_qsl
    out: List[Tuple[str, str, str]] = []
    seen = set()
    for req in requests or []:
        url = req.get("url") if isinstance(req, dict) else \
            getattr(req, "url", "")
        if not url:
            continue
        try:
            q = parse_qsl(urlsplit(url).query, keep_blank_values=True)
        except Exception:
            continue
        for k, v in q:
            if _is_identifier_name(k) and _is_meaningful_value(v) \
                    and (url, k, v) not in seen:
                seen.add((url, k, v))
                out.append((url, k, v))
    return out
