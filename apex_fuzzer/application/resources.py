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
from typing import List
from ..models import Resource

# identifier-like parameter names (superset of the differential probe set:
# graph modeling is broader than probe targeting)
IDENTIFIER_NAMES = {
    "id", "uuid", "guid", "uid", "user_id", "userid",
    "account_id", "accountid", "organization_id", "org_id",
    "tenant_id", "tenantid", "workspace_id", "project_id",
    "order_id", "invoice_id", "document_id", "doc_id", "file_id",
    "customer_id", "card_id", "transaction_id", "txn_id",
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
