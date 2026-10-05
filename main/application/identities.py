"""Identities, roles, tenants derived from auth contexts (§7, §11–12).

Header-based contexts keep working untouched; the extra fields
(identity/roles/tenant/storage_state) attach each context to the
application model so later engines (authz matrix, tenant isolation,
browser sessions) share one source of truth.
"""
from typing import List, Tuple
from ..models import Identity, Role, Tenant


def from_auth_contexts(contexts) -> Tuple[List[Identity], List[Role],
                                          List[Tenant]]:
    """Build model objects from configured AuthContext entries.

    The implicit ``anonymous`` context becomes an Identity with no
    roles and no headers. Roles are collected across identities;
    tenants likewise.
    """
    identities: List[Identity] = []
    roles: dict = {}
    tenants: dict = {}
    for ctx in contexts or []:
        name = getattr(ctx, "name", "anonymous")
        tenant = getattr(ctx, "tenant", "") or ""
        ctx_roles = list(getattr(ctx, "roles", None) or [])
        identities.append(Identity(
            name=name,
            roles=ctx_roles,
            tenant=tenant or None,
            auth_headers=dict(getattr(ctx, "headers", None) or {}),
            storage_state=getattr(ctx, "storage_state", None),
            notes=f"auth context '{name}'"))
        for r in ctx_roles:
            if r not in roles:
                roles[r] = Role(name=r, tenant=tenant or None)
        if tenant and tenant not in tenants:
            tenants[tenant] = Tenant(name=tenant)
    if not any(i.name == "anonymous" for i in identities):
        identities.insert(0, Identity(name="anonymous"))
    return identities, list(roles.values()), list(tenants.values())
