"""Identity/role/permission registry (agent Phase 2).

Reuses the Identity/Role/Tenant models from models.py — this module
adds the Permission model and the explicit relationship queries the
authorization matrix consumes (identity → roles → permissions,
tenant scoping). No duplicate identity types.
"""
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from ..models import Identity, Role, Tenant


@dataclass
class Permission:
    """One named capability, optionally scoped to a tenant."""
    name: str
    tenant: Optional[str] = None
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "tenant": self.tenant,
                "description": self.description}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Permission":
        return cls(name=d.get("name", ""), tenant=d.get("tenant"),
                   description=d.get("description", ""))


class IdentityRegistry:
    """Explicit identity → roles → permissions graph for one scan."""

    def __init__(self):
        self.identities: Dict[str, Identity] = {}
        self.roles: Dict[str, Role] = {}
        self.tenants: Dict[str, Tenant] = {}

    def add_identity(self, identity: Identity):
        self.identities[identity.name] = identity
        for r in identity.roles:
            if r not in self.roles:
                self.roles[r] = Role(name=r)
        if identity.tenant and identity.tenant not in self.tenants:
            self.tenants[identity.tenant] = Tenant(name=identity.tenant)

    def add_role(self, role: Role):
        cur = self.roles.get(role.name)
        if cur is None:
            self.roles[role.name] = role
        else:
            for p in role.permissions:
                if p not in cur.permissions:
                    cur.permissions.append(p)

    def roles_for(self, identity_name: str) -> List[str]:
        ident = self.identities.get(identity_name)
        return list(ident.roles) if ident else []

    def permissions_for(self, identity_name: str) -> List[str]:
        out: List[str] = []
        for r in self.roles_for(identity_name):
            role = self.roles.get(r)
            if role:
                for p in role.permissions:
                    if p not in out:
                        out.append(p)
        return out

    def identity_has_permission(self, identity_name: str,
                                permission: str) -> bool:
        return permission in self.permissions_for(identity_name)

    def same_tenant(self, a: str, b: str) -> bool:
        ia, ib = self.identities.get(a), self.identities.get(b)
        if ia is None or ib is None:
            return False
        return bool(ia.tenant) and ia.tenant == ib.tenant

    def to_dict(self) -> Dict[str, Any]:
        return {"identities": [i.to_dict() for i in
                               self.identities.values()],
                "roles": [r.to_dict() for r in self.roles.values()],
                "tenants": [t.to_dict() for t in self.tenants.values()]}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "IdentityRegistry":
        reg = cls()
        for r in d.get("roles") or []:
            reg.roles[r.get("name", "")] = Role.from_dict(r)
        for t in d.get("tenants") or []:
            reg.tenants[t.get("name", "")] = Tenant.from_dict(t)
        for i in d.get("identities") or []:
            reg.identities[i.get("name", "")] = Identity.from_dict(i)
        return reg


def build_registry(auth_contexts, extra_roles=None) -> IdentityRegistry:
    """Registry from configured contexts (+ optional Role definitions)."""
    from ..application.identities import from_auth_contexts
    identities, roles, tenants = from_auth_contexts(auth_contexts)
    reg = IdentityRegistry()
    for t in tenants:
        reg.tenants[t.name] = t
    for r in list(roles) + list(extra_roles or []):
        reg.add_role(r)
    for i in identities:
        reg.add_identity(i)
    return reg
