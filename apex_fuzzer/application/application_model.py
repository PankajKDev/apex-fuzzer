"""Application-level model (§4).

Built *incrementally*: the orchestrator starts from recon endpoints +
fingerprinted technologies + configured auth contexts, then appends
resources and (later phases) workflows, sessions and findings. Never
requires perfect knowledge before testing begins.
"""
from typing import Any, Dict, List, Optional
from ..models import Identity, Role, Tenant, Resource
from .workflows import Workflow
from .identities import from_auth_contexts
from .resources import extract_resources


class Application:
    def __init__(self, id: str, name: str,
                 root_domains: Optional[List[str]] = None):
        self.id = id
        self.name = name
        self.root_domains = root_domains or []
        self.hosts: List[str] = []
        self.technologies: List[Dict[str, Any]] = []
        self.endpoints: List[Dict[str, Any]] = []
        self.identities: List[Identity] = []
        self.roles: List[Role] = []
        self.tenants: List[Tenant] = []
        self.resources: List[Resource] = []
        self.workflows: List[Workflow] = []
        self.sessions: List[Dict[str, Any]] = []
        self.findings: List[Dict[str, Any]] = []

    # ── incremental construction ─────────────────────────────────────
    def add_host(self, host: str):
        if host and host not in self.hosts:
            self.hosts.append(host)

    def add_technology(self, tech: Dict[str, Any]):
        name = tech.get("name", "")
        if name and not any(t.get("name") == name
                            for t in self.technologies):
            self.technologies.append(tech)

    def add_endpoint(self, endpoint_dict: Dict[str, Any]):
        norm = endpoint_dict.get("normalized_url", "")
        for e in self.endpoints:
            if e.get("normalized_url") == norm:
                return
        self.endpoints.append(endpoint_dict)
        host = endpoint_dict.get("host", "")
        if host:
            self.add_host(host)

    def ingest_endpoints(self, endpoint_dicts: List[Dict[str, Any]]):
        for e in endpoint_dicts:
            self.add_endpoint(e)

    def ingest_identities(self, auth_contexts) -> None:
        identities, roles, tenants = from_auth_contexts(auth_contexts)
        seen_i = {i.name for i in self.identities}
        for i in identities:
            if i.name not in seen_i:
                self.identities.append(i)
                seen_i.add(i.name)
        seen_r = {r.name for r in self.roles}
        for r in roles:
            if r.name not in seen_r:
                self.roles.append(r)
                seen_r.add(r.name)
        seen_t = {t.name for t in self.tenants}
        for t in tenants:
            if t.name not in seen_t:
                self.tenants.append(t)
                seen_t.add(t.name)

    def ingest_resources(self, resources: List[Resource]):
        seen = {r.key for r in self.resources}
        for r in resources:
            if r.key not in seen:
                self.resources.append(r)
                seen.add(r.key)

    # ── persistence ──────────────────────────────────────────────────
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "name": self.name,
            "root_domains": self.root_domains,
            "hosts": self.hosts,
            "technologies": self.technologies,
            "endpoints": self.endpoints,
            "identities": [i.to_dict() for i in self.identities],
            "roles": [r.to_dict() for r in self.roles],
            "tenants": [t.to_dict() for t in self.tenants],
            "resources": [r.to_dict() for r in self.resources],
            "workflows": [w.to_dict() for w in self.workflows],
            "sessions": self.sessions,
            "findings": self.findings,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Application":
        app = cls(id=d.get("id", ""), name=d.get("name", ""),
                  root_domains=d.get("root_domains") or [])
        app.hosts = list(d.get("hosts") or [])
        app.technologies = list(d.get("technologies") or [])
        app.endpoints = list(d.get("endpoints") or [])
        app.identities = [Identity.from_dict(i)
                          for i in (d.get("identities") or [])]
        app.roles = [Role.from_dict(r) for r in (d.get("roles") or [])]
        app.tenants = [Tenant.from_dict(t)
                       for t in (d.get("tenants") or [])]
        app.resources = [Resource.from_dict(r)
                         for r in (d.get("resources") or [])]
        app.workflows = [Workflow.from_dict(w)
                         for w in (d.get("workflows") or [])]
        app.sessions = list(d.get("sessions") or [])
        app.findings = list(d.get("findings") or [])
        return app


def build_from_scan(host: str, endpoints, technologies: List[Dict],
                    auth_contexts) -> Application:
    """Assemble the Phase 1 application snapshot after mapping."""
    app = Application(id=f"app-{host}", name=host, root_domains=[host])
    app.ingest_endpoints([e.to_dict() if hasattr(e, "to_dict") else e
                          for e in endpoints])
    for t in technologies:
        app.add_technology(t if isinstance(t, dict) else t.to_dict()
                           if hasattr(t, "to_dict") else {"name": str(t)})
    app.ingest_identities(auth_contexts)
    app.ingest_resources(extract_resources(endpoints))
    return app
