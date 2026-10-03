"""Access tests: cross-user ID swap + per-method BFLA sweep.

- ``swap_ids`` replays each harvested victim object as a different
  identity and compares against the owner's baseline shape.
- ``sweep_methods`` requests each endpoint with every configured HTTP
  method as every identity (BFLA / function-level coverage the
  GET-only differential engine cannot see).

State-changing methods send minimal empty bodies; every request passes
scope + budget gates before firing. Findings are only ever
strong_candidate — swapping proves access, and the report shows the
paired responses for human confirmation.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
from .matrix import (AuthorizationMatrix, AuthorizationObservation)
from ..budgets import BudgetExceeded
from ..logging_setup import get_logger

log = get_logger("access")


@dataclass
class SwapResult:
    endpoint_url: str
    param: str
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

    def to_dict(self) -> Dict[str, Any]:
        return {"endpoint_url": self.endpoint_url, "param": self.param,
                "victim_value": self.victim_value, "owner": self.owner,
                "owner_tenant": self.owner_tenant, "tester": self.tester,
                "tester_tenant": self.tester_tenant, "status": self.status,
                "match": self.match, "verdict": self.verdict,
                "notes": self.notes,
                "markers_matched": list(self.markers_matched),
                "generic_response": self.generic_response,
                "owner_snippet": self.owner_snippet,
                "tester_snippet": self.tester_snippet}


def _with_param(url: str, name: str, value: str) -> str:
    parts = urlsplit(url)
    q = parse_qsl(parts.query, keep_blank_values=True)
    q.append((name, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path,
                       urlencode(q, doseq=True), ""))


def swap_ids(http, harvested, tester, timeout: int = 10,
             matrix: AuthorizationMatrix | None = None,
             owner_headers: Dict[str, Dict[str, str]] | None = None,
             ownership_fields: List[str] | None = None
             ) -> List[SwapResult]:
    """Replay victim IDs as ``tester`` (an Identity). ``harvested`` are
    HarvestedId records owned by *other* identities.

    Same-endpoint records carry the owner's baseline shape. Records
    with an empty baseline (cross-endpoint candidates) trigger a
    baseline fetch as the owner first — via ``owner_headers`` — so the
    comparison stays owner-vs-tester on the *target* endpoint.

    A shape match is then graded by ownership comparison
    (authz/compare.py): generic tester bodies and contradictory
    markers void the match instead of becoming findings.
    """
    from ..validation.differential import normalize_response
    from ..authz.compare import compare_access
    from ..shell import redact
    out: List[SwapResult] = []
    tester_name = getattr(tester, "name", "anonymous")
    tester_tenant = getattr(tester, "tenant", "") or ""
    headers = dict(getattr(tester, "auth_headers", None) or {})
    for h in harvested or []:
        if h.owner == tester_name:
            continue
        shape, body_hash = h.shape or "", h.body_hash or ""
        markers = dict(getattr(h, "markers", None) or {})
        if (not shape or not body_hash) and owner_headers is not None \
                and h.owner in (owner_headers or {}):
            try:
                b = http.get(_with_param(h.endpoint_url, h.param,
                                         h.value),
                             headers=owner_headers[h.owner],
                             timeout=timeout)
            except BudgetExceeded:
                raise
            except Exception as e:
                log.debug("swap baseline %s as %s failed: %s",
                          h.endpoint_url, h.owner, e)
                continue
            if b.status_code != 200:
                continue
            try:
                bn = normalize_response(b)
            except Exception:
                continue
            shape = bn.get("key_shape", "")
            body_hash = bn.get("body_hash", "")
            if not shape and not body_hash:
                continue
            # baseline response belongs to the TARGET endpoint:
            # extract its markers (never reuse another endpoint's)
            from ..authorization.harvest import extract_ids_from_body
            try:
                markers = dict(extract_ids_from_body(b.text or ""))
            except Exception:
                pass
        url = _with_param(h.endpoint_url, h.param, h.value)
        try:
            r = http.get(url, headers=headers, timeout=timeout)
        except BudgetExceeded:
            raise
        except Exception as e:
            log.debug("swap %s as %s failed: %s", url, tester_name, e)
            continue
        try:
            norm = normalize_response(r)
        except Exception:
            continue
        match = norm.get("status") == 200 and (
            (norm.get("body_hash") and
             norm["body_hash"] == body_hash) or
            (norm.get("key_shape") and norm["key_shape"] == shape))
        # M2.5: grade the shape match before it can become a verdict
        comparison = {"level": "medium", "matched": [],
                      "detail": "shape match stands alone"}
        tester_snippet = ""
        if match:
            comparison = compare_access(
                markers, r.text or "",
                ownership_fields, exclude=h.param)
            try:
                tester_snippet = redact((r.text or "")[:500])
            except Exception:
                tester_snippet = ""
            if comparison["level"] == "none":
                match = False
        res = SwapResult(
            endpoint_url=url, param=h.param, victim_value=h.value,
            owner=h.owner, owner_tenant=h.owner_tenant,
            tester=tester_name, tester_tenant=tester_tenant,
            status=norm.get("status", 0), match=bool(match),
            markers_matched=comparison.get("matched", []),
            generic_response=comparison["level"] == "none" and
            "generic" in comparison.get("detail", ""),
            owner_snippet=getattr(h, "snippet", "") or "",
            tester_snippet=tester_snippet)
        if match:
            if tester_tenant and h.owner_tenant and \
                    tester_tenant != h.owner_tenant:
                res.verdict = "strong_candidate"
                res.notes = (f"cross-tenant read: '{tester_name}' "
                             f"(tenant {tester_tenant}) reads object "
                             f"'{h.value}' owned by '{h.owner}' "
                             f"(tenant {h.owner_tenant}). "
                             f"{comparison['detail']}")
            else:
                res.verdict = "strong_candidate"
                res.notes = (f"BOLA: '{tester_name}' reads object "
                             f"'{h.value}' owned by '{h.owner}' via "
                             f"parameter '{h.param}'. "
                             f"{comparison['detail']}")
        elif comparison["level"] == "none" and norm.get("status") == 200:
            res.notes = (f"shape matched but voided: "
                         f"{comparison['detail']}")
        else:
            res.notes = (f"no cross-access ({tester_name}→"
                         f"{norm.get('status')})")
        if matrix is not None:
            matrix.record(AuthorizationObservation(
                identity=tester_name, tenant=tester_tenant,
                endpoint=h.normalized_url, resource=h.value,
                method="GET", status=norm.get("status", 0),
                shape=norm.get("key_shape", ""),
                body_hash=norm.get("body_hash", ""),
                length_bucket=norm.get("length_bucket", 0),
                evidence=res.notes))
        out.append(res)
    return out


def sweep_methods(http, endpoint, identities, methods: List[str],
                  timeout: int = 10,
                  matrix: AuthorizationMatrix | None = None
                  ) -> List[AuthorizationObservation]:
    """Request one endpoint with each method as each identity."""
    from ..validation.differential import normalize_response
    out: List[AuthorizationObservation] = []
    for ident in identities or []:
        name = getattr(ident, "name", "anonymous")
        headers = dict(getattr(ident, "auth_headers", None) or {})
        tenant = getattr(ident, "tenant", "") or ""
        roles = ",".join(getattr(ident, "roles", None) or [])
        for method in methods:
            try:
                if method == "GET":
                    r = http.get(endpoint.url, headers=headers,
                                 timeout=timeout)
                else:
                    r = http.request(method, endpoint.url,
                                     headers=headers, timeout=timeout)
            except BudgetExceeded:
                raise
            except Exception as e:
                log.debug("bfla %s %s as %s failed: %s",
                          method, endpoint.url, name, e)
                continue
            try:
                norm = normalize_response(r)
            except Exception:
                continue
            obs = AuthorizationObservation(
                identity=name, role=roles, tenant=tenant,
                endpoint=endpoint.normalized_url, method=method,
                status=norm.get("status", 0),
                shape=norm.get("key_shape", ""),
                body_hash=norm.get("body_hash", ""),
                length_bucket=norm.get("length_bucket", 0))
            out.append(obs)
            if matrix is not None:
                matrix.record(obs)
    return out
