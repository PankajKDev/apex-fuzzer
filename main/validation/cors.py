"""Credentialed cross-origin policy checks on observed GET endpoints.

The check sends one unique, non-resolving Origin value with each configured
cookie-authenticated identity. A reflected origin is only a lead: Apex emits a
candidate when the server also permits credentials and returns a non-empty
successful response. Optional Chromium verification proves that the
configured cookie is sent and page JavaScript can read a successful response.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List
from urllib.parse import urlparse
import uuid

from ..models import (Confidence, Endpoint, Finding, ValidationStatus,
                      stable_finding_id)


def _header(headers: Dict[str, Any], name: str) -> str:
    return next((str(value).strip() for key, value in headers.items()
                 if str(key).lower() == name.lower()), "")


def _cookie_contexts(identities: Iterable[Any], max_identities: int):
    contexts = []
    for identity in identities:
        headers = dict(getattr(identity, "auth_headers", {}) or {})
        if any(key.lower() == "cookie" and value
               for key, value in headers.items()):
            contexts.append((identity, headers))
        if len(contexts) >= max_identities:
            break
    return contexts


def probe_cors(endpoints: Iterable[Endpoint], http: Any, evidence: Any,
               metrics: Any, coverage: Any, scope: Any,
               identities: Iterable[Any], max_endpoints: int = 10,
               max_identities: int = 3, timeout: int = 10
               ) -> List[Finding]:
    """Probe bounded observed GET endpoints under cookie auth contexts."""
    # Hard ceilings keep configuration from turning this into a crawler.
    max_endpoints = min(int(max_endpoints), 10)
    max_identities = min(int(max_identities), 3)
    if max_endpoints <= 0 or max_identities <= 0:
        coverage.record("cors", "untestable", "CORS probe caps are zero")
        return []

    contexts = _cookie_contexts(identities, max_identities)
    if not contexts:
        coverage.record(
            "cors", "untestable",
            "no configured cookie-authenticated identity; credentialed read impact not assessed")
        return []

    candidates: List[Endpoint] = []
    for endpoint in endpoints:
        if (endpoint.method.upper() == "GET"
                and scope.active_test_allowed(endpoint.url)):
            candidates.append(endpoint)
        if len(candidates) >= max_endpoints:
            break
    if not candidates:
        coverage.record("cors", "untestable",
                        "no in-scope GET endpoints available")
        return []

    findings: List[Finding] = []
    tested = 0
    errors = 0
    for endpoint in candidates:
        for identity, auth_headers in contexts:
            scheme = urlparse(endpoint.url).scheme.lower()
            marker_origin = (f"{scheme}://apex-{uuid.uuid4().hex}.invalid"
                             if scheme in {"http", "https"} else
                             f"https://apex-{uuid.uuid4().hex}.invalid")
            request_headers = {k: v for k, v in auth_headers.items()
                               if k.lower() != "origin"}
            request_headers["Origin"] = marker_origin
            try:
                response = http.get(endpoint.url, headers=request_headers,
                                    timeout=timeout)
                tested += 1
            except Exception:
                errors += 1
                continue

            response_headers = dict(response.headers or {})
            allow_origin = _header(response_headers,
                                   "Access-Control-Allow-Origin")
            allow_credentials = _header(
                response_headers, "Access-Control-Allow-Credentials")
            body = str(getattr(response, "text", "") or "")
            status = int(response.status_code)
            if (allow_origin != marker_origin
                    or allow_credentials.lower() != "true"
                    or status < 200 or status >= 300
                    or not body.strip()):
                continue

            relevant_headers = {
                name: _header(response_headers, name)
                for name in (
                    "Access-Control-Allow-Origin",
                    "Access-Control-Allow-Credentials",
                    "Access-Control-Allow-Headers",
                    "Access-Control-Allow-Methods",
                    "Access-Control-Expose-Headers",
                    "Vary")
                if _header(response_headers, name)
            }
            hostname = urlparse(endpoint.url).hostname or ""
            finding = Finding(
                id=stable_finding_id("cors", endpoint.normalized_url,
                                     identity.name),
                source="cors-validator",
                template_id="apex/cors/credentialed-origin-reflection",
                name="Potential credentialed cross-origin data read",
                severity="medium", confidence=Confidence.PROBABLE.value,
                validation_status=ValidationStatus.STRONG_CANDIDATE.value,
                host=hostname, matched_at=endpoint.url,
                endpoint_url=endpoint.url, parameter=None, method="GET",
                response_status=status,
                response_headers=relevant_headers,
                response_snippet=("Authenticated response body was non-empty; "
                                  "body omitted from evidence."),
                description=(
                    "A unique arbitrary Origin was reflected while credential "
                    "access was enabled on a non-empty authenticated response. "
                    "This is a candidate: browser cookie rules, especially "
                    "SameSite, and actual cross-origin readability need review."),
                tags=["cors", "credentialed-origin-reflection"],
                identity=str(identity.name),
                raw={"origin": marker_origin,
                     "allow_origin": allow_origin,
                     "allow_credentials": allow_credentials,
                     "body_length": len(body),
                     "response_headers": relevant_headers,
                     "identity": str(identity.name),
                     "response_body_recorded": False},
            )
            finding.reproduction = (
                "curl -i -H 'Origin: " + marker_origin + "' '"
                + endpoint.url + "'  # rerun with the authorized test session")
            evidence.record(
                finding,
                request_text=(f"GET {endpoint.url}\n"
                              f"Origin: {marker_origin}\n"
                              f"[identity: {identity.name}; credentials redacted]\n"),
                response_text=(f"HTTP {status}\n"
                               + "".join(f"{k}: {v}\n" for k, v in
                                         relevant_headers.items())
                               + f"[body omitted; {len(body)} characters]\n"),
                response_headers=relevant_headers)
            findings.append(finding)
            metrics.validation_candidates += 1

    if findings:
        coverage.record("cors", "candidate",
                        f"{len(findings)} credentialed arbitrary-origin candidate(s); browser impact needs review")
    elif tested and errors == 0:
        coverage.record("cors", "tested_negative",
                        f"tested {tested} authenticated endpoint/identity pair(s); no credentialed arbitrary-origin read signal")
    elif tested or errors:
        coverage.record("cors", "inconclusive",
                        f"completed {tested} authenticated request(s); {errors} request error(s)")
    return findings
