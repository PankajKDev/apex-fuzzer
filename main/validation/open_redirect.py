"""Bounded open-redirect verification using observed query parameters.

Probes are GET-only, replace one observed parameter at a time, use a reserved
``.invalid`` hostname, and never follow redirects. A finding is confirmed
only when a 3xx response sends the unique marker hostname in Location.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Tuple
from urllib.parse import (parse_qsl, urlencode, urljoin, urlparse,
                          urlunparse)
import uuid

from ..models import (Confidence, Endpoint, Finding, ValidationStatus,
                      stable_finding_id)


_REDIRECT_NAMES = {
    "back", "callback", "callback_uri", "callback_url", "continue",
    "continueurl", "dest", "destination", "forward", "goto", "next",
    "out", "redirect", "redirect_to", "redirect_uri", "redirect_url",
    "redirectto", "return", "return_to", "return_url", "returnto",
    "returnurl", "target", "to", "url",
}


def _query_parameters(endpoint: Endpoint) -> List[str]:
    """Return observed redirect-like query names that are actually present."""
    try:
        parsed = urlparse(endpoint.url)
        present = {name for name, _ in parse_qsl(
            parsed.query, keep_blank_values=True)}
    except (TypeError, ValueError):
        return []
    observed = {p.name for p in endpoint.query_parameters
                if p.location.lower() in ("query", "url")}
    return sorted(name for name in present & observed
                  if name.lower() in _REDIRECT_NAMES)


def _replace_query_value(url: str, parameter: str, value: str) -> str:
    parsed = urlparse(url)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    replaced = False
    output: List[Tuple[str, str]] = []
    for name, old_value in query:
        if name == parameter and not replaced:
            output.append((name, value))
            replaced = True
        else:
            output.append((name, old_value))
    if not replaced:
        raise ValueError("parameter is not present in endpoint URL")
    return urlunparse(parsed._replace(query=urlencode(output)))


def _is_external_marker(status: int, location: str, marker_host: str,
                        target_url: str) -> bool:
    if status not in (301, 302, 303, 307, 308) or not location:
        return False
    target = urlparse(target_url)
    # Resolve network-path references (//host/path) against the target so
    # browser-effective redirects are handled consistently.
    redirect = urlparse(urljoin(target_url, location))
    if redirect.scheme.lower() not in ("http", "https"):
        return False
    if (redirect.hostname or "").lower() != marker_host.lower():
        return False
    return (redirect.hostname or "").lower() != (target.hostname or "").lower()


def probe_open_redirects(endpoints: Iterable[Endpoint], http: Any,
                         evidence: Any, metrics: Any, coverage: Any,
                         scope: Any, max_endpoints: int = 10,
                         max_params: int = 3,
                         timeout: int = 10) -> List[Finding]:
    """Test capped, observed GET redirect fields and record evidence."""
    # These are hard ceilings; config can lower the request count but cannot
    # turn this bounded check into an unbounded parameter sweep.
    max_endpoints = min(int(max_endpoints), 10)
    max_params = min(int(max_params), 3)
    if max_endpoints <= 0 or max_params <= 0:
        coverage.record("open_redirect", "untestable",
                        "open redirect probe caps are zero")
        return []

    candidates = []
    for endpoint in endpoints:
        if endpoint.method.upper() != "GET":
            continue
        names = _query_parameters(endpoint)[:max_params]
        if names and scope.active_test_allowed(endpoint.url):
            candidates.append((endpoint, names))
        if len(candidates) >= max_endpoints:
            break

    if not candidates:
        coverage.record("open_redirect", "untestable",
                        "no in-scope GET endpoints with observed redirect fields")
        return []

    findings: List[Finding] = []
    tested = 0
    errors = 0
    for endpoint, names in candidates:
        for parameter in names:
            marker_host = f"apex-{uuid.uuid4().hex}.invalid"
            marker_url = f"https://{marker_host}/apex-redirect-check"
            probe_url = _replace_query_value(endpoint.url, parameter,
                                             marker_url)
            try:
                response = http.get(probe_url, timeout=timeout)
                tested += 1
            except Exception as exc:
                errors += 1
                # Budgets and scope gates are surfaced distinctly in coverage.
                name = type(exc).__name__.lower()
                if "budget" in name or "scope" in name:
                    coverage.record("open_redirect", "blocked",
                                    f"probe blocked: {type(exc).__name__}")
                continue

            headers: Dict[str, str] = dict(response.headers or {})
            location = next((str(v) for k, v in headers.items()
                             if k.lower() == "location"), "")
            if not _is_external_marker(int(response.status_code), location,
                                       marker_host, endpoint.url):
                continue

            finding = Finding(
                id=stable_finding_id("open-redirect", endpoint.normalized_url,
                                     parameter),
                source="open-redirect-validator",
                template_id="apex/open-redirect/observed-query",
                name="Unvalidated external redirect",
                severity="medium", confidence=Confidence.CONFIRMED.value,
                validation_status=ValidationStatus.CONFIRMED.value,
                host=urlparse(endpoint.url).hostname or "",
                matched_at=probe_url, endpoint_url=endpoint.url,
                parameter=parameter, method="GET",
                response_status=int(response.status_code),
                response_headers={"Location": location},
                response_snippet="Response redirected to the unique external "
                                 "probe hostname.",
                description=("An observed redirect parameter caused the "
                             "application to return a 3xx Location pointing "
                             "to the unique external probe hostname."),
                tags=["open-redirect", "validated"],
                raw={"probe_url": probe_url,
                     "location": location,
                     "marker_host": marker_host,
                     "followed_redirects": False},
            )
            finding.reproduction = (
                "curl -i --max-redirs 0 "
                f"'{probe_url}'")
            evidence.record(
                finding,
                request_text=f"GET {probe_url}\n",
                response_text=(f"HTTP {response.status_code}\n"
                               f"Location: {location}\n"),
                response_headers=headers)
            findings.append(finding)
            metrics.validation_candidates += 1
            metrics.validated_confirmed += 1

    if findings:
        coverage.record("open_redirect", "confirmed",
                        f"confirmed {len(findings)} observed redirect field(s)")
    elif tested and errors == 0:
        coverage.record("open_redirect", "tested_negative",
                        f"tested {tested} observed redirect field(s); no external redirect")
    elif tested or errors:
        coverage.record("open_redirect", "inconclusive",
                        f"tested {tested} field(s); {errors} request error(s)")
    return findings
