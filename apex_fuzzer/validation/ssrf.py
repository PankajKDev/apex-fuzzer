"""SSRF validation adapter — OAST-confirmed out-of-band (spec §3)."""
from typing import Optional
from urllib.parse import urlparse, parse_qsl
from .base import Validator, Candidate, ValidationOutcome
from ..models import (Parameter, Endpoint, ValidationStatus, Confidence)
from ..discovery.url_normalizer import normalize_url
from ..logging_setup import get_logger
from .oast import (InteractshProvider, probe_endpoint,
                   ssrf_candidates)

log = get_logger("ssrf")


def endpoint_from_url(url: str, extra_param: Optional[str] = None) -> Endpoint:
    """Rebuild a minimal Endpoint from a URL (+ optional param name)."""
    p = urlparse(url)
    ep = Endpoint(url=url, normalized_url=normalize_url(url),
                  host=p.hostname or "", path=p.path,
                  method="GET", source=["validation"])
    seen = set()
    for name, val in parse_qsl(p.query, keep_blank_values=True):
        if name in seen:
            continue
        seen.add(name)
        ep.query_parameters.append(Parameter(
            name=name, location="query", source=["validation"],
            sample_value=val))
    if extra_param and extra_param not in seen:
        ep.query_parameters.append(Parameter(
            name=extra_param, location="query", source=["validation"],
            confidence=Confidence.POSSIBLE.value))
    return ep


class SsrfValidator(Validator):
    name = "oast-ssrf"
    test_class = "ssrf"

    def __init__(self, cfg, provider: InteractshProvider, http):
        super().__init__(cfg)
        self.provider = provider
        self.http = http

    def can_handle(self, candidate: Candidate) -> bool:
        return candidate.test_class == "ssrf" and \
            self.provider.available()

    def validate(self, candidate: Candidate) -> ValidationOutcome:
        # Honor the candidate's observed shape: method, body fields, and
        # headers replay verbatim instead of collapsing to GET-query.
        # Non-GET shapes need the state-change acknowledgment, like every
        # other mutating probe.
        method = (candidate.method or "GET").upper()
        if method not in {"GET", "POST", "PUT", "PATCH"}:
            return ValidationOutcome(
                status=ValidationStatus.INCONCLUSIVE.value,
                confidence=Confidence.UNKNOWN.value,
                notes=f"SSRF validation skipped: unsupported method {method}")
        if method != "GET" and not getattr(
                getattr(self.cfg, "safety", None), "allow_state_change",
                False):
            return ValidationOutcome(
                status=ValidationStatus.INCONCLUSIVE.value,
                confidence=Confidence.UNKNOWN.value,
                notes="SSRF body probes skipped: state-changing requests "
                      "require allow_state_change")
        ep = endpoint_from_url(candidate.endpoint_url,
                               candidate.parameter)
        ep.method = method
        if candidate.request_headers:
            ep.headers = dict(candidate.request_headers)
        # The candidate's own parameter rides as a header candidate only
        # when it is not an identity/framing carrier; observed auth
        # headers above travel as credentials, never as targets.
        if (candidate.parameter_location or "").lower() == "header" \
                and candidate.parameter:
            from .request_shape import is_protected_parameter
            if is_protected_parameter("header", candidate.parameter):
                return ValidationOutcome(
                    status=ValidationStatus.INCONCLUSIVE.value,
                    confidence=Confidence.UNKNOWN.value,
                    notes="SSRF validation skipped: identity/framing "
                          "headers are never probed")
            if not any(p.name.lower() == candidate.parameter.lower()
                       for p in ep.header_parameters):
                ep.header_parameters.append(Parameter(
                    name=candidate.parameter, location="header",
                    source=["validation"]))
        body_params = list(getattr(candidate, "body_parameters", []) or [])
        if body_params:
            ep.body_parameters = list(body_params)
            if not ep.request_content_types and candidate.request_content_type:
                ep.request_content_types = [candidate.request_content_type]
        if candidate.request_body is not None:
            # peer fields from the retained body ride along so the probe
            # keeps the observed shape; declared params win conflicts
            from urllib.parse import parse_qsl as _pqsl
            content_type = (candidate.request_content_type or "").lower()
            if "json" in content_type and isinstance(candidate.request_body,
                                                     str):
                import json as _json
                try:
                    data = _json.loads(candidate.request_body)
                    if isinstance(data, dict):
                        known = {p.name for p in ep.body_parameters}
                        for key, val in data.items():
                            if str(key) not in known:
                                known.add(str(key))
                                ep.body_parameters.append(Parameter(
                                    name=str(key), location="body",
                                    source=["observed-body"],
                                    sample_value=str(val)[:200]
                                    if isinstance(val, (str, int)) else ""))
                except (ValueError, TypeError):
                    pass
            elif isinstance(candidate.request_body, str):
                known = {p.name for p in ep.body_parameters}
                for key, val in _pqsl(candidate.request_body,
                                      keep_blank_values=True):
                    if key and key not in known:
                        known.add(key)
                        ep.body_parameters.append(Parameter(
                            name=key, location="body",
                            source=["observed-body"],
                            sample_value=val[:200]))
        if not ssrf_candidates(list(ep.query_parameters) +
                               list(ep.body_parameters) +
                               list(ep.header_parameters), ep):
            # no SSRF-like param found — try the candidate's param anyway
            if candidate.parameter:
                ep.query_parameters.append(Parameter(
                    name=candidate.parameter, location="query",
                    source=["validation"]))
            else:
                return ValidationOutcome(
                    status=ValidationStatus.INCONCLUSIVE.value,
                    confidence=Confidence.UNKNOWN.value,
                    notes="no SSRF-like parameter identified on endpoint")
        cfg = self.cfg
        res = probe_endpoint(
            self.http, ep, self.provider,
            poll_timeout=getattr(cfg.oast, "poll_timeout", 15),
            poll_interval=getattr(cfg.oast, "poll_interval", 2),
            max_params=getattr(cfg.oast, "max_params_per_endpoint", 3))
        if res is None or not res.confirmed:
            return ValidationOutcome(
                status=ValidationStatus.INCONCLUSIVE.value,
                confidence=Confidence.UNKNOWN.value,
                evidence={"oast_notes": res.notes if res else "no provider",
                          "response_status": (res.response_status
                                              if res else None),
                          "response_length": (res.response_length
                                              if res else None),
                          "response_time_ms": (res.response_time_ms
                                               if res else None),
                          "request_method": (res.request_method
                                             if res else None),
                          "request_url": (res.request_url
                                          if res else None),
                          "parameter_location": (res.parameter_location
                                                 if res else None),
                          "payload": res.payload if res else None},
                notes=("no out-of-band callback received; response "
                       "differences alone are not confirmation"))
        snippet = ""
        for it in res.interactions[:3]:
            proto = it.get("proto") or it.get("type", "?")
            snippet += f"[{proto}] " + " ".join(
                str(v)[:120] for v in it.values()
                if isinstance(v, str))[:200] + "\n"
        return ValidationOutcome(
            status=ValidationStatus.CONFIRMED.value,
            confidence=Confidence.CONFIRMED.value,
            evidence={"parameter": res.parameter, "payload": res.payload,
                      "interactions": snippet[:2000],
                      "callback_host": res.callback_host,
                      "request_method": res.request_method,
                      "request_url": res.request_url,
                      "parameter_location": res.parameter_location,
                      "response_status": res.response_status,
                      "response_length": res.response_length,
                      "response_time_ms": res.response_time_ms,
                      "bypass_kind": res.bypass_kind,
                      "response_reflects_token":
                          res.response_reflects_token},
            notes=(f"confirmed SSRF via OAST callback on "
                   f"'{res.parameter}'"
                   + (f" through parser-bypass variant "
                      f"({res.bypass_kind})" if res.bypass_kind else "")
                   + ("; target response reflects the callback token "
                      "(possible full-read: confirm manually)"
                      if res.response_reflects_token else "")))
