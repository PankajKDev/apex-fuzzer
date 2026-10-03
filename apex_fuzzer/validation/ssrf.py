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
        ep = endpoint_from_url(candidate.endpoint_url,
                               candidate.parameter)
        if not ssrf_candidates(list(ep.query_parameters) +
                               list(ep.body_parameters)):
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
                      "response_time_ms": res.response_time_ms},
            notes=f"confirmed SSRF via OAST callback on "
                  f"'{res.parameter}'")
