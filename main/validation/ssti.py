"""Bounded, non-executing SSTI validation for observed request fields.

The validator sends paired arithmetic expressions and confirms only when
both distinct expressions are rendered to their exact computed values inside
unique markers. It never attempts template introspection, file access, or code
execution. Candidate POST bodies require the explicit state-change gate.
"""
from __future__ import annotations

import secrets
from typing import Any, Dict, List
from urllib.parse import parse_qsl, urlsplit

from .base import Candidate, ValidationOutcome, Validator
from .mutate import _inject
from .request_shape import body_with_parameter, encode_form, encode_json, is_json
from ..models import Confidence, ValidationStatus
from ..budgets import BudgetExceeded


_EXPRESSION_PAIRS = (
    ("{{", "}}", "7*7", "49", "7+7", "14", "double-curly"),
    ("${", "}", "7*7", "49", "7+7", "14", "dollar-brace"),
)


class SstiValidator(Validator):
    name = "ssti-arithmetic"
    test_class = "ssti"

    def __init__(self, cfg, http, timeout: int = 10):
        super().__init__(cfg)
        self.http = http
        self.timeout = timeout

    def validate(self, candidate: Candidate) -> ValidationOutcome:
        method = (candidate.method or "GET").upper()
        parameter = candidate.parameter
        if not parameter:
            query = parse_qsl(urlsplit(candidate.endpoint_url).query,
                              keep_blank_values=True)
            parameter = query[-1][0] if query else None
        if not parameter:
            return self._inconclusive("no observed parameter was identified")

        location = (candidate.parameter_location or "query").lower()
        if location == "query":
            if method != "GET":
                return self._inconclusive(
                    f"query validation skipped for unsupported method {method}")
            names = {name for name, _ in parse_qsl(
                urlsplit(candidate.endpoint_url).query,
                keep_blank_values=True)}
            if parameter not in names:
                return self._inconclusive(
                    "selected query parameter is absent from the observed URL")
        elif location == "body":
            if method != "POST":
                return self._inconclusive(
                    f"body validation skipped for unsupported method {method}")
            safety = getattr(self.cfg, "safety", None)
            if not getattr(safety, "allow_state_change", False):
                return self._inconclusive(
                    "POST body probes require safety.allow_state_change")
            known = {getattr(item, "name", "") for item in
                     (candidate.body_parameters or [])}
            if parameter not in known:
                return self._inconclusive(
                    "selected body parameter is not present in observed metadata")
        else:
            return self._inconclusive(
                f"parameter location {location!r} is not supported")

        marker = "apx" + secrets.token_hex(5) + "z"
        headers = dict(candidate.request_headers or {})
        tested = 0
        syntax_signals: List[Dict[str, Any]] = []
        for left, right, expr_a, expected_a, expr_b, expected_b, label in \
                _EXPRESSION_PAIRS:
            payloads = (
                (f"{marker}{left}{expr_a}{right}x", marker + expected_a + "x"),
                (f"{marker}{left}{expr_b}{right}y", marker + expected_b + "y"),
            )
            matched: List[bool] = []
            statuses: List[int] = []
            for payload, expected in payloads:
                try:
                    response = self._send(candidate, method, location,
                                          parameter, payload, headers)
                except BudgetExceeded:
                    raise
                except Exception as exc:
                    return self._inconclusive(
                        f"paired probe stopped after {tested} request(s): "
                        f"{type(exc).__name__}",
                        {"syntax": label, "requests_sent": tested})
                tested += 1
                body = str(getattr(response, "text", "") or "")
                statuses.append(int(getattr(response, "status_code", 0) or 0))
                matched.append(expected in body)

            syntax_signals.append({"syntax": label, "matched": matched,
                                   "http_statuses": statuses})
            if all(matched):
                return ValidationOutcome(
                    status=ValidationStatus.CONFIRMED.value,
                    confidence=Confidence.CONFIRMED.value,
                    evidence={"parameter": parameter,
                              "location": location,
                              "syntax": label,
                              "expressions": ["7*7 -> 49", "7+7 -> 14"],
                              "http_statuses": statuses,
                              "request_count": tested},
                    notes=("two distinct inert arithmetic expressions were "
                           "evaluated inside unique response markers"))

        if any(any(signal["matched"]) for signal in syntax_signals):
            return ValidationOutcome(
                status=ValidationStatus.STRONG_CANDIDATE.value,
                confidence=Confidence.PROBABLE.value,
                evidence={"parameter": parameter, "location": location,
                          "signals": syntax_signals,
                          "request_count": tested},
                notes=("one arithmetic expression produced its exact value; "
                       "the paired control did not, so impact is unconfirmed"))
        return self._inconclusive(
            "no paired arithmetic evaluation was observed; this does not "
            "rule out other template syntaxes or non-reflected sinks",
            {"parameter": parameter, "location": location,
             "signals": syntax_signals, "request_count": tested})

    def _send(self, candidate: Candidate, method: str, location: str,
              parameter: str, payload: str, headers: Dict[str, str]):
        if location == "query":
            url = _inject(candidate.endpoint_url, parameter, payload)
            return self.http.get(url, headers=headers, timeout=self.timeout)

        body = body_with_parameter(candidate, parameter, payload)
        if is_json(candidate):
            request_headers = dict(headers)
            if not any(key.lower() == "content-type"
                       for key in request_headers):
                request_headers["Content-Type"] = "application/json"
            return self.http.request(
                method, candidate.endpoint_url, headers=request_headers,
                data=encode_json(body), timeout=self.timeout)
        return self.http.request(
            method, candidate.endpoint_url, headers=headers,
            data=encode_form(body), timeout=self.timeout)

    @staticmethod
    def _inconclusive(note: str, evidence: Dict[str, Any] | None = None
                      ) -> ValidationOutcome:
        return ValidationOutcome(
            status=ValidationStatus.INCONCLUSIVE.value,
            confidence=Confidence.UNKNOWN.value,
            evidence=evidence or {}, notes=note)
