"""SQLi validation adapter."""
from .base import Validator, Candidate, ValidationOutcome
from ..shell import run, which, redact
from ..models import ValidationStatus, Confidence


class SqliValidator(Validator):
    name = "sqlmap"
    test_class = "sqli"

    def can_handle(self, candidate: Candidate) -> bool:
        return candidate.test_class == "sqli" and which("sqlmap") is not None

    def validate(self, candidate: Candidate) -> ValidationOutcome:
        from urllib.parse import parse_qsl, urlsplit
        from .request_shape import (body_with_parameter, encode_form,
                                    encode_json, is_json)

        method = (candidate.method or "GET").upper()
        if method not in {"GET", "POST", "PUT", "PATCH"}:
            return ValidationOutcome(
                status=ValidationStatus.INCONCLUSIVE.value,
                confidence=Confidence.UNKNOWN.value,
                evidence={},
                notes=f"sqlmap skipped: unsupported method {method}")
        if method != "GET" and not getattr(
                getattr(self.cfg, "safety", None), "allow_state_change", False):
            return ValidationOutcome(
                status=ValidationStatus.INCONCLUSIVE.value,
                confidence=Confidence.UNKNOWN.value,
                evidence={},
                notes="sqlmap body probes skipped: state-changing requests "
                      "require allow_state_change")
        if candidate.parameter_location == "body" and method == "GET":
            return ValidationOutcome(
                status=ValidationStatus.INCONCLUSIVE.value,
                confidence=Confidence.UNKNOWN.value,
                evidence={},
                notes="sqlmap skipped: GET body shape is unsupported")

        param = candidate.parameter
        if not param and candidate.parameter_location != "body":
            query_params = parse_qsl(urlsplit(candidate.endpoint_url).query,
                                     keep_blank_values=True)
            param = query_params[-1][0] if query_params else None
        if not param:
            return ValidationOutcome(
                status=ValidationStatus.INCONCLUSIVE.value,
                confidence=Confidence.UNKNOWN.value,
                evidence={},
                notes="sqlmap skipped: no candidate parameter was identified")

        out_dir = getattr(candidate.finding, "evidence_dir", None) or \
            "/tmp/sqlmap"
        args = [
            "sqlmap", "-u", candidate.endpoint_url, "--batch",
            f"-p={param}", "--level", "1", "--risk", "1",
            "--technique", "BE",
            f"--output-dir={out_dir}", "--timeout", "10",
            "--retries", "0", "--threads", "1",
        ]
        if method != "GET":
            args.extend(["--method", method])
        if candidate.parameter_location == "body":
            body = body_with_parameter(
                candidate, param, self._body_sample(candidate, param))
            args.extend(["--data", encode_json(body) if is_json(candidate)
                         else encode_form(body)])
            if is_json(candidate):
                args.extend(["--headers", "Content-Type: application/json"])
        r = run(args, timeout=180)
        log_text = redact((r.stdout or "") + (r.stderr or ""))
        if "is vulnerable" in log_text.lower():
            return ValidationOutcome(
                status=ValidationStatus.CONFIRMED.value,
                confidence=Confidence.CONFIRMED.value,
                evidence={"sqlmap_tail": log_text[-2000:],
                          "parameter": param,
                          "techniques": "boolean-based and error-based"},
                notes="sqlmap reported a confirmed injection point on "
                      f"parameter {param!r}")
        if "not injectable" in log_text.lower():
            return ValidationOutcome(
                status=ValidationStatus.FALSE_POSITIVE.value,
                confidence=Confidence.PROBABLE.value,
                evidence={"sqlmap_tail": log_text[-1000:]},
                notes="sqlmap reports parameter is not injectable")
        return ValidationOutcome(
            status=ValidationStatus.INCONCLUSIVE.value,
            confidence=Confidence.UNKNOWN.value,
            evidence={"sqlmap_tail": log_text[-1000:]},
            notes="sqlmap finished without a definitive result")

    @staticmethod
    def _body_sample(candidate: Candidate, parameter: str) -> str:
        from .request_shape import body_parameter_value
        return body_parameter_value(candidate, parameter)
