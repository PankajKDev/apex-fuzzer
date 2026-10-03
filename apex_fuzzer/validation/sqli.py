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
        out_dir = candidate.finding.evidence_dir or "/tmp/sqlmap"
        args = [
            "sqlmap", "-u", candidate.endpoint_url, "--batch",
            "--level", "1", "--risk", "1", "--dbs",
            f"--output-dir={out_dir}", "--timeout", "10",
            "--retries", "1", "--threads", "2",
        ]
        r = run(args, timeout=600)
        log_text = redact((r.stdout or "") + (r.stderr or ""))
        if "is vulnerable" in log_text.lower() or \
                "available databases" in log_text.lower():
            return ValidationOutcome(
                status=ValidationStatus.CONFIRMED.value,
                confidence=Confidence.CONFIRMED.value,
                evidence={"sqlmap_tail": log_text[-2000:]},
                notes="sqlmap reported a confirmed injection point")
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
