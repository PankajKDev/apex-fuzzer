"""XSS validation adapter."""
from pathlib import Path
from .base import Validator, Candidate, ValidationOutcome
from ..shell import run, which, redact
from ..models import ValidationStatus, Confidence


class XssValidator(Validator):
    name = "dalfox"
    test_class = "xss"

    def can_handle(self, candidate: Candidate) -> bool:
        return candidate.test_class == "xss" and which("dalfox") is not None

    def validate(self, candidate: Candidate) -> ValidationOutcome:
        out_file = Path(candidate.finding.evidence_dir or "/tmp") / "dalfox.json"
        args = ["dalfox", "url", candidate.endpoint_url,
                "--no-color", "--silence", "-o", str(out_file)]
        r = run(args, timeout=300)
        text = redact((r.stdout or "") + (r.stderr or ""))
        if "verified" in text.lower() or "poc" in text.lower():
            return ValidationOutcome(
                status=ValidationStatus.STRONG_CANDIDATE.value,
                confidence=Confidence.PROBABLE.value,
                evidence={"dalfox_tail": text[-1500:]},
                notes="dalfox produced a candidate payload")
        if not r.ok:
            return ValidationOutcome(
                status=ValidationStatus.INCONCLUSIVE.value,
                confidence=Confidence.UNKNOWN.value,
                evidence={"dalfox_tail": text[-800:]})
        return ValidationOutcome(
            status=ValidationStatus.NOT_TESTED.value,
            confidence=Confidence.UNKNOWN.value,
            notes="dalfox did not produce a signal")
