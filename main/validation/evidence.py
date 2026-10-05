"""Evidence collection — one dir per finding, secrets redacted."""
import json
from pathlib import Path
from datetime import datetime
from ..shell import redact
from ..models import Finding
from typing import Dict


def interaction_line(i: Dict) -> str:
    """One-line evidence summary for an OAST interaction record."""
    proto = i.get("proto") or i.get("type", "?")
    return f"[{proto}] " + " ".join(str(v)[:120] for v in i.values()
                                    if isinstance(v, str))[:240]


class EvidenceStore:
    def __init__(self, proofs_dir: Path):
        self.dir = proofs_dir
        self.dir.mkdir(parents=True, exist_ok=True)
        self._counter = 0

    def allocate(self, finding: Finding) -> Path:
        self._counter += 1
        sub = self.dir / f"finding-{self._counter:03d}"
        sub.mkdir(parents=True, exist_ok=True)
        finding.evidence_dir = str(sub)
        return sub

    def record(self, finding: Finding, request_text: str = "",
               response_text: str = "",
               response_headers: dict | None = None) -> None:
        sub = Path(finding.evidence_dir) if finding.evidence_dir \
            else self.allocate(finding)
        if request_text:
            (sub / "request.txt").write_text(redact(request_text))
        if response_text:
            (sub / "response.txt").write_text(redact(response_text))
        meta = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "finding_id": finding.id, "url": finding.matched_at,
            "method": finding.method, "severity": finding.severity,
            "validation_status": finding.validation_status,
            "result_status": finding.result_status,
            "confidence": finding.confidence,
            "template_id": finding.template_id,
            "source": finding.source,
            "response_status": finding.response_status,
            "response_headers": {k: v for k, v in
                                 (response_headers or {}).items()
                                 if k.lower() not in ("set-cookie",)},
        }
        (sub / "metadata.json").write_text(json.dumps(meta, indent=2))


def build_reproduction(finding: Finding) -> str:
    lines = ["curl -sk"]
    if finding.method and finding.method.upper() != "GET":
        lines.append(f"-X {finding.method.upper()}")
    for k, v in (finding.request_headers or {}).items():
        if k.lower() in ("host", "content-length"):
            continue
        lines.append(f"-H '{k}: {redact(v)}'")
    if finding.request_body:
        body = redact(finding.request_body).replace("'", "'\\''")
        lines.append(f"--data '{body}'")
    lines.append(f"'{finding.matched_at}'")
    return " ".join(lines)
