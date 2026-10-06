"""Evidence collection — one dir per finding, secrets redacted."""
import json
from pathlib import Path
from datetime import datetime, timezone
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
            "timestamp": datetime.now(timezone.utc).isoformat().replace(
                "+00:00", "Z"),
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

    def manifest(self) -> dict:
        """sha256 per evidence file, keyed by finding dir then name.

        Tamper-evidence for the report handoff: recompute and compare
        with verify_integrity(). Never fails; unreadable files are
        recorded with null hashes.
        """
        import hashlib
        out: dict = {}
        try:
            children = sorted(p for p in self.dir.iterdir()
                              if p.is_dir())
        except OSError:
            return out
        for sub in children:
            files: dict = {}
            try:
                names = sorted(p for p in sub.iterdir()
                               if p.is_file())
            except OSError:
                names = []
            for path in names:
                try:
                    digest = hashlib.sha256(
                        path.read_bytes()).hexdigest()
                except OSError:
                    digest = None
                files[path.name] = digest
            out[sub.name] = files
        return out

    def write_manifest(self) -> Path:
        """Persist integrity.json beside the finding directories."""
        dest = self.dir / "integrity.json"
        try:
            dest.write_text(json.dumps({"proofs": self.manifest()},
                                       indent=2))
        except OSError as exc:
            from ..logging_setup import get_logger
            get_logger("evidence").debug(
                "integrity manifest unwritable: %s", exc)
        return dest


def verify_integrity(proofs_dir) -> dict:
    """Re-hash evidence files against integrity.json.

    Returns {"ok": bool, "mismatches": [...], "reason": ""}.
    Absent manifest or unreadable files fail closed (ok False).
    """
    import hashlib
    base = Path(proofs_dir)
    manifest_file = base / "integrity.json"
    try:
        expected = json.loads(manifest_file.read_text(
            errors="ignore") or "{}").get("proofs", {})
    except (ValueError, OSError) as exc:
        return {"ok": False, "mismatches": [],
                "reason": f"manifest unreadable: {exc}"[:200]}
    if not isinstance(expected, dict) or not expected:
        return {"ok": False, "mismatches": [],
                "reason": "no manifest recorded"}
    mismatches = []
    for dirname, files in expected.items():
        if not isinstance(files, dict):
            continue
        for name, digest in files.items():
            if not isinstance(name, str) or "/" in name:
                continue
            try:
                actual = hashlib.sha256(
                    (base / dirname / name).read_bytes()).hexdigest()
            except OSError:
                actual = None
            if actual != digest:
                mismatches.append(f"{dirname}/{name}")
    if mismatches:
        return {"ok": False, "mismatches": sorted(mismatches),
                "reason": f"{len(mismatches)} file(s) changed "
                          f"since the manifest"}
    return {"ok": True, "mismatches": [], "reason": ""}


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
