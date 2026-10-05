"""postMessage/SOP static sweep over the cached JS inventory.

Offline file reads only: no requests, no budgets, no scope checks
(the cache is first-party inventory, not target traffic). Findings
are static-analysis candidates; code excerpts are never persisted —
evidence keeps the file, line, and marker family so the operator
can inspect the exact spot.
"""
import json
from pathlib import Path
from typing import List
from urllib.parse import urlsplit

from ...logging_setup import get_logger
from ...models import (Confidence, Finding, ValidationStatus,
                       stable_finding_id)
from ...reporting.coverage import CoverageTracker
from ...validation.evidence import EvidenceStore
from ...validation.postmessage import check_javascript
from . import ProbeControls

log = get_logger("stages-validation")

_MAX_FILES = 20
_MAX_PER_FILE = 5
_MAX_TOTAL = 30

_SEVERITY = {"handler-no-origin-check": "medium",
             "wildcard-target-origin": "medium",
             "document-domain": "low"}


def _severity(kind: str, hit: dict) -> str:
    if kind == "wildcard-target-origin" and not hit.get("sensitive"):
        return "low"
    return _SEVERITY.get(kind, "low")


_FP_NOTES = {
    "handler-no-origin-check":
        "Static vicinity scan only: origin validation may live in a "
        "called function outside the scanned window, and not every "
        "handler acts on untrusted data. Confirm the handler reaches "
        "a sensitive sink with an attacker-controlled origin.",
    "wildcard-target-origin":
        "A '*' targetOrigin leaks the posted data to any origin that "
        "embeds the page. Confirm sensitive data actually flows here "
        "and a victim session visits attacker content.",
    "document-domain":
        "Setting document.domain is often benign (same-value) or "
        "legacy; only a suffix relaxation that shares state across "
        "trust boundaries matters. Confirm before reporting.",
}


def postmessage_probe(out_dir: Path, evidence: EvidenceStore,
                      coverage: CoverageTracker, cfg,
                      controls: ProbeControls) -> List[Finding]:
    """Check cached first-party bundles for postMessage hazards."""
    cache = Path(out_dir) / "cache"
    files = []
    if cache.exists():
        files = sorted(
            f for f in cache.glob("*")
            if f.is_file() and f.suffix != ".meta"
            and Path(str(f) + ".meta").exists())[:_MAX_FILES]
    if not files:
        log.info("postmessage: no cached JS with metadata — "
                 "nothing to check")
        coverage.record("postmessage", "untestable",
                        "no cached first-party JavaScript")
        return []
    findings: List[Finding] = []
    for path in files:
        if controls.halted():
            log.info("postmessage: halted by stop control")
            break
        if len(findings) >= _MAX_TOTAL:
            break
        try:
            meta = json.loads(
                Path(str(path) + ".meta").read_text())
            source_url = str(meta.get("url", "") or "")
            js = path.read_text(errors="ignore")
        except (OSError, ValueError) as exc:
            log.debug("postmessage: unreadable cache %s: %s", path, exc)
            continue
        if not source_url.startswith(("http://", "https://")):
            continue
        try:
            parts = urlsplit(source_url)
            host = parts.hostname or ""
            epath = parts.path or "/"
        except ValueError:
            continue
        for hit in check_javascript(js)[:_MAX_PER_FILE]:
            if len(findings) >= _MAX_TOTAL:
                break
            kind = str(hit.get("kind", ""))
            line = int(hit.get("line", 0) or 0)
            notes = (f"{kind} in {path.name}:{line} "
                     f"(source: {source_url[:200]})")
            coverage.record("postmessage", "candidate",
                            f"{source_url[:200]}:{line}: {kind}")
            f = Finding(
                id=stable_finding_id("postmessage", source_url,
                                     kind, str(line)),
                source="postmessage-static",
                name=(f"postMessage hazard: {kind} ({epath}:{line})"),
                severity=_severity(kind, hit),
                confidence=Confidence.POSSIBLE.value,
                validation_status=ValidationStatus.
                STRONG_CANDIDATE.value,
                host=host, matched_at=source_url,
                endpoint_url=source_url, method="GET",
                description=notes,
                tags=["postmessage", kind, "static-javascript"],
                raw={"check": "postmessage",
                     "kind": kind, "line": line,
                     "file": path.name,
                     "sensitive": bool(hit.get("sensitive", False))},
                false_positive_notes=(
                    f"{notes}. {_FP_NOTES.get(kind, '')}"),
            )
            evidence.allocate(f)
            evidence.record(
                f,
                request_text=(f"static analysis of cached bundle "
                              f"{path.name}:{line}"),
                response_text=notes)
            findings.append(f)
            log.info("postmessage: %s in %s:%d", kind, path.name,
                     line)
    return findings
