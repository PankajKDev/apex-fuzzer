"""SARIF export (v2.1.0) for CI consumption.

A machine-readable projection of findings.jsonl — severities become
SARIF levels, sources become rules, endpoints become locations.
Evidence stays in the HTML report and proofs/ directories; SARIF is
a triage feed, not a replacement for evidence.
"""
import json
from pathlib import Path
from typing import Dict, List

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_LEVELS = {"critical": "error", "high": "error", "medium": "warning",
           "low": "note", "info": "note"}


def level_for(severity) -> str:
    return _LEVELS.get(str(severity or "info").lower(), "note")


def export_sarif(findings: List[Dict], tool_version: str) -> Dict:
    """Finding dicts (as stored in findings.jsonl) → SARIF log."""
    rules = {}
    results = []
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        source = str(f.get("source", "unknown") or "unknown")
        if source not in rules:
            rules[source] = {
                "id": source,
                "name": source.replace("-", " ").title(),
                "shortDescription": {
                    "text": f"Apex-Fuzzer {source} candidate"},
                "helpUri": "",
            }
        description = str(f.get("description", "") or "")
        name = str(f.get("name", "") or source)
        message = f"{name}: {description}"[:2000] if description \
            else name[:500]
        endpoint = str(f.get("endpoint_url", "") or
                       f.get("matched_at", "") or "")
        results.append({
            "ruleId": source,
            "level": level_for(f.get("severity")),
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": endpoint},
                },
            }],
            "partialFingerprints": {
                "finding-id/v1": str(f.get("id", "")),
            },
            "properties": {
                "result_status": f.get("result_status"),
                "confidence": f.get("confidence"),
                "validation_status": f.get("validation_status"),
                "parameter": f.get("parameter"),
                "method": f.get("method"),
                "evidence_dir": f.get("evidence_dir"),
            },
        })
    return {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [{
            "tool": {"driver": {
                "name": "apex-fuzzer",
                "version": str(tool_version or ""),
                "informationUri": "",
                "rules": sorted(rules.values(),
                                key=lambda r: r["id"]),
            }},
            "results": results,
        }],
    }


def write_sarif(out_dir: Path, findings: List[Dict],
                tool_version: str) -> Path:
    """Write sarif.json next to the other report artifacts."""
    dest = Path(out_dir) / "sarif.json"
    with open(dest, "w") as handle:
        json.dump(export_sarif(findings, tool_version), handle,
                  indent=2)
    return dest
