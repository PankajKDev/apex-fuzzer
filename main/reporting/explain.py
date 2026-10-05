"""Finding explainer: every signal behind one result.

Reads findings.jsonl (the same records the report renders) and prints
a deterministic, human-readable account: what was observed, what it
was compared against, why it scored, what would disprove it, and
where the raw evidence lives. Zero network.
"""
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def _load_findings(out_dir: Path) -> List[Dict]:
    path = Path(out_dir) / "findings.jsonl"
    try:
        lines = path.read_text(errors="ignore").splitlines()
    except OSError:
        return []
    out = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict):
            out.append(record)
    return out


def find_finding(out_dir: Path, finding_id: str) -> Optional[Dict]:
    for record in _load_findings(out_dir):
        if str(record.get("id", "")) == str(finding_id):
            return record
    return None


def explain_finding(out_dir: Path, finding_id: str) -> Tuple[str, bool]:
    """Explain one finding. Returns (text, found)."""
    record = find_finding(out_dir, finding_id)
    if record is None:
        known = [str(r.get("id", "")) for r in
                 _load_findings(out_dir)][:20]
        lines = [f"finding {finding_id} not found in "
                 f"{out_dir}/findings.jsonl"]
        if known:
            lines.append("known IDs (first 20): " + ", ".join(known))
        return "\n".join(lines), False
    raw = record.get("raw") if isinstance(record.get("raw"), dict) \
        else {}
    lines = [
        f"Finding {record.get('id')}: "
        f"{record.get('name', '(unnamed)')}",
        f"  status: {record.get('result_status', '?')} "
        f"(legacy: {record.get('validation_status', '?')})",
        f"  severity: {record.get('severity', '?')}  "
        f"confidence: {record.get('confidence', '?')}",
        f"  source: {record.get('source', '?')}  "
        f"method: {record.get('method', '?')}",
        f"  target: {record.get('endpoint_url', '') or '?'}"
        + (f"  parameter: {record.get('parameter')}"
           if record.get("parameter") else ""),
        f"  host: {record.get('host', '?')}",
    ]
    if record.get("identity"):
        lines.append(f"  tested as: {record.get('identity')}"
                     + (f" (tenant {record.get('tenant')})"
                        if record.get("tenant") else ""))
    lines.append(f"Observed: {record.get('description', '(no notes)')}")
    signals = []
    for key in ("contexts", "swap", "interactions", "types",
                "observations", "validator_results", "cache",
                "transition", "graphql", "business", "race",
                "prescreen", "verification", "invariants"):
        if raw.get(key) not in (None, [], {}, ""):
            value = raw[key]
            size = len(value) if isinstance(value, (list, dict)) \
                else len(str(value))
            signals.append(f"{key} ({size})")
    if raw.get("confirmed") is True or \
            record.get("result_status") == "verified_effect":
        signals.append("confirmation: repeated/confirmed effect")
    if record.get("confirmation_notes"):
        signals.append(f"confirmation: {record['confirmation_notes']}")
    lines.append("Signals: " + (", ".join(signals) if signals
                                 else "(none recorded)"))
    if record.get("false_positive_notes"):
        lines.append(f"False-positive checks: "
                     f"{record['false_positive_notes']}")
    review = raw.get("review")
    if isinstance(review, dict):
        lines.append(f"Operator review: {review.get('verdict', '?')}"
                     + (f" — {review.get('reason')}"
                        if review.get("reason") else ""))
    if record.get("reproduction_steps"):
        lines.append("Reproduction:")
        for step in record["reproduction_steps"]:
            lines.append(f"  - {step}")
    lines.append("Human checklist: re-run the baseline request; "
                 "confirm the differential repeats; rule out login-wall "
                 "shadowing, shared templates, and volatile content; "
                 "verify impact before reporting.")
    evidence = record.get("evidence_dir")
    if evidence:
        lines.append(f"Evidence: {evidence}/ "
                     "(request.txt, response.txt, metadata.json)")
    return "\n".join(lines), True


def explain_in_output_base(output_base, finding_id: str
                           ) -> Tuple[str, bool]:
    """Search every target dir under the output base for the ID."""
    base = Path(output_base or "output")
    hits = []
    if base.is_dir():
        for child in sorted(base.iterdir()):
            if not child.is_dir():
                continue
            text, found = explain_finding(child, finding_id)
            if found:
                hits.append(f"[{child.name}]\n{text}")
    if not hits:
        return (f"finding {finding_id} not found under {base}/ "
                 f"(no output dir contained it)"), False
    return "\n\n".join(hits), True
