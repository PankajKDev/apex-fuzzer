"""Structured HTML report.

Spec §11: each finding now carries an impact statement, numbered
reproduction steps, false-positive considerations, and direct links to
the evidence files.
"""
import html as _h
from pathlib import Path
from typing import List, Dict, Optional
from ..models import Finding, ValidationStatus
from ..validation.evidence import build_reproduction
from .impact import build_impact, build_repro_steps, build_fp_notes

ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
MIN_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def render_html(output: Path, target: str, findings: List[Finding],
                hypotheses: List[Dict], metrics: Dict,
                min_severity: str = "info",
                output_dir: Optional[Path] = None,
                coverage: Optional[Dict] = None,
                safety_info: Optional[Dict] = None) -> None:
    min_rank = MIN_RANK.get(min_severity, 0)
    findings = [f for f in findings
                if MIN_RANK.get(f.severity, 4) >= min_rank]
    findings.sort(key=lambda f: ORDER.get(f.severity, 5))
    confirmed = [f for f in findings
                 if f.validation_status == ValidationStatus.CONFIRMED.value]
    strong = [f for f in findings
              if f.validation_status ==
              ValidationStatus.STRONG_CANDIDATE.value]
    informational = [f for f in findings
                     if f.validation_status in
                     (ValidationStatus.NOT_TESTED.value,
                      ValidationStatus.INCONCLUSIVE.value)]
    parts = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'>",
        f"<title>Apex-Fuzzer — {_h.escape(target)}</title>",
        _CSS, "</head><body>",
        "<h1>⚡ Apex-Fuzzer Report</h1>",
        f"<p class='target'>Target: <b>{_h.escape(target)}</b></p>",
        _metrics_block(metrics),
        _coverage_block(coverage),
        _safety_block(safety_info),
        _section("🟥 Confirmed", confirmed, output_dir),
        _section("🟧 Strong Candidates", strong, output_dir),
        _section("🟦 Informational & Untested", informational, output_dir),
        _hypotheses_block(hypotheses),
        "</body></html>"]
    output.write_text("".join(parts))


_CSS = """<style>
body{background:#0f1115;color:#e6e6e6;font-family:'Segoe UI',sans-serif;padding:40px;line-height:1.5}
h1{color:#ff5c5c} h2{margin-top:40px;border-bottom:1px solid #333;padding-bottom:8px}
.summary{display:flex;flex-wrap:wrap;gap:12px;margin:20px 0}
.box{background:#1a1d23;padding:12px 20px;border-radius:8px;border-left:4px solid #333;min-width:130px}
.box b{display:block;font-size:20px;color:#00ffcc}
.crit{border-color:#ff4444;color:#ff4444} .high{border-color:#ff8800}
.med{border-color:#ffcc00} .low{border-color:#00ccff} .info{border-color:#aaa}
table{width:100%;border-collapse:collapse;background:#1a1d23;border-radius:8px;overflow:hidden;margin-top:12px}
th,td{padding:10px 12px;border-bottom:1px solid #2a2d33;text-align:left;vertical-align:top}
th{background:#232730;color:#00ffcc}
.sev{font-weight:bold;text-transform:uppercase;font-size:12px}
a{color:#00ffcc;text-decoration:none}
code{font-size:11px;color:#9aa0a6;background:#0b0d10;padding:2px 4px;border-radius:3px;word-break:break-all}
.status{font-size:11px;padding:2px 6px;border-radius:4px;background:#232730;color:#9aa0a6}
.status.confirmed{background:#3a1414;color:#ff8888}
.status.strong{background:#3a2a14;color:#ffbb66}
.status.hypothesis{background:#122a3a;color:#66c6ff}
tr.detail td{background:#14171d;padding:10px 16px;border-bottom:1px solid #1f232b}
.detail .impact{color:#ffd28a;margin-bottom:8px}
.detail ol{margin:4px 0 8px 22px;padding:0}
.detail li{margin:2px 0;font-size:13px}
.detail .fp{color:#9aa0a6;font-size:12px}
</style>"""


def _metrics_block(m: Dict) -> str:
    keys = [("URLs", m.get("urls_discovered")),
            ("Endpoints", m.get("unique_endpoints")),
            ("Params", m.get("parameters_discovered")),
            ("Arjun params", m.get("arjun_params_found")),
            ("JS files", m.get("js_files_analyzed")),
            ("Techs", m.get("technologies_detected")),
            ("Live hosts", m.get("live_hosts")),
            ("Nuclei", m.get("nuclei_findings")),
            ("After dedup", m.get("nuclei_findings_after_dedup")),
            ("Validated", m.get("validated_confirmed")),
            ("OAST confirmed", m.get("oast_confirmed")),
            ("BOLA/IDOR", m.get("differential_candidates")),
            ("Authz matrix", m.get("authorization_confirmed")),
            ("Stored XSS", m.get("second_order_candidates")),
            ("Biz logic", m.get("business_logic_candidates")),
            ("Race", m.get("race_candidates")),
            ("Inv violated", m.get("invariants_violated")),
            ("Verified fx", m.get("effects_verified")),
            ("Logins", m.get("logins_succeeded")),
            ("Graph", f"{m.get('graph_nodes', 0)}/"
                      f"{m.get('graph_edges', 0)}"),
            ("Flows", m.get("workflows_discovered")),
            ("Hypotheses", m.get("hypotheses_generated")),
            ("Hyp. validated", m.get("hypotheses_validated")),
            ("Takeovers", m.get("takeover_confirmed")),
            ("WAF", m.get("waf_detected")),
            ("Duration", f"{m.get('scan_duration_seconds', 0):.1f}s")]
    boxes = "".join(
        f"<div class='box'>{_h.escape(k)}<b>{v}</b></div>"
        for k, v in keys if v is not None)
    return f"<div class='summary'>{boxes}</div>"


def _section(title: str, findings: List[Finding],
             output_dir: Optional[Path] = None) -> str:
    if not findings:
        return f"<h2>{title} (0)</h2><p>None.</p>"
    rows = "".join(_finding_row(f, output_dir) for f in findings)
    return (f"<h2>{title} ({len(findings)})</h2>"
            f"<table><tr><th>Severity</th><th>Name</th>"
            f"<th>Endpoint</th><th>Status</th>"
            f"<th>Reproduction</th></tr>{rows}</table>")


def _coverage_block(coverage: Optional[Dict]) -> str:
    """Per-class test coverage (§44–45): tested vs explicitly untested."""
    if not coverage:
        return ""
    status = coverage.get("status") or {}
    known = coverage.get("known") or sorted(status.keys())
    if not known:
        return ""
    chips = "".join(
        f"<span class='status cov-{_h.escape(status.get(c, 'not_tested'))}'>"
        f"{_h.escape(c)}: {_h.escape(status.get(c, 'not_tested'))}</span>"
        for c in known)
    untested = [c for c in known
                if status.get(c, "not_tested") in ("not_tested",
                                                   "inconclusive")]
    note = ""
    if untested:
        note = (f"<p><em>Untested attack classes "
                f"({len(untested)}): "
                f"{_h.escape(', '.join(untested))}. Absence of findings "
                f"for these classes means they were not tested — not "
                f"that they are secure.</em></p>")
    return (f"<h2>📊 Coverage</h2><p>{chips}</p>{note}")


def _safety_block(safety_info: Optional[Dict]) -> str:
    """Authorization metadata for the run. Reference identifiers only —
    never document content, never secrets (the model holds none)."""
    if not safety_info:
        return ""
    auth = safety_info.get("authorization") or {}
    rows = "".join(
        f"<tr><td>{_h.escape(k)}</td><td>{_h.escape(str(v))}</td></tr>"
        for k, v in [
            ("strict mode",
             "on" if safety_info.get("strict") else "off"),
            ("max impact", safety_info.get("max_impact", "")),
            ("authorization ref", auth.get("reference") or "—"),
            ("gated modules",
             ", ".join(safety_info.get("gated_modules") or []) or "—"),
            ("validity",
             f"{auth.get('valid_from') or '…'} → "
             f"{auth.get('valid_until') or '…'}"),
        ])
    refused = ""
    if safety_info.get("refusal"):
        refused = "<p><em>Refused (this run did not execute): " + \
            _h.escape("; ".join(safety_info["refusal"])) + "</em></p>"
    return (f"<h2>🛡 Authorization &amp; Safety</h2>"
            f"<table>{rows}</table>{refused}")


def _evidence_links(f: Finding, output_dir: Optional[Path]) -> str:
    """Direct links into the evidence directory (relative to the report)."""
    if not f.evidence_dir or output_dir is None:
        return ""
    try:
        rel = Path(f.evidence_dir).relative_to(output_dir)
    except ValueError:
        return ""
    links = []
    for name in ("response.txt", "request.txt", "metadata.json"):
        if (Path(f.evidence_dir) / name).exists():
            links.append(
                f"<a href='{_h.escape(str(rel / name))}'>{name}</a>")
    if not links:
        return ""
    return ("<br><small>📁 evidence: "
            + " · ".join(links) + "</small>")


def _finding_row(f: Finding, output_dir: Optional[Path] = None) -> str:
    status_cls = ""
    if f.validation_status == ValidationStatus.CONFIRMED.value:
        status_cls = "confirmed"
    elif f.validation_status == ValidationStatus.STRONG_CANDIDATE.value:
        status_cls = "strong"
    repro = _h.escape(build_reproduction(f))
    # ── triage layer (spec §11) ────────────────────────────────────────
    impact = build_impact(f)
    steps = build_repro_steps(f)
    fp = build_fp_notes(f)
    steps_html = "".join(f"<li>{_h.escape(s)}</li>" for s in steps)
    ev_links = _evidence_links(f, output_dir)
    detail = (
        f"<tr class='detail'><td colspan='5'>"
        f"<div class='impact'><b>Impact:</b> "
        f"{_h.escape(impact)}</div>"
        f"<div><b>Reproduction steps:</b>"
        f"<ol>{steps_html}</ol></div>"
        f"<div class='fp'><b>False-positive checks:</b> "
        f"{_h.escape(fp)}</div>"
        f"{ev_links}"
        f"</td></tr>")
    return (f"<tr>"
            f"<td class='sev {f.severity}'>{_h.escape(f.severity)}</td>"
            f"<td>{_h.escape(f.name or f.template_id or '')}"
            f"<br><small>{_h.escape(f.source)}</small></td>"
            f"<td><a href='{_h.escape(f.matched_at)}' target='_blank'>"
            f"{_h.escape(f.matched_at)}</a>{ev_links}</td>"
            f"<td><span class='status {status_cls}'>"
            f"{_h.escape(f.validation_status)}</span></td>"
            f"<td><code>{repro}</code></td></tr>"
            f"{detail}")


def _hypotheses_block(hypotheses: List[Dict]) -> str:
    if not hypotheses:
        return ""
    validated = [h for h in hypotheses
                 if h.get("status") in ("validated", "rejected",
                                        "inconclusive")]
    pending = [h for h in hypotheses if h not in validated]

    def row(h: Dict) -> str:
        st = h.get("status", "hypothesized")
        cls = {"validated": "confirmed", "rejected": "",
               "inconclusive": ""}.get(st, "hypothesis")
        note = _h.escape(str(h.get("notes") or ""))
        return (f"<tr><td>{_h.escape(h.get('test_class', ''))}</td>"
                f"<td>{_h.escape(str(h.get('endpoint') or ''))}</td>"
                f"<td>{_h.escape(h.get('hypothesis', ''))}</td>"
                f"<td>{h.get('confidence', 0):.2f}</td>"
                f"<td><span class='status {cls}'>{_h.escape(st)}</span>"
                f"{'<br><small>' + note + '</small>' if note else ''}"
                f"</td></tr>")

    parts = [f"<h2>🧠 AI Hypotheses ({len(hypotheses)})</h2>",
             "<p><em>AI-generated; <b>validated</b> items were fed back "
             "into deterministic testing (OAST / sqlmap / differential / "
             "nuclei) — others remain unconfirmed and are not findings."
             "</em></p>"]
    if validated:
        parts.append("<h3>Validated / rejected by the pipeline</h3>"
                     "<table><tr><th>Class</th><th>Endpoint</th>"
                     "<th>Hypothesis</th><th>Conf</th>"
                     "<th>Status</th></tr>"
                     + "".join(row(h) for h in validated) + "</table>")
    if pending:
        parts.append("<h3>Hypothesized (not yet tested)</h3>"
                     "<table><tr><th>Class</th><th>Endpoint</th>"
                     "<th>Hypothesis</th><th>Conf</th>"
                     "<th>Status</th></tr>"
                     + "".join(row(h) for h in pending) + "</table>")
    return "".join(parts)
