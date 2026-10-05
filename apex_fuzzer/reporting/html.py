"""Structured HTML report.

Spec §11: each finding now carries an impact statement, numbered
reproduction steps, false-positive considerations, and direct links to
the evidence files.
"""
import html as _h
from pathlib import Path
from typing import List, Dict, Optional
from ..models import Finding, ResultStatus
from ..validation.evidence import build_reproduction
from .impact import build_impact, build_repro_steps, build_fp_notes

ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
MIN_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def render_html(output: Path, target: str, findings: List[Finding],
                hypotheses: List[Dict], metrics: Dict,
                min_severity: str = "info",
                output_dir: Optional[Path] = None,
                coverage: Optional[Dict] = None,
                safety_info: Optional[Dict] = None,
                leads: Optional[List[Dict]] = None,
                burp: Optional[Dict] = None,
                changes: Optional[Dict] = None) -> None:
    min_rank = MIN_RANK.get(min_severity, 0)
    findings = [f for f in findings
                if MIN_RANK.get(f.severity, 4) >= min_rank]
    findings.sort(key=lambda f: ORDER.get(f.severity, 5))
    verified = [f for f in findings
                if f.result_status == ResultStatus.VERIFIED_EFFECT.value]
    candidates = [f for f in findings
                  if f.result_status == ResultStatus.CANDIDATE.value]
    informational = [f for f in findings
                     if f.result_status in
                     (ResultStatus.OBSERVATION.value,
                      ResultStatus.INCONCLUSIVE.value)]
    parts = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'>",
        f"<title>Apex-Fuzzer — {_h.escape(target)}</title>",
        _CSS, "</head><body>",
        "<h1>⚡ Apex-Fuzzer Report</h1>",
        f"<p class='target'>Target: <b>{_h.escape(target)}</b></p>",
        _metrics_block(metrics),
        _coverage_block(coverage),
        _safety_block(safety_info),
        _section("🟥 Verified Effects", verified, output_dir),
        _section("🟧 Candidates", candidates, output_dir),
        _section("🟦 Observations & Inconclusive", informational,
                 output_dir),
        _changes_block(changes),
        _leads_block(leads),
        _burp_block(burp),
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
tr.group td{background:#1f232b;color:#ffbb66;font-weight:bold}
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
            ("Stored SSRF", m.get("second_order_ssrf_confirmed")),
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
    result_counts = m.get("result_status_counts") or {}
    if result_counts:
        counts_text = ", ".join(
            f"{k}: {v}" for k, v in sorted(result_counts.items()))
        keys.append(("Result statuses", counts_text))
    boxes = "".join(
        f"<div class='box'>{_h.escape(k)}<b>{v}</b></div>"
        for k, v in keys if v is not None)
    return f"<div class='summary'>{boxes}</div>"


def _collapse_key(f: Finding):
    """Group key for combinatorial findings (swap/matrix replays).

    One finding per (victim × tester) explodes the report; grouping by
    (source, endpoint, method, parameter) keeps every evidence trail
    while triaging as one authorization gap.
    """
    from ..discovery.url_normalizer import normalize_url
    try:
        norm = normalize_url(f.endpoint_url or f.matched_at or "")
    except Exception:
        norm = f.endpoint_url or f.matched_at or ""
    return (f.source or "", norm, (f.method or "GET").upper(),
            f.parameter or "")


def _group_header(key, members: List[Finding]) -> str:
    source, norm, method, param = key
    testers = sorted({str(getattr(m, "identity", "") or "")
                      for m in members} - {""})
    objects = {str(getattr(m, "resource_key", "") or "")
               for m in members} - {""}
    detail = (f"testers: {', '.join(testers)}"
              if testers else f"{len(members)} finding(s)")
    if objects:
        detail += f" · objects: {len(objects)}"
    return (
        f"<tr class='group'><td colspan='5'>"
        f"↳ {len(members)}× {_h.escape(source)} — "
        f"<code>{_h.escape(method)} {_h.escape(norm)}</code>"
        f"{f' :: <code>{_h.escape(param)}</code>' if param else ''}"
        f"<br><small>{_h.escape(detail)} — one gap, "
        f"per-object evidence below</small></td></tr>")


def _section(title: str, findings: List[Finding],
             output_dir: Optional[Path] = None) -> str:
    if not findings:
        return f"<h2>{title} (0)</h2><p>None.</p>"
    groups: Dict[tuple, List[Finding]] = {}
    for f in findings:
        groups.setdefault(_collapse_key(f), []).append(f)
    parts = []
    for key, members in groups.items():
        if len(members) > 1:
            parts.append(_group_header(key, members))
        parts.extend(_finding_row(m, output_dir) for m in members)
    return (f"<h2>{title} ({len(findings)})</h2>"
            f"<table><tr><th>Severity</th><th>Name</th>"
            f"<th>Endpoint</th><th>Status</th>"
            f"<th>Reproduction</th></tr>{''.join(parts)}</table>")


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


def _changes_block(changes: Optional[Dict]) -> str:
    """Attack-surface change since the previous finished run."""
    if not changes or changes.get("baseline"):
        return ""
    rows = []
    for item in changes.get("new", []) or []:
        rows.append(
            f"<tr><td class='sev'>new</td>"
            f"<td><code>{_h.escape(item.get('method', ''))} "
            f"{_h.escape(item.get('normalized_url', ''))}</code></td>"
            f"<td>{_h.escape(item.get('endpoint_type', ''))}</td></tr>")
    for item in changes.get("changed", []) or []:
        rows.append(
            f"<tr><td class='sev'>changed</td>"
            f"<td><code>{_h.escape(item.get('method', ''))} "
            f"{_h.escape(item.get('url', ''))}</code></td>"
            f"<td>params/type/content changed since run "
            f"{_h.escape(str(changes.get('against_run', '')))}</td></tr>")
    for item in changes.get("gone", []) or []:
        rows.append(
            f"<tr><td class='sev'>gone</td>"
            f"<td><code>{_h.escape(item.get('method', ''))} "
            f"{_h.escape(item.get('normalized_url', ''))}</code></td>"
            f"<td>—</td></tr>")
    if not rows:
        return ""
    return (f"<h2>🔄 Surface changes (vs run "
            f"{_h.escape(str(changes.get('against_run', '')))})</h2>"
            f"<p><em>New or changed endpoints deserve first testing "
            f"priority on the next run.</em></p>"
            f"<table><tr><th>Change</th><th>Endpoint</th>"
            f"<th>Detail</th></tr>{''.join(rows)}</table>")


def _leads_block(leads: Optional[List[Dict]]) -> str:
    """Ranked follow-ups, not verdicts: what to test next and how."""
    if not leads:
        return ""
    rows = "".join(
        f"<tr><td class='sev'>{_h.escape(lead.get('priority', ''))}</td>"
        f"<td><code>{_h.escape(lead.get('kind', ''))}</code><br>"
        f"{_h.escape(lead.get('reason', ''))}</td>"
        f"<td><code>{_h.escape(lead.get('url', '') or '—')}</code>"
        f"{('<br>param: <code>' + _h.escape(lead['param']) + '</code>') if lead.get('param') else ''}</td>"
        f"<td>{_h.escape(lead.get('suggested_followup', ''))}</td></tr>"
        for lead in leads)
    return (f"<h2>🧭 Leads ({len(leads)})</h2>"
            f"<p><em>Discovered-but-untested surface. A lead is not a "
            f"vulnerability — it names the follow-up run that would test "
            f"it.</em></p>"
            f"<table><tr><th>Priority</th><th>Lead</th>"
            f"<th>Where</th><th>Suggested follow-up</th></tr>{rows}</table>")


def _burp_block(burp: Optional[Dict]) -> str:
    """Burp handoff note: what was exported for manual verification."""
    if not burp:
        return ""
    return (f"<h2>🔌 Burp handoff</h2>"
            f"<p><code>burp/urls.txt</code> (scope seed), "
            f"<code>burp/requests/</code> ({burp.get('requests', 0)} raw "
            f"requests — paste into Repeater), "
            f"<code>burp/sitemap.xml</code> (Burp site-map schema), "
            f"<code>burp/lead-checklist.md</code> (per-lead Burp clicks)."
            f"</p>")


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
    if f.result_status == ResultStatus.VERIFIED_EFFECT.value:
        status_cls = "confirmed"
    elif f.result_status == ResultStatus.CANDIDATE.value:
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
            f"{_h.escape(f.result_status or 'observation')}</span>"
            f"<br><small>legacy: "
            f"{_h.escape(f.validation_status)}</small></td>"
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
