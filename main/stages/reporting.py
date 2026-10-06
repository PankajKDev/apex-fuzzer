"""Reporting tail: leads, Burp handoff, reviews, report, audit.

Everything here reads artifacts and writes artifacts — zero network.
"""
import time
from pathlib import Path
from typing import List, Tuple

from ..leads import collect_leads, write_leads
from ..logging_setup import get_logger
from ..models import (RESULT_STATUSES, Finding, read_jsonl)
from ..reporting.burp import export_burp
from ..reporting.coverage import CoverageTracker
from ..reporting.html import render_html
from ..reporting.metrics import Metrics
from ..reporting.reviews import load_reviews
from ..reporting.run_store import RunStore, diff_endpoint_runs

log = get_logger("stages-reporting")


def takeover_notes_from_file(path: Path) -> List[str]:
    """Vulnerable-host lines from subzy stdout.

    Subzy prints banner/config lines even with zero hits; only lines
    naming a vulnerable host become leads. Pure file read, no network.
    """
    import re as _re
    notes: List[str] = []
    try:
        text = path.read_text(errors="ignore")
    except OSError:
        return []
    for line in text.splitlines():
        clean = _re.sub(r"\x1b\[[0-9;]*m", "", line).strip()
        # subzy prints banner/config lines even with zero hits; only
        # lines naming a vulnerable host become leads. Flag
        # descriptions (e.g. --hide_fails) mention "vulnerable" too,
        # so lines documenting a CLI flag are excluded.
        if clean and "vuln" in clean.lower() and "(--" not in clean:
            notes.append(clean)
        if len(notes) >= 20:
            break
    return notes


def collect_leads_bundle(out_dir: Path, endpoints, metrics: Metrics):
    """Ranked follow-ups plus the Burp manual-testing handoff."""
    takeover = takeover_notes_from_file(out_dir / "takeover.txt")
    tech_dicts = read_jsonl(out_dir / "technologies.jsonl")
    js_intel = {}
    intel_file = out_dir / "js_intel.json"
    if intel_file.exists():
        try:
            import json as _json
            data = _json.loads(intel_file.read_text(errors="ignore")
                               or "{}")
            if isinstance(data, dict):
                js_intel = data
        except Exception as exc:
            log.debug("leads: js intel unreadable: %s", exc)
    api_diff = {}
    diff_file = out_dir / "api_diff.json"
    if diff_file.exists():
        try:
            import json as _json
            data = _json.loads(diff_file.read_text(errors="ignore")
                               or "{}")
            if isinstance(data, dict):
                api_diff = data
        except Exception as exc:
            log.debug("leads: api diff unreadable: %s", exc)
    leads = collect_leads(endpoints, tech_dicts, takeover, js_intel,
                          api_diff)
    write_leads(out_dir / "leads.jsonl", leads)
    metrics.leads_total = len(leads)
    log.info("leads: %d ranked follow-ups -> leads.jsonl", len(leads))
    burp_summary = export_burp(out_dir, endpoints, leads)
    log.info("burp: %d requests + sitemap + checklist -> burp/",
             burp_summary["requests"])
    return leads, burp_summary


def apply_reviews(findings: List[Finding],
                  out_dir: Path) -> int:
    """Attach operator review marks to findings (report-time).

    Marks surface in ``false_positive_notes`` (rendered by the
    HTML report) and ``raw.review`` (persisted to findings.jsonl),
    so triage decisions stick across runs via stable finding IDs.
    Returns the number of marked findings.
    """
    index = load_reviews(out_dir / "reviews.jsonl")
    if not len(index):
        return 0
    marked = 0
    for f in findings or []:
        record = index.verdict_for_finding(getattr(f, "id", ""))
        if not record:
            continue
        verdict, reason = record["verdict"], record["reason"]
        note = f"Operator review ({verdict})" + \
               (f": {reason}" if reason else "")
        existing = str(getattr(f, "false_positive_notes", "") or "")
        f.false_positive_notes = (
            f"{existing} [{note}]" if existing else note)
        try:
            f.raw["review"] = record
        except (TypeError, AttributeError):
            pass
        marked += 1
    if marked:
        log.info("reviews: %d finding(s) marked", marked)
    return marked


def flush_run_audit(out_dir: Path, target: str, host: str,
                    started_epoch: float, denials, cfg, profile,
                    last_endpoints) -> dict:
    """Persist the run + scope-gate audit trail to apex.db.

    Best-effort by design: a store failure logs and never fails
    the scan (artifacts on disk stay the system of record).
    Returns the endpoint-change diff (for the report), or {}.
    """
    try:
        from datetime import datetime, timezone
        from .. import __version__
        started_utc = datetime.fromtimestamp(
            started_epoch, tz=timezone.utc).isoformat(
                timespec="seconds")
        with RunStore(out_dir / "apex.db") as store:
            previous = store.latest_run(target)
            if previous is not None and \
                    not previous.get("finished_utc"):
                # an interrupted run leaves partial inventory:
                # never diff against it, wait for a clean baseline
                previous = None
            run_id = store.begin_run(
                target, host,
                profile=getattr(profile, "name", "standard"),
                tool_version=str(__version__),
                authorization_ref=str(
                    cfg.safety.authorization_ref or ""),
                started_utc=started_utc)
            stored = store.record_denials(run_id, denials)
            inventoried = store.record_endpoints(
                run_id, list(last_endpoints or []))
            previous_rows = [] if previous is None else \
                store.endpoints_for_run(previous["id"])
            current_rows = store.endpoints_for_run(run_id)
            changes = diff_endpoint_runs(previous_rows,
                                         current_rows)
            changes["against_run"] = (previous or {}).get("id")
            import json as _json
            (out_dir / "changes.json").write_text(
                _json.dumps(changes, indent=2))
            store.finish_run(run_id)
        if stored:
            log.info("audit: %d scope denial(s) -> apex.db",
                     stored)
        log.debug("audit: %d endpoint(s) -> apex.db", inventoried)
        if not changes.get("baseline"):
            log.info("changes: %d new, %d changed, %d gone "
                     "(vs run %s) -> changes.json",
                     len(changes["new"]), len(changes["changed"]),
                     len(changes["gone"]), changes["against_run"])
        else:
            log.info("changes: baseline established (%d endpoints) "
                     "-> changes.json", len(current_rows))
        return changes
    except Exception as e:
        log.debug("run audit skipped: %s", e)
        return {}


def render_report(out_dir: Path, target: str, host: str,
                  started_epoch: float, findings: List[Finding],
                  hypotheses: list, metrics: Metrics,
                  coverage: CoverageTracker, budgets, ck, cfg,
                  profile, client, safety_info, endpoints,
                  last_endpoints) -> Tuple[list, dict]:
    """Leads, reviews, metrics, audit flush, and the HTML report."""
    leads, burp_summary = collect_leads_bundle(out_dir, endpoints,
                                               metrics)
    apply_reviews(findings, out_dir)
    ck.mark("report", "running")
    metrics.scan_duration_seconds = time.time() - started_epoch
    metrics.result_status_counts = {status: sum(
        1 for finding in findings
        if finding.result_status == status)
        for status in RESULT_STATUSES}
    metrics.write(out_dir / "metrics.json")
    import json as _json
    (out_dir / "coverage.json").write_text(
        _json.dumps(coverage.to_dict(), indent=2))
    ck.save_blob("coverage", coverage.to_dict())
    ck.save_blob("budgets", budgets.to_dict())
    changes = flush_run_audit(
        out_dir, target, host, started_epoch,
        getattr(client, "scope_denials", None) or [], cfg, profile,
        last_endpoints) or {}
    from ..chains.builder import load_chains
    render_html(out_dir / "report.html", target, findings,
                [h.to_dict() for h in hypotheses],
                metrics.to_dict(),
                min_severity=cfg.reporting.min_severity,
                output_dir=out_dir,
                coverage=coverage.to_dict(),
                safety_info=safety_info,
                leads=leads,
                burp=burp_summary,
                changes=changes or None,
                chains=load_chains(out_dir))
    try:
        from ..validation.evidence import EvidenceStore
        manifest_path = EvidenceStore(
            out_dir / "proofs").write_manifest()
        log.info("evidence integrity manifest -> %s", manifest_path)
    except Exception as e:
        log.debug("integrity manifest skipped: %s", e)
    ck.mark("report")
    log.info("done: %s (%.1fs)", host, metrics.scan_duration_seconds)
    from ..reporting.sarif import write_sarif
    from .. import __version__
    try:
        write_sarif(out_dir, [f.to_dict() for f in findings],
                    str(__version__))
    except Exception as e:
        log.debug("sarif export skipped: %s", e)
    return leads, burp_summary
