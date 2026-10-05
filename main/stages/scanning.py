"""Scanning stage: live probing, takeover checks, Nuclei DAST.

Wraps external enumeration binaries (httpx, tko-subs, subzy, nuclei).
Every subprocess input is scope-filtered first — these tools follow
redirects themselves, outside the gate — and every output is
scope-filtered before it becomes a finding.
"""
import csv
from pathlib import Path
from typing import List, Optional, Set, Tuple
from urllib.parse import urlparse

from ..detection.nuclei import NucleiRunner, correlate
from ..logging_setup import get_logger
from ..models import (Confidence, Finding, ValidationStatus, read_jsonl,
                      write_jsonl)
from ..reporting.coverage import CoverageTracker
from ..reporting.metrics import Metrics
from ..shell import redact, run, which
from .recon import scoped_subprocess_input

log = get_logger("stages-scanning")

LIVE_CODES = "200,204,301,302,401,403,405,500,502,503,504"


def probe_live(cfg, scope, out_dir: Path, live_file: Path):
    probe_input = scoped_subprocess_input(
        scope, out_dir, "raw.txt", "probe-input.txt")
    if probe_input.stat().st_size == 0:
        log.warning("nothing to probe — no in-scope URLs")
        live_file.write_text("")
        return
    if not which("httpx"):
        log.warning("httpx missing — falling back to in-scope raw set")
        live_file.write_text(probe_input.read_text())
        return
    r = run([
        "httpx", "-silent",
        "-mc", LIVE_CODES,
        "-l", str(probe_input),
        "-o", str(live_file),
    ], timeout=cfg.scan.timeout * 2)
    if r.timed_out:
        log.warning("httpx timed out")
    if not live_file.exists():
        live_file.write_text("")


def takeover_check(cfg, profile, scope, out_dir: Path, host: str,
                   metrics: Metrics,
                   coverage: Optional[CoverageTracker] = None
                   ) -> List[Finding]:
    raw = out_dir / "raw.txt"
    if not raw.exists():
        return []
    hosts: Set[str] = set()
    for line in raw.read_text(errors="ignore").splitlines():
        try:
            h = urlparse(line.strip()).hostname
            if h and scope.is_in_scope(f"https://{h}/"):
                hosts.add(h)
        except Exception:
            continue
    if not hosts:
        return []
    hosts_file = out_dir / "hosts.txt"
    hosts_file.write_text("\n".join(sorted(hosts)))

    # confirmed takeover via tko-subs -takeover (github/heroku tokens)
    if profile.run_tko and which("tko-subs"):
        tko_out = out_dir / "tko.csv"
        args = ["tko-subs", "-domains", str(hosts_file),
                "-output", str(tko_out)]
        import os
        if os.environ.get("GITHUB_TOKEN"):
            args += ["-takeover",
                     "-githubtoken", os.environ["GITHUB_TOKEN"],
                     "-herokuusername",
                     os.environ.get("HEROKU_USERNAME", ""),
                     "-herokuapikey", os.environ.get("HEROKU_API_KEY", ""),
                     "-herokuappname",
                     os.environ.get("HEROKU_APP_NAME", "")]
        log.info("tko-subs: checking %d hosts (%s)",
                 len(hosts),
                 "confirmed takeover" if "-takeover" in args
                 else "fingerprint only")
        r = run(args, timeout=cfg.scan.timeout * 2)
        if r.stdout:
            (out_dir / "takeover.txt").write_text(redact(r.stdout))
        if tko_out.exists():
            return parse_tko(tko_out, metrics, coverage)
    # fallback: subzy fingerprint (detection-only)
    if which("subzy"):
        log.info("subzy: checking %d hosts", len(hosts))
        r = run([
            "subzy", "run",
            "--targets", str(hosts_file),
            "--hide_fails", "--https",
            "--timeout", "10",
        ], timeout=cfg.scan.timeout * 2)
        if r.stdout:
            (out_dir / "takeover.txt").write_text(redact(r.stdout))
    return []


def parse_tko(tko_csv: Path, metrics: Metrics,
              coverage: Optional[CoverageTracker] = None
              ) -> List[Finding]:
    """tko-subs CSV: Domain,CNAME,Provider,IsVulnerable,IsTakenOver,Resp"""
    findings: List[Finding] = []
    try:
        with open(tko_csv) as f:
            for row in csv.DictReader(f):
                domain = (row.get("Domain") or "").strip()
                vuln = (row.get("IsVulnerable") or "").lower()
                taken = (row.get("IsTakenOver") or "").lower()
                provider = row.get("Provider") or "unknown"
                if not domain or vuln != "true":
                    continue
                confirmed = taken == "true"
                metrics.takeover_confirmed += 1
                if coverage is not None:
                    coverage.record(
                        "takeover",
                        "confirmed" if confirmed else "candidate",
                        f"tko-subs: {domain} ({provider})")
                findings.append(Finding(
                    id=f"takeover-{domain}",
                    source="tko-subs" if confirmed else "tko-subs-fp",
                    name=(f"Subdomain takeover CONFIRMED — {domain} "
                          f"({provider})" if confirmed
                          else f"Subdomain takeover candidate — "
                               f"{domain} ({provider})"),
                    severity="high",
                    confidence=(Confidence.CONFIRMED.value
                                if confirmed else
                                Confidence.PROBABLE.value),
                    validation_status=(
                        ValidationStatus.CONFIRMED.value
                        if confirmed else
                        ValidationStatus.STRONG_CANDIDATE.value),
                    host=domain,
                    matched_at=f"https://{domain}/",
                    endpoint_url=f"https://{domain}/",
                    method="GET",
                    response_status=200 if not confirmed else None,
                    description=(
                        f"CNAME {row.get('CNAME', '')} points to an "
                        f"unclaimed {provider} resource."
                        + (" The resource was claimed during the scan "
                           "to confirm control." if confirmed else
                           " No takeover performed — fingerprint only.")),
                    tags=["subdomain-takeover", provider],
                    raw={"provider": provider,
                         "cname": row.get("CNAME", ""),
                         "response": (row.get("Response") or "")[:500]},
                ))
    except Exception as e:
        log.warning("tko csv parse failed: %s", e)
    if findings:
        log.info("takeover: %d candidate(s)", len(findings))
    return findings


def run_nuclei_stage(cfg, profile, scope, out_dir: Path,
                     live_file: Path, nuclei: NucleiRunner,
                     findings: List[Finding], metrics: Metrics,
                     coverage: CoverageTracker, ck, resume: bool
                     ) -> Tuple[List[Finding], List[Finding]]:
    """Nuclei DAST over the live set; take over prior findings on resume.

    Returns (findings, fresh_nuclei): takeover/tko findings seed the
    list and nuclei findings append, exactly as before.
    """
    if not profile.run_nuclei:
        ck.mark("nuclei", "skipped")
        return findings, []
    if resume and ck.is_complete("nuclei"):
        findings = [Finding.from_dict(d) for d in
                    read_jsonl(out_dir / "findings.jsonl")]
        # resume: re-derive floor coverage from stored findings
        fresh_nuclei = [f for f in findings
                        if f.source.startswith("nuclei")]
    else:
        ck.mark("nuclei", "running")
        raw_findings = nuclei.run_scan(live_file)
        metrics.nuclei_findings = len(raw_findings)
        deduped = correlate(raw_findings)
        metrics.nuclei_findings_after_dedup = len(deduped)
        deduped = [f for f in deduped
                   if scope.is_in_scope(f.matched_at)]
        findings = findings + deduped
        write_jsonl(out_dir / "findings.jsonl", findings)
        ck.mark("nuclei")
        fresh_nuclei = deduped
    # nuclei matches are candidates, never confirmations (§57)
    for f in fresh_nuclei:
        coverage.record(_classify(f), "candidate",
                        f"nuclei template {f.template_id}")
    return findings, fresh_nuclei
def _classify(finding: Finding) -> str:
    """Nuclei finding → coverage class."""
    from ..reporting.coverage import classify_finding
    return classify_finding(finding)
