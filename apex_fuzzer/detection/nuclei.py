"""Nuclei runner + structured JSONL correlation.

Upgrades (spec §5):
- bug-bounty-specific template dir (IDOR / SSRF / JWT / WAF / secrets)
  run alongside the main community set;
- ``-workflow`` support for multi-step conditional templates;
- ``generate_template_for_hypothesis`` turns an AI hypothesis into a
  runnable Nuclei template so the planner's output closes the loop.
"""
import json
import hashlib
from pathlib import Path
from typing import List, Dict, Optional
from ..shell import run, which, tool_version
from ..models import Finding, Confidence, ValidationStatus
from ..logging_setup import get_logger

log = get_logger("nuclei")


class NucleiRunner:
    def __init__(self, cfg, output_dir: Path):
        self.cfg = cfg
        self.output_dir = output_dir
        self.jsonl = output_dir / "nuclei.jsonl"
        self.templates_dir = Path.home() / "nuclei-templates"
        nc = getattr(cfg, "nuclei", None)
        self.bb_templates_dir = (
            Path(str(getattr(nc, "bb_templates_dir",
                             "~/nuclei-bb-templates"))).expanduser()
            if nc else None)
        self.workflows = bool(getattr(nc, "workflows", False)) \
            if nc else False

    def check_ready(self) -> bool:
        if not which("nuclei"):
            log.error("nuclei binary not found")
            return False
        if not self.templates_dir.exists():
            log.error("nuclei-templates not found at %s — run --update",
                      self.templates_dir)
            return False
        log.info("nuclei version: %s", tool_version("nuclei"))
        return True

    def _template_args(self) -> List[str]:
        dirs = [str(self.templates_dir)]
        if self.bb_templates_dir and self.bb_templates_dir.is_dir():
            dirs.append(str(self.bb_templates_dir))
            log.info("nuclei: including BB templates at %s",
                     self.bb_templates_dir)
        else:
            log.debug("nuclei: BB template dir %s not found — "
                      "community set only", self.bb_templates_dir)
        return ["-t", ",".join(dirs)]

    def run_scan(self, live_file: Path,
                 extra_templates_dir: Optional[Path] = None) -> List[Finding]:
        if not self.check_ready():
            return []
        if not live_file.exists() or live_file.stat().st_size == 0:
            log.warning("no live hosts to scan")
            return []
        if self.jsonl.exists():
            self.jsonl.unlink()
        args = [
            "nuclei", "-l", str(live_file),
        ]
        tdirs = [str(self.templates_dir)]
        if extra_templates_dir and extra_templates_dir.is_dir():
            tdirs.append(str(extra_templates_dir))
        if self.bb_templates_dir and self.bb_templates_dir.is_dir():
            tdirs.append(str(self.bb_templates_dir))
        args += ["-t", ",".join(tdirs)]
        if self.workflows:
            args += ["-workflow", "-workflow-threads", "3"]
            log.info("nuclei: workflows enabled")
        args += [
            "-dast", "-rl", str(self.cfg.scan.rate_limit),
            "-jsonl", "-no-color", "-stats",
            "-timeout", "10", "-retries", "1", "-o", str(self.jsonl),
        ]
        log.info("running nuclei (rate=%d, templates=%s)",
                 self.cfg.scan.rate_limit, ",".join(tdirs))
        r = run(args, timeout=self.cfg.scan.timeout * 4, check=False)
        if r.timed_out:
            log.warning("nuclei timed out")
        return self._parse_jsonl()

    def _parse_jsonl(self) -> List[Finding]:
        if not self.jsonl.exists():
            return []
        findings: List[Finding] = []
        with open(self.jsonl) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                info = d.get("info", {}) or {}
                tid = d.get("template-id") or d.get("templateID") or ""
                findings.append(Finding(
                    id=f"nuclei-{tid}-{d.get('matched-at','')}",
                    source="nuclei", template_id=tid,
                    name=info.get("name", ""),
                    severity=(info.get("severity") or "info").lower(),
                    host=d.get("host", ""),
                    matched_at=d.get("matched-at", ""),
                    endpoint_url=d.get("matched-at"),
                    method=(d.get("type") or "GET").upper(),
                    description=info.get("description", "") or "",
                    tags=info.get("tags", []) or [],
                    raw=d,
                    confidence=Confidence.PROBABLE.value,
                    validation_status=ValidationStatus.NOT_TESTED.value,
                    root_cause_key=make_root_cause_key(d),
                ))
        log.info("nuclei returned %d findings", len(findings))
        return findings


def make_root_cause_key(d: Dict) -> str:
    from urllib.parse import urlparse
    try:
        p = urlparse(d.get("matched-at", "")).path
    except Exception:
        p = d.get("matched-at", "")
    tid = d.get("template-id", "")
    param = ""
    ext = d.get("extracted-results") or []
    if ext:
        param = str(ext[0])[:32]
    return f"{tid}::{p}::{param}"


def correlate(findings: List[Finding]) -> List[Finding]:
    by_key: Dict[str, Finding] = {}
    for f in findings:
        key = f.root_cause_key or f.id
        if key in by_key:
            cur = by_key[key]
            order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
            if order.get(f.severity, 0) > order.get(cur.severity, 0):
                by_key[key] = f
        else:
            by_key[key] = f
    return list(by_key.values())


# ── hypothesis → template generation (spec §5c) ────────────────────────

_SEVERITY_BY_CLASS = {
    "ssrf": "high", "sqli": "high", "idor": "high", "authz": "high",
    "bola": "high", "cmdi": "high", "ssti": "high",
    "xss": "medium", "xxe": "medium", "path_traversal": "medium",
    "open_redirect": "medium", "info_disclosure": "low",
}


def hypothesis_slug(h) -> str:
    text = str(getattr(h, "hypothesis", "") or "")[:64].lower()
    text = "".join(c if c.isalnum() else "-" for c in text).strip("-")
    return text[:32] or "hypothesis"


def generate_template_for_hypothesis(h, endpoint_url: str,
                                     method: str = "GET") -> Optional[Dict]:
    """Turn an AI hypothesis into a runnable Nuclei template.

    These templates are *gates*: they fire when the target responds the
    way the hypothesis predicts (200 + expected marker), so follow-up
    exploitation only runs against live behaviour instead of the whole
    asset base.
    """
    if not endpoint_url:
        return None
    from urllib.parse import urlparse
    host = urlparse(endpoint_url).hostname or ""
    slug = hypothesis_slug(h)
    digest = hashlib.md5(
        (slug + '|' + endpoint_url).encode()).hexdigest()[:8]
    tid = f"ai-gen-{digest}"
    words = [w for w in str(getattr(h, "hypothesis", "")).split()[:5]
             if len(w) > 2][:3]
    return {
        "id": tid,
        "info": {
            "name": f"AI hypothesis gate: {slug}",
            "severity": _SEVERITY_BY_CLASS.get(
                str(getattr(h, "test_class", "")).lower(), "medium"),
            "tags": [str(getattr(h, "test_class", "ai")).lower(),
                     "ai-generated", "bugbounty"],
            "description": str(getattr(h, "reason", ""))[:300],
        },
        "requests": [{
            "raw": [
                f"{method.upper()} {endpoint_url} HTTP/1.1\n"
                f"Host: {host}\n"
                f"User-Agent: ApexFuzzer-ai-gate\n\n",
            ],
        }],
        "matchers": [
            {"type": "status", "status": [200]},
        ] + (
            [{"type": "word", "words": words, "condition": "or"}]
            if words else []),
    }


def run_hypothesis_templates(runner: "NucleiRunner",
                             hypotheses,
                             live_file: Path) -> List[Finding]:
    """Generate templates for in-scope hypotheses and run them.

    ``hypotheses`` may be Hypothesis objects or dicts (``endpoint``,
    ``test_class``, ``hypothesis``, ``reason``).
    """
    from urllib.parse import urlparse
    tdir = runner.output_dir / "ai-templates"
    tdir.mkdir(parents=True, exist_ok=True)
    written: List[str] = []
    seen: set = set()
    for h in hypotheses:
        url = str(getattr(h, "endpoint", None) or
                  (h.get("endpoint") if isinstance(h, dict) else None) or "")
        if not url or not url.startswith("http"):
            continue
        host = (urlparse(url).hostname or "").lower()
        if not runner.cfg.scope.is_in_scope(url):
            continue
        tpl = generate_template_for_hypothesis(h, url)
        if not tpl or tpl["id"] in seen:
            continue
        seen.add(tpl["id"])
        (tdir / f"{tpl['id']}.json").write_text(json.dumps(tpl, indent=2))
        written.append(tpl["id"])
    if not written or not live_file.exists():
        return []
    out_jsonl = runner.output_dir / "nuclei-ai.jsonl"
    if out_jsonl.exists():
        out_jsonl.unlink()
    args = [
        "nuclei", "-l", str(live_file), "-t", str(tdir),
        "-rl", str(runner.cfg.scan.rate_limit),
        "-jsonl", "-no-color",
        "-timeout", "10", "-retries", "1", "-o", str(out_jsonl),
    ]
    log.info("running %d AI-generated nuclei templates", len(written))
    r = run(args, timeout=runner.cfg.scan.timeout * 2, check=False)
    if r.timed_out:
        log.warning("AI-template nuclei run timed out")
    findings: List[Finding] = []
    if not out_jsonl.exists():
        return findings
    with open(out_jsonl) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = d.get("info", {}) or {}
            tid = d.get("template-id") or d.get("templateID") or ""
            findings.append(Finding(
                id=f"nuclei-ai-{tid}-{d.get('matched-at','')}",
                source="nuclei-ai-gen", template_id=tid,
                name=info.get("name", ""),
                severity=(info.get("severity") or "medium").lower(),
                host=d.get("host", ""),
                matched_at=d.get("matched-at", ""),
                endpoint_url=d.get("matched-at"),
                method=(d.get("type") or "GET").upper(),
                description=info.get("description", "") or "",
                tags=info.get("tags", []) or [],
                raw=d,
                confidence=Confidence.PROBABLE.value,
                validation_status=ValidationStatus.NOT_TESTED.value,
                root_cause_key=make_root_cause_key(d),
            ))
    log.info("AI templates produced %d nuclei findings", len(findings))
    return findings
