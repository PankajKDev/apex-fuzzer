"""WebSocket handshake layer: auth boundary + origin validation.

Offline target discovery (recorded ws addresses) plus bounded live
handshakes through the shared gated client. No frames are spoken:
101-with-upgrade means accepted; anything else is a refusal. An
anonymous accept on a privileged path and an evil-Origin accept on
an authed-only endpoint are candidates; enforced boundaries are
genuine negatives.
"""
from pathlib import Path
from typing import List
from urllib.parse import urlsplit

from ...budgets import BudgetExceeded, BudgetTracker
from ...logging_setup import get_logger
from ...models import (Confidence, Finding, ValidationStatus,
                       stable_finding_id)
from ...reporting.coverage import CoverageTracker
from ...reporting.metrics import Metrics
from ...safety.preflight import plan_websocket
from ...validation.evidence import EvidenceStore
from ...validation.websocket import (EVIL_ORIGIN, check_ws_handshake,
                                     ws_targets)
from . import ProbeControls, reserve_or_block

log = get_logger("stages-validation")

_PRIVILEGED_HINTS = ("admin", "api", "auth", "private", "internal",
                     "account", "settings")


def _privileged_path(url: str) -> bool:
    try:
        segments = [seg for seg in urlsplit(url).path.lower().split("/")
                    if seg]
    except ValueError:
        return False
    return any(seg in _PRIVILEGED_HINTS for seg in segments)


def websocket_probe(out_dir: Path, evidence: EvidenceStore,
                    metrics: Metrics, budgets: BudgetTracker,
                    coverage: CoverageTracker, client, cfg, scope,
                    controls: ProbeControls,
                    identities) -> List[Finding]:
    """Handshake auth boundary plus evil-Origin replay per target."""
    traffic_file = Path(out_dir) / "browser_traffic.json"
    recorded: list = []
    if traffic_file.exists():
        try:
            import json as _json
            data = _json.loads(traffic_file.read_text(
                errors="ignore") or "{}")
            recorded = [u for u in data.get("websockets", []) or []
                        if isinstance(u, str)]
        except Exception as exc:
            log.debug("websocket traffic read failed: %s", exc)
    targets = [u for u in ws_targets(recorded)
               if scope.active_test_allowed(u)]
    if not targets:
        log.info("websocket: no in-scope recorded WebSocket "
                 "addresses — nothing to check")
        coverage.record("websocket", "untestable",
                        "no recorded WebSocket addresses")
        return []
    if not reserve_or_block(
            budgets, coverage, "websocket",
            plan_websocket(len(targets), len(identities or []))):
        return []
    findings: List[Finding] = []
    for url in targets:
        if controls.halted():
            log.info("websocket: halted by stop control")
            break
        if not budgets.consume_test("websocket", url,
                                    limit=2 + len(identities or [])):
            coverage.record("websocket", "blocked", f"budget: {url}")
            continue
        outcomes = {}
        headers_by_name = {}
        try:
            for ident in identities or []:
                name = getattr(ident, "name", "anonymous")
                headers = dict(getattr(ident, "auth_headers", None)
                               or {})
                headers_by_name[name] = headers
                outcomes[name] = check_ws_handshake(
                    client, url, headers, name,
                    timeout=cfg.scan.http_timeout)
        except BudgetExceeded:
            coverage.record("websocket", "blocked", f"budget: {url}")
            continue
        anon = outcomes.get("anonymous")
        authed = {n: r for n, r in outcomes.items()
                  if n != "anonymous"}
        if anon is not None and anon.accepted:
            if _privileged_path(url):
                controls.noted()
                coverage.record("websocket", "candidate",
                                f"{url}: anonymous handshake accepted "
                                f"on privileged path")
                findings.append(_finding(
                    url, "websocket-handshake",
                    f"WebSocket accepts anonymous handshake on "
                    f"privileged path ({urlsplit(url).path or '/'})",
                    "high",
                    f"{anon.notes}. An unauthenticated handshake "
                    f"reaches a privileged socket path — the same "
                    f"broken-access shape as anonymous HTTP 200s. "
                    f"Confirm the channel serves privileged data "
                    f"before reporting.",
                    evidence, {"handshake": anon.to_dict()},
                    "anonymous"))
            else:
                coverage.record("websocket", "tested_negative",
                                f"{url}: public endpoint, anonymous "
                                f"handshake is normal")
            continue
        allowed = [n for n, r in authed.items() if r.accepted]
        if anon is not None and not anon.accepted and allowed:
            coverage.record("websocket", "tested_negative",
                            f"{url}: anonymous refused, "
                            f"{','.join(sorted(allowed))} accepted")
            # Cross-site hijack primitive: evil Origin on an
            # authed-only endpoint.
            first = next((n for n in outcomes if n != "anonymous"
                          and outcomes[n].accepted), None)
            if first is None:
                continue
            controls.paced()
            try:
                evil = check_ws_handshake(
                    client, url, headers_by_name.get(first, {}),
                    first, origin=EVIL_ORIGIN,
                    timeout=cfg.scan.http_timeout)
            except BudgetExceeded:
                coverage.record("websocket", "blocked",
                                f"budget: {url}")
                continue
            except Exception as exc:
                log.debug("websocket origin replay failed %s: %s",
                          url, exc)
                continue
            if evil.accepted:
                controls.noted()
                coverage.record("websocket", "candidate",
                                f"{url}: evil Origin accepted with "
                                f"{first}'s session")
                findings.append(_finding(
                    url, "websocket-origin",
                    f"WebSocket accepts evil Origin with victim "
                    f"session ({urlsplit(url).path or '/'})",
                    "high",
                    f"{evil.notes}. A cross-site page can ride "
                    f"{first}'s session into this socket. Confirm "
                    f"message-layer impact with test accounts "
                    f"before reporting.",
                    evidence, {"handshake": evil.to_dict()}, first))
            else:
                coverage.record("websocket", "tested_negative",
                                f"{url}: evil Origin refused "
                                f"({evil.status})")
            continue
        coverage.record("websocket", "inconclusive",
                        f"{url}: no identity completed a handshake")
    return findings


def _finding(url: str, source: str, name: str, severity: str,
             fp_notes: str, evidence: EvidenceStore, raw: dict,
             identity: str) -> Finding:
    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        host = ""
    f = Finding(
        id=stable_finding_id("ws", source, url),
        source=source,
        name=name,
        severity=severity,
        confidence=Confidence.PROBABLE.value,
        validation_status=ValidationStatus.STRONG_CANDIDATE.value,
        host=host, matched_at=url,
        endpoint_url=url, method="GET",
        description=name,
        tags=["websocket", source.split("-", 1)[-1]],
        raw=raw,
        false_positive_notes=fp_notes,
        identity=identity,
    )
    evidence.allocate(f)
    evidence.record(
        f,
        request_text=(f"GET {url}\n(Upgrade: websocket handshake; "
                      f"identity: {identity})"),
        response_text=name)
    log.info("websocket: %s", name)
    return f
