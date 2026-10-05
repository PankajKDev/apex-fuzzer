"""Chain builder: deterministic rules over recorded findings."""
from pathlib import Path
from typing import Any, Dict, List

from ..logging_setup import get_logger
from .models import AttackChain
from .rules import RULES

log = get_logger("chains")


def build_chains(findings) -> List[AttackChain]:
    """Run every rule; dedupe by (rule, finding-set). Pure function."""
    out: List[AttackChain] = []
    seen = set()
    for rule in RULES:
        try:
            chains = rule(findings)
        except Exception as exc:
            log.debug("chain rule %s failed: %s",
                      getattr(rule, "__name__", "?"), exc)
            continue
        for chain in chains or []:
            key = (chain.rule, tuple(chain.finding_ids))
            if key in seen:
                continue
            seen.add(key)
            out.append(chain)
    out.sort(key=lambda c: (c.host, c.rule, c.id))
    return out


def build_attack_chains(out_dir: Path, findings,
                        metrics) -> List[AttackChain]:
    """Offline chain step: build, persist, count. Zero network."""
    import json as _json
    chains = build_chains(findings)
    try:
        (Path(out_dir) / "attack_chains.jsonl").write_text("\n".join(
            _json.dumps(c.to_dict()) for c in chains) + ("\n" if chains
                                                         else ""))
    except Exception as exc:
        log.debug("attack chains persist failed: %s", exc)
    try:
        metrics.attack_chains_built = len(chains)
    except Exception:
        pass
    ato = sum(1 for c in chains if c.impact == "account-takeover")
    log.info("chains: %d hypothesized (%d account-takeover)",
             len(chains), ato)
    return chains


def load_chains(out_dir: Path) -> List[Dict[str, Any]]:
    """Read back persisted chains for reporting; never fails."""
    import json as _json
    try:
        text = (Path(out_dir) / "attack_chains.jsonl").read_text()
    except Exception:
        return []
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = _json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            out.append(row)
    return out
