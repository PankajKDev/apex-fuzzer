"""Pipeline stages: one module per scan phase.

Stages are pure-ish functions over explicit inputs (config, scope,
profile, clients, directories) instead of Orchestrator methods. The
orchestrator coordinates stage order, checkpoints, and shared budgets;
stages own their own logic. Shared file IO lives here.
"""
from pathlib import Path
from typing import List


def read_lines(path: Path) -> List[str]:
    if not path.exists():
        return []
    return [line.strip() for line in
            path.read_text(errors="ignore").splitlines() if line.strip()]
