"""Validation probes: one module per test family.

Each probe is a function over explicit inputs (endpoints, evidence,
metrics, budgets, coverage, client, config, scope, controls). Shared
sweep controls (halt/pacer/candidate-note) travel as a ProbeControls
value built from the orchestrator — no stage imports the orchestrator.
"""
from dataclasses import dataclass
from typing import Callable

from ...logging_setup import get_logger

log = get_logger("stages-validation")


@dataclass
class ProbeControls:
    """Sweep controls injected by the coordinator."""

    halted: Callable[[], bool] = lambda: False  # noqa: E731
    paced: Callable[[], None] = lambda: None  # noqa: E731
    noted: Callable[[], None] = lambda: None  # noqa: E731

    @classmethod
    def from_orchestrator(cls, orch) -> "ProbeControls":
        return cls(halted=orch._halted, paced=orch._paced,
                   noted=orch._note_candidate)


def reserve_or_block(budgets, coverage, test_class: str, plan,
                     host: str = "") -> bool:
    """Reserve a sweep's worst-case cost up front. Failure records
    blocked coverage and skips the sweep — never a negative."""
    if budgets.reserve(plan.total, host):
        log.info("%s: reserved %d requests (base=%d mut=%d "
                 "burst=%d verify=%d)", plan.module, plan.total,
                 plan.baseline_requests, plan.mutation_requests,
                 plan.concurrency_requests,
                 plan.verification_requests)
        return True
    log.warning("%s: cannot reserve %d requests — skipping sweep "
                "(budget)", plan.module, plan.total)
    coverage.record(test_class, "blocked",
                    f"could not reserve {plan.total} requests")
    return False
