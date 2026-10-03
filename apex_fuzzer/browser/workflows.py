"""Recordable browser workflows (Phase 1: login-flow reuse).

A BrowserWorkflow is an explicit step list (goto/fill/click/wait) that
can be recorded once — e.g. a login sequence — and replayed per
identity to mint fresh sessions. Keeps browser automation
declarative and replayable instead of buried in ad-hoc scripts.
"""
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from ..logging_setup import get_logger
from .actions import ActionLog

log = get_logger("browser-workflows")


@dataclass
class WorkflowStep:
    action: str  # goto | fill | click | press | wait_url | wait_text
    target: str = ""
    value: str = ""
    timeout_ms: int = 15000

    def to_dict(self) -> Dict[str, Any]:
        return {"action": self.action, "target": self.target,
                "value": self.value, "timeout_ms": self.timeout_ms}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "WorkflowStep":
        return cls(action=d.get("action", ""),
                   target=d.get("target", ""), value=d.get("value", ""),
                   timeout_ms=int(d.get("timeout_ms") or 15000))


class BrowserWorkflow:
    def __init__(self, name: str,
                 steps: Optional[List[WorkflowStep]] = None):
        self.name = name
        self.steps = steps or []

    def add(self, action: str, target: str = "", value: str = "",
            timeout_ms: int = 15000) -> "BrowserWorkflow":
        self.steps.append(WorkflowStep(action=action, target=target,
                                       value=value,
                                       timeout_ms=timeout_ms))
        return self

    def replay(self, page, log_actions: Optional[ActionLog] = None
               ) -> List[Dict[str, Any]]:
        """Execute every step; returns per-step {ok, detail} (never
        raises — a failed login step is data, not a crash)."""
        from .actions import fill_form, click
        results: List[Dict[str, Any]] = []
        for step in self.steps:
            ok, detail = self._run_step(page, step, log_actions)
            results.append({"action": step.action, "target": step.target,
                            "ok": ok, "detail": detail})
            if not ok:
                log.warning("workflow '%s': step %s %s failed: %s",
                            self.name, step.action, step.target, detail)
                break
        return results

    def _run_step(self, page, step: WorkflowStep,
                  log_actions: Optional[ActionLog]):
        from .actions import fill_form, click
        try:
            if step.action == "goto":
                page.goto(step.target, timeout=step.timeout_ms)
                ok = True
            elif step.action == "fill":
                ok = fill_form(page, {step.target: step.value},
                               log_actions) > 0
            elif step.action == "click":
                ok = click(page, step.target, log_actions)
            elif step.action == "press":
                page.keyboard.press(step.value or "Enter",
                                    timeout=step.timeout_ms)
                ok = True
            elif step.action == "wait_url":
                page.wait_for_url(step.target, timeout=step.timeout_ms)
                ok = True
            elif step.action == "wait_text":
                page.get_by_text(step.target).first.wait_for(
                    timeout=step.timeout_ms)
                ok = True
            else:
                return False, f"unknown action '{step.action}'"
            if log_actions is not None:
                log_actions.record(step.action, step.target, step.value)
            return ok, ""
        except Exception as e:
            return False, str(e)[:200]

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name,
                "steps": [s.to_dict() for s in self.steps]}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "BrowserWorkflow":
        return cls(name=d.get("name", ""),
                   steps=[WorkflowStep.from_dict(s)
                          for s in (d.get("steps") or [])])
