"""DOM interaction + snapshotting (Phase 1).

Small, explicit primitives (goto/fill/click/js/snapshot) plus an
action log so interaction sequences can be replayed (login flows in
workflows.py). Every primitive is scope-checked by the caller.
"""
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from ..logging_setup import get_logger

log = get_logger("browser-actions")


@dataclass
class Action:
    kind: str  # goto | fill | click | press | js | wait
    target: str = ""
    value: str = ""
    timestamp: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind, "target": self.target,
                "value": self.value, "timestamp": self.timestamp}


class ActionLog:
    def __init__(self):
        self.actions: List[Action] = []

    def record(self, kind: str, target: str = "", value: str = ""):
        self.actions.append(Action(kind=kind, target=target, value=value,
                                   timestamp=time.time()))

    def to_dict(self) -> List[Dict[str, Any]]:
        return [a.to_dict() for a in self.actions]


def snapshot_dom(page) -> Dict[str, Any]:
    """First-party structure: forms, links, scripts, iframes."""
    snap: Dict[str, Any] = {"title": "", "forms": [], "links": [],
                            "scripts": [], "iframes": []}
    try:
        snap["title"] = page.title() or ""
    except Exception:
        pass
    try:
        snap["forms"] = page.evaluate(
            "() => Array.from(document.forms).map(f => ({"
            "action: f.action || '', method: (f.method || 'get'), "
            "inputs: Array.from(f.elements).map(e => ({"
            "name: e.name || '', type: e.type || '', "
            "value: (e.value || '').slice(0, 100)}))}))") or []
    except Exception as e:
        log.debug("form snapshot failed: %s", e)
    for attr, key in (("a[href]", "links"), ("script[src]", "scripts"),
                      ("iframe[src]", "iframes")):
        try:
            snap[key] = page.eval_on_selector_all(
                attr, "els => els.map(e => e.getAttribute('src') || "
                       "e.getAttribute('href') || '')") or []
        except Exception:
            pass
    return snap


def fill_form(page, fields: Dict[str, str],
              log_actions: Optional[ActionLog] = None) -> int:
    """Fill inputs matched by name; returns fields filled."""
    filled = 0
    for name, value in (fields or {}).items():
        for selector in (f'input[name="{name}"]',
                         f'textarea[name="{name}"]',
                         f'select[name="{name}"]'):
            try:
                page.fill(selector, value, timeout=5000)
                filled += 1
                if log_actions is not None:
                    log_actions.record("fill", selector, value)
                break
            except Exception:
                continue
    return filled


def click(page, selector: str,
          log_actions: Optional[ActionLog] = None) -> bool:
    try:
        page.click(selector, timeout=5000)
        if log_actions is not None:
            log_actions.record("click", selector)
        return True
    except Exception as e:
        log.debug("click %s failed: %s", selector, e)
        return False


def run_js(page, expression: str):
    try:
        return page.evaluate(expression)
    except Exception as e:
        log.debug("js evaluate failed: %s", e)
        return None
