"""Workflow replay over HTTP (agent Phase 4).

Executes a Flow's steps in order as one identity, binding recorded
parameter values (harvest pool overrides samples). Every step result
carries status/shape; a failed step stops the flow but never raises —
a broken prerequisite is data for mutation testing, not a crash.
Scope and budgets gate every request; budget exhaustion aborts with
the steps completed so far.
"""
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
from ..budgets import BudgetExceeded
from ..logging_setup import get_logger

log = get_logger("workflows-replay")


class StepResult:
    def __init__(self, name: str, status: int = 0, shape: str = "",
                 body_hash: str = "", note: str = ""):
        self.name = name
        self.status = status
        self.shape = shape
        self.body_hash = body_hash
        self.note = note

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "status": self.status,
                "shape": self.shape, "body_hash": self.body_hash,
                "note": self.note}


class ReplayResult:
    def __init__(self, flow_name: str, identity: str):
        self.flow_name = flow_name
        self.identity = identity
        self.steps: List[StepResult] = []
        self.completed = False

    def to_dict(self) -> Dict[str, Any]:
        return {"flow": self.flow_name, "identity": self.identity,
                "completed": self.completed,
                "steps": [s.to_dict() for s in self.steps]}


def _bind_params(step, harvest_pool) -> Dict[str, str]:
    """Recorded samples, overridden by fresher harvested values."""
    out: Dict[str, str] = {}
    for p in getattr(step, "parameters", []) or []:
        if getattr(p, "name", ""):
            sample = (getattr(p, "sample_value", "") or "").strip()
            out[p.name] = sample or "1"
    if harvest_pool:
        by_param: Dict[str, str] = {}
        for h in harvest_pool:
            pname = getattr(h, "param", "")
            if pname and pname not in by_param:
                by_param[pname] = str(getattr(h, "value", ""))
        for name in out:
            if name in by_param and by_param[name]:
                out[name] = by_param[name]
    return out


def replay_flow(http, flow, identity, harvest_pool=None,
                timeout: int = 10, budgets=None,
                scope=None) -> ReplayResult:
    """Run every step in order. Returns completed=True only when all
    steps return HTTP 200."""
    from ..validation.differential import normalize_response
    name = getattr(identity, "name", "anonymous")
    headers = dict(getattr(identity, "auth_headers", None) or {})
    result = ReplayResult(getattr(flow, "name", ""), name)
    for step in getattr(flow, "steps", []) or []:
        url = getattr(step, "endpoint", "")
        method = (getattr(step, "method", "GET") or "GET").upper()
        if scope is not None and not scope.is_in_scope(url):
            result.steps.append(StepResult(
                getattr(step, "name", ""), note="out of scope — skipped"))
            return result
        if budgets is not None and \
                not budgets.consume_test("workflow", url):
            result.steps.append(StepResult(
                getattr(step, "name", ""), note="budget exhausted"))
            return result
        params = _bind_params(step, harvest_pool)
        try:
            if method == "GET":
                parts = urlsplit(url)
                q = parse_qsl(parts.query, keep_blank_values=True)
                q.extend(sorted(params.items()))
                target = urlunsplit(
                    (parts.scheme, parts.netloc, parts.path,
                     urlencode(q, doseq=True), ""))
                r = http.get(target, headers=headers, timeout=timeout)
            elif method == "POST":
                r = http.post(url, data=params, headers=headers,
                              timeout=timeout)
            else:
                r = http.request(method, url, headers=headers,
                                 timeout=timeout)
        except BudgetExceeded:
            raise
        except Exception as e:
            result.steps.append(StepResult(
                getattr(step, "name", ""), note=f"failed: {e}"[:200]))
            return result
        try:
            norm = normalize_response(r)
        except Exception:
            result.steps.append(StepResult(
                getattr(step, "name", ""), status=r.status_code,
                note="unparseable response"))
            return result
        result.steps.append(StepResult(
            getattr(step, "name", ""), status=norm.get("status", 0),
            shape=norm.get("key_shape", ""),
            body_hash=norm.get("body_hash", "")))
        if norm.get("status") != 200:
            return result
    result.completed = True
    return result
