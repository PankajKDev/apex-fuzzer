"""Workflow mutation generation (agent Phase 4).

Derives invalid-sequence variants from a discovered Flow: skipped,
reordered, repeated, and replayed steps; removed prerequisites;
identity/tenant/role changes; stale-token substitution; cross-flow
resource use; direct invalid transitions. Generation is pure and
capped — no requests. A mutation is a test candidate, never a
verdict: executing it and judging the outcome belongs to later
phases, which must never treat a bare HTTP 200 as proof.
"""
from typing import Any, Dict, List, Optional
from .model import Flow, FlowStep
from ..logging_setup import get_logger

log = get_logger("workflows-mutations")

MUTATION_KINDS = ("skip_step", "reorder_steps", "repeat_step",
                  "replay_stale", "drop_prerequisite",
                  "change_identity", "change_tenant", "change_role",
                  "stale_token", "cross_workflow_resource",
                  "invalid_transition")


class FlowMutation:
    def __init__(self, kind: str, flow_name: str, steps: List[FlowStep],
                 detail: str = ""):
        self.kind = kind
        self.flow_name = flow_name
        self.steps = steps
        self.detail = detail

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind, "flow": self.flow_name,
                "steps": [s.to_dict() for s in self.steps],
                "detail": self.detail}


def _clone(step: FlowStep) -> FlowStep:
    return FlowStep.from_dict(step.to_dict())


def mutate(flow: Flow, kinds: Optional[List[str]] = None,
           stale_values: Optional[Dict[str, str]] = None,
           identities: Optional[List[str]] = None,
           max_per_kind: int = 2) -> List[FlowMutation]:
    """Generate bounded mutation variants of one flow."""
    kinds = [k for k in (kinds or list(MUTATION_KINDS))
             if k in MUTATION_KINDS]
    steps = list(getattr(flow, "steps", []) or [])
    out: List[FlowMutation] = []
    if len(steps) < 1:
        return out

    def _add(kind: str, variant: List[FlowStep], detail: str):
        if kind not in kinds:
            return
        if sum(1 for m in out if m.kind == kind) >= max_per_kind:
            return
        out.append(FlowMutation(kind, flow.name, variant, detail))

    names = [s.name for s in steps]
    # skip each non-final step (final-step skip == abandon, untestable)
    for i in range(len(steps) - 1):
        _add("skip_step", [_clone(s) for j, s in enumerate(steps)
                           if j != i],
             f"omitted step {names[i]!r}")
    # adjacent reorder
    for i in range(len(steps) - 1):
        variant = [_clone(s) for s in steps]
        variant[i], variant[i + 1] = variant[i + 1], variant[i]
        _add("reorder_steps", variant,
             f"swapped {names[i]!r} ↔ {names[i + 1]!r}")
    # repeat each step once (duplicate action)
    for i in range(len(steps)):
        variant = [_clone(s) for s in steps]
        variant.insert(i + 1, _clone(steps[i]))
        _add("repeat_step", variant, f"duplicated {names[i]!r}")
    # replay the whole flow a second time (idempotency probe)
    _add("replay_stale", [_clone(s) for s in steps] +
         [_clone(s) for s in steps], "full flow executed twice")
    # drop prerequisites: first step removed (unauthorized entry)
    if len(steps) > 1:
        _add("drop_prerequisite", [_clone(s) for s in steps[1:]],
             f"entered at {names[1]!r} without {names[0]!r}")
    # identity / tenant / role changes (actor recorded on mutation;
    # the executor substitutes credentials at replay time)
    for ident in (identities or [])[:max_per_kind]:
        _add("change_identity", [_clone(s) for s in steps],
             f"replay as {ident}")
    if stale_values:
        _add("stale_token", [_clone(s) for s in steps],
             "replay with superseded token/ID values: " +
             ", ".join(sorted(stale_values)[:5]))
    # invalid transition: jump straight to the final step
    if len(steps) > 2:
        _add("invalid_transition", [_clone(steps[-1])],
             f"jump directly to {names[-1]!r}")
    # cross-workflow resource use is recorded structurally: consumers
    # of shared params are already linked by dependencies.py; the
    # mutation marks the intent for the executor
    for s in steps:
        if getattr(s, "consumes", None):
            _add("cross_workflow_resource", [_clone(s) for s in steps],
                 f"replay with foreign values for {s.consumes}")
            break
    # change_tenant / change_role are actor variants of change_identity
    for ident in (identities or [])[:max_per_kind]:
        _add("change_tenant", [_clone(s) for s in steps],
             f"replay in another tenant context (actor {ident})")
        break
    for ident in (identities or [])[:max_per_kind]:
        _add("change_role", [_clone(s) for s in steps],
             f"replay with elevated role (actor {ident})")
        break
    log.debug("workflows-mutations: %d variants for '%s'",
              len(out), flow.name)
    return out


def mutation_catalog(flows, **kw) -> Dict[str, List[Dict[str, Any]]]:
    """flow name → serializable mutation list (artifact payload)."""
    return {f.name: [m.to_dict() for m in mutate(f, **kw)]
            for f in flows or []}
