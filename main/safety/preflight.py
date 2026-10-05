"""Preflight: module resolution, cost planning, dry-run (M1).

Resolves the enabled module set with the SAME boolean expressions
the orchestrator uses (tested pairwise), estimates worst-case
request costs per stateful module, and validates strict-mode
authorization before any network activity. Also hosts the
cross-sweep StopFlag, the stateful-request Pacer, and SIGINT/SIGTERM
handling (finish current probe, keep partial results, never mark
unfinished work as negative).
"""
import os
import signal
import sys
import threading
import time
from dataclasses import dataclass
from typing import Dict, List
from .impact import (ModuleState, max_level, MODULE_LEVELS)
from .authorization import Authorization
from ..logging_setup import get_logger

log = get_logger("preflight")


# ── module resolution (mirrors orchestrator/profile/config) ──────────
def resolve_modules(cfg, profile) -> List[ModuleState]:
    """Enabled set + reasons. Keep conditions in sync with the
    orchestrator stage guards they mirror (see tests)."""
    p, c = profile, cfg
    dv = bool(getattr(p, "differential", False)
              or c.validation.differential)
    states = [
        ("recon", True, "always runs (resume-aware)"),
        ("discovery", True, "always runs (resume-aware)"),
        ("mapping", True, "always runs (resume-aware)"),
        ("probe", bool(getattr(p, "run_httpx", True)),
         "profile.run_httpx"),
        ("browser", bool(getattr(p, "browser", False)
                         or c.browser.enabled),
         "profile.browser or browser.enabled"),
        ("nuclei", bool(getattr(p, "run_nuclei", False)),
         "profile.run_nuclei"),
        ("takeover_fingerprint",
         bool(getattr(p, "run_subzy", False)
              or getattr(p, "run_tko", False)),
         "profile.run_subzy/run_tko"),
        ("takeover_claim",
         bool(getattr(p, "run_tko", False)
              and os.environ.get("GITHUB_TOKEN")),
         "profile.run_tko + GITHUB_TOKEN present"),
        ("differential", dv, "profile.differential or "
                             "validation.differential"),
        ("oast", bool(getattr(p, "oast", False) or c.validation.ssrf
                       or c.validation.second_order_ssrf),
         "profile.oast or validation.ssrf or "
         "validation.second_order_ssrf"),
        ("validation", bool(getattr(p, "run_validation", False)
                            or c.validation.enabled),
         "profile.run_validation or validation.enabled"),
        ("authz_matrix", bool(getattr(p, "authz_matrix", False)
                              or c.authorization.enabled),
         "profile.authz_matrix or authorization.enabled"),
        ("second_order", bool(getattr(p, "second_order", False)
                              or c.validation.second_order
                              or c.validation.second_order_ssrf),
         "profile.second_order or validation.second_order or "
         "validation.second_order_ssrf"),
        ("business_logic", bool(getattr(p, "business_logic", False)
                                or c.business.enabled),
         "profile.business_logic or business.enabled"),
        ("race", bool(getattr(p, "race", False) or c.race.enabled),
         "profile.race or race.enabled"),
        ("login", bool(getattr(c.auth.login, "enabled", False)),
         "auth.login.enabled"),
        ("ai", bool(getattr(p, "run_ai", False) or c.ai.enabled),
         "profile.run_ai or ai.enabled (key checked at runtime)"),
    ]
    return [ModuleState(name=n, level=MODULE_LEVELS[n], enabled=e,
                        reason=r) for n, e, r in states]


# ── request-cost planning (upper bounds, reserved pre-sweep) ──────────
@dataclass(frozen=True)
class RequestPlan:
    module: str
    endpoint: str
    baseline_requests: int = 0
    mutation_requests: int = 0
    concurrency_requests: int = 0
    verification_requests: int = 0

    @property
    def total(self) -> int:
        return (self.baseline_requests + self.mutation_requests
                + self.concurrency_requests
                + self.verification_requests)


def plan_differential(n_endpoints: int, n_contexts: int) -> RequestPlan:
    return RequestPlan("differential", "*", 0, n_endpoints * n_contexts)


def plan_authz_matrix(n_endpoints: int, n_identities: int,
                      n_methods: int, max_ids: int,
                      write_replays: int = 0,
                      graphql_replays: int = 0,
                      bfla_proofs: int = 0,
                      mass_assignments: int = 0) -> RequestPlan:
    harvest = n_endpoints * n_identities
    swap = n_endpoints * max_ids * max(0, n_identities - 1) * 2
    sweep = n_endpoints * n_methods * n_identities
    # write replay: baseline + replay + readback per attempt;
    # GraphQL operation replay: owner baseline + tester replay;
    # BFLA proof: reader baseline + tester replay + reader readback;
    # mass assignment: own-object baseline + replay + readback per
    # field (up to 2 fields)
    write = write_replays * 3
    graphql = graphql_replays * 2
    bfla = bfla_proofs * 3
    mass = mass_assignments * 5
    return RequestPlan("authz_matrix", "*", harvest,
                       swap + sweep + write + graphql + bfla + mass)


def plan_race(n_endpoints: int, concurrency: int,
              rounds: int) -> RequestPlan:
    return RequestPlan("race", "*", 0, 0, n_endpoints * concurrency
                       * rounds, verification_requests=n_endpoints * 2)


def plan_business(n_endpoints: int, max_params: int) -> RequestPlan:
    per_ep = 1 + max_params * (3 + 2)  # baseline + mutations + replays
    return RequestPlan("business_logic", "*", 0, n_endpoints * per_ep)


def plan_second_order(n_forms: int, n_renders: int) -> RequestPlan:
    return RequestPlan("second_order", "*", 0, n_forms,
                       verification_requests=n_forms * n_renders)


def plan_second_order_ssrf(n_injections: int,
                           n_triggers: int) -> RequestPlan:
    return RequestPlan("second_order_ssrf", "*", 0, n_injections,
                       verification_requests=n_injections * n_triggers)


def plan_prescreen(n_endpoints: int, max_params: int) -> RequestPlan:
    # baseline + boolean pairs + error ladder per parameter, worst case
    return RequestPlan("prescreen", "*", 0, n_endpoints * max_params * 10)


def plan_deser(n_endpoints: int, max_params: int) -> RequestPlan:
    # scalar control plus array/object probes per parameter
    return RequestPlan("deser", "*", 0, n_endpoints * max_params * 3)


def plan_cache(n_endpoints: int) -> RequestPlan:
    # anonymous baseline + victim fetch + anonymous re-read per endpoint
    return RequestPlan("cache", "*", 0, n_endpoints * 3)


def plan_oast(n_endpoints: int, max_params: int) -> RequestPlan:
    # direct HTTP+HTTPS callbacks plus bounded parser-bypass variants
    # (up to 5 per scheme) for params that miss
    return RequestPlan("oast", "*", 0, n_endpoints * max_params * 12)


def plan_graphql_introspection(n_endpoints: int) -> RequestPlan:
    # one minimal introspection document per GraphQL endpoint
    return RequestPlan("graphql_introspection", "*", 0, n_endpoints)


def plan_jwt(n_endpoints: int, n_identities: int) -> RequestPlan:
    # baseline plus up to two confusion replays per identity
    return RequestPlan("jwt", "*", 0, n_endpoints * n_identities * 3)


def plan_header(n_endpoints: int, max_params: int) -> RequestPlan:
    # Host override pair plus one CRLF probe per parameter
    return RequestPlan("header", "*", 0,
                       n_endpoints * (2 + max_params))


def plan_upload(n_endpoints: int) -> RequestPlan:
    # submit plus bounded readback per upload endpoint
    return RequestPlan("upload", "*", 0, n_endpoints * 3)


def plan_misconfig(n_endpoints: int) -> RequestPlan:
    # one read-only GET per page endpoint (headers + body analyzed)
    return RequestPlan("misconfig", "*", 0, n_endpoints)


def plan_info(n_endpoints: int) -> RequestPlan:
    # endpoint fetch (headers) plus one 404-handler probe per endpoint
    return RequestPlan("info", "*", 0, n_endpoints * 2)


def plan_hpp(n_endpoints: int, max_params: int) -> RequestPlan:
    # baseline plus duplicate and repeat-control probes per parameter
    return RequestPlan("hpp", "*", 0,
                       n_endpoints * (1 + 2 * max_params))


def plan_reset(n_endpoints: int) -> RequestPlan:
    # enumeration pair plus one host-poison reset request per endpoint
    return RequestPlan("reset", "*", 0, n_endpoints * 3)


def plan_otp(n_endpoints: int) -> RequestPlan:
    # wrong-code baseline plus empty-code and omitted-code probes
    return RequestPlan("otp", "*", 0, n_endpoints * 3)


# ── dry-run (zero network: file reads only) ───────────────────────────
def dry_run_plan(target: str, cfg, profile,
                 out_dir) -> Dict:
    """Build the preflight plan without sending any request."""
    from pathlib import Path
    from ..scope import Scope
    host = (target.replace("http://", "").replace("https://", "")
            .split("/")[0])
    scope_cfg = cfg.scope
    if not scope_cfg.allowed_domains:
        scope_cfg.allowed_domains = [host]
    scope = Scope(scope_cfg)
    in_scope = scope.is_in_scope(
        target if "://" in target else f"https://{target}")
    states = resolve_modules(cfg, profile)
    level = max_level(states)
    strict = bool(getattr(cfg.safety, "strict", False))
    auth = Authorization.from_safety_cfg(cfg)
    from .authorization import GATED_MODULES
    gated = [s.name for s in states
             if s.enabled and s.name in GATED_MODULES]
    refusal: List[str] = []
    if strict:
        refusal = auth.check(target, gated)
    # inventory: previous scan artifacts only, never the network
    endpoints: List[dict] = []
    inv_file = Path(out_dir) / "endpoints.jsonl"
    if inv_file.exists():
        import json as _json
        for line in inv_file.read_text(errors="ignore").splitlines():
            try:
                endpoints.append(_json.loads(line))
            except Exception:
                continue
    n_identities = max(1, len(getattr(cfg.auth, "contexts", [])) or 1)
    plans: List[RequestPlan] = []
    names = {s.name for s in states if s.enabled}
    if "differential" in names:
        plans.append(plan_differential(
            len(endpoints) or cfg.validation.differential_max_endpoints,
            n_identities))
    if "authz_matrix" in names:
        n_eps = len(endpoints) or cfg.authorization.max_endpoints
        writes = 0
        graphql = 0
        if getattr(cfg.authorization, "write_replay", False):
            writes = (n_eps * cfg.authorization.max_ids_per_endpoint *
                      max(0, n_identities - 1))
        graphql = (n_eps * cfg.authorization.max_ids_per_endpoint *
                   max(0, n_identities - 1))
        plans.append(plan_authz_matrix(
            n_eps, n_identities, len(cfg.authorization.methods),
            cfg.authorization.max_ids_per_endpoint, writes, graphql))
    if "race" in names:
        plans.append(plan_race(cfg.race.max_endpoints,
                               cfg.race.concurrency, cfg.race.rounds))
    if "business_logic" in names:
        plans.append(plan_business(cfg.business.max_endpoints,
                                   cfg.business.max_params))
    if (getattr(profile, "second_order", False)
            or cfg.validation.second_order):
        plans.append(plan_second_order(
            cfg.validation.second_order_max_endpoints,
            cfg.validation.second_order_max_renders))
    if cfg.validation.second_order_ssrf:
        injections = (cfg.validation.second_order_max_endpoints *
                      cfg.validation.second_order_ssrf_max_fields)
        plans.append(plan_second_order_ssrf(
            injections, cfg.validation.second_order_max_renders))
    if cfg.validation.upload:
        plans.append(plan_upload(cfg.validation.upload_max_endpoints))
    if "oast" in names:
        plans.append(plan_oast(cfg.oast.max_endpoints,
                               cfg.oast.max_params_per_endpoint))
    if cfg.validation.cache and (getattr(profile, "run_validation", False)
                                 or cfg.validation.enabled):
        plans.append(plan_cache(cfg.validation.cache_max_endpoints))
    total = sum(p.total for p in plans)
    fit, fit_reasons = check_fit(cfg, total)
    return {"target": target, "host": host, "strict": strict,
            "target_in_scope": in_scope,
            "modules": [{"name": s.name, "level": s.level,
                         "enabled": s.enabled, "reason": s.reason}
                        for s in states],
            "max_impact": level, "gated_modules": gated,
            "authorization": auth.describe(), "refusal": refusal,
            "inventory_endpoints": len(endpoints),
            "inventory_estimated": not inv_file.exists(),
            "plans": [{"module": p.module, "baseline": p.baseline_requests,
                       "mutation": p.mutation_requests,
                       "concurrency": p.concurrency_requests,
                       "verification": p.verification_requests,
                       "total": p.total} for p in plans],
            "total_planned": total, "budget_fit": fit,
            "budget_fit_reasons": fit_reasons,
            "excluded_hosts": list(scope_cfg.excluded_hosts),
            "excluded_paths": list(scope_cfg.excluded_paths)}


def check_fit(cfg, total: int):
    """Planned total vs configured caps (informational, not a gate)."""
    reasons = []
    max_req = getattr(cfg.safety, "max_requests", None)
    if max_req is not None and total > max_req:
        reasons.append(f"planned {total} exceeds max_requests={max_req}")
    lim = cfg.budgets
    if total > lim.requests_per_host:
        reasons.append(f"planned {total} exceeds "
                       f"requests_per_host={lim.requests_per_host} "
                       f"(raise it or narrow scope)")
    return (not reasons), reasons


def render_plan_text(plan: Dict) -> str:
    lines = [f"Preflight plan for {plan['target']} "
             f"(strict={'on' if plan['strict'] else 'off'}, "
             f"max impact: {plan['max_impact']})"]
    if not plan.get("target_in_scope", True):
        lines.append("  WARNING: target is outside the configured scope "
                     "— nothing would run")
    for m in plan["modules"]:
        mark = "ON " if m["enabled"] else "off"
        lines.append(f"  [{mark}] {m['name']:<18} {m['level']:<10} "
                     f"{m['reason']}")
    if plan["inventory_estimated"]:
        lines.append("  (no prior endpoints.jsonl — costs are upper "
                     "bounds from config caps)")
    else:
        lines.append(f"  (inventory: {plan['inventory_endpoints']} "
                     f"known endpoints)")
    for p in plan["plans"]:
        lines.append(f"  reservation {p['module']:<15} total={p['total']} "
                     f"(base={p['baseline']} mut={p['mutation']} "
                     f"burst={p['concurrency']} verify={p['verification']})")
    lines.append(f"  TOTAL planned stateful requests: "
                 f"{plan['total_planned']}")
    stateful = sum(p["mutation"] + p["concurrency"] + p["verification"]
                   for p in plan["plans"])
    lines.append(f"  of which state-changing (mutation/burst/verify): "
                 f"~{stateful} (read-only discovery and crawling excluded)")
    if plan["excluded_hosts"]:
        lines.append("  scope excluded hosts: " +
                     ", ".join(plan["excluded_hosts"]))
    if plan["excluded_paths"]:
        lines.append("  scope excluded paths: " +
                     ", ".join(plan["excluded_paths"]))
    if not plan["strict"] and plan["gated_modules"]:
        lines.append("  non-strict advisory: enabling --strict would "
                     "additionally require --auth-ref, approved "
                     "domains/modules, a validity window, and "
                     "--ack-state-change for: " +
                     ", ".join(plan["gated_modules"]))
    if not plan["budget_fit"]:
        lines.append("  BUDGET MISMATCH: " +
                     "; ".join(plan["budget_fit_reasons"]))
    if plan["refusal"]:
        lines.append("  REFUSED:")
        lines.extend(f"    - {r}" for r in plan["refusal"])
    return "\n".join(lines)


# ── stop flag, pacer, signals ─────────────────────────────────────────
class StopFlag:
    """Shared halt for sweep loops (stop-on-candidate or SIGINT)."""

    def __init__(self):
        self._event = threading.Event()

    def set(self):
        self._event.set()

    def is_set(self) -> bool:
        return self._event.is_set()

    def clear(self):
        self._event.clear()


class Pacer:
    """Minimum delay between stateful probes (0 = disabled)."""

    def __init__(self, cooldown_ms: int = 0):
        self.ms = max(0, int(cooldown_ms or 0))

    def wait(self):
        if self.ms > 0:
            time.sleep(self.ms / 1000.0)


_interrupt_flag = StopFlag()
_signals_armed = False


def get_interrupt_flag() -> StopFlag:
    return _interrupt_flag


def install_signal_handlers():
    """First SIGINT/SIGTERM: halt sweeps, finish the stage, keep
    partial results. Second: force-exit immediately."""
    global _signals_armed
    if _signals_armed:
        return
    _signals_armed = True
    state = {"count": 0}

    def _handler(signum, frame):
        state["count"] += 1
        if state["count"] == 1:
            log.warning("interrupted — halting sweeps, finishing "
                        "current stage (partial results preserved, "
                        "unfinished work stays untested)")
            _interrupt_flag.set()
        else:
            sys.exit(128 + signum)

    try:
        signal.signal(signal.SIGINT, _handler)
        signal.signal(signal.SIGTERM, _handler)
    except (ValueError, OSError, RuntimeError) as e:
        log.debug("signal install failed (non-main thread?): %s", e)


__all__ = ["resolve_modules", "RequestPlan", "plan_differential",
           "plan_authz_matrix", "plan_race", "plan_business",
           "plan_second_order", "plan_oast", "dry_run_plan",
           "render_plan_text", "check_fit", "StopFlag", "Pacer",
           "get_interrupt_flag", "install_signal_handlers"]
