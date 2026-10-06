"""Authz matrix probe: harvest → swap → method sweep → write replay.

Cross-user/cross-tenant read isolation over harvested object IDs,
plus the opt-in MTN-pattern write replay. Returns (findings,
matrix, pool): the coordinator persists the pool and records
behavioral state from the returned matrix.
"""
from pathlib import Path
from typing import List, Tuple

from ...authorization.access_tests import swap_ids, sweep_methods
from ...authorization.harvest import HarvestedId, harvest_ids
from ...authorization.matrix import (AuthorizationMatrix, describe_cell,
                                     evaluate_cell)
from ...authorization.write_replay import (PROOF_METHODS, prove_bfla)
from ...budgets import BudgetExceeded, BudgetTracker
from ...logging_setup import get_logger
from ...logic.observations import (evaluate_observation,
                                   observation_from_swap)
from ...models import (Confidence, Endpoint, Finding, ValidationStatus,
                       stable_finding_id)
from ...reporting.coverage import CoverageTracker
from ...validation.evidence import EvidenceStore
from ...reporting.metrics import Metrics
from ...safety.preflight import plan_authz_matrix
from ...validation.differential import PRIVILEGED_TYPES, has_idor_params
from . import ProbeControls, reserve_or_block
from .authz_graphql import authz_graphql_probe, graphql_schema_probe

log = get_logger("stages-validation")

# BFLA state-changing proofs per endpoint (each costs at most
# baseline + replay + readback; the preflight reservation above
# accounts for the worst case).
_BFLA_PROOFS_PER_ENDPOINT = 2


def _bfla_tester_reader(obs):
    """Split a BFLA candidate cell into (tester, reader) observations.

    The tester is the lower-privilege 200 identity (first non-admin
    signal wins), preferring an authenticated identity over
    anonymous: an anonymous 200 proves nothing about the tester's
    shapes, and HAR/browser shapes are identity-bound. The reader
    is a different 200 identity when one exists — preferring an
    admin signal — else the tester itself.
    Returns (None, None) when nobody reached 200.
    """
    ok = [o for o in obs or []
          if getattr(o, "status", 0) == 200
          and getattr(o, "identity", "")]
    if not ok:
        return None, None
    authed = [o for o in ok if o.identity != "anonymous"] or ok

    def _privileged(o):
        blob = (f"{getattr(o, 'identity', '')} "
                f"{getattr(o, 'role', '')}").lower()
        return "admin" in blob

    low = [o for o in authed if not _privileged(o)] or authed
    tester = low[0]
    others = [o for o in ok
              if o.identity != tester.identity]
    privileged = [o for o in others if _privileged(o)]
    reader = (privileged or others or [tester])[0]
    return tester, reader


def attempt_bfla_proof(ep, method, obs, identities, owner_headers,
                       client, cfg, scope, controls):
    """Run one BFLA state-changing proof for a candidate cell.

    Returns (proof, updates): the BflaProofResult (or None when the
    cell has no 200 identity to prove with) and finding-field updates
    that apply only on confirmation. Anything else leaves the sweep
    candidate standing with the proof notes attached.
    """
    from types import SimpleNamespace
    pair = _bfla_tester_reader(obs)
    if pair == (None, None):
        return None, {}
    tester_obs, reader_obs = pair
    by_name = {getattr(i, "name", ""): i for i in identities or []}
    tester = by_name.get(tester_obs.identity) or SimpleNamespace(
        name=tester_obs.identity, auth_headers={})
    reader = by_name.get(reader_obs.identity) or SimpleNamespace(
        name=reader_obs.identity, auth_headers={})
    controls.paced()
    proof = prove_bfla(
        client, ep, method, tester, reader, owner_headers,
        timeout=cfg.scan.http_timeout, scope=scope)
    if proof.verdict == "confirmed":
        return proof, {
            "status": ValidationStatus.CONFIRMED.value,
            "confidence": Confidence.CONFIRMED.value,
            "extra_tags": ["verified-effect"],
            "suffix": " [verified effect]",
        }
    return proof, {}


def authz_matrix_probe(endpoints: List[Endpoint],
                       evidence: EvidenceStore, metrics: Metrics,
                       budgets: BudgetTracker,
                       coverage: CoverageTracker, client,
                       out_dir: Path, identities, cfg, scope,
                       controls: ProbeControls, app_graph=None
                       ) -> Tuple[List[Finding], object, list]:
    cfg_a = cfg.authorization
    if len(identities) < 2:
        coverage.record("authz", "untestable",
                        "fewer than 2 identities configured")
        return [], AuthorizationMatrix(), []
    targets = [e for e in endpoints
               if e.endpoint_type in PRIVILEGED_TYPES
               or (has_idor_params(e)
                   and e.endpoint_type != "static")]
    targets.sort(key=lambda e: 0 if has_idor_params(e) else 1)
    targets = targets[:cfg_a.max_endpoints]
    if not targets:
        log.info("authz-matrix: no privileged/identifier endpoints "
                 "discovered — nothing to test")
        return [], AuthorizationMatrix(), []
    log.info("authz-matrix: %d endpoints × %s as %d identities",
             len(targets), cfg_a.methods,
             len(identities))
    write_replays = 0
    write_gated = bool(getattr(cfg_a, "write_replay", False)) and \
        bool(getattr(getattr(cfg, "safety", None),
                     "allow_state_change", False))
    if write_gated:
        write_replays = (len(targets) *
                         cfg_a.max_ids_per_endpoint *
                         max(0, len(identities) - 1))
    graphql_replays = (len(targets) * cfg_a.max_ids_per_endpoint *
                       max(0, len(identities) - 1))
    bfla_proofs = (len(targets) * _BFLA_PROOFS_PER_ENDPOINT
                   if write_gated else 0)
    mass_assignments = len(targets) if write_gated else 0
    gql_targets = [e for e in targets
                   if getattr(e, "endpoint_type", "") == "graphql"]
    schema_requests = len(gql_targets) * (
        1 + 5 * 2 * max(0, len(identities) - 1))
    if not reserve_or_block(
            budgets, coverage, "authz",
            plan_authz_matrix(len(targets), len(identities),
                              len(cfg_a.methods),
                              cfg_a.max_ids_per_endpoint,
                              write_replays, graphql_replays,
                              bfla_proofs, mass_assignments,
                              schema_requests)):
        return [], AuthorizationMatrix(), []
    matrix = AuthorizationMatrix()
    findings: List[Finding] = []
    seen_cells = set()
    all_swaps: list = []
    owner_headers = {getattr(i, "name", "anonymous"):
                     dict(getattr(i, "auth_headers", None) or {})
                     for i in identities}

    def ownership_fields_for(endpoint):
        overrides = cfg_a.ownership_fields_by_endpoint or {}
        for selector in (endpoint.url, endpoint.normalized_url,
                         endpoint.path):
            if selector in overrides:
                return list(overrides[selector] or [])
        return list(cfg_a.ownership_fields or [])

    # — pass 1: harvest object IDs from every target (global pool
    # enables cross-endpoint replay, not just same-endpoint swap) —
    pool = []
    for ep in targets:
        if controls.halted():
            log.info("authz-harvest: halted by stop control; "
                     "remaining targets stay untested")
            break
        if not scope.active_test_allowed(ep.url):
            continue
        if not budgets.consume_test("authz", ep.normalized_url):
            coverage.record("authz", "blocked",
                            f"budget: {ep.normalized_url}")
            continue
        try:
            pool.extend(harvest_ids(
                client, ep, identities,
                timeout=cfg.scan.http_timeout,
                max_ids_per_param=cfg_a.max_ids_per_endpoint,
                ownership_fields=ownership_fields_for(ep)))
        except BudgetExceeded:
            coverage.record("authz", "blocked",
                            f"budget: {ep.normalized_url}")
            continue

    def handle_swaps(swaps, ep):
        for sw in swaps:
            metrics.authorization_tests += 1
            cross_tenant = bool(
                sw.tester_tenant and sw.owner_tenant and
                sw.tester_tenant != sw.owner_tenant)
            if sw.verdict != "strong_candidate":
                # precondition rule (§20): owner baseline was 200 by
                # construction and the tester request completed —
                # a denial/difference is a genuine negative. Edge or
                # bot-wall answers never reached the app, so they stay
                # inconclusive instead.
                if getattr(sw, "edge_denied", False):
                    coverage.record(
                        "tenant_isolation" if cross_tenant else "bola",
                        "inconclusive",
                        f"{ep.normalized_url}::{sw.param}: "
                        f"{sw.tester} hit edge infrastructure")
                    continue
                if 400 <= sw.status < 500 or sw.status == 200:
                    coverage.record(
                        "tenant_isolation" if cross_tenant else "bola",
                        "tested_negative",
                        f"{ep.normalized_url}::{sw.param}: "
                        f"{sw.tester}→{sw.status}")
                continue
            metrics.authorization_confirmed += 1
            controls.noted()
            cls = ("tenant_isolation" if cross_tenant else "bola")
            coverage.record(cls, "candidate", sw.notes)
            coverage.record("idor", "candidate", sw.notes)
            # invariant corroboration (provenance in evidence, never
            # a duplicate finding — the swap verdict stays primary)
            inv_results = evaluate_observation(
                observation_from_swap(sw))
            metrics.invariants_tested += len(inv_results)
            metrics.invariants_violated += sum(
                1 for r in inv_results if r.violated)
            f = Finding(
                id=stable_finding_id("swap", sw.endpoint_url, sw.param,
                                     sw.victim_value),
                source="idor-swap",
                name=(f"{'Cross-tenant read' if cross_tenant else 'BOLA'}: "
                      f"'{sw.tester}' reads '{sw.owner}''s "
                      f"'{sw.param}={sw.victim_value}' ({ep.path})"),
                severity="high",
                confidence=Confidence.PROBABLE.value,
                validation_status=ValidationStatus.STRONG_CANDIDATE.value,
                host=ep.host, matched_at=sw.endpoint_url,
                endpoint_url=sw.endpoint_url, method="GET",
                parameter=sw.param,
                description=sw.notes,
                tags=["bola", "idor", "authz",
                      "tenant-isolation" if cross_tenant else
                      "cross-user", ep.endpoint_type],
                raw={"swap": sw.to_dict(),
                     "invariants": [r.to_dict()
                                    for r in inv_results]},
                false_positive_notes=(
                    "Victim object harvested from the owner's own "
                    "session; replayed verbatim as a different "
                    "identity; response shape compared excluding "
                    "volatile keys."),
                identity=sw.tester, tenant=sw.tester_tenant,
                resource_key=(f"{ep.normalized_url}::{sw.param}"
                              f"={sw.victim_value}"),
            )
            evidence.allocate(f)
            evidence.record(
                f,
                request_text=(f"GET {sw.endpoint_url}\n(as "
                              f"{sw.tester}; owner: {sw.owner})"),
                response_text=sw.notes)
            findings.append(f)
            log.info("authz-matrix: %s", sw.notes)

    for ep in targets:
        if controls.halted():
            log.info("authz-swap: halted by stop control; "
                     "remaining targets stay untested")
            break
        controls.paced()
        if not scope.active_test_allowed(ep.url):
            continue
        ep_params = {p.name for p in
                     list(ep.query_parameters or []) +
                     list(ep.body_parameters or [])}
        same = [h for h in pool
                if h.normalized_url == ep.normalized_url
                and getattr(h, "source", "response") == "response"]
        # — cross-endpoint candidates: pool IDs whose param exists here,
        # retargeted at this endpoint with an empty baseline (the swap
        # engine fetches the owner's baseline on the target first) —
        seen_x, cross = set(), []
        for h in pool:
            if getattr(h, "source", "response") != "response":
                continue  # traffic/JS/HTML IDs enrich views only
            if h.normalized_url == ep.normalized_url:
                continue
            if h.param not in ep_params:
                continue
            key = (h.param, h.value, h.owner)
            if key in seen_x:
                continue
            seen_x.add(key)
            cross.append(HarvestedId(
                endpoint_url=ep.url, normalized_url=ep.normalized_url,
                param=h.param, value=h.value, owner=h.owner,
                owner_tenant=h.owner_tenant, shape="", body_hash=""))
        cross = cross[:cfg_a.max_ids_per_endpoint]
        # — swap same-endpoint victims, then cross-endpoint ones —
        for tester in identities:
            for batch in (same, cross):
                if not batch:
                    continue
                try:
                    swaps = swap_ids(
                        client, batch, tester,
                        timeout=cfg.scan.http_timeout,
                        matrix=matrix, owner_headers=owner_headers,
                        ownership_fields=ownership_fields_for(ep))
                    all_swaps.extend(swaps)
                    handle_swaps(swaps, ep)
                except BudgetExceeded:
                    coverage.record("authz", "blocked",
                                    f"budget: {ep.normalized_url}")
                    break
        # — per-method sweep (BFLA coverage beyond GET) —
        # sweep-only observations (resource == "") — swap observations
        # are evaluated by the swap verdicts above, not re-judged here
        try:
            sweep_methods(client, ep, identities, cfg_a.methods,
                          timeout=cfg.scan.http_timeout,
                          matrix=matrix)
        except BudgetExceeded:
            coverage.record("authz", "blocked",
                            f"budget: {ep.normalized_url}")
            continue
        proofs_for_ep = 0
        for cell_key, obs in matrix.cells().items():
            method, _, url = cell_key.partition("::")
            if url != ep.normalized_url or len(obs) < 2:
                continue
            if cell_key in seen_cells:
                continue
            seen_cells.add(cell_key)
            obs = [o for o in obs if not o.resource]
            if len(obs) < 2:
                coverage.record("bfla", "inconclusive",
                                f"{method} {url}: single-identity cell")
                continue
            metrics.authorization_tests += 1
            verdict, notes, kind = evaluate_cell(
                obs, ep.endpoint_type)
            if verdict != "strong_candidate":
                if kind == "" and verdict == "inconclusive":
                    coverage.record("bfla", "tested_negative",
                                    f"{method} {url}: "
                                    f"{describe_cell(obs)}")
                continue
            metrics.authorization_confirmed += 1
            controls.noted()
            coverage.record(kind or "authz", "candidate", notes)
            # — BFLA state-changing proof (opt-in, same gate as write
            # replay): replay the lower-privilege identity's observed
            # mutating shape, verify persistence via readback. Only a
            # confirmed proof upgrades the finding; anything else
            # leaves the sweep candidate standing with proof notes.
            proof, updates = None, {}
            if (write_gated and kind == "bfla"
                    and method in PROOF_METHODS
                    and proofs_for_ep < _BFLA_PROOFS_PER_ENDPOINT
                    and scope.active_test_allowed(ep.url)):
                try:
                    proof, updates = attempt_bfla_proof(
                        ep, method, obs, identities, owner_headers,
                        client, cfg, scope, controls)
                    proofs_for_ep += 1
                except BudgetExceeded:
                    coverage.record("authz", "blocked",
                                    f"budget: {ep.normalized_url}")
                    continue
            if proof is not None and proof.verdict == "confirmed":
                coverage.record("bfla", "confirmed", proof.notes)
            names = [o.identity for o in obs if o.status == 200]
            tenants = sorted({o.tenant for o in obs
                              if o.status == 200 and o.tenant})
            description = f"{notes} [{describe_cell(obs)}]"
            if proof is not None:
                description += f" Proof: {proof.notes}"
            raw = {"observations": [o.to_dict() for o in obs]}
            if proof is not None:
                raw["bfla_proof"] = proof.to_dict()
            f = Finding(
                id=stable_finding_id("bfla", cell_key),
                source="authz-matrix",
                name=(f"BFLA/{kind.upper()}: {method} {ep.path} "
                      f"treats identities identically"
                      f"{updates.get('suffix', '')}"),
                severity="high",
                confidence=updates.get("confidence",
                                       Confidence.PROBABLE.value),
                validation_status=updates.get(
                    "status", ValidationStatus.STRONG_CANDIDATE.value),
                host=ep.host, matched_at=ep.url,
                endpoint_url=ep.url, method=method,
                description=description,
                tags=["bfla", kind, "authz", ep.endpoint_type] +
                updates.get("extra_tags", []),
                raw=raw,
                false_positive_notes=(
                    "Same method compared across identities with "
                    "semantic shape matching; verify the 200s are "
                    "not error pages sharing a template before "
                    "reporting."),
                identity="+".join(names[:2]),
                tenant="+".join(tenants),
            )
            evidence.allocate(f)
            evidence.record(
                f,
                request_text=(f"{method} {ep.url}\n--- matrix ---\n" +
                              describe_cell(obs)),
                response_text=notes)
            findings.append(f)
            log.info("authz-matrix: %s", notes)
        # — MTN-pattern write replay (opt-in): attacker's observed
        # mutating shape with the victim's ID, verified via readback —
        if write_gated and scope.active_test_allowed(ep.url):
            controls.paced()
            try:
                findings.extend(authz_write_replay(
                    ep, pool, identities, owner_headers, evidence,
                    metrics, coverage, client, ep_params, cfg, scope,
                    controls))
            except BudgetExceeded:
                coverage.record("authz", "blocked",
                                f"budget: {ep.normalized_url}")
                continue
            # — self-object mass assignment (same opt-in): privileged
            # fields added to the tester's own shape, verified via
            # own-object readback —
            controls.paced()
            try:
                findings.extend(authz_mass_assignment(
                    ep, identities, owner_headers, evidence,
                    metrics, coverage, client, cfg, scope))
            except BudgetExceeded:
                coverage.record("authz", "blocked",
                                f"budget: {ep.normalized_url}")
                continue
    # ── operation-aware GraphQL replay (read side; mutations are
    # never replayed) over endpoints with observed query operations
    try:
        findings.extend(authz_graphql_probe(
            endpoints, pool, identities, owner_headers, evidence,
            metrics, coverage, client, matrix, cfg, scope, controls))
    except BudgetExceeded:
        coverage.record("authz", "blocked", "graphql replay budget")
    # ── schema-driven field replay (read side; mutations are never
    # generated) over advertised Query fields with identifier args ──
    try:
        findings.extend(graphql_schema_probe(
            endpoints, pool, identities, owner_headers, evidence,
            metrics, coverage, client, matrix, cfg, scope, controls))
    except BudgetExceeded:
        coverage.record("authz", "blocked", "graphql schema budget")
    # ── Phase 7 views: extended matrix + role/tenant/resource/
    # action analytics over everything the sweeps observed ──────
    from ...authz.matrix import build_extended
    from ...authz.roles import (role_access_map,
                                check_vertical_escalation)
    from ...authz.tenants import tenant_view
    from ...authz.resources import resource_access_map
    from ...authz.actions import action_coverage
    extended = build_extended(matrix.observations, all_swaps)
    views = {
        "roles": role_access_map(extended.cells.values()),
        "vertical_escalations": check_vertical_escalation(
            matrix.observations),
        "tenants": tenant_view(pool, all_swaps),
        "resources": resource_access_map(
            pool, all_swaps, matrix.observations),
        "actions": action_coverage(
            extended.cells.values(), endpoints,
            cfg_a.methods),
    }
    for esc in views["vertical_escalations"]:
        coverage.record("authz", "candidate",
                        f"role gap: {esc['other_identity']} "
                        f"({esc['other_role']}) matches "
                        f"{esc['privileged_identity']} "
                        f"({esc['privileged_role']}) on "
                        f"{esc['method']} {esc['endpoint']}")
    artifact = matrix.to_dict()
    artifact["extended"] = extended.to_dict()
    artifact["views"] = views
    import json as _json
    (out_dir / "authorization_matrix.json").write_text(
        _json.dumps(artifact, indent=2))
    if app_graph is not None:
        from ...authz.graph import sync_extended
        sync_extended(app_graph, pool)
    return findings, matrix, pool


def authz_write_replay(ep, pool, identities, owner_headers,
                       evidence, metrics, coverage, client,
                       ep_params, cfg, scope,
                       controls: ProbeControls) -> List[Finding]:
    """Replay attacker shapes with victim IDs; readback decides."""
    from ...authorization.write_replay import replay_writes
    cfg_a = cfg.authorization
    findings: List[Finding] = []
    for tester in identities or []:
        tester_name = getattr(tester, "name", "anonymous")
        victims = [h for h in pool
                   if getattr(h, "param", "") in (ep_params or set())
                   and getattr(h, "source", "response") == "response"
                   and getattr(h, "owner", "") not in ("", tester_name)]
        if not victims:
            continue
        results = replay_writes(
            client, ep, victims, tester, owner_headers,
            timeout=cfg.scan.http_timeout,
            max_ids=cfg_a.max_ids_per_endpoint, scope=scope)
        for res in results:
            if res.verdict not in ("strong_candidate", "confirmed"):
                if getattr(res, "edge_denied", False):
                    coverage.record(
                        "bola", "inconclusive",
                        f"{ep.normalized_url}::{res.param}: "
                        f"{tester_name} hit edge infrastructure")
                    continue
                # completed denial with a finished request is a
                # genuine negative (same precondition rule as swaps);
                # timeouts and 5xx stay unrecorded, never negative
                if 400 <= res.status < 500:
                    coverage.record(
                        "bola", "tested_negative",
                        f"{ep.normalized_url}::{res.param}: "
                        f"{tester_name}→{res.status}")
                continue
            metrics.authorization_tests += 1
            metrics.authorization_confirmed += 1
            controls.noted()
            cross_tenant = bool(
                res.tester_tenant and res.owner_tenant and
                res.tester_tenant != res.owner_tenant)
            cls = ("tenant_isolation" if cross_tenant else "bola")
            if res.verdict == "confirmed":
                coverage.record(cls, "confirmed", res.notes)
                status = ValidationStatus.CONFIRMED.value
                conf = Confidence.CONFIRMED.value
                extra = ["verified-effect"]
                suffix = " [verified effect]"
            else:
                coverage.record(cls, "candidate", res.notes)
                coverage.record("idor", "candidate", res.notes)
                status = ValidationStatus.STRONG_CANDIDATE.value
                conf = Confidence.PROBABLE.value
                extra = []
                suffix = ""
            f = Finding(
                id=stable_finding_id("bolawrite", res.endpoint_url,
                                     res.method, res.param,
                                     res.victim_value),
                source="bola-write",
                name=(f"BOLA write: '{res.tester}' modifies "
                      f"'{res.owner}''s '{res.param}="
                      f"{res.victim_value}' ({ep.path})" + suffix),
                severity="high",
                confidence=conf,
                validation_status=status,
                host=ep.host, matched_at=res.endpoint_url,
                endpoint_url=res.endpoint_url, method=res.method,
                parameter=res.param,
                description=res.notes,
                tags=["bola", "idor", "authz",
                      "tenant-isolation" if cross_tenant else
                      "cross-user", ep.endpoint_type] + extra,
                raw={"write_replay": res.to_dict()},
                false_positive_notes=(
                    "Victim ID harvested from the owner's own session; "
                    "the attacker's own observed mutating request was "
                    "replayed with only the identifier swapped. "
                    "Confirmation requires a clean readback showing "
                    "the attacker's values newly persisted — confirm "
                    "interactively before reporting."),
                identity=res.tester, tenant=res.tester_tenant,
                resource_key=(f"{ep.normalized_url}::{res.param}"
                              f"={res.victim_value}"),
            )
            evidence.allocate(f)
            evidence.record(
                f,
                request_text=(f"{res.method} {res.endpoint_url}\n(as "
                              f"{res.tester}; owner: {res.owner}; "
                              f"readback: {res.readback})"),
                response_text=res.notes)
            findings.append(f)
            log.info("authz-write-replay: %s", res.notes)
    return findings


def authz_mass_assignment(ep, identities, owner_headers,
                          evidence, metrics, coverage, client,
                          cfg, scope) -> List[Finding]:
    """Inject privileged fields into the tester's own object shape."""
    from ...authorization.write_replay import replay_mass_assignment
    tester = next(
        (i for i in identities or []
         if getattr(i, "name", "anonymous") != "anonymous"
         and dict(getattr(i, "auth_headers", None) or {})), None)
    if tester is None:
        log.info("authz-mass-assignment: no authenticated identity "
                 "with headers — skipping")
        return []
    tester_name = getattr(tester, "name", "tester")
    try:
        results = replay_mass_assignment(
            client, ep, tester, owner_headers,
            timeout=cfg.scan.http_timeout, scope=scope)
    except BudgetExceeded:
        raise
    findings: List[Finding] = []
    for res in results:
        if res.verdict != "strong_candidate":
            if getattr(res, "edge_denied", False):
                coverage.record(
                    "mass_assignment", "inconclusive",
                    f"{ep.normalized_url}::{res.field}: "
                    f"{tester_name} hit edge infrastructure")
            elif res.verdict == "tested_negative":
                coverage.record(
                    "mass_assignment", "tested_negative",
                    f"{ep.normalized_url}::{res.field}: "
                    f"{tester_name}→{res.status}")
            continue
        metrics.authorization_tests += 1
        metrics.authorization_confirmed += 1
        coverage.record("mass_assignment", "candidate", res.notes)
        f = Finding(
            id=stable_finding_id("massassign", res.endpoint_url,
                                 res.method, res.field),
            source="mass-assignment",
            name=(f"Mass assignment: '{res.field}' persisted on "
                  f"'{tester_name}''s own object ({ep.path})"),
            severity="high",
            confidence=Confidence.PROBABLE.value,
            validation_status=ValidationStatus.STRONG_CANDIDATE.value,
            host=ep.host, matched_at=res.endpoint_url,
            endpoint_url=res.endpoint_url, method=res.method,
            parameter=res.field,
            description=res.notes,
            tags=["mass_assignment", "authz", "idor",
                  ep.endpoint_type],
            raw={"mass_assignment": res.to_dict()},
            false_positive_notes=(
                "The probe value is an inert marker, never a real "
                "privilege: persistence proves the binder accepted "
                "the field. Confirm the field carries privilege "
                "impact (roles, tiers, ownership) interactively "
                "before reporting."),
            identity=tester_name,
            tenant=getattr(tester, "tenant", "") or "",
            resource_key=(f"{ep.normalized_url}::{res.field}"),
        )
        evidence.allocate(f)
        evidence.record(
            f,
            request_text=(f"{res.method} {res.endpoint_url}\n(as "
                          f"{tester_name}; own object; "
                          f"readback: {res.readback})"),
            response_text=res.notes)
        findings.append(f)
        log.info("authz-mass-assignment: %s", res.notes)
    return findings
