"""Offline intel: behavioral state, workflows, resources, invariants.

Pure analysis over collected artifacts — zero network. Findings only
on observed violations; holdings persist as enforcement evidence.
"""
from pathlib import Path
from typing import List

from ..logging_setup import get_logger
from ..models import (Confidence, Finding, ValidationStatus,
                      stable_finding_id)
from ..reporting.coverage import CoverageTracker
from ..validation.evidence import EvidenceStore
from ..reporting.metrics import Metrics
from ..checkpoints import Checkpoint

log = get_logger("stages-intel")

_INVARIANT_CLASSES = {
    "no_cross_user_read": {"bola", "idor", "tenant_isolation",
                           "authz"},
    "no_unauthorized_write": {"authz", "bfla"},
    "no_access_deleted": {"authz"},
    "no_modify_deleted": {"authz"},
    "no_self_promote": {"authz"},
    "no_expired_session": {"authz", "broken_auth"},
    "no_recharge_refunded": {"business_logic"},
    "quantity_non_negative": {"business_logic"},
    "price_stable": {"business_logic"},
    "refund_lte_payment": {"business_logic"},
    "single_use_token": {"business_logic"},
    "no_revert_completed": {"business_logic"},
}


def check_of(engine, invariant_id: str) -> str:
    for inv in engine.invariants:
        if inv.id == invariant_id:
            return inv.check
    return ""


def record_behavioral_state(app_graph, matrix, out_dir: Path):
    """Sync matrix observations into the graph; snapshot every cell;
    link cross-run changes as transitions. Additive and idempotent."""
    from ..state.graph import (sync_matrix_observations,
                               record_transition)
    from ..state.snapshots import StateSnapshot, SnapshotStore
    from ..state.transitions import TransitionLog
    sync_matrix_observations(app_graph, matrix.observations)
    state_dir = out_dir / "state"
    store = SnapshotStore.load(state_dir / "snapshots.jsonl")
    tlog = TransitionLog.load(state_dir / "transitions.jsonl")
    for o in matrix.observations:
        snap = StateSnapshot.capture(
            identity=o.identity, endpoint=o.endpoint,
            method=o.method, status=o.status, shape=o.shape)
        prev = store.latest(o.identity, o.endpoint, o.method)
        store.add(snap)
        if prev is not None:
            t = tlog.record_if_changed(
                prev, snap, via=snap.snapshot_id, actor=o.identity)
            if t is not None:
                record_transition(app_graph, prev.snapshot_id,
                                  snap.snapshot_id, snap.snapshot_id,
                                  actor=o.identity)
    store.save(state_dir / "snapshots.jsonl")
    tlog.save(state_dir / "transitions.jsonl")


def discover_workflows(out_dir: Path, endpoints, application,
                       app_graph, metrics: Metrics, ck: Checkpoint,
                       harvest_pool: list):
    """Infer flows from collected data only — no requests sent.

    Sources: REST stem grouping, timestamp-ordered browser traffic,
    CRUD linkage, harvested value overlap. Persists workflows.json
    (+ mutation catalog), appends stored workflows to the
    application model, and links step chains in the graph.
    """
    from ..workflows.discovery import discover_all
    from ..workflows.mutations import mutation_catalog
    from ..state.resources import ResourceTracker, \
        link_crud_from_endpoints
    from ..state.graph import ensure_workflow
    import json as _json
    traffic: dict = {}
    traffic_file = out_dir / "browser_traffic.json"
    if traffic_file.exists():
        try:
            traffic = _json.loads(traffic_file.read_text())
        except Exception as e:
            log.debug("workflow discovery: bad traffic file: %s", e)
    # CRUD linkage from app resources × endpoint methods
    tracker = ResourceTracker()
    resources = []
    if application is not None:
        resources = getattr(application, "resources", []) or []
    link_crud_from_endpoints(tracker, resources, endpoints)
    flows = discover_all(
        endpoints=endpoints, traffic=traffic,
        resources=list(tracker.resources.values()),
        harvest_pool=list(harvest_pool or []))
    payload = {"flows": [f.to_dict() for f in flows],
               "mutations": mutation_catalog(flows)}
    (out_dir / "workflows.json").write_text(
        _json.dumps(payload, indent=2))
    if application is not None:
        try:
            stored = [f.to_stored() for f in flows]
            existing = {w.name for w in
                        getattr(application, "workflows", []) or []}
            application.workflows.extend(
                w for w in stored if w.name not in existing)
            (out_dir / "application.json").write_text(
                _json.dumps(application.to_dict(), indent=2))
            ck.save_blob("application", application.to_dict())
        except Exception as e:
            log.debug("workflow discovery: app persist failed: %s",
                      e)
    metrics.workflows_discovered = len(flows)
    if app_graph is not None:
        try:
            for f in flows:
                ensure_workflow(app_graph, f.name,
                                [s.name for s in f.steps])
        except Exception as e:
            log.debug("workflow discovery: graph link failed: %s",
                      e)
    log.info("workflows: %d discovered (%d observed)",
             len(flows), sum(1 for f in flows if f.observed))


def build_resource_intel(out_dir: Path, endpoints, application,
                         app_graph, metrics: Metrics, ck: Checkpoint,
                         harvest_pool: list, page_ids: list,
                         matrix) -> None:
    """Lifecycle-aware resource records from all collected sources.

    Producers (all offline): harvest pool, stashed page IDs, JS
    cache, browser traffic, OpenAPI-declared params (already
    endpoints). Records never drive swap verdicts unless their
    source is an authenticated response (see source filter).
    """
    from ..application.resources import (
        discover_ids_from_js, discover_ids_from_traffic)
    from ..authorization.harvest import HarvestedId
    from ..authz.resources import enrich_resource_records
    from ..discovery.url_normalizer import normalize_url
    from ..state.resources import (ResourceTracker,
                                   link_crud_from_endpoints)
    import json as _json
    pool = list(harvest_pool or [])
    extra: list = []

    def _add(url: str, param: str, value: str, source: str):
        if not url or not param or not value:
            return
        try:
            norm = normalize_url(url)
        except Exception:
            norm = url
        if any(e.normalized_url == norm and e.param == param
               and e.value == value for e in pool + extra):
            return
        extra.append(HarvestedId(
            endpoint_url=url, normalized_url=norm, param=param,
            value=value, owner="", owner_tenant="", shape="",
            body_hash=""))
        extra[-1].source = source

    # stashed page IDs (HTML/headers parsed during mapping)
    for url, param, value, source in page_ids or []:
        _add(url, param, value, source)
    # JS bundle cache (meta files carry the source URL)
    cache_dir = out_dir / "cache"
    if cache_dir.exists():
        for meta_file in sorted(cache_dir.glob("*.meta"))[:50]:
            try:
                data_file = meta_file.with_name(
                    meta_file.name[:-len(".meta")])
                if not data_file.exists():
                    continue
                meta = _json.loads(meta_file.read_text())
                url = str(meta.get("url", ""))
                text = data_file.read_text(
                    errors="ignore")[:200_000]
            except Exception as e:
                log.debug("resource intel: cache read failed: %s",
                          e)
                continue
            if not url:
                continue
            try:
                found = discover_ids_from_js(text)
            except Exception:
                continue
            for pname, pvalue in found.items():
                _add(url, pname, pvalue, "javascript")
    # browser traffic URLs
    traffic_file = out_dir / "browser_traffic.json"
    if traffic_file.exists():
        try:
            traffic = _json.loads(traffic_file.read_text())
            reqs = traffic.get("requests", [])
        except Exception:
            reqs = []
        try:
            for url, pname, pvalue in discover_ids_from_traffic(
                    reqs):
                _add(url, pname, pvalue, "traffic")
        except Exception as e:
            log.debug("resource intel: traffic parse failed: %s", e)
    # matrix observations (permissions) + CRUD linkage + enrich
    observations = list(getattr(matrix, "observations", []) or [])
    tracker = ResourceTracker()
    app_resources = []
    if application is not None:
        app_resources = getattr(application, "resources", []) or []
    link_crud_from_endpoints(tracker, app_resources, endpoints)
    combined = pool + extra
    records = enrich_resource_records(
        combined, observations, tracker, endpoints)
    (out_dir / "resources.json").write_text(
        _json.dumps({"records": records}, indent=2))
    if app_graph is not None and extra:
        try:
            from ..authz.graph import sync_extended
            sync_extended(app_graph, extra)
            app_graph.save(out_dir / "application_graph.json")
            ck.save_blob("application_graph", app_graph.to_dict())
            metrics.graph_nodes = len(app_graph.nodes)
            metrics.graph_edges = len(app_graph.edges)
        except Exception as e:
            log.debug("resource intel: graph sync failed: %s", e)
    log.info("resources: %d enriched records (%d harvest, %d "
             "supplementary)", len(records), len(pool), len(extra))


def discover_invariants(out_dir: Path, endpoints,
                        evidence: EvidenceStore, metrics: Metrics,
                        coverage: CoverageTracker,
                        findings: List[Finding], matrix,
                        harvest_pool: list) -> List[Finding]:
    """Mine holding rules from matrix observations, then run every
    invariant (built-in + discovered) as a second opinion.

    - holding + fires + existing finding in mapped classes →
      corroboration attached, no duplicate;
    - holding + fires + no such finding → new invariant finding;
    - holdings that hold → persisted as enforcement evidence.
    Zero network; findings only on observed violations.
    """
    from ..logic.invariant_discovery import discover_invariants
    from ..logic.invariant_engine import InvariantEngine
    from ..logic.observations import observation_from_matrix_cell
    observations = list(getattr(matrix, "observations", []) or [])
    if not observations:
        log.debug("invariant discovery: no matrix observations")
        return []
    pool = list(harvest_pool or [])
    discovered = discover_invariants(observations, pool)
    engine = InvariantEngine()
    for rule in discovered:
        engine.add(rule.invariant)
    obs_dicts = [observation_from_matrix_cell(o, pool)
                 for o in observations]
    new_findings: List[Finding] = []
    for obs in obs_dicts:
        for res in engine.evaluate(obs):
            metrics.invariants_tested += 1
            if not res.violated:
                continue
            metrics.invariants_violated += 1
            covered = _INVARIANT_CLASSES.get(
                check_of(engine, res.invariant_id), set())
            dup = next((f for f in findings
                        if covered & set(f.tags or [])), None)
            if dup is not None:
                inv_list = dup.raw.setdefault("invariants", [])
                if not any(e.get("invariant_id") == res.invariant_id
                           for e in inv_list):
                    inv_list.append({
                        "invariant_id": res.invariant_id,
                        "detail": res.detail,
                        "corroborated_by": "invariant-engine"})
                continue
            f = Finding(
                id=stable_finding_id(
                    "inv", res.invariant_id,
                    str(obs.get("endpoint", "")),
                    str(obs.get("actor", ""))),
                source="invariant",
                name=(f"Invariant violated: {res.invariant_id} "
                      f"on {obs.get('endpoint', '')}"),
                severity="high",
                confidence=Confidence.PROBABLE.value,
                validation_status=ValidationStatus.STRONG_CANDIDATE.value,
                host="", matched_at=obs.get("endpoint", ""),
                endpoint_url=obs.get("endpoint", ""),
                method="GET",
                description=res.detail,
                tags=["invariant", check_of(
                    engine, res.invariant_id)],
                raw={"invariant_id": res.invariant_id,
                     "observation": obs},
                false_positive_notes=(
                    "Second-opinion evaluation over recorded matrix "
                    "observations — same evidence the verdict passes "
                    "saw, judged by an independent rule. Confirm "
                    "interactively before reporting."),
                identity=str(obs.get("actor", "")),
            )
            evidence.allocate(f)
            evidence.record(
                f,
                request_text=(f"invariant {res.invariant_id} "
                              f"over recorded observations"),
                response_text=res.detail)
            new_findings.append(f)
            for cls in sorted(covered) or ["authz"]:
                coverage.record(cls, "candidate",
                                f"invariant {res.invariant_id}: "
                                f"{res.detail}")
            log.info("invariant: NEW violation %s — %s",
                     res.invariant_id, res.detail)
    import json as _json
    (out_dir / "invariants.json").write_text(_json.dumps(
        {"discovered": [r.to_dict() for r in discovered],
         "summary": engine.summary()}, indent=2))
    return new_findings
