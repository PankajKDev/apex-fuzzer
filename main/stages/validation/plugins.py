"""Per-finding plugin result application (evidence aggregation)."""
from typing import List

from ...logging_setup import get_logger
from ...models import RESULT_STATUSES, Finding, ResultStatus
from ...reporting.coverage import CoverageTracker
from ...validation.evidence import EvidenceStore

log = get_logger("stages-validation")


def finding_endpoint(f: Finding, by_norm: dict):
    from ...discovery.url_normalizer import normalize_url
    if not f.matched_at:
        return None
    try:
        return by_norm.get(normalize_url(f.matched_at))
    except Exception:
        return None


def apply_plugin_result(f: Finding, plugin, res, evidence: EvidenceStore,
                        test_class: str, coverage: CoverageTracker):
    """Apply one validator result (legacy/single-plugin helper)."""
    result_status = res.result_status
    if result_status == ResultStatus.VERIFIED_EFFECT.value:
        conf = "confirmed"
    elif result_status == ResultStatus.CANDIDATE.value:
        conf = "probable"
    elif result_status == ResultStatus.NEGATIVE.value:
        conf = "probable"
    else:
        conf = "unknown"
    if result_status is None:
        # Older/custom plugins may still return only the legacy status.
        result_status = {
            "confirmed": ResultStatus.VERIFIED_EFFECT.value,
            "candidate": ResultStatus.CANDIDATE.value,
            "negative": ResultStatus.NEGATIVE.value,
            "inconclusive": ResultStatus.INCONCLUSIVE.value,
        }.get(res.status, ResultStatus.INCONCLUSIVE.value)
    f.set_result_status(result_status)
    f.confidence = conf
    notes = "; ".join(res.observations)[:500]
    if getattr(plugin, "allocates_evidence", True):
        evidence.allocate(f)
        if res.evidence:
            f.raw = res.evidence
        evidence.record(f,
                        request_text=f"{f.method} {f.matched_at}",
                        response_headers=f.response_headers)
    else:
        # prescreen path: record notes without pre-allocating
        f.false_positive_notes = notes
        f.raw = {"evidence": res.evidence}
        evidence.record(
            f, request_text=f"{f.method} {f.matched_at}",
            response_text=notes)
    coverage.record_result(test_class, result_status,
                           notes or f"plugin {plugin.name}")


def plugin_result_status(res) -> str:
    """Normalize legacy and canonical plugin outcomes."""
    result_status = getattr(res, "result_status", None)
    if result_status in RESULT_STATUSES:
        return result_status
    return {
        "confirmed": ResultStatus.VERIFIED_EFFECT.value,
        "candidate": ResultStatus.CANDIDATE.value,
        "negative": ResultStatus.NEGATIVE.value,
        "inconclusive": ResultStatus.INCONCLUSIVE.value,
        "not_tested": ResultStatus.OBSERVATION.value,
    }.get(getattr(res, "status", ""),
          ResultStatus.INCONCLUSIVE.value)


def aggregate_plugin_status(statuses: List[str]) -> str:
    """Combine independent evidence without last-plugin-wins behavior.

    Positive and negative evidence conflicts become inconclusive. An
    inconclusive validator cannot erase a supported candidate; verified
    evidence wins over candidates when no negative evidence conflicts.
    """
    verified = ResultStatus.VERIFIED_EFFECT.value
    candidate = ResultStatus.CANDIDATE.value
    negative = ResultStatus.NEGATIVE.value
    inconclusive = ResultStatus.INCONCLUSIVE.value
    observation = ResultStatus.OBSERVATION.value
    observed = [s for s in statuses if s in RESULT_STATUSES]
    has_positive = verified in observed or candidate in observed
    if has_positive and negative in observed:
        return inconclusive
    if verified in observed:
        return verified
    if candidate in observed:
        return candidate
    if inconclusive in observed:
        return inconclusive
    if negative in observed:
        return negative
    return observation


def apply_plugin_results(f: Finding, plugin_results, evidence,
                         test_class: str, coverage: CoverageTracker):
    """Aggregate validator evidence while retaining each tool's record."""
    normalized = [(plugin, res,
                   plugin_result_status(res))
                  for plugin, res in plugin_results]
    statuses = [f.result_status] + [status for _, _, status in normalized]
    aggregate = aggregate_plugin_status(statuses)

    records = []
    note_parts = []
    for plugin, res, status in normalized:
        observations = list(getattr(res, "observations", []) or [])
        notes = "; ".join(str(note) for note in observations)[:500]
        note_parts.append(f"{plugin.name}: {notes or status}")
        records.append({
            "plugin": plugin.name,
            "result_status": status,
            "duration_seconds": getattr(res, "duration_seconds", 0.0),
            "observations": observations,
            "errors": list(getattr(res, "errors", []) or []),
            "evidence": dict(getattr(res, "evidence", {}) or {}),
        })

    f.set_result_status(aggregate)
    f.confidence = {
        ResultStatus.VERIFIED_EFFECT.value: "confirmed",
        ResultStatus.CANDIDATE.value: "probable",
        ResultStatus.NEGATIVE.value: "probable",
    }.get(aggregate, "unknown")
    combined_notes = " | ".join(note_parts)[:2000]
    if aggregate in (ResultStatus.NEGATIVE.value,
                     ResultStatus.INCONCLUSIVE.value):
        f.false_positive_notes = combined_notes

    # Preserve the original Nuclei/source record and attach each
    # validator's independent evidence under an additive key.
    if not isinstance(f.raw, dict):
        f.raw = {"source_raw": f.raw}
    f.raw["validator_results"] = records

    if any(getattr(plugin, "allocates_evidence", True)
           for plugin, _, _ in normalized) and not f.evidence_dir:
        evidence.allocate(f)
    evidence.record(
        f, request_text=f"{f.method} {f.matched_at}",
        response_text=combined_notes,
        response_headers=f.response_headers)
    coverage.record_result(
        test_class, aggregate,
        combined_notes or "aggregated plugin outcomes")
