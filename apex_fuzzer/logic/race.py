"""Race-condition engine (synchronized dispatch + comparison).

Fires N identical state-changing requests through a barrier so they
hit the server as simultaneously as the network allows, then compares
outcomes. Signal: all-200 with *divergent* resource identifiers where
the operation should be single/idempotent (double creation, double
spend). Fully consistent rounds are genuine negatives; mixed errors
are inconclusive — never negatives.

Off by default (``race.enabled``); only POST endpoints with body
parameters are targeted (explicitly state-changing surface).
"""
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Dict, List
from ..authorization.harvest import extract_ids_from_body
from ..budgets import BudgetExceeded
from ..logging_setup import get_logger
from .observations import (observation_from_race, evaluate_observation,
                           violated)

log = get_logger("race")
_SINGLE_USE_NAME = re.compile(
    r"coupon|voucher|promo|invite|reset|token|nonce", re.I)


def single_use_field(body: Dict[str, Any]) -> str:
    """Return the first transaction field that names a single-use value."""
    return next((str(name) for name in body
                 if _SINGLE_USE_NAME.search(str(name))), "")


def inventory_value(body_text: str, jsonpath: str):
    """Read one numeric inventory value using the supported JSONPath subset."""
    import json
    import math
    from ..verify.assertions import jsonpath_get
    try:
        data = json.loads(body_text or "")
    except (ValueError, TypeError):
        return None
    understood, matches = jsonpath_get(data, jsonpath)
    if not understood or len(matches) != 1:
        return None
    value = matches[0]
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


@dataclass
class RaceRound:
    statuses: List[int] = field(default_factory=list)
    hashes: List[str] = field(default_factory=list)
    id_sets: List[List[str]] = field(default_factory=list)
    errors: int = 0


@dataclass
class RaceResult:
    endpoint_url: str
    method: str
    concurrency: int
    rounds: int
    round_results: List[RaceRound] = field(default_factory=list)
    verdict: str = "inconclusive"
    notes: str = ""
    violations: List[Dict[str, Any]] = field(default_factory=list)
    profile: str = "generic"

    def to_dict(self) -> Dict[str, Any]:
        return {"endpoint_url": self.endpoint_url, "method": self.method,
                "concurrency": self.concurrency, "rounds": self.rounds,
                "verdict": self.verdict, "notes": self.notes,
                "profile": self.profile,
                "violations": self.violations,
                "rounds_detail": [
                    {"statuses": r.statuses, "hashes": r.hashes,
                     "id_sets": r.id_sets, "errors": r.errors}
                    for r in self.round_results]}


def _single_fire(http, method: str, url: str, body: Dict,
                 headers: Dict, timeout: int, barrier,
                 out: list, idx: int):
    try:
        barrier.wait(timeout=timeout + 10)
    except threading.BrokenBarrierError:
        out[idx] = ("barrier-break", "", [])
        return
    try:
        if method == "POST":
            r = http.post(url, data=body, headers=headers, timeout=timeout)
        else:
            r = http.request(method, url, headers=headers, timeout=timeout)
        ids = sorted(set(extract_ids_from_body(r.text or "").values()))
        import hashlib as _hl
        h = _hl.sha256((r.text or "").encode("utf-8", "replace")
                       ).hexdigest()[:16]
        out[idx] = (r.status_code, h, ids)
    except BudgetExceeded:
        out[idx] = ("budget", "", [])
    except Exception as e:
        log.debug("race fire failed: %s", e)
        out[idx] = ("error", "", [])


def run_race(http, method: str, url: str, body: Dict, headers: Dict,
             concurrency: int = 10, rounds: int = 3,
             timeout: int = 10, profile: str = "generic") -> RaceResult:
    res = RaceResult(endpoint_url=url, method=method,
                     concurrency=concurrency, rounds=rounds,
                     profile=profile)
    tokenish = bool(re.search(r"coupon|voucher|promo|invite|reset|token",
                              url, re.I))
    for _ in range(rounds):
        barrier = threading.Barrier(concurrency)
        slots: list = [None] * concurrency
        with ThreadPoolExecutor(max_workers=concurrency) as ex:
            futures = [ex.submit(_single_fire, http, method, url, body,
                                 headers, timeout, barrier, slots, i)
                       for i in range(concurrency)]
            for fu in futures:
                fu.result()
        if any(s == "budget" for s, _, _ in slots):
            raise BudgetExceeded(f"race over budget at {url}")
        rr = RaceRound()
        for status, h, ids in slots:
            if isinstance(status, int):
                rr.statuses.append(status)
                rr.hashes.append(h)
                rr.id_sets.append(ids)
            else:
                rr.errors += 1
        res.round_results.append(rr)
    # verdict across rounds
    candidate_round = None
    clean_rounds = 0
    for i, rr in enumerate(res.round_results):
        if rr.errors or not rr.statuses:
            continue
        if profile == "single_use":
            # A single-use value must succeed once and be rejected on
            # concurrent replays. 5xx and non-HTTP failures are ambiguous.
            if any(not (200 <= s < 300 or 400 <= s < 500)
                   for s in rr.statuses):
                continue
            accepted = sum(1 for s in rr.statuses if 200 <= s < 300)
            if accepted > 1:
                candidate_round = i
            elif accepted == 1:
                clean_rounds += 1
            continue
        if all(s == 200 for s in rr.statuses):
            distinct = {tuple(sorted(s)) for s in rr.id_sets
                        if s}
            if len(distinct) > 1:
                candidate_round = i
            elif len(set(rr.hashes)) == 1 and rr.errors == 0:
                clean_rounds += 1
            # else: all-200 but bodies differ with no comparable IDs —
            # genuinely ambiguous, deliberately NOT counted clean
            # (Rule 7: never read ambiguity as a negative)
    if candidate_round is not None:
        res.verdict = "strong_candidate"
        rr = res.round_results[candidate_round]
        if profile == "single_use":
            accepted = sum(1 for s in rr.statuses if 200 <= s < 300)
            res.notes = (f"round {candidate_round + 1}: {accepted} of "
                         f"{concurrency} concurrent replays of a "
                         "single-use value succeeded")
        else:
            res.notes = (f"round {candidate_round + 1}: {concurrency}× "
                         f"{method} all-200 with divergent object IDs "
                         f"({len(rr.id_sets)} distinct sets) — operation "
                         f"processed concurrently instead of once")
        obs = observation_from_race(
            url, profile == "single_use" or tokenish, True)
        res.violations = [v.to_dict() for v in
                          violated(evaluate_observation(obs))]
        if not res.violations:
            res.notes += " (no invariant in the default set fired; " \
                         "review manually)"
    elif clean_rounds == rounds and rounds > 0:
        res.verdict = "negative"
        if profile == "single_use":
            res.notes = (f"{rounds} rounds accepted the single-use value "
                         "once each and rejected concurrent replays")
        else:
            res.notes = (f"{rounds} rounds fully consistent — no divergence")
    else:
        res.notes = "mixed errors/statuses — inconclusive, not a negative"
    return res
