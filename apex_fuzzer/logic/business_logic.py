"""Business-logic mutation engine (bounty item: logic flaws).

For parameters that look numeric or transactional, submits boundary /
abuse values and checks whether the server *accepts* them (HTTP 200
plus the mutated value echoed back). Acceptance is translated into an
invariant observation — a finding requires BOTH acceptance AND an
invariant violation, never a bare 200 (§57). Echo-based acceptance is
a proxy for server-side effect; every finding says so explicitly.

Covered: negative/zero/huge quantities, zero/negative prices,
refund-exceeds-payment pairs, single-use token replay. State-skip
transitions (completed→pending, deleted→modified) need workflow
knowledge and arrive with the Phase 5 workflow engine.
"""
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from ..budgets import BudgetExceeded
from ..logging_setup import get_logger
from .observations import (observation_from_business, evaluate_observation,
                           violated)

log = get_logger("business")

_QTY_HINT = re.compile(
    r"qty|quantity|count|number|limit|stock|balance", re.I)
_PRICE_HINT = re.compile(
    r"price|amount|total|cost|fee|payment", re.I)
_REFUND_HINT = re.compile(r"refund|rebate|credit", re.I)
_TOKEN_HINT = re.compile(
    r"coupon|voucher|promo|invite|reset|token|code|nonce", re.I)

INT_MUTATIONS = [-1, 0, 999999]
SUCCESS_HINTS = ("success", "created", "updated", "applied", "accepted",
                 "confirmed", "redeemed")


@dataclass
class BusinessCandidate:
    endpoint_url: str
    normalized_url: str
    param: str
    location: str
    kind: str  # quantity | price | refund_pair | token_reuse
    sample: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"endpoint_url": self.endpoint_url,
                "normalized_url": self.normalized_url,
                "param": self.param, "location": self.location,
                "kind": self.kind, "sample": self.sample}


@dataclass
class BusinessResult:
    candidate: BusinessCandidate
    identity: str
    identity_tenant: str = ""
    mutated: Any = None
    baseline_status: int = 0
    mutated_status: int = 0
    echoed: bool = False
    accepted_twice: bool = False
    violations: List[Dict[str, Any]] = field(default_factory=list)
    verdict: str = "inconclusive"
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"candidate": self.candidate.to_dict(),
                "identity": self.identity,
                "identity_tenant": self.identity_tenant,
                "mutated": self.mutated,
                "baseline_status": self.baseline_status,
                "mutated_status": self.mutated_status,
                "echoed": self.echoed,
                "accepted_twice": self.accepted_twice,
                "violations": self.violations,
                "verdict": self.verdict, "notes": self.notes}


def candidate_params(endpoint, max_params: int = 3) -> List[BusinessCandidate]:
    """Parameters worth mutating: numeric samples or transactional names."""
    out: List[BusinessCandidate] = []
    params = list(getattr(endpoint, "query_parameters", []) or []) + \
        list(getattr(endpoint, "body_parameters", []) or [])
    for p in params:
        name = p.name or ""
        sample = (p.sample_value or "").strip()
        kind = ""
        if _REFUND_HINT.search(name):
            kind = "refund_pair"
        elif _TOKEN_HINT.search(name):
            kind = "token_reuse"
        elif _QTY_HINT.search(name):
            kind = "quantity"
        elif _PRICE_HINT.search(name):
            kind = "price"
        elif re.fullmatch(r"-?\d+", sample):
            kind = "quantity"
        if kind:
            out.append(BusinessCandidate(
                endpoint_url=endpoint.url,
                normalized_url=endpoint.normalized_url,
                param=name, location=p.location, kind=kind,
                sample=sample))
        if len(out) >= max_params:
            break
    return out


def _is_numeric_sample(sample: str) -> bool:
    return bool(re.fullmatch(r"-?\d+(?:\.\d+)?", (sample or "").strip()))


class BusinessLogicTester:
    def __init__(self, cfg, http):
        self.cfg = cfg
        self.http = http
        self.evaluations = 0  # invariant evaluations performed

    def _send(self, endpoint, params: Dict[str, str], headers: Dict,
              timeout: int) -> tuple:
        """Baseline transport: POST form for body params, else GET query."""
        from urllib.parse import (urlsplit, urlunsplit, parse_qsl,
                                  urlencode)
        has_body = bool(getattr(endpoint, "body_parameters", None))
        if has_body:
            r = self.http.post(endpoint.url, data=params, headers=headers,
                               timeout=timeout)
        else:
            parts = urlsplit(endpoint.url)
            q = parse_qsl(parts.query, keep_blank_values=True)
            q.extend(sorted(params.items()))
            r = self.http.get(urlunsplit(
                (parts.scheme, parts.netloc, parts.path,
                 urlencode(q, doseq=True), "")),
                headers=headers, timeout=timeout)
        return r.status_code, r.text or ""

    def probe(self, endpoint, candidate: BusinessCandidate,
              identity, timeout: int = 10) -> List[BusinessResult]:
        """Baseline, then mutate. Findings need acceptance + violation."""
        name = getattr(identity, "name", "anonymous")
        tenant = getattr(identity, "tenant", "") or ""
        headers = dict(getattr(identity, "auth_headers", None) or {})
        base_params = {p.name: (p.sample_value or "1")
                       for p in list(
                           getattr(endpoint, "query_parameters", []) or [])
                       + list(getattr(endpoint, "body_parameters", []) or [])
                       if p.name}
        out: List[BusinessResult] = []
        try:
            base_status, _ = self._send(endpoint, base_params, headers,
                                        timeout)
        except BudgetExceeded:
            raise
        except Exception as e:
            log.debug("business baseline %s failed: %s",
                      endpoint.url, e)
            return out
        if base_status != 200:
            # precondition rule: no usable baseline → inconclusive,
            # never a negative
            out.append(BusinessResult(
                candidate=candidate, identity=name,
                identity_tenant=tenant,
                baseline_status=base_status, verdict="inconclusive",
                notes="baseline not 200 — endpoint not testable "
                      "as this identity"))
            return out
        mutations = self._mutations_for(candidate)
        for mutated in mutations:
            out.append(self._try_mutation(
                endpoint, candidate, base_params, mutated, headers,
                name, tenant, timeout))
        # token-reuse is a double-submit, handled separately
        if candidate.kind == "token_reuse" and candidate.sample:
            out.append(self._try_reuse(
                endpoint, candidate, base_params, headers, name,
                tenant, timeout))
        return out

    def _mutations_for(self, candidate: BusinessCandidate) -> List[Any]:
        if candidate.kind in ("quantity", "price"):
            return list(INT_MUTATIONS)
        if candidate.kind == "refund_pair":
            return [1000000]  # absurd refund vs any real payment
        return []

    def _try_mutation(self, endpoint, candidate, base_params, mutated,
                      headers, name, tenant, timeout) -> BusinessResult:
        res = BusinessResult(candidate=candidate, identity=name,
                             identity_tenant=tenant, mutated=mutated,
                             baseline_status=200)
        params = dict(base_params)
        params[candidate.param] = str(mutated)
        try:
            status, body = self._send(endpoint, params, headers, timeout)
        except BudgetExceeded:
            raise
        except Exception as e:
            res.notes = f"mutated request failed: {e}"[:200]
            return res
        res.mutated_status = status
        res.echoed = str(mutated) in body and status == 200
        if not res.echoed:
            res.notes = (f"mutated {candidate.param}={mutated} → "
                         f"HTTP {status}, value not reflected")
            return res
        obs = observation_from_business(
            endpoint.url, name, candidate.param, mutated, True,
            status, tenant)
        if candidate.kind == "refund_pair":
            pay = self._find_payment(base_params)
            if pay is not None:
                obs["payment"] = pay
                obs["refund"] = mutated
        self.evaluations += 1
        results = evaluate_observation(obs)
        hits = violated(results)
        if hits:
            res.verdict = "strong_candidate"
            res.violations = [h.to_dict() for h in hits]
            res.notes = (f"server accepted {candidate.param}={mutated} "
                         f"(echoed, HTTP 200); invariant violated: "
                         f"{hits[0].invariant_id} — {hits[0].detail}")
        else:
            res.notes = (f"accepted + echoed but no invariant violated "
                         f"({candidate.param}={mutated})")
        return res

    def _try_reuse(self, endpoint, candidate, base_params, headers,
                   name, tenant, timeout) -> BusinessResult:
        res = BusinessResult(candidate=candidate, identity=name,
                             identity_tenant=tenant,
                             mutated=candidate.sample,
                             baseline_status=200)
        try:
            s1, b1 = self._send(endpoint, base_params, headers, timeout)
            s2, b2 = self._send(endpoint, base_params, headers, timeout)
        except BudgetExceeded:
            raise
        except Exception as e:
            res.notes = f"reuse probe failed: {e}"[:200]
            return res
        same_shape = False
        if s1 == 200 and s2 == 200:
            try:
                from ..validation.differential import normalize_response

                class _R:
                    def __init__(self, st, tx):
                        self.status_code = st
                        self.text = tx
                n1 = normalize_response(_R(s1, b1))
                n2 = normalize_response(_R(s2, b2))
                same_shape = bool(n1.get("body_hash")) and \
                    n1["body_hash"] == n2["body_hash"]
            except Exception:
                same_shape = False
        res.accepted_twice = same_shape
        if same_shape:
            obs = observation_from_business(
                endpoint.url, name, candidate.param, candidate.sample,
                True, s2, tenant,
                extra={"token_single_use": True, "token_reused": True})
            self.evaluations += 1
            hits = violated(evaluate_observation(obs))
            if hits:
                res.verdict = "strong_candidate"
                res.violations = [h.to_dict() for h in hits]
                res.notes = (f"single-use value '{candidate.sample}' "
                             f"accepted twice with identical response; "
                             f"{hits[0].detail}")
            else:
                res.notes = "accepted twice but no invariant fired"
        else:
            res.notes = f"reuse gave {s1}/{s2} — not replayable"
        return res

    @staticmethod
    def _find_payment(params: Dict[str, str]) -> Optional[float]:
        for k, v in params.items():
            if _PRICE_HINT.search(k) and _is_numeric_sample(v):
                try:
                    return float(v)
                except ValueError:
                    continue
        return None
