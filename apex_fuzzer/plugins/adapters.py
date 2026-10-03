"""Built-in plugins: thin adapters over the existing validators.

These change *how* engines are invoked (registry + TestResult), not
*what* they do. Preserved semantics from the pre-plugin loop:

- mutation prescreen runs before the heavy validator of the same class;
- a prescreen hit does NOT suppress the heavy validator — when the
  heavy tool is available it runs too and its outcome wins (last write);
- prescreen outcomes record evidence without pre-allocating a proof dir;
  heavy validators allocate first.
"""
from typing import Optional, Tuple
from .base import (SecurityTest, TestTarget, TestContext, register)
from ..models import (TestResult, RESULT_CONFIRMED, RESULT_CANDIDATE,
                      RESULT_NEGATIVE, RESULT_INCONCLUSIVE,
                      ValidationStatus, Confidence)
from ..validation.base import Candidate
from ..validation.mutate import MutationEngine
from ..validation.sqli import SqliValidator
from ..validation.xss import XssValidator
from ..validation.ssrf import SsrfValidator


def _candidate_from(target: TestTarget, test_class: str) -> Candidate:
    return Candidate(finding=target.finding, test_class=test_class,
                     endpoint_url=target.endpoint_url,
                     method=target.method or "GET",
                     parameter=target.parameter)


class _ClassGated(SecurityTest):
    handled_classes: Tuple[str, ...] = ()
    allocates_evidence = True

    def _class_ok(self, target: TestTarget) -> Optional[TestResult]:
        cls = (target.test_class or "unknown").lower()
        if self.handled_classes and cls not in self.handled_classes:
            return TestResult(status="skipped",
                              observations=[f"class {cls} not handled"])
        return None


def _from_sqli_mutation(outcome) -> TestResult:
    if outcome is None:
        return TestResult(status="skipped",
                          observations=["no mutation signal"])
    if outcome.status == ValidationStatus.CONFIRMED.value:
        st = RESULT_CONFIRMED
    elif outcome.status == ValidationStatus.STRONG_CANDIDATE.value:
        st = RESULT_CANDIDATE
    elif outcome.status == ValidationStatus.FALSE_POSITIVE.value:
        st = RESULT_NEGATIVE
    else:
        st = RESULT_INCONCLUSIVE
    return TestResult(status=st, evidence=dict(outcome.evidence or {}),
                      observations=[outcome.notes or ""])


class SqliMutationPlugin(_ClassGated):
    name = "sqli-mutation"
    handled_classes = ("sqli",)
    prerequisites = ("net",)
    allocates_evidence = False

    def run(self, target: TestTarget, ctx: TestContext) -> TestResult:
        gated = self._class_ok(target)
        if gated:
            return gated
        if not ctx.cfg.validation.mutation:
            return TestResult(status="skipped",
                              observations=["mutation engine disabled"])
        engine = MutationEngine(ctx.cfg, ctx.http, ctx.waf)
        return _from_sqli_mutation(engine.prescreen_sqli(
            _candidate_from(target, "sqli")))


class SqliPlugin(_ClassGated):
    name = "sqli-sqlmap"
    handled_classes = ("sqli",)
    prerequisites = ("net", "tool:sqlmap")

    def run(self, target: TestTarget, ctx: TestContext) -> TestResult:
        gated = self._class_ok(target)
        if gated:
            return gated
        outcome = SqliValidator(ctx.cfg).validate(
            _candidate_from(target, "sqli"))
        if "vulnerable" in (outcome.notes or "").lower() or \
                outcome.status == ValidationStatus.CONFIRMED.value:
            st = RESULT_CONFIRMED
        elif outcome.status == ValidationStatus.FALSE_POSITIVE.value:
            st = RESULT_NEGATIVE
        else:
            st = RESULT_INCONCLUSIVE
        return TestResult(status=st, evidence=dict(outcome.evidence or {}),
                          observations=[outcome.notes or ""])


class XssMutationPlugin(_ClassGated):
    name = "xss-mutation"
    handled_classes = ("xss",)
    prerequisites = ("net",)
    allocates_evidence = False

    def run(self, target: TestTarget, ctx: TestContext) -> TestResult:
        gated = self._class_ok(target)
        if gated:
            return gated
        if not ctx.cfg.validation.mutation:
            return TestResult(status="skipped",
                              observations=["mutation engine disabled"])
        engine = MutationEngine(ctx.cfg, ctx.http, ctx.waf)
        return _from_sqli_mutation(engine.prescreen_xss(
            _candidate_from(target, "xss")))


class XssPlugin(_ClassGated):
    name = "xss-dalfox"
    handled_classes = ("xss",)
    prerequisites = ("net", "tool:dalfox")

    def run(self, target: TestTarget, ctx: TestContext) -> TestResult:
        gated = self._class_ok(target)
        if gated:
            return gated
        outcome = XssValidator(ctx.cfg).validate(
            _candidate_from(target, "xss"))
        if outcome.status == ValidationStatus.STRONG_CANDIDATE.value:
            st = RESULT_CANDIDATE
        elif outcome.status == ValidationStatus.FALSE_POSITIVE.value:
            st = RESULT_NEGATIVE
        else:
            st = RESULT_INCONCLUSIVE
        return TestResult(status=st, evidence=dict(outcome.evidence or {}),
                          observations=[outcome.notes or ""])


class SsrfPlugin(_ClassGated):
    name = "ssrf-oast"
    handled_classes = ("ssrf",)
    prerequisites = ("net", "oast")

    def run(self, target: TestTarget, ctx: TestContext) -> TestResult:
        gated = self._class_ok(target)
        if gated:
            return gated
        outcome = SsrfValidator(ctx.cfg, ctx.oast_provider,
                                ctx.http).validate(
            _candidate_from(target, "ssrf"))
        if outcome.status == ValidationStatus.CONFIRMED.value:
            st = RESULT_CONFIRMED
        else:
            st = RESULT_INCONCLUSIVE
        return TestResult(status=st, evidence=dict(outcome.evidence or {}),
                          observations=[outcome.notes or ""])


for _p in (SqliMutationPlugin(), SqliPlugin(), XssMutationPlugin(),
           XssPlugin(), SsrfPlugin()):
    register(_p)

# fixed execution order: prescreen before heavy tool, same class grouped
PLUGIN_ORDER = ["sqli-mutation", "sqli-sqlmap", "xss-mutation",
                "xss-dalfox", "ssrf-oast"]
