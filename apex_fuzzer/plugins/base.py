"""Pluggable security-test interface (§48).

New engines subclass :class:`SecurityTest`, declare which endpoint
types they support and what they need, and implement :meth:`run`,
which returns a :class:`TestResult` — never a Finding directly. The
orchestrator maps results to findings, so a new scanner lands as a
new file plus one registry line instead of orchestrator surgery.

Prerequisite tokens (strings in ``prerequisites``):

- ``tool:<binary>``   — external binary must exist (e.g. ``tool:sqlmap``)
- ``oast``             — a live Interactsh provider in the context
- ``auth:N``           — at least N authenticated identities
- ``tech:<name>``      — technology must be fingerprinted
- ``net``              — direct HTTP allowed (always true in phase 1)
"""
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple
from ..models import TestResult, RESULT_SKIPPED
from ..logging_setup import get_logger

log = get_logger("plugins")

_REGISTRY: Dict[str, "SecurityTest"] = {}


def register(test: "SecurityTest"):
    _REGISTRY[test.name] = test


def get(name: str) -> Optional["SecurityTest"]:
    return _REGISTRY.get(name)


def registered() -> List[str]:
    return sorted(_REGISTRY.keys())


class TestTarget:
    """What to test: resolved endpoint + parameter + method."""

    __test__ = False  # not a pytest test case

    def __init__(self, endpoint_url: str, endpoint_type: str = "unknown",
                 parameter: Optional[str] = None, method: str = "GET",
                 finding=None, endpoint=None, test_class: str = "unknown"):
        self.endpoint_url = endpoint_url
        self.endpoint_type = endpoint_type
        self.parameter = parameter
        self.method = method
        self.finding = finding
        self.endpoint = endpoint
        self.test_class = test_class


class TestContext:
    """Everything a test may need — the orchestrator fills it per scan."""

    __test__ = False  # not a pytest test case

    def __init__(self, cfg, http=None, scope=None, budgets=None,
                 oast_provider=None, waf: Optional[str] = None,
                 technologies: Optional[List] = None,
                 identities: Optional[List] = None,
                 evidence=None, timeout: int = 10):
        self.cfg = cfg
        self.http = http
        self.scope = scope
        self.budgets = budgets
        self.oast_provider = oast_provider
        self.waf = waf
        self.technologies = technologies or []
        self.identities = identities or []
        self.evidence = evidence
        self.timeout = timeout

    @property
    def authenticated_identities(self) -> List:
        return [i for i in self.identities
                if getattr(i, "name", "anonymous") != "anonymous"]


class SecurityTest(ABC):
    name = "base"
    # endpoint types this test applies to; empty = all
    supported_endpoint_types: Tuple[str, ...] = ()
    prerequisites: Tuple[str, ...] = ()

    def supports(self, target: TestTarget) -> bool:
        if not self.supported_endpoint_types:
            return True
        return target.endpoint_type in self.supported_endpoint_types

    def check_prerequisites(self, ctx: TestContext
                            ) -> Tuple[bool, str]:
        from ..shell import which
        for pre in self.prerequisites:
            if pre.startswith("tool:"):
                if which(pre[5:]) is None:
                    return False, f"missing tool {pre[5:]}"
            elif pre == "oast":
                if ctx.oast_provider is None or \
                        not ctx.oast_provider.available():
                    return False, "no live OAST provider"
            elif pre.startswith("auth:"):
                try:
                    need = int(pre[5:])
                except ValueError:
                    return False, f"bad prerequisite {pre}"
                if len(ctx.authenticated_identities) < need:
                    return False, \
                        f"needs {need} authenticated identities"
            elif pre.startswith("tech:"):
                names = {getattr(t, "name", t) if not isinstance(t, dict)
                         else t.get("name", "")
                         for t in ctx.technologies}
                if pre[5:] not in names:
                    return False, f"technology {pre[5:]} not detected"
            elif pre == "net":
                if ctx.http is None:
                    return False, "no HTTP client"
        return True, ""

    @abstractmethod
    def run(self, target: TestTarget, ctx: TestContext) -> TestResult:
        raise NotImplementedError


def run_plugins(target: TestTarget, ctx: TestContext,
                names: List[str]) -> List[Tuple[SecurityTest, TestResult]]:
    """Execute named plugins in order; unsuitable ones are skipped with
    a SKIPPED result (never an error, never a negative)."""
    out = []
    for name in names:
        plugin = get(name)
        if plugin is None:
            log.warning("unknown plugin requested: %s", name)
            continue
        if not plugin.supports(target):
            out.append((plugin, TestResult(
                status=RESULT_SKIPPED,
                observations=[f"endpoint type {target.endpoint_type} "
                              f"unsupported"])))
            continue
        ok, reason = plugin.check_prerequisites(ctx)
        if not ok:
            out.append((plugin, TestResult(
                status=RESULT_SKIPPED, observations=[reason])))
            continue
        t0 = time.time()
        try:
            res = plugin.run(target, ctx)
            res.duration_seconds = time.time() - t0
        except Exception as e:
            log.warning("plugin %s errored: %s", name, e, exc_info=True)
            res = TestResult(status="error", errors=[str(e)[:300]],
                             duration_seconds=time.time() - t0)
        out.append((plugin, res))
    return out
