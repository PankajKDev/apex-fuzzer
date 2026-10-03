"""Request budgets (§50) — backstop against runaway testing.

Every direct HTTP request passes through ``BudgetTracker.consume`` via
``_HTTPClient``; looping engines (differential, OAST, and later the
authz matrix / AI agent) additionally consume per-test-class budgets
before probing. All caps are generous by default: a normal scan stays
an order of magnitude below every limit.
"""
import threading
from dataclasses import dataclass, field
from typing import Dict
from .logging_setup import get_logger

log = get_logger("budgets")


class BudgetExceeded(Exception):
    """Raised by the HTTP client when a request would exceed a budget.

    Probing loops treat this as BLOCKED coverage — never as a negative.
    """


@dataclass
class BudgetUsage:
    per_host: Dict[str, int] = field(default_factory=dict)
    per_endpoint: Dict[str, int] = field(default_factory=dict)
    per_class: Dict[str, int] = field(default_factory=dict)
    blocked: int = 0

    def to_dict(self) -> Dict:
        return {"per_host": dict(self.per_host),
                "per_endpoint": dict(self.per_endpoint),
                "per_class": dict(self.per_class),
                "blocked": self.blocked}

    @classmethod
    def from_dict(cls, d: Dict) -> "BudgetUsage":
        return cls(per_host=dict(d.get("per_host") or {}),
                   per_endpoint=dict(d.get("per_endpoint") or {}),
                   per_class=dict(d.get("per_class") or {}),
                   blocked=int(d.get("blocked") or 0))


class BudgetTracker:
    def __init__(self, cfg):
        self.cfg = cfg.budgets
        self.usage = BudgetUsage()
        self._lock = threading.Lock()

    def _limits(self):
        return self.cfg

    def check_request(self, host: str, endpoint: str) -> bool:
        """True if one more plain HTTP request fits the budgets."""
        with self._lock:
            if (self.usage.per_host.get(host, 0) + 1 >
                    self._limits().requests_per_host):
                return False
            if (self.usage.per_endpoint.get(endpoint, 0) + 1 >
                    self._limits().requests_per_endpoint):
                return False
            return True

    def consume_request(self, host: str, endpoint: str) -> bool:
        """Record one request; False (and counted as blocked) if over."""
        with self._lock:
            lim = self._limits()
            if (self.usage.per_host.get(host, 0) + 1 >
                    lim.requests_per_host):
                self.usage.blocked += 1
                log.warning("budget: host %s over requests_per_host=%d",
                            host, lim.requests_per_host)
                return False
            if (self.usage.per_endpoint.get(endpoint, 0) + 1 >
                    lim.requests_per_endpoint):
                self.usage.blocked += 1
                log.warning("budget: endpoint over requests_per_endpoint=%d",
                            lim.requests_per_endpoint)
                return False
            self.usage.per_host[host] = \
                self.usage.per_host.get(host, 0) + 1
            self.usage.per_endpoint[endpoint] = \
                self.usage.per_endpoint.get(endpoint, 0) + 1
            return True

    def consume_test(self, test_class: str, endpoint: str = "",
                     limit: int | None = None) -> bool:
        """Consume one class-scoped test (authz matrix, AI experiment,
        browser action). ``limit`` overrides the configured cap for
        classes without a dedicated config key."""
        with self._lock:
            lim = self.cfg
            cap = limit
            if cap is None:
                if test_class == "authz":
                    cap = lim.authz_tests_per_endpoint
                elif test_class == "browser":
                    cap = lim.browser_actions
                elif test_class == "ai_experiment":
                    cap = lim.ai_experiments
            key = f"{test_class}::{endpoint}" if endpoint else test_class
            if cap is not None and \
                    self.usage.per_class.get(key, 0) + 1 > cap:
                self.usage.blocked += 1
                log.warning("budget: %s over cap=%d", key, cap)
                return False
            self.usage.per_class[key] = \
                self.usage.per_class.get(key, 0) + 1
            return True

    def to_dict(self) -> Dict:
        return self.usage.to_dict()

    def load_dict(self, d: Dict):
        with self._lock:
            self.usage = BudgetUsage.from_dict(d or {})
