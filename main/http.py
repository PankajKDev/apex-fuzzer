"""Shared gated HTTP client (limiter + budgets + default-deny gate).

Extracted from the orchestrator: transport policy lives here, stage
logic lives with callers. The client is injected (never imported by
validators), so probes stay testable with fakes.
"""
from typing import Dict, List, Optional
from .budgets import BudgetTracker, BudgetExceeded
from .shell import AdaptiveRateLimiter


class HTTPClient:
    # Methods that never change server state (read-only discovery).
    # Everything else goes through the gate as an active, state-changing
    # test (scope + private-IP + state-change acknowledgement).
    _READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

    def __init__(self, limiter: Optional[AdaptiveRateLimiter] = None,
                 budgets: Optional[BudgetTracker] = None,
                 extra_headers: Optional[Dict[str, str]] = None,
                 user_agent: str = "",
                 scope=None,
                 resolver=None,
                 allow_private_targets: bool = False,
                 allow_state_change: bool = False,
                 approved_cidrs=None):
        import requests
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": (user_agent.strip() or
                           "ApexFuzzer/5.2 (+authorized-testing)")})
        for name, value in (extra_headers or {}).items():
            if isinstance(name, str) and isinstance(value, str) \
                    and name.strip() and value:
                self.session.headers[name.strip()] = value
        self.limiter = limiter
        self.budgets = budgets
        # Default-deny gate (safety/gate.py). None = ungated, preserving
        # today's behavior for direct unit calls; the orchestrator always
        # passes its Scope. Denials are recorded, never sent.
        self.scope = scope
        self.resolver = resolver
        self.allow_private_targets = allow_private_targets
        self.allow_state_change = allow_state_change
        self.approved_cidrs = list(approved_cidrs or [])
        self.scope_denials: List[Dict[str, str]] = []

    def _budget_ok(self, url: str, mutating: bool = False):
        if not self.budgets:
            return
        from urllib.parse import urlparse as _up
        try:
            host = _up(url).hostname or ""
        except Exception:
            host = ""
        if mutating:
            if not self.budgets.consume_mutation(host, url):
                raise BudgetExceeded(f"mutation budget exceeded for {host}")
            return
        if not self.budgets.consume_request(host, url):
            raise BudgetExceeded(f"budget exceeded for {host}")

    def _gate(self, url: str, method: str):
        """Enforce the default-deny gate before any request is sent.

        Ungated (``scope=None``) clients keep today's behavior for
        direct unit calls. Denials raise ScopeRefused and are recorded
        in ``scope_denials``; denied requests never touch the limiter,
        budgets, or the network.
        """
        if self.scope is None:
            return
        from .safety.gate import can_send, ScopeRefused
        read_only = method.upper() in self._READ_METHODS
        decision = can_send(
            url, self.scope, self.resolver, method=method,
            active_test=not read_only, is_state_changing=not read_only,
            allow_private_targets=self.allow_private_targets,
            allow_state_change=self.allow_state_change,
            approved_cidrs=self.approved_cidrs)
        if not decision.allowed:
            self.scope_denials.append(
                {"url": url, "method": method.upper(),
                 "reason": decision.reason})
            raise ScopeRefused(decision.reason, url)

    def get(self, url, **kw):
        self._gate(url, "GET")
        if self.limiter:
            self.limiter.before_request()
        self._budget_ok(url)
        r = self.session.get(url, allow_redirects=False, **kw)
        if self.limiter:
            self.limiter.after_response(r.status_code)
        return r

    def post(self, url, **kw):
        self._gate(url, "POST")
        if self.limiter:
            self.limiter.before_request()
        self._budget_ok(url, mutating=True)
        r = self.session.post(url, allow_redirects=False, **kw)
        if self.limiter:
            self.limiter.after_response(r.status_code)
        return r

    def request(self, method, url, **kw):
        """Generic verb (PUT/PATCH/DELETE…) with limiter + budget gates."""
        self._gate(url, method)
        if self.limiter:
            self.limiter.before_request()
        self._budget_ok(url, mutating=method.upper() != "GET")
        r = self.session.request(method.upper(), url,
                                 allow_redirects=False, **kw)
        if self.limiter:
            self.limiter.after_response(r.status_code)
        return r
