"""Tests for the default-deny gate wired into _HTTPClient (no network)."""
import pytest

from main.config import ScopeConfig
from main.orchestrator import _HTTPClient
from main.safety.gate import ScopeRefused, REASON_ALLOWED
from main.scope import Scope


class FakeResolver:
    def __init__(self, mapping):
        self.mapping = mapping
        self.calls = []

    def resolve(self, host):
        self.calls.append(host)
        if host not in self.mapping:
            raise RuntimeError("NXDOMAIN")
        return list(self.mapping[host])


class FakeSession:
    def __init__(self):
        self.calls = []

    def _resp(self):
        class R:
            status_code = 200
        return R()

    def get(self, url, **kw):
        self.calls.append(("GET", url))
        return self._resp()

    def post(self, url, **kw):
        self.calls.append(("POST", url))
        return self._resp()

    def request(self, method, url, **kw):
        self.calls.append((method, url))
        return self._resp()


class CountingBudgets:
    def __init__(self):
        self.requests = 0
        self.mutations = 0

    def consume_request(self, host, url):
        self.requests += 1
        return True

    def consume_mutation(self, host, url):
        self.mutations += 1
        return True


def _scope():
    return Scope(ScopeConfig(allowed_domains=["example.com"]))


def _client(**kw):
    kw.setdefault("scope", _scope())
    kw.setdefault("resolver", FakeResolver({"example.com": ["93.184.216.34"]}))
    c = _HTTPClient(**kw)
    c.session = FakeSession()
    return c


def test_ungated_client_preserves_legacy_behavior():
    class Exploding:
        def resolve(self, host):
            raise AssertionError("no DNS without scope")
    c = _HTTPClient()
    c.session = FakeSession()
    c.resolver = Exploding()
    r = c.get("https://anything.example/x")
    assert r.status_code == 200
    assert c.session.calls == [("GET", "https://anything.example/x")]
    assert c.scope_denials == []


def test_gated_get_allowed_passes_through():
    c = _client()
    r = c.get("https://example.com/api")
    assert r.status_code == 200
    assert c.session.calls == [("GET", "https://example.com/api")]
    assert c.scope_denials == []


def test_out_of_scope_raises_without_sending():
    c = _client()
    with pytest.raises(ScopeRefused) as ei:
        c.get("https://evil.com/")
    assert ei.value.reason == "out_of_scope"
    assert c.session.calls == []
    assert c.scope_denials == [
        {"url": "https://evil.com/", "method": "GET",
         "reason": "out_of_scope"}]


def test_private_ip_blocked_without_sending():
    resolver = FakeResolver({"example.com": ["10.1.2.3"]})
    c = _client(resolver=resolver)
    with pytest.raises(ScopeRefused) as ei:
        c.get("https://example.com/")
    assert ei.value.reason == "blocked_ip_range"
    assert c.session.calls == []


def test_lab_mode_and_approved_cidrs_allow_private():
    resolver = FakeResolver({"example.com": ["10.1.2.3"]})
    lab = _client(resolver=resolver, allow_private_targets=True)
    assert lab.get("https://example.com/").status_code == 200

    approved = _client(resolver=FakeResolver({"example.com": ["10.1.2.3"]}),
                       approved_cidrs=["10.0.0.0/8"])
    assert approved.get("https://example.com/").status_code == 200

    other = _client(resolver=FakeResolver({"example.com": ["10.1.2.3"]}),
                    approved_cidrs=["192.168.0.0/16"])
    with pytest.raises(ScopeRefused):
        other.get("https://example.com/")


def test_post_needs_state_change_ack():
    c = _client()
    with pytest.raises(ScopeRefused) as ei:
        c.post("https://example.com/api")
    assert ei.value.reason == "state_change_disabled"
    assert c.session.calls == []

    acked = _client(allow_state_change=True)
    assert acked.post("https://example.com/api").status_code == 200


def test_request_verb_dispatch():
    c = _client(allow_state_change=True)
    assert c.request("DELETE", "https://example.com/api").status_code == 200
    assert c.session.calls == [("DELETE", "https://example.com/api")]
    refused = _client()
    with pytest.raises(ScopeRefused):
        refused.request("DELETE", "https://example.com/api")


def test_denial_consumes_no_budget():
    budgets = CountingBudgets()
    c = _client(budgets=budgets)
    with pytest.raises(ScopeRefused):
        c.get("https://evil.com/")
    assert budgets.requests == 0 and budgets.mutations == 0
    c.get("https://example.com/api")
    assert budgets.requests == 1


def test_reason_strings_stable_for_audit_db():
    import main.safety.gate as g
    assert g.REASON_ALLOWED == "allowed"
    assert REASON_ALLOWED == "allowed"


def test_scope_refused_is_budget_exceeded():
    """Contract: every `except BudgetExceeded → blocked` site in the
    tree handles gate denials with zero per-site edits."""
    from main.budgets import BudgetExceeded
    from main.safety.gate import ScopeRefused
    assert issubclass(ScopeRefused, BudgetExceeded)
    c = _client()
    try:
        c.get("https://evil.com/")
        raise AssertionError("must refuse")
    except BudgetExceeded as exc:
        assert isinstance(exc, ScopeRefused)
        assert exc.reason == "out_of_scope"


def test_differential_probe_propagates_denial_as_blocked():
    """A denied differential URL re-raises (caller records BLOCKED)
    instead of collapsing into per-context errors."""
    from main.budgets import BudgetExceeded
    from main.config import Config
    from main.validation.differential import DifferentialTester
    import pytest as _pytest
    c = _client()
    with _pytest.raises(BudgetExceeded):
        DifferentialTester(Config(), c).probe("https://evil.com/api")


def test_mutation_fetch_propagates_denial():
    from main.budgets import BudgetExceeded
    from main.config import Config
    from main.validation.mutate import MutationEngine
    import pytest as _pytest
    c = _client()
    with _pytest.raises(BudgetExceeded):
        MutationEngine(Config(), c, None)._fetch("https://evil.com/api")
