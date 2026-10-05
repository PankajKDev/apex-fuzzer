"""Tests for the centralized scope gate (default-deny)."""
from main.config import ScopeConfig
from main.scope import Scope
from main.safety import gate


class FakeResolver:
    def __init__(self, mapping):
        self.mapping = mapping

    def resolve(self, host):
        if host not in self.mapping:
            raise RuntimeError("NXDOMAIN")
        return list(self.mapping[host])


def _scope():
    return Scope(ScopeConfig(allowed_domains=["example.com"]))


def test_allowed_public_ip():
    r = FakeResolver({"example.com": ["93.184.216.34"]})
    d = gate.can_send("https://example.com/api", _scope(), r)
    assert d.allowed and d.reason == gate.REASON_ALLOWED


def test_unsupported_scheme():
    r = FakeResolver({"example.com": ["93.184.216.34"]})
    d = gate.can_send("ftp://example.com/x", _scope(), r)
    assert not d.allowed and d.reason == gate.REASON_UNSUPPORTED_SCHEME


def test_out_of_scope_denied_before_dns():
    class Exploding:
        def resolve(self, host):
            raise AssertionError("resolver must not run out-of-scope")
    d = gate.can_send("https://evil.com/", _scope(), Exploding())
    assert not d.allowed and d.reason == gate.REASON_OUT_OF_SCOPE


def test_active_test_excluded():
    r = FakeResolver({"example.com": ["93.184.216.34"]})
    d = gate.can_send("https://example.com/logo.png", _scope(), r,
                      active_test=True)
    assert not d.allowed and d.reason == gate.REASON_ACTIVE_TEST_EXCLUDED
    # same URL as a discovery read is still allowed
    d2 = gate.can_send("https://example.com/logo.png", _scope(), r)
    assert d2.allowed


def test_private_ip_blocked():
    r = FakeResolver({"example.com": ["192.168.1.10"]})
    d = gate.can_send("https://example.com/", _scope(), r)
    assert not d.allowed and d.reason == gate.REASON_BLOCKED_IP_RANGE


def test_disallowed_port_denied_without_dns():
    from main.config import ScopeConfig
    from main.scope import Scope
    scope = Scope(ScopeConfig(allowed_domains=["example.com"],
                              allowed_ports=[443]))

    class Exploding:
        def resolve(self, host):
            raise AssertionError("no DNS past a scope denial")
    d = gate.can_send("https://example.com:8080/", scope, Exploding())
    assert not d.allowed and d.reason == "disallowed_port"


def test_private_ip_allowed_in_lab_mode():
    r = FakeResolver({"example.com": ["192.168.1.10"]})
    d = gate.can_send("https://example.com/", _scope(), r,
                      allow_private_targets=True)
    assert d.allowed


def test_metadata_and_loopback_blocked():
    for ip in ("169.254.169.254", "127.0.0.1", "10.0.0.5", "::1",
               "0.0.0.0", "224.0.0.1"):
        assert gate.is_non_public_ip(ip), ip
    assert not gate.is_non_public_ip("93.184.216.34")
    assert gate.is_non_public_ip("not-an-ip")  # fail closed


def test_dns_failure_denied():
    d = gate.can_send("https://example.com/", _scope(),
                      FakeResolver({}))
    assert not d.allowed and d.reason == gate.REASON_DNS_FAILURE


def test_state_change_gate():
    r = FakeResolver({"example.com": ["93.184.216.34"]})
    d = gate.can_send("https://example.com/api", _scope(), r,
                      is_state_changing=True)
    assert not d.allowed and d.reason == gate.REASON_STATE_CHANGE_DISABLED
    d2 = gate.can_send("https://example.com/api", _scope(), r,
                       is_state_changing=True, allow_state_change=True)
    assert d2.allowed


def test_redirect_rechecked():
    r = FakeResolver({"example.com": ["93.184.216.34"]})
    d = gate.check_redirect("https://example.com/a", "/b", _scope(), r)
    assert d.allowed
    d2 = gate.check_redirect("https://example.com/a",
                             "https://evil.com/b", _scope(), r)
    assert not d2.allowed and d2.reason == gate.REASON_OUT_OF_SCOPE


def test_redirect_to_private_blocked():
    r = FakeResolver({"internal.example.com": ["10.9.9.9"]})
    scope = Scope(ScopeConfig(allowed_domains=["example.com"]))
    d = gate.check_redirect("https://example.com/a",
                            "https://internal.example.com/b", scope, r)
    assert not d.allowed and d.reason == gate.REASON_BLOCKED_IP_RANGE


def test_approved_cidrs_bypass_private_block():
    r = FakeResolver({"example.com": ["10.9.9.9"]})
    d = gate.can_send("https://example.com/", _scope(), r,
                      approved_cidrs=["10.0.0.0/8"])
    assert d.allowed and d.reason == gate.REASON_ALLOWED
    d2 = gate.can_send("https://example.com/", _scope(), r,
                       approved_cidrs=["192.168.0.0/16", "not-a-cidr"])
    assert not d2.allowed and d2.reason == gate.REASON_BLOCKED_IP_RANGE
