from apex_fuzzer.config import ScopeConfig
from apex_fuzzer.scope import Scope


def test_allowed_domain():
    s = Scope(ScopeConfig(allowed_domains=["example.com"]))
    assert s.is_in_scope("https://example.com/x")
    assert s.is_in_scope("https://api.example.com/y")


def test_off_scope_rejected():
    s = Scope(ScopeConfig(allowed_domains=["example.com"]))
    assert not s.is_in_scope("https://evil.com/")


def test_excluded_host():
    s = Scope(ScopeConfig(allowed_domains=["example.com"],
                          excluded_hosts=["admin.example.com"]))
    assert not s.is_in_scope("https://admin.example.com/")


def test_scheme_required():
    s = Scope(ScopeConfig(allowed_domains=["example.com"]))
    assert not s.is_in_scope("ftp://example.com/")


def test_active_test_blocks_static():
    s = Scope(ScopeConfig(allowed_domains=["example.com"]))
    assert not s.active_test_allowed("https://example.com/logo.png")
    assert s.active_test_allowed("https://example.com/api")
