from main.config import ScopeConfig
from main.scope import Scope, target_hostname


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


def test_target_hostname_excludes_port():
    assert target_hostname("http://localhost:8000") == "localhost"
    assert target_hostname("https://127.0.0.1:9443/path") == "127.0.0.1"
    assert target_hostname("[::1]:8080") == "::1"


def test_wildcard_allowlist_matches_subdomains():
    s = Scope(ScopeConfig(allowed_domains=["*.example.com"]))
    assert s.is_in_scope("https://api.example.com/y")
    assert s.is_in_scope("https://example.com/x")
    assert not s.is_in_scope("https://example.com.attacker.tld/")


def test_deceptive_suffix_never_matches():
    s = Scope(ScopeConfig(allowed_domains=["example.com"]))
    assert not s.is_in_scope("https://example.com.attacker.tld/")
    assert not s.is_in_scope("https://notexample.com/")


def test_allowed_ports_restrict():
    s = Scope(ScopeConfig(allowed_domains=["example.com"],
                          allowed_ports=[443]))
    assert s.is_in_scope("https://example.com/a")
    assert s.is_in_scope("https://example.com:443/a")
    assert not s.is_in_scope("https://example.com:8080/a")
    assert not s.is_in_scope("http://example.com/a")
    _, reason = s.check("https://example.com:8080/a")
    assert reason == "disallowed_port"


def test_empty_ports_means_unrestricted():
    s = Scope(ScopeConfig(allowed_domains=["example.com"]))
    assert s.is_in_scope("https://example.com:8443/a")


def test_check_reasons():
    s = Scope(ScopeConfig(
        allowed_domains=["example.com"],
        excluded_hosts=["admin.example.com"],
        excluded_paths=["/static/"]))
    assert s.check("https://example.com/a") == (True, "allowed")
    assert s.check("https://evil.com/") == (False, "out_of_scope_domain")
    assert s.check("ftp://example.com/") == (False, "unsupported_scheme")
    assert s.check("https://admin.example.com/") == (
        False, "excluded_host")
    assert s.check("https://example.com/static/a") == (
        False, "excluded_path")
    assert s.check("") == (False, "out_of_scope_domain")


def test_scope_check_report(tmp_path):
    from main.cli import scope_check_report
    from main.config import Config
    cfg = Config()
    cfg.scope.allowed_domains = ["example.com"]
    text, denied = scope_check_report(
        cfg, ["https://example.com/a", "https://evil.com/"])
    assert "ALLOW allowed https://example.com/a" in text
    assert "DENY out_of_scope_domain https://evil.com/" in text
    assert denied is True
    _, clean = scope_check_report(cfg, ["https://example.com/a"])
    assert clean is False


def test_allowed_ports_validation():
    from main.config import Config
    cfg = Config()
    cfg.scope.allowed_ports = [443, 0]
    assert any("allowed_ports" in e for e in cfg.validate()["errors"])
    cfg.scope.allowed_ports = [80, 443]
    assert cfg.validate()["errors"] == [] or not any(
        "allowed_ports" in e for e in cfg.validate()["errors"])
