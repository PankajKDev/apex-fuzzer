"""Attack chains: deterministic finding→capability→impact hypotheses.

Zero network — the builder reads recorded findings only. Chains are
always hypothesized, never confirmed, and never alter finding counts.
"""
from main.chains.builder import build_attack_chains, build_chains
from main.chains.models import HYPOTHESIZED
from main.models import Finding


def _finding(id, source, host="example.test", url="", tags=(),
             status="strong_candidate"):
    return Finding(
        id=id, source=source, host=host,
        endpoint_url=url or f"https://{host}/app",
        matched_at=url or f"https://{host}/app",
        tags=list(tags), validation_status=status)


def test_no_findings_no_chains():
    assert build_chains([]) == []
    assert build_chains(None) == []


def test_reset_poison_forms_single_chain():
    chains = build_chains([
        _finding("r1", "reset-poison",
                 url="https://example.test/forgot")])
    assert len(chains) == 1
    chain = chains[0]
    assert chain.rule == "reset-poison"
    assert chain.status == HYPOTHESIZED
    assert chain.confidence == "possible"
    assert chain.impact == "account-takeover"
    assert chain.finding_ids == ["r1"]
    assert chain.missing_links
    assert any(s.kind == "impact" for s in chain.steps)


def test_enum_plus_poison_upgrades_confidence():
    chains = build_chains([
        _finding("r1", "reset-poison",
                 url="https://example.test/forgot"),
        _finding("r2", "reset-enum",
                 url="https://example.test/forgot")])
    by_rule = {c.rule: c for c in chains}
    assert by_rule["reset-enum-assists"].confidence == "probable"
    assert by_rule["reset-enum-assists"].finding_ids == ["r1", "r2"]
    assert "reset-poison" in by_rule


def test_xss_needs_auth_surface():
    auth_xss = _finding("x1", "prescreen-xss",
                        url="https://example.test/login",
                        tags=["authentication"])
    chains = build_chains([auth_xss])
    assert [c.rule for c in chains] == ["xss-session-theft"]
    plain = _finding("x2", "prescreen-xss",
                     url="https://example.test/about")
    assert build_chains([plain]) == []


def test_oauth_needs_same_host_redirect():
    pair = [_finding("o1", "oauth-pkce",
                     url="https://example.test/oauth/authorize"),
            _finding("d1", "open-redirect-validator",
                     url="https://example.test/go")]
    chains = build_chains(pair)
    assert [c.rule for c in chains] == ["oauth-token-theft"]
    assert chains[0].confidence == "probable"
    split = [_finding("o1", "oauth-pkce", host="a.test"),
             _finding("d1", "open-redirect-validator", host="b.test")]
    assert build_chains(split) == []


def test_reset_plus_otp_forms_full_chain():
    chains = build_chains([
        _finding("r1", "reset-enum",
                 url="https://example.test/forgot"),
        _finding("t1", "otp-bypass",
                 url="https://example.test/verify-otp")])
    assert [c.rule for c in chains] == ["reset-plus-otp"]
    assert chains[0].confidence == "probable"


def test_sqli_auth_bypass_grades_confirmation():
    maybe = _finding("s1", "prescreen-sqli",
                     url="https://example.test/login")
    assert build_chains([maybe])[0].confidence == "possible"
    sure = _finding("s1", "prescreen-sqli",
                    url="https://example.test/login",
                    status="confirmed")
    assert build_chains([sure])[0].confidence == "probable"


def test_cors_needs_cross_user_read():
    chains = build_chains([
        _finding("c1", "cors-validator",
                 url="https://example.test/api/me"),
        _finding("b1", "idor-swap",
                 url="https://example.test/api/me")])
    assert [c.rule for c in chains] == ["cors-session-read"]
    assert build_chains([
        _finding("c1", "cors-validator",
                 url="https://example.test/api/me")]) == []


def test_chains_never_confirm():
    findings = [
        _finding("r1", "reset-poison",
                 url="https://example.test/forgot"),
        _finding("r2", "reset-enum",
                 url="https://example.test/forgot"),
        _finding("t1", "otp-bypass",
                 url="https://example.test/verify-otp"),
        _finding("s1", "prescreen-sqli",
                 url="https://example.test/login", status="confirmed"),
    ]
    chains = build_chains(findings)
    assert chains
    assert {c.status for c in chains} == {HYPOTHESIZED}
    assert set() == {c.confidence for c in chains} - {
        "possible", "probable"}
    for c in chains:
        assert c.missing_links


def test_stable_ids_and_dedupe():
    findings = [_finding("r1", "reset-poison",
                         url="https://example.test/forgot")]
    first = [c.id for c in build_chains(findings)]
    second = [c.id for c in build_chains(list(reversed(findings)))]
    assert first == second
    doubled = build_chains(findings + findings)
    assert [c.id for c in doubled] == first


def test_artifact_round_trip(tmp_path):
    from main.chains.models import AttackChain
    from main.reporting.metrics import Metrics
    out = build_attack_chains(tmp_path, [
        _finding("r1", "reset-poison",
                 url="https://example.test/forgot")], Metrics())
    assert len(out) == 1
    rows = (tmp_path / "attack_chains.jsonl").read_text().splitlines()
    assert len(rows) == 1
    import json as _json
    restored = AttackChain.from_dict(_json.loads(rows[0]))
    assert restored.to_dict() == out[0].to_dict()


def test_unrelated_findings_form_nothing():
    assert build_chains([
        _finding("t1", "tko-subs", url="https://example.test/")]) == []
