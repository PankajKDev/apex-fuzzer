"""Observed-request SQLi: single-shape selection plus raw-file sqlmap.

Deterministic fixtures and a fake sqlmap runner only. No network, no
real sqlmap binary, no persisted secrets.
"""
import os
import stat
from types import SimpleNamespace

from main.config import Config, ScopeConfig
from main.models import Endpoint, Finding, Parameter
from main.plugins.adapters import _candidate_from, SqliPlugin
from main.plugins.base import TestTarget, TestContext
from main.scope import Scope
from main.validation import observed_sqli as obs_mod
from main.validation import sqli as sqli_mod
from main.validation.base import Candidate
from main.budgets import BudgetTracker


SECRET_COOKIE = "session=SECRET-ABC-123"
SECRET_BODY = "s3cr3t-body-value"


def _scope():
    return Scope(ScopeConfig(allowed_domains=["example.test"]))


def _endpoint_with(observed):
    ep = Endpoint(url="https://example.test/search?q=1",
                  normalized_url="https://example.test/search?q=1",
                  method="GET")
    ep.query_parameters = [Parameter(name="q", location="query")]
    ep.observed_requests = observed
    return ep


def _finding(parameter="q"):
    return Finding(id="obs1", source="nuclei", method="GET",
                   parameter=parameter,
                   endpoint_url="https://example.test/search?q=1",
                   matched_at="https://example.test/search?q=1")


def test_selection_pins_single_query_request_with_identity():
    observed = [{"identity": "alice", "method": "GET",
                 "url": "https://example.test/search?q=1",
                 "headers": {"X-Trace": "t1"}, "post_data": None,
                 "content_type": ""}]
    target = TestTarget("https://example.test/search?q=1", parameter="q",
                        method="GET", finding=_finding(),
                        endpoint=_endpoint_with(observed), test_class="sqli")
    candidate = _candidate_from(target, "sqli", scope=_scope())
    assert candidate.parameter == "q"
    assert candidate.method == "GET"
    assert candidate.observed_identity == "alice"
    assert isinstance(candidate.observed_request, dict)
    assert candidate.observed_ambiguous is None


def test_selection_requires_parameter_in_observed_shape():
    observed = [{"identity": "alice", "method": "GET",
                 "url": "https://example.test/other?z=1",
                 "headers": {}, "post_data": None, "content_type": ""}]
    target = TestTarget("https://example.test/search?q=1", parameter="q",
                        method="GET", finding=_finding(),
                        endpoint=_endpoint_with(observed), test_class="sqli")
    candidate = _candidate_from(target, "sqli", scope=_scope())
    assert candidate.observed_request is None
    assert candidate.observed_ambiguous is None
    assert candidate.parameter == "q"


def test_selection_does_not_cross_scheme_or_port():
    for observed_url in (
            "http://example.test/search?q=1",
            "https://example.test:8443/search?q=1"):
        observed = [{"identity": "alice", "method": "GET",
                     "url": observed_url, "headers": {},
                     "post_data": None, "content_type": ""}]
        target = TestTarget(
            "https://example.test/search?q=1", parameter="q",
            method="GET", finding=_finding(),
            endpoint=_endpoint_with(observed), test_class="sqli")
        candidate = _candidate_from(target, "sqli", scope=_scope())
        assert candidate.observed_request is None


def test_ambiguous_identities_fail_closed_without_guessing(monkeypatch):
    monkeypatch.setattr(sqli_mod, "which", lambda _: "/usr/bin/sqlmap")
    calls = []
    monkeypatch.setattr(sqli_mod, "run", lambda args, timeout: (
        calls.append(args) or SimpleNamespace(stdout="", stderr="")))
    observed = [
        {"identity": "alice", "method": "GET",
         "url": "https://example.test/search?q=1",
         "headers": {}, "post_data": None, "content_type": ""},
        {"identity": "bob", "method": "GET",
         "url": "https://example.test/search?q=2",
         "headers": {}, "post_data": None, "content_type": ""},
    ]
    target = TestTarget("https://example.test/search?q=1", parameter="q",
                        method="GET", finding=_finding(),
                        endpoint=_endpoint_with(observed), test_class="sqli")
    candidate = _candidate_from(target, "sqli", scope=_scope())
    assert candidate.observed_request is None
    assert candidate.observed_ambiguous is not None
    assert "ambiguous" in candidate.observed_ambiguous
    result = sqli_mod.SqliValidator(Config()).validate(candidate)
    assert result.status == "inconclusive"
    assert "ambiguous" in result.notes
    assert not calls


def test_same_identity_different_auth_headers_is_ambiguous():
    observed = [
        {"identity": "alice", "method": "GET",
         "url": "https://example.test/search?q=1",
         "headers": {"Cookie": "session=first"},
         "post_data": None, "content_type": ""},
        {"identity": "alice", "method": "GET",
         "url": "https://example.test/search?q=1",
         "headers": {"Cookie": "session=second"},
         "post_data": None, "content_type": ""},
    ]
    target = TestTarget("https://example.test/search?q=1", parameter="q",
                        method="GET", finding=_finding(),
                        endpoint=_endpoint_with(observed), test_class="sqli")
    candidate = _candidate_from(target, "sqli", scope=_scope())
    assert candidate.observed_request is None
    assert "ambiguous" in candidate.observed_ambiguous


def test_sqlmap_uses_raw_file_with_pinned_parameter(monkeypatch, tmp_path):
    monkeypatch.setattr(sqli_mod, "which", lambda _: "/usr/bin/sqlmap")
    seen = {}

    def fake_run(args, timeout):
        assert "-r" in args
        raw_path = args[args.index("-r") + 1]
        seen["mode"] = stat.S_IMODE(os.stat(raw_path).st_mode)
        seen["raw"] = open(raw_path, encoding="utf-8").read()
        seen["args"] = list(args)
        seen["output_dir"] = next(
            arg.split("=", 1)[1] for arg in args
            if arg.startswith("--output-dir="))
        assert os.path.exists(raw_path)
        return SimpleNamespace(stdout="not injectable", stderr=SECRET_COOKIE)
    monkeypatch.setattr(sqli_mod, "run", fake_run)
    cfg = Config()
    observed = [{"identity": "alice", "method": "GET",
                 "url": "https://example.test/search?q=7&lang=en",
                 "headers": {"X-Trace": "exact",
                             "Cookie": SECRET_COOKIE},
                 "post_data": None, "content_type": ""}]
    target = TestTarget("https://example.test/search?q=1", parameter="q",
                        method="GET", finding=_finding(),
                        endpoint=_endpoint_with(observed), test_class="sqli")
    candidate = _candidate_from(target, "sqli", scope=_scope())
    result = sqli_mod.SqliValidator(cfg).validate(candidate)
    args = seen["args"]
    assert args[args.index("-p") + 1] == "q"
    assert "-u" not in args
    assert args[args.index("--level") + 1] == "1"
    assert args[args.index("--risk") + 1] == "1"
    assert args[args.index("--technique") + 1] == "BEU"
    assert args[args.index("--threads") + 1] == "1"
    assert args[args.index("--retries") + 1] == "0"
    assert "--dbs" not in args and "--tables" not in args
    raw = seen["raw"]
    assert raw.startswith("GET /search?")
    assert "q=7" in raw and "lang=en" in raw
    assert "X-Trace: exact" in raw
    assert seen["mode"] == 0o600
    assert result.status == "false_positive"
    assert not os.path.exists(seen["output_dir"])
    assert result.evidence["observed_identity"] == "alice"
    assert result.evidence["observed_method"] == "GET"
    assert "sqlmap_tail" not in result.evidence
    assert SECRET_COOKIE not in str(result.evidence)
    assert SECRET_COOKIE not in result.notes


def test_post_form_uses_observed_method_and_body(monkeypatch):
    monkeypatch.setattr(sqli_mod, "which", lambda _: "/usr/bin/sqlmap")
    seen = {}
    monkeypatch.setattr(sqli_mod, "run", lambda args, timeout: (
        seen.update(raw=open(args[args.index("-r") + 1],
                             encoding="utf-8").read(), args=list(args))
        or SimpleNamespace(stdout="", stderr="")))
    cfg = Config()
    cfg.safety.allow_state_change = True
    ep = Endpoint(url="https://example.test/submit",
                  normalized_url="https://example.test/submit",
                  method="POST",
                  request_content_types=[
                      "application/x-www-form-urlencoded"],
                  body_parameters=[Parameter(name="id", location="body")])
    ep.observed_requests = [{
        "identity": "alice", "method": "POST",
        "url": "https://example.test/submit",
        "headers": {"Content-Type":
                    "application/x-www-form-urlencoded"},
        "post_data": "id=7&mode=exact", "content_type":
        "application/x-www-form-urlencoded"}]
    finding = Finding(id="obs2", source="nuclei", method="POST",
                      parameter="id",
                      endpoint_url="https://example.test/submit",
                      matched_at="https://example.test/submit")
    target = TestTarget(finding.endpoint_url, parameter="id", method="POST",
                        finding=finding, endpoint=ep, test_class="sqli")
    candidate = _candidate_from(target, "sqli", scope=_scope())
    assert candidate.method == "POST"
    assert candidate.parameter == "id"
    sqli_mod.SqliValidator(cfg).validate(candidate)
    assert "POST /submit HTTP/1.1" in seen["raw"]
    assert "id=7" in seen["raw"] and "mode=exact" in seen["raw"]
    assert seen["args"][seen["args"].index("-p") + 1] == "id"


def test_xml_body_supported_via_raw_when_textual(monkeypatch):
    monkeypatch.setattr(sqli_mod, "which", lambda _: "/usr/bin/sqlmap")
    seen = {}
    monkeypatch.setattr(sqli_mod, "run", lambda args, timeout: (
        seen.update(raw=open(args[args.index("-r") + 1],
                             encoding="utf-8").read())
        or SimpleNamespace(stdout="", stderr="")))
    cfg = Config()
    cfg.safety.allow_state_change = True
    ep = Endpoint(url="https://example.test/xml",
                  normalized_url="https://example.test/xml",
                  method="POST",
                  request_content_types=["application/xml"],
                  body_parameters=[Parameter(name="id", location="body")])
    ep.observed_requests = [{
        "identity": "anonymous", "method": "POST",
        "url": "https://example.test/xml",
        "headers": {"Content-Type": "application/xml"},
        "post_data": "<search><id>7</id><page>2</page></search>",
        "content_type": "application/xml"}]
    finding = Finding(id="obs3", source="nuclei", method="POST",
                      parameter="id",
                      endpoint_url="https://example.test/xml",
                      matched_at="https://example.test/xml")
    target = TestTarget(finding.endpoint_url, parameter="id", method="POST",
                        finding=finding, endpoint=ep, test_class="sqli")
    candidate = _candidate_from(target, "sqli", scope=_scope())
    sqli_mod.SqliValidator(cfg).validate(candidate)
    assert "<page>2</page>" in seen["raw"]
    assert "Content-Type: application/xml" in seen["raw"]


def test_temp_file_removed_after_run(monkeypatch, tmp_path):
    monkeypatch.setattr(sqli_mod, "which", lambda _: "/usr/bin/sqlmap")
    captured = {}

    def fake_run(args, timeout):
        captured["path"] = args[args.index("-r") + 1]
        return SimpleNamespace(stdout="", stderr="")
    monkeypatch.setattr(sqli_mod, "run", fake_run)
    candidate = Candidate(
        finding=_finding(), test_class="sqli",
        endpoint_url="https://example.test/search?q=1",
        parameter="q", method="GET",
        observed_request={"identity": "alice", "method": "GET",
                          "url": "https://example.test/search?q=1",
                          "headers": {}, "post_data": None,
                          "content_type": ""},
        observed_identity="alice")
    sqli_mod.SqliValidator(Config()).validate(candidate)
    assert captured["path"]
    assert not os.path.exists(captured["path"])


def test_state_change_gate_blocks_post_without_ack(monkeypatch):
    monkeypatch.setattr(sqli_mod, "which", lambda _: "/usr/bin/sqlmap")
    calls = []
    monkeypatch.setattr(sqli_mod, "run", lambda *a, **k: (
        calls.append(a) or SimpleNamespace(stdout="", stderr="")))
    candidate = Candidate(
        finding=_finding("id"), test_class="sqli",
        endpoint_url="https://example.test/submit", parameter="id",
        method="POST", parameter_location="body",
        request_content_type="application/x-www-form-urlencoded",
        observed_request={"identity": "alice", "method": "POST",
                          "url": "https://example.test/submit",
                          "headers": {"Content-Type":
                                      "application/x-www-form-urlencoded"},
                          "post_data": "id=7", "content_type":
                          "application/x-www-form-urlencoded"},
        observed_identity="alice")
    result = sqli_mod.SqliValidator(Config()).validate(candidate)
    assert result.status == "inconclusive"
    assert "allow_state_change" in result.notes
    assert not calls


def test_binary_and_multipart_fail_closed_without_sending(monkeypatch):
    monkeypatch.setattr(sqli_mod, "which", lambda _: "/usr/bin/sqlmap")
    calls = []
    monkeypatch.setattr(sqli_mod, "run", lambda *a, **k: (
        calls.append(a) or SimpleNamespace(stdout="", stderr="")))
    cfg = Config()
    cfg.safety.allow_state_change = True
    binary = Candidate(
        finding=_finding("f"), test_class="sqli",
        endpoint_url="https://example.test/up", parameter="f",
        method="POST", parameter_location="body",
        request_content_type="application/octet-stream",
        observed_request={"identity": "alice", "method": "POST",
                          "url": "https://example.test/up",
                          "headers": {"Content-Type":
                                      "application/octet-stream"},
                          "post_data": b"\x00\x01\x02binary",
                          "content_type": "application/octet-stream"},
        observed_identity="alice")
    assert sqli_mod.SqliValidator(cfg).validate(binary).status == \
        "inconclusive"
    multipart = Candidate(
        finding=_finding("title"), test_class="sqli",
        endpoint_url="https://example.test/up", parameter="title",
        method="POST", parameter_location="body",
        request_content_type="multipart/form-data; boundary=b",
        observed_request={"identity": "alice", "method": "POST",
                          "url": "https://example.test/up",
                          "headers": {"Content-Type":
                                      "multipart/form-data; boundary=b"},
                          "post_data": "--b\r\nok\r\n--b--\r\n",
                          "content_type":
                          "multipart/form-data; boundary=b"},
        observed_identity="alice")
    assert sqli_mod.SqliValidator(cfg).validate(multipart).status == \
        "inconclusive"
    assert not calls


def test_unknown_body_content_type_fails_closed():
    request = {"identity": "alice", "method": "POST",
               "url": "https://example.test/submit",
               "headers": {"Content-Type": "text/plain"},
               "post_data": "id=7", "content_type": "text/plain"}
    endpoint = _endpoint_with([request])
    matched, reason = obs_mod.select_observed_request(
        endpoint, "id", "body", scope=_scope(),
        endpoint_url="https://example.test/submit")
    assert matched is None
    assert "unsupported observed request shape" in reason


def test_unsupported_capture_cannot_fall_back_to_synthesized_request(
        monkeypatch):
    monkeypatch.setattr(sqli_mod, "which", lambda _: "/usr/bin/sqlmap")
    calls = []
    monkeypatch.setattr(sqli_mod, "run", lambda *args, **kwargs: calls.append(
        args) or SimpleNamespace(stdout="", stderr=""))
    endpoint = Endpoint(url="https://example.test/submit",
                        normalized_url="https://example.test/submit",
                        method="POST",
                        body_parameters=[Parameter(name="id",
                                                   location="body")])
    endpoint.observed_requests = [{
        "identity": "alice", "method": "POST",
        "url": "https://example.test/submit",
        "headers": {"Content-Type": "text/plain"},
        "post_data": "id=7", "content_type": "text/plain"}]
    finding = Finding(id="obs4", source="nuclei", method="POST",
                      parameter="id",
                      endpoint_url="https://example.test/submit",
                      matched_at="https://example.test/submit")
    target = TestTarget(finding.endpoint_url, parameter="id", method="POST",
                        finding=finding, endpoint=endpoint,
                        test_class="sqli")
    candidate = _candidate_from(target, "sqli", scope=_scope())
    result = sqli_mod.SqliValidator(Config()).validate(candidate)
    assert result.status == "inconclusive"
    assert "unsupported observed request shape" in result.notes
    assert not calls


def test_malformed_url_fails_closed(monkeypatch):
    monkeypatch.setattr(sqli_mod, "which", lambda _: "/usr/bin/sqlmap")
    calls = []
    monkeypatch.setattr(sqli_mod, "run", lambda *a, **k: (
        calls.append(a) or SimpleNamespace(stdout="", stderr="")))
    candidate = Candidate(
        finding=_finding("q"), test_class="sqli",
        endpoint_url="https://example.test/search?q=1", parameter="q",
        observed_request={"identity": "alice", "method": "GET",
                          "url": "not-a-url", "headers": {},
                          "post_data": None, "content_type": ""},
        observed_identity="alice")
    assert sqli_mod.SqliValidator(Config()).validate(candidate).status == \
        "inconclusive"
    assert not calls


def test_no_secret_leakage_in_evidence_and_serialization_is_exact():
    raw = obs_mod.serialize_observed_to_raw({
        "identity": "alice", "method": "POST",
        "url": "https://example.test/submit?a=1",
        "headers": {"X-Mode": "exact", "Cookie": SECRET_COOKIE,
                    "Content-Type": "application/x-www-form-urlencoded"},
        "post_data": f"id=7&note={SECRET_BODY}",
        "content_type": "application/x-www-form-urlencoded"})
    assert "X-Mode: exact" in raw
    assert "id=7" in raw
    candidate = Candidate(
        finding=_finding("id"), test_class="sqli",
        endpoint_url="https://example.test/submit?a=1", parameter="id",
        method="POST", parameter_location="body",
        request_content_type="application/x-www-form-urlencoded",
        observed_request={"identity": "alice", "method": "POST",
                          "url": "https://example.test/submit?a=1",
                          "headers": {"Cookie": SECRET_COOKIE},
                          "post_data": "id=7", "content_type":
                          "application/x-www-form-urlencoded"},
        observed_identity="alice")
    assert SECRET_COOKIE not in str(candidate.observed_identity)
    assert SECRET_BODY not in candidate.parameter


def test_plugin_blocks_out_of_scope_target():
    cfg = Config()
    scope = _scope()
    target = TestTarget("https://other.example/search?q=1", parameter="q",
                        method="GET", finding=_finding(), endpoint=None,
                        test_class="sqli")
    ctx = TestContext(cfg, http=SimpleNamespace(), scope=scope)
    result = SqliPlugin().run(target, ctx)
    assert result.status == "blocked"


def test_plugin_uses_single_observed_run(monkeypatch):
    monkeypatch.setattr(sqli_mod, "which", lambda _: "/usr/bin/sqlmap")
    calls = []
    monkeypatch.setattr(sqli_mod, "run", lambda args, timeout: (
        calls.append(list(args)) or SimpleNamespace(stdout="", stderr="")))
    cfg = Config()
    observed = [{"identity": "alice", "method": "GET",
                 "url": "https://example.test/search?q=1",
                 "headers": {}, "post_data": None, "content_type": ""}]
    target = TestTarget("https://example.test/search?q=1", parameter="q",
                        method="GET", finding=_finding(),
                        endpoint=_endpoint_with(observed), test_class="sqli")
    ctx = TestContext(cfg, http=SimpleNamespace(), scope=_scope())
    SqliPlugin().run(target, ctx)
    assert len(calls) == 1
    assert "-r" in calls[0] and calls[0][calls[0].index("-p") + 1] == "q"


def test_sqlmap_external_admission_uses_shared_budget(monkeypatch):
    monkeypatch.setattr(sqli_mod, "which", lambda _: "/usr/bin/sqlmap")
    calls = []
    monkeypatch.setattr(sqli_mod, "run", lambda *args, **kwargs: (
        calls.append(args) or SimpleNamespace(stdout="", stderr="")))
    cfg = Config()
    cfg.safety.max_requests = 0
    observed = [{"identity": "alice", "method": "GET",
                 "url": "https://example.test/search?q=1",
                 "headers": {}, "post_data": None, "content_type": ""}]
    target = TestTarget("https://example.test/search?q=1", parameter="q",
                        method="GET", finding=_finding(),
                        endpoint=_endpoint_with(observed), test_class="sqli")
    ctx = TestContext(cfg, http=SimpleNamespace(), scope=_scope(),
                      budgets=BudgetTracker(cfg))
    result = SqliPlugin().run(target, ctx)
    assert result.status == "inconclusive"
    assert "shared request budget" in result.observations[0]
    assert not calls


def test_sqlmap_post_admission_uses_mutation_budget(monkeypatch):
    monkeypatch.setattr(sqli_mod, "which", lambda _: "/usr/bin/sqlmap")
    monkeypatch.setattr(sqli_mod, "run", lambda *args, **kwargs:
                        SimpleNamespace(stdout="", stderr=""))
    cfg = Config()
    cfg.safety.allow_state_change = True
    cfg.safety.max_state_changes = 0
    candidate = Candidate(
        finding=_finding("id"), test_class="sqli",
        endpoint_url="https://example.test/submit", parameter="id",
        method="POST", parameter_location="body",
        observed_request={"identity": "alice", "method": "POST",
                          "url": "https://example.test/submit",
                          "headers": {"Content-Type":
                                      "application/x-www-form-urlencoded"},
                          "post_data": "id=7", "content_type":
                          "application/x-www-form-urlencoded"},
        observed_identity="alice")
    result = sqli_mod.SqliValidator(cfg).validate(
        candidate, budgets=BudgetTracker(cfg))
    assert result.status == "inconclusive"
    assert "shared request budget" in result.notes


def test_observed_sqlmap_skips_when_parameter_absent(monkeypatch):
    monkeypatch.setattr(sqli_mod, "which", lambda _: "/usr/bin/sqlmap")
    calls = []
    monkeypatch.setattr(sqli_mod, "run", lambda *a, **k: (
        calls.append(a) or SimpleNamespace(stdout="", stderr="")))
    cfg = Config()
    cfg.safety.allow_state_change = True
    candidate = Candidate(
        finding=_finding("id"), test_class="sqli",
        endpoint_url="https://example.test/submit", parameter="other",
        method="POST", parameter_location="body",
        request_content_type="application/x-www-form-urlencoded",
        observed_request={"identity": "alice", "method": "POST",
                          "url": "https://example.test/submit",
                          "headers": {"Content-Type":
                                      "application/x-www-form-urlencoded"},
                          "post_data": "id=7", "content_type":
                          "application/x-www-form-urlencoded"},
        observed_identity="alice")
    result = sqli_mod.SqliValidator(cfg).validate(candidate)
    assert result.status == "inconclusive"
    assert "absent" in result.notes
    assert not calls
