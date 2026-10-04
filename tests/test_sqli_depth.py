"""SQLi depth: quote-context booleans, baseline-gated errors, DBMS hints.

No network. Fake HTTP clients and fake sqlmap runners only.
"""
from types import SimpleNamespace

from apex_fuzzer.config import Config
from apex_fuzzer.models import Finding
from apex_fuzzer.validation import mutate as mut_mod
from apex_fuzzer.validation import observed_sqli as obs_mod
from apex_fuzzer.validation import sqli as sqli_mod
from apex_fuzzer.validation.base import Candidate


def _candidate(**overrides):
    base = dict(
        finding=Finding(id="sqli-depth", source="test"), test_class="sqli",
        endpoint_url="https://example.test/items?name=hello",
        parameter="name")
    base.update(overrides)
    return Candidate(**base)


def test_double_quote_context_boolean_difference_is_candidate():
    from urllib.parse import unquote_plus as unquote
    seen = []

    class Http:
        def get(self, url, **kwargs):
            seen.append(url)
            # only the double-quote true condition changes the rows
            if 'AND "1"="1' in unquote(url):
                return SimpleNamespace(status_code=200,
                                       text='{"rows":[1,2]}')
            return SimpleNamespace(status_code=200, text='{"rows":[]}')

    outcome = mut_mod.MutationEngine(Config(), Http()).prescreen_sqli(
        _candidate())
    assert outcome is not None
    assert outcome.status == "strong_candidate"
    assert outcome.evidence["control_pair"]["true_condition"].endswith(
        '" AND "1"="1')
    # baseline + single-quote pair (3) + double-quote pair (3)
    assert len(seen) == 7


def test_baseline_error_text_disables_error_marker_stage():
    sent = []

    class Http:
        def get(self, url, **kwargs):
            sent.append(url)
            # every response carries the error page, including the baseline
            return SimpleNamespace(
                status_code=200,
                text="docs: You have an error in your SQL syntax; read more")

    outcome = mut_mod.MutationEngine(Config(), Http()).prescreen_sqli(
        _candidate())
    assert outcome is None
    # boolean probes ran, but no error-ladder payload was ever sent
    assert not [url for url in sent if "OR" in url or "UNION" in url]


def test_error_marker_carries_dbms_hint():
    class Http:
        def get(self, url, **kwargs):
            if "UNION" in url or " OR " in url:
                return SimpleNamespace(
                    status_code=500,
                    text="Unclosed quotation mark after the character "
                         "string 'abc'.")
            return SimpleNamespace(status_code=200, text='{"rows":[]}')

    outcome = mut_mod.MutationEngine(Config(), Http()).prescreen_sqli(
        _candidate())
    assert outcome is not None
    assert outcome.status == "strong_candidate"
    assert outcome.evidence["dbms_hint"] == ["mssql"]


def test_error_families_label_backends():
    assert mut_mod.sqli_error_families("ORA-00933: SQL command ended") == \
        ["oracle"]
    assert mut_mod.sqli_error_families("SQLSTATE[42000]: syntax error") == \
        ["generic"]
    assert mut_mod.sqli_error_families("MariaDB server version 10.6") == \
        ["mariadb"]
    assert mut_mod.sqli_error_families("welcome to our homepage") == []
    assert mut_mod.sqli_error_families("") == []


def test_no_time_based_payloads_in_ladder():
    banned = ("SLEEP", "BENCHMARK", "PG_SLEEP", "WAITFOR", "DBMS_LOCK")
    for payload in mut_mod.SQLI_MUTATIONS:
        assert not any(marker in payload.upper() for marker in banned)


def test_deeper_ladder_reaches_union_context_variants():
    from urllib.parse import unquote_plus as unquote
    cfg = Config()
    cfg.validation.mutation_payloads = 12

    class Http:
        def get(self, url, **kwargs):
            if '" UNION SELECT NULL-- -' in unquote(url):
                return SimpleNamespace(
                    status_code=500, text="SQLSTATE[HY000]: General error")
            return SimpleNamespace(status_code=200, text='{"rows":[]}')

    outcome = mut_mod.MutationEngine(cfg, Http()).prescreen_sqli(
        _candidate())
    assert outcome is not None
    assert outcome.status == "strong_candidate"
    assert "UNION" in outcome.evidence["payload"]
    assert outcome.evidence["dbms_hint"] == ["generic"]


def test_raw_file_args_use_union_without_enumeration():
    args = obs_mod.sqlmap_args_for_raw("/tmp/x.req", "id", "/tmp/out")
    assert args[args.index("--technique") + 1] == "BEU"
    for flag in ("--dbs", "--tables", "--dump", "--os-shell", "--os-cmd"):
        assert flag not in args


def test_direct_args_use_union_without_enumeration(monkeypatch):
    calls = []
    monkeypatch.setattr(sqli_mod, "which", lambda _: "/usr/bin/sqlmap")
    monkeypatch.setattr(sqli_mod, "run", lambda args, timeout: (
        calls.append(list(args)) or
        SimpleNamespace(stdout="not injectable", stderr="")))
    result = sqli_mod.SqliValidator(Config()).validate(_candidate())
    assert result.status == "false_positive"
    args = calls[0]
    assert args[args.index("--technique") + 1] == "BEU"
    assert "--time-sec" not in args
    for flag in ("--dbs", "--tables", "--dump", "--os-shell", "--time-sec"):
        assert flag not in args


def test_time_technique_is_opt_in_with_bounded_delay(monkeypatch):
    calls = []
    monkeypatch.setattr(sqli_mod, "which", lambda _: "/usr/bin/sqlmap")
    monkeypatch.setattr(sqli_mod, "run", lambda args, timeout: (
        calls.append(list(args)) or
        SimpleNamespace(stdout="not injectable", stderr="")))
    cfg = Config()
    cfg.validation.sqli_time_based = True
    result = sqli_mod.SqliValidator(cfg).validate(_candidate())
    assert result.status == "false_positive"
    args = calls[0]
    assert args[args.index("--technique") + 1] == "BEUT"
    assert args[args.index("--time-sec") + 1] == "2"
    assert result.evidence["sqlmap_tail"]
    for flag in ("--dbs", "--tables", "--dump", "--os-shell"):
        assert flag not in args


def test_raw_file_args_add_time_only_when_opted_in():
    off = obs_mod.sqlmap_args_for_raw("/tmp/x.req", "id", "/tmp/out")
    assert off[off.index("--technique") + 1] == "BEU"
    assert "--time-sec" not in off
    on = obs_mod.sqlmap_args_for_raw("/tmp/x.req", "id", "/tmp/out",
                                     time_based=True, time_sec=99)
    assert on[on.index("--technique") + 1] == "BEUT"
    assert on[on.index("--time-sec") + 1] == "10"


def test_time_opt_in_flows_through_observed_path(monkeypatch):
    monkeypatch.setattr(sqli_mod, "which", lambda _: "/usr/bin/sqlmap")
    seen = {}
    monkeypatch.setattr(sqli_mod, "run", lambda args, timeout: (
        seen.update(args=list(args)) or
        SimpleNamespace(stdout="not injectable", stderr="")))
    cfg = Config()
    cfg.validation.sqli_time_based = True
    candidate = Candidate(
        finding=_candidate().finding, test_class="sqli",
        endpoint_url="https://example.test/search?q=1", parameter="q",
        method="GET",
        observed_request={"identity": "alice", "method": "GET",
                          "url": "https://example.test/search?q=1",
                          "headers": {}, "post_data": None,
                          "content_type": ""},
        observed_identity="alice")
    result = sqli_mod.SqliValidator(cfg).validate(candidate)
    assert result.status == "false_positive"
    assert seen["args"][seen["args"].index("--technique") + 1] == "BEUT"
    assert "time" in result.evidence["techniques"]


def test_cli_flag_enables_time_opt_in():
    from apex_fuzzer.cli import build_parser
    from apex_fuzzer.config import apply_cli_overrides
    args = build_parser().parse_args(["-d", "example.test", "--sqli-time"])
    cfg = apply_cli_overrides(Config(), args)
    assert cfg.validation.sqli_time_based is True
    plain = build_parser().parse_args(["-d", "example.test"])
    assert apply_cli_overrides(Config(), plain).validation.sqli_time_based \
        is False


def test_sqlmap_signal_parsing_covers_184_phrasing():
    assert sqli_mod._sqlmap_success(
        "GET parameter 'id' is 'AND boolean-based blind' injectable")
    assert sqli_mod._sqlmap_success("target is vulnerable: SQLi confirmed")
    assert sqli_mod._sqlmap_negative(
        "GET parameter 'id' does not seem to be injectable")
    assert sqli_mod._sqlmap_negative(
        "all tested parameters do not appear to be injectable")
    assert sqli_mod._sqlmap_negative("parameter is not injectable")
    assert not sqli_mod._sqlmap_success("no result yet")
    assert not sqli_mod._sqlmap_negative("no result yet")
    assert not sqli_mod._sqlmap_success("")


def test_echoing_page_disables_boolean_pair():
    from urllib.parse import parse_qsl, urlsplit

    class Http:
        def get(self, url, **kwargs):
            query = dict(parse_qsl(urlsplit(url).query,
                                   keep_blank_values=True))
            value = next(iter(query.values()), "")
            return SimpleNamespace(
                status_code=200,
                text=f"<html>results for {value}</html>")

    candidate = Candidate(
        finding=Finding(id="echo1", source="test"), test_class="sqli",
        endpoint_url="https://example.test/docs?search=hello",
        parameter="search")
    assert mut_mod.MutationEngine(Config(), Http()).prescreen_sqli(
        candidate) is None
