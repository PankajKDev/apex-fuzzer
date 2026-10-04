"""Non-query XSS prescreen: form/JSON/XML bodies with safety gates.

No network. Fake HTTP clients only.
"""
from types import SimpleNamespace

from apex_fuzzer.config import Config, ScopeConfig
from apex_fuzzer.models import Endpoint, Finding, Parameter
from apex_fuzzer.plugins.adapters import _candidate_from, XssMutationPlugin
from apex_fuzzer.plugins.base import TestTarget, TestContext
from apex_fuzzer.scope import Scope
from apex_fuzzer.validation import mutate as mut_mod
from apex_fuzzer.validation.base import Candidate
from apex_fuzzer.budgets import BudgetExceeded


def _scope():
    return Scope(ScopeConfig(allowed_domains=["example.test"]))


def _finding(parameter="comment", method="POST",
             url="https://example.test/submit"):
    return Finding(id="xss-body", source="nuclei", method=method,
                   parameter=parameter, endpoint_url=url,
                   matched_at=url)


class _ReflectiveHttp:
    """Echo the sent payload back unescaped so reflection is deterministic."""

    def __init__(self):
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        data = kwargs.get("data")
        payload = ""
        if isinstance(data, dict):
            payload = str(data.get("comment", ""))
        elif isinstance(data, str):
            payload = data
        else:
            body = kwargs.get("json")
            if isinstance(body, dict):
                payload = str(body.get("comment", ""))
        return SimpleNamespace(status_code=200,
                               text=f"<div>{payload}</div>")

    def get(self, url, **kwargs):
        from urllib.parse import parse_qsl, urlsplit
        query = dict(parse_qsl(urlsplit(url).query,
                               keep_blank_values=True))
        payload = next(iter(query.values()), "")
        return SimpleNamespace(status_code=200,
                               text=f"<div>{payload}</div>")


def _form_candidate(**overrides):
    base = dict(
        finding=_finding(), test_class="xss",
        endpoint_url="https://example.test/submit", parameter="comment",
        method="POST", parameter_location="body",
        request_content_type="application/x-www-form-urlencoded",
        body_parameters=[Parameter(name="comment", location="body",
                                   sample_value="hello")])
    base.update(overrides)
    return Candidate(**base)


def test_form_body_reflection_is_candidate_with_state_ack():
    cfg = Config()
    cfg.safety.allow_state_change = True
    http = _ReflectiveHttp()
    outcome = mut_mod.MutationEngine(cfg, http).prescreen_xss(
        _form_candidate())
    assert outcome is not None
    assert outcome.status == "strong_candidate"
    assert outcome.evidence["parameter_location"] == "body"
    assert http.calls
    assert all(call[0] == "POST" for call in http.calls)


def test_body_blocked_without_state_ack_and_sends_nothing():
    http = _ReflectiveHttp()
    outcome = mut_mod.MutationEngine(Config(), http).prescreen_xss(
        _form_candidate())
    assert outcome is not None
    assert outcome.status == "inconclusive"
    assert "allow_state_change" in outcome.notes
    assert not http.calls


def test_json_nested_body_preserves_peers():
    seen = {}

    class Http:
        def request(self, method, url, **kwargs):
            seen["body"] = kwargs["json"]
            return SimpleNamespace(status_code=200, text="<div>clean</div>")

    cfg = Config()
    cfg.safety.allow_state_change = True
    candidate = _form_candidate(
        parameter="user.comment",
        request_content_type="application/json",
        body_parameters=[Parameter(name="user.comment", location="body",
                                    sample_value="hello"),
                         Parameter(name="user.id", location="body",
                                   sample_value="7")])
    outcome = mut_mod.MutationEngine(cfg, Http()).prescreen_xss(candidate)
    assert outcome is None  # clean response, no reflection
    assert seen["body"]["user"]["id"] == "7"
    assert "user" in seen["body"]


def test_xml_leaf_body_reflection():
    import xml.etree.ElementTree as _et

    class Http:
        def __init__(self):
            self.calls = []

        def request(self, method, url, **kwargs):
            self.calls.append((kwargs["data"], kwargs["headers"]))
            # vulnerable app: XML-parses the body (decoding entities)
            # then reflects the node text raw into HTML
            try:
                text = _et.fromstring(kwargs["data"]).findtext("comment")
            except _et.ParseError:
                text = ""
            return SimpleNamespace(status_code=200,
                                   text=f"<p>{text}</p>")

    cfg = Config()
    cfg.safety.allow_state_change = True
    http = Http()
    candidate = _form_candidate(
        request_content_type="application/xml",
        request_headers={"X-Mode": "exact"},
        request_body="<note><comment>hello</comment><page>2</page></note>")
    outcome = mut_mod.MutationEngine(cfg, http).prescreen_xss(candidate)
    assert outcome is not None
    assert outcome.status == "strong_candidate"
    sent, headers = http.calls[0]
    assert "<page>2</page>" in sent
    assert headers["X-Mode"] == "exact"


def test_xml_escaped_reflection_stays_silent():
    class Http:
        def request(self, method, url, **kwargs):
            # safe app: echoes the raw (still entity-escaped) body
            return SimpleNamespace(status_code=200,
                                   text=f"<p>{kwargs['data']}</p>")

    cfg = Config()
    cfg.safety.allow_state_change = True
    candidate = _form_candidate(
        request_content_type="application/xml",
        request_body="<note><comment>hello</comment></note>")
    assert mut_mod.MutationEngine(cfg, Http()).prescreen_xss(
        candidate) is None


def test_multipart_body_fails_closed_without_sending():
    class Http:
        def request(self, *args, **kwargs):
            raise AssertionError("multipart must not send")

        def get(self, *args, **kwargs):
            raise AssertionError("multipart must not send")

    cfg = Config()
    cfg.safety.allow_state_change = True
    outcome = mut_mod.MutationEngine(cfg, Http()).prescreen_xss(
        _form_candidate(
            request_content_type="multipart/form-data; boundary=b"))
    assert outcome is not None
    assert outcome.status == "inconclusive"
    assert "multipart" in outcome.notes.lower()


def test_get_body_shape_and_bad_method_fail_closed():
    cfg = Config()
    cfg.safety.allow_state_change = True

    class Http:
        def request(self, *args, **kwargs):
            raise AssertionError("must not send")

        def get(self, *args, **kwargs):
            raise AssertionError("must not send")

    http = Http()
    get_body = mut_mod.MutationEngine(cfg, http).prescreen_xss(
        _form_candidate(method="GET"))
    assert get_body is not None
    assert get_body.status == "inconclusive"
    bad_method = mut_mod.MutationEngine(cfg, http).prescreen_xss(
        _form_candidate(method="DELETE"))
    assert bad_method is not None
    assert bad_method.status == "inconclusive"


def test_ambiguous_observed_request_fails_closed():
    cfg = Config()
    cfg.safety.allow_state_change = True

    class Http:
        def request(self, *args, **kwargs):
            raise AssertionError("ambiguous must not send")

        def get(self, *args, **kwargs):
            raise AssertionError("ambiguous must not send")

    candidate = _form_candidate(
        observed_ambiguous="ambiguous observed requests: 2 matches")
    outcome = mut_mod.MutationEngine(cfg, Http()).prescreen_xss(candidate)
    assert outcome is not None
    assert outcome.status == "inconclusive"
    assert "ambiguous" in outcome.notes


def test_budget_exhaustion_maps_to_blocked_via_plugin():
    class Http:
        def request(self, *args, **kwargs):
            raise BudgetExceeded("request budget exhausted")

        def get(self, *args, **kwargs):
            raise BudgetExceeded("request budget exhausted")

    cfg = Config()
    cfg.safety.allow_state_change = True
    endpoint = Endpoint(url="https://example.test/submit",
                        normalized_url="https://example.test/submit",
                        method="POST",
                        request_content_types=[
                            "application/x-www-form-urlencoded"],
                        body_parameters=[Parameter(name="comment",
                                                   location="body")])
    target = TestTarget(endpoint.url, parameter="comment", method="POST",
                         finding=_finding(), endpoint=endpoint,
                         test_class="xss")
    result = XssMutationPlugin().run(target, TestContext(cfg, http=Http()))
    assert result.status == "blocked"


def test_plugin_blocks_out_of_scope_target():
    cfg = Config()
    target = TestTarget("https://other.example/search?q=1", parameter="q",
                         method="GET", finding=_finding(
                             parameter="q", method="GET",
                             url="https://other.example/search?q=1"),
                         endpoint=None, test_class="xss")
    ctx = TestContext(cfg, http=SimpleNamespace(), scope=_scope())
    assert XssMutationPlugin().run(target, ctx).status == "blocked"


def test_candidate_pins_single_observed_body_request():
    ep = Endpoint(url="https://example.test/submit",
                  normalized_url="https://example.test/submit",
                  method="POST",
                  request_content_types=[
                      "application/x-www-form-urlencoded"],
                  body_parameters=[Parameter(name="comment",
                                             location="body")])
    ep.observed_requests = [{
        "identity": "alice", "method": "POST",
        "url": "https://example.test/submit",
        "headers": {"Content-Type":
                    "application/x-www-form-urlencoded"},
        "post_data": "comment=hello&mode=exact",
        "content_type": "application/x-www-form-urlencoded"}]
    target = TestTarget("https://example.test/submit", parameter="comment",
                         method="POST", finding=_finding(), endpoint=ep,
                         test_class="xss")
    candidate = _candidate_from(target, "xss", scope=_scope())
    assert candidate.observed_identity == "alice"
    assert candidate.request_body == "comment=hello&mode=exact"


def test_bare_javascript_scheme_without_tags_stays_silent():
    class Http:
        def get(self, url, **kwargs):
            from urllib.parse import parse_qsl, urlsplit
            query = dict(parse_qsl(urlsplit(url).query,
                                   keep_blank_values=True))
            value = next(iter(query.values()), "")
            # encodes tags (real output encoding) but leaves the URL
            # scheme text untouched, like a redirect target echo
            safe = value.replace("<", "&lt;").replace(">", "&gt;")
            return SimpleNamespace(status_code=200,
                                   text=f"<p>see {safe}</p>")

    candidate = Candidate(
        finding=Finding(id="xss-scheme", source="nuclei"), test_class="xss",
        endpoint_url="https://example.test/go?next=home", parameter="next")
    assert mut_mod.MutationEngine(Config(), Http()).prescreen_xss(
        candidate) is None
