"""SSTI validator checks against deterministic, local-only render fixtures."""
import json
import re
from urllib.parse import parse_qs, parse_qsl, urlparse

import pytest

from apex_fuzzer.budgets import BudgetExceeded
from apex_fuzzer.config import Config
from apex_fuzzer.models import Finding, Parameter
from apex_fuzzer.validation.base import Candidate
from apex_fuzzer.validation.ssti import SstiValidator


class Response:
    status_code = 200

    def __init__(self, text):
        self.text = text
        self.headers = {"Content-Type": "text/plain"}


class LocalTemplateFixture:
    """Small arithmetic-only stand-in; it cannot execute arbitrary code."""

    def __init__(self, syntax="double-curly", partial=False):
        self.syntax = syntax
        self.partial = partial
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        fields = parse_qs(urlparse(url).query, keep_blank_values=True)
        value = fields.get("name", [""])[0]
        return Response(self._render(value))

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        raw = kwargs.get("data", "")
        content_type = next((v for k, v in
                             kwargs.get("headers", {}).items()
                             if k.lower() == "content-type"), "")
        if "json" in content_type.lower():
            fields = json.loads(raw)
        else:
            fields = dict(parse_qsl(raw, keep_blank_values=True))
        return Response(self._render(str(fields.get("name", ""))))

    def _render(self, value):
        if self.syntax == "double-curly":
            pattern = r"\{\{\s*(\d+)([+*])(\d+)\s*\}\}"
        elif self.syntax == "dollar-brace":
            pattern = r"\$\{\s*(\d+)([+*])(\d+)\s*\}"
        else:
            return value  # reflection without template evaluation

        def evaluate(match):
            left, operation, right = match.groups()
            if self.partial and operation == "+":
                return match.group(0)
            a, b = int(left), int(right)
            return str(a * b if operation == "*" else a + b)

        return re.sub(pattern, evaluate, value)


def query_candidate():
    finding = Finding(id="ssti-fixture", source="fixture",
                      name="SSTI candidate", parameter="name")
    return Candidate(
        finding=finding, test_class="ssti",
        endpoint_url="https://app.example.test/render?name=sample",
        parameter="name", method="GET", parameter_location="query")


@pytest.mark.parametrize("syntax", ["double-curly", "dollar-brace"])
def test_confirms_two_distinct_arithmetic_expressions(syntax):
    fixture = LocalTemplateFixture(syntax=syntax)
    outcome = SstiValidator(Config(), fixture).validate(query_candidate())

    assert outcome.status == "confirmed"
    assert outcome.evidence["syntax"] == syntax
    assert outcome.evidence["expressions"] == ["7*7 -> 49", "7+7 -> 14"]
    assert len(fixture.calls) == (2 if syntax == "double-curly" else 4)


def test_reflection_without_evaluation_is_inconclusive():
    fixture = LocalTemplateFixture(syntax="reflection-only")
    outcome = SstiValidator(Config(), fixture).validate(query_candidate())

    assert outcome.status == "inconclusive"
    assert len(fixture.calls) == 4


def test_one_computed_expression_remains_a_candidate():
    fixture = LocalTemplateFixture(syntax="double-curly", partial=True)
    outcome = SstiValidator(Config(), fixture).validate(query_candidate())

    assert outcome.status == "strong_candidate"
    assert len(fixture.calls) == 4


def test_observed_json_post_is_gated_and_preserves_body_shape():
    finding = Finding(id="ssti-post", source="fixture", parameter="name",
                      method="POST", request_body='{"name":"sample"}')
    candidate = Candidate(
        finding=finding, test_class="ssti",
        endpoint_url="https://app.example.test/render", parameter="name",
        method="POST", parameter_location="body",
        request_content_type="application/json",
        request_body={"name": "sample"},
        body_parameters=[Parameter(name="name", location="body")])
    fixture = LocalTemplateFixture()
    cfg = Config()
    outcome = SstiValidator(cfg, fixture).validate(candidate)
    assert outcome.status == "inconclusive"
    assert fixture.calls == []

    cfg.safety.allow_state_change = True
    outcome = SstiValidator(cfg, fixture).validate(candidate)
    assert outcome.status == "confirmed"
    assert len(fixture.calls) == 2
    assert all(call[0] == "POST" for call in fixture.calls)
    assert all(call[2]["headers"]["Content-Type"] == "application/json"
               for call in fixture.calls)
    assert all(json.loads(call[2]["data"]).keys() == {"name"}
               for call in fixture.calls)


def test_budget_exhaustion_is_not_downgraded_to_inconclusive():
    class Exhausted:
        def get(self, *_args, **_kwargs):
            raise BudgetExceeded("fixture request cap")

    with pytest.raises(BudgetExceeded):
        SstiValidator(Config(), Exhausted()).validate(query_candidate())


def test_query_parameter_must_be_observed_on_target_url():
    candidate = query_candidate()
    candidate.endpoint_url = "https://app.example.test/render?other=sample"
    fixture = LocalTemplateFixture()

    outcome = SstiValidator(Config(), fixture).validate(candidate)

    assert outcome.status == "inconclusive"
    assert fixture.calls == []


def test_ssti_plugin_blocks_out_of_scope_target():
    from apex_fuzzer.config import Config, ScopeConfig
    from apex_fuzzer.plugins.adapters import SstiPlugin
    from apex_fuzzer.plugins.base import TestTarget, TestContext
    from apex_fuzzer.scope import Scope
    from types import SimpleNamespace as _NS

    cfg = Config()
    scope = Scope(ScopeConfig(allowed_domains=["example.test"]))
    finding = Finding(id="ssti-oos", source="nuclei", parameter="q",
                      endpoint_url="https://other.test/s?q=1",
                      matched_at="https://other.test/s?q=1")
    target = TestTarget("https://other.test/s?q=1", parameter="q",
                        method="GET", finding=finding, endpoint=None,
                        test_class="ssti")
    ctx = TestContext(cfg, http=_NS(), scope=scope)
    assert SstiPlugin().run(target, ctx).status == "blocked"
