"""Path traversal tests use a local response fixture and harmless marker."""
from urllib.parse import parse_qs, urlparse

import pytest

from apex_fuzzer.budgets import BudgetExceeded
from apex_fuzzer.config import Config
from apex_fuzzer.models import Finding
from apex_fuzzer.validation.base import Candidate
from apex_fuzzer.validation.path_traversal import PathTraversalValidator


MARKER = "APEX_SAFE_FILE_MARKER_2026"


class Response:
    def __init__(self, text, status=200):
        self.text = text
        self.status_code = status


class MarkerFileFixture:
    def __init__(self, marker=MARKER, match_depth=3):
        self.marker = marker
        self.match_depth = match_depth
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        value = parse_qs(urlparse(url).query).get("file", [""])[0]
        if value == "../" * self.match_depth + "apex-marker.txt":
            return Response(self.marker)
        return Response("not found", status=404)


def candidate(url="https://app.example.test/download?file=sample.txt",
              parameter="file", method="GET", location="query"):
    finding = Finding(id="path-fixture", source="fixture",
                      name="Path traversal candidate", parameter=parameter,
                      method=method)
    return Candidate(finding=finding, test_class="path_traversal",
                     endpoint_url=url, parameter=parameter, method=method,
                     parameter_location=location)


def config(path="apex-marker.txt", content=MARKER, depth=4):
    cfg = Config()
    cfg.validation.path_traversal_marker_path = path
    cfg.validation.path_traversal_marker_content = content
    cfg.validation.path_traversal_max_depth = depth
    return cfg


def test_confirms_only_the_exact_operator_configured_marker():
    http = MarkerFileFixture()
    outcome = PathTraversalValidator(config(), http).validate(candidate())

    assert outcome.status == "confirmed"
    assert outcome.evidence["depth"] == 3
    assert outcome.evidence["marker_path"] == "apex-marker.txt"
    assert outcome.evidence["response_body_recorded"] is False
    assert MARKER not in str(outcome.evidence)
    assert len(http.calls) == 3
    assert all("etc%2Fpasswd" not in url for url, _ in http.calls)


def test_missing_marker_config_disables_all_requests():
    http = MarkerFileFixture()
    outcome = PathTraversalValidator(Config(), http).validate(candidate())

    assert outcome.status == "inconclusive"
    assert "configure a harmless relative marker" in outcome.notes
    assert http.calls == []


@pytest.mark.parametrize("path,content", [
    ("../etc/passwd", MARKER), ("/tmp/apex-marker.txt", MARKER),
    ("apex-marker.txt", "short"), ("dir\\marker.txt", MARKER),
])
def test_unsafe_or_weak_marker_config_is_rejected(path, content):
    http = MarkerFileFixture()
    outcome = PathTraversalValidator(config(path, content), http).validate(
        candidate())

    assert outcome.status == "inconclusive"
    assert http.calls == []


def test_only_observed_path_like_get_parameters_are_probed():
    http = MarkerFileFixture()
    no_field = candidate(
        url="https://app.example.test/download?other=sample", parameter=None)
    outcome = PathTraversalValidator(config(), http).validate(no_field)
    assert outcome.status == "inconclusive"
    assert http.calls == []

    inferred = candidate(parameter=None)
    outcome = PathTraversalValidator(config(), http).validate(inferred)
    assert outcome.status == "confirmed"


def test_no_marker_match_is_inconclusive_and_depth_is_hard_capped():
    cfg = config(depth=100)
    http = MarkerFileFixture(marker="different", match_depth=99)
    outcome = PathTraversalValidator(cfg, http).validate(candidate())

    assert outcome.status == "inconclusive"
    assert len(http.calls) == 6


def test_mutating_methods_and_body_inputs_are_not_probed():
    http = MarkerFileFixture()
    post = candidate(method="POST")
    outcome = PathTraversalValidator(config(), http).validate(post)
    assert outcome.status == "inconclusive"
    assert http.calls == []

    body = candidate(location="body")
    outcome = PathTraversalValidator(config(), http).validate(body)
    assert outcome.status == "inconclusive"
    assert http.calls == []


def test_budget_exhaustion_propagates():
    class Exhausted:
        def get(self, *_args, **_kwargs):
            raise BudgetExceeded("fixture request cap")

    with pytest.raises(BudgetExceeded):
        PathTraversalValidator(config(), Exhausted()).validate(candidate())
