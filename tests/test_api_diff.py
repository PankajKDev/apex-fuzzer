"""OpenAPI vs behavior diffing: shadow, unseen, and param gaps.

Pure offline comparison; gaps are untested surface (leads), never
verdicts.
"""
import json
from types import SimpleNamespace

from main.discovery import api_diff as diff_mod
from main.leads import collect_leads


def _spec(paths):
    return [{"endpoints": [
        {"path": path, "method": method, "parameters": [
            {"name": name, "in": "query"} for name in params]}
        for path, method, params in paths]}]


def _ep(method, url, params=()):
    return SimpleNamespace(
        method=method, normalized_url=url, url=url,
        endpoint_type="api",
        query_parameters=[SimpleNamespace(name=n) for n in params],
        body_parameters=[], header_parameters=[])


def test_template_paths_match_concrete():
    out = diff_mod.diff_api(
        _spec([("/users/{id}", "GET", ["id"])]),
        [_ep("GET", "https://example.test/users/123", ["id"])])
    assert out["shadow"] == [] and out["unseen"] == []
    assert out["param_gaps"] == []


def test_shadow_api_detected():
    out = diff_mod.diff_api(
        _spec([("/users/{id}", "GET", ["id"])]),
        [_ep("GET", "https://example.test/admin/export", [])])
    assert len(out["shadow"]) == 1
    assert out["shadow"][0]["path"] == "/admin/export"
    assert out["unseen"][0]["path"] == "/users/{id}"


def test_method_mismatch_is_shadow():
    out = diff_mod.diff_api(
        _spec([("/users/{id}", "GET", ["id"])]),
        [_ep("POST", "https://example.test/users/123", ["id"])])
    assert len(out["shadow"]) == 1
    assert len(out["unseen"]) == 1


def test_param_gaps_both_directions():
    out = diff_mod.diff_api(
        _spec([("/users", "GET", ["id", "verbose"])]),
        [_ep("GET", "https://example.test/users", ["id", "role"])])
    assert out["shadow"] == []
    assert len(out["param_gaps"]) == 1
    gap = out["param_gaps"][0]
    assert gap["extra_params"] == ["role"]
    assert gap["missing_params"] == ["verbose"]


def test_non_api_types_ignored():
    ep = _ep("GET", "https://example.test/logo.png", [])
    ep.endpoint_type = "static"
    out = diff_mod.diff_api(_spec([]), [ep])
    assert out == {"shadow": [], "unseen": [], "param_gaps": []}


def test_caps_bound_output():
    specs = _spec([(f"/r{i}/{{id}}", "GET", ["id"]) for i in range(5)])
    eps = [_ep("GET", f"https://example.test/x{i}") for i in range(30)]
    out = diff_mod.diff_api(specs, eps)
    assert len(out["shadow"]) <= 20 and len(out["unseen"]) <= 20


def test_build_artifact_without_specs(tmp_path):
    from main.stages.mapping import build_api_diff
    payload = build_api_diff(tmp_path, [_ep("GET",
                                            "https://example.test/x")])
    assert payload == {"shadow": [], "unseen": [],
                       "param_gaps": []}
    assert json.loads((tmp_path / "api_diff.json").read_text()) == \
        payload


def test_gaps_become_leads():
    leads = collect_leads(
        [], [], [], {},
        {"shadow": [{"method": "GET", "path": "/admin/export",
                     "url": "https://example.test/admin/export",
                     "params": []}],
         "unseen": [{"method": "POST", "path": "/users/{id}",
                     "params": ["id"]}],
         "param_gaps": [{"method": "GET", "path": "/users",
                         "url": "https://example.test/users",
                         "extra_params": ["role"],
                         "missing_params": []}]})
    kinds = {lead["kind"]: lead for lead in leads}
    assert kinds["shadow-api"]["priority"] == "medium"
    assert kinds["shadow-api"]["url"] == \
        "https://example.test/admin/export"
    assert kinds["spec-unseen"]["priority"] == "info"
    assert "role" in kinds["spec-param-gap"]["reason"]
    assert kinds["spec-param-gap"]["param"] == "role"
    # backward compatible: old callers pass nothing extra
    assert collect_leads([], [], []) == []
