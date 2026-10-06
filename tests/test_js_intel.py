"""JS intel: flags, admin routes, and SDKs into artifact + graph + leads.

Zero network everywhere (offline cache reads). Admin routes are
unverified client hints: leads, never endpoints.
"""
import json

from main.discovery import js_intel as intel_mod
from main.graph.application_graph import ApplicationGraph
from main.leads import collect_leads
from main.reporting.metrics import Metrics


def _write_cache(tmp_path, name, js, url):
    cache = tmp_path / "cache"
    cache.mkdir(exist_ok=True)
    (cache / name).write_text(js)
    (cache / (name + ".meta")).write_text(json.dumps({"url": url}))


def test_flag_reads_and_values():
    js = ('if (isEnabled("newCheckout")) {}\n'
          'const x = flags.darkLaunch;\n'
          'const y = featureFlags["betaSearch"];\n'
          '"newCheckout": true\n')
    flags = {f["name"]: f["value"]
             for f in intel_mod.extract_feature_flags(js)}
    assert flags["newCheckout"] is True
    assert flags["darkLaunch"] is None
    assert flags["betaSearch"] is None
    assert intel_mod.extract_feature_flags("var x = 1;") == []


def test_comment_words_are_not_flags():
    js = '// flags for later use\nvar ok = isEnabled("real-flag");\n'
    names = [f["name"] for f in intel_mod.extract_feature_flags(js)]
    assert names == ["real-flag"]


def test_admin_routes_and_sdk_fingerprints():
    js = ('fetch("/api/items");\n'
          'route("/admin/users");\n'
          'link("/internal/debug");\n'
          'ldClient.variation("x");\n')
    routes = [r["path"] for r in intel_mod.extract_admin_routes(js)]
    assert routes == ["/admin/users", "/internal/debug"]
    assert intel_mod.detect_flag_sdks(js) == ["launchdarkly"]
    assert intel_mod.detect_flag_sdks("var x = 1;") == []
    # plain substrings never match: /preset stays out
    assert intel_mod.extract_admin_routes('"/preset"') == []


def test_analyze_bundle_shape():
    row = intel_mod.analyze_bundle('isEnabled("ab");\n',
                                   "https://example.test/a.js")
    assert row["source"] == "https://example.test/a.js"
    assert [f["name"] for f in row["flags"]] == ["ab"]
    assert row["admin_routes"] == [] and row["sdks"] == []
    # single characters are variables, not flags
    assert intel_mod.analyze_bundle(
        'isEnabled("a");\n')["flags"] == []


def test_stage_writes_artifact_and_graph(tmp_path):
    from main.stages.intel import build_js_intel
    _write_cache(tmp_path, "app.js",
                 'if (isEnabled("newCheckout")) {}\n'
                 'go("/admin/users");\n',
                 "https://example.test/app.js")
    graph = ApplicationGraph()
    payload = build_js_intel(tmp_path, graph, Metrics())
    artifact = json.loads((tmp_path / "js_intel.json").read_text())
    assert artifact == payload
    assert payload["bundles"][0]["flags"][0]["name"] == "newCheckout"
    assert payload["bundles"][0]["admin_routes"][0]["path"] == \
        "/admin/users"
    flag_nodes = [n for n in graph.nodes.values()
                  if n["type"] == "feature_flag"]
    assert [n["label"] for n in flag_nodes] == ["newCheckout"]
    assert any(e["type"] == "CONTAINS" for e in graph.edges)


def test_stage_without_cache_never_fails(tmp_path):
    from main.stages.intel import build_js_intel
    payload = build_js_intel(tmp_path, None, Metrics())
    assert payload == {"bundles": []}
    artifact = json.loads((tmp_path / "js_intel.json").read_text())
    assert artifact == {"bundles": []}


def test_admin_routes_become_leads_not_endpoints():
    leads = collect_leads(
        [], [], [],
        {"bundles": [{"source": "https://example.test/app.js",
                      "bundle": "app.js",
                      "flags": [{"name": "newCheckout",
                                 "value": True}],
                      "admin_routes": [{"path": "/admin/users"}],
                      "sdks": []}]})
    kinds = {lead["kind"]: lead for lead in leads}
    assert kinds["js-admin-route"]["priority"] == "high"
    assert kinds["js-admin-route"]["url"] == \
        "https://example.test/admin/users"
    assert "verify by hand" in kinds["js-admin-route"][
        "suggested_followup"]
    assert kinds["feature-flag"]["url"] == "https://example.test"
    # backward compatible: old callers pass nothing extra
    assert collect_leads([], [], []) == []
