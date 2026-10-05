"""Tests for HAR import (inventory only: no network, no replay)."""
import json

from apex_fuzzer.config import ScopeConfig
from apex_fuzzer.discovery import har as har_mod
from apex_fuzzer.scope import Scope


def _scope():
    return Scope(ScopeConfig(allowed_domains=["example.com"]))


def _har(*requests):
    return {"log": {"entries": [
        {"request": req, "response": {"status": 200}} for req in requests]}}


def _req(url, method="GET", headers=None, query=None, post=None):
    return {"url": url, "method": method,
            "headers": [{"name": k, "value": v}
                        for k, v in (headers or {}).items()],
            "queryString": [{"name": k, "value": v}
                            for k, v in (query or {}).items()],
            "postData": post}


def test_query_params_and_method_preserved():
    data = _har(_req("https://example.com/api/docs?id=7&slug=a",
                     query={"id": "7", "slug": "a"}))
    entries = har_mod.parse_har(data, _scope())
    assert len(entries) == 1
    e = entries[0]
    assert e["method"] == "GET" and e["source"] == ["har"]
    assert sorted(e["params"]) == ["id", "slug"]
    assert e["observed_requests"][0]["identity"] == "har"


def test_form_and_json_bodies_blank_samples():
    data = _har(
        _req("https://example.com/login", method="POST",
             headers={"Content-Type": "application/x-www-form-urlencoded"},
             post={"mimeType": "application/x-www-form-urlencoded",
                   "text": "user=alice&password=s3cret"}),
        _req("https://example.com/api/items", method="POST",
             headers={"Content-Type": "application/json"},
             post={"mimeType": "application/json",
                   "text": '{"sku": "A-1", "token": "abc"}'}))
    entries = har_mod.parse_har(data, _scope())
    assert {e["url"] for e in entries} == {
        "https://example.com/login", "https://example.com/api/items"}
    login = next(e for e in entries if "login" in e["url"])
    assert login["body"] == {"user": "", "password": ""}
    items = next(e for e in entries if "items" in e["url"])
    assert items["body"] == {"sku": "", "token": ""}
    # exact bytes retained runtime-only for replay fidelity
    assert "password=s3cret" in login["observed_requests"][0]["post_data"]


def test_identity_carriers_dropped_from_retained_headers():
    data = _har(_req("https://example.com/api/me",
                     headers={"Cookie": "session=AAA",
                              "Authorization": "Bearer BBB",
                              "Accept": "application/json"}))
    (e,) = har_mod.parse_har(data, _scope())
    kept = e["observed_requests"][0]["headers"]
    assert "Cookie" not in kept and "Authorization" not in kept
    assert kept.get("Accept") == "application/json"


def test_scope_ext_and_credential_url_filtering():
    data = _har(
        _req("https://evil.com/api"),
        _req("https://example.com/logo.png"),
        _req("https://user:pass@example.com/api/x#frag"),
        _req("ftp://example.com/file"))
    entries = har_mod.parse_har(data, _scope())
    assert [e["url"] for e in entries] == ["https://example.com/api/x"]


def test_malformed_har_fails_closed():
    assert har_mod.parse_har({}, _scope()) == []
    assert har_mod.parse_har({"log": {"entries": "nope"}},
                             _scope()) == []
    assert har_mod.parse_har({"log": {"entries": [None, "x", {}]}},
                             _scope()) == []
    assert har_mod.load_har_file("/nonexistent/file.har") is None


def test_entry_cap_and_observed_dedupe():
    reqs = [_req(f"https://example.com/a?i={i}", query={"i": str(i)})
            for i in range(10)]
    entries = har_mod.parse_har(_har(*reqs), _scope(), max_entries=3)
    assert len(entries) == 3
    dup = _har(_req("https://example.com/a?x=1", query={"x": "1"}),
               _req("https://example.com/a?x=1", query={"x": "1"}))
    (e,) = har_mod.parse_har(dup, _scope())
    assert len(e["observed_requests"]) == 1


def test_oversized_body_keeps_inventory_drops_bytes():
    big = "f=" + "A" * (har_mod._MAX_BODY_CHARS + 1)
    data = _har(_req("https://example.com/upload", method="POST",
                     headers={"Content-Type":
                              "application/x-www-form-urlencoded"},
                     post={"mimeType": "application/x-www-form-urlencoded",
                           "text": big}))
    (e,) = har_mod.parse_har(data, _scope())
    assert e["body"] == {"f": ""}
    assert e["observed_requests"] == []


def test_merge_attributes_har_source():
    from apex_fuzzer.discovery.url_normalizer import normalize_url
    from apex_fuzzer.models import Endpoint
    from apex_fuzzer.orchestrator import Orchestrator
    data = _har(_req("https://example.com/api/docs?id=7",
                     query={"id": "7"}))
    (entry,) = har_mod.parse_har(data, _scope())
    n = normalize_url(entry["url"])
    by_norm = {n: Endpoint(url=entry["url"], normalized_url=n,
                           host="example.com", path="/api/docs",
                           method="GET", source=["recon"])}
    Orchestrator._merge_browser_entry(by_norm, "example.com", entry)
    ep = by_norm[n]
    assert "har" in ep.source and "browser" not in ep.source
    locs = {(p.name, p.location) for p in ep.query_parameters}
    assert ("id", "query") in locs
    assert all("har" in p.source for p in ep.query_parameters)


def test_orchestrator_har_import_skips_missing(tmp_path):
    from apex_fuzzer.config import Config
    from apex_fuzzer.orchestrator import Orchestrator
    from apex_fuzzer.profiles import get as get_profile
    cfg = Config()
    cfg.scope.allowed_domains = ["example.com"]
    cfg.har_files = [str(tmp_path / "missing.har")]
    orch = Orchestrator(cfg, tmp_path, profile=get_profile("standard"))
    assert orch._har_import("example.com") == []


def test_orchestrator_har_import_merges_endpoints(tmp_path):
    from apex_fuzzer.config import Config
    from apex_fuzzer.orchestrator import Orchestrator
    from apex_fuzzer.profiles import get as get_profile
    har = tmp_path / "capture.har"
    har.write_text(json.dumps(_har(
        _req("https://example.com/api/orders?order_id=9",
             query={"order_id": "9"}))))
    cfg = Config()
    cfg.scope.allowed_domains = ["example.com"]
    cfg.har_files = [str(har)]
    orch = Orchestrator(cfg, tmp_path, profile=get_profile("standard"))
    found = orch._har_import("example.com")
    assert len(found) == 1 and found[0]["params"] == ["order_id"]
