"""Quiet lead-finder mode: read-only discovery, ranked follow-ups.

Fake objects only. No network.
"""
import json
from types import SimpleNamespace

from main.config import Config
from main.leads import MAX_LEADS, collect_leads, write_leads
from main.orchestrator import katana_rl, takeover_notes_from_file
from main.profiles import get as get_profile
from main.safety.preflight import resolve_modules


def _ep(url, endpoint_type="unknown", params=(), forms=()):
    from urllib.parse import urlparse
    return SimpleNamespace(
        url=url, normalized_url=url, endpoint_type=endpoint_type,
        path=urlparse(url).path,
        query_parameters=[SimpleNamespace(name=name) for name in params],
        body_parameters=[], header_parameters=[], forms=list(forms))


def test_leads_profile_is_read_only():
    profile = get_profile("leads")
    assert profile.run_nuclei is False
    assert profile.run_validation is False
    assert profile.run_ai is False
    assert profile.differential is False
    assert profile.param_mining is False
    assert profile.oast is False
    assert profile.run_tko is False
    assert profile.authz_matrix is False
    assert profile.second_order is False
    assert profile.business_logic is False
    assert profile.race is False
    assert profile.browser is False
    # read-only stages stay on: archives, JS, specs, robots, probe,
    # subzy fingerprint reads
    assert profile.run_httpx is True
    assert profile.js_analysis is True
    assert profile.api_specs is True
    assert profile.robots is True
    assert profile.run_subzy is True


def test_leads_profile_resolves_no_active_modules():
    states = {s.name: s.enabled
              for s in resolve_modules(Config(), get_profile("leads"))}
    for module in ("nuclei", "takeover_claim", "differential", "oast",
                   "validation", "authz_matrix", "second_order",
                   "business_logic", "race", "login", "ai", "browser"):
        assert states.get(module) is False, module


def test_quiet_crawl_rates():
    assert katana_rl("leads", 200) == 5
    assert katana_rl("leads", 20) == 5
    assert katana_rl("standard", 200) == 30
    assert katana_rl("standard", 20) == 10


def test_collect_leads_ranks_and_suggests():
    endpoints = [
        _ep("https://example.test/admin/users", "admin"),
        _ep("https://example.test/api/orders", "api",
            params=("order_id", "verbose")),
        _ep("https://example.test/hooks/incoming", "webhook",
            params=("callback_url",)),
        _ep("https://example.test/go", "redirect", params=("next",)),
        _ep("https://example.test/upload", "upload"),
        _ep("https://example.test/graphql", "graphql"),
        _ep("https://example.test/about", "page"),
    ]
    techs = [{"name": "nginx", "version": "1.25.3"}]
    leads = collect_leads(endpoints, techs, ["shop.example.test"])
    kinds = {lead["kind"] for lead in leads}
    assert {"privileged-endpoint", "id-param", "url-param",
            "redirect-sink", "upload-surface", "graphql-operation",
            "versioned-tech", "takeover-fingerprint"} <= kinds
    # every lead names its follow-up; none claims a vulnerability
    for lead in leads:
        assert lead["suggested_followup"]
        assert lead["id"].startswith("lead-")
        assert lead["priority"] in ("high", "medium", "low", "info")
    # high priority first
    ranks = [lead["priority"] for lead in leads]
    assert ranks == sorted(ranks,
                           key=("high", "medium", "low", "info").index)
    id_lead = next(lead for lead in leads if lead["kind"] == "id-param")
    assert id_lead["param"] == "order_id"
    assert "BOLA" in id_lead["suggested_followup"]
    url_lead = next(lead for lead in leads if lead["kind"] == "url-param")
    assert "oast" in url_lead["suggested_followup"]


def test_collect_leads_empty_and_stable():
    assert collect_leads([], [], []) == []
    endpoints = [_ep("https://example.test/api/orders", "api",
                     params=("order_id",))]
    first = collect_leads(endpoints, [], [])
    second = collect_leads(endpoints, [], [])
    assert [lead["id"] for lead in first] == \
        [lead["id"] for lead in second]


def test_collect_leads_capped():
    endpoints = [_ep(f"https://example.test/p{i}", "page",
                     params=tuple(f"q{i}_{j}" for j in range(5)))
                 for i in range(MAX_LEADS + 50)]
    assert len(collect_leads(endpoints, [], [])) == MAX_LEADS


def test_takeover_banner_lines_are_not_leads(tmp_path):
    path = tmp_path / "takeover.txt"
    path.write_text("[ * ] Loaded 1 targets\n"
                    "[ * ] Loaded 76 fingerprints\n"
                    "[ Yes ] HTTPS by default (--https)\n"
                    "[ Yes ] Show only potentially vulnerable "
                    "subdomains (--hide_fails)\n"
                    "\x1b[32m[VULN]\x1b[0m https://shop.example.test "
                    "is vulnerable (Shopify)\n")
    notes = takeover_notes_from_file(path)
    assert len(notes) == 1
    assert "shop.example.test" in notes[0]
    assert takeover_notes_from_file(tmp_path / "missing.txt") == []


def test_write_leads_roundtrip(tmp_path):
    endpoints = [_ep("https://example.test/admin", "admin")]
    leads = collect_leads(endpoints, [], [])
    path = tmp_path / "leads.jsonl"
    write_leads(path, leads)
    loaded = [json.loads(line) for line in
              path.read_text().splitlines()]
    assert loaded == leads
    empty = tmp_path / "empty.jsonl"
    write_leads(empty, [])
    assert empty.read_text() == ""


def test_report_renders_leads_section(tmp_path):
    from main.reporting.html import render_html
    endpoints = [_ep("https://example.test/admin", "admin")]
    leads = collect_leads(endpoints, [], [])
    out = tmp_path / "report.html"
    render_html(out, "example.test", [], [], {"leads_total": 1},
                leads=leads)
    html = out.read_text()
    assert "Leads (1)" in html
    assert "privileged-endpoint" in html
    assert "not a vulnerability" in html
    out2 = tmp_path / "report2.html"
    render_html(out2, "example.test", [], [], {})
    assert "Leads" not in out2.read_text()


def test_interesting_paths_become_leads():
    endpoints = [_ep("https://example.test/panel/", "page"),
                 _ep("https://example.test/inv/", "page"),
                 _ep("https://example.test/about", "page"),
                 _ep("https://example.test/invoice-regulations", "page")]
    leads = collect_leads(endpoints, [], [])
    by_url = {lead["url"]: lead for lead in leads
              if lead["kind"] == "interesting-path"}
    assert "https://example.test/panel/" in by_url
    assert "https://example.test/inv/" in by_url
    assert "https://example.test/about" not in by_url
    # segment match only: 'inv' must not fire on invoice-regulations
    assert "https://example.test/invoice-regulations" not in by_url
    assert "Repeater" in by_url["https://example.test/panel/"][
        "suggested_followup"]


def test_robots_harvest_reaches_endpoint_pool(tmp_path):
    """Robots/sitemap URLs harvested after recon must enter raw.txt.

    Regression: _harvest_robots wrote robots.txt.out after _merge_recon
    had already run, so its URLs never became endpoints (live run on a
    login-walled target kept 1 endpoint while robots named 19 paths).
    """
    from main.config import Config
    from main.orchestrator import Orchestrator
    from main.profiles import get as get_profile
    (tmp_path / "raw.txt").write_text("http://example.test/\n")
    (tmp_path / "robots.txt.out").write_text(
        "https://example.test/panel/\nhttps://example.test/inv/\n")
    orch = Orchestrator(Config(), tmp_path, profile=get_profile("leads"))
    orch._merge_recon(tmp_path)
    raw = (tmp_path / "raw.txt").read_text()
    assert "https://example.test/panel/" in raw
    assert "https://example.test/inv/" in raw
    assert "http://example.test/" in raw
