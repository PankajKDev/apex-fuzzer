"""Burp handoff export: paste-ready requests, sitemap XML, checklist.

Fake objects only. No network.
"""
import base64
import xml.etree.ElementTree as ET
from types import SimpleNamespace

from apex_fuzzer.reporting.burp import (
    BURP_STEPS, build_raw_request, export_burp, lead_checklist,
    sitemap_xml)


def _param(name, sample=None):
    return SimpleNamespace(name=name, sample_value=sample)


def _ep(url, method="GET", query=(), body=(), headers=()):
    return SimpleNamespace(
        url=url, normalized_url=url, method=method,
        query_parameters=[_param(n) for n in query],
        body_parameters=[_param(n, s) for n, s in body],
        header_parameters=[_param(n, s) for n, s in headers])


def test_build_get_request():
    raw = build_raw_request(
        _ep("https://example.test/api/orders?order_id=5"))
    head, _, body = raw.partition("\r\n\r\n")
    assert head.splitlines()[0] == \
        "GET /api/orders?order_id=5 HTTP/1.1"
    assert "Host: example.test" in head
    assert "Content-Length" not in head
    assert body == ""


def test_build_post_request_with_samples():
    raw = build_raw_request(_ep(
        "http://example.test:8080/login", method="POST",
        body=(("username", "alice"), ("password", None))))
    head, _, body = raw.partition("\r\n\r\n")
    assert head.splitlines()[0] == "POST /login HTTP/1.1"
    assert "Host: example.test:8080" in head
    assert "application/x-www-form-urlencoded" in head
    assert body == "username=alice&password="
    for line in head.splitlines():
        if line.lower().startswith("content-length:"):
            assert line.split(":")[1].strip() == str(len(body.encode()))
            break
    else:
        raise AssertionError("missing Content-Length")


def test_identity_headers_never_invented():
    raw = build_raw_request(_ep(
        "https://example.test/", headers=(("X-Debug", "1"),
                                          ("Cookie", "s=abc"),
                                          ("Authorization", "x"))))
    assert "X-Debug: 1" in raw
    assert "Cookie:" not in raw
    assert "Authorization:" not in raw


def test_sitemap_xml_roundtrips():
    endpoints = [_ep("https://example.test/api/orders?order_id=5"),
                 _ep("http://example.test:8080/login", method="POST")]
    pairs = [(ep, build_raw_request(ep)) for ep in endpoints]
    root = ET.fromstring(sitemap_xml(pairs))
    assert root.tag == "items"
    items = root.findall("item")
    assert len(items) == 2
    first = items[0]
    assert first.find("url").text == \
        "https://example.test/api/orders?order_id=5"
    assert first.find("protocol").text == "https"
    assert first.find("comment").text.startswith("apex-fuzzer lead")
    decoded = base64.b64decode(first.find("request").text).decode()
    assert decoded == pairs[0][1]
    assert items[1].find("port").text == "8080"


def test_checklist_maps_every_lead_kind():
    leads = [{"id": "lead-1", "kind": kind, "priority": "high",
              "url": "https://example.test/x", "param": "id",
              "reason": "r", "suggested_followup": "f",
              "confidence": "possible"}
             for kind in BURP_STEPS]
    md = lead_checklist(leads)
    for kind in BURP_STEPS:
        assert kind in md
    assert "Intruder" in md and "Repeater" in md and "Collaborator" in md
    assert "not a finding" in md


def test_export_writes_burp_dir(tmp_path):
    endpoints = [_ep("https://example.test/api/orders?order_id=5"),
                 _ep("https://example.test/api/orders?order_id=5"),
                 _ep("not-a-url"),
                 _ep("https://example.test/about")]
    leads = [{"id": "lead-1", "kind": "id-param", "priority": "high",
              "url": "https://example.test/api/orders?order_id=5",
              "param": "order_id", "reason": "ids",
              "suggested_followup": "validate", "confidence": "possible"}]
    summary = export_burp(tmp_path, endpoints, leads)
    assert summary == {"requests": 2, "urls": 2, "sitemap_items": 2,
                       "leads": 1}
    burp = tmp_path / "burp"
    assert (burp / "urls.txt").read_text().splitlines() == [
        "https://example.test/about",
        "https://example.test/api/orders?order_id=5"]
    assert len(list((burp / "requests").glob("*.txt"))) == 2
    ET.fromstring((burp / "sitemap.xml").read_text())
    assert "id-param" in (burp / "lead-checklist.md").read_text()


def test_report_renders_burp_block(tmp_path):
    from apex_fuzzer.reporting.html import render_html
    out = tmp_path / "report.html"
    render_html(out, "example.test", [], [], {},
                burp={"requests": 3, "urls": 3,
                      "sitemap_items": 3, "leads": 1})
    html = out.read_text()
    assert "Burp handoff" in html
    assert "lead-checklist.md" in html
    out2 = tmp_path / "report2.html"
    render_html(out2, "example.test", [], [], {})
    assert "Burp handoff" not in out2.read_text()
