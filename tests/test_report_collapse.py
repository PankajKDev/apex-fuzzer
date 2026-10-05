"""Tests: report-level collapse of combinatorial findings."""
from apex_fuzzer.models import Finding
from apex_fuzzer.reporting.html import _collapse_key, _section


def _swap(i, tester, victim, param="id"):
    return Finding(
        id=f"swap-{i}", source="idor-swap",
        endpoint_url="https://example.com/api/u/1",
        matched_at="https://example.com/api/u/1",
        method="GET", parameter=param, severity="high",
        identity=tester,
        resource_key=f"https://example.com/api/u/1::{param}={victim}")


def test_collapse_key_groups_combinatorics():
    a = _swap(1, "user_b", "v1")
    b = _swap(2, "user_c", "v2")
    assert _collapse_key(a) == _collapse_key(b)
    other = _swap(3, "user_b", "v1", param="order_id")
    assert _collapse_key(a) != _collapse_key(other)


def test_section_groups_with_header_and_keeps_rows():
    findings = [_swap(1, "user_b", "v1"), _swap(2, "user_c", "v2"),
                _swap(3, "user_b", "v3", param="order_id")]
    html = _section("Candidates", findings, None)
    assert html.count("class='group'") == 1
    assert "2× idor-swap" in html
    assert "user_b, user_c" in html
    assert "objects: 2" in html
    # every finding still renders its own row (endpoint link per row)
    assert html.count("https://example.com/api/u/1") >= 3


def test_singleton_renders_unchanged():
    f = Finding(id="n-1", source="nuclei-x", severity="medium",
                endpoint_url="https://example.com/x", method="GET")
    html = _section("Candidates", [f], None)
    assert "class='group'" not in html
    assert "nuclei-x" in html


def test_render_html_with_swap_volume(tmp_path):
    from apex_fuzzer.reporting.html import render_html
    findings = [_swap(i, f"user_{i % 3}", f"victim-{i}")
                for i in range(6)]
    out = tmp_path / "report.html"
    render_html(out, "example.com", findings, [], {}, "info", tmp_path)
    text = out.read_text()
    assert text.count("class='group'") == 1
    assert "6× idor-swap" in text
