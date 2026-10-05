"""postMessage/SOP static sweep over the cached JS inventory.

Zero network in production (offline file reads); no network here
either. Code excerpts are never persisted — only file, line, and
marker family.
"""
import json

from main.reporting.coverage import CoverageTracker
from main.validation import postmessage as pm_mod
from main.validation.evidence import EvidenceStore


def _handler_js():
    return ('window.addEventListener("message", function(e) {\n'
            '  document.getElementById("x").innerHTML = e.data;\n'
            '});\n')


def _guarded_js():
    return ('window.addEventListener("message", function(e) {\n'
            '  if (e.origin !== "https://app.example.test") return;\n'
            '  handle(e.data);\n'
            '});\n')


def test_handler_without_origin_check_is_candidate():
    hits = pm_mod.check_message_handlers(_handler_js())
    assert len(hits) == 1
    assert hits[0]["kind"] == "handler-no-origin-check"
    assert hits[0]["line"] == 1


def test_guarded_handler_is_silent():
    assert pm_mod.check_message_handlers(_guarded_js()) == []
    assert pm_mod.check_message_handlers("") == []


def test_onmessage_assignment_counts_as_handler():
    hits = pm_mod.check_message_handlers("window.onmessage = (e) => {\n"
                                         "  go(e.data);\n};\n")
    assert len(hits) == 1


def test_wildcard_post_is_graded_by_sensitivity():
    sensitive = ('var t = localStorage.getItem("token");\n'
                 'other.postMessage({t: t}, "*");\n')
    hits = pm_mod.check_wildcard_posts(sensitive)
    assert len(hits) == 1
    assert hits[0]["sensitive"] is True
    plain = 'other.postMessage({ok: 1}, "*");\n'
    hits = pm_mod.check_wildcard_posts(plain)
    assert len(hits) == 1
    assert hits[0]["sensitive"] is False
    assert pm_mod.check_wildcard_posts(
        'other.postMessage({ok: 1}, "https://app.example.test");\n') == []


def test_document_domain_is_flagged():
    hits = pm_mod.check_document_domain("document.domain = 'example.test';")
    assert len(hits) == 1
    assert hits[0]["kind"] == "document-domain"
    assert pm_mod.check_document_domain("var x = 1;") == []


def _write_cache(tmp_path, name, js, url):
    cache = tmp_path / "cache"
    cache.mkdir(exist_ok=True)
    (cache / name).write_text(js)
    (cache / (name + ".meta")).write_text(json.dumps({"url": url}))


def test_probe_emits_findings_without_code_excerpts(tmp_path):
    from main.stages.validation import ProbeControls
    from main.stages.validation.postmessage import postmessage_probe

    _write_cache(tmp_path, "app.js", _handler_js(),
                 "https://example.test/app.js")
    coverage = CoverageTracker()
    out = postmessage_probe(tmp_path, EvidenceStore(tmp_path / "p"),
                            coverage, None, ProbeControls())
    assert len(out) == 1
    finding = out[0]
    assert finding.source == "postmessage-static"
    assert finding.severity == "medium"
    assert "innerHTML" not in finding.description
    assert "innerHTML" not in json.dumps(finding.raw)
    assert coverage.summary()["postmessage"] == "candidate"


def test_probe_skips_meta_files_and_unusable_entries(tmp_path):
    from main.stages.validation import ProbeControls
    from main.stages.validation.postmessage import postmessage_probe

    cache = tmp_path / "cache"
    cache.mkdir(exist_ok=True)
    (cache / "orphan.js").write_text(_handler_js())  # no .meta
    (cache / "notes.meta").write_text("{}")
    coverage = CoverageTracker()
    out = postmessage_probe(tmp_path, EvidenceStore(tmp_path / "p"),
                            coverage, None, ProbeControls())
    assert out == []


def test_probe_without_cache_is_untestable(tmp_path):
    from main.stages.validation import ProbeControls
    from main.stages.validation.postmessage import postmessage_probe

    coverage = CoverageTracker()
    out = postmessage_probe(tmp_path, EvidenceStore(tmp_path / "p"),
                            coverage, None, ProbeControls())
    assert out == []
    assert coverage.summary()["postmessage"] == "untestable"


def test_reviews_map_postmessage_findings():
    from main.models import Finding
    from main.reporting.reviews import finding_test_class
    assert finding_test_class(
        Finding(id="a", source="postmessage-static",
                tags=["postmessage"])) == "postmessage"
