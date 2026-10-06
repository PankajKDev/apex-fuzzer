"""Tests: file-upload workflow review (no network)."""
from main.models import Endpoint, Parameter


def _ep(path="/upload", params=()):
    ep = Endpoint(url=f"https://example.com{path}",
                  normalized_url=f"https://example.com{path}",
                  host="example.com", path=path, method="POST",
                  endpoint_type="upload",
                  body_parameters=[Parameter(name=n, location="body")
                                   for n in params])
    return ep


class Http:
    def __init__(self, submit=None, fetched=None):
        self._submit = submit or (200, "stored")
        self._fetched = fetched
        self.posts = []
        self.gets = []

    def post(self, url, data=None, headers=None, timeout=10):
        self.posts.append((url, data, headers))
        status, text = self._submit
        return _R(status, text, {})

    def get(self, url, **kw):
        self.gets.append(url)
        if self._fetched is None:
            return _R(404, "nope", {})
        status, text, ctype = self._fetched
        return _R(status, text, {"content-type": ctype})


class _R:
    def __init__(self, status_code, text, headers):
        self.status_code = status_code
        self.text = text
        self.headers = headers


def _run(ep, http, cfg=None):
    from main.budgets import BudgetTracker
    from main.config import Config
    from main.reporting.coverage import CoverageTracker
    from main.reporting.metrics import Metrics
    from main.scope import Scope
    from main.stages.validation import ProbeControls
    from main.stages.validation.upload import upload_probe
    from main.validation.evidence import EvidenceStore
    from pathlib import Path
    import tempfile
    out = Path(tempfile.mkdtemp())
    cfg = cfg or Config()
    coverage = CoverageTracker()
    found = upload_probe(
        [ep], EvidenceStore(out / "proofs"), Metrics(),
        BudgetTracker(cfg), coverage, http, cfg, Scope(cfg.scope),
        ProbeControls())
    return found, coverage


def test_type_confusion_is_candidate():
    # declared text served back as HTML: stored-XSS vector
    http = Http(submit=(200, '{"url": "/files/a.jpg"}'),
                fetched=(200, "apex probe", "text/html"))
    found, coverage = _run(_ep(), http)
    cands = [f for f in found if f.source == "upload-probe"]
    assert cands, "served-as-HTML mismatch must raise"
    assert cands[0].validation_status == "strong_candidate"
    assert coverage.summary()["upload"] == "candidate"


def test_traversal_echo_is_candidate():
    http = Http(submit=(200, "stored at ../../evil.txt"), fetched=None)
    found, coverage = _run(_ep(), http)
    assert any(f.source == "upload-probe" for f in found)


def test_clean_reject_is_negative():
    http = Http(submit=(415, "unsupported media type"), fetched=None)
    found, coverage = _run(_ep(), http)
    assert found == []
    assert coverage.summary()["upload"] == "tested_negative"


def test_safe_serve_is_negative():
    http = Http(submit=(200, '{"url": "/files/a.txt"}'),
                fetched=(200, "apex probe", "text/plain"))
    found, coverage = _run(_ep(), http)
    assert found == []
    assert coverage.summary()["upload"] == "tested_negative"


def test_no_readback_is_inconclusive():
    http = Http(submit=(200, "ok"), fetched=None)
    found, coverage = _run(_ep(), http)
    assert found == []
    assert coverage.summary()["upload"] == "inconclusive"


def test_non_upload_endpoints_skipped():
    ep = _ep("/api/items")
    ep.endpoint_type = "api"
    found, coverage = _run(ep, Http())
    assert found == []


def test_attachment_downgrades_active_content():
    from main.config import ScopeConfig
    from main.scope import Scope
    from main.validation import upload as upload_mod

    class Http2(Http):
        def get(self, url, **kw):
            self.gets.append(url)
            return _R(200, "apex probe",
                      {"content-type": "text/html",
                       "content-disposition":
                       "attachment; filename=x",
                       "x-content-type-options": "nosniff"})

    http = Http2(submit=(200, '{"url": "/files/a.html"}'),
                 fetched=(200, "apex probe", "text/html"))
    out = upload_mod.probe_upload(
        http, "https://example.com/upload", "file", scope=Scope(
            ScopeConfig(allowed_domains=["example.com"])))
    assert out
    assert all(r.verdict == "safe" for r in out if r.served_url)
    assert any("attachment" in r.notes for r in out if r.served_url)
    assert all(r.served_nosniff for r in out if r.served_url)
    assert all(r.evidence.get("disposition") == "attachment"
               for r in out if r.served_url)


def test_off_scope_readback_is_never_fetched():
    from main.config import ScopeConfig
    from main.scope import Scope
    from main.validation import upload as upload_mod

    http = Http(submit=(200, '{"url": "https://evil.test/files/x"}'),
                fetched=(200, "apex probe", "text/html"))
    out = upload_mod.probe_upload(
        http, "https://example.com/upload", "file", scope=Scope(
            ScopeConfig(allowed_domains=["example.com"])))
    assert http.gets == []
    assert all(r.served_url == "" for r in out)
    assert any("out of scope" in r.notes for r in out)


def test_inert_content_only(tmp_path):
    from main.budgets import BudgetTracker
    from main.config import Config
    from main.reporting.coverage import CoverageTracker
    from main.reporting.metrics import Metrics
    from main.scope import Scope
    from main.stages.validation import ProbeControls
    from main.stages.validation.upload import upload_probe
    from main.validation.evidence import EvidenceStore
    from pathlib import Path
    out = Path(tmp_path)
    cfg = Config()
    http = Http()
    upload_probe([_ep()], EvidenceStore(out / "proofs"), Metrics(),
                 BudgetTracker(cfg), CoverageTracker(), http, cfg,
                 Scope(cfg.scope), ProbeControls())
    for _, data, _ in http.posts:
        assert b"apex-fuzzer harmless upload probe" in data
        for danger in (b"<?php", b"<script", b"#!/bin",
                       b"webshell", b"<?="):
            assert danger not in data.lower()


def test_multipart_shape():
    from main.validation.upload import (multipart_body, upload_variants,
                                        PROBE_TEXT)
    assert len(upload_variants()) == 3
    body = multipart_body("file", "a.txt", "text/plain", PROBE_TEXT,
                          "BOUND")
    assert body.startswith(b"--BOUND\r\n")
    assert b'filename="a.txt"' in body
    assert body.endswith(b"--BOUND--\r\n")


def test_plan_and_flag():
    from main.safety.preflight import plan_upload
    assert plan_upload(4).total == 12
    from main.cli import build_parser
    from main.config import Config, apply_cli_overrides
    args = build_parser().parse_args(["-d", "x.test", "--upload"])
    cfg = apply_cli_overrides(Config(), args)
    assert cfg.validation.upload is True
    cfg.validation.upload_max_endpoints = -1
    assert any("upload_max_endpoints" in e
               for e in cfg.validate()["errors"])
