"""Multipart validation/replay: byte-exact single-field replacement.

No network. Fake HTTP clients and fake sqlmap runners only.
"""
from types import SimpleNamespace

from main.config import Config
from main.models import Finding, Parameter
from main.validation import mutate as mut_mod
from main.validation import observed_sqli as obs_mod
from main.validation import sqli as sqli_mod
from main.validation.base import Candidate
from main.validation.multipart import (
    multipart_field_value, multipart_with_parameter)

BOUNDARY = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
CTYPE = f"multipart/form-data; boundary={BOUNDARY}"

# file content deliberately contains delimiter-like bytes
FILE_BYTES = (b"\x89PNG\r\n\x1a\n----WebKitFormBoundary7MA4YWxkTrZu0gW-fake"
              b"\x00\x01binary")


def _text_body(title="hello"):
    """Text-only upload: every part UTF-8-decodable, no NUL bytes."""
    return (
        f"--{BOUNDARY}\r\n"
        'Content-Disposition: form-data; name="title"\r\n\r\n'
        f"{title}\r\n"
        f"--{BOUNDARY}\r\n"
        'Content-Disposition: form-data; name="data"; '
        'filename="rows.csv"\r\n'
        "Content-Type: text/csv\r\n\r\n"
        "a,b\n1,2\n"
        f"\r\n--{BOUNDARY}\r\n"
        'Content-Disposition: form-data; name="note"\r\n\r\n'
        "plain\r\n"
        f"--{BOUNDARY}--\r\n"
    ).encode()


def _body(title="hello"):
    return (
        f"--{BOUNDARY}\r\n"
        'Content-Disposition: form-data; name="title"\r\n\r\n'
        f"{title}\r\n"
        f"--{BOUNDARY}\r\n"
        'Content-Disposition: form-data; name="avatar"; '
        'filename="a.png"\r\n'
        "Content-Type: image/png\r\n\r\n"
    ).encode() + FILE_BYTES + (
        f"\r\n--{BOUNDARY}\r\n"
        'Content-Disposition: form-data; name="note"\r\n\r\n'
        "plain\r\n"
        f"--{BOUNDARY}--\r\n"
    ).encode()


def _candidate(**overrides):
    base = dict(
        finding=Finding(id="mp1", source="test"), test_class="sqli",
        endpoint_url="https://example.test/upload", parameter="title",
        method="POST", parameter_location="body",
        request_content_type=CTYPE, request_body=_body(),
        body_parameters=[Parameter(name="title", location="body",
                                   sample_value="hello")])
    base.update(overrides)
    return Candidate(**base)


def test_replacement_preserves_everything_else_byte_exact():
    raw = _body()
    out = multipart_with_parameter(raw, CTYPE, "title", "INJECTED")
    assert b"INJECTED" in out
    assert b"hello" not in out
    assert FILE_BYTES in out  # file bytes untouched
    assert out.count(BOUNDARY.encode()) == raw.count(BOUNDARY.encode())
    # peer text field intact, framing intact
    assert b'name="note"\r\n\r\nplain\r\n' in out
    assert out.endswith(f"--{BOUNDARY}--\r\n".encode())
    assert multipart_field_value(out, CTYPE, "title") == "INJECTED"
    assert multipart_field_value(raw, CTYPE, "title") == "hello"


def test_file_part_is_never_read_or_rewritten():
    raw = _body()
    try:
        multipart_field_value(raw, CTYPE, "avatar")
    except ValueError:
        pass
    else:
        raise AssertionError("file content must not be readable")
    try:
        multipart_with_parameter(raw, CTYPE, "avatar", "x")
    except ValueError:
        pass
    else:
        raise AssertionError("file content must not be rewritable")


def test_duplicate_text_fields_fail_closed():
    raw = (f"--{BOUNDARY}\r\n"
           'Content-Disposition: form-data; name="tag"\r\n\r\na\r\n'
           f"--{BOUNDARY}\r\n"
           'Content-Disposition: form-data; name="tag"\r\n\r\nb\r\n'
           f"--{BOUNDARY}--\r\n").encode()
    try:
        multipart_with_parameter(raw, CTYPE, "tag", "x")
    except ValueError:
        pass
    else:
        raise AssertionError("duplicate fields must fail closed")


def test_missing_boundary_and_garbage_fail_closed():
    for bad_ct, bad_raw in [
            ("multipart/form-data", _body()),
            (CTYPE, b"not a multipart body"),
            ("text/plain", b"title=hello")]:
        try:
            multipart_with_parameter(bad_raw, bad_ct, "title", "x")
        except ValueError:
            pass
        else:
            raise AssertionError(f"must fail closed: {bad_ct!r}")


def test_oversized_body_fails_closed():
    big = _body() + b"x" * (2_000_000)
    try:
        multipart_with_parameter(big, CTYPE, "title", "x")
    except ValueError:
        pass
    else:
        raise AssertionError("oversized bodies must fail closed")


def test_metadata_only_shape_fails_closed_without_sending():
    class Http:
        def request(self, *args, **kwargs):
            raise AssertionError("metadata-only must not send")

    cfg = Config()
    cfg.safety.allow_state_change = True
    candidate = _candidate(request_body=None)
    outcome = mut_mod.MutationEngine(cfg, Http()).prescreen_sqli(candidate)
    assert outcome is not None
    assert outcome.status == "inconclusive"
    assert "retained" in outcome.notes


def test_sqli_prescreen_replays_single_field_byte_exact():
    seen = {}

    class Http:
        def request(self, method, url, **kwargs):
            seen["body"] = kwargs["data"]
            seen["headers"] = kwargs["headers"]
            text = kwargs["data"].decode("utf-8", "replace")
            if "MySQL" in text or "syntax" in text:
                return SimpleNamespace(status_code=500, text=text)
            if "' OR '1'='1" in text:
                return SimpleNamespace(
                    status_code=500,
                    text="You have an error in your SQL syntax; "
                         "echo '" + text[-200:] + "'")
            return SimpleNamespace(status_code=200, text='{"ok":true}')

    cfg = Config()
    cfg.safety.allow_state_change = True
    outcome = mut_mod.MutationEngine(cfg, Http()).prescreen_sqli(
        _candidate())
    assert outcome is not None
    assert outcome.status == "strong_candidate"
    assert FILE_BYTES in seen["body"]
    assert BOUNDARY in seen["headers"]["Content-Type"]


def test_xss_prescreen_replays_multipart_text_field():
    seen = {}

    class Http:
        def request(self, method, url, **kwargs):
            seen["body"] = kwargs["data"]
            return SimpleNamespace(
                status_code=200,
                text="<div>" + kwargs["data"].decode(
                    "utf-8", "replace") + "</div>")

    cfg = Config()
    cfg.safety.allow_state_change = True
    candidate = _candidate(test_class="xss")
    outcome = mut_mod.MutationEngine(cfg, Http()).prescreen_xss(candidate)
    assert outcome is not None
    assert outcome.status == "strong_candidate"
    assert FILE_BYTES in seen["body"]


def test_multipart_body_stays_off_without_state_ack():
    class Http:
        def request(self, *args, **kwargs):
            raise AssertionError("must not send without ack")

    outcome = mut_mod.MutationEngine(Config(), Http()).prescreen_sqli(
        _candidate())
    assert outcome is not None
    assert outcome.status == "inconclusive"
    assert "allow_state_change" in outcome.notes


def test_observed_selection_pins_text_only_multipart():
    from main.models import Endpoint
    ep = Endpoint(url="https://example.test/upload",
                  normalized_url="https://example.test/upload",
                  method="POST",
                  request_content_types=[CTYPE],
                  body_parameters=[Parameter(name="title",
                                             location="body")])
    ep.observed_requests = [{
        "identity": "alice", "method": "POST",
        "url": "https://example.test/upload",
        "headers": {"Content-Type": CTYPE},
        "post_data": _text_body().decode("utf-8"),
        "content_type": CTYPE}]
    matched, reason = obs_mod.select_observed_request(
        ep, "title", "body", endpoint_url="https://example.test/upload")
    assert matched is not None, reason
    raw = obs_mod.serialize_observed_to_raw(matched)
    assert BOUNDARY in raw
    assert "rows.csv" in raw


def test_observed_file_param_and_binary_fail_closed():
    from main.models import Endpoint
    ep = Endpoint(url="https://example.test/upload",
                  normalized_url="https://example.test/upload",
                  method="POST")
    ep.observed_requests = [{
        "identity": "alice", "method": "POST",
        "url": "https://example.test/upload",
        "headers": {"Content-Type": CTYPE},
        "post_data": _body(),  # binary file bytes: not UTF-8 text
        "content_type": CTYPE}]
    matched, _ = obs_mod.select_observed_request(
        ep, "avatar", "body", endpoint_url="https://example.test/upload")
    assert matched is None


def test_sqlmap_raw_path_keeps_multipart_bytes(monkeypatch):
    monkeypatch.setattr(sqli_mod, "which", lambda _: "/usr/bin/sqlmap")
    seen = {}
    monkeypatch.setattr(sqli_mod, "run", lambda args, timeout: (
        seen.update(raw=open(args[args.index("-r") + 1],
                             encoding="utf-8",
                             errors="replace").read(),
                    args=list(args))
        or SimpleNamespace(stdout="not injectable", stderr="")))
    candidate = _candidate(
        observed_request={"identity": "alice", "method": "POST",
                          "url": "https://example.test/upload",
                          "headers": {"Content-Type": CTYPE},
                          "post_data": _text_body().decode("utf-8"),
                          "content_type": CTYPE},
        observed_identity="alice")
    cfg = Config()
    cfg.safety.allow_state_change = True
    result = sqli_mod.SqliValidator(cfg).validate(candidate)
    assert "-r" in seen["args"]
    assert BOUNDARY in seen["raw"]
    assert "rows.csv" in seen["raw"]
    assert result.status == "false_positive"
