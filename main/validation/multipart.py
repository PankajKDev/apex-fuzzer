"""Byte-surgical multipart replay for observed upload shapes.

Real upload flows (the file-backed cases in hunter writeups) send
multipart bodies. Rebuilding them from parsed fields would re-encode
file bytes and invent boundaries, so this module does the opposite:
it keeps every observed byte and replaces exactly one text part's
content span.

Safety contract (bounded, fail-closed):
- only retained raw bytes are ever replayed; metadata-only shapes
  (no raw body) cannot be rebuilt and raise ValueError.
- only parts WITHOUT a filename may be targeted; file parts are
  never read for values and never rewritten (no invented uploads).
- the target field must occur exactly once among text parts;
  duplicates, missing boundaries, malformed/delimiter-confused
  bodies, oversized bodies (>1 MB), and >50 parts raise ValueError.
- part spans located by delimiter scan are cross-checked against an
  independent MIME parse (count, order, names); any disagreement
  raises ValueError instead of sending a misaligned body.
- the replacement value must not contain the boundary delimiter.
"""
import re
from email.parser import BytesParser
from email.policy import default as _email_policy
from typing import Any, Dict, List, Tuple

MAX_MULTIPART_BYTES = 1_000_000
MAX_MULTIPART_PARTS = 50

_BOUNDARY_RE = re.compile(r"boundary=([^;]+)", re.I)


def boundary_from_content_type(content_type: str) -> bytes:
    """Extract the MIME boundary token (fail-closed)."""
    match = _BOUNDARY_RE.search(content_type or "")
    if not match:
        raise ValueError("multipart boundary was not observed")
    token = match.group(1).strip().strip('"')
    if not token or len(token) > 200 or any(
            ch in token for ch in " \t\r\n"):
        raise ValueError("multipart boundary is unsupported")
    return token.encode("latin-1", errors="replace")


def raw_body_bytes(body: Any) -> bytes:
    """Coerce retained post data to bytes (fail-closed on binary gaps)."""
    if isinstance(body, (bytes, bytearray)):
        return bytes(body)
    if isinstance(body, str):
        return body.encode("utf-8")
    raise ValueError("multipart replay requires the retained request bytes")


def _mime_parts(raw: bytes, content_type: str) -> List[Dict[str, Any]]:
    """Independent MIME parse: [{name, filename, is_file}]."""
    prefix = ("Content-Type: " + (content_type or "") +
              "\r\nMIME-Version: 1.0\r\n\r\n").encode(
                  "latin-1", errors="replace")
    try:
        message = BytesParser(policy=_email_policy).parsebytes(prefix + raw)
    except (TypeError, ValueError, LookupError) as exc:
        raise ValueError("multipart body cannot be parsed safely") from exc
    if not message.is_multipart() or message.defects:
        raise ValueError("multipart body is malformed")
    parts = []
    for part in message.iter_parts():
        if part.defects or part.get_content_disposition() != "form-data":
            raise ValueError("multipart body is malformed")
        name = part.get_param("name", header="content-disposition")
        if not isinstance(name, str) or not name or len(name) > 200:
            raise ValueError("multipart field name is unsupported")
        parts.append({"name": name,
                      "is_file": part.get_filename() is not None})
        if len(parts) > MAX_MULTIPART_PARTS:
            raise ValueError("multipart body exceeds the part limit")
    return parts


def _part_spans(raw: bytes, boundary: bytes) -> List[Tuple[int, int, bytes]]:
    """Locate (content_start, content_end, header_block) per part.

    A span is accepted only when its header block parses as form-data
    with a plausible field name, so delimiter-like bytes inside file
    content cannot manufacture phantom parts.
    """
    delimiter = b"--" + boundary
    positions = []
    idx = 0
    while True:
        at = raw.find(delimiter, idx)
        if at < 0:
            break
        positions.append(at)
        idx = at + len(delimiter)
    spans = []
    for ordinal, at in enumerate(positions):
        rest = raw[at + len(delimiter):at + len(delimiter) + 2]
        if rest == b"--":
            break  # closing delimiter; preamble/epilogue untouched
        if rest != b"\r\n":
            raise ValueError("multipart body is malformed")
        head_start = at + len(delimiter) + 2
        head_end = raw.find(b"\r\n\r\n", head_start)
        if head_end < 0:
            raise ValueError("multipart body is malformed")
        nxt = positions[ordinal + 1] if ordinal + 1 < len(positions) else -1
        if nxt < 0 or not raw[nxt:nxt + len(delimiter)] == delimiter:
            raise ValueError("multipart body is malformed")
        # part content ends where the CRLF before the next delimiter
        # begins; a missing CRLF means the split is untrustworthy
        if raw[nxt - 2:nxt] != b"\r\n":
            raise ValueError("multipart body is malformed")
        header_block = raw[head_start:head_end]
        spans.append((head_end + 4, nxt - 2, header_block))
    if not spans:
        raise ValueError("multipart body holds no parts")
    return spans


def _span_field_name(header_block: bytes) -> str:
    try:
        text = header_block.decode("latin-1")
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("multipart part headers are undecodable") from exc
    match = re.search(r'name="([^"]{1,200})"', text)
    if not match:
        match = re.search(r"name=([^;\s]{1,200})", text)
    if not match:
        raise ValueError("multipart part has no field name")
    return match.group(1)


def _span_is_file(header_block: bytes) -> bool:
    try:
        text = header_block.decode("latin-1")
    except (UnicodeDecodeError, ValueError):
        return True  # undecodable headers: treat as untouchable
    return "filename=" in text.lower()


def multipart_field_value(raw: bytes, content_type: str,
                          parameter: str) -> str:
    """Return the text value of one uniquely occurring form field."""
    boundary = boundary_from_content_type(content_type)
    if len(raw) > MAX_MULTIPART_BYTES:
        raise ValueError("multipart body exceeds the local size limit")
    reference = _mime_parts(raw, content_type)
    targets = [i for i, part in enumerate(reference)
               if part["name"] == parameter and not part["is_file"]]
    if any(part["name"] == parameter and part["is_file"]
           for part in reference):
        raise ValueError("multipart file content is never read or replayed")
    if len(targets) != 1:
        raise ValueError("multipart field must occur exactly once "
                         "as a text part")
    spans = _part_spans(raw, boundary)
    if len(spans) != len(reference):
        raise ValueError("multipart part scan disagrees with MIME parse")
    for (start, _end, header), part in zip(spans, reference):
        _ = start  # spans verified positionally below
        if _span_field_name(header) != part["name"] or \
                _span_is_file(header) != part["is_file"]:
            raise ValueError("multipart part scan disagrees with MIME parse")
    start, end, _header = spans[targets[0]]
    try:
        return raw[start:end].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("multipart text field is not UTF-8") from exc


def multipart_with_parameter(raw: bytes, content_type: str, parameter: str,
                             value: str) -> bytes:
    """Return a copy of the body with one text part's value replaced.

    Every other byte (boundary, file contents, peer parts, framing)
    is preserved exactly.
    """
    boundary = boundary_from_content_type(content_type)
    if len(raw) > MAX_MULTIPART_BYTES:
        raise ValueError("multipart body exceeds the local size limit")
    encoded = str(value).encode("utf-8")
    if boundary in encoded or b"\r\n--" in encoded:
        raise ValueError("multipart replacement would corrupt framing")
    reference = _mime_parts(raw, content_type)
    if any(part["name"] == parameter and part["is_file"]
           for part in reference):
        raise ValueError("multipart file content is never read or replayed")
    targets = [i for i, part in enumerate(reference)
               if part["name"] == parameter and not part["is_file"]]
    if len(targets) != 1:
        raise ValueError("multipart field must occur exactly once "
                         "as a text part")
    spans = _part_spans(raw, boundary)
    if len(spans) != len(reference):
        raise ValueError("multipart part scan disagrees with MIME parse")
    for (_start, _end, header), part in zip(spans, reference):
        if _span_field_name(header) != part["name"] or \
                _span_is_file(header) != part["is_file"]:
            raise ValueError("multipart part scan disagrees with MIME parse")
    start, end, _header = spans[targets[0]]
    return raw[:start] + encoded + raw[end:]
