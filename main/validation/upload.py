"""File-upload workflow review (opt-in: persists files server-side).

Submits benign text files under probing filenames and verifies via
readback. Content is ALWAYS inert text — never scripts, polyglots,
or executable payloads. A candidate means the server accepted and
served a dangerous shape (active content type, unsanitized traversal,
confused type); execution is never attempted and needs a human.
"""
import re
import secrets
from dataclasses import dataclass, field
from typing import Any, Dict, List
from urllib.parse import urljoin, urlsplit

from ..budgets import BudgetExceeded
from ..logging_setup import get_logger

log = get_logger("upload")

# Inert probe content. Never anything executable.
PROBE_TEXT = "apex-fuzzer harmless upload probe"

_ACTIVE_CONTENT_TYPES = ("text/html", "application/xhtml+xml",
                         "image/svg+xml", "text/javascript",
                         "application/javascript", "application/x-shockwave-flash")

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)


@dataclass
class UploadResult:
    endpoint_url: str
    variant: str
    filename: str
    # accepted | rejected | inconclusive | candidate
    verdict: str = "inconclusive"
    notes: str = ""
    status: int = 0
    served_url: str = ""
    served_content_type: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"endpoint_url": self.endpoint_url,
                "variant": self.variant, "filename": self.filename,
                "verdict": self.verdict, "notes": self.notes,
                "status": self.status, "served_url": self.served_url,
                "served_content_type": self.served_content_type,
                "evidence": dict(self.evidence)}


def _nonce() -> str:
    return f"apex-{secrets.token_hex(4)}"


def upload_variants() -> List[Dict[str, str]]:
    """Probing filenames (content is always inert text)."""
    nonce = _nonce()
    return [
        {"variant": "content_type_mismatch",
         "filename": f"{nonce}.jpg",
         "content_type": "text/plain",
         "rationale": "image extension served as non-image type, "
                      "or declared type ignored"},
        {"variant": "traversal_filename",
         "filename": f"../../{nonce}.txt",
         "content_type": "text/plain",
         "rationale": "path separators must be stripped, never "
                      "honored in storage paths"},
        {"variant": "double_extension",
         "filename": f"{nonce}.txt.php",
         "content_type": "text/plain",
         "rationale": "executable-looking suffix must not survive "
                      "sanitization or be served as code"},
    ]


def multipart_body(field_name: str, filename: str,
                   content_type: str, text: str,
                   boundary: str) -> bytes:
    """Build one text-only multipart body (no file content ever)."""
    lines = [
        f"--{boundary}",
        f'Content-Disposition: form-data; name="{field_name}"; '
        f'filename="{filename}"',
        f"Content-Type: {content_type}",
        "",
        text,
        f"--{boundary}--",
        "",
    ]
    return "\r\n".join(lines).encode("utf-8", errors="replace")


def _is_active_content_type(content_type: str) -> bool:
    ctype = str(content_type or "").split(";")[0].strip().lower()
    return ctype in _ACTIVE_CONTENT_TYPES


def _readback_urls(response, base_url: str) -> List[str]:
    """In-scope readback candidates: Location, then JSON URL fields."""
    urls = []
    try:
        headers = dict(getattr(response, "headers", None) or {})
    except (AttributeError, TypeError):
        headers = {}
    for name, value in headers.items():
        if str(name).lower() == "location" and value:
            urls.append(urljoin(base_url, str(value)))
    try:
        import json as _json
        data = _json.loads(getattr(response, "text", "") or "")
    except (ValueError, TypeError):
        data = None
    if isinstance(data, dict):
        stack = [data]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                stack.extend(node.values())
            elif isinstance(node, list):
                stack.extend(node)
            elif isinstance(node, str):
                for match in _URL_RE.findall(node):
                    urls.append(match)
    # relative storage paths under well-known keys (url, path, file,
    # location, href) resolve against the endpoint
    if isinstance(data, dict):
        for key in ("url", "path", "file", "location", "href",
                    "file_url", "file_path"):
            value = data.get(key)
            if isinstance(value, str) and value.startswith("/"):
                urls.append(urljoin(base_url, value))
    seen, out = set(), []
    for url in urls:
        if url not in seen:
            seen.add(url)
            out.append(url)
    return out


def probe_upload(client, endpoint_url: str, field_name: str,
                 timeout: int = 10) -> List[UploadResult]:
    """Submit probing filenames, verify each via readback."""
    results = []
    for spec in upload_variants():
        result = UploadResult(
            endpoint_url=endpoint_url, variant=spec["variant"],
            filename=spec["filename"])
        boundary = f"apex-{secrets.token_hex(8)}"
        body = multipart_body(field_name, spec["filename"],
                              spec["content_type"], PROBE_TEXT,
                              boundary)
        headers = {"Content-Type":
                   f"multipart/form-data; boundary={boundary}"}
        try:
            r = client.post(endpoint_url, data=body,
                            headers=headers, timeout=timeout)
        except BudgetExceeded:
            raise
        except Exception as e:
            result.notes = f"submit failed: {e}"[:200]
            results.append(result)
            continue
        result.status = getattr(r, "status_code", 0) or 0
        if result.status in (400, 401, 403, 404, 405, 406, 409,
                             413, 415, 422, 428):
            result.verdict = "rejected"
            result.notes = f"server refused upload " \
                           f"(HTTP {result.status})"
            results.append(result)
            continue
        if not 200 <= result.status < 300:
            result.notes = f"unexpected HTTP {result.status}"
            results.append(result)
            continue
        # accepted: verify what the server actually stored/served
        served = ""
        served_ct = ""
        text = getattr(r, "text", "") or ""
        if ".." in spec["filename"] and (".." in text or
                                         "%2e%2e" in text.lower()):
            result.verdict = "candidate"
            result.notes = "traversal sequence echoed in storage " \
                           "response (sanitization failure)"
            result.evidence = {"echo": text[:500]}
            results.append(result)
            continue
        for candidate_url in _readback_urls(r, endpoint_url):
            try:
                parts = urlsplit(candidate_url)
            except ValueError:
                continue
            if parts.scheme not in ("http", "https"):
                continue
            try:
                fetched = client.get(candidate_url, timeout=timeout)
            except BudgetExceeded:
                raise
            except Exception:
                continue
            if getattr(fetched, "status_code", 0) != 200:
                continue
            served = candidate_url
            for name, value in (
                    getattr(fetched, "headers", None) or {}).items():
                if str(name).lower() == "content-type":
                    served_ct = str(value or "")
                    break
            break
        result.served_url = served
        result.served_content_type = served_ct
        if not served:
            result.notes = "accepted but no readable artifact " \
                           "found (no readback, no verification)"
            results.append(result)
            continue
        if _is_active_content_type(served_ct):
            result.verdict = "candidate"
            result.notes = f"stored file served as active content " \
                           f"({served_ct}): stored-XSS vector"
        elif ".." in served or "%2e" in served.lower():
            result.verdict = "candidate"
            result.notes = "stored path preserves traversal " \
                           "sequences"
        elif spec["variant"] == "double_extension" and \
                served.lower().endswith((".php", ".phtml", ".phar",
                                         ".asp", ".aspx", ".jsp")):
            result.verdict = "candidate"
            result.notes = "executable-looking suffix survived " \
                           "sanitization"
        else:
            result.verdict = "safe"
            result.notes = f"stored safely (served as " \
                           f"{served_ct or 'unknown type'})"
        results.append(result)
    return results
