"""Nonce-correlated, out-of-band XXE detection for observed XML requests.

This probe never references local files. It adds one external entity pointing
to the configured OAST provider and confirms only a callback correlated to
that exact request. POST bodies require the explicit state-change gate.
"""
from __future__ import annotations

import re
import secrets
from xml.etree import ElementTree
from typing import Any, Dict
from urllib.parse import urlsplit

from .base import Candidate, ValidationOutcome, Validator
from .oast import matching_interactions
from .second_order import make_ssrf_canary
from ..budgets import BudgetExceeded
from ..models import Confidence, ValidationStatus


_MAX_XML_BYTES = 64 * 1024
_FORBIDDEN_DTD = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)\b", re.I)
_ROOT_TAG = re.compile(r"<([A-Za-z_:][\w:.-]*)(?=[\s/>])[^<>]*>")

# container formats: only XML-text shapes are probed in normal scans.
# Zip/office and binary image metadata need isolated document tooling;
# they fail closed here with an explicit note.
_CONTAINER_MAGIC = (b"\x50\x4b\x03\x04",  # zip: docx/xlsx/odt/jar
                    b"\xd0\xcf\x11\xe0",  # OLE: doc/xls/ppt
                    b"\xff\xd8\xff",  # JPEG (EXIF/XMP lives here)
                    b"\x89PNG",  # PNG (iTXt/tEXt metadata)
                    b"GIF8",  # GIF comment blocks
                    b"%PDF-")  # PDF (embedded XML/XMP)
_XML_PROLOG_RE = re.compile(r"<\?xml\b", re.I)
_CONTAINER_ROOT_RE = re.compile(r"<(?:\w+:)?(?:svg|Envelope)\b", re.I)


def sniff_xml_shape(raw: Any, content_type: str) -> str:
    """Classify an observed body for XXE probing.

    Returns "xml" (declared or sniffed XML text: prolog, svg root, or
    Envelope root), "container" (office/binary formats needing isolated
    document tooling), or "other".
    """
    lowered = (content_type or "").lower()
    if "xml" in lowered or "svg" in lowered:
        return "xml"
    if isinstance(raw, (bytes, bytearray)):
        blob = bytes(raw)
        if blob.startswith(_CONTAINER_MAGIC):
            return "container"
        try:
            head = blob[:2000].decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            return "container"
    elif isinstance(raw, str):
        head = raw.lstrip("\ufeff \t\r\n")[:2000]
    else:
        return "other"
    if _XML_PROLOG_RE.match(head) or _CONTAINER_ROOT_RE.match(head):
        return "xml"
    return "other"


def container_note(raw: Any) -> str:
    """Explain why a container/binary body stays out of normal scans."""
    if isinstance(raw, (bytes, bytearray)) and bytes(raw)[:4] in (
            b"\x50\x4b\x03\x04", b"\xd0\xcf\x11\xe0"):
        return ("office document container (zip/OLE): XXE inside document "
                "parts needs isolated document tooling with established "
                "format libraries; not replayed in normal scans")
    return ("binary or container format: XXE inside image metadata, PDF, "
            "or office parts needs isolated fixtures; not replayed in "
            "normal scans")


class XxeValidator(Validator):
    name = "xxe-oast"
    test_class = "xxe"

    def __init__(self, cfg, http, provider, timeout: int = 10):
        super().__init__(cfg)
        self.http = http
        self.provider = provider
        self.timeout = timeout

    def validate(self, candidate: Candidate) -> ValidationOutcome:
        if not self.provider or not self.provider.available():
            return self._inconclusive("no live OAST provider")
        if (candidate.method or "GET").upper() != "POST":
            return self._inconclusive(
                "XXE probe currently supports observed POST XML bodies only")
        if not getattr(getattr(self.cfg, "safety", None),
                       "allow_state_change", False):
            return self._inconclusive(
                "XML POST probe requires safety.allow_state_change")

        body = candidate.request_body
        if isinstance(body, (bytes, bytearray)) and \
                bytes(body)[:4] in (b"\x50\x4b\x03\x04", b"\xd0\xcf\x11\xe0"):
            return self._inconclusive(container_note(body))
        if not isinstance(body, str) or not body.strip():
            return self._inconclusive("no observed XML request body")
        raw = body.strip()
        if len(raw.encode("utf-8", "replace")) > _MAX_XML_BYTES:
            return self._inconclusive("observed XML body exceeds 64 KiB cap")
        shape = sniff_xml_shape(raw, candidate.request_content_type or "")
        if shape == "container":
            return self._inconclusive(container_note(raw))
        if shape != "xml":
            return self._inconclusive("observed request body is not XML")
        if _FORBIDDEN_DTD.search(raw):
            return self._inconclusive(
                "observed XML already contains a DTD/entity declaration")
        try:
            ElementTree.fromstring(raw)
        except ElementTree.ParseError:
            return self._inconclusive("observed request body is malformed XML")
        root = _ROOT_TAG.search(raw)
        if not root or not re.search(
                rf"</{re.escape(root.group(1))}\s*>\s*$", raw):
            return self._inconclusive(
                "observed body is not a supported single-root XML document")

        callback = make_ssrf_canary(self.provider.create_token(), "http")
        parsed = urlsplit(callback)
        if parsed.scheme != "http" or not parsed.netloc:
            return self._inconclusive("OAST provider returned an invalid callback")
        entity = "apx" + secrets.token_hex(5)
        declaration = (f'<!DOCTYPE {root.group(1)} '
                       f'[<!ENTITY {entity} SYSTEM "{callback}">]>')
        # Reference the entity in the root's text content while retaining the
        # observed document structure and all existing fields.
        probe_body = (raw[:root.start()] + declaration + raw[root.start():
                      root.end()] + f"&{entity};" + raw[root.end():])
        headers = dict(candidate.request_headers or {})
        if not any(key.lower() == "content-type" for key in headers):
            headers["Content-Type"] = (candidate.request_content_type or
                                       "application/xml")
        try:
            response = self.http.request(
                "POST", candidate.endpoint_url, headers=headers,
                data=probe_body, timeout=self.timeout)
        except BudgetExceeded:
            raise
        except Exception as exc:
            return self._inconclusive(
                f"XML probe request failed: {type(exc).__name__}")

        key_builder = getattr(self.provider, "correlation_key", None)
        callback_key = (key_builder(callback) if callable(key_builder)
                        else (urlsplit(callback).hostname or ""))
        cfg_oast = getattr(self.cfg, "oast", None)
        interactions = self.provider.poll(
            timeout=getattr(cfg_oast, "poll_timeout", 15),
            interval=getattr(cfg_oast, "poll_interval", 2))
        matched = matching_interactions(interactions, callback_key)
        if not matched:
            return self._inconclusive(
                "no nonce-correlated external-entity callback received",
                {"callback_host": parsed.hostname,
                 "response_status": getattr(response, "status_code", None),
                 "request_count": 1})

        protocols = sorted({str(item.get("proto") or item.get("type") or
                                 "unknown") for item in matched})
        return ValidationOutcome(
            status=ValidationStatus.CONFIRMED.value,
            confidence=Confidence.CONFIRMED.value,
            evidence={"callback_host": parsed.hostname,
                      "interaction_protocols": protocols,
                      "response_status": getattr(response, "status_code",
                                                  None),
                      "request_count": 1},
            notes=("an external entity in the observed XML request caused "
                   "a nonce-correlated OAST interaction; no local file was "
                   "requested"))

    @staticmethod
    def _inconclusive(note: str,
                      evidence: Dict[str, Any] | None = None
                      ) -> ValidationOutcome:
        return ValidationOutcome(
            status=ValidationStatus.INCONCLUSIVE.value,
            confidence=Confidence.UNKNOWN.value,
            evidence=evidence or {}, notes=note)
