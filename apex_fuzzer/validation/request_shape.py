"""Build one narrowly targeted request from observed endpoint metadata."""
import json
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict
from urllib.parse import parse_qsl, urlencode
from xml.sax.saxutils import escape as xml_escape


MAX_BODY_FIELDS = 50


def is_json(candidate) -> bool:
    content_type = (getattr(candidate, "request_content_type", "") or "")
    return "json" in content_type.lower()


def is_xml(candidate) -> bool:
    """Return whether the observed request declares an XML media type."""
    content_type = (getattr(candidate, "request_content_type", "") or "")
    return "xml" in content_type.lower()


def is_multipart(candidate) -> bool:
    """Return whether the observed request declares a multipart body."""
    content_type = (getattr(candidate, "request_content_type", "") or "")
    return "multipart/" in content_type.lower()


_XML_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")
_XML_FORBIDDEN = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)\b", re.I)
_MAX_XML_BODY_BYTES = 1_000_000


def _xml_parameter(candidate, parameter: str):
    """Return (element, body) for one unambiguous simple XML text field.

    Only plain element names and leaf text nodes are supported. Namespace
    paths, attributes, DTD/entity-bearing documents, malformed documents,
    oversized bodies, and duplicate element names fail closed.
    """
    body = getattr(candidate, "request_body", None)
    if not isinstance(body, str) or not body:
        raise ValueError("XML request body was not retained")
    if len(body.encode("utf-8")) > _MAX_XML_BODY_BYTES:
        raise ValueError("XML request body exceeds the local parsing limit")
    if not _XML_NAME.fullmatch(parameter or ""):
        raise ValueError("XML candidate must be a simple observed element name")
    if _XML_FORBIDDEN.search(body):
        raise ValueError("XML DTD/entity declarations are unsupported")
    try:
        root = ET.fromstring(body)
    except (ET.ParseError, ValueError) as exc:
        raise ValueError("malformed XML request body") from exc
    matches = [element for element in root.iter()
               if element.tag == parameter]
    if len(matches) != 1:
        raise ValueError("XML candidate element must occur exactly once")
    element = matches[0]
    if list(element):
        raise ValueError("nested XML candidate elements are unsupported")
    if "<![CDATA[" in body:
        raise ValueError("CDATA XML request bodies are unsupported")
    return element, body


def xml_body_parameter_value(candidate, parameter: str) -> str:
    element, _ = _xml_parameter(candidate, parameter)
    return element.text or ""


def xml_body_with_parameter(candidate, parameter: str, value: str) -> str:
    element, body = _xml_parameter(candidate, parameter)
    # ElementTree validates the document and name uniqueness; replace only
    # the selected text span so prefixes, whitespace, declarations, attributes,
    # and all peer fields remain byte-for-byte intact.
    pattern = re.compile(
        rf"<(?P<name>{re.escape(parameter)})(?P<attrs>\s+[^<>]*?)?>"
        rf"(?P<text>.*?)</{re.escape(parameter)}\s*>", re.S)
    spans = list(pattern.finditer(body))
    if len(spans) != 1:
        raise ValueError("XML candidate text cannot be preserved safely")
    match = spans[0]
    if match.group("text").lstrip().startswith("<"):
        raise ValueError("XML candidate is not a plain text element")
    start, end = match.span("text")
    # Ensure the text span corresponds to the parsed leaf's value rather than
    # silently changing a comment or markup-wrapped value.
    raw_text = match.group("text")
    if raw_text.strip() != (element.text or "").strip():
        raise ValueError("XML candidate text uses unsupported markup")
    return body[:start] + xml_escape(str(value)) + body[end:]


def _body_template(candidate) -> Dict[str, Any]:
    body = getattr(candidate, "request_body", None)
    if isinstance(body, dict):
        return dict(body)
    if isinstance(body, str) and body.strip():
        if is_json(candidate):
            try:
                value = json.loads(body)
                if isinstance(value, dict):
                    return value
            except (ValueError, TypeError):
                pass
        else:
            pairs = parse_qsl(body, keep_blank_values=True)
            if pairs:
                return dict(pairs)

    values = {}
    for parameter in (getattr(candidate, "body_parameters", []) or
                      [])[:MAX_BODY_FIELDS]:
        name = getattr(parameter, "name", "")
        if name:
            sample = getattr(parameter, "sample_value", None)
            values[name] = "" if sample is None else sample
    return _nested_object(values) if is_json(candidate) else values


def _nested_object(values: Dict[str, Any]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for name, value in values.items():
        _assign_nested(result, name, value)
    return result


def _assign_nested(target: Dict[str, Any], name: str, value: Any) -> None:
    """Assign dotted OpenAPI field names into a JSON object."""
    import re
    parts = re.findall(r"[^.\[\]]+|\[\d*\]", name)
    current: Any = target
    for index, raw in enumerate(parts):
        last = index == len(parts) - 1
        if raw.startswith("["):
            if not isinstance(current, list):
                return
            slot = raw[1:-1]
            pos = int(slot) if slot.isdigit() else 0
            while len(current) <= pos:
                current.append({})
            if last:
                current[pos] = value
                return
            if not isinstance(current[pos], (dict, list)):
                current[pos] = [] if parts[index + 1].startswith("[") else {}
            current = current[pos]
            continue
        if not isinstance(current, dict):
            return
        if last:
            current[raw] = value
            return
        if not isinstance(current.get(raw), (dict, list)):
            current[raw] = [] if parts[index + 1].startswith("[") else {}
        current = current[raw]


def body_with_parameter(candidate, parameter: str, value: str):
    if is_multipart(candidate):
        from .multipart import (multipart_with_parameter, raw_body_bytes)
        body = getattr(candidate, "request_body", None)
        if body is None:
            raise ValueError("multipart replay requires the retained "
                             "request bytes; metadata alone cannot rebuild "
                             "boundaries or file content")
        return multipart_with_parameter(
            raw_body_bytes(body),
            getattr(candidate, "request_content_type", "") or "",
            parameter, value)
    if is_xml(candidate):
        return xml_body_with_parameter(candidate, parameter, value)
    body = _body_template(candidate)
    if is_json(candidate):
        _assign_nested(body, parameter, value)
    else:
        body[parameter] = value
    return body


def body_parameter_value(candidate, parameter: str) -> str:
    if is_multipart(candidate):
        from .multipart import (multipart_field_value, raw_body_bytes)
        body = getattr(candidate, "request_body", None)
        if body is None:
            raise ValueError("multipart replay requires the retained "
                             "request bytes")
        return multipart_field_value(
            raw_body_bytes(body),
            getattr(candidate, "request_content_type", "") or "",
            parameter)
    if is_xml(candidate):
        return xml_body_parameter_value(candidate, parameter)
    body = _body_template(candidate)
    if is_json(candidate):
        import re
        parts = re.findall(r"[^.\[\]]+|\[\d*\]", parameter)
        current: Any = body
        for raw in parts:
            if raw.startswith("["):
                if not isinstance(current, list):
                    return ""
                slot = raw[1:-1]
                pos = int(slot) if slot.isdigit() else 0
                if pos >= len(current):
                    return ""
                current = current[pos]
            else:
                if not isinstance(current, dict) or raw not in current:
                    return ""
                current = current[raw]
        return "" if current is None else str(current)
    value = body.get(parameter, "")
    return "" if value is None else str(value)


def encode_form(body: Dict[str, Any]) -> str:
    return urlencode(body, doseq=True)


def encode_json(body: Dict[str, Any]) -> str:
    return json.dumps(body, separators=(",", ":"), ensure_ascii=False)


# Headers/cookies that carry identity or framing: never mutated by
# probes. Testing these would break the tester's own session or the
# request shape instead of probing application logic.
_PROTECTED_HEADERS = frozenset({
    "authorization", "proxy-authorization", "proxy-authenticate",
    "host", "content-length", "content-type", "connection",
    "transfer-encoding", "cookie", "set-cookie",
})

# Cookie pairs that carry identity or request integrity: never mutated.
_PROTECTED_COOKIES = frozenset({
    "session", "sessionid", "sessid", "phpsessid", "jsessionid",
    "token", "jwt", "auth", "auth_token", "access_token", "refresh_token",
    "csrf", "csrf_token", "xsrf", "xsrf_token", "nonce", "signature",
})


def is_protected_parameter(location: str, name: str) -> bool:
    """True when a header/cookie target must not be probed."""
    if not name:
        return True
    lowered = str(name).strip().lower()
    if (location or "").lower() == "cookie":
        return lowered in _PROTECTED_COOKIES
    if (location or "").lower() == "header":
        return lowered in _PROTECTED_HEADERS
    return False


def header_parameter_value(candidate, parameter: str) -> str:
    """Current value of an observed request header ("" when absent)."""
    headers = getattr(candidate, "request_headers", None) or {}
    if not isinstance(headers, dict):
        raise ValueError("observed headers are unrepresentable")
    for name, value in headers.items():
        if isinstance(name, str) and name.strip().lower() == \
                parameter.strip().lower():
            if not isinstance(value, str):
                raise ValueError("observed header value is unrepresentable")
            if "\r" in value or "\n" in value:
                raise ValueError("observed header value is unrepresentable")
            return value
    return ""


def cookie_pairs(headers) -> list:
    """Parse Cookie header pairs, preserving order. Fail-closed."""
    if not isinstance(headers, dict):
        raise ValueError("observed headers are unrepresentable")
    raw = None
    for name, value in headers.items():
        if isinstance(name, str) and name.strip().lower() == "cookie":
            if not isinstance(value, str):
                raise ValueError("observed cookie value is unrepresentable")
            raw = value.strip()
            break
    if raw is None:
        raise ValueError("no observed Cookie header to replay")
    if '"' in raw:
        raise ValueError("quoted cookie values are unsupported")
    pairs = []
    for chunk in raw.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        name, sep, value = chunk.partition("=")
        if not sep or not name.strip():
            raise ValueError("observed cookie is malformed")
        pairs.append((name.strip(), value.strip()))
    if not pairs:
        raise ValueError("no observed cookie pairs to replay")
    return pairs


def cookie_with_parameter(headers, parameter: str, value: str) -> str:
    """Rebuild a Cookie header with one pair replaced (or appended)."""
    if "\r" in str(value) or "\n" in str(value) or ";" in str(value):
        raise ValueError("cookie replacement value is unsafe")
    pairs = cookie_pairs(headers)
    wanted = parameter.strip()
    found = False
    rebuilt = []
    for name, current in pairs:
        if name.lower() == wanted.lower():
            rebuilt.append((name, str(value)))
            found = True
        else:
            rebuilt.append((name, current))
    if not found:
        rebuilt.append((wanted, str(value)))
    return "; ".join(f"{name}={val}" for name, val in rebuilt)


def cookie_parameter_value(headers, parameter: str) -> str:
    """Current value of one observed cookie pair ("" when absent)."""
    wanted = parameter.strip().lower()
    for name, value in cookie_pairs(headers):
        if name.lower() == wanted:
            return value
    return ""
