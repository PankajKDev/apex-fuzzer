"""Build one narrowly targeted request from observed endpoint metadata."""
import json
from typing import Any, Dict
from urllib.parse import parse_qsl, urlencode


MAX_BODY_FIELDS = 50


def is_json(candidate) -> bool:
    content_type = (getattr(candidate, "request_content_type", "") or "")
    return "json" in content_type.lower()


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


def body_with_parameter(candidate, parameter: str, value: str) -> Dict[str, Any]:
    body = _body_template(candidate)
    if is_json(candidate):
        _assign_nested(body, parameter, value)
    else:
        body[parameter] = value
    return body


def body_parameter_value(candidate, parameter: str) -> str:
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
