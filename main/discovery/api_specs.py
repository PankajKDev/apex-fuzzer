"""OpenAPI / Swagger spec discovery (spec §6, §11)."""
from __future__ import annotations
import json
from urllib.parse import urljoin
from typing import List, Dict, Optional
from ..logging_setup import get_logger

log = get_logger("api_specs")

# Common locations for specs, in priority order
SPEC_PATHS = [
    "/openapi.json", "/openapi.yaml", "/openapi.yml",
    "/swagger.json", "/swagger.yaml", "/swagger.yml",
    "/api-docs", "/api-docs.json",
    "/v2/api-docs", "/v3/api-docs",
    "/.well-known/openapi.json",
]


def _try_parse_json(text: str) -> Optional[dict]:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _parse_spec(data: dict) -> Dict:
    """Extract endpoints + parameters from an OpenAPI/Swagger doc."""
    out = {"endpoints": [], "title": "", "version": ""}
    if not isinstance(data, dict):
        return out

    info = data.get("info", {}) or {}
    out["title"] = info.get("title", "")
    out["version"] = info.get("version", "")

    base = ""
    if "servers" in data and data["servers"]:
        base = data["servers"][0].get("url", "") or ""
    elif "basePath" in data:
        base = data.get("basePath", "") or ""

    paths = data.get("paths", {}) or {}

    def resolve(obj, seen=None):
        if not isinstance(obj, dict) or "$ref" not in obj:
            return obj
        ref = obj.get("$ref", "")
        if not ref.startswith("#/") or ref in (seen or set()):
            return {}
        target = data
        for part in ref[2:].split("/"):
            target = target.get(part.replace("~1", "/").replace("~0", "~"), {}) \
                if isinstance(target, dict) else {}
        return resolve(target, (seen or set()) | {ref})

    def schema_fields(schema, prefix="", depth=0):
        schema = resolve(schema)
        if not isinstance(schema, dict) or depth > 5:
            return []
        fields = []
        required = set(schema.get("required", []) or [])
        for name, raw_prop in (schema.get("properties") or {}).items():
            prop = resolve(raw_prop)
            field_name = f"{prefix}.{name}" if prefix else name
            fields.append((field_name, name in required))
            if isinstance(prop, dict) and isinstance(prop.get("properties"), dict):
                fields.extend(schema_fields(prop, field_name, depth + 1))
            items = prop.get("items") if isinstance(prop, dict) else None
            if isinstance(items, dict) and isinstance(items.get("properties"), dict):
                fields.extend(schema_fields(items, f"{field_name}[]", depth + 1))
        return fields

    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        common_params = methods.get("parameters", []) or []
        for method, op in methods.items():
            m = method.upper()
            if m not in ("GET", "POST", "PUT", "PATCH", "DELETE",
                         "OPTIONS", "HEAD"):
                continue
            params = []
            content_types = []
            if isinstance(op, dict):
                for p in [*common_params, *(op.get("parameters", []) or [])]:
                    p = resolve(p)
                    if isinstance(p, dict) and p.get("name"):
                        location = p.get("location") or p.get("in", "query")
                        if location == "formData":
                            location = "body"
                        if location == "body" and isinstance(p.get("schema"), dict):
                            for pname, required in schema_fields(p["schema"]):
                                params.append({"name": pname, "in": "body",
                                               "required": required})
                            continue
                        params.append({
                            "name": p["name"],
                            "in": location,
                            "required": bool(p.get("required", False)),
                        })
                # OpenAPI 3 requestBody
                rb = op.get("requestBody")
                if isinstance(rb, dict):
                    rb = resolve(rb)
                    for ct, content in (rb.get("content") or {}).items():
                        content_types.append(ct)
                        schema = resolve((content or {}).get("schema", {}))
                        for pname, required in schema_fields(schema):
                            params.append({"name": pname, "in": "body",
                                           "required": required})
                if not content_types:
                    content_types = (op.get("consumes") or
                                     data.get("consumes") or [])
            out["endpoints"].append({
                "path": path, "method": m, "base": base,
                "parameters": params,
                "operation_id": (op.get("operationId", "")
                                 if isinstance(op, dict) else ""),
                "summary": (op.get("summary", "")
                            if isinstance(op, dict) else ""),
                "description": (op.get("description", "")
                                if isinstance(op, dict) else ""),
                "tags": (op.get("tags", []) or []
                         if isinstance(op, dict) else []),
                "request_content_types": content_types,
            })
    return out


def discover(client, base_url: str,
             timeout: int = 10) -> List[Dict]:
    """Probe common spec locations; return list of parsed specs."""
    found = []
    for path in SPEC_PATHS:
        url = urljoin(base_url, path)
        try:
            r = client.get(url, timeout=timeout,
                           headers={"Accept": "application/json"})
        except Exception:
            continue
        if r.status_code != 200:
            continue
        ct = r.headers.get("content-type", "").lower()
        if "json" not in ct and not r.text.lstrip().startswith("{"):
            continue
        data = _try_parse_json(r.text[:3_000_000])
        if not data:
            continue
        parsed = _parse_spec(data)
        if parsed["endpoints"]:
            parsed["url"] = url
            found.append(parsed)
            log.info("api spec found: %s (%d endpoints)",
                     url, len(parsed["endpoints"]))
    return found
