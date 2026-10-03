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
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, op in methods.items():
            m = method.upper()
            if m not in ("GET", "POST", "PUT", "PATCH", "DELETE",
                         "OPTIONS", "HEAD"):
                continue
            params = []
            if isinstance(op, dict):
                for p in op.get("parameters", []) or []:
                    if isinstance(p, dict) and p.get("name"):
                        params.append({
                            "name": p["name"],
                            "in": p.get("location") or p.get("in", "query"),
                            "required": bool(p.get("required", False)),
                        })
                # OpenAPI 3 requestBody
                rb = op.get("requestBody")
                if isinstance(rb, dict):
                    for ct, content in (rb.get("content") or {}).items():
                        schema = (content or {}).get("schema", {})
                        if isinstance(schema, dict):
                            for pname in (schema.get("properties") or {}):
                                params.append({
                                    "name": pname, "in": "body",
                                    "required": False,
                                })
            out["endpoints"].append({
                "path": path, "method": m, "base": base,
                "parameters": params,
                "summary": (op.get("summary", "")
                            if isinstance(op, dict) else ""),
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
