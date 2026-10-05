"""Stored-SSRF trigger helpers: rank and materialize GET triggers.

Pure functions shared by the orchestrator's stored-SSRF probe (and its
tests). No network, no scope decisions — callers gate every URL the
helpers produce before requesting it.
"""
import json
import re
from typing import Dict, List
from urllib.parse import (parse_qsl, urlencode, urljoin, urlsplit,
                           urlunsplit)

from .request_shape import _assign_nested as assign_nested


def append_query_parameter(url: str, name: str, value: str) -> str:
    parts = urlsplit(url)
    query = parse_qsl(parts.query, keep_blank_values=True)
    query.append((name, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path,
                       urlencode(query, doseq=True), parts.fragment))


def nested_parameter_object(values: Dict[str, str]) -> Dict:
    """Convert OpenAPI dotted property names into a JSON object."""
    out: Dict = {}
    for name, value in values.items():
        assign_nested(out, name, value)
    return out


def rank_ssrf_triggers(sink, endpoints: List):
    """Rank safe GET routes that can plausibly process a stored sink value."""
    sink_path = (sink.path or "").lower().rstrip("/") or "/"
    sink_tokens = set(re.findall(r"[a-z0-9]+", sink_path))
    sink_context = " ".join([sink.summary, sink.description,
                             sink.operation_id, *sink.tags]).lower()
    sink_terms = set(re.findall(r"[a-z0-9]+", sink_context))
    trigger_terms = {"job", "task", "status", "result", "preview", "render",
                     "process", "worker", "history", "detail", "file", "image"}
    ranked = []
    for candidate in endpoints:
        if candidate.method.upper() != "GET" or candidate.endpoint_type == "static":
            continue
        path = (candidate.path or "").lower().rstrip("/") or "/"
        tokens = set(re.findall(r"[a-z0-9]+", path))
        context = " ".join([candidate.summary, candidate.description,
                            candidate.operation_id, *candidate.tags]).lower()
        context_tokens = set(re.findall(r"[a-z0-9]+", context))
        score = 0
        rationale = []
        if path == sink_path:
            score += 8
            rationale.append("same resource route")
        overlap = sink_tokens & tokens - {"api", "v1", "v2", "v3"}
        if overlap:
            score += min(5, len(overlap) * 2)
            rationale.append("shared resource path: " + ", ".join(sorted(overlap)))
        if context_tokens & trigger_terms:
            score += 3
            rationale.append("documented processing or result route")
        if tokens & trigger_terms:
            score += 2
            rationale.append("processing or result path segment")
        if sink_terms & context_tokens:
            score += 2
            rationale.append("shared OpenAPI operation context")
        if score >= 3:
            ranked.append((candidate, score, "; ".join(rationale)))
    return sorted(ranked, key=lambda item: (-item[1], item[0].url))


def materialize_trigger_urls(templates: List[str], response,
                             base_url: str):
    """Fill documented `{id}` trigger paths from a create response."""
    values = {}
    try:
        payload = json.loads(getattr(response, "text", "") or "")
        if isinstance(payload, dict):
            values.update({str(k).lower(): str(v) for k, v in payload.items()
                           if isinstance(v, (str, int))})
            for key in ("data", "result", "job", "task", "resource"):
                nested = payload.get(key)
                if isinstance(nested, dict):
                    values.update({str(k).lower(): str(v)
                                   for k, v in nested.items()
                                   if isinstance(v, (str, int))})
    except (TypeError, ValueError):
        pass
    location = ""
    for key, value in (getattr(response, "headers", {}) or {}).items():
        if str(key).lower() == "location":
            location = urljoin(base_url, str(value))
            break
    location_id = urlsplit(location).path.rstrip("/").split("/")[-1]
    if location_id and location_id.lower() not in {
            "", "status", "result", "preview", "history"}:
        values.setdefault("id", location_id)
        values.setdefault("jobid", location_id)
        values.setdefault("taskid", location_id)
    materialized = []
    for template in templates:
        unresolved = False

        def replace(match):
            nonlocal unresolved
            key = match.group(1).lower()
            value = values.get(key)
            if value is None and key.endswith("id"):
                value = values.get("id")
            if value is None:
                unresolved = True
                return match.group(0)
            return value

        url = re.sub(r"\{([^{}]+)\}", replace, template)
        if not unresolved:
            materialized.append(url)
    return materialized
