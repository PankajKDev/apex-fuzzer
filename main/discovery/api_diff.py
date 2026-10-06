"""OpenAPI vs observed-behavior diffing (shadow surface inventory).

Pure offline comparison of spec-declared operations against the
crawled endpoint inventory. Three gap classes, all leads (never
verdicts — a gap is untested surface, not a vulnerability):
  - shadow-api: observed API surface with no spec operation;
  - spec-unseen: declared operations never observed in crawl;
  - spec-param-gap: parameter sets disagree on a matched operation
    (extra accepted params hint at mass assignment; untested
    declared params hint at missed inputs).

OpenAPI path templates (/users/{id}) match concrete paths. Only
relative-path comparison happens here — hosts are the scan target
by construction.
"""
import re
from typing import Any, Dict, List, Tuple
from urllib.parse import urlsplit

_MAX_LEADS = 20


def _template_regex(template: str) -> "re.Pattern[str]":
    """OpenAPI path template → full-match regex for concrete paths."""
    parts = re.split(r"(\{[^}]+\})", str(template or ""))
    out = []
    for part in parts:
        if part.startswith("{") and part.endswith("}"):
            out.append("[^/]+")
        else:
            out.append(re.escape(part))
    return re.compile("^" + "".join(out) + "/?$")


def _norm_path(url: str) -> str:
    try:
        return urlsplit(url or "").path or "/"
    except ValueError:
        return "/"


def _endpoint_params(endpoint: Any) -> List[str]:
    names = []
    for attr in ("query_parameters", "body_parameters",
                 "header_parameters"):
        for param in list(getattr(endpoint, attr, None) or []):
            name = getattr(param, "name", "") or ""
            if name and name not in names:
                names.append(name)
    return names


def diff_api(specs: List[Dict[str, Any]],
             endpoints: List[Any]) -> Dict[str, List[Dict[str, Any]]]:
    """Compare declared operations with observed API endpoints."""
    declared: List[Tuple[str, str, List[str]]] = []
    for spec in specs or []:
        for entry in (spec or {}).get("endpoints", []) or []:
            if not isinstance(entry, dict):
                continue
            method = str(entry.get("method", "GET") or "GET").upper()
            path = str(entry.get("path", "") or "")
            if not path:
                continue
            params = [str(p.get("name", ""))
                      for p in (entry.get("parameters") or [])
                      if isinstance(p, dict) and p.get("name")]
            declared.append((method, path,
                             sorted(set(params))))
    observed = []
    for endpoint in endpoints or []:
        if getattr(endpoint, "endpoint_type", "") not in (
                "api", "graphql", "unknown", "page"):
            continue
        method = str(getattr(endpoint, "method", "GET") or
                     "GET").upper()
        url = getattr(endpoint, "normalized_url", "") or \
            getattr(endpoint, "url", "")
        if not url:
            continue
        observed.append((method, _norm_path(url), url,
                         _endpoint_params(endpoint)))
    shadow, seen_declared = [], set()
    for method, path, url, params in observed:
        matched = None
        for index, (dmethod, dpath, dparams) in enumerate(declared):
            if dmethod != method:
                continue
            try:
                hit = _template_regex(dpath).match(path) is not None
            except re.error:
                hit = False
            if hit:
                matched = (index, dparams)
                seen_declared.add(index)
                break
        if matched is None:
            shadow.append({"method": method, "path": path, "url": url,
                           "params": params})
        else:
            _, dparams = matched
            extra = [p for p in params if p not in dparams]
            missing = [p for p in dparams if p not in params]
            if extra or missing:
                shadow.append({"method": method, "path": path,
                               "url": url, "params": params,
                               "declared_params": dparams,
                               "extra_params": extra,
                               "missing_params": missing,
                               "param_gap": True})
    unseen = [{"method": method, "path": path, "params": params}
              for index, (method, path, params) in enumerate(declared)
              if index not in seen_declared]
    gaps = [s for s in shadow if s.get("param_gap")]
    pure_shadow = [s for s in shadow if not s.get("param_gap")]
    return {"shadow": pure_shadow[:_MAX_LEADS],
            "unseen": unseen[:_MAX_LEADS],
            "param_gaps": gaps[:_MAX_LEADS]}
