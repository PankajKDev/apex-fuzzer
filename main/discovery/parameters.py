"""Parameter extraction from URLs / HTML / JS."""
import re
from typing import Iterable, List
from ..models import Parameter, Confidence
from .url_normalizer import extract_query_params

_INPUT_RE = re.compile(
    r"<(input|select|textarea)\b[^>]*?\bname\s*=\s*['\"]([^'\"]+)['\"]",
    re.IGNORECASE)
_FORM_ACTION_RE = re.compile(
    r"<form\b[^>]*?\baction\s*=\s*['\"]([^'\"]*)['\"]", re.IGNORECASE)
_HIDDEN_RE = re.compile(
    r"<input\b[^>]*?\btype\s*=\s*['\"]hidden['\"][^>]*?\bname\s*=\s*['\"]"
    r"([^'\"]+)['\"]", re.IGNORECASE)
_JS_PARAM_PATTERNS = [
    re.compile(r"[?&]([a-zA-Z_][\w]*)\s*="),
    re.compile(r"\.(?:set|append|get)\(\s*['\"]([a-zA-Z_][\w]*)['\"]"),
    re.compile(r"params?\s*[:=]\s*\{[^}]*?([a-zA-Z_][\w]*)\s*:"),
    re.compile(r"query\s*[:=]\s*\{[^}]*?([a-zA-Z_][\w]*)\s*:"),
]


def from_url(url: str) -> List[Parameter]:
    out, seen = [], set()
    for name, val in extract_query_params(url):
        if name in seen:
            continue
        seen.add(name)
        out.append(Parameter(name=name, location="query", source=["url"],
                             sample_value=val,
                             confidence=Confidence.CONFIRMED.value))
    return out


def from_html(html: str) -> List[Parameter]:
    out, seen = [], set()
    for m in _INPUT_RE.finditer(html):
        name = m.group(2)
        if not name or name in seen:
            continue
        seen.add(name)
        out.append(Parameter(name=name, location="body", source=["html"],
                             confidence=Confidence.CONFIRMED.value))
    for m in _HIDDEN_RE.finditer(html):
        name = m.group(1)
        if name in seen:
            continue
        seen.add(name)
        out.append(Parameter(name=name, location="body",
                             source=["html:hidden"],
                             confidence=Confidence.CONFIRMED.value))
    return out


def from_js(js: str) -> List[Parameter]:
    out, seen = [], set()
    for pat in _JS_PARAM_PATTERNS:
        for m in pat.finditer(js):
            name = m.group(1)
            if not name or name in seen or len(name) < 2:
                continue
            seen.add(name)
            out.append(Parameter(name=name, location="query",
                                 source=["javascript"],
                                 confidence=Confidence.POSSIBLE.value))
    return out


def form_actions(html: str) -> List[str]:
    return [m.group(1) for m in _FORM_ACTION_RE.finditer(html)
            if m.group(1)]


def merge(existing: Iterable[Parameter],
          new: Iterable[Parameter]) -> List[Parameter]:
    by_key = {(p.name, p.location): p for p in existing}
    for p in new:
        key = (p.name, p.location)
        if key in by_key:
            cur = by_key[key]
            for s in p.source:
                if s not in cur.source:
                    cur.source.append(s)
        else:
            by_key[key] = p
    return list(by_key.values())
