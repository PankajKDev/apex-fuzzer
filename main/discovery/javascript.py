"""First-party JS analysis + source maps + secret detection.

Upgrades (spec §6):
- ``chunk_js`` splits bundles on structural boundaries (module exports,
  function boundaries, then fixed-size with overlap) instead of raw
  slices, so downstream AI analysis sees complete statements.
- source maps are actually fetched and parsed: ``sourcesContent`` holds
  the original unminified source, which reveals internal API paths,
  parameter names, and occasionally hardcoded credentials that never
  survived minification.
- bundle contents are fed to technology fingerprinting (React/Vue/
  Angular/Svelte/Next, auth SDKs, cloud SDKs).
"""
import re
import json
from pathlib import Path
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Set, Tuple
from ..logging_setup import get_logger
from . import technologies as tech_mod
from . import parameters as param_mod

log = get_logger("js")

_SOURCE_MAP_RE = re.compile(r"//#\s*sourceMappingURL=([^\s]+)")

_ENDPOINT_PATTERNS = [
    (re.compile(r"""['"`](/api/[A-Za-z0-9_\-/{}.:]+)['"`]"""), "high"),
    (re.compile(r"""['"`](/v\d+/[A-Za-z0-9_\-/{}.:]+)['"`]"""), "high"),
    (re.compile(r"""['"`](/graphql[A-Za-z0-9_\-/]*)['"`]"""), "high"),
    (re.compile(r"""fetch\(\s*['"`]([^'"`]+)['"`]"""), "medium"),
    (re.compile(r"""axios\.(get|post|put|delete|patch)\(\s*['"`]([^'"`]+)['"`]"""),
     "medium"),
    (re.compile(r"""\.open\(\s*['"][A-Z]+['"]\s*,\s*['"`]([^'"`]+)['"`]"""),
     "medium"),
]

_SECRET_PATTERNS = [
    ("aws_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("slack_token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("jwt", re.compile(
        r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("private_key", re.compile(
        r"-----BEGIN (RSA|EC|OPENSSH|DSA) PRIVATE KEY-----")),
    ("generic_api_key", re.compile(
        r"(?i)\b(api[_-]?key|apikey|secret[_-]?key)\b\s*[:=]\s*"
        r"['\"]([A-Za-z0-9_\-]{16,})['\"]")),
]


def chunk_js(js_text: str, max_chunk: int = 12000,
             overlap: int = 400) -> List[str]:
    """Split JS into semantically meaningful chunks, not arbitrary slices.

    1. module boundaries (export / module.exports / define / import)
    2. top-level function boundaries
    3. fixed-size chunks with overlap, only as a last resort
    """
    if not js_text:
        return []
    if len(js_text) <= max_chunk:
        return [js_text]

    # collect boundary offsets
    boundaries: Set[int] = set()
    for m in re.finditer(r"(?:^|\n)\s*(?:export\s|module\.exports|"
                         r"define\s*\(|import\s*\()", js_text):
        boundaries.add(m.start())
    for m in re.finditer(r"(?:^|\n)\s*(?:function\s+[A-Za-z_$][\w$]*|"
                         r"(?:^|\n|;)\s*(?:async\s+)?function\s*\()",
                         js_text):
        boundaries.add(m.start())

    chunks: List[str] = []
    start = 0
    for b in sorted(boundaries):
        if b <= start:
            continue
        if b - start >= max_chunk:
            # too far — split the span on function boundaries or size
            chunk = js_text[start:b]
            if len(chunk) > max_chunk:
                chunks.extend(_fixed_chunks(chunk, max_chunk, overlap))
            else:
                chunks.append(chunk)
            start = b
    tail = js_text[start:]
    if tail:
        if len(tail) > max_chunk:
            chunks.extend(_fixed_chunks(tail, max_chunk, overlap))
        else:
            chunks.append(tail)
    return [c for c in chunks if c.strip()]


def _fixed_chunks(text: str, max_chunk: int, overlap: int) -> List[str]:
    out = []
    step = max(1, max_chunk - overlap)
    i = 0
    while i < len(text):
        out.append(text[i:i + max_chunk])
        i += step
    return out


def parse_source_map(data: Dict) -> Dict:
    """Deep-parse a source map for endpoints / params / secrets.

    ``sourcesContent`` (when present) contains the original unminified
    source; ``sources`` reveals internal module paths.
    """
    result: Dict = {"endpoints": [], "params": [], "secrets": []}
    seen_ep: Set[str] = set()
    seen_sec: Set[str] = set()

    content = ""
    for c in data.get("sourcesContent") or []:
        if isinstance(c, str):
            content += c + "\n"
    if not content:
        content = "\n".join(s for s in data.get("sources") or []
                            if isinstance(s, str))

    if content:
        for pat, conf in _ENDPOINT_PATTERNS:
            for m in pat.finditer(content):
                raw = m.group(m.lastindex) if m.lastindex else m.group(0)
                if not isinstance(raw, str) or not raw.startswith("/"):
                    continue
                # strip query/fragment — params are extracted separately
                raw = raw.split("?", 1)[0].split("#", 1)[0]
                if not raw or raw in seen_ep:
                    continue
                seen_ep.add(raw)
                result["endpoints"].append(
                    {"path": raw, "confidence": conf, "source": "sourcemap"})
        for name, pat in _SECRET_PATTERNS:
            for m in pat.finditer(content):
                key = (name, m.group(0)[:16])
                if key in seen_sec:
                    continue
                seen_sec.add(key)
                result["secrets"].append(
                    {"type": name,
                     "snippet": m.group(0)[:8] + "*" * 12,
                     "source": "sourcemap"})
        result["params"] = sorted({p.name for p in
                                   param_mod.from_js(content[:500_000])})

    # internal module paths (e.g. src/api/users.ts → /api/users)
    for src in data.get("sources") or []:
        if not isinstance(src, str):
            continue
        m = re.search(r"((?:/[A-Za-z0-9_\-]+){2,})", src)
        if m and m.group(1) not in seen_ep:
            seen_ep.add(m.group(1))
            result["endpoints"].append(
                {"path": m.group(1), "confidence": "possible",
                 "source": "sourcemap:path"})
    return result


class JSAnalyzer:
    def __init__(self, cfg, http_client, cache_dir: Path):
        self.cfg = cfg
        self.http = http_client
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def fetch(self, url: str) -> Tuple[str, Dict]:
        key = re.sub(r"[^A-Za-z0-9_.-]", "_", url)[:180]
        cached = self.cache_dir / key
        meta_file = cached.with_suffix(cached.suffix + ".meta")
        if cached.exists() and meta_file.exists():
            return cached.read_text(errors="ignore"), json.loads(
                meta_file.read_text())
        try:
            r = self.http.get(url, timeout=self.cfg.scan.http_timeout)
            text = r.text[:self.cfg.discovery.js_max_bytes_per_file]
            meta = {"url": url, "status": r.status_code,
                    "content_type": r.headers.get("content-type", ""),
                    "content_length": len(text)}
            cached.write_text(text, errors="ignore")
            meta_file.write_text(json.dumps(meta, indent=2))
            return text, meta
        except Exception as e:
            log.warning("failed to fetch %s: %s", url, e)
            return "", {}

    def analyze(self, url: str) -> Dict:
        js, meta = self.fetch(url)
        if not js:
            return {"url": url, "endpoints": [], "params": [],
                    "secrets": [], "source_maps": [], "techs": [],
                    "meta": meta, "raw_length": 0}
        endpoints, seen = [], set()
        for pat, conf in _ENDPOINT_PATTERNS:
            for m in pat.finditer(js):
                raw = m.group(m.lastindex) if m.lastindex else m.group(0)
                if not isinstance(raw, str) or not raw.startswith("/"):
                    continue
                raw = raw.split("?", 1)[0].split("#", 1)[0]
                if not raw or raw in seen:
                    continue
                seen.add(raw)
                endpoints.append({"path": raw, "confidence": conf,
                                  "source": url})
        secrets = []
        seen_sec = set()
        for name, pat in _SECRET_PATTERNS:
            for m in pat.finditer(js):
                key = (name, m.group(0)[:16])
                if key in seen_sec:
                    continue
                seen_sec.add(key)
                secrets.append({"type": name,
                                "snippet": m.group(0)[:8] + "*" * 12,
                                "source": url})
        sm = _SOURCE_MAP_RE.findall(js)
        source_maps = []
        if self.cfg.discovery.source_maps:
            for s in sm:
                sm_url = urljoin(url, s)
                detail = self._analyze_source_map(sm_url)
                source_maps.append(detail)
        techs = [t.to_dict() for t in tech_mod.detect_js_bundle(js)]
        params = sorted({p.name for p in param_mod.from_js(js[:500_000])})
        return {"url": url, "endpoints": endpoints, "params": params,
                "secrets": secrets, "source_maps": source_maps,
                "techs": techs, "meta": meta, "raw_length": len(js)}

    def _analyze_source_map(self, sm_url: str) -> Dict:
        text, meta = self.fetch(sm_url)
        detail = {"url": sm_url, "sources": [], "sources_count": 0,
                  "details": {}, "meta": meta}
        if not text:
            return detail
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            detail["error"] = "invalid_json"
            return detail
        detail["sources"] = (data.get("sources") or [])[:200]
        detail["sources_count"] = len(data.get("sources") or [])
        detail["details"] = parse_source_map(data)
        return detail

    def fetch_source_map(self, sm_url: str) -> Dict:
        if not self.cfg.discovery.source_maps:
            return {}
        return self._analyze_source_map(sm_url)


def is_first_party(js_url: str, host: str) -> bool:
    try:
        return urlparse(js_url).hostname == host
    except Exception:
        return False
