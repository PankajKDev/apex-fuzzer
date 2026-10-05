"""Robots.txt + sitemap.xml discovery (spec §6)."""
from __future__ import annotations
import re
from urllib.parse import urljoin
from typing import List, Dict
from ..logging_setup import get_logger

log = get_logger("robots")

_DISALLOW_RE = re.compile(r"^\s*(Disallow|Allow):\s*(\S+)", re.M)
_SITEMAP_RE = re.compile(r"^\s*Sitemap:\s*(\S+)", re.M)
_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)


def fetch_robots(client, base_url: str, timeout: int = 10) -> Dict:
    """Return {paths: [...], sitemaps: [...]}."""
    out = {"paths": [], "sitemaps": []}
    try:
        r = client.get(urljoin(base_url, "/robots.txt"), timeout=timeout)
        if r.status_code != 200:
            return out
        text = r.text[:200_000]
    except Exception as e:
        log.debug("robots fetch failed: %s", e)
        return out

    for m in _DISALLOW_RE.finditer(text):
        p = m.group(2)
        if p and p != "/" and "*" not in p and "$" not in p:
            out["paths"].append(p)
    for m in _SITEMAP_RE.finditer(text):
        out["sitemaps"].append(m.group(1))
    return out


def fetch_sitemap(client, sitemap_url: str,
                  timeout: int = 10) -> List[str]:
    """Return URLs from a sitemap (or sitemap index, one level deep)."""
    urls: List[str] = []
    try:
        r = client.get(sitemap_url, timeout=timeout)
        if r.status_code != 200:
            return urls
        text = r.text[:2_000_000]
    except Exception as e:
        log.debug("sitemap fetch failed: %s", e)
        return urls

    locs = _LOC_RE.findall(text)
    # sitemap index → follow one level
    if all(u.endswith(".xml") for u in locs[:3]) and locs:
        for sub in locs[:10]:
            urls.extend(fetch_sitemap(client, sub, timeout))
        return urls
    return locs
