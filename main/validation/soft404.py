"""Soft-404 detection: cluster nonexistent-path responses.

Many apps answer unknown routes with HTTP 200 plus a shared template
(login wall, SPA shell, bot page). Without a not-found baseline,
every bogus recon URL looks like a live endpoint and floods the
inventory. This module establishes the baseline by requesting a few
random nonexistent paths and clustering the answers:

- all samples share status + normalized body + title → baseline
- anything else (varied statuses, dynamic bodies, errors) → None,
  meaning no template could be established and nothing is filtered

A missing baseline never filters: only a proven template matches.
"""
import re
import secrets
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit

from ..budgets import BudgetExceeded
from ..logging_setup import get_logger

log = get_logger("soft404")

SAMPLES = 4
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


@dataclass
class Soft404Baseline:
    base_url: str
    status: int = 0
    body_hash: str = ""
    key_shape: str = ""
    length_bucket: int = 0
    title: str = ""
    samples: int = 0
    probe_urls: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"base_url": self.base_url, "status": self.status,
                "body_hash": self.body_hash, "key_shape": self.key_shape,
                "length_bucket": self.length_bucket, "title": self.title,
                "samples": self.samples}


def _title_of(text: str) -> str:
    try:
        match = _TITLE_RE.search(text or "")
    except (TypeError, ValueError):
        return ""
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip().lower()[:200]


def _random_paths(base_url: str, count: int) -> List[str]:
    try:
        parts = urlsplit(base_url)
        prefix = urlunsplit((parts.scheme, parts.netloc, "", "", ""))
    except (TypeError, ValueError):
        return []
    return [f"{prefix}/apex-no-such-{secrets.token_hex(4)}"
            for _ in range(max(0, count))]


def detect_soft404(client, base_url: str, timeout: int = 10,
                   samples: int = SAMPLES) -> Optional[Soft404Baseline]:
    """Establish the not-found baseline, or None when unclusterable."""
    from ..validation.differential import normalize_response
    urls = _random_paths(base_url, samples)
    if not urls:
        return None
    sigs = []
    for url in urls:
        try:
            r = client.get(url, timeout=timeout)
        except BudgetExceeded:
            raise
        except Exception as e:
            log.debug("soft-404 probe failed %s: %s", url, e)
            return None
        try:
            norm = normalize_response(r)
        except Exception:
            return None
        sigs.append((norm["status"], norm["body_hash"],
                     norm["key_shape"], norm["length_bucket"],
                     _title_of(getattr(r, "text", ""))))
    first = sigs[0]
    if not all(s == first for s in sigs):
        log.info("soft-404: no consistent not-found template "
                 "(%d samples differ) — nothing filtered", len(sigs))
        return None
    status, body_hash, key_shape, bucket, title = first
    log.info("soft-404: baseline HTTP %s (%d/%d identical)",
             status, len(sigs), len(urls))
    return Soft404Baseline(base_url=base_url, status=status,
                           body_hash=body_hash, key_shape=key_shape,
                           length_bucket=bucket, title=title,
                           samples=len(sigs), probe_urls=urls)


def matches(baseline: Optional[Soft404Baseline], response) -> bool:
    """True when a fetched response IS the not-found template."""
    if baseline is None:
        return False
    try:
        from ..validation.differential import normalize_response
        norm = normalize_response(response)
    except Exception:
        return False
    if norm["status"] != baseline.status:
        return False
    if baseline.key_shape:
        if norm["key_shape"] != baseline.key_shape:
            return False
    elif norm["body_hash"] != baseline.body_hash:
        return False
    return _title_of(getattr(response, "text", "")) == baseline.title
