"""Web-cache deception checks under a unique-key, read-only contract.

Hunter methodology for cache deception: a personalized response stored
under a shared cache key is later served to someone else. The safe way
to test this without touching shared state is unique cache keys: every
probe carries a one-time query token, so only the probe's own entries
are created and read back. No shared cache entry is ever written.

Safety contract (bounded, fail-closed):
- GET only, same URL plus a unique `apexcb<hex>` query token per
  endpoint; shared cache keys are never requested.
- three requests per endpoint: anonymous baseline, victim fetch, then
  anonymous re-read of the same unique key.
- a finding needs all of: victim and anonymous baselines differ
  (content is actually personalized), the re-read carries a cache HIT
  signal, and the re-read body equals the victim body (not the
  anonymous baseline).
- completed comparisons that fail any leg are genuine negatives;
  errors, missing markers, and ambiguous signals are inconclusive.
"""
import re
import secrets
from dataclasses import dataclass
from typing import Dict, Optional
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

from ..budgets import BudgetExceeded
from ..logging_setup import get_logger

log = get_logger("cache_probe")

BUSTER_PREFIX = "apexcb"

_HIT_HEADERS = ("age", "x-cache", "cf-cache-status", "x-cache-status",
                "x-served-by", "x-proxy-cache", "x-varnish-cache",
                "akamai-cache-status", "x-edge-cache", "cache-status",
                "cdn-cache", "x-cdn-cache", "x-fastly-cache-status")
_HIT_VALUES = ("hit", "tcp_hit", "tcp_mem_hit")


@dataclass
class CacheResult:
    endpoint_url: str
    cache_key_url: str
    identity: str
    verdict: str = "inconclusive"
    notes: str = ""
    hit_detail: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {"endpoint_url": self.endpoint_url,
                "cache_key_url": self.cache_key_url,
                "identity": self.identity, "verdict": self.verdict,
                "notes": self.notes, "hit_detail": self.hit_detail}


def cache_hit_detail(headers) -> str:
    """Describe cache HIT evidence, or "" when absent."""
    from collections.abc import Mapping
    if not isinstance(headers, Mapping):
        return ""
    lowered = {str(k).lower(): str(v) for k, v in headers.items()}
    age = lowered.get("age", "").strip()
    if age.isdigit() and int(age) > 0:
        return f"Age: {age}"
    for name in _HIT_HEADERS[1:]:
        value = lowered.get(name, "").strip().lower()
        if not value:
            continue
        tokens = [tok.strip() for tok in re.split(r"[,;]", value)]
        if any(tok in _HIT_VALUES or tok.startswith("hit ")
               for tok in tokens):
            return f"{name}: {lowered.get(name, '').strip()[:60]}"
    return ""


def _unique_url(url: str) -> Optional[str]:
    try:
        parts = urlsplit(url)
    except (TypeError, ValueError):
        return None
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        return None
    query = parse_qsl(parts.query, keep_blank_values=True)
    query = [(k, v) for k, v in query if k != BUSTER_PREFIX]
    query.append((BUSTER_PREFIX, secrets.token_hex(6)))
    return urlunsplit((parts.scheme, parts.netloc, parts.path,
                       urlencode(query, doseq=True), ""))


def _body_signature(response) -> Optional[str]:
    try:
        from .differential import normalize_response
        norm = normalize_response(response)
    except Exception:
        return None
    return f"{norm.get('status')}:{norm.get('key_shape')}:{norm.get('body_hash')}"


def probe_deception(http, endpoint_url: str, victim_headers: Dict[str, str],
                    identity_name: str, timeout: int = 10) -> CacheResult:
    """Run the anonymous-baseline / victim / anonymous-reread triple."""
    key_url = _unique_url(endpoint_url)
    res = CacheResult(endpoint_url=endpoint_url,
                      cache_key_url=key_url or endpoint_url,
                      identity=identity_name)
    if key_url is None:
        res.notes = "endpoint URL is unrepresentable"
        return res
    try:
        anon_first = http.get(key_url, timeout=timeout)
        revalidate = dict(victim_headers or {})
        revalidate.setdefault("Cache-Control", "no-cache")
        revalidate.setdefault("Pragma", "no-cache")
        victim = http.get(key_url, headers=revalidate, timeout=timeout)
        anon_again = http.get(key_url, timeout=timeout)
    except BudgetExceeded:
        raise
    except Exception as exc:
        log.debug("cache probe failed for %s: %s", endpoint_url, exc)
        res.notes = "probe requests failed without responses"
        return res
    if any(getattr(r, "status_code", 0) != 200
           for r in (anon_first, victim, anon_again)):
        res.notes = (" baselines unreadable ("
                     f"anon={getattr(anon_first, 'status_code', '?')}, "
                     f"victim={getattr(victim, 'status_code', '?')}, "
                     f"reread={getattr(anon_again, 'status_code', '?')})")
        return res
    base_sig = _body_signature(anon_first)
    victim_sig = _body_signature(victim)
    reread_sig = _body_signature(anon_again)
    if base_sig is None or victim_sig is None or reread_sig is None:
        res.notes = "responses could not be normalized safely"
        return res
    if victim_sig == base_sig:
        res.verdict = "tested_negative"
        res.notes = ("content is identical anonymous and authenticated: "
                     "nothing personalized to deceive with")
        return res
    hit = cache_hit_detail(getattr(anon_again, "headers", None))
    if reread_sig == victim_sig and hit:
        res.verdict = "confirmed"
        res.hit_detail = hit
        res.notes = (f"anonymous re-read of the unique key served the "
                     f"victim's personalized body from cache ({hit})")
        return res
    if reread_sig == base_sig:
        res.verdict = "tested_negative"
        res.notes = "cache keyed correctly: anonymous re-read matches " \
            "the anonymous baseline, not the victim body"
        return res
    res.notes = ("ambiguous cache behavior: re-read matches neither "
                 "baseline cleanly")
    return res
