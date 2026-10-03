"""Out-of-band verification via Interactsh (spec §3).

Blind SSRF / RCE / XXE / SQLi cannot be confirmed in-band; they only
produce a DNS or HTTP callback to an oracle we control. This module
registers with Interactsh (public servers oast.pro / oast.live, or a
self-hosted instance), generates unique callback tokens, fires
candidates, and polls for interactions that correlate back to the
token.

Interactions are matched on DNS *and* HTTP (and SMTP): many blind sinks
resolve the hostname but never complete an HTTP request (DNS rebinding,
libraries that resolve before connecting).
"""
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode, urlsplit, urlunsplit, parse_qsl
from ..budgets import BudgetExceeded
from ..logging_setup import get_logger

log = get_logger("oast")

DEFAULT_SERVERS = ("oast.pro", "oast.live")

# parameter names that usually accept a URL / host the server will fetch
SSRF_PARAM_NAMES = {
    "url", "uri", "link", "src", "source", "dest", "destination",
    "redirect", "return", "return_to", "next", "continue", "callback",
    "webhook", "hook", "fetch", "load", "file", "path", "proxy",
    "open", "target", "host", "domain", "site", "feed", "rss",
    "import", "export", "download", "image", "avatar", "upload",
    "img", "img_url", "logo", "url_to", "href", "page",
}

# cloud metadata endpoints — only used when a cloud provider is detected
CLOUD_METADATA_PAYLOADS = {
    "Amazon S3": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "AWS ELB": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "CloudFront": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "GCS": "http://metadata.google.internal/computeMetadata/v1/?recursive=true",
    "Azure": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
}


def ssrf_candidates(params) -> List[Any]:
    """Filter a parameter list down to SSRF-like names."""
    return [p for p in params
            if getattr(p, "name", "") and
            p.name.lower() in SSRF_PARAM_NAMES]


def _with_param(url: str, name: str, value: str) -> str:
    parts = urlsplit(url)
    q = parse_qsl(parts.query, keep_blank_values=True)
    q.append((name, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path,
                       urlencode(q, doseq=True), ""))


def _with_body_param(params: List[Any], name: str, value: str) -> Dict[str, str]:
    out = {p.name: (p.sample_value or "test") for p in params}
    out[name] = value
    return out


class InteractshProvider:
    """Thin client over the Interactsh REST API.

    Public:   register on https://api.oast.pro, callbacks at {token}.oast.pro
    Self-host: set ``api_base`` (REST) — the callback host is then
    {token}.{server} where ``server`` is your interactsh callback domain.
    """

    def __init__(self, server: str = "oast.pro", api_base: Optional[str] = None,
                 timeout: int = 15):
        self.server = (server or "oast.pro").strip().rstrip(".")
        self.timeout = timeout
        if api_base:
            self.api_base = api_base.rstrip("/")
        elif self.server in DEFAULT_SERVERS:
            self.api_base = f"https://api.{self.server}"
        else:
            self.api_base = f"https://{self.server}"
        self.uuid: Optional[str] = None
        self.token: Optional[str] = None
        self._closed = False

    # ── lifecycle ──────────────────────────────────────────────────────
    def register(self) -> bool:
        import requests
        try:
            r = requests.post(f"{self.api_base}/register",
                              timeout=self.timeout)
            r.raise_for_status()
            data = r.json()
        except Exception as e:
            log.warning("interactsh register failed on %s: %s",
                        self.api_base, e)
            if self.server in DEFAULT_SERVERS:
                # fail over to the other public server
                alt = "oast.live" if self.server == "oast.pro" else "oast.pro"
                self.server = alt
                self.api_base = f"https://api.{alt}"
                try:
                    r = requests.post(f"{self.api_base}/register",
                                      timeout=self.timeout)
                    r.raise_for_status()
                    data = r.json()
                except Exception as e2:
                    log.warning("interactsh register failed on %s: %s",
                                alt, e2)
                    return False
            else:
                return False
        payload = data.get("data", data) if isinstance(data, dict) else {}
        self.uuid = payload.get("uuid") or data.get("uuid")
        self.token = payload.get("token") or data.get("token")
        if not self.uuid:
            log.warning("interactsh register returned no uuid")
            return False
        log.info("interactsh registered on %s (uuid=%s...)",
                 self.server, self.uuid[:8])
        return True

    def available(self) -> bool:
        return bool(self.token) and not self._closed

    def create_token(self) -> str:
        """Unique callback hostname for this scan."""
        return f"{self.token}.{self.server}"

    def poll(self, timeout: Optional[int] = None,
             interval: Optional[int] = None) -> List[Dict]:
        """Poll for interactions until ``timeout`` seconds elapse."""
        import requests
        timeout = timeout or self.timeout
        interval = interval or 2
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                r = requests.get(f"{self.api_base}/data/{self.uuid}",
                                 timeout=self.timeout)
                data = r.json()
            except Exception:
                time.sleep(interval)
                continue
            interactions = (data.get("data") if isinstance(data, dict)
                            else None) or []
            if interactions:
                return interactions
            time.sleep(interval)
        return []

    def correlate(self, interactions: List[Dict], token: Optional[str] = None
                  ) -> bool:
        """True if any interaction reached our callback hostname."""
        if not interactions:
            return False
        needle = token or self.create_token()
        for it in interactions:
            if not isinstance(it, dict):
                continue
            haystack = " ".join(str(v) for v in it.values()
                                if isinstance(v, (str, int, float)))
            if needle in haystack:
                return True
        return False

    def close(self):
        if self._closed:
            return
        self._closed = True
        if not self.uuid:
            return
        import requests
        try:
            requests.delete(f"{self.api_base}/deregister/{self.uuid}",
                            timeout=10)
        except Exception:
            pass


@dataclass
class OastResult:
    confirmed: bool
    url: str = ""
    parameter: Optional[str] = None
    payload: Optional[str] = None
    interactions: List[Dict] = field(default_factory=list)
    notes: str = ""


def probe_endpoint(http, endpoint, provider: InteractshProvider,
                   poll_timeout: int = 15, poll_interval: int = 2,
                   max_params: int = 3,
                   cloud_payloads: Optional[List[str]] = None,
                   scope_ok=None) -> Optional[OastResult]:
    """Fire SSRF candidates at one endpoint and correlate callbacks.

    ``http`` needs ``.get(url, **kw)`` and ``.post(url, **kw)``.
    ``endpoint`` needs ``.url`` plus ``query_parameters`` /
    ``body_parameters`` lists of Parameter objects.
    """
    if not provider.available():
        return None
    cands = ssrf_candidates(
        list(getattr(endpoint, "query_parameters", []) or []) +
        list(getattr(endpoint, "body_parameters", []) or []))[:max_params]
    if not cands:
        return None

    fired = 0
    for p in cands:
        for payload in [provider.create_token()] + (cloud_payloads or []):
            try:
                if p.location in ("body",):
                    http.post(endpoint.url,
                              data=_with_body_param(
                                  list(getattr(endpoint, "body_parameters", [])
                                       or []), p.name, payload),
                              timeout=10)
                else:
                    http.get(_with_param(endpoint.url, p.name, payload),
                             timeout=10)
                fired += 1
            except BudgetExceeded:
                raise
            except Exception as e:
                log.debug("oast fire failed (%s): %s", p.name, e)
                continue
            interactions = provider.poll(timeout=poll_timeout,
                                         interval=poll_interval)
            if provider.correlate(interactions):
                log.info("OAST HIT: param=%s on %s (%d interactions)",
                         p.name, endpoint.url, len(interactions))
                return OastResult(
                    confirmed=True, url=endpoint.url, parameter=p.name,
                    payload=payload, interactions=interactions[:20],
                    notes=f"out-of-band callback on parameter '{p.name}'")
    if fired:
        return OastResult(confirmed=False, url=endpoint.url,
                          notes=f"{fired} OAST probes fired, no callback")
    return None
