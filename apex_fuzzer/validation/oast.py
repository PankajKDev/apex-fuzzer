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

_STRONG_SSRF_TOKENS = {
    "url", "uri", "callback", "webhook", "fetch", "remote", "endpoint",
    "imageurl", "avatarurl", "sourceurl", "targeturl", "feedurl",
    "previewurl", "downloadurl", "redirecturl", "proxyurl", "hookurl",
    "rssurl", "importurl", "asseturl", "documenturl", "returnurl",
}
_CONTEXT_SSRF_TOKENS = {
    "src", "href", "link", "source", "dest", "destination", "host",
    "domain", "site", "feed", "rss", "image", "avatar", "logo", "img",
    "file", "path", "proxy", "target", "open", "load", "download",
    "import", "upload", "page", "redirect", "return", "next", "continue",
}
_FETCH_CONTEXT = {
    "fetch", "preview", "thumbnail", "image", "avatar", "webhook", "hook",
    "callback", "proxy", "import", "export", "download", "document",
    "pdf", "feed", "rss", "asset", "remote", "url", "sync", "scrape",
}


def _normalized_name(name: str) -> List[str]:
    """Split camelCase and path-like schema names into useful tokens."""
    import re
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name or "")
    return [part.lower() for part in re.split(r"[^A-Za-z0-9]+", value)
            if part]


def ssrf_candidate_score(param, endpoint=None):
    """Score URL-like inputs using field semantics and API operation context.

    Ambiguous names (for example `path`, `file`, or `host`) only qualify when
    the documented route/operation describes a fetch-like action.
    """
    name = getattr(param, "name", "") or ""
    tokens = _normalized_name(name)
    joined = "".join(tokens)
    strong = joined in _STRONG_SSRF_TOKENS or any(
        token in _STRONG_SSRF_TOKENS for token in tokens)
    context = " ".join(str(getattr(endpoint, field, "") or "")
                       for field in ("path", "summary", "description",
                                     "operation_id", "endpoint_type"))
    context += " " + " ".join(getattr(endpoint, "tags", []) or [])
    context_tokens = set(_normalized_name(context))
    fetch_context = bool(context_tokens & _FETCH_CONTEXT)
    contextual = bool(set(tokens) & _CONTEXT_SSRF_TOKENS)
    if strong:
        priority = 4 if {"url", "uri"} & set(tokens) else 3
        return priority, "URL-bearing parameter name"
    if contextual and fetch_context:
        return 2, "ambiguous parameter supported by fetch-like operation"
    return 0, "field and operation do not establish a server-fetch sink"

def ssrf_candidates(params, endpoint=None) -> List[Any]:
    """Select SSRF inputs, using endpoint context when supplied.

    Context-free calls preserve the old name list for compatibility.
    Endpoint-aware calls require semantic evidence from the field name and
    operation metadata, so ambiguous names do not qualify on their own.
    """
    if endpoint is not None:
        return [p for p in params
                if getattr(p, "name", "") and
                ssrf_candidate_score(p, endpoint)[0] > 0]
    return [p for p in params if getattr(p, "name", "") and
            p.name.lower() in SSRF_PARAM_NAMES]


def _with_param(url: str, name: str, value: str) -> str:
    parts = urlsplit(url)
    q = [(key, val) for key, val in
         parse_qsl(parts.query, keep_blank_values=True) if key != name]
    q.append((name, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path,
                       urlencode(q, doseq=True), ""))


def _with_body_param(params: List[Any], name: str, value: str) -> Dict[str, str]:
    out = {p.name: (p.sample_value or "test") for p in params}
    out[name] = value
    return out


def _nested_json(values: Dict[str, str]) -> Dict:
    """Convert dotted and bracketed OpenAPI property names to JSON."""
    import re
    result: Dict = {}
    for name, value in values.items():
        parts = re.findall(r"[^.\[\]]+|\[\d*\]", name)
        current = result
        for index, raw in enumerate(parts):
            last = index == len(parts) - 1
            if raw.startswith("["):
                if not isinstance(current, list):
                    break
                number = raw[1:-1]
                slot = int(number) if number.isdigit() else 0
                while len(current) <= slot:
                    current.append({})
                if last:
                    current[slot] = value
                current = current[slot]
                continue
            if not isinstance(current, dict):
                break
            if last:
                current[raw] = value
                break
            wants_list = parts[index + 1].startswith("[")
            if not isinstance(current.get(raw), (dict, list)):
                current[raw] = [] if wants_list else {}
            current = current[raw]
    return result


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
        return bool(matching_interactions(
            interactions, token or self.create_token()))

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


def matching_interactions(interactions: List[Dict], token: str
                          ) -> List[Dict]:
    """Return only interactions containing a callback token/hostname."""
    if not interactions or not token:
        return []
    needle = token.lower()
    matched = []
    for it in interactions:
        if not isinstance(it, dict):
            continue
        haystack = " ".join(str(v) for v in it.values()
                            if isinstance(v, (str, int, float))).lower()
        if needle in haystack:
            matched.append(it)
    return matched


@dataclass
class OastResult:
    confirmed: bool
    url: str = ""
    parameter: Optional[str] = None
    payload: Optional[str] = None
    callback_host: Optional[str] = None
    response_status: Optional[int] = None
    response_length: Optional[int] = None
    response_time_ms: Optional[float] = None
    request_method: str = "GET"
    request_url: str = ""
    parameter_location: str = "query"
    interactions: List[Dict] = field(default_factory=list)
    notes: str = ""


def probe_endpoint(http, endpoint, provider: InteractshProvider,
                   poll_timeout: int = 15, poll_interval: int = 2,
                   max_params: int = 3,
                   scope_ok=None) -> Optional[OastResult]:
    """Fire SSRF candidates at one endpoint and correlate callbacks.

    Each parameter gets independent HTTP and HTTPS callback hosts so stale
    interactions from another parameter cannot confirm this probe. Requests
    follow the endpoint's documented method and JSON/form content type.
    """
    if not provider.available():
        return None
    params = (list(getattr(endpoint, "query_parameters", []) or []) +
              list(getattr(endpoint, "body_parameters", []) or []) +
              list(getattr(endpoint, "header_parameters", []) or []))
    cands = [p for p in params if ssrf_candidate_score(p, endpoint)[0] > 0
             or "validation" in (getattr(p, "source", []) or [])]
    cands = cands[:max_params]
    if not cands:
        return None

    fired = 0
    last_response = None
    last_request = ("GET", endpoint.url, "query", "")
    for p in cands:
        pending = []
        for scheme in ("http", "https"):
            from .second_order import make_ssrf_canary
            payload = make_ssrf_canary(provider.create_token(), scheme)
            callback_host = urlsplit(payload).hostname or ""
            try:
                method = (getattr(endpoint, "method", "GET") or
                          "GET").upper()
                if method not in {"GET", "POST", "PUT", "PATCH"}:
                    continue
                if p.location == "body" and method not in {
                        "POST", "PUT", "PATCH"}:
                    continue
                request_url = endpoint.url
                headers = {}
                request_kwargs = {"timeout": 10}
                if p.location == "body":
                    params = list(getattr(endpoint, "body_parameters", [])
                                  or [])
                    values = _with_body_param(params, p.name, payload)
                    content_types = list(getattr(
                        endpoint, "request_content_types", []) or [])
                    content_type = (getattr(endpoint, "content_type", "")
                                    or "").lower()
                    is_json = ("json" in content_type or any(
                        "json" in str(value).lower()
                        for value in content_types))
                    if is_json:
                        request_kwargs["json"] = _nested_json(values)
                    else:
                        request_kwargs["data"] = values
                elif p.location == "header":
                    headers[p.name] = payload
                else:
                    request_url = _with_param(endpoint.url, p.name, payload)
                if headers:
                    request_kwargs["headers"] = headers
                request_fn = getattr(http, "request", None)
                if callable(request_fn):
                    response = request_fn(method, request_url,
                                          **request_kwargs)
                else:
                    response = getattr(http, method.lower())(
                        request_url, **request_kwargs)
                fired += 1
                last_response = response
                last_request = (method, request_url, p.location, payload)
                pending.append((payload, callback_host, response, method,
                                request_url, p.location))
            except BudgetExceeded:
                raise
            except Exception as e:
                log.debug("oast fire failed (%s): %s", p.name, e)
                continue
        if not pending:
            continue
        interactions = provider.poll(timeout=poll_timeout,
                                     interval=poll_interval)
        for payload, callback_host, response, method, request_url, location \
                in pending:
            matched = matching_interactions(interactions, callback_host)
            if matched:
                log.info("OAST HIT: param=%s on %s (%d interactions)",
                         p.name, endpoint.url, len(matched))
                return OastResult(
                    confirmed=True, url=endpoint.url, parameter=p.name,
                    payload=payload, callback_host=callback_host,
                    response_status=getattr(response, "status_code", None),
                    response_length=len(getattr(response, "content", b"")
                                        or getattr(response, "text", "")
                                        or ""),
                    response_time_ms=_response_time_ms(response),
                    request_method=method, request_url=request_url,
                    parameter_location=location,
                    interactions=matched[:20],
                    notes=f"out-of-band callback on parameter '{p.name}'")
    if fired:
        method, request_url, location, payload = last_request
        status = getattr(last_response, "status_code", None)
        body = getattr(last_response, "content", b"") or \
            getattr(last_response, "text", "") or ""
        response_length = len(body)
        signals = []
        baseline_status = getattr(endpoint, "status_code", None)
        baseline_length = getattr(endpoint, "response_size", None)
        if baseline_status is not None and status != baseline_status:
            signals.append(f"status {baseline_status}->{status}")
        if baseline_length is not None and abs(response_length -
                                               baseline_length) >= max(
                                                   64, baseline_length // 4):
            signals.append(f"response length {baseline_length}->"
                           f"{response_length}")
        note = f"{fired} probes sent; no correlated callback"
        if signals:
            note += "; response differences: " + ", ".join(signals)
        return OastResult(confirmed=False, url=endpoint.url,
                          payload=payload,
                          response_status=status,
                          response_length=response_length,
                          response_time_ms=_response_time_ms(last_response),
                          request_method=method, request_url=request_url,
                          parameter_location=location, notes=note)
    return None


def _response_time_ms(response) -> Optional[float]:
    elapsed = getattr(response, "elapsed", None)
    seconds = getattr(elapsed, "total_seconds", None)
    return round(seconds() * 1000, 1) if callable(seconds) else None
