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
import json
import os
import shutil
import signal
import subprocess
import tempfile
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
    """Provider adapter for official Interactsh, custom REST, or a lab.

    Public and ordinary self-hosted sessions use ``interactsh-client``.
    Explicit ``api_base`` selects the legacy custom-REST compatibility path;
    ``callback_url`` selects the static local-lab collector.
    """

    def __init__(self, server: str = "oast.pro", api_base: Optional[str] = None,
                 timeout: int = 15, callback_url: str = ""):
        self.server = (server or "oast.pro").strip().rstrip(".")
        self.timeout = timeout
        self._custom_api_base = bool(api_base)
        self.callback_url = (callback_url or "").strip().rstrip("/")
        if api_base:
            self.api_base = api_base.rstrip("/")
        elif self.server in DEFAULT_SERVERS:
            self.api_base = f"https://api.{self.server}"
        else:
            self.api_base = f"https://{self.server}"
        self.uuid: Optional[str] = None
        self.token: Optional[str] = None
        self._closed = False
        self._client_process: Optional[subprocess.Popen] = None
        self._client_tmp: Optional[tempfile.TemporaryDirectory] = None
        self._client_log = None
        self._interaction_file = None

    # ── lifecycle ──────────────────────────────────────────────────────
    def register(self) -> bool:
        if self.callback_url:
            # The lab collector has no registration protocol: a random path
            # is the correlation token and GET /_log returns its hit list.
            import uuid
            self.token = uuid.uuid4().hex
            self.uuid = self.token
            log.info("using static OAST callback collector %s",
                     self.callback_url)
            return True
        if not self._custom_api_base:
            return self._register_client()
        return self._register_rest()

    def _register_rest(self) -> bool:
        """Compatibility path for custom REST endpoints.

        The public Interactsh protocol is handled by the official client.
        Keep explicit ``api_base`` support for self-hosted deployments whose
        REST endpoint differs from the endpoint inferred by interactsh-client.
        """
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

    def _register_client(self) -> bool:
        """Start ProjectDiscovery's client and consume its machine outputs."""
        binary = shutil.which("interactsh-client")
        if not binary:
            log.warning("interactsh-client not installed; public OAST is "
                        "unavailable (install with apex-fuzzer --update)")
            return False

        servers = [self.server]
        if self.server in DEFAULT_SERVERS:
            alternate = "oast.live" if self.server == "oast.pro" else "oast.pro"
            if alternate not in servers:
                servers.append(alternate)
        for server in servers:
            if self._start_client(binary, server):
                return True
            self._stop_client()
        return False

    def _start_client(self, binary: str, server: str) -> bool:
        temp = tempfile.TemporaryDirectory(prefix="apex-interactsh-")
        root = temp.name
        config_file = os.path.join(root, "config.yaml")
        payload_file = os.path.join(root, "payloads.txt")
        interaction_file = os.path.join(root, "interactions.jsonl")
        log_file = os.path.join(root, "client.log")
        with open(config_file, "w", encoding="utf-8") as f:
            f.write("{}\n")
        log_handle = open(log_file, "w", encoding="utf-8")
        command = [
            binary, "-s", server, "-n", "1", "-ps", "-psf", payload_file,
            "-json", "-o", interaction_file, "-pi", "1", "-duc",
            "-auth=false", "-config", config_file,
        ]
        try:
            proc = subprocess.Popen(
                command, stdin=subprocess.DEVNULL, stdout=log_handle,
                stderr=subprocess.STDOUT, close_fds=True)
        except OSError as exc:
            log_handle.close()
            temp.cleanup()
            log.warning("could not start interactsh-client: %s", exc)
            return False

        self._client_tmp = temp
        self._client_log = log_handle
        self._client_process = proc
        self._interaction_file = interaction_file
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            if os.path.isfile(payload_file):
                try:
                    with open(payload_file, encoding="utf-8") as f:
                        lines = f.read().splitlines()
                except OSError:
                    lines = []
                for line in lines:
                    host = (urlsplit("//" + line.strip()).hostname or "")
                    labels = host.split(".")
                    if len(labels) >= 2 and all(labels):
                        self.token = labels[0]
                        self.server = ".".join(labels[1:])
                        self.uuid = self.token
                        log.info("interactsh-client registered on %s",
                                 self.server)
                        return True
            if proc.poll() is not None:
                break
            time.sleep(0.1)

        detail = ""
        try:
            log_handle.flush()
            with open(log_file, encoding="utf-8") as f:
                detail = f.read()[-500:].strip()
        except OSError:
            pass
        log.warning("interactsh-client registration failed on %s%s",
                    server, f": {detail}" if detail else "")
        return False

    def _read_client_interactions(self) -> List[Dict]:
        if not self._interaction_file:
            return []
        try:
            with open(self._interaction_file, encoding="utf-8") as f:
                interactions = []
                for line in f:
                    try:
                        item = json.loads(line)
                    except (TypeError, ValueError):
                        continue
                    if isinstance(item, dict):
                        interactions.append(item)
                return interactions
        except OSError:
            return []

    def _stop_client(self) -> None:
        proc, self._client_process = self._client_process, None
        if proc is not None and proc.poll() is None:
            try:
                proc.send_signal(signal.SIGINT)
                proc.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    proc.kill()
                    proc.wait(timeout=2)
                except (OSError, subprocess.TimeoutExpired):
                    pass
        self._interaction_file = None
        if self._client_log is not None:
            try:
                self._client_log.close()
            except OSError:
                pass
            self._client_log = None
        if self._client_tmp is not None:
            self._client_tmp.cleanup()
            self._client_tmp = None

    def available(self) -> bool:
        process_ok = (self._client_process is None or
                      self._client_process.poll() is None)
        return bool(self.token) and not self._closed and process_ok

    def create_token(self) -> str:
        """Unique callback hostname for this scan."""
        if self.callback_url:
            return f"{self.callback_url}/{self.token}"
        return f"{self.token}.{self.server}"

    def correlation_key(self, callback: str) -> str:
        """Return the per-request value to match in OAST interactions.

        Interactsh places a nonce after the registered correlation ID in the
        first DNS label. Static collectors carry their nonce in the final URL
        path segment. Matching only the scan ID would let delayed callbacks
        from one parameter be attributed to a later parameter.
        """
        if self.callback_url:
            path = urlsplit(callback).path.rstrip("/")
            nonce = path.rsplit("/", 1)[-1]
            return nonce or self.token or ""
        hostname = urlsplit(callback).hostname or ""
        # The first label is the registered ID plus this probe's nonce.
        return hostname.split(".", 1)[0]

    def poll(self, timeout: Optional[int] = None,
             interval: Optional[int] = None) -> List[Dict]:
        """Poll for interactions until ``timeout`` seconds elapse."""
        if self._client_process is not None:
            timeout = self.timeout if timeout is None else timeout
            interval = 1 if interval is None else max(1, interval)
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                interactions = self._read_client_interactions()
                if interactions:
                    return interactions
                if self._client_process.poll() is not None:
                    return []
                time.sleep(min(interval, max(0.0,
                                             deadline - time.monotonic())))
            return self._read_client_interactions()
        import requests
        timeout = timeout or self.timeout
        interval = interval or 2
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                url = (f"{self.callback_url}/_log" if self.callback_url
                       else f"{self.api_base}/data/{self.uuid}")
                r = requests.get(url, timeout=self.timeout)
                data = r.json()
            except Exception:
                time.sleep(interval)
                continue
            interactions = (data if isinstance(data, list) else
                            (data.get("data") or data.get("hits") or [])
                            if isinstance(data, dict) else [])
            if self.callback_url:
                interactions = matching_interactions(
                    interactions, self.token or "")
            if interactions:
                return interactions
            time.sleep(interval)
        return []

    def correlate(self, interactions: List[Dict], token: Optional[str] = None
                  ) -> bool:
        """True if any interaction reached our callback hostname."""
        return bool(matching_interactions(
            interactions, token or self.correlation_key(
                self.create_token())))

    def close(self):
        if self._closed:
            return
        self._closed = True
        if self._client_process is not None:
            self._stop_client()
            return
        if not self.uuid or self.callback_url:
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
    # parser-bypass variant kind that earned the callback ("" = direct);
    # whether the target response reflects the callback token, a
    # possible full-read signal that never upgrades a finding alone.
    bypass_kind: str = ""
    response_reflects_token: bool = False


def _fire_probe_request(http, endpoint, param, payload: str,
                        timeout: int = 10):
    """Send one SSRF probe; return (response, request_url).

    Raises BudgetExceeded (shared budgets) or ValueError for
    unsupported shapes; other transport errors propagate to the caller.
    """
    method = (getattr(endpoint, "method", "GET") or "GET").upper()
    if method not in {"GET", "POST", "PUT", "PATCH"}:
        raise ValueError(f"unsupported method {method}")
    if param.location == "body" and method not in {"POST", "PUT", "PATCH"}:
        raise ValueError("body probe needs a mutating method")
    request_url = endpoint.url
    # observed base headers (including auth contexts) ride along;
    # only the probed input is replaced
    headers = {name: value for name, value in
               (getattr(endpoint, "headers", None) or {}).items()
               if isinstance(name, str) and isinstance(value, str)}
    request_kwargs = {"timeout": timeout}
    if param.location == "body":
        params = list(getattr(endpoint, "body_parameters", []) or [])
        values = _with_body_param(params, param.name, payload)
        content_types = list(getattr(
            endpoint, "request_content_types", []) or [])
        content_type = (getattr(endpoint, "content_type", "") or "").lower()
        is_json = ("json" in content_type or any(
            "json" in str(value).lower() for value in content_types))
        if is_json:
            request_kwargs["json"] = _nested_json(values)
        else:
            request_kwargs["data"] = values
    elif param.location == "header":
        headers[param.name] = payload
    else:
        request_url = _with_param(endpoint.url, param.name, payload)
    if headers:
        request_kwargs["headers"] = headers
    request_fn = getattr(http, "request", None)
    if callable(request_fn):
        response = request_fn(method, request_url, **request_kwargs)
    else:
        response = getattr(http, method.lower())(request_url,
                                                 **request_kwargs)
    return response, request_url


def _response_reflects_token(response, markers) -> bool:
    """True when the target response echoes a callback marker."""
    try:
        body = getattr(response, "content", b"") or \
            getattr(response, "text", "") or ""
    except Exception:
        return False
    if isinstance(body, (bytes, bytearray)):
        try:
            body = bytes(body).decode("utf-8", "replace")
        except (UnicodeDecodeError, ValueError):
            return False
    if not isinstance(body, str):
        return False
    return any(marker and marker in body for marker in markers)


def _confirmed_result(endpoint, param, payload: str, callback_host: str,
                      response, method: str, request_url: str,
                      location: str, matched, bypass_kind: str = "",
                      callback_key: str = "") -> OastResult:
    notes = f"out-of-band callback on parameter '{param.name}'"
    if bypass_kind:
        notes += f" via parser-bypass variant ({bypass_kind})"
    reflects = _response_reflects_token(
        response, [payload, callback_host, callback_key])
    if reflects:
        notes += ("; target response reflects the callback token "
                  "(possible full-read: confirm manually)")
    log.info("OAST HIT: param=%s on %s (%d interactions)%s",
             param.name, endpoint.url, len(matched),
             f" [{bypass_kind}]" if bypass_kind else "")
    return OastResult(
        confirmed=True, url=endpoint.url, parameter=param.name,
        payload=payload, callback_host=callback_host,
        response_status=getattr(response, "status_code", None),
        response_length=len(getattr(response, "content", b"")
                            or getattr(response, "text", "")
                            or ""),
        response_time_ms=_response_time_ms(response),
        request_method=method, request_url=request_url,
        parameter_location=location,
        interactions=matched[:20],
        notes=notes, bypass_kind=bypass_kind,
        response_reflects_token=reflects)


def _probe_bypass_variants(http, endpoint, tried_params, provider,
                           poll_timeout: int, poll_interval: int
                           ) -> Optional[OastResult]:
    """Fire parser-bypass callback variants for params that missed.

    Variants run only for schemes that answered the direct probe: firing
    at a scheme the target never speaks wastes requests and muddies
    attribution.
    """
    from .ssrf_bypass import bypass_variants
    from .second_order import make_ssrf_canary
    try:
        decoy = urlsplit(endpoint.url).hostname or ""
    except (TypeError, ValueError):
        decoy = ""
    for p, schemes_ok in tried_params or []:
        for scheme in ("http", "https"):
            if scheme not in (schemes_ok or {"http", "https"}):
                continue
            try:
                direct = make_ssrf_canary(provider.create_token(), scheme)
            except (ValueError, TypeError) as exc:
                log.debug("bypass canary failed (%s): %s", p.name, exc)
                continue
            variants = bypass_variants(direct, decoy)
            if not variants:
                continue
            pending = []
            for kind, variant in variants:
                callback_host = urlsplit(variant).hostname or ""
                key_builder = getattr(provider, "correlation_key", None)
                callback_key = (key_builder(variant)
                                if callable(key_builder)
                                else callback_host)
                try:
                    response, request_url = _fire_probe_request(
                        http, endpoint, p, variant, timeout=10)
                    method = (getattr(endpoint, "method", "GET") or
                              "GET").upper()
                    pending.append((variant, callback_host, callback_key,
                                    response, method, request_url,
                                    p.location, kind))
                except BudgetExceeded:
                    raise
                except Exception as exc:
                    log.debug("bypass fire failed (%s/%s): %s",
                              p.name, kind, exc)
                    continue
            if not pending:
                continue
            interactions = provider.poll(timeout=poll_timeout,
                                         interval=poll_interval)
            for (variant, callback_host, callback_key, response, method,
                 request_url, location, kind) in pending:
                matched = matching_interactions(interactions, callback_key)
                if matched:
                    return _confirmed_result(
                        endpoint, p, variant, callback_host, response,
                        method, request_url, location, matched,
                        bypass_kind=kind, callback_key=callback_key)
    return None


def probe_endpoint(http, endpoint, provider: InteractshProvider,
                   poll_timeout: int = 15, poll_interval: int = 2,
                   max_params: int = 3,
                   scope_ok=None) -> Optional[OastResult]:
    """Fire SSRF candidates at one endpoint and correlate callbacks.

    Each parameter gets independent HTTP and HTTPS callback hosts so stale
    interactions from another parameter cannot confirm this probe. Requests
    follow the endpoint's documented method and JSON/form content type.
    When direct callbacks fail, bounded parser-bypass variants of each
    callback URL are tried with fresh per-variant nonces.
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
    tried_params = []
    for p in cands:
        pending = []
        for scheme in ("http", "https"):
            from .second_order import make_ssrf_canary
            payload = make_ssrf_canary(provider.create_token(), scheme)
            callback_host = urlsplit(payload).hostname or ""
            key_builder = getattr(provider, "correlation_key", None)
            callback_key = (key_builder(payload) if callable(key_builder)
                            else callback_host)
            try:
                response, request_url = _fire_probe_request(
                    http, endpoint, p, payload, timeout=10)
                method = (getattr(endpoint, "method", "GET") or
                          "GET").upper()
                fired += 1
                last_response = response
                last_request = (method, request_url, p.location, payload)
                pending.append((payload, callback_host, callback_key,
                                response, method, request_url, p.location))
            except BudgetExceeded:
                raise
            except Exception as e:
                log.debug("oast fire failed (%s): %s", p.name, e)
                continue
        if not pending:
            continue
        schemes_ok = {urlsplit(entry[0]).scheme for entry in pending}
        tried_params.append((p, schemes_ok))
        interactions = provider.poll(timeout=poll_timeout,
                                     interval=poll_interval)
        for (payload, callback_host, callback_key, response, method,
             request_url, location) in pending:
            matched = matching_interactions(interactions, callback_key)
            if matched:
                log.info("OAST HIT: param=%s on %s (%d interactions)",
                         p.name, endpoint.url, len(matched))
                return _confirmed_result(
                    endpoint, p, payload, callback_host, response, method,
                    request_url, location, matched,
                    callback_key=callback_key)
    # bypass stage: direct callbacks failed everywhere; try bounded
    # parser-bypass variants with fresh per-variant nonces
    bypass_hit = _probe_bypass_variants(
        http, endpoint, tried_params, provider, poll_timeout,
        poll_interval)
    if bypass_hit is not None:
        return bypass_hit
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
