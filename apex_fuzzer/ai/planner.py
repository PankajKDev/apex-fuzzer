"""AI hypothesis planner — structured in/out, never declares vulns."""
import json
import os
import time
from typing import List, Dict, Tuple, Any
from ..models import Hypothesis
from ..logging_setup import get_logger

log = get_logger("ai")

# error classes for deterministic, non-crashing behavior (M3.1)
ERR_AUTH = "auth"
ERR_TIMEOUT = "timeout"
ERR_CONNECTION = "connection"
ERR_MALFORMED = "malformed"
ERR_RATE_LIMIT = "rate_limit"
ERR_SERVER = "server"
ERR_UNKNOWN = "unknown"

_RETRYABLE_STATUS = {429, 502, 503, 504}
_MAX_ATTEMPTS = 3
_LOG_BODY_LIMIT = 300

# These are the free-tier model IDs documented by the providers. Keep paid
# models out of both the default route and user-configurable overrides.
FREE_GEMINI_MODELS = {"gemini-3.5-flash-lite", "gemini-3.1-flash-lite"}
FREE_GROQ_MODELS = (
    "openai/gpt-oss-20b",
    "openai/gpt-oss-120b",
)


def _truncate(text: Any, limit: int = _LOG_BODY_LIMIT) -> str:
    text = str(text or "")
    return text if len(text) <= limit else text[:limit] + "…"


def classify_http_error(status: int | None = None,
                        exc: Exception | None = None) -> str:
    """Map transport/HTTP failures to a stable error class."""
    import requests as _rq
    if status is not None:
        if status in (401, 403):
            return ERR_AUTH
        if status == 404:
            return ERR_MALFORMED  # wrong URL/model name, not auth
        if status == 429:
            return ERR_RATE_LIMIT
        if status is not None and status >= 500:
            return ERR_SERVER
        return ERR_UNKNOWN
    if isinstance(exc, _rq.exceptions.Timeout):
        return ERR_TIMEOUT
    if isinstance(exc, _rq.exceptions.ConnectionError):
        return ERR_CONNECTION
    return ERR_UNKNOWN


class AIPlanner:
    def __init__(self, cfg):
        self.cfg = cfg
        self.key = os.environ.get("GEMINI_API_KEY")
        self.groq_key = os.environ.get("GROQ_API_KEY")
        self.provider = (getattr(cfg.ai, "provider", "gemini")
                         or "gemini").lower()
        # precedence: explicit ai.ollama.host block > OLLAMA_HOST
        # env > legacy ai.ollama_host > localhost default
        block_host = str((cfg.ai.ollama or {}).get("host") or "")
        host = block_host or os.environ.get("OLLAMA_HOST", "") or \
            getattr(cfg.ai, "ollama_host", "") or \
            "http://localhost:11434"
        self.ollama_host = str(host).rstrip("/")

    def available(self) -> bool:
        if not self.cfg.ai.enabled:
            return False
        if self.provider == "ollama":
            return self._ollama_ready()
        if self.provider == "gemini":
            # The Groq credential enables the automatic fallback even when
            # Gemini credentials are absent or Gemini is temporarily down.
            return bool(self.key or self.groq_key)
        if self.provider == "groq":
            return bool(self.groq_key)
        return False

    def validate_config(self) -> List[str]:
        """Startup validation: problems that disable the AI stage,
        each with precise remediation (M3.2). Empty = usable."""
        problems: List[str] = []
        if not self.cfg.ai.enabled:
            return ["ai.enabled is false"]
        if self.provider not in ("gemini", "groq", "ollama"):
            return [f"unknown ai.provider '{self.provider}' "
                    f"(want gemini|groq|ollama)"]
        if self.provider == "gemini" and not (self.key or self.groq_key):
            problems.append(
                "GEMINI_API_KEY and GROQ_API_KEY are empty — configure "
                "Gemini or Groq for hosted AI, or switch to "
                "ai.provider: ollama")
        if self.provider == "groq" and not self.groq_key:
            problems.append(
                "GROQ_API_KEY is empty — export it or use "
                "ai.provider: gemini with GEMINI_API_KEY")
        if self.provider in ("gemini", "groq"):
            gemini_model = self.cfg.ai.effective_gemini().get("model")
            groq_model = self.cfg.ai.effective_groq().get("model")
            if self.provider == "gemini" and gemini_model not in \
                    FREE_GEMINI_MODELS:
                problems.append(
                    f"Gemini model '{gemini_model}' is not in the "
                    "free-tier allowlist")
            if groq_model not in FREE_GROQ_MODELS:
                problems.append(
                    f"Groq model '{groq_model}' is not in the "
                    "free-tier allowlist")
        if self.provider == "ollama":
            ok, reason = self._ollama_status()
            if not ok:
                problems.append(reason)
        return problems

    def _ollama_status(self) -> Tuple[bool, str]:
        """(reachable-and-loaded, remediation message)."""
        import requests
        try:
            r = requests.get(f"{self.ollama_host}/api/tags", timeout=5)
            r.raise_for_status()
            models = [m.get("name", "") for m in
                      r.json().get("models", [])]
        except Exception as e:
            kind = classify_http_error(
                status=getattr(getattr(e, "response", None),
                               "status_code", None),
                exc=e)
            return False, (
                f"Ollama not reachable at {self.ollama_host} "
                f"({kind}: {_truncate(e, 120)}). Is `ollama serve` "
                f"running?")
        want = self.cfg.ai.effective_ollama().get("model",
                                                  "llama3.1")
        if not any(m == want or m.startswith(want + ":") for m in models):
            return False, (
                f"Ollama model '{want}' not loaded (have: "
                f"{', '.join(models) or 'none'}). Run: ollama pull "
                f"{want}")
        return True, ""

    def _ollama_ready(self) -> bool:
        """True when the server answers and the model is pulled."""
        ok, reason = self._ollama_status()
        if not ok:
            log.warning("%s", reason)
        return ok

    def _post_json(self, url: str, payload: dict,
                   timeout: int, headers: dict | None = None
                   ) -> Tuple[bool, dict, str]:
        """POST with raise_for_status, bounded logs, and retries for
        transient statuses only (429/502/503/504). Returns
        (ok, data, error_class). Never raises; never retries timeouts
        or connection failures (fail fast, especially for slow local
        inference and stateful-adjacent callers)."""
        import requests
        last_kind = ERR_UNKNOWN
        for attempt in range(1, _MAX_ATTEMPTS + 1):
            try:
                r = requests.post(url, json=payload, timeout=timeout,
                                  headers=headers)
                r.raise_for_status()
            except requests.exceptions.HTTPError as e:
                status = getattr(getattr(e, "response", None),
                                 "status_code", None)
                last_kind = classify_http_error(status=status)
                if status in _RETRYABLE_STATUS and \
                        attempt < _MAX_ATTEMPTS:
                    log.warning("AI HTTP %s (attempt %d/%d): backing "
                                "off", status, attempt, _MAX_ATTEMPTS)
                    time.sleep(attempt)
                    continue
                log.warning("AI HTTP error (%s): %s", last_kind,
                            _truncate(e))
                return False, {}, last_kind
            except Exception as e:
                last_kind = classify_http_error(exc=e)
                log.warning("AI call failed (%s): %s", last_kind,
                            _truncate(e))
                return False, {}, last_kind
            try:
                data = r.json()
            except Exception:
                log.warning("AI returned non-JSON output")
                return False, {}, ERR_MALFORMED
            if not isinstance(data, dict):
                log.warning("AI returned non-object JSON")
                return False, {}, ERR_MALFORMED
            return True, data, ""
        return False, {}, last_kind

    def _call(self, prompt: str, timeout: int = 30) -> str:
        if self.provider == "ollama":
            return self._call_ollama(prompt, timeout)
        if self.provider == "groq":
            return self._call_groq(prompt, timeout)
        if self.key:
            result = self._call_gemini(prompt, timeout)
            if result:
                return result
            log.info("Gemini unavailable or returned no content; trying "
                     "free-tier Groq fallback")
        elif self.groq_key:
            log.info("GEMINI_API_KEY is unset; using free-tier Groq fallback")
        else:
            return ""
        return self._call_groq(prompt, timeout)

    def _call_gemini(self, prompt: str, timeout: int = 30) -> str:
        eff = self.cfg.ai.effective_gemini()
        model = eff.get("model")
        if model not in FREE_GEMINI_MODELS:
            log.warning("Refusing non-free Gemini model '%s'", model)
            return ""
        if not self.key:
            return ""
        ok, data, kind = self._post_json(
            f"https://generativelanguage.googleapis.com/v1beta/"
            f"models/{model}:generateContent",
            {"contents": [{"parts": [{"text": prompt}]}],
             "generationConfig": {
                 "maxOutputTokens": eff.get("max_output_tokens", 8192),
                 "responseMimeType": "application/json"}},
            timeout=timeout,
            headers={"x-goog-api-key": self.key})
        if not ok:
            return ""
        if "error" in data:
            log.warning("AI error: %s",
                        _truncate((data["error"] or {}).get("message")
                                  if isinstance(data["error"], dict)
                                  else data["error"]))
            return ""
        cands = data.get("candidates") or []
        if not cands:
            return ""
        try:
            return cands[0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError, TypeError):
            log.warning("AI response missing candidates content")
            return ""

    def _call_groq(self, prompt: str, timeout: int = 30) -> str:
        """Free-tier Groq fallback using its OpenAI-compatible API."""
        if not self.groq_key:
            return ""
        eff = self.cfg.ai.effective_groq()
        preferred = eff.get("model", FREE_GROQ_MODELS[0])
        if preferred not in FREE_GROQ_MODELS:
            log.warning("Refusing non-free Groq model '%s'", preferred)
            return ""
        # If a free model is not enabled for this account, try the next
        # documented free model before giving up.
        models = (preferred,) + tuple(m for m in FREE_GROQ_MODELS
                                      if m != preferred)
        for model in models:
            ok, data, kind = self._post_json(
                "https://api.groq.com/openai/v1/chat/completions",
                {"model": model,
                 "messages": [{"role": "user", "content": prompt}],
                 "max_tokens": eff.get("max_output_tokens", 8192),
                 "response_format": {"type": "json_object"}},
                timeout=max(timeout, int(eff.get("timeout", 60) or 60)),
                headers={"Authorization": f"Bearer {self.groq_key}"})
            if ok:
                try:
                    text = data["choices"][0]["message"]["content"]
                except (KeyError, IndexError, TypeError):
                    log.warning("Groq response missing chat content")
                    return ""
                if text:
                    return text
                log.warning("Groq returned an empty response for '%s'",
                            model)
                return ""
            log.warning("Groq model '%s' unavailable (%s); trying next "
                        "free model", model, kind)
            if kind in (ERR_AUTH, ERR_CONNECTION, ERR_TIMEOUT,
                        ERR_UNKNOWN):
                break
        return ""

    def _call_ollama(self, prompt: str, timeout: int = 30) -> str:
        """Local inference via Ollama. `format: json` constrains the
        model to valid JSON, which feeds straight into _parse."""
        eff = self.cfg.ai.effective_ollama()
        timeout = max(timeout, int(eff.get("timeout", 180) or 180))
        model = eff.get("model", "llama3.1")
        ok, data, kind = self._post_json(
            f"{self.ollama_host}/api/generate",
            {"model": model, "prompt": prompt,
             "stream": False, "format": "json",
             "options": {"num_predict":
                         eff.get("max_output_tokens", 8192)}},
            timeout=timeout)
        if not ok:
            return ""
        if data.get("error"):
            log.warning("Ollama error: %s", _truncate(data["error"]))
            return ""
        text = data.get("response") or ""
        if not text:
            log.warning("Ollama returned an empty response "
                        "(model '%s' loaded?)", model)
        return text

    def generate_hypotheses(self, technologies: List[Dict],
                            endpoints: List[Dict],
                            findings: List[Dict]) -> List[Hypothesis]:
        if not self.available():
            return []
        context = {
            "technologies": technologies[:40],
            "endpoint_sample": self._chunk_endpoints(endpoints),
            # group by host + vuln class instead of a raw char slice, so
            # one chatty host can't eat the whole prompt budget
            "findings": self._chunk_findings(findings),
        }
        prompt = (
            "You are an authorized security assessment analyst.\n"
            "Given the structured context, produce JSON hypotheses.\n"
            "Rules:\n"
            " - Never declare a vulnerability as confirmed.\n"
            " - Classify every item as: observed | inferred | hypothesized.\n"
            " - test_class must be one of: sqli, xss, ssrf, ssti, "
            "path_traversal, open_redirect, idor, authz, xxe, cmdi, "
            "info_disclosure.\n"
            " - required_context must be: unauthenticated | user | admin.\n"
            "Respond with a JSON array of objects with keys: "
            "hypothesis, endpoint, reason, test_class, confidence (0-1), "
            "required_context, status.\n\n"
            f"CONTEXT:\n{self._bounded_json(context)}")
        return self._parse(self._call(prompt))

    def plan_js_chunk(self, js_url: str, chunk: str) -> List[Hypothesis]:
        """Feed one structurally-chunked JS slice to the planner (spec §6).

        Full SPAs ship 500KB–2MB bundles; chunking on structural
        boundaries (modules, functions) and sending each chunk
        separately keeps every route/param/secret in scope instead of
        silently truncating the bundle header.
        """
        if not self.available() or not chunk:
            return []
        prompt = (
            "You are an authorized security assessment analyst.\n"
            "Below is a chunk of a first-party JavaScript bundle from "
            f"{js_url}.\n"
            "Find: hidden API endpoints/paths, parameter names, "
            "authentication/authorization logic, secrets, and "
            "SSRF/redirect/file parameters.\n"
            "Rules:\n"
            " - Never declare a vulnerability as confirmed.\n"
            " - test_class must be one of: sqli, xss, ssrf, ssti, "
            "path_traversal, open_redirect, idor, authz, xxe, cmdi, "
            "info_disclosure.\n"
            " - endpoint may be a path (e.g. /api/users) or a URL.\n"
            "Respond with a JSON array of objects with keys: "
            "hypothesis, endpoint, reason, test_class, confidence (0-1), "
            "required_context, status.\n\n"
            f"JS CHUNK:\n{chunk[:12000]}")
        return self._parse(self._call(prompt, timeout=60))

    @staticmethod
    def _bounded_json(context: Dict, total: int = 14000) -> str:
        """JSON-dump context with per-part caps so no single part can
        truncate everything after it."""
        parts = []
        for key, cap in (("technologies", 2000),
                         ("endpoint_sample", 6000),
                         ("findings", 4000)):
            val = context.get(key) or []
            if not isinstance(val, list):
                val = [val]
            s = json.dumps(val)
            while len(s) > cap and len(val) > 1:
                val = val[:max(1, len(val) // 2)]
                s = json.dumps(val)
            parts.append(f"{key}: {s}")
        return "\n".join(parts)[:total]

    def _chunk_endpoints(self, endpoints: List[Dict]) -> List[Dict]:
        seen: set = set()
        out: List[Dict] = []
        for e in endpoints:
            key = (e.get("host"), e.get("endpoint_type"))
            if key in seen and len(out) > 200:
                continue
            seen.add(key)
            out.append({"host": e.get("host"), "path": e.get("path"),
                        "type": e.get("endpoint_type"),
                        "params": [p.get("name") for p in
                                   (e.get("query_parameters") or [])][:10]})
            if len(out) >= 400:
                break
        return out

    def _chunk_findings(self, findings: List[Dict]) -> List[Dict]:
        # group by host + vuln class; cap each group so one noisy
        # host/class can't dominate the prompt
        by_key: Dict[tuple, List] = {}
        for f in findings:
            from urllib.parse import urlparse
            host = (urlparse(f.get("matched_at", "")).hostname
                    or f.get("host", ""))
            cls = f.get("template_id", "other").split("-")[0]
            by_key.setdefault((host, cls), []).append(
                {"severity": f.get("severity"), "url": f.get("matched_at")})
        out: List[Dict] = []
        for (host, cls), items in by_key.items():
            for item in items[:10]:
                out.append({"host": host, "class": cls, **item})
            if len(out) >= 150:
                return out
        return out

    def _parse(self, raw: str) -> List[Hypothesis]:
        if not raw:
            return []
        raw = raw.strip()
        if raw.startswith("```"):
            raw = raw.strip("`")
            if raw.startswith("json"):
                raw = raw[4:]
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            log.warning("AI returned non-JSON; discarding")
            return []
        if isinstance(data, dict):
            data = data.get("hypotheses", [])
        out = []
        for item in data:
            if not isinstance(item, dict):
                continue
            out.append(Hypothesis(
                hypothesis=str(item.get("hypothesis", ""))[:500],
                endpoint=item.get("endpoint"),
                reason=str(item.get("reason", ""))[:500],
                test_class=str(item.get("test_class", "unknown")),
                confidence=float(item.get("confidence", 0.0) or 0.0),
                required_context=str(item.get("required_context",
                                              "unauthenticated")),
                status=str(item.get("status", "hypothesized"))))
        return out
