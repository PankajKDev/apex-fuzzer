"""Ollama (local) AI backend tests. HTTP is fully mocked."""
import json

from apex_fuzzer.ai.planner import AIPlanner
from apex_fuzzer.config import Config, apply_cli_overrides


def _cfg(provider="ollama", enabled=True):
    cfg = Config()
    cfg.ai.enabled = enabled
    cfg.ai.provider = provider
    return cfg


class _Resp:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests
            raise requests.exceptions.HTTPError(
                f"HTTP {self.status_code}",
                response=type("R", (), {"status_code": self.status_code})())

    def json(self):
        return self._payload


# ── availability ────────────────────────────────────────────────────
def test_gemini_needs_key(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    cfg = _cfg("gemini")
    assert AIPlanner(cfg).available() is False
    monkeypatch.setenv("GEMINI_API_KEY", "x")
    assert AIPlanner(Config()).available() is False  # disabled default


def test_ollama_ready_when_model_listed(monkeypatch):
    def fake_get(url, **kw):
        assert url == "http://localhost:11434/api/tags"
        return _Resp({"models": [{"name": "llama3.1:latest"}]})
    monkeypatch.setattr("requests.get", fake_get)
    assert AIPlanner(_cfg()).available() is True


def test_ollama_model_mismatch_means_unavailable(monkeypatch):
    def fake_get(url, **kw):
        return _Resp({"models": [{"name": "other:latest"}]})
    monkeypatch.setattr("requests.get", fake_get)
    assert AIPlanner(_cfg()).available() is False


def test_ollama_unreachable_means_unavailable(monkeypatch):
    def fake_get(url, **kw):
        raise ConnectionError("refused")
    monkeypatch.setattr("requests.get", fake_get)
    assert AIPlanner(_cfg()).available() is False


def test_ollama_disabled_means_unavailable():
    assert AIPlanner(_cfg(enabled=False)).available() is False


def test_ollama_host_env_override(monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "http://gpu-box:11434/")
    cfg = _cfg()
    cfg.ai.ollama_host = ""
    assert AIPlanner(cfg).ollama_host == "http://gpu-box:11434"


def test_provider_normalized():
    cfg = _cfg()
    cfg.ai.provider = "Ollama"
    assert AIPlanner(cfg).provider == "ollama"


# ── ollama _call ────────────────────────────────────────────────────
def _hyps():
    return [{"hypothesis": "SSRF via url param", "endpoint": "/export",
             "reason": "fetches remote", "test_class": "ssrf",
             "confidence": 0.8, "required_context": "unauthenticated",
             "status": "hypothesized"}]


def test_ollama_call_shape_and_parse(monkeypatch):
    seen = {}

    def fake_post(url, **kw):
        seen.update(kw.get("json") or {})
        assert url == "http://localhost:11434/api/generate"
        return _Resp({"response": json.dumps(_hyps())})
    monkeypatch.setattr("requests.post", fake_post)
    out = AIPlanner(_cfg())._call("hello", timeout=5)
    assert seen["format"] == "json"
    assert seen["stream"] is False
    assert seen["model"] == "llama3.1"
    assert seen["options"]["num_predict"] == 8192
    assert seen["prompt"] == "hello"
    hyps = AIPlanner(_cfg())._parse(out)
    assert len(hyps) == 1 and hyps[0].test_class == "ssrf"


def test_ollama_error_and_empty(monkeypatch):
    monkeypatch.setattr("requests.post",
                        lambda *a, **k: _Resp({"error": "boom"}))
    assert AIPlanner(_cfg())._call("x") == ""
    monkeypatch.setattr("requests.post",
                        lambda *a, **k: _Resp({"response": ""}))
    assert AIPlanner(_cfg())._call("x") == ""
    def _raise(*a, **k):
        raise TimeoutError("slow")
    monkeypatch.setattr("requests.post", _raise)
    assert AIPlanner(_cfg())._call("x") == ""


def test_gemini_call_shape(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "K")
    seen = {}

    def fake_post(url, **kw):
        seen["url"] = url
        return _Resp({"candidates": [{"content": {"parts": [
            {"text": json.dumps(_hyps())}]}}]})
    monkeypatch.setattr("requests.post", fake_post)
    cfg = _cfg("gemini")
    out = AIPlanner(cfg)._call("hi")
    assert "key=K" in seen["url"] and "gemini-1.5-flash" in seen["url"]
    assert AIPlanner(cfg)._parse(out)[0].endpoint == "/export"


# ── config / CLI ────────────────────────────────────────────────────
def test_ai_config_defaults():
    cfg = Config()
    assert cfg.ai.provider == "gemini"
    assert cfg.ai.ollama_host == "http://localhost:11434"
    assert cfg.ai.ollama_model == "llama3.1"
    assert cfg.ai.ollama_timeout == 180


def test_ai_config_yaml(tmp_path):
    f = tmp_path / "c.yaml"
    f.write_text("ai:\n  enabled: true\n  provider: ollama\n"
                 "  ollama_model: qwen2.5:14b\n")
    cfg = Config.load(f)
    assert cfg.ai.provider == "ollama"
    assert cfg.ai.ollama_model == "qwen2.5:14b"
    assert AIPlanner(cfg).provider == "ollama"


def test_cli_ai_provider_flag():
    from apex_fuzzer.cli import build_parser
    args = build_parser().parse_args(["-d", "x.com", "--ai",
                                      "--ai-provider", "ollama"])
    cfg = apply_cli_overrides(Config(), args)
    assert cfg.ai.enabled and cfg.ai.provider == "ollama"


# ── M3.1 error classification + retry ───────────────────────────────
def test_classify_errors():
    import requests
    from apex_fuzzer.ai.planner import classify_http_error as cls
    assert cls(status=401) == "auth"
    assert cls(status=403) == "auth"
    assert cls(status=404) == "malformed"
    assert cls(status=429) == "rate_limit"
    assert cls(status=500) == "server"
    assert cls(status=418) == "unknown"
    assert cls(exc=requests.exceptions.Timeout()) == "timeout"
    assert cls(exc=requests.exceptions.ConnectionError()) == \
        "connection"
    assert cls(exc=ValueError("x")) == "unknown"


def test_retry_transient_then_success(monkeypatch):
    calls = []

    def fake_post(url, **kw):
        calls.append(1)
        if len(calls) < 3:
            return _Resp({"error": "busy"}, status=503)
        return _Resp({"response": json.dumps(_hyps())})
    monkeypatch.setattr("requests.post", fake_post)
    monkeypatch.setattr("time.sleep", lambda s: None)
    out = AIPlanner(_cfg())._call("hi", timeout=5)
    assert len(calls) == 3  # initial + 2 retries
    assert len(AIPlanner(_cfg())._parse(out)) == 1


def test_no_retry_on_timeout_or_auth(monkeypatch):
    import requests
    calls = []

    def fake_timeout(url, **kw):
        calls.append(1)
        raise requests.exceptions.Timeout()
    monkeypatch.setattr("requests.post", fake_timeout)
    assert AIPlanner(_cfg())._call("hi", timeout=5) == ""
    assert len(calls) == 1  # fail fast, no retry storm

    def fake_auth(url, **kw):
        calls.append(1)
        return _Resp({"error": "denied"}, status=401)
    monkeypatch.setattr("requests.post", fake_auth)
    assert AIPlanner(_cfg())._call("hi", timeout=5) == ""
    assert len(calls) == 2  # one attempt only


def test_malformed_json_body(monkeypatch):
    class BadResp(_Resp):
        def json(self):
            raise ValueError("nope")
    monkeypatch.setattr("requests.post",
                        lambda *a, **k: BadResp({}))
    assert AIPlanner(_cfg())._call("hi", timeout=5) == ""


def test_bounded_log_bodies():
    from apex_fuzzer.ai.planner import _truncate
    assert _truncate("x" * 500) == "x" * 300 + "…"
    assert _truncate("short") == "short"


# ── M3.2 config + validation ─────────────────────────────────────────
def test_effective_settings_precedence():
    cfg = Config()
    assert cfg.ai.effective_ollama()["model"] == "llama3.1"
    assert cfg.ai.effective_gemini()["model"] == "gemini-1.5-flash"
    cfg.ai.ollama = {"model": "qwen2.5:14b", "host": "http://g:11434"}
    cfg.ai.ollama_model = "should-lose"
    eff = cfg.ai.effective_ollama()
    assert eff["model"] == "qwen2.5:14b" and eff["host"] == "http://g:11434"
    cfg.ai.gemini = {"model": "gemini-2.0-flash"}
    assert cfg.ai.effective_gemini()["model"] == "gemini-2.0-flash"


def test_validate_config_cases(monkeypatch):
    cfg = _cfg()
    cfg.ai.enabled = False
    assert AIPlanner(cfg).validate_config() == ["ai.enabled is false"]
    cfg = _cfg()
    cfg.ai.provider = "mystery"
    assert any("unknown ai.provider" in p
               for p in AIPlanner(cfg).validate_config())
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    cfg = _cfg("gemini")
    assert any("GEMINI_API_KEY" in p
               for p in AIPlanner(cfg).validate_config())
    monkeypatch.setenv("GEMINI_API_KEY", "K")
    assert AIPlanner(_cfg("gemini")).validate_config() == []


def test_ollama_host_precedence(monkeypatch):
    cfg = _cfg()
    cfg.ai.ollama = {"host": "http://block:11434"}
    cfg.ai.ollama_host = "http://legacy:11434"
    monkeypatch.setenv("OLLAMA_HOST", "http://env:11434")
    # explicit block beats env beats legacy flat key
    assert AIPlanner(cfg).ollama_host == "http://block:11434"
    cfg.ai.ollama = {}
    assert AIPlanner(cfg).ollama_host == "http://env:11434"
    monkeypatch.delenv("OLLAMA_HOST")
    assert AIPlanner(cfg).ollama_host == "http://legacy:11434"
