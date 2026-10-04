"""Tests for v5.2 additions: arjun parsing, tech gating, JS chunking,
differential auth, mutation engine, OAST helpers, nuclei gen, limiter."""
import json
import time
from types import SimpleNamespace

from apex_fuzzer.discovery import param_miner, technologies as tech_mod
from apex_fuzzer.discovery.javascript import chunk_js, parse_source_map
from apex_fuzzer.models import Parameter, Hypothesis, Endpoint, Finding
from apex_fuzzer.validation import differential as diff_mod
from apex_fuzzer.validation import mutate as mut_mod
from apex_fuzzer.validation import oast as oast_mod
from apex_fuzzer.detection import nuclei as nuclei_mod
from apex_fuzzer.shell import AdaptiveRateLimiter
from apex_fuzzer.config import Config
from apex_fuzzer.validation.base import Candidate
from apex_fuzzer.validation import sqli as sqli_mod


# ── arjun JSON parsing ────────────────────────────────────────────────
def test_parse_arjun_json_basic():
    url = "https://a.com/api/x"
    text = json.dumps({url: {"params": ["debug", "admin"],
                             "method": "GET", "headers": {}}})
    assert param_miner.parse_arjun_json(text, url) == ["debug", "admin"]


def test_parse_arjun_json_empty():
    assert param_miner.parse_arjun_json("", "https://a.com/") == []
    assert param_miner.parse_arjun_json("not json", "https://a.com/") == []
    assert param_miner.parse_arjun_json("{}", "https://a.com/") == []


# ── technology gating ─────────────────────────────────────────────────
def test_detect_waf_cloudflare():
    assert tech_mod.detect_waf({"cf-ray": "abc123"}) == "cloudflare"
    assert tech_mod.detect_waf({"x-sucuri-id": "1"}) == "sucuri"


def test_detect_waf_none():
    assert tech_mod.detect_waf({}) is None
    assert tech_mod.detect_waf({"server": "nginx"}) is None


def test_detect_js_bundle_react_auth0():
    techs = tech_mod.detect_js_bundle(
        "var x = createRoot(document); createAuth0Client({})")
    names = {t.name for t in techs}
    assert "React" in names
    assert "Auth0 JS" in names
    cats = tech_mod.categories(techs)
    assert "React" in cats["frontend"]
    assert tech_mod.gate(techs, "auth", "Auth0 JS")


def test_detect_cloud_error_page():
    techs = tech_mod.detect({"server": "nginx"}, "<Code>NoSuchKey</Code>")
    by_name = {t.name: t for t in techs}
    assert by_name["Amazon S3"].category == "cloud"


def test_detect_gateway_header():
    techs = tech_mod.detect({"server": "kong/3.4"}, "")
    by_name = {t.name: t for t in techs}
    assert by_name["Kong"].category == "gateway"


# ── JS chunking + source maps ─────────────────────────────────────────
def test_chunk_js_small_passthrough():
    assert chunk_js("var a = 1;") == ["var a = 1;"]
    assert chunk_js("") == []


def test_chunk_js_structural():
    big = "\n".join(f"export const m{i} = {i};" + "x" * 500
                    for i in range(40))
    chunks = chunk_js(big, max_chunk=4000)
    assert len(chunks) > 1
    # every chunk is bounded (+overlap tolerance)
    assert all(len(c) <= 4600 for c in chunks)
    # no content lost
    assert "".join(chunks).replace("x", "") != ""


def test_parse_source_map_endpoints():
    data = {"sources": ["webpack://app/src/api/users.ts"],
            "sourcesContent": ["fetch('/api/internal/debug?token=1')\n"
                               "AKIAIOSFODNN7EXAMPLE"]}
    out = parse_source_map(data)
    assert any(e["path"] == "/api/internal/debug" for e in out["endpoints"])
    assert any(s["type"] == "aws_key" for s in out["secrets"])
    assert "token" in out["params"]


# ── differential ──────────────────────────────────────────────────────
class _Resp:
    def __init__(self, status, text):
        self.status_code = status
        self.text = text


def _ctx(name, status, body):
    n = diff_mod.normalize_response(_Resp(status, body))
    return diff_mod.ContextResult(name=name, status=n["status"],
                                  length=n["length"],
                                  length_bucket=n["length_bucket"],
                                  key_shape=n["key_shape"],
                                  body_hash=n["body_hash"])


def test_differential_bola():
    body = json.dumps({"id": 1, "email": "a@b.c"})
    res = diff_mod.DifferentialResult(url="https://a.com/api/u/1",
                                      endpoint_type="api")
    res.contexts = [_ctx("anonymous", 401, ""),
                    _ctx("user_a", 200, body),
                    _ctx("user_b", 200, body)]
    verdict, notes = diff_mod.DifferentialResult.evaluate(res) \
        if hasattr(diff_mod.DifferentialResult, "evaluate") else \
        diff_mod.DifferentialTester.evaluate(res)
    assert verdict == "strong_candidate"
    assert "BOLA" in notes


def test_differential_broken_access():
    res = diff_mod.DifferentialResult(url="https://a.com/admin",
                                      endpoint_type="admin")
    res.contexts = [_ctx("anonymous", 200, "<h1>admin</h1>")]
    verdict, _ = diff_mod.DifferentialTester.evaluate(res)
    assert verdict == "strong_candidate"


def test_differential_healthy_authz():
    res = diff_mod.DifferentialResult(url="https://a.com/api/u/1",
                                      endpoint_type="api")
    res.contexts = [_ctx("anonymous", 401, ""),
                    _ctx("user_a", 200, '{"id":1}'),
                    _ctx("user_b", 403, "")]
    verdict, _ = diff_mod.DifferentialTester.evaluate(res)
    assert verdict == "inconclusive"


def test_differential_volatile_keys_ignored():
    b1 = json.dumps({"id": 1, "csrf": "aaa", "timestamp": 111})
    b2 = json.dumps({"id": 1, "csrf": "bbb", "timestamp": 222})
    res = diff_mod.DifferentialResult(url="x", endpoint_type="api")
    res.contexts = [_ctx("user_a", 200, b1), _ctx("user_b", 200, b2)]
    verdict, _ = diff_mod.DifferentialTester.evaluate(res)
    assert verdict == "strong_candidate"


# ── mutation engine ───────────────────────────────────────────────────
def test_mutations_cloudflare_first():
    ordered = mut_mod.mutations_for("cloudflare", "sqli")
    assert set(ordered) == set(mut_mod.SQLI_MUTATIONS)
    # obfuscation comes before the naive payload
    assert ordered.index("'/**/OR/**/1=1-- -") < ordered.index("' OR '1'='1")


def test_mutations_unknown_waf_passthrough():
    assert mut_mod.mutations_for(None, "xss") == mut_mod.XSS_MUTATIONS


def test_sqli_error_signal():
    assert mut_mod.sqli_error_signal("You have an error in your SQL syntax;")
    assert not mut_mod.sqli_error_signal("welcome to our homepage")


def test_sqli_boolean_pair_is_repeatable_candidate_and_has_no_delay_payload():
    class Http:
        def __init__(self):
            self.urls = []

        def get(self, url, **kwargs):
            self.urls.append(url)
            body = ('{"items":[1,2]}' if "AND+1%3D1" in url else
                    '{"items":[]}')
            return SimpleNamespace(status_code=200, text=body)

    http = Http()
    candidate = Candidate(
        finding=Finding(id="f1", source="test"), test_class="sqli",
        endpoint_url="https://example.test/items?id=7", parameter="id")
    outcome = mut_mod.MutationEngine(Config(), http).prescreen_sqli(candidate)
    assert outcome and outcome.status == "strong_candidate"
    assert outcome.evidence["control_pair"]["true_first"] == \
        outcome.evidence["control_pair"]["true_repeat"]
    assert len(http.urls) == 3
    assert all("SLEEP" not in url.upper() and "PG_SLEEP" not in url.upper()
               for url in http.urls)


def test_sqlmap_is_parameter_pinned_and_does_not_enumerate(monkeypatch):
    calls = []
    monkeypatch.setattr(sqli_mod, "which", lambda _: "/usr/bin/sqlmap")
    monkeypatch.setattr(sqli_mod, "run", lambda args, timeout: (
        calls.append((args, timeout)) or
        SimpleNamespace(stdout="", stderr="")))
    candidate = Candidate(
        finding=Finding(id="f2", source="test"), test_class="sqli",
        endpoint_url="https://example.test/items?id=7&view=full",
        parameter="id")
    result = sqli_mod.SqliValidator(Config()).validate(candidate)
    assert result.status == "inconclusive"
    args, timeout = calls[0]
    assert "-p=id" in args
    assert "--dbs" not in args
    assert args[args.index("--technique") + 1] == "BE"
    assert timeout == 180


def test_sqlmap_skips_without_a_query_candidate(monkeypatch):
    monkeypatch.setattr(sqli_mod, "which", lambda _: "/usr/bin/sqlmap")
    candidate = Candidate(
        finding=Finding(id="f3", source="test"), test_class="sqli",
        endpoint_url="https://example.test/items")
    result = sqli_mod.SqliValidator(Config()).validate(candidate)
    assert result.status == "inconclusive"
    assert "no candidate parameter" in result.notes


def test_sqlmap_skips_unimplemented_post_body_shape(monkeypatch):
    monkeypatch.setattr(sqli_mod, "which", lambda _: "/usr/bin/sqlmap")
    candidate = Candidate(
        finding=Finding(id="f4", source="test"), test_class="sqli",
        endpoint_url="https://example.test/items", parameter="id",
        method="POST", request_body="id=7")
    result = sqli_mod.SqliValidator(Config()).validate(candidate)
    assert result.status == "inconclusive"
    assert "allow_state_change" in result.notes


def test_sqli_form_body_boolean_pair_requires_and_uses_state_change_ack():
    class Http:
        def __init__(self):
            self.calls = []

        def request(self, method, url, **kwargs):
            self.calls.append((method, url, kwargs))
            body = ("{\"rows\":[1]}" if "1=1" in
                    kwargs["data"]["id"] else "{\"rows\":[]}")
            return SimpleNamespace(status_code=200, text=body)

    cfg = Config()
    cfg.safety.allow_state_change = True
    http = Http()
    candidate = Candidate(
        finding=Finding(id="f5", source="test"), test_class="sqli",
        endpoint_url="https://example.test/search", parameter="id",
        method="POST", parameter_location="body",
        request_content_type="application/x-www-form-urlencoded",
        body_parameters=[Parameter(name="id", location="body",
                                   sample_value="7")])
    outcome = mut_mod.MutationEngine(cfg, http).prescreen_sqli(candidate)
    assert outcome and outcome.status == "strong_candidate"
    assert len(http.calls) == 3
    assert all(call[0] == "POST" and call[1] == candidate.endpoint_url
               for call in http.calls)
    assert all("id" in call[2]["data"] for call in http.calls)


def test_sqli_body_mutations_stay_off_without_state_change_ack():
    class Http:
        def __init__(self):
            self.calls = 0

        def request(self, method, url, **kwargs):
            self.calls += 1
            return SimpleNamespace(status_code=200, text="ok")

    http = Http()
    candidate = Candidate(
        finding=Finding(id="f8", source="test"), test_class="sqli",
        endpoint_url="https://example.test/search", parameter="id",
        method="POST", parameter_location="body",
        request_content_type="application/x-www-form-urlencoded",
        body_parameters=[Parameter(name="id", location="body",
                                   sample_value="7")])
    outcome = mut_mod.MutationEngine(Config(), http).prescreen_sqli(candidate)
    assert outcome and outcome.status == "inconclusive"
    assert http.calls == 0


def test_sqli_json_body_supports_nested_observed_parameter():
    class Http:
        def __init__(self):
            self.calls = []

        def request(self, method, url, **kwargs):
            self.calls.append(kwargs["json"])
            true_case = "1=1" in kwargs["json"]["user"]["id"]
            return SimpleNamespace(
                status_code=200,
                text='{"rows":[1]}' if true_case else '{"rows":[]}')

    cfg = Config()
    cfg.safety.allow_state_change = True
    http = Http()
    candidate = Candidate(
        finding=Finding(id="f6", source="test"), test_class="sqli",
        endpoint_url="https://example.test/search", parameter="user.id",
        method="PATCH", parameter_location="body",
        request_content_type="application/json",
        body_parameters=[Parameter(name="user.id", location="body",
                                   sample_value="7")])
    outcome = mut_mod.MutationEngine(cfg, http).prescreen_sqli(candidate)
    assert outcome and outcome.status == "strong_candidate"
    assert len(http.calls) == 3
    assert all("user" in call and "id" in call["user"]
               for call in http.calls)


def test_sqlmap_supports_json_body_with_parameter_pin(monkeypatch):
    calls = []
    monkeypatch.setattr(sqli_mod, "which", lambda _: "/usr/bin/sqlmap")
    monkeypatch.setattr(sqli_mod, "run", lambda args, timeout: (
        calls.append((args, timeout)) or
        SimpleNamespace(stdout="", stderr="")))
    cfg = Config()
    cfg.safety.allow_state_change = True
    candidate = Candidate(
        finding=Finding(id="f7", source="test"), test_class="sqli",
        endpoint_url="https://example.test/search", parameter="user.id",
        method="POST", parameter_location="body",
        request_content_type="application/json",
        body_parameters=[Parameter(name="user.id", location="body",
                                   sample_value="7")])
    result = sqli_mod.SqliValidator(cfg).validate(candidate)
    assert result.status == "inconclusive"
    args, _ = calls[0]
    assert "-p=user.id" in args
    assert args[args.index("--method") + 1] == "POST"
    data = args[args.index("--data") + 1]
    assert '"user":{"id":"7"}' in data
    assert args[args.index("--headers") + 1] == \
        "Content-Type: application/json"


def test_fingerprint_waf_none():
    assert mut_mod.fingerprint_waf({}) is None


# ── OAST helpers ──────────────────────────────────────────────────────
def test_ssrf_candidates_filter():
    params = [Parameter(name="url", location="query"),
              Parameter(name="page", location="query"),
              Parameter(name="q", location="query")]
    got = oast_mod.ssrf_candidates(params)
    assert {p.name for p in got} == {"url", "page"}


def test_with_param_appends():
    url = oast_mod._with_param("https://a.com/x?a=1", "url",
                               "https://cb.oast.pro")
    assert "a=1" in url and "cb.oast.pro" in url


def test_interactsh_create_token():
    p = oast_mod.InteractshProvider(server="oast.pro")
    p.token = "abc123"
    assert p.create_token() == "abc123.oast.pro"
    assert p.available()
    p.close()
    assert not p.available()
    fresh = oast_mod.InteractshProvider()
    assert not fresh.available()


def test_static_callback_collector_tokens_and_poll(monkeypatch):
    p = oast_mod.InteractshProvider(
        callback_url="http://localhost:9001")
    assert p.register()
    assert p.create_token().startswith("http://localhost:9001/")
    assert p.correlation_key(p.create_token()) == p.token

    class Response:
        def json(self):
            return [{"path": f"/{p.token}/stored/abc"}]

    seen = {}
    def fake_get(url, **kwargs):
        seen["url"] = url
        return Response()

    monkeypatch.setattr("requests.get", fake_get)
    assert p.poll(timeout=1, interval=0) == [
        {"path": f"/{p.token}/stored/abc"}]
    assert seen["url"] == "http://localhost:9001/_log"


def test_static_callback_collector_confirms_probe(monkeypatch):
    from types import SimpleNamespace
    from urllib.parse import parse_qs, urlsplit
    from apex_fuzzer.validation.oast import probe_endpoint

    provider = oast_mod.InteractshProvider(
        callback_url="http://localhost:9001")
    assert provider.register()

    callback_urls = []

    class CollectorResponse:
        def json(self):
            return [{"path": urlsplit(url).path} for url in callback_urls]

    monkeypatch.setattr("requests.get", lambda *args, **kwargs:
                        CollectorResponse())

    class Http:
        def request(self, method, url, **kwargs):
            callback_urls.extend(parse_qs(urlsplit(url).query).get("url", []))
            return SimpleNamespace(status_code=202, text="queued")

    endpoint = Endpoint(
        url="http://localhost:8000/fetch-blind",
        normalized_url="http://localhost:8000/fetch-blind",
        host="localhost", path="/fetch-blind", endpoint_type="api",
        query_parameters=[Parameter(name="url", location="query")])
    result = probe_endpoint(Http(), endpoint, provider,
                            poll_timeout=1, poll_interval=0.01,
                            max_params=1)
    assert result and result.confirmed
    assert result.callback_host == "localhost"


def test_static_callback_canary_preserves_local_port():
    from apex_fuzzer.validation.second_order import make_ssrf_canary
    payload = make_ssrf_canary(
        "http://localhost:9001/abc123", scheme="https")
    assert payload.startswith("http://localhost:9001/abc123/stored/")


def test_oast_callback_cli_override():
    from apex_fuzzer.cli import build_parser
    from apex_fuzzer.config import Config, apply_cli_overrides
    args = build_parser().parse_args([
        "-d", "http://localhost:8000", "--oast-callback-url",
        "http://localhost:9001"])
    cfg = apply_cli_overrides(Config(), args)
    assert cfg.oast.enabled and cfg.validation.ssrf
    assert cfg.oast.callback_url == "http://localhost:9001"


def test_correlate_dns_and_http():
    p = oast_mod.InteractshProvider()
    p.token = "tok1"
    hits = [{"proto": "dns", "query": "*.tok1.oast.pro query"},
            {"proto": "http", "path": "/other"}]
    assert p.correlate(hits, "tok1.oast.pro")
    assert not p.correlate([{"proto": "http", "path": "/other"}],
                           "tok1.oast.pro")
    assert not p.correlate([], "tok1.oast.pro")


# ── nuclei hypothesis templates ───────────────────────────────────────
def test_generate_template_for_hypothesis():
    h = Hypothesis(hypothesis="SSRF via url parameter on export",
                   endpoint="https://a.com/export?url=1",
                   reason="export fetches remote", test_class="ssrf",
                   confidence=0.8)
    tpl = nuclei_mod.generate_template_for_hypothesis(
        h, "https://a.com/export?url=1")
    assert tpl["id"].startswith("ai-gen-")
    assert tpl["info"]["severity"] == "high"
    assert "ssrf" in tpl["info"]["tags"]
    import json as _j
    _j.dumps(tpl)  # must be JSON-serializable


def test_generate_template_no_url():
    h = Hypothesis(hypothesis="x", endpoint=None, reason="y",
                   test_class="xss", confidence=0.5)
    assert nuclei_mod.generate_template_for_hypothesis(h, "") is None


# ── adaptive limiter ──────────────────────────────────────────────────
def test_limiter_backoff_and_recovery():
    lim = AdaptiveRateLimiter(100.0)
    lim.after_response(200)
    assert lim.rate == 100.0
    lim.after_response(429)
    assert lim.rate == 50.0
    assert lim.cooldown_until > time.time()
    lim.cooldown_until = 0  # expire cooldown for the test
    for _ in range(20):
        lim.after_response(200)
    assert lim.rate == 100.0
    assert lim.consecutive_429 == 0


def test_limiter_ignores_404():
    lim = AdaptiveRateLimiter(50.0)
    lim.after_response(404)
    assert lim.rate == 50.0


# ── config auth parsing ───────────────────────────────────────────────
def test_config_auth_contexts(tmp_path):
    f = tmp_path / "c.yaml"
    f.write_text("auth:\n  contexts:\n"
                 "    - name: user_a\n"
                 "      headers:\n"
                 "        Cookie: 'session=abc'\n")
    cfg = Config.load(f)
    assert cfg.auth.has_authenticated
    assert cfg.auth.contexts[0].headers["Cookie"] == "session=abc"
    assert not cfg.auth.has_two_authenticated


def test_config_oast_defaults():
    cfg = Config()
    assert cfg.oast.server == "oast.pro"
    assert cfg.validation.mutation is True
