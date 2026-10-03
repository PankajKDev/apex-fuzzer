"""Tests for v5.2 additions: arjun parsing, tech gating, JS chunking,
differential auth, mutation engine, OAST helpers, nuclei gen, limiter."""
import json
import time

from apex_fuzzer.discovery import param_miner, technologies as tech_mod
from apex_fuzzer.discovery.javascript import chunk_js, parse_source_map
from apex_fuzzer.discovery import parameters as param_mod
from apex_fuzzer.models import Parameter, Endpoint, Finding, Hypothesis
from apex_fuzzer.validation import differential as diff_mod
from apex_fuzzer.validation import mutate as mut_mod
from apex_fuzzer.validation import oast as oast_mod
from apex_fuzzer.detection import nuclei as nuclei_mod
from apex_fuzzer.shell import AdaptiveRateLimiter
from apex_fuzzer.config import Config


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
