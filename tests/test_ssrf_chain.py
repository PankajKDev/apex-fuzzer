"""SSRF chain proof: parser-bypass variants and readback signals.

Fake providers/HTTP only, except where noted. No network.
"""
from types import SimpleNamespace

from main.models import Endpoint, Parameter
from main.stages.validation import ProbeControls
from main.stages.validation.second_order import second_order_ssrf_probe
from main.validation import ssrf_bypass as bypass_mod
from main.validation.oast import probe_endpoint


def _ep(url="https://target.test/fetch?url=1"):
    ep = Endpoint(url=url, normalized_url=url, method="GET",
                  host="target.test", path="/fetch", endpoint_type="proxy")
    ep.query_parameters = [Parameter(name="url", location="query")]
    return ep


def test_decimal_hex_octal_forms_preserve_port_and_path():
    variants = dict(bypass_mod.ip_literal_variants(
        "http://127.0.0.1:9001/stored/abc123"))
    assert variants["decimal-ip"] == \
        "http://2130706433:9001/stored/abc123"
    assert variants["hex-ip"] == "http://0x7f.0.0.1:9001/stored/abc123"
    assert variants["octal-ip"] == "http://0177.0.0.1:9001/stored/abc123"


def test_hostnames_get_no_ip_variants():
    assert bypass_mod.ip_literal_variants(
        "http://abc.oast.pro/stored/x") == []
    assert bypass_mod.ip_literal_variants("not a url") == []
    # hostnames get no IP forms; only the fetcher-dependent backslash
    assert [kind for kind, _ in bypass_mod.bypass_variants(
        "http://abc.oast.pro/stored/x", "")] == ["backslash"]


def test_userinfo_decoy_needs_inscope_host():
    variants = bypass_mod.userinfo_decoy_variant(
        "http://127.0.0.1:9001/stored/abc", "target.test")
    assert variants == [("userinfo-decoy",
                         "http://target.test@127.0.0.1:9001/stored/abc")]
    assert bypass_mod.userinfo_decoy_variant(
        "http://127.0.0.1:9001/stored/abc", "") == []
    assert bypass_mod.userinfo_decoy_variant(
        "http://127.0.0.1:9001/stored/abc", "evil/x") == []


def test_variants_capped_and_ordered():
    variants = bypass_mod.bypass_variants(
        "http://127.0.0.1:9001/stored/abc", "target.test")
    assert len(variants) <= bypass_mod.MAX_VARIANTS
    assert variants[0][0] == "decimal-ip"
    kinds = [kind for kind, _ in variants]
    assert "userinfo-decoy" in kinds
    assert "ipv6-bracket" in kinds


def test_ipv6_zero_and_backslash_forms():
    import ipaddress
    variants = dict(bypass_mod.bypass_variants(
        "http://127.0.0.1:9001/stored/abc", "target.test"))
    bracket = variants["ipv6-bracket"]
    assert bracket.startswith("http://[::ffff:127.0.0.1]:9001/stored/abc")
    assert ipaddress.ip_address(
        bracket.split("[")[1].split("]")[0]).ipv4_mapped is not None
    assert variants["zero-ip"] == "http://0.0.0.0:9001/stored/abc"
    backslash = dict(bypass_mod.backslash_variant(
        "http://127.0.0.1:9001/stored/abc"))["backslash"]
    assert backslash.startswith("http:")
    assert "://" not in backslash
    # non-loopback callbacks get no zero-ip form
    assert bypass_mod.zero_ip_variant(
        "http://93.184.216.34/stored/x") == []
    # non-IP hosts get no IP forms at all
    assert bypass_mod.ipv6_bracket_variant(
        "http://abc.oast.pro/stored/x") == []


class _Provider:
    """Static-collector-style fake with per-call fresh tokens."""

    def __init__(self):
        self.n = 0
        self.fetched = []

    def available(self):
        return True

    def create_token(self):
        return "http://127.0.0.1:9001/cb"

    def correlation_key(self, callback):
        from urllib.parse import urlsplit
        path = urlsplit(callback).path.rstrip("/")
        return path.rsplit("/", 1)[-1]

    def poll(self, **kwargs):
        return [{"path": path} for path in self.fetched]


def _canary_paths():
    from main.validation.second_order import make_ssrf_canary
    return make_ssrf_canary("http://127.0.0.1:9001/cb", "http")


def test_bypass_confirms_when_direct_is_blocked():
    import urllib.parse
    provider = _Provider()

    class Http:
        def get(self, url, **kwargs):
            parsed = urllib.parse.urlsplit(url)
            target = urllib.parse.parse_qsl(parsed.query)[0][1]
            host = urllib.parse.urlsplit(target).hostname or ""
            # naive substring denylist blocks the direct literal only
            if "127.0.0.1" in target:
                return SimpleNamespace(status_code=403, text="blocked")
            provider.fetched.append(urllib.parse.urlsplit(target).path)
            assert host not in ("", "target.test")
            return SimpleNamespace(status_code=200, text="fetched")

    result = probe_endpoint(Http(), _ep(), provider, poll_timeout=0,
                            poll_interval=0)
    assert result is not None and result.confirmed
    assert result.bypass_kind == "decimal-ip"
    assert result.response_reflects_token is False


def test_stale_variant_callback_cannot_confirm():
    provider = _Provider()
    provider.fetched.append("/stored/stale-unrelated")

    class Http:
        def get(self, url, **kwargs):
            return SimpleNamespace(status_code=200, text="ok")

    result = probe_endpoint(Http(), _ep(), provider, poll_timeout=0,
                            poll_interval=0)
    assert result is None or not result.confirmed


def test_response_reflecting_token_is_flagged_not_upgraded():
    provider = _Provider()

    class Http:
        def get(self, url, **kwargs):
            import urllib.parse
            target = urllib.parse.parse_qsl(
                urllib.parse.urlsplit(url).query)[0][1]
            provider.fetched.append(urllib.parse.urlsplit(target).path)
            return SimpleNamespace(
                status_code=200, text=f"fetched content from {target}")

    result = probe_endpoint(Http(), _ep(), provider, poll_timeout=0,
                            poll_interval=0)
    assert result is not None and result.confirmed
    assert result.bypass_kind == ""
    assert result.response_reflects_token is True


def test_budget_exhaustion_propagates():
    from main.budgets import BudgetExceeded

    class Http:
        def get(self, *args, **kwargs):
            raise BudgetExceeded("budget exhausted")

    try:
        probe_endpoint(Http(), _ep(), _Provider(), poll_timeout=0,
                       poll_interval=0)
    except BudgetExceeded:
        return
    raise AssertionError("BudgetExceeded must propagate")


def test_validator_surfaces_bypass_evidence(monkeypatch):
    from main.config import Config
    from main.validation.base import Candidate
    from main.models import Finding
    from main.validation.ssrf import SsrfValidator
    import main.validation.oast as oast_mod

    real_probe = oast_mod.probe_endpoint

    def fake_probe(http, endpoint, provider, **kwargs):
        result = real_probe(http, endpoint, provider, poll_timeout=0,
                            poll_interval=0, **kwargs)
        return result

    monkeypatch.setattr(oast_mod, "probe_endpoint", fake_probe)
    provider = _Provider()

    class Http:
        def get(self, url, **kwargs):
            import urllib.parse
            target = urllib.parse.parse_qsl(
                urllib.parse.urlsplit(url).query)[0][1]
            provider.fetched.append(urllib.parse.urlsplit(target).path)
            return SimpleNamespace(status_code=200, text="fetched")

    candidate = Candidate(
        finding=Finding(id="ssrf1", source="test"), test_class="ssrf",
        endpoint_url="https://target.test/fetch?url=1", parameter="url")
    outcome = SsrfValidator(Config(), provider, Http()).validate(candidate)
    assert outcome.status == "confirmed"
    assert outcome.evidence["bypass_kind"] in ("", "decimal-ip",
                                              "userinfo-decoy")


def test_validator_honors_post_json_and_state_gate():
    from main.config import Config
    from main.validation.base import Candidate
    from main.models import Finding
    from main.validation.ssrf import SsrfValidator

    seen = {}

    class Http:
        def request(self, method, url, **kwargs):
            seen["method"] = method
            seen["json"] = kwargs.get("json")
            return SimpleNamespace(status_code=200, text="ok")

    finding = Finding(id="ssrf-post", source="test", method="POST",
                      parameter="callbackUrl",
                      endpoint_url="https://target.test/api/import",
                      matched_at="https://target.test/api/import",
                      request_body='{"callbackUrl": "http://x/", "mode": 1}',
                      request_headers={"Content-Type": "application/json"})
    candidate = Candidate(
        finding=finding, test_class="ssrf",
        endpoint_url="https://target.test/api/import", method="POST",
        parameter="callbackUrl", parameter_location="body",
        request_headers={"Content-Type": "application/json"},
        request_body='{"callbackUrl": "http://x/", "mode": 1}',
        request_content_type="application/json",
        body_parameters=[Parameter(name="callbackUrl", location="body")])
    cfg = Config()
    provider = _Provider()
    out = SsrfValidator(cfg, provider, Http()).validate(candidate)
    assert out.status == "inconclusive"
    assert "allow_state_change" in out.notes
    assert seen == {}

    cfg.safety.allow_state_change = True
    out = SsrfValidator(cfg, provider, Http()).validate(candidate)
    assert seen.get("method") == "POST"
    assert seen["json"]["callbackUrl"].startswith("http://")
    assert "/cb/stored/" in seen["json"]["callbackUrl"]
    assert seen["json"]["mode"] == "1"


def test_validator_sends_observed_auth_headers():
    from main.config import Config
    from main.validation.base import Candidate
    from main.models import Finding
    from main.validation.ssrf import SsrfValidator

    seen = {}

    class Http:
        def get(self, url, **kwargs):
            seen["headers"] = dict(kwargs.get("headers") or {})
            return SimpleNamespace(status_code=200, text="ok")

    candidate = Candidate(
        finding=Finding(id="ssrf-auth", source="test"), test_class="ssrf",
        endpoint_url="https://target.test/fetch?url=1", parameter="url",
        request_headers={"Authorization": "Bearer CTX"})
    out = SsrfValidator(Config(), _Provider(), Http()).validate(candidate)
    assert seen["headers"].get("Authorization") == "Bearer CTX"
    assert out.status == "inconclusive"


def test_bypass_only_for_answering_schemes():
    import urllib.parse
    provider = _Provider()
    fired = []

    class Http:
        def request(self, method, url, **kwargs):
            body = kwargs.get("json") or {}
            target = body.get("url", "")
            scheme = urllib.parse.urlsplit(target).scheme
            fired.append((method, scheme, target))
            if scheme == "https":
                raise ConnectionError("https refused")
            provider.fetched.append(urllib.parse.urlsplit(target).path)
            return SimpleNamespace(status_code=200, text="fetched")

    ep = _ep()
    ep.method = "POST"
    ep.body_parameters = [Parameter(name="url", location="body")]
    ep.query_parameters = []
    ep.request_content_types = ["application/json"]
    result = probe_endpoint(Http(), ep, provider, poll_timeout=0,
                            poll_interval=0)
    assert result is not None and result.confirmed
    assert result.bypass_kind == ""
    schemes = {urllib.parse.urlsplit(url).scheme
               for _, _, url in fired}
    assert schemes == {"http"}


def test_sweep_finding_carries_bypass_evidence(tmp_path):
    import urllib.parse
    from main.config import Config
    from main.orchestrator import Orchestrator
    from main.profiles import get as get_profile
    from main.reporting.metrics import Metrics
    from main.reporting.coverage import CoverageTracker
    from main.budgets import BudgetTracker
    from main.validation.evidence import EvidenceStore
    from main.scope import Scope
    from main.config import ScopeConfig

    cfg = Config()
    cfg.scope.allowed_domains = ["target.test"]
    cfg.oast.max_endpoints = 5
    orch = Orchestrator(cfg, tmp_path, profile=get_profile("standard"))
    orch.scope = Scope(ScopeConfig(allowed_domains=["target.test"]))
    provider = _Provider()

    class Http:
        def get(self, url, **kwargs):
            target = urllib.parse.parse_qsl(
                urllib.parse.urlsplit(url).query)[0][1]
            if "127.0.0.1" in target:
                return SimpleNamespace(status_code=403, text="blocked")
            provider.fetched.append(urllib.parse.urlsplit(target).path)
            return SimpleNamespace(status_code=200, text="fetched")

    from main.stages.validation import ProbeControls
    from main.stages.validation.oast import oast_sweep
    findings = oast_sweep(
        [_ep()], provider, EvidenceStore(tmp_path / "proofs"), Metrics(),
        Http(), tmp_path, BudgetTracker(cfg), CoverageTracker(),
        cfg, orch.scope, ProbeControls.from_orchestrator(orch))
    assert len(findings) == 1
    finding = findings[0]
    assert "ssrf-bypass" in finding.tags
    assert finding.raw["bypass_kind"] == "decimal-ip"
    assert "parser-bypass variant" in finding.description


def test_stored_trigger_reflection_recorded(tmp_path):
    from main.config import Config
    from main.orchestrator import Orchestrator
    from main.profiles import get as get_profile
    from main.reporting.metrics import Metrics
    from main.reporting.coverage import CoverageTracker
    from main.budgets import BudgetTracker
    from main.validation.evidence import EvidenceStore
    from main.models import Identity
    from main.discovery.url_normalizer import normalize_url
    from main.models import Endpoint as EndpointModel
    from urllib.parse import urlparse

    cfg = Config()
    cfg.scope.allowed_domains = ["t.com"]
    cfg.validation.second_order_ssrf = True
    cfg.validation.second_order_ssrf_max_fields = 2
    cfg.validation.second_order_max_renders = 2
    cfg.oast.poll_timeout = 1
    orch = Orchestrator(cfg, tmp_path, profile=get_profile("standard"))

    class Provider:
        interactions = []

        def available(self):
            return True

        def create_token(self):
            return "registered.oast.pro"

        def poll(self, **kwargs):
            return self.interactions

    provider = Provider()

    class Resp:
        def __init__(self, status, text):
            self.status_code = status
            self.text = text

    class Http:
        def post(self, url, **kwargs):
            callback = kwargs["data"]["url"]
            host = urlparse(callback).hostname
            provider.interactions = [{
                "protocol": "dns", "full-id": host,
                "raw-request": f"QUERY {host} A"}]
            return Resp(202, "accepted")

        def get(self, url, **kwargs):
            # trigger route echoes the stored callback host back
            return Resp(200, f"processed {provider.interactions[0]['full-id']}"
                        if provider.interactions else "empty")

    def _endpoint(url, body_params=None, etype="api", method="GET"):
        p = urlparse(url)
        e = EndpointModel(
            url=url, normalized_url=normalize_url(url),
            host=p.hostname or "", path=p.path, method=method,
            endpoint_type=etype, source=["recon"])
        for name in (body_params or []):
            e.body_parameters.append(Parameter(name=name, location="body",
                                               source=["html"]))
        return e

    ep = _endpoint("https://t.com/api/import", ["url", "name"], "import",
                   method="POST")
    trigger = _endpoint("https://t.com/api/import/status",
                        [], "page")
    findings = second_order_ssrf_probe(
        [ep, trigger], EvidenceStore(tmp_path / "proofs"), Metrics(),
        BudgetTracker(cfg), CoverageTracker(), Http(),
        orch.cfg, orch.scope, ProbeControls.from_orchestrator(orch),
        [Identity(name="operator", auth_headers={"Cookie": "s=1"})],
        provider)
    assert len(findings) == 1
    assert findings[0].raw["trigger_reflects_token"] == [
        "https://t.com/api/import/status"]
    assert "readback" in findings[0].description


def test_ssrf_plugin_blocks_out_of_scope_target():
    from main.config import Config, ScopeConfig
    from main.models import Finding
    from main.plugins.adapters import SsrfPlugin
    from main.plugins.base import TestTarget, TestContext
    from main.scope import Scope

    cfg = Config()
    scope = Scope(ScopeConfig(allowed_domains=["example.test"]))
    finding = Finding(id="ssrf-oos", source="nuclei", parameter="url",
                      endpoint_url="https://other.test/fetch?url=1",
                      matched_at="https://other.test/fetch?url=1")
    target = TestTarget("https://other.test/fetch?url=1", parameter="url",
                        method="GET", finding=finding, endpoint=None,
                        test_class="ssrf")
    ctx = TestContext(cfg, http=SimpleNamespace(), scope=scope)
    assert SsrfPlugin().run(target, ctx).status == "blocked"
