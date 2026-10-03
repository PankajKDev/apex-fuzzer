"""Configuration loader with CLI-override precedence."""
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional

try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False
import json


@dataclass
class ScanConfig:
    rate_limit: int = 50
    concurrency: int = 5
    timeout: int = 300
    http_timeout: int = 10
    jitter_between_targets: int = 2


@dataclass
class DiscoveryConfig:
    javascript: bool = True
    js_max_files: int = 40
    js_max_bytes_per_file: int = 400_000
    source_maps: bool = True
    api_specs: bool = True
    html_forms: bool = True
    robots_sitemap: bool = True
    # ── Arjun active parameter mining (spec §1) ─────────────────────────
    arjun: bool = True
    arjun_methods: List[str] = field(
        default_factory=lambda: ["GET", "POST", "JSON"])
    arjun_max_endpoints: int = 15
    arjun_timeout: int = 180
    arjun_stable: bool = False
    # restrict arjun to endpoints that already expose >= 1 parameter
    arjun_require_existing_param: bool = False
    # LinkFinder passive JS parameter extraction (spec §1, Gaia-style)
    linkfinder: bool = False


@dataclass
class ValidationConfig:
    enabled: bool = False
    ssrf: bool = False
    differential: bool = False
    mutation: bool = True
    mutation_payloads: int = 8
    differential_max_endpoints: int = 30
    # stored-XSS correlation writes canary data: opt-in only
    second_order: bool = False
    # blind stored-SSRF correlation writes callback URLs: opt-in only
    second_order_ssrf: bool = False
    second_order_max_endpoints: int = 10
    second_order_max_renders: int = 40
    second_order_ssrf_max_fields: int = 3
    min_severity: str = "medium"


@dataclass
class AuthorizationConfig:
    """Cross-user swap + per-method BFLA matrix (bounty items #1–2)."""
    enabled: bool = False
    methods: List[str] = field(
        default_factory=lambda: ["GET", "POST", "PUT", "PATCH", "DELETE"])
    max_endpoints: int = 20
    max_ids_per_endpoint: int = 3
    # identifier fields that prove object ownership when equal in
    # owner and tester responses (Terra M2.5)
    ownership_fields: List[str] = field(
        default_factory=lambda: ["owner_id", "user_id", "account_id",
                                  "tenant_id", "created_by", "owner",
                                  "email"])
    # Optional endpoint-specific replacements, keyed by exact URL or path.
    ownership_fields_by_endpoint: Dict[str, List[str]] = field(
        default_factory=dict)


@dataclass
class BusinessConfig:
    """Business-logic mutation engine (quantity/price/refund/replay)."""
    enabled: bool = False
    max_endpoints: int = 10
    max_params: int = 3
    # user-supplied readback assertions (Terra M2.4); see
    # verify/assertions.py for the schema
    assertions: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class RaceConfig:
    """Race-condition engine. Off by default — synchronized bursts of
    state-changing requests are the most aggressive test in the suite."""
    enabled: bool = False
    concurrency: int = 10
    rounds: int = 3
    max_endpoints: int = 5
    # Generic preserves the original duplicate-processing detector.
    # Specialized profiles attach an invariant and require verification.
    profile: str = "generic"  # generic | single_use | idempotency | inventory
    inventory_endpoint: str = ""
    inventory_read_url: str = ""
    inventory_jsonpath: str = ""


@dataclass
class SafetyConfig:
    """Strict-mode gates + execution controls (Milestone 1).

    Everything defaults to today's behavior (strict off, no caps).
    бюджетов max_requests / max_state_changes use None = unlimited.
    """
    strict: bool = False
    authorization_ref: str = ""
    approved_domains: List[str] = field(default_factory=list)
    approved_cidrs: List[str] = field(default_factory=list)
    valid_from: str = ""
    valid_until: str = ""
    allowed_modules: List[str] = field(default_factory=list)
    allow_state_change: bool = False
    max_requests: Optional[int] = None
    max_state_changes: Optional[int] = None
    stop_on_candidate: bool = False
    cooldown_ms: int = 0


@dataclass
class BudgetConfig:
    """Request budgets (§50). Generous defaults: normal scans stay far
    below every cap; the caps only bite runaway loops."""
    requests_per_host: int = 10000
    requests_per_endpoint: int = 100
    authz_tests_per_endpoint: int = 20
    browser_actions: int = 500
    ai_experiments: int = 50


@dataclass
class BrowserConfig:
    """Browser-driven discovery + sessions (agent Phase 1)."""
    enabled: bool = False
    headless: bool = True
    max_pages: int = 100
    max_depth: int = 5
    capture_network: bool = True
    capture_websocket: bool = True
    capture_storage: bool = True
    capture_dom: bool = True
    navigation_timeout_ms: int = 30000


@dataclass
class OastConfig:
    enabled: bool = True
    server: str = "oast.pro"
    api_base: Optional[str] = None
    poll_timeout: int = 15
    poll_interval: int = 2
    max_endpoints: int = 10
    max_params_per_endpoint: int = 3


@dataclass
class NucleiConfig:
    # bug-bounty specific template dir (e.g. unrandoms/nuclei-bb-templates)
    bb_templates_dir: str = "~/nuclei-bb-templates"
    # enable nuclei workflows (chained, conditional templates)
    workflows: bool = False
    # generate + run templates for AI hypotheses
    ai_templates: bool = True


@dataclass
class AIConfig:
    enabled: bool = False
    # Gemini is the preferred hosted provider and falls back to free-tier
    # Groq models when unavailable. Ollama remains optional.
    provider: str = "gemini"
    model: str = "gemini-3.5-flash-lite"
    max_output_tokens: int = 8192
    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "llama3.1"
    ollama_timeout: int = 180
    # provider-scoped blocks (M3.2) take precedence over the legacy
    # flat keys above, which keep working with a deprecation note
    gemini: Dict[str, Any] = field(default_factory=dict)
    groq: Dict[str, Any] = field(default_factory=dict)
    ollama: Dict[str, Any] = field(default_factory=dict)
    # how many JS chunks get sent to the planner (spec §6)
    js_chunk_budget: int = 6
    # max hypotheses per test class fed back into deterministic testing
    max_hypothesis_tests: int = 5

    def effective_gemini(self) -> Dict[str, Any]:
        out = {"model": self.model, "timeout": 30,
               "max_output_tokens": self.max_output_tokens}
        out.update({k: v for k, v in (self.gemini or {}).items()
                    if v is not None})
        return out

    def effective_groq(self) -> Dict[str, Any]:
        out = {"model": "openai/gpt-oss-20b", "timeout": 60,
               "max_output_tokens": self.max_output_tokens}
        out.update({k: v for k, v in (self.groq or {}).items()
                    if v is not None})
        return out

    def effective_ollama(self) -> Dict[str, Any]:
        out = {"host": self.ollama_host, "model": self.ollama_model,
               "timeout": self.ollama_timeout,
               "max_output_tokens": self.max_output_tokens}
        out.update({k: v for k, v in (self.ollama or {}).items()
                    if v is not None})
        return out


@dataclass
class ReportingConfig:
    redact_secrets: bool = True
    min_severity: str = "info"


@dataclass
class ScopeConfig:
    allowed_domains: List[str] = field(default_factory=list)
    allow_subdomains: bool = True
    excluded_hosts: List[str] = field(default_factory=list)
    excluded_paths: List[str] = field(default_factory=list)
    crawl_exclude_exts: List[str] = field(default_factory=lambda: [
        "png", "jpg", "jpeg", "gif", "svg", "webp", "ico",
        "woff", "woff2", "ttf", "otf", "eot",
        "mp4", "webm", "mp3", "wav",
        "pdf", "zip", "tar", "gz", "7z", "rar",
    ])
    active_test_exclude_exts: List[str] = field(default_factory=lambda: [
        "png", "jpg", "jpeg", "gif", "svg", "webp", "ico",
        "woff", "woff2", "ttf", "otf", "eot",
        "mp4", "webm", "mp3", "wav", "pdf",
    ])


@dataclass
class AuthContext:
    """One authentication context for differential testing (spec §2).

    ``headers`` may include ``Cookie`` and/or ``Authorization``.
    ``identity``/``roles``/``tenant`` attach the context to the
    application model; ``storage_state`` points at a Playwright
    storage-state file for browser sessions (Phase 2). Header-based
    auth keeps working when the new fields are empty.
    """
    name: str
    headers: Dict[str, str] = field(default_factory=dict)
    identity: str = ""
    roles: List[str] = field(default_factory=list)
    tenant: str = ""
    storage_state: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class LoginIdentityConfig:
    """One login-capable identity. The password itself is NEVER stored
    here — `password_env` names the environment variable holding it."""
    name: str = ""
    username: str = ""
    password_env: str = ""
    roles: List[str] = field(default_factory=list)
    tenant: str = ""


@dataclass
class LoginConfig:
    """Automated form-login minting (agent Phase 2). Disabled unless
    explicitly configured; the login URL must be in scope."""
    enabled: bool = False
    url: str = ""
    username_field: str = "username"
    password_field: str = "password"
    submit: str = "button[type=submit]"
    success_url_contains: str = ""
    success_text: str = ""
    identities: List[LoginIdentityConfig] = field(default_factory=list)


@dataclass
class AuthConfig:
    # anonymous context is always implicitly present
    contexts: List[AuthContext] = field(default_factory=list)
    login: LoginConfig = field(default_factory=LoginConfig)

    @property
    def has_authenticated(self) -> bool:
        return any(c.name != "anonymous" for c in self.contexts)

    @property
    def has_two_authenticated(self) -> bool:
        authed = [c for c in self.contexts if c.name != "anonymous"]
        return len(authed) >= 2


@dataclass
class Config:
    scan: ScanConfig = field(default_factory=ScanConfig)
    discovery: DiscoveryConfig = field(default_factory=DiscoveryConfig)
    validation: ValidationConfig = field(default_factory=ValidationConfig)
    authorization: AuthorizationConfig = field(
        default_factory=AuthorizationConfig)
    business: BusinessConfig = field(default_factory=BusinessConfig)
    race: RaceConfig = field(default_factory=RaceConfig)
    safety: SafetyConfig = field(default_factory=SafetyConfig)
    browser: BrowserConfig = field(default_factory=BrowserConfig)
    budgets: BudgetConfig = field(default_factory=BudgetConfig)
    oast: OastConfig = field(default_factory=OastConfig)
    nuclei: NucleiConfig = field(default_factory=NucleiConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    reporting: ReportingConfig = field(default_factory=ReportingConfig)
    scope: ScopeConfig = field(default_factory=ScopeConfig)

    @classmethod
    def load(cls, path) -> "Config":
        if path is None or not Path(path).exists():
            return cls()
        path = Path(path)
        raw = path.read_text()
        if path.suffix in (".yaml", ".yml"):
            if not _HAS_YAML:
                raise RuntimeError("pyyaml is required; pip install pyyaml")
            data = yaml.safe_load(raw) or {}
        else:
            data = json.loads(raw)

        cfg = cls()
        for section, values in data.items():
            if not hasattr(cfg, section) or not isinstance(values, dict):
                continue
            target = getattr(cfg, section)
            for k, v in values.items():
                if hasattr(target, k):
                    setattr(target, k, v)

        # nested dataclass parsing (the generic setattr above can't build
        # lists of AuthContext from plain dicts)
        if isinstance(data.get("auth"), dict):
            raw_ctx = data["auth"].get("contexts") or []
            ctxs: List[AuthContext] = []
            for item in raw_ctx:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name", "")).strip()
                if not name:
                    continue
                headers = {str(k): str(v) for k, v in
                           (item.get("headers") or {}).items()}
                roles = [str(r) for r in (item.get("roles") or [])]
                ctxs.append(AuthContext(
                    name=name, headers=headers,
                    identity=str(item.get("identity") or ""),
                    roles=roles,
                    tenant=str(item.get("tenant") or ""),
                    storage_state=item.get("storage_state")))
            login_raw = data["auth"].get("login") or {}
            login = LoginConfig(
                enabled=bool(login_raw.get("enabled", False)),
                url=str(login_raw.get("url", "")),
                username_field=str(login_raw.get("username_field",
                                                 "username")),
                password_field=str(login_raw.get("password_field",
                                                 "password")),
                submit=str(login_raw.get("submit",
                                         "button[type=submit]")),
                success_url_contains=str(login_raw.get(
                    "success_url_contains", "")),
                success_text=str(login_raw.get("success_text", "")),
                identities=[LoginIdentityConfig(
                    name=str(i.get("name", "")),
                    username=str(i.get("username", "")),
                    password_env=str(i.get("password_env", "")),
                    roles=[str(r) for r in (i.get("roles") or [])],
                    tenant=str(i.get("tenant", "")))
                    for i in (login_raw.get("identities") or [])
                    if isinstance(i, dict) and i.get("name")])
            cfg.auth = AuthConfig(contexts=ctxs, login=login)
        return cfg

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def apply_cli_overrides(cfg: Config, args) -> Config:
    if getattr(args, "fast", False):
        cfg.scan.rate_limit = 200
    if getattr(args, "deep", False):
        cfg.scan.rate_limit = 20
    if getattr(args, "validate", False):
        cfg.validation.enabled = True
    if getattr(args, "ai", False):
        cfg.ai.enabled = True
    if getattr(args, "ai_provider", None):
        cfg.ai.provider = args.ai_provider
    if getattr(args, "min_sev", None):
        cfg.reporting.min_severity = args.min_sev
    if getattr(args, "no_js", False):
        cfg.discovery.javascript = False
    if getattr(args, "oast", False):
        cfg.oast.enabled = True
        cfg.validation.ssrf = True
    if getattr(args, "differential", False):
        cfg.validation.differential = True
    if getattr(args, "second_order", False):
        cfg.validation.second_order = True
    if getattr(args, "second_order_ssrf", False):
        cfg.validation.second_order_ssrf = True
        cfg.oast.enabled = True
    if getattr(args, "business_logic", False):
        cfg.business.enabled = True
    if getattr(args, "race", False):
        cfg.race.enabled = True
    if getattr(args, "browser", False):
        cfg.browser.enabled = True
    if getattr(args, "no_browser", False):
        cfg.browser.enabled = False
    if getattr(args, "strict", False):
        cfg.safety.strict = True
    if getattr(args, "auth_ref", None):
        cfg.safety.authorization_ref = args.auth_ref
    if getattr(args, "ack_state_change", False):
        cfg.safety.allow_state_change = True
    if getattr(args, "max_requests", None) is not None:
        cfg.safety.max_requests = args.max_requests
    if getattr(args, "max_state_changes", None) is not None:
        cfg.safety.max_state_changes = args.max_state_changes
    if getattr(args, "stop_on_candidate", False):
        cfg.safety.stop_on_candidate = True
    if getattr(args, "cooldown_ms", None) is not None:
        cfg.safety.cooldown_ms = args.cooldown_ms
    return cfg
