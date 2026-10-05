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
    # Value sent as the X-HackerOne header on every request made through
    # the tool's HTTP client (e.g. researcher handle or program ref).
    # Empty disables it. Must be a short, single-line, non-secret label:
    # newlines (header injection) are rejected at startup validation.
    hacker_header: str = ""
    # Default User-Agent override for direct HTTP requests. Empty keeps
    # the honest ApexFuzzer default. Operators may set a browser string
    # where program rules allow it; bot-wall evasion is the operator's
    # call, never the default.
    user_agent: str = ""


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
    # Authenticated recon: repeat the live crawlers (katana, hakrawler)
    # carrying the first authenticated identity's Cookie/Authorization.
    # Public archives never take sessions. Off by default: it spends
    # budget as somebody and changes what the crawlers can see.
    authenticated_recon: bool = False


@dataclass
class ValidationConfig:
    enabled: bool = False
    ssrf: bool = False
    differential: bool = False
    ssti: bool = True
    xxe: bool = True
    path_traversal: bool = True
    path_traversal_marker_path: str = ""
    path_traversal_marker_content: str = ""
    path_traversal_max_depth: int = 4
    mutation: bool = True
    mutation_payloads: int = 8
    # Lead-independent prescreen sweep: endpoints and params probed per
    # validation run without requiring a Nuclei lead first.
    prescreen_max_endpoints: int = 30
    prescreen_max_params: int = 3
    differential_max_endpoints: int = 30
    # Time-based sqlmap confirmation is a separate opt-in: delay payloads
    # hold DB connections open and are the load-heaviest check in the
    # suite. Off by default; the mutation prescreen never sends delays.
    sqli_time_based: bool = False
    sqli_time_sec: int = 2
    # Web-cache deception checks run read-only GETs under unique cache
    # keys during validation passes; poisoning probes are out of scope.
    cache: bool = True
    cache_max_endpoints: int = 10
    # Safe, non-following GET checks against observed redirect-like query
    # parameters. Runs only as part of an explicitly enabled validation pass.
    open_redirect: bool = True
    open_redirect_max_endpoints: int = 10
    open_redirect_max_params: int = 3
    cors: bool = True
    # Real Chromium fetch confirmation is opt-in because it performs one
    # additional credentialed GET for each arbitrary-origin candidate.
    cors_browser: bool = False
    cors_max_endpoints: int = 10
    cors_max_identities: int = 3
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
    # MTN-pattern write replay: replays the attacker's own observed
    # mutating request with the victim's ID, verified via readback.
    # Opt-in only (test accounts/objects required) and additionally
    # requires safety.allow_state_change.
    write_replay: bool = False
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
    chromium_executable_path: str = ""
    max_pages: int = 100
    max_depth: int = 5
    capture_network: bool = True
    capture_websocket: bool = True
    capture_storage: bool = True
    capture_dom: bool = True
    # Separate, read-only capture pass for explicitly configured identities.
    capture_authenticated_requests: bool = False
    navigation_timeout_ms: int = 30000


@dataclass
class OastConfig:
    enabled: bool = True
    server: str = "oast.pro"
    api_base: Optional[str] = None
    # Optional static HTTP callback collector, e.g. a local SSRF lab's
    # /_log-compatible server. When set, registration/polling use this URL.
    callback_url: str = ""
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
    # Marks a test session that has authenticated but not yet completed
    # MFA. Used only by the MFA session-transition check, which verifies
    # the pre-MFA session cannot reach privileged resources.
    mfa_pending: bool = False

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
    # Operator-supplied seed URLs (e.g. panel API routes harvested from
    # devtools on a JS SPA). Merged into the recon pool and scope-filtered
    # like any discovered URL. Set via --seed-urls; never scanned directly.
    seed_urls: List[str] = field(default_factory=list)
    # dotted `section.key` paths from the file that match no known field.
    # Unknown content stays ignored (backward compatibility), but the
    # paths are reported so typos do not fail silently.
    unknown_keys: List[str] = field(default_factory=list)

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
            if section == "seed_urls" and isinstance(values, list):
                cfg.seed_urls = [str(u).strip() for u in values
                                 if str(u).strip()]
                continue
            if not hasattr(cfg, section) or not isinstance(values, dict):
                if isinstance(values, dict):
                    for key in values:
                        cfg.unknown_keys.append(f"{section}.{key}")
                else:
                    cfg.unknown_keys.append(str(section))
                continue
            target = getattr(cfg, section)
            for k, v in values.items():
                if hasattr(target, k):
                    setattr(target, k, v)
                else:
                    cfg.unknown_keys.append(f"{section}.{k}")

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
                    storage_state=item.get("storage_state"),
                    mfa_pending=bool(item.get("mfa_pending", False))))
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

    def validate(self) -> Dict[str, List[str]]:
        """Check types, enums, ranges, and impossible combinations.

        Returns {"errors": [...], "warnings": [...]}. Errors must block
        startup; warnings are advisory. Pure: no network, no secrets.
        """
        from .ai.planner import (FREE_GEMINI_MODELS, FREE_GROQ_MODELS)
        errors: List[str] = []
        warnings: List[str] = []

        def err(message: str) -> None:
            errors.append(f"ERROR: {message}")

        def warn(message: str) -> None:
            warnings.append(f"WARNING: {message}")

        def _num(value: Any) -> Optional[float]:
            if isinstance(value, bool):
                return None
            return float(value) if isinstance(value, (int, float)) else None

        def need_positive(name: str, value: Any) -> None:
            if _num(value) is None or value <= 0:
                err(f"{name} must be a number > 0 (got {value!r})")

        def need_non_negative(name: str, value: Any) -> None:
            if _num(value) is None or value < 0:
                err(f"{name} must be a number >= 0 (got {value!r})")

        # scan numerics
        need_positive("scan.rate_limit", self.scan.rate_limit)
        need_positive("scan.concurrency", self.scan.concurrency)
        need_positive("scan.timeout", self.scan.timeout)
        need_positive("scan.http_timeout", self.scan.http_timeout)
        if _num(self.scan.jitter_between_targets) is None or \
                self.scan.jitter_between_targets < 0:
            err("scan.jitter_between_targets must be a number >= 0 "
                f"(got {self.scan.jitter_between_targets!r})")
        hacker = getattr(self.scan, "hacker_header", "")
        if hacker:
            if not isinstance(hacker, str) or "\r" in hacker \
                    or "\n" in hacker:
                err("scan.hacker_header must be a single-line string "
                    "(newlines would inject headers)")
            elif len(hacker) > 200:
                err("scan.hacker_header must be at most 200 characters")
        user_agent = getattr(self.scan, "user_agent", "")
        if user_agent:
            if not isinstance(user_agent, str) or "\r" in user_agent \
                    or "\n" in user_agent:
                err("scan.user_agent must be a single-line string")
            elif len(user_agent) > 200:
                err("scan.user_agent must be at most 200 characters")

        # discovery
        need_non_negative("discovery.js_max_files",
                          self.discovery.js_max_files)
        need_non_negative("discovery.js_max_bytes_per_file",
                          self.discovery.js_max_bytes_per_file)
        need_non_negative("discovery.arjun_max_endpoints",
                          self.discovery.arjun_max_endpoints)
        need_positive("discovery.arjun_timeout",
                      self.discovery.arjun_timeout)
        for method in self.discovery.arjun_methods or []:
            if str(method).upper() not in ("GET", "POST", "JSON"):
                err(f"discovery.arjun_methods has unsupported method "
                    f"{method!r} (GET, POST, JSON)")

        # validation
        for key in ("mutation_payloads", "differential_max_endpoints",
                    "open_redirect_max_endpoints", "open_redirect_max_params",
                    "cors_max_endpoints", "cors_max_identities",
                    "second_order_max_endpoints", "second_order_max_renders",
                    "second_order_ssrf_max_fields", "prescreen_max_endpoints",
                    "prescreen_max_params", "cache_max_endpoints"):
            need_non_negative(f"validation.{key}",
                              getattr(self.validation, key, 0))
        if self.validation.sqli_time_sec not in (1, 2, 3, 4, 5, 6, 7, 8,
                                                 9, 10):
            err("validation.sqli_time_sec must be 1-10 "
                f"(got {self.validation.sqli_time_sec!r})")
        if self.validation.path_traversal_max_depth not in (1, 2, 3, 4, 5,
                                                             6):
            err("validation.path_traversal_max_depth must be 1-6 "
                f"(got {self.validation.path_traversal_max_depth!r})")
        if self.validation.path_traversal and not (
                self.validation.path_traversal_marker_path
                and self.validation.path_traversal_marker_content):
            warn("validation.path_traversal is enabled but no marker "
                 "path/content is configured: the validator stays idle")
        for section, name in (("reporting", "min_severity"),
                              ("validation", "min_severity")):
            value = getattr(getattr(self, section), name)
            if value not in ("info", "low", "medium", "high", "critical"):
                err(f"{section}.{name} must be "
                    f"info|low|medium|high|critical (got {value!r})")

        # authorization
        known_methods = {"GET", "POST", "PUT", "PATCH", "DELETE",
                         "OPTIONS", "HEAD"}
        for method in self.authorization.methods or []:
            if str(method).upper() not in known_methods:
                err(f"authorization.methods has unsupported method "
                    f"{method!r}")
        if self.authorization.enabled and not self.authorization.methods:
            err("authorization.enabled with empty authorization.methods: "
                "nothing would be swept")
        need_non_negative("authorization.max_endpoints",
                          self.authorization.max_endpoints)
        need_non_negative("authorization.max_ids_per_endpoint",
                          self.authorization.max_ids_per_endpoint)

        # business / race
        need_non_negative("business.max_endpoints",
                          self.business.max_endpoints)
        need_non_negative("business.max_params", self.business.max_params)
        if self.race.profile not in ("generic", "single_use",
                                     "idempotency", "inventory"):
            err(f"race.profile must be generic|single_use|idempotency|"
                f"inventory (got {self.race.profile!r})")
        need_positive("race.concurrency", self.race.concurrency)
        need_positive("race.rounds", self.race.rounds)
        need_non_negative("race.max_endpoints", self.race.max_endpoints)
        if self.race.profile == "inventory" and not (
                self.race.inventory_endpoint and self.race.inventory_read_url
                and self.race.inventory_jsonpath):
            err("race.profile=inventory needs inventory_endpoint, "
                "inventory_read_url, and inventory_jsonpath")

        # safety / budgets
        for key in ("max_requests", "max_state_changes"):
            value = getattr(self.safety, key)
            if value is not None and (
                    _num(value) is None or value < 0):
                err(f"safety.{key} must be a number >= 0 or null "
                    f"(got {value!r})")
        if _num(self.safety.cooldown_ms) is None or \
                self.safety.cooldown_ms < 0:
            err("safety.cooldown_ms must be a number >= 0 "
                f"(got {self.safety.cooldown_ms!r})")
        for key in ("requests_per_host", "requests_per_endpoint",
                    "authz_tests_per_endpoint", "browser_actions",
                    "ai_experiments"):
            need_non_negative(f"budgets.{key}", getattr(self.budgets, key))

        # oast
        need_positive("oast.poll_timeout", self.oast.poll_timeout)
        if _num(self.oast.poll_interval) is None or \
                self.oast.poll_interval < 0:
            err("oast.poll_interval must be a number >= 0 "
                f"(got {self.oast.poll_interval!r})")
        need_non_negative("oast.max_endpoints", self.oast.max_endpoints)
        need_non_negative("oast.max_params_per_endpoint",
                          self.oast.max_params_per_endpoint)

        # browser
        for key in ("max_pages", "max_depth", "navigation_timeout_ms"):
            need_non_negative(f"browser.{key}",
                              getattr(self.browser, key))

        # ai
        if self.ai.provider not in ("gemini", "groq", "ollama"):
            err(f"ai.provider must be gemini|groq|ollama "
                f"(got {self.ai.provider!r})")
        if _num(self.ai.max_output_tokens) is None or \
                self.ai.max_output_tokens <= 0:
            err("ai.max_output_tokens must be a number > 0 "
                f"(got {self.ai.max_output_tokens!r})")
        if _num(self.ai.js_chunk_budget) is None or \
                self.ai.js_chunk_budget < 0:
            err("ai.js_chunk_budget must be a number >= 0 "
                f"(got {self.ai.js_chunk_budget!r})")
        if _num(self.ai.max_hypothesis_tests) is None or \
                self.ai.max_hypothesis_tests < 0:
            err("ai.max_hypothesis_tests must be a number >= 0 "
                f"(got {self.ai.max_hypothesis_tests!r})")
        if self.ai.provider == "gemini" and self.ai.model \
                not in FREE_GEMINI_MODELS:
            warn(f"ai.model {self.ai.model!r} is outside the free-tier "
                 f"allowlist; hosted planning may bill or refuse")
        if self.ai.provider == "groq":
            groq_model = (self.ai.groq or {}).get("model") or self.ai.model
            if groq_model not in FREE_GROQ_MODELS:
                warn(f"ai groq model {groq_model!r} is outside the "
                     f"free-tier allowlist")

        # auth
        names = [c.name for c in self.auth.contexts or []]
        if len(set(names)) != len(names):
            err(f"auth.contexts has duplicate names: {names}")
        for context in self.auth.contexts or []:
            if not str(getattr(context, "name", "")).strip():
                err("auth.contexts has an entry with an empty name")
            headers = getattr(context, "headers", None) or {}
            if not isinstance(headers, dict):
                err(f"auth context {getattr(context, 'name', '?')!r}: "
                    f"headers must be a mapping")
        if self.auth.login.enabled and not (
                self.auth.login.identities or []):
            err("auth.login.enabled with no login.identities: nothing "
                "can be minted")
        if self.auth.login.enabled and self.auth.login.url:
            try:
                from urllib.parse import urlsplit
                parts = urlsplit(self.auth.login.url)
                if parts.scheme not in ("http", "https") \
                        or not parts.hostname:
                    err("auth.login.url must be an http(s) URL with a host")
            except (TypeError, ValueError):
                err("auth.login.url is unrepresentable")

        # scope
        for key in ("allowed_domains", "excluded_hosts", "excluded_paths",
                    "crawl_exclude_exts", "active_test_exclude_exts"):
            value = getattr(self.scope, key)
            if not isinstance(value, list) or not all(
                    isinstance(item, str) for item in value):
                err(f"scope.{key} must be a list of strings")
        if not self.scope.allowed_domains:
            warn("scope.allowed_domains is empty: the first target host "
                 "is auto-seeded (explicit scope is recommended)")

        for url in self.seed_urls or []:
            if not isinstance(url, str) or not url.startswith(
                    ("http://", "https://")):
                err(f"seed_urls entries must be http(s) URLs (got {url!r})")
        for unknown in self.unknown_keys:
            warn(f"unknown configuration key {unknown!r} is ignored "
                 f"(possible typo)")
        return {"errors": errors, "warnings": warnings}


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
    if getattr(args, "oast_callback_url", None):
        cfg.oast.callback_url = args.oast_callback_url
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
    if getattr(args, "sqli_time", False):
        cfg.validation.sqli_time_based = True
    if getattr(args, "race", False):
        cfg.race.enabled = True
    if getattr(args, "authz_write_replay", False):
        cfg.authorization.write_replay = True
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
    if getattr(args, "seed_urls", None):
        try:
            seeds = Path(args.seed_urls).read_text(
                errors="ignore").splitlines()
        except Exception as exc:
            raise SystemExit(f"seed file unreadable: {exc}")
        cfg.seed_urls = [line.strip() for line in seeds
                         if line.strip() and not line.startswith("#")]
    return cfg
