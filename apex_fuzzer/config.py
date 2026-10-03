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
    second_order_max_endpoints: int = 10
    second_order_max_renders: int = 40
    min_severity: str = "medium"


@dataclass
class AuthorizationConfig:
    """Cross-user swap + per-method BFLA matrix (bounty items #1–2)."""
    enabled: bool = False
    methods: List[str] = field(
        default_factory=lambda: ["GET", "POST", "PUT", "PATCH", "DELETE"])
    max_endpoints: int = 20
    max_ids_per_endpoint: int = 3


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
    model: str = "gemini-1.5-flash"
    max_output_tokens: int = 8192
    # how many JS chunks get sent to the planner (spec §6)
    js_chunk_budget: int = 6
    # max hypotheses per test class fed back into deterministic testing
    max_hypothesis_tests: int = 5


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
class AuthConfig:
    # anonymous context is always implicitly present
    contexts: List[AuthContext] = field(default_factory=list)

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
            cfg.auth = AuthConfig(contexts=ctxs)
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
    return cfg
