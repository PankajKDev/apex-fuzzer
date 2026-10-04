# Apex-Fuzzer

Evidence-driven web security assessment orchestrator. Apex-Fuzzer runs a
10-stage pipeline — recon, endpoint building, API-spec discovery, attack-surface
mapping, live-host probing, subdomain-takeover checks, Nuclei scanning,
multi-engine validation, AI hypothesis planning with deterministic loop closure,
and HTML reporting — and writes structured JSONL plus per-finding evidence
directories for everything it does.

Version: **5.2.0**. Requires Python ≥ 3.10.

> **Authorized testing only.** Apex-Fuzzer sends active payloads (Arjun
> mining, mutation prescreens, sqlmap, dalfox, OAST callbacks, Nuclei DAST).
> Only run it against targets you own or are explicitly authorized to test.
> Active payloads never fire against out-of-scope hosts or excluded file
> extensions (see [Scope enforcement](#scope-enforcement)).

---

## Table of contents

1. [Pipeline at a glance](#pipeline-at-a-glance)
2. [Installation](#installation)
3. [Quick start](#quick-start)
4. [CLI reference](#cli-reference)
5. [Testing profiles](#testing-profiles)
6. [Configuration reference](#configuration-reference)
7. [Authentication contexts (differential testing)](#authentication-contexts-differential-testing)
8. [OAST setup (Interactsh)](#oast-setup-interactsh)
9. [Stage reference](#stage-reference)
10. [Validation semantics](#validation-semantics)
11. [WAF-aware mutation engine](#waf-aware-mutation-engine)
12. [AI planner and loop closure](#ai-planner-and-loop-closure)
13. [Browser-driven discovery (agent Phase 1)](#browser-driven-discovery-agent-phase-1)
14. [Output files](#output-files)
15. [Data models](#data-models)
16. [Application model and graph (Phase 1)](#application-model-and-graph-phase-1)
17. [Security invariants (Phase 1)](#security-invariants-phase-1)
18. [Coverage model (Phase 1)](#coverage-model-phase-1)
19. [Budgets (Phase 1)](#budgets-phase-1)
20. [Safety gates (Milestone 1)](#safety-gates-and-execution-controls-milestone-1)
21. [Plugin architecture (Phase 1)](#plugin-architecture-phase-1)
22. [Scope enforcement](#scope-enforcement)
23. [Evidence and secret redaction](#evidence-and-secret-redaction)
24. [Rate limiting](#rate-limiting)
25. [Running the tests](#running-the-tests)
26. [Tool dependency matrix](#tool-dependency-matrix)
27. [Project structure](#project-structure)

---

## Pipeline at a glance

```
target
  │
  ▼
1. RECON ............ ParamSpider · waybackurls · gauplus · hakrawler · katana
  │                    → raw.txt
  ├─ robots.txt / sitemaps ──→ raw.txt
  ▼
2. ENDPOINT BUILD .... normalize + dedupe URLs → Endpoint objects
  │                    first-party JS → endpoints · source-map deep parse
  ├─ API SPEC DISCOVERY (openapi.json / swagger.json) ──→ new api Endpoints
  ▼
4. MAPPING ........... tech fingerprint · HTML forms · WAF fingerprint
  │                    ARJUN hidden-parameter mining · LinkFinder (optional)
  │                    → endpoints.jsonl · technologies.jsonl
  ├─ APPLICATION ..... Application model + graph from endpoints/techs/ids
  │                    → application.json · application_graph.json
  ▼
5. LIVE PROBE ......... httpx (200,204,301,302,401,403,405,500,502,503,504)
  │                    → live.txt
  ▼
6. TAKEOVER ........... tko-subs (confirmed, with tokens) → subzy fallback
  ▼
7. NUCLEI ............ community templates + bug-bounty templates (+ workflows)
  │                    → nuclei.jsonl → findings.jsonl (deduped, in-scope)
  ▼
8. VALIDATION ......... differential auth (BOLA/broken-access) · OAST sweep
  │                    plugins (mutation → sqlmap / dalfox / OAST-SSRF)
  │                    authz-matrix (swap + BFLA) · stored-XSS · biz-logic
  │                    race (opt-in) · budgets · coverage per class
  ▼
9. AI ................. hypotheses → fed BACK into deterministic tests
  │                    → hypotheses.jsonl (validated / rejected / hypothesized)
  ▼
10. REPORT ............ report.html · metrics.json · coverage.json · proofs/
```

Each stage writes a checkpoint to `checkpoint.json`, so `--resume` skips
finished stages. Stage order and names: `recon, discovery, mapping, probe,
nuclei, validation, ai, report`.

---

## Installation

```bash
cd apex-fuzzer
python3 -m venv .venv && . .venv/bin/activate
pip install -e .            # apex-fuzzer command (colorama, requests, pyyaml)
apex-fuzzer --update        # installs nuclei, httpx, katana, waybackurls,
                            # gauplus, hakrawler, dalfox, subzy, tko-subs,
                            # interactsh-client (go) + arjun, linkfinder (pip)
apex-fuzzer --doctor        # verify every tool is present
```

`--doctor` reports each binary as present (with version) or MISSING. Every
stage that depends on a missing binary logs the skip and continues — see
[Tool dependency matrix](#tool-dependency-matrix).

Optional extras:

- **Bug-bounty Nuclei templates** (IDOR/SSRF/JWT/WAF/secrets): clone
  `unrandoms/nuclei-bb-templates` to `~/nuclei-bb-templates` (configurable via
  `nuclei.bb_templates_dir`).
- **Arjun**: `pipx install arjun` (or `pip install arjun`).
- **Ollama** (optional, local AI backend): install from
  https://ollama.com, then `ollama pull llama3.1` and `ollama serve`.
  Set `ai.provider: ollama` (or `--ai-provider ollama`). Larger models
  (e.g. `qwen2.5:14b`) give better hypotheses if you have the VRAM;
  the planner checks the model is loaded and tells you the pull
  command when it isn't.
- **Playwright** (optional, browser-driven discovery): `pip install
  "apex-fuzzer[browser]"` plus `playwright install chromium` (or reuse
  an existing ms-playwright browser install). Without it the browser
  stage logs a skip; all 18 unit tests still run, the 2 live-Chromium
  integration tests skip.

### Environment file (.env)

Secrets come from the environment, never from `config.yaml`:

```bash
cp .env.example .env   # then fill in; .env is git-ignored, never commit it
```

| variable | enables |
|----------|---------|
| `GEMINI_API_KEY` | AI hypothesis planning via Gemini (`--ai`) |
| `GROQ_API_KEY` | Free-tier fallback for Gemini, or direct Groq planning (`--ai-provider groq`) |
| `OLLAMA_HOST` | (optional) Ollama server override, e.g. `http://gpu-box:11434` — no key needed for local models |
| `GITHUB_TOKEN` | confirmed takeover claims (`tko-subs -takeover`, needs repo scope) |
| `HEROKU_USERNAME` / `HEROKU_API_KEY` / `HEROKU_APP_NAME` | confirmed Heroku takeover claims |

The CLI auto-loads `.env` from the working directory on startup
(stdlib-only parsing; already-exported variables always win). Without
these, the corresponding stages skip gracefully and log why.

---

## Quick start

```bash
# standard passive+DAST scan of one domain
apex-fuzzer -d example.com -c config.yaml --output output

# multiple targets, deep profile (differential + OAST + confirmed takeover)
apex-fuzzer -f targets.txt --profile deep --output output

# validation-heavy run with AI hypotheses
apex-fuzzer -d example.com --validate --ai --oast --differential

# resume an interrupted scan
apex-fuzzer -d example.com --resume --output output
```

Results land in `output/<host>/`: `report.html`, `findings.jsonl`,
`endpoints.jsonl`, `technologies.jsonl`, `hypotheses.jsonl`, `metrics.json`,
`coverage.json`, `application.json`, `application_graph.json`,
`attack_chains.jsonl`, `proofs/`.

For a strict, bounded bounty workflow with zero-network preflight, see
[Authorized bounty scan workflow](docs/bounty-scan.md).
For class-by-class coverage and the prioritized tool roadmap, see the
[bug bounty class and tool matrix](docs/bounty-class-tool-matrix.md).
For a loopback-only discovery walkthrough, see the
[local-lab quickstart](docs/local-lab-quickstart.md). Detection boundaries
and the release gate are documented in
[known limitations](docs/known-limitations.md) and the
[release checklist](docs/release-checklist.md); sanitized example outcomes are
in [sample artifacts](docs/sample-artifacts/).

---

## CLI reference

```
-d, --domain DOMAIN     Single domain (host or URL)
-f, --file FILE         File with one target per line
-c, --config CONFIG     Path to config.yaml (defaults if missing)
--fast                  rate_limit → 200
--deep                  rate_limit → 20
--validate              validation.enabled → true
--ai                    ai.enabled → true
--oast                  OAST blind-SSRF confirmation on
--oast-callback-url URL Use a static HTTP callback collector (local labs)
--differential          differential auth-context tests on
--second-order          stored-XSS correlation on (persists canaries)
--second-order-ssrf     stored-SSRF OAST correlation (persists callback URLs)
--business-logic        business-logic mutation engine on (submits abuse values)
--race                  race-condition engine on (synchronized bursts)
--browser               browser-driven discovery on (needs playwright)
--no-browser            browser-driven discovery off
--no-js                 disable JavaScript analysis
--min-sev {info,low,medium,high,critical}
                        minimum severity rendered in the report
--resume                skip checkpoint-complete stages
--output OUTPUT         base output dir (default: output)
--profile {passive,standard,deep,api,authenticated,validation}
--doctor                check tool availability, exit 0/1
--update                install/update external tools and templates
-v, --verbose           debug logging
```

---

## Testing profiles

| profile         | nuclei | validation | AI | JS | api_specs | robots | differential | arjun | oast | tko-subs | authz-matrix | 2nd-order |
|-----------------|--------|------------|----|----|-----------|--------|--------------|-------|------|----------|--------------|-----------|
| `passive`       | –      | –          | –  | ✓  | ✓         | ✓      | –            | –     | –    | –        | –            | –         |
| `standard`      | ✓      | –          | –  | ✓  | ✓         | ✓      | –            | ✓     | –    | ✓ (subzy)| –            | –         |
| `deep`          | ✓      | –          | –  | ✓  | ✓         | ✓      | ✓            | ✓     | ✓    | ✓ (tko)  | ✓            | ✓         |
| `api`           | ✓      | –          | –  | ✓  | ✓         | –      | ✓            | ✓     | ✓    | ✓ (subzy)| ✓            | –         |
| `authenticated` | ✓      | –          | –  | ✓  | ✓         | ✓      | ✓            | ✓     | ✓    | ✓ (subzy)| ✓            | –         |
| `validation`    | ✓      | ✓          | –  | ✓  | ✓         | ✓      | –            | ✓     | ✓    | ✓ (subzy)| –            | ✓         |

Combine profiles with flags: `--validate`, `--ai`, `--oast`, `--differential`,
`--second-order` and `--second-order-ssrf` force-enable their stages
regardless of profile.

The passive profile still sends read-only discovery requests. It disables
Nuclei, validation, AI, OAST, parameter mining, and takeover checks. For
loopback/private targets, Apex also skips public archive lookups; see the
[local-lab quickstart](docs/local-lab-quickstart.md).
`--business-logic` / `--race` / `--browser` (and `--no-browser` to force
off) do the same for their engines. Config-file keys
(`validation.enabled/differential/ssrf/second_order/second_order_ssrf`,
`authorization.enabled`, `business.enabled`, `race.enabled`,
`browser.enabled`,
`ai.enabled`) do the same. Business-logic runs in deep/validation;
race stays off in every profile (opt-in via `--race`).

---

## Configuration reference

`Config.load(path)` reads YAML or JSON; unknown sections are ignored. CLI
flags override file values (see above). Full annotated default (`config.yaml`):

```yaml
scan:
  rate_limit: 50        # nuclei -rl; direct HTTP uses rate_limit/10 via limiter
  concurrency: 5        # recon thread pool
  timeout: 300          # per-tool subprocess budget (seconds)
  http_timeout: 10      # direct requests via _HTTPClient
  jitter_between_targets: 2

discovery:
  javascript: true
  js_max_files: 40
  js_max_bytes_per_file: 400000   # per-file fetch cap (analysis is chunked)
  source_maps: true               # fetch + deep-parse .map files
  api_specs: true
  html_forms: true
  robots_sitemap: true
  arjun: true
  arjun_methods: ["GET", "POST", "JSON"]
  arjun_max_endpoints: 15         # highest-param endpoints first
  arjun_timeout: 180              # per-method subprocess timeout
  arjun_stable: false             # --stable: 1 thread, slower, steadier
  arjun_require_existing_param: false  # only mine endpoints with ≥1 param
  linkfinder: false               # passive JS param extraction (needs binary)

validation:
  enabled: false
  ssrf: false             # also enables the OAST sweep
  differential: false
  open_redirect: true     # validation profile/enabled only; observed GET fields
  open_redirect_max_endpoints: 10
  open_redirect_max_params: 3
  cors: true              # cookie-authenticated contexts only
  cors_max_endpoints: 10
  cors_max_identities: 3
  mutation: true          # WAF-aware prescreen before sqlmap/dalfox
  mutation_payloads: 8    # ladder depth per class
  differential_max_endpoints: 30
  min_severity: medium     # reserved
  # Stored-XSS correlation persists canary data server-side: opt-in only.
  second_order: false       # or --second-order / validation profile
  # Stored-SSRF writes callback URLs; opt in separately.
  second_order_ssrf: false
  second_order_max_endpoints: 10
  second_order_max_renders: 40
  second_order_ssrf_max_fields: 3

budgets:                  # backstop against runaway testing (§50)
  requests_per_host: 10000
  requests_per_endpoint: 100
  authz_tests_per_endpoint: 20
  browser_actions: 500    # Phase 2 browser engine
  ai_experiments: 50      # Phase 8 AI agent

oast:
  enabled: true
  server: "oast.pro"      # callback domain; oast.live is the failover
  api_base: null          # null → https://api.<server>; set for self-hosted
  callback_url: ""        # local collector base, e.g. http://localhost:9001
  poll_timeout: 15
  poll_interval: 2
  max_endpoints: 10
  max_params_per_endpoint: 3

# Cross-user swap + per-method authz matrix (BOLA/BFLA/tenant isolation).
# NOTE: the method sweep sends state-changing verbs with empty bodies.
authorization:
  enabled: false           # or deep/api/authenticated profiles
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE"]
  max_endpoints: 20
  max_ids_per_endpoint: 3

# Business-logic mutations (quantity/price/refund/token-reuse).
business:
  enabled: false           # or --business-logic / deep/validation profiles
  max_endpoints: 10
  max_params: 3

# Race-condition engine. Off by default: synchronized bursts of
# state-changing requests are the most aggressive test in the suite.
race:
  enabled: false           # or --race
  concurrency: 10
  rounds: 3
  max_endpoints: 5

# Browser-driven discovery + sessions (GET navigations only, safe).
# Needs: pip install "apex-fuzzer[browser]" (Playwright + Chromium).
browser:
  enabled: false           # or --browser / deep profile
  headless: true
  max_pages: 100
  max_depth: 5
  capture_network: true
  capture_websocket: true   # record ws:// URLs for later phases
  capture_storage: true     # cookies + web storage + session export
  capture_dom: true
  navigation_timeout_ms: 30000

nuclei:
  bb_templates_dir: "~/nuclei-bb-templates"
  workflows: false         # -workflow -workflow-threads 3
  ai_templates: true       # run AI-generated gate templates

ai:
  enabled: false
  provider: gemini          # free Gemini, then free Groq fallback
  model: "gemini-3.5-flash-lite"
  max_output_tokens: 8192
  ollama_host: "http://localhost:11434"  # or OLLAMA_HOST env
  ollama_model: "llama3.1"  # must be pulled: ollama pull llama3.1
  ollama_timeout: 180       # local inference is slower than API calls
  js_chunk_budget: 6
  max_hypothesis_tests: 5     # per test class fed back into testing

auth:
  contexts:               # see next section
    - name: anonymous
      headers: {}

reporting:
  redact_secrets: true
  min_severity: info      # report filter: info|low|medium|high|critical

scope:
  allowed_domains: []     # empty + first target → auto-seeded with target host
  allow_subdomains: true
  excluded_hosts: []
  excluded_paths: []      # prefix matches, e.g. ["/static/"]
  # crawl_exclude_exts / active_test_exclude_exts default to image, font,
  # media and archive extensions
```

---

## Authentication contexts (differential testing)

The differential engine compares the **same endpoint under different
credentials**. `anonymous` is always probed implicitly; add accounts under
`auth.contexts`:

```yaml
auth:
  contexts:
    - name: anonymous
      headers: {}
    - name: user_a
      headers:
        Cookie: "session=AAA"
      identity: user_a      # application-model identity (Phase 1)
      roles: ["member"]     # collected into Role objects
      tenant: acme          # tenant membership for isolation tests
      # storage_state: auth/user_a.json  # Playwright state (Phase 2)
    - name: user_b
      headers:
        Cookie: "session=BBB"
      identity: user_b
      roles: ["member"]
      tenant: acme
```

Two authenticated contexts enable BOLA detection; one is enough for the
broken-access and enforcement checks. Header-based auth works with the new
fields left empty. The extra fields attach each context to the application
model (`Identity` with `auth_headers`, `Role`, `Tenant`) and flow into
finding attribution (`Finding.identity/tenant`) and the tenant-aware
engines of later phases. Rotate the placeholder secrets per
engagement — they stay in your local config and are redacted from evidence
and reports.

What gets probed: endpoints typed `admin`/`api`/`authentication`, plus any
endpoint carrying an identifier-like parameter (`id, uuid, uid, user_id,
account_id, order_id, email, username, …`), IDOR-param endpoints first, capped
by `validation.differential_max_endpoints`.

### Automated login (agent Phase 2)

When static cookies aren't available, the login engine mints sessions
itself. Configure under `auth.login` (disabled by default):

```yaml
auth:
  login:
    enabled: true
    url: "https://target.example/login"
    username_field: username
    password_field: password
    submit: "button[type=submit]"
    success_url_contains: "/dashboard"
    identities:
      - name: user_a          # must match a context name above
        username: alice@example.com
        password_env: USER_A_PASSWORD   # env var, never this file
        roles: ["member"]
        tenant: acme
```

Behavior: for each login identity whose context exists **and has no
headers yet**, Chromium fills the form, submits, and verifies logout is
gone. Success → cookies captured into a session, context enriched,
persisted under `sessions/`. MFA challenge → persisted
`mfa_<name>.json` checkpoint for manual completion, never bypassed or
auto-retried. Missing password env, out-of-scope URL, or absent
Playwright → logged skip. No login automation runs unless you opt in.

### Auth sessions, JWT, OAuth/OIDC (passive)

- `auth/sessions.py`: `AuthSession` records (cookies/headers/tokens,
  expiry windows) with refresh-token rotation and secret-redacted
  persistence; `SessionStore` creates, refreshes, prunes, and reloads.
- `auth/jwt.py`: decodes tokens and models claims (alg, iss, aud, exp,
  nbf, iat, kid, privilege-adjacent claims). Observations only —
  active JWT attacks arrive in a later phase with behavioral evidence.
- `auth/oauth.py`: PKCE pairs (RFC 7636 S256), authorize-URL builder,
  single-use authorization-code tracking (reuse flagged), and
  token-leakage detection over recorded traffic (codes/tokens leaving
  first-party hosts).
- `auth/oidc.py`: discovery-document fetch, passive issuer checks,
  nonce issue/consume with replay detection, ID-token parsing.
- `auth/identities.py`: `Permission` model + `IdentityRegistry`
  (identity → roles → permissions, tenant checks) feeding later
  authorization work.

---

## OAST setup (Interactsh)

Blind SSRF/RCE/XXE produce no in-band signal, so candidates are fired with a
unique, per-request Interactsh callback hostname and the provider is polled for
DNS/HTTP/SMTP interactions (`validation/oast.py`).

- **Public (default):** `server: "oast.pro"`, `api_base: null` → Apex starts
  the official `interactsh-client`, reads its generated callback payload, and
  consumes its JSONL interaction output. It needs no ProjectDiscovery API key.
  If registration fails on the selected public server, Apex retries the other
  default (`oast.live` / `oast.pro`). Install the binary with
  `apex-fuzzer --update`; if it is missing, public OAST is marked unavailable
  rather than falling back to the legacy empty registration request.
- **Self-hosted:** point `server` at your Interactsh callback domain and set
  `api_base` to its custom REST endpoint to use the compatibility REST path.
  When `api_base` is `null`, the official client is used for public or
  self-hosted servers it can address directly.
- **Local static collector:** pass `--oast-callback-url
  http://localhost:9001` for a simple HTTP collector exposing a JSON `/_log`
  endpoint (such as the SSRF lab). This uses unique path tokens and avoids
  Interactsh registration. The target scan should include an endpoint URL with
  a URL-like parameter; a root page with route names shown only as text is not
  enough for endpoint discovery.

Interactsh probes use fresh HTTP and HTTPS callback hosts. Each uses a
provider-compatible nonce in the registered correlation label; static
collectors use a unique path nonce and their configured scheme (the lab's
collector is HTTP). The scanner matches that per-request nonce, retains the
request method and shape, and records status/length differences as
inconclusive signals when no callback arrives. It does not request cloud
metadata or credential endpoints. The official client is interrupted and
deregisters its session after the scan; the explicit custom-REST compatibility
path uses `DELETE /deregister/{uuid}`.

---

## Stage reference

### 1. Recon → `raw.txt`

Runs ParamSpider (if `~/ParamSpider/paramspider.py` exists), `waybackurls`,
`gauplus -subs`, `hakrawler -d 3 -subs`, `katana -d 3` concurrently, merges
stdout files, drops non-`http` lines and `crawl_exclude_exts` extensions.
`robots.txt` Disallows and up to 5 sitemaps are harvested into the same pool.

### 2. Endpoint build → `endpoints.jsonl`

URLs are normalized (`discovery/url_normalizer.py`: lowercase host, default-port
stripping, `//` collapse, trailing-slash trim, sorted query) and deduped into
`Endpoint` objects with query params from the URL. First-party `.js` URLs are
fetched (cached under `cache/`) and mined for endpoints; source maps are
fetched and **deep-parsed** — `sourcesContent` yields unminified endpoints,
params, and secrets, `sources` yields internal module paths.

With `browser.enabled` (`--browser`, deep profile), Chromium crawls
same-host GET navigations (bounded by `max_pages`/`max_depth`/budget),
records traffic, and merges discovered requests, form actions/inputs,
and WebSocket URLs into the same endpoint pool (`source: ["browser"]`,
params `probable`, form inputs `possible`). Cookies, web storage, and
extracted tokens export to `sessions/browser.json`; auth contexts
declaring `storage_state` files get their Cookie headers filled before
validation. Without Playwright installed the stage logs a skip.

### 3. API-spec discovery → `api_specs.json`

Probes well-known spec locations for OpenAPI/Swagger documents and adds each
documented operation as an `endpoint_type: api` Endpoint with its declared
parameters (`source: ["api_spec"]`).

### 4. Mapping → `technologies.jsonl`, updated `endpoints.jsonl`

- Up to 30 GET endpoints are fetched: header/HTML/cookie tech fingerprinting,
  HTML form parameter harvesting.
- JS-bundle tech signals (frameworks, auth SDKs, cloud SDKs) are merged in.
- Every endpoint is classified (`api, graphql, authentication, admin, upload,
  download, export, import, redirect, webhook, callback, proxy, static, page,
  unknown`) and tagged with detected technologies.
- WAF is fingerprinted from headers (Cloudflare `cf-ray`, Sucuri, Akamai,
  F5, Imperva, Wallarm, ModSecurity, AWS WAF) into `metrics.waf_detected`.
- **Arjun mining** (`discovery/param_miner.py`): eligible `api`/`page`/
  `authentication` endpoints (param-bearing first, capped by
  `arjun_max_endpoints`) are mined per method; new params are merged with
  `source: ["arjun"]`, `confidence: probable`. Skipped with a log line when
  the binary is absent. Optional LinkFinder pass attaches passive JS params.

### 4b. Application model + graph → `application.json`, `application_graph.json`

Right after mapping, the orchestrator builds the incremental `Application`
(endpoints, technologies, identities from auth contexts, resources from
identifier parameters) and its graph skeleton (hosts, endpoints, params,
techs, identities→roles→tenants, resources `EXPOSED_BY` endpoints). Both
persist to disk and to checkpoint blobs, so `--resume` reloads instead of
rebuilding. Empty `attack_chains.jsonl` is created as a stable placeholder
for the Phase 9 chain engine.

### 5. Live probe → `live.txt`

`httpx -silent -mc 200,204,301,302,401,403,405,500,502,503,504 -l raw.txt`.
Falls back to `raw.txt` verbatim when `httpx` is missing.

### 6. Subdomain takeover → `takeover.txt`, `tko.csv`

Unique in-scope hostnames go to `hosts.txt`. With the `deep` profile (or
`tko-subs` present), `tko-subs -domains … -output tko.csv` runs; if
`GITHUB_TOKEN` is set it adds `-takeover` with the Heroku/GitHub flags for
**confirmed** claims. `tko.csv` (`Domain,CNAME,Provider,IsVulnerable,
IsTakenOver,Response`) becomes findings: `IsTakenOver=true` →
`severity high, validation confirmed`; fingerprint-only hits → strong
candidates. Otherwise (or additionally) `subzy run --hide_fails --https`
runs detection-only.

### 7. Nuclei → `nuclei.jsonl`, `findings.jsonl`

Runs community templates **plus** `nuclei.bb_templates_dir` when present,
with `-dast`, configured rate limit, JSONL output. Optional `-workflow` mode.
Findings are parsed into `Finding` objects, deduped by
`template-id::path::param` root-cause key (keeping highest severity),
filtered to scope. AI-generated gate templates run separately into
`nuclei-ai.jsonl` (`ai-templates/`).

### 8. Validation → updated `findings.jsonl`, `proofs/`

Four layers, in order:

1. **Differential auth-context testing** → BOLA/IDOR and broken-access
   findings (`source: differential`, high severity, strong candidates).
2. **OAST sweep** → SSRF-suspect endpoints (proxy/webhook/callback/
   import/export/download/api types with URL-like params) fired with
   callback + cloud payloads → confirmed findings (`source: oast-sweep`).
3. **Per-finding plugins** (§48): the `sqli-mutation → sqli-sqlmap →
   xss-mutation → xss-dalfox → ssrf-oast` chain runs through the plugin
   registry. Each plugin returns a `TestResult`; the orchestrator maps it
   onto the finding with the same overwrite semantics as the old direct
   loop (prescreen first, heavy tool still runs and wins). Unsuitable
   plugins yield `skipped`, exceptions are contained as `error` (the
   finding is left untouched instead of failing the target). Outcomes
   feed the coverage tracker per test class.
4. Metrics (`validation_candidates`, `validated_confirmed`,
   `false_positives`, `differential_*`, `oast_*`,
   `authorization_tests/confirmed`, `second_order_tests/candidates`)
   and checkpoint blobs (`coverage`, `budgets`) updated throughout.

### 8b. Authorization matrix → `authorization_matrix.json`

With `authorization.enabled` (or the deep/api/authenticated profiles) and
≥2 configured identities, each privileged/resource endpoint goes through
harvest → swap → method sweep (`authorization/harvest.py`,
`access_tests.py`, `matrix.py`):

1. **Harvest**: GET the endpoint as every identity, parse JSON responses
   for identifier-like keys — one `(endpoint, param, value, owner)` record
   per object, with the owner's response shape as baseline. All records
   join a global pool keyed by parameter name.
2. **Swap**: replay each victim object as every *other* identity; a shape
   match is graded by ownership comparison (`authz/compare.py`) before
   it can become a verdict (`source: idor-swap`) — tagged
   `tenant-isolation` when the two identities sit in different tenants:
   - **high**: an `ownership_fields` value (`owner_id`, `user_id`, …,
     configurable) agrees in both responses;
   - **medium**: identifiers agree but ownership can't be confirmed
     (reflection explicitly not ruled out — the finding says so);
   - **voided**: generic tester body (`{"ok": true}`, empty
     arrays/pagination shells) or contradictory markers (different
     object, same template) — never a finding.
   The swapped parameter itself is excluded from proof (the tester
   supplied it). Same-endpoint victims reuse the harvest baseline;
   cross-endpoint candidates establish the owner's baseline on the
   target first. Completed denials record `tested_negative` — the
   owner baseline was 200 and the tester request finished, so the
   negative is genuine.
3. **Method sweep**: request the endpoint with every configured verb as
   every identity into an `AuthorizationMatrix`; per-cell verdicts flag
   BOLA (same object, two users), BFLA (role/method gaps, anonymous denied
   but a user succeeds on privileged endpoints), and cross-tenant reads
   (`source: authz-matrix`). Clean cells record `tested_negative`.

Swap findings carry their invariant evaluation (`no_cross_user_read`)
as corroboration in evidence — the swap verdict stays primary, so
nothing is double-reported. Both baselines ship redacted
(owner/ tester snippets in `raw.swap`). Method-level BFLA cells keep
shape comparison (observations carry no bodies by design) with the
shared-template warning in every FP note.

### Phase 7 views (same stage, no new requests)

`apex_fuzzer/authz/` replays the recorded data four ways into
`authorization_matrix.json` (`extended` + `views` keys, additive —
old artifacts still load):

- **Extended matrix** (`authz/matrix.py`): every tested cell with an
  explicit identity × role × tenant × resource × endpoint × method
  status in coverage vocabulary (`negative` renders as
  `tested_negative`); this is the legacy coverage view of canonical
  result outcomes.
- **Roles** (`authz/roles.py`): per-role endpoint×method access map
  plus vertical-escalation analysis (non-privileged role receiving
  the same 200 object as an admin role).
- **Tenants** (`authz/tenants.py`): owned resources per tenant from
  harvest ownership (never tester-biased cells) plus the
  cross-tenant access list.
- **Resources** (`authz/resources.py`): per-object owner, values,
  exposing endpoints, and accessing identities.
- **Actions** (`authz/actions.py`): tested methods per endpoint and
  the configured-but-never-probed remainder.
- **Graph** (`authz/graph.py`): ownership/tenancy/exposure edges
  (`OWNS`, `CONTAINS`, `EXPOSED_BY`) for the chain engine and AI
  loop. Per-endpoint `ownership_fields` override the default
  identifier list (`owner_id`, `user_id`, `account_id`, …). Configure
  endpoint-specific replacements with `authorization.ownership_fields_by_endpoint`,
  keyed by the endpoint's exact URL or path.

### 8c. Stored-XSS correlation (opt-in: persists canaries)

With `validation.second_order` (`--second-order`, deep/validation
profiles), HTML-form endpoints are POSTed a canary carrying an *inert*
unknown tag, then render candidates are fetched and classified
(`validation/second_order.py`): inside `<script>` / event-handler /
`javascript:` URI / raw HTML → `strong_candidate` (`source:
second-order`) with inject request + render snippet as evidence;
entity-encoded → `tested_negative`; never rendered → `inconclusive`.

Stored SSRF is a separate explicit opt-in with
`validation.second_order_ssrf: true`. OpenAPI operation IDs, summaries,
tags, nested request schemas, content types, and query/body/header parameter
locations are retained to build realistic requests. Strong URL names (such
as `callbackUrl`) qualify directly; ambiguous names (such as `file` or
`path`) qualify only when route or operation metadata describes a fetch-like
action. Mutating POST/PUT/PATCH operations are submitted in their documented
JSON or form shape. Bounded GET triggers are ranked by shared resource paths
and processing/result semantics; `{id}` routes are filled from response IDs
or `Location` headers. Only in-scope routes are called. A unique Interactsh
callback confirms a server-side fetch; it does not prove internal-resource
access. No internal addresses or metadata URLs are requested. No callback
is `inconclusive` because asynchronous workers may run later. Preflight
accounts for injection and trigger requests.

### 8d. Business-logic mutations (opt-in: submits abuse values)

With `business.enabled` (`--business-logic`, deep/validation profiles),
transactional parameters (quantities, prices, refund pairs, single-use
tokens) receive boundary/abuse values (`logic/business_logic.py`):
`-1`/`0`/`999999` quantities and prices, absurd refunds, double-submits
of token-bearing requests. A finding needs **both** server acceptance
(HTTP 200 + mutated value echoed) **and** an invariant violation
(`logic/observations.py` translates outcomes for the invariant engine) —
a bare 200 is never enough. Non-200 baselines yield `inconclusive`,
never negatives.

Every accepted mutation then goes through **readback verification**
(`apex_fuzzer/verify/`): the mutated value is re-observed via a clean
re-read (GET endpoints), user-supplied `after_read` URLs, or sequential
double-submits (token reuse, idempotency keys). A persisted effect
upgrades the finding to `confirmed` (`verified-effect` tag); a clean
re-read proving non-persistence downgrades it to `inconclusive`;
anything unverifiable leaves the candidate exactly as produced.
POST endpoints without an `after_read` have no safe re-read
(re-POSTing would be another write) and stay unverified by design.
Optional per-workflow contracts live under `business.assertions`
(`after_read` + `jsonpath`/`rule`/`value` checks; tiny subset:
dotted paths, `[n]` indexes, one `[?(@.k == v)]` filter).

### 8e. Race engine (opt-in: synchronized bursts)

With `race.enabled` (`--race`; off in every profile), POST endpoints
fire N identical requests through a start barrier (`logic/race.py`).
The default `generic` profile preserves the all-200/divergent-ID check.
Opt-in `single_use` requires a token-like body field and verifies a race
candidate with a sequential replay; `idempotency` requires an
idempotency-key field and verifies using the same key; `inventory`
requires an endpoint selector, an in-scope read URL, and a JSONPath for
one numeric stock value. Inventory reads establish a positive baseline
and verify state afterward; only a negative balance upgrades to
`verified_effect`. Other profile outcomes stay candidate or
inconclusive. Request reservation includes two verification/readback
requests per endpoint. Budget exhaustion is `blocked`, never a negative.

### 8f. Workflow discovery (always on, zero network)

After validation, `apex_fuzzer/workflows/` infers multi-step flows
purely from collected data — no requests are sent, so this stage
always runs. Producers: REST stem grouping (collection/member
folding, CRUD-ordered steps), timestamp-ordered browser traffic
chains, CRUD linkage from resource states, and harvested value
overlap (producer→consumer 2-step flows). Every flow cites its
evidence and confidence (`observed` only for sequences that
literally happened). `mutations.py` derives bounded invalid-sequence
variants (skip/reorder/repeat/replay/prerequisite-drop/actor-change/
stale-token/invalid-transition) as test candidates for later phases
— generating a mutation claims nothing. Artifacts: `workflows.json`
(flows + mutation catalog); stored workflows append to the
application model; step chains link into the graph.

### 8g. Resource intel (always on, zero network)

Right after workflow discovery, resource records become
lifecycle-aware (`resources.json`) — composed purely from collected
data, no requests. Identifier producers: harvest pool, page
HTML/headers parsed during mapping (stashed, never refetched), the
JS bundle cache (via `.meta` source URLs), browser traffic URLs,
and OpenAPI-declared parameters (already endpoints). Each record
carries type (GraphQL `__typename` preferred over name heuristics),
identifiers, owner/tenant, permissions (identities with a 200 on an
exposing endpoint), field inventory, lifecycle state/history/CRUD,
and provenance source. Records from passive sources enrich views
and dependencies only — swap verdicts still require authenticated
responses. Shared identifier values link resource nodes
(`DEPENDS_ON`, symmetric, deterministic order).

### 9. AI → `hypotheses.jsonl`

`AIPlanner` emits structured hypotheses
(`hypothesis, endpoint, reason, test_class, confidence, required_context,
status`) — never confirmed vulns. Hosted planning uses the free Gemini
model `gemini-3.5-flash-lite` first (`GEMINI_API_KEY`), then falls back
to free-tier Groq models (`GROQ_API_KEY`) if Gemini is unavailable or
returns no content. Hosted models are restricted to documented
free-tier model IDs. Set `provider: groq` to use Groq directly, or
`provider: ollama` for local inference (needs `ollama serve` plus a
pulled model such as `llama3.1` — no key, nothing leaves the machine).
Ollama requests use JSON mode
(`format: json`) straight into the shared parser, with a longer default
timeout for local inference. Context is prompt-budgeted per part
(techs/endpoints/findings) and findings are grouped by host+class so one
noisy host can't evict the rest. Large JS bundles are analyzed per
structural chunk (`plan_js_chunk`). See
[AI planner and loop closure](#ai-planner-and-loop-closure).

### 10. Report → `report.html`, `metrics.json`, `coverage.json`

Severity-filtered HTML with Verified Effects / Candidates / Observations &
Inconclusive sections, each finding showing its canonical result status,
legacy validation label, impact, numbered reproduction steps,
false-positive notes, curl one-liner, and direct evidence-file links; a
Coverage section naming tested vs explicitly untested attack classes; plus
a hypotheses section split into validated-vs-pending.

---

## Validation semantics

Canonical `Finding.result_status` and `TestResult.result_status` use five
evidence outcomes:

| Canonical result | Meaning | Legacy `validation_status` | Coverage status |
|------------------|---------|---------------------------|-----------------|
| `observation` | Signal recorded, no vulnerability verdict yet | `not_tested` | `not_tested` |
| `candidate` | Evidence suggests a security effect, not verified | `strong_candidate` | `candidate` |
| `verified_effect` | Required behavioral effect was verified | `confirmed` | `confirmed` |
| `negative` | Preconditions held and the completed probe found no effect | `false_positive` | `tested_negative` |
| `inconclusive` | Probe could not distinguish the result | `inconclusive` | `inconclusive` |

The canonical field is additive. Old `findings.jsonl` records without
`result_status` are upgraded in memory from `validation_status`, and new
records continue to write the legacy field for existing consumers. Plugin
execution states (`blocked`, `skipped`, `error`) stay in `TestResult.status`;
they are not vulnerability outcomes and cannot map to `negative`.
`metrics.json` includes final finding counts by canonical result status.
`confidence`: `unknown | possible | probable | confirmed`.

| engine | strong_candidate when | confirmed when |
|--------|----------------------|----------------|
| differential | two users, both 200, same shape/hash; or anonymous 200 on admin/api | — (stays candidate, needs id-swap proof) |
| OAST sweep / SsrfValidator | — | unique callback token observed inbound |
| mutation SQLi prescreen | DB error marker reflected | ≥4 s delay on SLEEP/BENCHMARK payload vs baseline |
| mutation XSS prescreen | payload reflected unfiltered | — |
| sqlmap | — | "is vulnerable" / "available databases" in output |
| dalfox | "verified"/"PoC" in output | — |
| idor-swap (same + cross-endpoint) | victim object served to another identity, same shape | — (swap proves access; impact confirmed by human) |
| authz-matrix BFLA | method treats roles/tenants identically (200s match) | — |
| business-logic | abuse value accepted (echoed, 200) **and** invariant violated | clean re-read shows the mutated value persisted (`verified-effect`) |
| stored-XSS | inert canary persists and renders unescaped in active sink | — (confirm script execution manually) |
| race | synchronized burst all-200 with divergent object IDs | sequential idempotency re-check accepts twice with different objects |

Healthy authorization (user A 200 / user B 401-403, or anonymous blocked while
an authenticated user succeeds) yields `inconclusive` with an explanatory
note. sqlmap "not injectable" maps to `false_positive`.

---

## WAF-aware mutation engine

`validation/mutate.py` selects a payload ladder per fingerprinted WAF
(Cloudflare, Sucuri, Akamai, F5 BIG-IP, Imperva, AWS, Wallarm, ModSecurity;
unknown WAFs get the default order):

- **SQLi** (8): classic `' OR '1'='1`, comment-obfuscated `/**/OR/**/`,
  `+`-joined, URL-encoded, MySQL version-comment `/*!50000UNION*/`, UNION and
  SLEEP time-based variants.
- **XSS** (6): script, img-onerror, javascript-URI, svg-onload,
  URL-encoded, nested-tag `<scr<script>ipt>`.

The prescreen runs before sqlmap/dalfox so WAF-blocked targets still get a
cheap signal, and its outcome (payload, WAF, response tail) is stored as
evidence. SQL error markers cover MySQL/MariaDB, PostgreSQL, SQLite, Oracle,
ODBC, and generic syntax errors.

---

## AI planner and loop closure

Hypotheses are routed back into deterministic tests
(`Orchestrator._validate_hypotheses`, capped by `ai.max_hypothesis_tests`
per class, highest confidence first):

| test_class | deterministic test |
|------------|-------------------|
| `ssrf` | Interactsh OAST probe → `ai+oast` finding on callback |
| `sqli` | mutation prescreen → sqlmap fallback → `ai+sqli` finding |
| `xss` | mutation prescreen → dalfox fallback → `ai+xss` finding |
| `idor` / `authz` / `bola` | differential probe → `ai+differential` finding |
| anything else (`ssti`, `xxe`, traversal, …) | generated Nuclei gate template; a match promotes the hypothesis → `ai+nuclei-gate` finding |

Outcomes update the hypothesis in place: `validated` (with notes), `rejected`
(no signal), or `inconclusive`. Untestable hypotheses keep `hypothesized` and
render as pending — never as findings.

---

## Browser-driven discovery (agent Phase 1)

With `browser.enabled` (`--browser`, deep profile; needs
`pip install "apex-fuzzer[browser]"`), Chromium crawls the target with
GET navigations only — nothing state-changing:

- **Lifecycle** (`browser/browser.py`): headless launch, per-scan
  contexts, graceful skip when Playwright/Chromium is absent.
- **Network** (`browser/network.py`): request/response interception,
  WebSocket URL discovery, conversion of recorded traffic into endpoint
  dicts merged into the normal pipeline (`source: ["browser"]`).
- **DOM** (`browser/actions.py`): form/link/script/iframe snapshots;
  form actions become endpoints with `body_parameters`, methods upgraded
  from the form's method. Fill/click/js primitives plus an action log.
- **Storage** (`browser/storage.py`): cookies, localStorage,
  sessionStorage, JWT/bearer/CSRF-token extraction.
- **Sessions** (`browser/sessions.py`): capture → `BrowserSession`
  → `Identity` (Cookie/Authorization headers) reused straight through
  `_HTTPClient`, differential testing, and the authz matrix.
  Storage-state files declared in auth contexts are imported the same
  way (static headers always win). Login-redirect/logout heuristics
  included.
- **Workflows** (`browser/workflows.py`): recordable goto/fill/click/
  wait step lists (e.g. login), replayable per identity with per-step
  results — failures stop the chain instead of crashing.

Crawl bounds (`max_pages`, `max_depth`), navigation timeouts, the
`browser_actions` budget, and scope checks apply to every navigation.
Artifacts: `browser_urls.txt`, `browser_traffic.json`,
`sessions/browser.json`, `metrics.browser_pages/browser_requests`.

---

## Output files

Per target, `output/<host>/`:

| file | contents |
|------|----------|
| `raw.txt` | merged in-scope + out-of-scope recon URLs |
| `param.txt`, `wayback.txt`, `gau.txt`, `hakrawler.txt`, `katana.txt` | per-tool recon stdout |
| `robots.txt.out`, `sitemap.txt` | robots/sitemap harvest |
| `hosts.txt` | unique in-scope hostnames for takeover checks |
| `endpoints.jsonl` | one `Endpoint` per line (final, post-mapping + Arjun) |
| `technologies.jsonl` | fingerprinted tech with evidence + category |
| `js_analysis.jsonl` | per-bundle endpoints/params/secrets/source-maps/techs |
| `api_specs.json` | discovered specs (when found) |
| `arjun/` | per-endpoint Arjun JSON output |
| `cache/` | fetched JS + HTTP cache |
| `live.txt` | httpx-confirmed live URLs |
| `takeover.txt`, `tko.csv` | takeover tool output |
| `nuclei.jsonl`, `nuclei-ai.jsonl` | raw Nuclei JSONL |
| `ai-templates/` | generated gate templates |
| `browser_urls.txt` | in-scope URLs visited by Chromium |
| `browser_traffic.json` | recorded browser requests + websockets |
| `sessions/browser.json` | exported browser session (cookies/tokens) |
| `findings.jsonl` | final deduped findings |
| `hypotheses.jsonl` | AI hypotheses with validation status |
| `application.json` | incremental application model (Phase 1) |
| `application_graph.json` | persisted application graph (Phase 1) |
| `coverage.json` | per-class test coverage (Phase 1) |
| `authorization_matrix.json` | authz observations per identity×method |
| `workflows.json` | discovered flows + mutation catalog (Phase 4) |
| `resources.json` | lifecycle-aware resource records (Phase 5) |
| `state/snapshots.jsonl` | point-in-time behavior snapshots (Phase 3) |
| `state/transitions.jsonl` | observed cross-run cell changes (Phase 3) |
| `attack_chains.jsonl` | attack chains (schema only until Phase 9) |
| `state/` | checkpoint blobs (application, graph, coverage, budgets) |
| `proofs/finding-NNN/` | `request.txt`, `response.txt`, `metadata.json` |
| `metrics.json` | coverage + validation counters |
| `report.html` | triage-ready report |
| `scan.log`, `checkpoint.json` | logs, resume state |

`metrics.json` keys: `urls_discovered, unique_endpoints,
parameters_discovered, arjun_params_found, arjun_endpoints_mined,
js_files_analyzed, source_maps_found, technologies_detected, live_hosts,
nuclei_findings, nuclei_findings_after_dedup, validation_candidates,
validated_confirmed, false_positives, differential_probes,
differential_candidates, oast_endpoints_probed, oast_confirmed,
takeover_confirmed, hypotheses_generated, hypotheses_validated,
waf_detected, resources_discovered, identities_tested, roles_tested,
tenants_tested, authorization_tests, authorization_confirmed,
second_order_tests, second_order_candidates,
business_logic_tests, business_logic_candidates,
race_tests, race_candidates,
invariants_tested, invariants_violated,
effects_verified,
logins_attempted, logins_succeeded,
graph_nodes, graph_edges,
workflows_discovered,
scan_duration_seconds`.

(`stage_durations` exists in the schema but is currently unpopulated —
reserved for per-stage timing.)

---

## Data models

`apex_fuzzer/models.py` — dataclasses with `to_dict`/`from_dict` (unknown
JSONL keys are ignored on load, so old artifacts stay readable):

- **`Parameter`**: `name, location` (query/body/header), `source` (url, html,
  html:hidden, javascript, api_spec, arjun, linkfinder, sourcemap,
  validation), `sample_value`, `confidence`.
- **`Endpoint`**: `url, normalized_url, method, host, path`,
  `query_parameters, body_parameters, headers, content_type, source`,
  `authentication_required, technology[]`, `endpoint_type`, `status_code,
  response_size`. Types: page, api, graphql, upload, download, redirect,
  webhook, callback, authentication, admin, export, import, proxy, static,
  unknown.
- **`Technology`**: `name, version, confidence, evidence[]`, `category`
  (server, frontend, gateway, auth, cloud, waf, other) — drives test gating.
- **`Finding`**: identity (`id, source, template_id`), `name, severity,
  confidence, canonical `result_status`, backward-compatible
  `validation_status`, location (`host, matched_at, endpoint_url,
  parameter, method`), traffic (`request_headers/body, response_status/
  headers/snippet`), triage (`impact, reproduction_steps,
  false_positive_notes, reproduction, description, tags`), attribution
  (`identity, tenant, resource_key`), `evidence_dir`,
  `raw`, `root_cause_key`.
- **`Hypothesis`**: `hypothesis, endpoint, reason, test_class, confidence,
  required_context, status, notes`, plus the evidence contract
  (`expected_signal, required_evidence, observation`).
- **`Identity` / `Role` / `Tenant`**: testable users, permission sets,
  tenant boundaries (`application/identities.py` builds them from
  `auth.contexts`).
- **`Resource`**: server-side object with stable `key`
  (`<endpoint>::<location>:<param>`), `resource_type`, `identifiers`,
  `owner`, `tenant`, `exposed_by`.
- **`TestResult`**: plugin outcome — legacy `status` plus canonical
  `result_status` (observation | candidate | verified_effect | negative |
  inconclusive), `evidence`, `observations`, `errors`, `requests_used`,
  `duration_seconds`. Execution states (`blocked`, `skipped`, `error`) have
  no canonical result status and are never mapped to vulnerability negatives.
- **`AttackChain`**: finding-sequence schema (`nodes, edges, evidence,
  impact, confidence`) — populated by the Phase 9 chain engine.

---

## Application model and graph (Phase 1)

`application/application_model.py` builds an `Application` incrementally —
endpoints + technologies after mapping, identities from auth contexts,
resources from identifier parameters, workflows/sessions/findings appended
by later phases. It never requires perfect knowledge before testing begins.
Persisted to `application.json` (and checkpoint blobs, so `--resume`
reloads instead of rebuilding).

`graph/application_graph.py` persists the structural skeleton to
`application_graph.json`. Node types: domain, host, service, endpoint,
parameter, technology, identity, role, tenant, resource, workflow, session,
secret, finding — plus Phase 3 behavioral types: state, transition,
request, response, observation, token, resource_field, workflow_step.
Edge types: HOSTS, CALLS, AUTHENTICATES_TO, OWNS,
BELONGS_TO, CAN_ACCESS, READS, WRITES, CREATES, DELETES, REDIRECTS_TO,
FETCHES, USES, GENERATES, DEPENDS_ON, LEADS_TO, EXPOSED_BY, CONTAINS —
plus Phase 3: AUTHENTICATED_AS, UPDATES, TRANSITIONS, PRECEDES,
REQUIRES, PRODUCES, CONSUMES, TRIGGERS, STORES, RENDERS, INVALIDATES,
REQUIRES_STATE, CHANGES_STATE.
Query helpers: `neighbors()`, `nodes_of_type()`,
`endpoints_exposing_resource()`, `resources_of_tenant()`.

## Application state graph (agent Phase 3)

`apex_fuzzer/state/` builds behavior onto the structural graph — same
`ApplicationGraph` store, no parallel implementation:

- **`graph.py`**: observation → edge builders. Every tested
  (identity × endpoint × method) cell becomes an observation node;
  HTTP 200s add `CAN_ACCESS` (+ `READS`/`WRITES`), denials add no
  access edge. Workflow step lists link via `PRECEDES`.
- **`snapshots.py`**: point-in-time captures (identity, endpoint,
  method, status, shape, cookie/storage digests) persisted to
  `state/snapshots.jsonl` — facts, never verdicts.
- **`transitions.py`**: before → after links recorded only when a
  resumed scan observably changes a cell; `state/transitions.jsonl`
  plus `TRANSITIONS` graph edges.
- **`diff.py`**: pure snapshot/graph diffs — the comparison primitive
  the Phase 22 regression engine builds on.
- **`resources.py`**: per-object lifecycle state + history + CRUD
  endpoint linkage (`state/resources.jsonl` when wired).
- **`lifecycle.py`**: explicit allow/deny/inconclusive transition
  rules (generic CRUD, order, invitation defaults). Unknown states
  are inconclusive, never violations.

The authz-matrix probe syncs its observations, snapshots, and
transitions automatically; the graph re-saves after validation with
`metrics.graph_nodes/graph_edges`. Later phases append workflow
discovery (Phase 4), CAN_ACCESS from richer matrices (Phase 7), and
chain edges (Phase 19) against this schema.

## Security invariants (Phase 1 + 6)

`logic/invariants.py` evaluates named predicates over normalized
observations. Built-ins (`default_invariants()`, twelve checks):
cross-user read, unauthorized write, modify-deleted, self-promotion,
negative quantity, unauthorized price change, refund-exceeds-payment,
single-use token reuse, revert-completed, plus deleted-access,
expired-session, and recharge-after-refund. Custom checks register via
`register_check(name, fn)`; `evaluate()` / `evaluate_all()` return
`InvariantResult(violated, detail)`. Invariant `params` act as
central scope filters (`resource`, `endpoint`, `actor`, `tenant`) —
out-of-scope observations report the skip explicitly instead of
silently passing. Observation producers are wired
for swap matches (attached to findings as corroboration), business-logic
mutations, race outcomes (`logic/observations.py`), and matrix cells.

`logic/invariant_engine.py` centralizes evaluation with a complete
log (violations and holds), per-invariant summary, and persistence.
`logic/invariant_discovery.py` mines holding rules from matrix
observations — only with consistent enforcement evidence (≥2
identities, ≥1 denial, no shared object); anything less emits
nothing.

### 8h. Invariant discovery (always on, zero network)

After resource intel, discovered holdings are re-evaluated as a
second opinion over the same observations: a firing holding with an
existing finding in the mapped classes (BOLA/IDOR/authz/…) attaches
as corroboration — never a duplicate; a firing holding with no such
finding becomes a new `source: invariant` strong candidate with the
mapped classes recorded as candidate coverage. Artifacts:
`invariants.json` (discovered rules + engine summary).

## Coverage model (Phase 1)

`reporting/coverage.py` tracks every detection class as exactly one of
`confirmed | candidate | tested_negative | inconclusive | blocked |
untestable | not_tested | not_applicable` (merge precedence in that
order). Only observed evidence moves a class: a probed endpoint with no
signal is `tested_negative`; untouched classes stay `not_tested`; budget
exhaustion records `blocked` — never a negative. Persisted to
`coverage.json`, resumable via checkpoint blobs, and rendered as a
Coverage section in the report that names untested classes explicitly
instead of implying they are secure. Known classes cover the §61
detection list (sqli … takeover, plus tenant_isolation).

## Budgets (Phase 1)

`budgets.py` `BudgetTracker` enforces `budgets.requests_per_host` (10k),
`requests_per_endpoint` (100), `authz_tests_per_endpoint` (20),
`browser_actions` (500), `ai_experiments` (50). Every direct HTTP request
is counted in `_HTTPClient`; over-budget requests raise `BudgetExceeded`,
which probing loops translate to `blocked` coverage. Differential and
OAST sweeps pre-check their per-endpoint test budget before firing.
Defaults only bite runaway loops — normal scans stay an order of magnitude
below every cap.

## Safety gates and execution controls (Milestone 1)

`apex_fuzzer/safety/` makes aggressive testing opt-in provable:

| Module | Traffic mode | Could change state? | Default | Extra authorization |
|---|---|---:|---:|---|
| Discovery / mapping / probe / browser | Read-only | No | Enabled by profile | No |
| Nuclei / differential / OAST / validators | Active | No | Varies | No (recommended) |
| Authz-matrix / stored-XSS / business-logic / login | Stateful | Yes | Opt-in | Required in strict mode |
| Race engine | Burst | Yes | Off | Required in strict mode |
| Takeover claiming | Claiming | Yes (external) | Off | Required in strict mode |

- **Strict mode** (`--strict` / `safety.strict`): stateful/burst/claiming
  modules fail closed *before any network activity* unless an
  authorization reference (`--auth-ref`), an explicit acknowledgment
  (`--ack-state-change`), an allowlisted target (domains or literal-IP
  CIDRs — hostnames are never DNS-resolved for matching), a valid time
  window, and a module allowlist entry are all present. Refusal prints
  every unmet condition and exits **2** (0 = completed, 1 = failure).
  Default scans are unchanged; strict adds gates only.
- **Dry-run** (`--dry-run`): resolves modules, impact level, and
  authorization, then prints worst-case request costs per stateful
  module (upper bounds from config caps, or concrete counts from a
  prior `endpoints.jsonl`) plus budget fit — sending zero requests.
- **Cost reservation**: each sweep reserves its worst-case plan
  (`RequestPlan`: baseline + mutation + burst + verification) before
  firing; unaffordable sweeps record `blocked`, never `negative`.
- **Circuit breakers**: `--max-requests` (global cap),
  `--max-state-changes` (POST/PUT/PATCH/DELETE cap),
  `--stop-on-candidate` (halt remaining sweeps after the first strong
  candidate — untested work stays `not_tested`),
  `--cooldown-ms` (delay between stateful probes). SIGINT/SIGTERM
  halts sweeps and finishes the stage so partial results are kept.
- Reports carry an authorization metadata block (reference identifiers
  only — never document content, never secrets).

## Milestone 3 — reliability and CI

- **Provider hardening** (`ai/planner.py`): `raise_for_status()`
  before every JSON parse, errors classified (auth / timeout /
  connection / malformed / rate-limit / server / unknown) with
  bodies truncated to 300 chars in logs, retries for transient
  HTTP statuses only (429/502/503/504, max 3 attempts) — timeouts
  and connection failures fail fast, and stateful target requests
  are never auto-retried by this path (it only calls AI APIs).
- **Provider config**: `ai.gemini.*` / `ai.ollama.*` blocks override
  the legacy flat keys (`model`, `ollama_host`, …), which keep
  working. Unknown providers fail clearly at startup validation
  (`AIPlanner.validate_config()`), never mid-scan.
- **CI** (`.github/workflows/ci.yml`): ruff (F/E9 subset), mypy on
  the gated scope (`safety/`, `verify/`, `budgets.py`, `ai/` —
  ratchets outward), pytest matrix (3.10/3.12) with a 70% coverage
  floor (measured baseline 73%), pip-audit, gitleaks on full
  history, wheel/sdist build + clean install check.
- **Local gates**: `make test|lint|typecheck|security|build|ci`,
  `.pre-commit-config.yaml` (ruff, mypy-scoped, gitleaks),
  `requirements.lock` (`make lock`), `--doctor` now also validates
  config parsing, credentials presence, module prerequisites
  (strict-without-auth, login-without-browser, missing login
  passwords), and output-dir writability — still zero network.

## Plugin architecture (Phase 1)

`plugins/base.py` defines `SecurityTest` (`name`,
`supported_endpoint_types`, `prerequisites`, `run() → TestResult`),
`TestTarget`, `TestContext`, a registry, and `run_plugins()` (ordered
execution; unsuitable plugins yield `skipped`, exceptions are contained as
`error`). Prerequisite tokens: `tool:<binary>`, `oast`, `auth:N`,
`tech:<name>`, `net`. `plugins/adapters.py` wraps the existing engines
(`sqli-mutation`, `sqli-sqlmap`, `xss-mutation`, `xss-dalfox`,
`ssrf-oast`) with identical overwrite semantics to the pre-plugin loop
(prescreen first, heavy tool still runs and wins). New scanners land as a
new file plus one `register()` line — no orchestrator surgery.

---

## Scope enforcement

`Scope` (`apex_fuzzer/scope.py`) is consulted on every URL the pipeline
emits, probes, or reports:

- scheme must be http/https; `excluded_hosts` and `excluded_paths` (prefix)
  always win;
- empty `allowed_domains` on first run auto-seeds the target host (subdomains
  included when `allow_subdomains`); otherwise exact-or-subdomain match only;
- `active_test_allowed` additionally blocks `active_test_exclude_exts`
  (images, fonts, media, archives) from Arjun, differential, and OAST probes.

Subprocess execution (`apex_fuzzer/shell.py`) takes argv arrays only (string
commands raise `TypeError`), with per-call timeouts and structured results.

---

## Evidence and secret redaction

Each validated finding gets `proofs/finding-NNN/` with the redacted request,
response (or validator notes), and `metadata.json` (timestamp, finding id,
URL, method, severity, status, confidence, template, response status —
`set-cookie` stripped from stored headers). `shell.redact` masks
`authorization/cookie/set-cookie/x-api-key/…` headers and
`api_key/token/secret/password/bearer` assignments in all tool output before
it touches disk or the report. Reproduction one-liners are built from the
stored request (`validation/evidence.py:build_reproduction`).

---

## Rate limiting

Static `scan.rate_limit` drives Nuclei `-rl` and recon tools. All **direct**
HTTP (mapping fetches, differential probes, OAST fires, mutation prescreens)
goes through `AdaptiveRateLimiter` at `rate_limit/10` req/s baseline: each
429/503 halves the rate and applies an exponential cooldown (2s, 4s, 8s…,
capped at 300 s); clean responses recover geometrically. Prevents scanner
self-DoS and the false negatives that timeouts masquerade as.

---

## Running the tests

```bash
.venv/bin/python -m pytest tests/ -q     # or: make test
make ci                                  # lint + types + tests + security + build
```

Last full local run: 357 passed, 4 skipped (361 collected) after the
first-order OAST hardening. Tests cover per-probe HTTP/HTTPS canaries,
stale-callback rejection, response-difference notes, OpenAPI operation
metadata and request locations, nested-schema sink scoring, related trigger
selection and response-ID substitution, URL normalization, endpoint
classification, parameter extraction
(URL/HTML/JS), scope rules, secret redaction, plus v5.2 coverage — Arjun JSON
parsing, WAF fingerprinting, JS-bundle tech gating, structural JS chunking,
source-map parsing, differential verdicts (BOLA / broken-access / healthy /
volatile-key immunity), mutation ordering and error signals, OAST
candidate filtering and correlation, AI template generation, limiter
backoff/recovery, and auth/OAST config parsing — plus Phase 1 foundation:
application/graph models, invariants, coverage precedence, budgets,
checkpoint blobs, plugin registry/prerequisites, and orchestrator wiring —
plus bounty engines (authz swap/BFLA, stored XSS, business logic, race),
Ollama backend, dotenv handling, browser/session engine, and auth
workflows (login, sessions, JWT/OAuth/OIDC passive), and state graph
(snapshots, transitions, diffs, resource states, lifecycles).

---

## Tool dependency matrix

| tool | used for | when missing |
|------|----------|--------------|
| ParamSpider | recon params | skipped silently |
| waybackurls / gauplus / hakrawler / katana | recon | skipped individually |
| httpx | live probe | `raw.txt` used as live set |
| subzy | takeover fingerprint | skipped |
| tko-subs | confirmed takeover | subzy path only |
| nuclei + templates | DAST | stage returns no findings |
| arjun | hidden params | mapping logs skip |
| linkfinder | passive JS params | skipped |
| sqlmap / dalfox | SQLi / XSS validation | mutation prescreen only |
| interactsh (oast.pro/live or self-hosted) | OAST | SSRF stays unconfirmed |
| go | toolchain for `--update` installs | informational |
| uro | version-checked by `--doctor` only; not invoked by the pipeline | informational |

---

## Project structure

```
apex_fuzzer/
  orchestrator.py        10-stage pipeline, AI loop closure
  cli.py                 argparse, --doctor, --update
  config.py              Scan/Discovery/Validation/Budgets/Oast/Nuclei/AI/Auth/Reporting/Scope
  profiles.py            passive · standard · deep · api · authenticated · validation
  models.py              Endpoint · Parameter · Technology · Finding · Hypothesis
                         Identity · Role · Tenant · Resource · TestResult · AttackChain
  scope.py               in-scope / active-test rules
  shell.py               argv-only subprocess, redaction, AdaptiveRateLimiter
  budgets.py             BudgetTracker + BudgetExceeded (Phase 1)
  checkpoints.py         per-stage resume state + state blobs (Phase 1)
  logging_setup.py       colored stderr + per-target scan.log
  application/           Application model · identities · resources · workflows (Phase 1)
  graph/
    application_graph.py node/edge store, queries, JSON persistence (Phase 1)
  logic/
    invariants.py        12 checks + central scope filters (P1+P6)
    invariant_engine.py  evaluation log, summary, persist (P6)
    invariant_discovery.py  evidenced holding rules (P6)
    observations.py      invariant observation producers (stateful slice)
    business_logic.py    quantity/price/refund/replay mutations
    race.py              barrier-synchronized burst engine
  state/                 snapshots · transitions · diffs · resource
                         states · lifecycles · behavioral graph (P3)
  browser/               Chromium lifecycle · network/storage/actions ·
                         sessions · recordable workflows (agent Phase 1)
  authz/                 ownership compare · extended matrix · role/
                         tenant/resource/action views · graph sync (P7)
  safety/                impact levels · authorization gates ·
                         preflight/costs/dry-run/stop controls (M1)
  verify/                readback/idempotency/token verifiers +
                         JSONPath assertions (M2.4)
  plugins/
    base.py              SecurityTest interface, registry, run_plugins (Phase 1)
    adapters.py          sqli/xss/ssrf adapters over existing validators
  discovery/
    parameters.py        URL / HTML / JS param extraction + merge
    param_miner.py       Arjun active mining + LinkFinder passive
    javascript.py        bundle analysis, chunk_js, source-map deep parse
    technologies.py      categorized fingerprinting + WAF detect + gating
    classifier.py        endpoint-type rules
    url_normalizer.py    canonicalization + query extraction
    robots.py / api_specs.py   robots/sitemap + OpenAPI/Swagger harvest
  detection/
    nuclei.py            runner, dedup, BB templates, workflows, AI gates
  validation/
    base.py              Candidate / ValidationOutcome / Validator
    sqli.py / xss.py     sqlmap / dalfox adapters
    ssrf.py              OAST-backed SSRF validator
    oast.py              Interactsh provider + SSRF sweep helpers
    differential.py      auth-context BOLA / broken-access engine
    mutate.py            WAF fingerprint + payload mutation ladders
    evidence.py          per-finding proof dirs + curl reproduction
  auth/                  login workflows · sessions · identities ·
                         OAuth/OIDC modeling · passive JWT (agent Phase 2)
  workflows/             discovery · model · replay · mutations ·
                         dependencies (agent Phase 4, offline analysis)
  ai/planner.py          Gemini/Ollama hypotheses + JS-chunk planning
  reporting/
    html.py              triage report (impact · repro · FP notes · evidence · coverage)
    impact.py            impact / repro-step / FP-note builders
    coverage.py          per-class CoverageTracker (Phase 1)
    metrics.py           coverage + validation counters
config.yaml              annotated defaults (copy per engagement, add secrets)
tests/                   pytest suite (test_v52.py: 5.2 additions, test_phase1.py: foundation)
                         (test_bounty3.py: authz/second-order, test_stateful.py: stateful slice)
                         (test_authz.py: 14 ownership/generic-guard/views/graph tests)
                         (test_verify.py: 18 readback/idempotency/token/JSONPath/wiring tests)
                         (test_browser.py: 18 unit + 2 live-Chromium integration, test_ollama.py, test_dotenv.py)
                         (test_auth.py: 34 auth-workflow/JWT/OAuth/OIDC tests + 2 live-browser login tests)
                         (test_state.py: 13 state-graph/snapshot/transition/diff/lifecycle tests)
                         (test_invariants.py: 9 scoping/checks/engine/discovery/producer tests)
                         (test_workflows.py: 19 discovery/replay/mutation/dependency tests)
                         (test_resources.py: 12 multi-source intel/enrichment/link tests)
setup1.sh … setup8.sh    project scaffolding scripts
Makefile                 test/lint/typecheck/security/build/ci targets
.pre-commit-config.yaml  ruff + scoped mypy + gitleaks hooks
requirements.lock        pinned dev+runtime deps (`make lock`)
.github/workflows/ci.yml  lint/types/tests+coverage/audit/secrets/build
```
