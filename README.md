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
13. [Output files](#output-files)
14. [Data models](#data-models)
15. [Application model and graph (Phase 1)](#application-model-and-graph-phase-1)
16. [Security invariants (Phase 1)](#security-invariants-phase-1)
17. [Coverage model (Phase 1)](#coverage-model-phase-1)
18. [Budgets (Phase 1)](#budgets-phase-1)
19. [Plugin architecture (Phase 1)](#plugin-architecture-phase-1)
20. [Scope enforcement](#scope-enforcement)
21. [Evidence and secret redaction](#evidence-and-secret-redaction)
22. [Rate limiting](#rate-limiting)
23. [Running the tests](#running-the-tests)
24. [Tool dependency matrix](#tool-dependency-matrix)
25. [Project structure](#project-structure)

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
  │                    budgets enforced · coverage recorded per class
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

### Environment file (.env)

Secrets come from the environment, never from `config.yaml`:

```bash
cp .env.example .env   # then fill in; .env is git-ignored, never commit it
```

| variable | enables |
|----------|---------|
| `GEMINI_API_KEY` | AI hypothesis planning (`--ai`) |
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
--differential          differential auth-context tests on
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

| profile         | nuclei | validation | AI | JS | api_specs | robots | differential | arjun | oast | tko-subs |
|-----------------|--------|------------|----|----|-----------|--------|--------------|-------|------|----------|
| `passive`       | –      | –          | –  | ✓  | ✓         | ✓      | –            | –     | –    | ✓ (subzy)|
| `standard`      | ✓      | –          | –  | ✓  | ✓         | ✓      | –            | ✓     | –    | ✓ (subzy)|
| `deep`          | ✓      | –          | –  | ✓  | ✓         | ✓      | ✓            | ✓     | ✓    | ✓ (tko)  |
| `api`           | ✓      | –          | –  | ✓  | ✓         | –      | ✓            | ✓     | ✓    | ✓ (subzy)|
| `authenticated` | ✓      | –          | –  | ✓  | ✓         | ✓      | ✓            | ✓     | ✓    | ✓ (subzy)|
| `validation`    | ✓      | ✓          | –  | ✓  | ✓         | ✓      | –            | ✓     | ✓    | ✓ (subzy)|

Combine profiles with flags: `--validate`, `--ai`, `--oast`, `--differential`
force-enable the matching stage regardless of profile. Config-file keys
(`validation.enabled/differential/ssrf`, `ai.enabled`) do the same.

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
  mutation: true          # WAF-aware prescreen before sqlmap/dalfox
  mutation_payloads: 8    # ladder depth per class
  differential_max_endpoints: 30
  min_severity: medium     # reserved

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
  poll_timeout: 15
  poll_interval: 2
  max_endpoints: 10
  max_params_per_endpoint: 3

nuclei:
  bb_templates_dir: "~/nuclei-bb-templates"
  workflows: false         # -workflow -workflow-threads 3
  ai_templates: true       # run AI-generated gate templates

ai:
  enabled: false
  model: "gemini-1.5-flash"   # Generative Language API, GEMINI_API_KEY env
  max_output_tokens: 8192
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

---

## OAST setup (Interactsh)

Blind SSRF/RCE/XXE produce no in-band signal, so candidates are fired with a
unique Interactsh callback hostname and the provider is polled for
DNS/HTTP/SMTP interactions (`validation/oast.py`).

- **Public (default):** `server: "oast.pro"`, `api_base: null` → registers at
  `https://api.oast.pro`, callbacks at `<token>.oast.pro`. On registration
  failure it fails over to `oast.live` automatically.
- **Self-hosted:** point `server` at your Interactsh callback domain and set
  `api_base` to its REST endpoint.

Callbacks are unique per scan; correlation matches the token hostname inside
interaction payloads. When cloud tech is fingerprinted (AWS/GCS/Azure), the
corresponding metadata-endpoint payload (`169.254.169.254…`,
`metadata.google.internal…`) is queued alongside the callback on each probe.
The provider is deregistered (`DELETE /deregister/{uuid}`) after the scan.

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
   `authorization_tests/confirmed`) and checkpoint blobs
   (`coverage`, `budgets`) updated throughout.

### 9. AI → `hypotheses.jsonl`

`AIPlanner` (Gemini, `GEMINI_API_KEY`) emits structured hypotheses
(`hypothesis, endpoint, reason, test_class, confidence, required_context,
status`) — never confirmed vulns. Context is prompt-budgeted per part
(techs/endpoints/findings) and findings are grouped by host+class so one
noisy host can't evict the rest. Large JS bundles are analyzed per
structural chunk (`plan_js_chunk`). See
[AI planner and loop closure](#ai-planner-and-loop-closure).

### 10. Report → `report.html`, `metrics.json`, `coverage.json`

Severity-filtered HTML with Confirmed / Strong Candidates / Informational
sections, each finding showing impact, numbered reproduction steps,
false-positive notes, curl one-liner, and direct evidence-file links; a
Coverage section naming tested vs explicitly untested attack classes; plus
a hypotheses section split into validated-vs-pending.

---

## Validation semantics

`Finding.validation_status`: `not_tested → inconclusive | strong_candidate |
confirmed | false_positive`. `confidence`: `unknown | possible | probable |
confirmed`.

| engine | strong_candidate when | confirmed when |
|--------|----------------------|----------------|
| differential | two users, both 200, same shape/hash; or anonymous 200 on admin/api | — (stays candidate, needs id-swap proof) |
| OAST sweep / SsrfValidator | — | unique callback token observed inbound |
| mutation SQLi prescreen | DB error marker reflected | ≥4 s delay on SLEEP/BENCHMARK payload vs baseline |
| mutation XSS prescreen | payload reflected unfiltered | — |
| sqlmap | — | "is vulnerable" / "available databases" in output |
| dalfox | "verified"/"PoC" in output | — |

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
| `findings.jsonl` | final deduped findings |
| `hypotheses.jsonl` | AI hypotheses with validation status |
| `application.json` | incremental application model (Phase 1) |
| `application_graph.json` | persisted application graph (Phase 1) |
| `coverage.json` | per-class test coverage (Phase 1) |
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
  confidence, validation_status`, location (`host, matched_at, endpoint_url,
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
- **`TestResult`**: plugin outcome — `status` (confirmed | candidate |
  negative | inconclusive | blocked | skipped | error), `evidence`,
  `observations`, `errors`, `requests_used`, `duration_seconds`.
  Infrastructure states are never mapped to vulnerability negatives.
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
secret, finding. Edge types: HOSTS, CALLS, AUTHENTICATES_TO, OWNS,
BELONGS_TO, CAN_ACCESS, READS, WRITES, CREATES, DELETES, REDIRECTS_TO,
FETCHES, USES, GENERATES, DEPENDS_ON, LEADS_TO, EXPOSED_BY, CONTAINS.
Query helpers: `neighbors()`, `nodes_of_type()`,
`endpoints_exposing_resource()`, `resources_of_tenant()`. Behavioral edges
(`CAN_ACCESS` from matrix observations, `LEADS_TO` from chains) arrive in
Phases 3/9 against this stable schema.

## Security invariants (Phase 1)

`logic/invariants.py` evaluates named predicates over normalized
observations. Built-ins (`default_invariants()`, all nine spec examples):
cross-user read, unauthorized write, modify-deleted, self-promotion,
negative quantity, unauthorized price change, refund-exceeds-payment,
single-use token reuse, revert-completed. Custom checks register via
`register_check(name, fn)`; `evaluate()` / `evaluate_all()` return
`InvariantResult(violated, detail)`. No observation producers are wired yet
— the Phase 3 authorization matrix and Phase 5 workflow engine will feed
it; the registry API is frozen now so those phases only append.

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
detection list (sqli … takeover).

## Budgets (Phase 1)

`budgets.py` `BudgetTracker` enforces `budgets.requests_per_host` (10k),
`requests_per_endpoint` (100), `authz_tests_per_endpoint` (20),
`browser_actions` (500), `ai_experiments` (50). Every direct HTTP request
is counted in `_HTTPClient`; over-budget requests raise `BudgetExceeded`,
which probing loops translate to `blocked` coverage. Differential and
OAST sweeps pre-check their per-endpoint test budget before firing.
Defaults only bite runaway loops — normal scans stay an order of magnitude
below every cap.

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
.venv/bin/python -m pytest tests/ -q
```

96 tests: URL normalization, endpoint classification, parameter extraction
(URL/HTML/JS), scope rules, secret redaction, plus v5.2 coverage — Arjun JSON
parsing, WAF fingerprinting, JS-bundle tech gating, structural JS chunking,
source-map parsing, differential verdicts (BOLA / broken-access / healthy /
volatile-key immunity), mutation ordering and error signals, OAST
candidate filtering and correlation, AI template generation, limiter
backoff/recovery, and auth/OAST config parsing — plus Phase 1 foundation:
application/graph models, invariants, coverage precedence, budgets,
checkpoint blobs, plugin registry/prerequisites, and orchestrator wiring.

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
    invariants.py        security invariant registry + built-ins (Phase 1)
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
  ai/planner.py          Gemini hypotheses + JS-chunk planning
  reporting/
    html.py              triage report (impact · repro · FP notes · evidence · coverage)
    impact.py            impact / repro-step / FP-note builders
    coverage.py          per-class CoverageTracker (Phase 1)
    metrics.py           coverage + validation counters
config.yaml              annotated defaults (copy per engagement, add secrets)
tests/                   pytest suite (test_v52.py: 5.2 additions, test_phase1.py: foundation)
setup1.sh … setup8.sh    project scaffolding scripts
```
