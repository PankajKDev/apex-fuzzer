# Apex-Fuzzer User Guide

End-to-end handbook for running authorized scans: install, configure,
choose a profile, set up identities, run validation, and read the
results. For the strict bounded bounty workflow see
[Authorized bounty scan workflow](bounty-scan.md); for class-by-class
coverage see the [class and tool matrix](bounty-class-tool-matrix.md);
for detection boundaries see [known limitations](known-limitations.md).

## 1. Install

```bash
cd apex-fuzzer
python3 -m venv .venv && . .venv/bin/activate
pip install -e .            # apex-fuzzer command
apex-fuzzer --update        # nuclei, httpx, katana, waybackurls,
                            # gauplus, hakrawler, dalfox, subzy, tko-subs,
                            # interactsh-client (go) + arjun, linkfinder (pip)
apex-fuzzer --doctor        # verify every tool is present
```

`--doctor` reports each binary as present (with version), present
with version detection unsupported, MISSING, or failing self-check.
`--config-check` validates the whole configuration and prints the
effective modules, validators, OAST/auth/AI/browser/scope/budget/safety
status without sending any request; invalid values block startup before
any network activity. Every stage that
depends on a missing binary logs the skip and continues — a scan never
fails because one tool is absent, but the corresponding coverage is
lost (see §9). Optional extras:

- **Browser (Chromium discovery, CORS proof, fragment/cookie XSS):**
  `pip install "apex-fuzzer[browser]"` plus `playwright install chromium`.
- **Bug-bounty Nuclei templates:** clone
  `unrandoms/nuclei-bb-templates` to `~/nuclei-bb-templates`.
- **Local AI:** install Ollama, `ollama pull llama3.1`, `ollama serve`.

Secrets live in a `.env` file (never in `config.yaml`):

```bash
cp .env.example .env   # then fill in
```

| variable | enables |
|----------|---------|
| `GEMINI_API_KEY` | hosted AI planning (with free Groq fallback) |
| `GROQ_API_KEY` | Groq fallback, or direct Groq planning |
| `OLLAMA_HOST` | optional Ollama override (no key needed locally) |
| `GITHUB_TOKEN` | confirmed takeover claims |
| `HEROKU_USERNAME` / `HEROKU_API_KEY` / `HEROKU_APP_NAME` | Heroku claims |

## 2. Your first scan

> New here? Read the [tutorial](tutorial.md) first: it attacks the
> fictional shop at `acme.com` step by step, using every feature once.

```bash
# lead finder: quiet read-only discovery, ranked follow-ups, no payloads
apex-fuzzer -d example.com --profile leads --output output

# passive discovery only: no DAST, no validation payloads
apex-fuzzer -d example.com -c config.yaml --output output

# standard scan: recon + Nuclei DAST
apex-fuzzer -d example.com --profile standard --output output

# validation-heavy run (needs explicit opt-in, see §5)
apex-fuzzer -d example.com --profile validation --validate --output output
```

Results land in `output/<host>/`: `report.html` (start here),
`findings.jsonl`, `endpoints.jsonl`, `leads.jsonl` (ranked follow-ups,
always written), `burp/` (manual-testing handoff, always written),
`coverage.json`, `metrics.json`,
`proofs/` (per-finding evidence). Re-run with `--resume` to skip
finished stages after an interruption.

> **Authorized testing only.** Validation profiles send active payloads
> (parameter mining, mutation probes, sqlmap, Dalfox, OAST callbacks,
> Nuclei DAST). Only scan targets you own or are explicitly authorized
> to test. Out-of-scope hosts never receive active payloads.

## 3. Profiles and what they run

| profile | nuclei | validation | OAST | differential | authz-matrix | stored-XSS | browser |
|---------|--------|------------|------|--------------|--------------|------------|---------|
| `passive` | – | – | – | – | – | – | – |
| `standard` | ✓ | – | – | – | – | – | – |
| `deep` | ✓ | – | ✓ | ✓ | ✓ | ✓ | on |
| `api` | ✓ | – | ✓ | ✓ | ✓ | – | – |
| `authenticated` | ✓ | – | ✓ | ✓ | ✓ | – | – |
| `validation` | ✓ | ✓ | ✓ | – | – | ✓ | – |
| `leads` | – | – | – | – | – | – | – |

The `leads` profile is the quiet mode: crawlers run shallow and slow
(depth 1, katana `-rl 5`), everything active stays off, and the output
is `leads.jsonl` — discovered-but-untested surface where each lead
names its follow-up. It sends no payloads: archive lookups hit third
parties, and the target sees only robots/sitemap reads, spec probes,
JS/tech fetches, httpx status checks, and subzy fingerprint reads.

Flags force-enable stages regardless of profile: `--validate`,
`--differential`, `--oast`, `--second-order`, `--business-logic`,
`--race` (off everywhere by default), `--browser` / `--no-browser`.

Practical guidance:

- Start with `passive` to learn the attack surface, then `standard`.
- Use `validation` when you are ready for active confirmation.
- `deep` is the broadest automated pass; `api`/`authenticated` focus
  the auth engines. Race and business-logic stay opt-in flags because
  they submit state-changing requests.
- **CI mode for owned apps** (`--fail-on high`): exit 1 when any
  finding meets the severity — gate merges on it. Bounty mode is the
  default (exit 0 with a report; strict refusals always exit 2).
  A pinned `python:3.12-slim` runtime image lives in `Dockerfile`
  (`docker build -t apex-fuzzer .`); DAST binaries stay out of the
  image — run `apex-fuzzer --update` inside, or mount a tools volume.

## 3b. Burp handoff (verify leads by hand)

Every run — including `passive` and `leads` — writes `burp/`:

| file | use in Burp |
|------|-------------|
| `urls.txt` | Target > Scope, include rules (paste as URL prefixes); Content discovery seed; Intruder target list |
| `requests/NNN-METHOD-host-path.txt` | open the file, paste the raw request into a Repeater tab (both editions), then Send to Intruder / Comparer |
| `sitemap.xml` | Burp site-map schema (same shape as Save selected items): archive runs, diff coverage over time |
| `lead-checklist.md` | per-lead clicks: id-param → Intruder Sniper over harvested IDs; url-param → Repeater + Collaborator; privileged endpoints → two-session Repeater + Comparer |

Request bodies reuse observed sample values when present, else empty
values — templates for manual testing, never probes. Cookie and
Authorization values are never exported: attach your own session
(session handling / a logged-in Burp browser) before replaying
anything authenticated.

## 3c. Review marks (tune out repeat noise)

After triaging a run, record verdicts in `output/<host>/reviews.jsonl`
(one JSON object per line — stable finding IDs keep marks valid
across runs):

```json
{"finding_id": "diff-abc123…", "verdict": "false_positive",
 "reason": "login page served with 200 to everyone"}
{"finding_id": "diff-abc123…", "verdict": "false_positive",
 "test_class": "sqli", "endpoint": "https://h/api/u/1",
 "parameter": "id"}
```

The next run attaches marks to findings (visible in the report's
false-positive notes) and skips prescreen re-probing of exact
false-positive triples — finding-ID marks link to triples via the
finding's class, endpoint, and parameter. Plugin re-validation
(sqlmap/dalfox) skips marked findings the same way, including swap
findings whose IDs rotate per run (matched by triple, with the
authorization family idor/bola/authz treated as one class and
query strings stripped from endpoint keys). True-positive marks are
retained as evidence. Malformed lines never fail a scan.

## 4. Configuration

`config.yaml` holds every knob; CLI flags override file values. The
annotated defaults in the file itself are the reference — the main
sections:

- `scan`: rate limit, concurrency, timeouts.
- `discovery`: JS analysis, source maps, API specs, Arjun mining.
- `validation`: every validator toggle and bound (mutation depth,
  `sqli_time_based`, `differential_max_endpoints`,
  `prescreen_max_endpoints/prescreen_max_params`, second-order caps,
  `cache`, open-redirect/CORS caps, path-traversal marker).
- `authorization`: methods swept, endpoint/ID caps, `write_replay`
  (opt-in test-account write proof), ownership fields.
- `business` / `race`: mutation and burst engines (both off).
- `browser`: crawl bounds, capture toggles.
- `oast`: callback server, poll windows, per-endpoint caps.
- `budgets`: `requests_per_host/endpoint`, authz tests, browser/AI caps.
- `auth.contexts`: test identities (see §5).
- `safety`: strict mode, authorization reference, state-change
  acknowledgment, request/state caps, stop-on-candidate, pacer.
- `scope`: allowed domains (`*.example.com` and `.example.com`
  forms match subdomains too; deceptive suffixes never match),
  subdomain handling, host/path exclusions, and `allowed_ports`
  (empty = any port). Explain any URL with `--scope-check URL`
  (repeatable, zero network): prints ALLOW/DENY plus the reason
  (`out_of_scope_domain`, `excluded_host`, `excluded_path`,
  `disallowed_port`, `unsupported_scheme`) and exits 1 on any deny.
- Top-level `seed_urls` / `har_files`: operator-supplied discovery
  input (see §4b). `--seed-urls FILE` merges manual URLs into the
  recon pool; `--har FILE` (repeatable) imports HAR 1.2 captures
  into the endpoint pool with observed request shapes. Both are
  scope-filtered; HAR import is inventory only (nothing sent).

Validate any edit with `Config.load('config.yaml')` semantics — the
suite checks this — and preview impact with `--dry-run` (zero network,
exit 0, writes `preflight.json` with per-module cost estimates).

## 4b. First-party captures (HAR import)

Export an authenticated session from DevTools (Network → Export HAR)
or Burp, then import it — captures beat crawling for real endpoints,
request bodies, and object IDs:

```bash
apex-fuzzer -d example.com --har user-a.har --har admin.har
```

```yaml
har_files: ["captures/user-a.har"]   # same input via config file
```

Rules: out-of-scope and static-asset entries are dropped; Cookie /
Authorization headers never enter retained material; body and query
sample values are blanked (exact bytes stay runtime-only for replay
fidelity and never reach artifacts); oversized bodies keep inventory
but drop bytes. Imported POST/PUT shapes feed the same observed-request
consumers as browser traffic (sqlmap raw replay, write replay).

External tools (httpx, nuclei, crawlers) run as subprocesses and
follow redirects themselves, outside the scope gate. The tool only
ever hands them scope-filtered inputs (`probe-input.txt`,
`nuclei-input.txt`; findings stay scope-filtered after the scan), but
a redirect chain inside a subprocess can still resolve out-of-scope —
treat subprocess output as untrusted discovery, never as proof.

## 5. Authentication contexts (two accounts unlock everything)

Anonymous probing is implicit. Add test accounts under `auth.contexts`:

```yaml
auth:
  contexts:
    - name: anonymous
      headers: {}
    - name: user_a
      headers:
        Cookie: "session=AAA"
      identity: user_a
      roles: ["member"]
      tenant: acme
    - name: user_b
      headers:
        Cookie: "session=BBB"
      identity: user_b
      roles: ["member"]
      tenant: acme
    # - name: pre_mfa
    #   headers:
    #     Cookie: "session=PRE"
    #   mfa_pending: true   # enables the MFA transition check
```

Two authenticated contexts unlock BOLA detection (swap testing),
cross-tenant isolation, the authz matrix, write replay, GraphQL
operation replay, and MFA transition checks. One is enough for
broken-access checks. Rotate placeholder secrets per engagement;
they are redacted from evidence and reports.

Without static cookies, the login engine can mint sessions itself
(`auth.login`, disabled by default — see README). MFA challenges
stop at a manual checkpoint: never bypassed, never auto-retried.

## 6. Validation, step by step

Validation runs only in validation-enabled scans, in this order:

1. **GraphQL introspection** — one minimal `__schema` document per
   GraphQL endpoint (type inventory only). Disclosure is a candidate
   (sensitivity needs human review); a valid GraphQL answer without
   `__schema` is a genuine negative. POST endpoints pass through the
   state-change gate, so they need `--ack-state-change`.
2. **Differential testing** — same endpoint under each identity;
   two matching 200s (or anonymous 200 on admin/API) become BOLA /
   broken-access candidates. Shape matches require agreeing
   content types; an anonymous HTML 200 against API content is
   login-wall shadowing, not access. Same-status error-signature
   asymmetry (one context leaks a framework traceback, the other
   does not) and redirect-path divergence across sessions are
   candidates; anonymous-redirect-while-authed-200 is healthy.
   Latency is recorded per context for evidence (single samples
   never decide). Candidates get one confirmation repeat:
   a contradictory second run downgrades to inconclusive (single-sample
   dynamics), while a blocked repeat keeps the candidate as
   single-sample evidence. Errored comparisons stay inconclusive,
   never negatives.
3. **MFA transitions** — needs one `mfa_pending` context: a pre-MFA
   session seeing the same protected object as a post-MFA session is
   a session-issuance flaw; a denied pre-session is healthy.
4. **Authz matrix** — harvest object IDs per identity, swap them
   cross-identity (GET reads), sweep HTTP methods per identity
   (BFLA), replay GraphQL query operations with victim variables.
   Optional **write replay** (`authorization.write_replay` plus
   `--ack-state-change`, test accounts only): the attacker's own
   observed mutating request with the victim ID, confirmed only by
   owner readback showing persisted values.
5. **OAST sweep** — URL-like params get per-request Interactsh
   callbacks (HTTP + HTTPS). A correlated callback confirms a
   server-side fetch. When direct callbacks miss, bounded
   parser-bypass variants (IP forms, userinfo-decoy, …) fire with
   fresh nonces. Callback ≠ internal data access: a reflected token
   is recorded as a full-read *signal*, never proof.
6. **Per-finding plugins** — mutation prescreens run first (cheap
   signal on WAF-blocked targets), then the heavy validators:
   parameter-pinned sqlmap (`--level 1 --risk 1`, boolean/error/union;
   time-based only with `--sqli-time`), Dalfox with Playwright
   execution confirmation (query, fragment, then cookie sources),
   paired-arithmetic SSTI, nonce-correlated XXE on retained XML,
   marker-file traversal. Each tool's result is kept; conflicting
   positive/negative signals resolve to inconclusive.
7. **Lead-independent prescreen sweep** — endpoint parameters go
   through the SQLi/XSS prescreens even with no Nuclei lead; hits
   re-enter the plugin loop for tool confirmation.
8. **Stored XSS / stored SSRF** (opt-in, they persist server-side
   canaries), **business logic** (needs your invariants plus
   readback), **race** (synchronized bursts, most aggressive test in
   the suite — enable deliberately or not at all).
9. **OAuth transitions** — authorize URLs from traffic analyzed
   offline (missing `state`, implicit flow); PKCE-strip and
   OAST-redirect probes only *observe* the authorize answer, never
   redeem codes or follow redirects.
10. **Cache deception** — anonymous/victim/re-read triple under unique
   cache keys; shared entries never touched. Poisoning stays manual.

Result vocabulary (canonical `result_status`): `observation` (signal
only), `candidate` (suggestive, unverified), `verified_effect`
(behavior proven), `negative` (tested, genuinely absent),
`inconclusive` (could not distinguish). Timeouts, blocks, and budget
exhaustion are never negatives.

## 7. OAST setup

Blind SSRF/RCE/XXE need a callback oracle:

- **Public (default):** `oast.pro` with `oast.live` failover via the
  official `interactsh-client` (`apex-fuzzer --update` installs it).
  Missing binary fails closed, never silently.
- **Self-hosted:** point `oast.server` at your domain with `api_base`.
- **Local lab:** `--oast-callback-url http://localhost:9001` uses a
  simple HTTP collector's `/_log` with per-request path nonces.

## 8. Reading results

Open `report.html`: Verified Effects, Candidates, then Observations &
Inconclusive, each with severity, reproduction steps, FP notes, a curl
one-liner, and evidence-file links. The Coverage section names tested
vs explicitly untested classes — untested means untested, not safe.
`findings.jsonl` is the machine-readable record; `proofs/finding-NNN/`
holds the raw evidence; `coverage.json`/`metrics.json` summarize.

Triage rules that prevent false reports:

- Candidates are leads, not bugs. Confirm impact manually.
- `inconclusive` means the probe couldn't distinguish — common behind
  WAFs, rate limits, and dynamic content.
- Identical-shape swap matches on non-identifier parameters deserve
  extra scrutiny (the swapped field may be ignored server-side).
- Callback-only SSRF proves a fetch, not data access.

## 9. Troubleshooting

| symptom | likely cause | fix |
|---------|--------------|-----|
| Stage logs skips, thin findings | missing binaries (`--doctor`) | install what's missing |
| No authz findings | fewer than 2 identities | configure two test accounts |
| Everything `blocked` | budgets exhausted / out-of-scope | raise caps, check scope |
| No OAST confirmations | client missing, firewall, slow workers | `--update`, check poll windows |
| Browser stages skip | no Playwright/Chromium | install browser extra |
| Hung or slow scans | sqlmap/Dalfox/Nuclei on many endpoints | lower caps, `--stop-on-candidate` |
| Strict refusal exit 2 | missing auth-ref/allowlist/ack | `--dry-run` shows exactly what's missing |

## 10. Safety rules that are never negotiable

- Program scope and exclusions gate every module; DoS and resource
  exhaustion are excluded, always.
- Active payloads never fire at out-of-scope hosts or excluded
  extensions; out-of-scope plugin targets return `blocked`.
- Secrets come from the environment and are redacted from evidence.
- Findings carry stable IDs (no timestamps/randomness in ID inputs).
- One finding per root cause; corroboration lives in evidence, never
  as duplicate findings.
