# Tutorial: assessing the fictional shop at acme.com

> **Fiction.** `acme.com` here is a made-up target used to demonstrate
> every feature end to end. Never run these commands against the real
> `acme.com` or any system you are not explicitly authorized to test.
> All tokens, responses, and findings below are synthetic.

Scenario: you are authorized to assess `acme.com`, a fictional store
(shop frontend, JSON API, admin panel, OAuth login). We go from zero to
a triaged report, touching each capability once.

## Step 0 — Install and check the toolchain

```bash
cd apex-fuzzer
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
apex-fuzzer --update
apex-fuzzer --doctor
```

`--doctor` prints one line per tool: present (with version), present
with version detection unsupported, MISSING, or failing self-check.
Note anything MISSING now — each gap silently narrows the scan later
(no sqlmap → no injection confirmations, no Interactsh client → no
blind findings, no Playwright → no browser stages).

```bash
cp .env.example .env   # fill in only what you will use
```

## Step 1 — Fix scope first

```bash
apex-fuzzer -d acme.com --dry-run
```

With an empty `scope.allowed_domains`, the first target auto-seeds —
check the dry-run output says `target_in_scope: true` for
`acme.com`. For a real engagement, prefer explicit scope in
`config.yaml`:

```yaml
scope:
  allowed_domains: ["acme.com"]
  allow_subdomains: false
  excluded_hosts: ["status.acme.com"]
  excluded_paths: ["/static/"]
```

Excluded hosts/paths never receive any request; media/archive
extensions are additionally excluded from active probes (but still
discovered). Re-run `--dry-run` until the plan matches your
authorization, then keep going.

## Step 2 — Passive discovery (read-only)

```bash
apex-fuzzer -d acme.com --profile passive --output output/acme-passive
```

What runs: recon mergers (ParamSpider/wayback/gau/hakrawler/katana
where installed), `robots.txt`/sitemaps, endpoint normalization,
first-party JS mining with source-map deep parse, API-spec discovery,
tech/WAF fingerprinting, HTML-form harvesting — all GETs. Open
`output/acme.com/endpoints.jsonl`: one `Endpoint` per line with
query/body/header parameters, sources (`recon`, `javascript`,
`api_spec`), and types (`api`, `admin`, `authentication`, …).
`technologies.jsonl` shows the stack; `metrics.browser_pages` stays 0.

## Step 3 — Standard scan (add Nuclei breadth)

```bash
apex-fuzzer -d acme.com --profile standard --output output/acme-standard
```

Adds Arjun hidden-parameter mining, `httpx` live probing, subzy
takeover fingerprinting, and community (+ bug-bounty) Nuclei
templates with `-dast`. Findings land in `findings.jsonl` as
*leads* — template matches are candidates, never confirmations.
`tko.csv` fingerprint-only rows are strong candidates; only
`tko-subs -takeover` with tokens makes a confirmed claim (a separate,
explicitly authorized action).

## Step 4 — Configure test identities (unlocks auth testing)

Two accounts minimum. Per engagement, fill `auth.contexts`:

```yaml
auth:
  contexts:
    - name: anonymous
      headers: {}
    - name: alice
      headers:
        Cookie: "session=AAA"
      identity: alice
      roles: ["member"]
      tenant: acme
    - name: bob
      headers:
        Cookie: "session=BBB"
      identity: bob
      roles: ["member"]
      tenant: acme
    # - name: pre_mfa
    #   headers:
    #     Cookie: "session=PRE"
    #   mfa_pending: true
```

Verify parsing and secret hygiene:

```bash
apex-fuzzer --config-check -c config.yaml --profile authenticated
```

The report lists enabled modules (`differential`, `authz_matrix`),
auth contexts with credential *presence* (never values), OAST/AI/
browser status, budgets, and safety. Fix errors before scanning.

## Step 5 — Differential testing (BOLA / broken access)

```bash
apex-fuzzer -d acme.com --differential --output output/acme-diff
```

The same endpoint is fetched as anonymous, alice, and bob. Two
matching 200s on `/api/users/482` as alice *and* bob:

```
source: differential | BOLA: identical access for two users (/api/users/482)
validation: strong_candidate
```

Healthy authorization (alice 200 / bob 403) records
`tested_negative` — a genuine negative, since both requests completed.

## Step 6 — Authz matrix: swaps, BFLA, GraphQL replay

```bash
# needs authorization.enabled or an api/authenticated profile
apex-fuzzer -d acme.com --profile authenticated --output output/acme-authz
```

1. **Harvest**: each identity's JSON responses yield object IDs with
   the owner's response shape as baseline.
2. **Swap**: bob's `order_id=77` replayed as alice. A shape match is
   graded by ownership markers (`owner_id`, `user_id`, …):
   `high` (ownership agrees), `medium` (identifiers agree, reflection
   not ruled out), voided (generic bodies, contradictory markers).
   Tenant-mismatched pairs tag `tenant-isolation`.
3. **Method sweep**: every configured verb × every identity. Alice
   getting 200 on `DELETE /admin/users` while anonymous is denied is
   a BFLA candidate (`source: authz-matrix`).
4. **GraphQL replay**: observed `query GetUser($id: …)` documents
   replay with the victim's variable as the other identity, owner
   baseline first. `mutation` operations are never replayed.

## Step 7 — Stateful write proof (test objects only)

```bash
# config: authorization.write_replay: true
apex-fuzzer -d acme.com --profile authenticated --ack-state-change \
  --output output/acme-write
```

The MTN pattern: alice's own observed update request replays with
bob's object ID. An accepted replay whose victim ID echoes stays a
candidate; only an owner readback showing alice's values newly
persisted on bob's object confirms (`verified-effect`). A clean
re-read refutes to `inconclusive`. Never point this at real user
data — test accounts and test-owned objects only.

## Step 8 — OAST blind SSRF (with filter-bypass stage)

```bash
apex-fuzzer -d acme.com --oast --output output/acme-oast
# local lab instead: --oast-callback-url http://localhost:9001
```

URL-like params (`callbackUrl`, `webhook`, `import`) get per-request
callback hosts over HTTP *and* HTTPS, so stale interactions can never
cross-confirm. A correlated callback confirms a server-side *fetch*
— not data access. When direct callbacks miss, parser-bypass
variants (decimal/hex/octal/IPv6/zero-IP, backslash, userinfo-decoy
with acme.com itself as decoy) fire with fresh nonces:

```
source: oast-sweep | Blind SSRF confirmed via OAST on
'callbackUrl' (/api/import) through parser-bypass variant (decimal-ip)
```

A response echoing the callback token adds a full-read *signal* tag;
it never upgrades the finding alone. Redirect chains and DNS
rebinding stay manual procedures.

## Step 9 — Injection validation: SQLi, XSS, SSTI, XXE, traversal

```bash
apex-fuzzer -d acme.com --profile validation --validate \
  --output output/acme-validation
```

No Nuclei lead is required: the prescreen sweep probes parameters
directly, and hits re-enter the plugin loop for tool confirmation.

- **SQLi**: boolean/error/UNION prescreens (numeric, single- and
  double-quote contexts, DBMS hints) run first; sqlmap confirms with
  `--level 1 --risk 1 -p <param>`, no enumeration. Delay techniques
  need `--sqli-time` explicitly.
- **XSS**: Dalfox structured output stays a candidate until Chromium
  observes the exact alert marker — trying query, then fragment, then
  cookie sources in the same sandbox.
- **SSTI**: paired inert arithmetic (`{{…}}`, `${…}`) must both render
  exact values; reflection alone never confirms.
- **XXE**: one external entity to your OAST collector on retained XML
  (plain, SVG, SOAP, XMP); office containers fail closed to isolated
  fixtures; local files are never requested.
- **Traversal**: only your configured harmless marker file, exact
  contents, depth capped at six. No marker configured means no probe.
- **Multipart uploads**: one text field is replaced byte-exact
  (boundaries and file bytes preserved); file parts are never touched.
- **Headers/cookies**: header values and single cookie pairs probe
  too — except Authorization, session cookies, and framing headers,
  which are never mutated.

## Step 10 — Stored chains, business logic, race (all opt-in)

```bash
apex-fuzzer -d acme.com --profile validation --second-order \
  --business-logic --output output/acme-stateful
# --race stays off unless you explicitly pass it
```

- **Stored XSS**: an inert `<axsl>` canary persists, then render
  points are classified (script/event-handler/`javascript:` URI/raw
  HTML). Entity-encoded is negative; never-rendered is inconclusive.
- **Stored SSRF**: callback URLs persist separately
  (`--second-order-ssrf`), confirmed on correlated fetch after
  ranked trigger routes.
- **Business logic**: `-1`/`0`/`999999` quantities, absurd refunds,
  token double-submits. A finding needs server acceptance *and* an
  invariant violation, then readback verification for confirmation.
- **Race**: synchronized bursts (generic, single-use, idempotency,
  inventory profiles with verification). The most aggressive test in
  the suite — enable deliberately or not at all.

## Step 11 — MFA, OAuth, cache, CORS, redirects

These run inside validation/auth-enabled scans once configured:

- **MFA**: the `pre_mfa` session hitting the same protected object
  as a completed session is a session-issuance flaw; a denied
  pre-session is healthy (`tested_negative`).
- **OAuth**: missing `state` and implicit-flow authorize URLs become
  candidates passively. PKCE-strip and OAST-redirect probes only
  *observe* the authorize answer — codes are never redeemed,
  redirects never followed.
- **Cache deception**: anonymous/victim/re-read triple under unique
  cache-buster keys. Confirmation needs personalized content *plus*
  a HIT signal *plus* the victim body on re-read. Poisoning stays
  manual.
- **CORS**: reflected arbitrary Origin with credentials on a
  non-empty cookie-authenticated 2xx is a candidate; opt-in Chromium
  proof confirms real readability. Never claims browser impact
  without it.
- **Open redirect**: observed redirect-like GET fields only, unique
  `.invalid` host, redirects never followed, 3xx `Location` match
  required.

## Step 12 — AI hypotheses and loop closure (optional)

```bash
apex-fuzzer -d acme.com --validate --ai --output output/acme-ai
```

The planner emits *hypotheses*, never vulns. Each routes back into a
deterministic validator (OAST/sqlmap/Dalfox/differential/Nuclei
gate), capped per class: `validated`, `rejected`, or left
`hypothesized`. Untestable ideas render as pending — never findings.

## Step 13 — Read the report and triage

Open `output/acme.com/report.html`: Verified Effects, Candidates,
Observations & Inconclusive — each with severity, reproduction steps,
FP notes, a curl one-liner, and evidence links. Check `coverage.json`
for explicitly untested classes (untested ≠ safe), and
`metrics.json` for counts. Triage rules: candidates are leads;
`inconclusive` means the probe couldn't distinguish (common behind
WAFs); callback-only SSRF proves a fetch, not data access.

## Step 14 — The strict bounty variant

```bash
apex-fuzzer -d acme.com --profile validation --strict \
  --auth-ref PROGRAM-1234 --ack-state-change \
  --max-requests 250 --max-state-changes 20 \
  --stop-on-candidate --cooldown-ms 500 --output output/acme-strict
```

Anything missing fails closed *before* network traffic with
per-condition reasons (exit 2). See
[bounty-scan](bounty-scan.md) for the full workflow.

## Quick reference: flags you will actually use

| goal | flags |
|------|-------|
| look around safely | `--profile passive` |
| breadth DAST | `--profile standard` |
| confirm injections | `--profile validation --validate` |
| auth testing | contexts + `--differential` / `--profile authenticated` |
| blind SSRF | `--oast` (or `--oast-callback-url` locally) |
| browser discovery/XSS | `--browser` |
| slow SQLi | `--sqli-time` |
| write proof | `write_replay: true` + `--ack-state-change` |
| stop early | `--stop-on-candidate` |
| prove nothing broke | `--dry-run`, `--config-check`, `--doctor` |
