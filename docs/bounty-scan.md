# Authorized bounty scan workflow

Use this workflow only for assets and test classes explicitly listed in the
program's current scope and rules. Save the program URL or authorization
reference in `safety.authorization_ref`; do not put credentials, cookies, or
tokens in the config or command line.

The strict starter config is [`examples/bounty-strict.yaml`](../examples/bounty-strict.yaml).
It uses placeholder authorization and `app.example.com`; replace the domain,
reference, and validity window with the exact approved values before scanning.
The approved-domain match is exact or a subdomain match. It does not resolve
hostnames or authorize sibling domains. Use CIDRs only for explicitly approved
literal IP targets.

## 1. Review the resolved plan (zero network requests)

From the repository root, set the target to one exact in-scope host and run:

```bash
TARGET=app.example.com
./.venv/bin/python -m apex_fuzzer.cli \
  --domain "$TARGET" \
  --config examples/bounty-strict.yaml \
  --profile validation \
  --strict \
  --auth-ref PROGRAM-1234-TARGET-5678 \
  --ack-state-change \
  --max-requests 250 \
  --max-state-changes 20 \
  --stop-on-candidate \
  --cooldown-ms 500 \
  --dry-run \
  --output output/bounty-preflight
```

`--dry-run` resolves the selected modules, strict authorization checks, scope,
and estimated stateful-module costs without sending scan requests. Check that:

- the target is in scope and strict mode is on;
- the only stateful modules are `business_logic` and `second_order`, both
  explicitly listed in `safety.allowed_modules`;
- no refusal is reported and the estimated costs fit the configured host
  budget;
- the target, authorization reference, and validity window match the program.

The validation profile enables active SQLi/XSS/SSRF validation, business-logic
checks, stored-XSS checks, and OAST. Strict mode gates the stateful modules.
The supplied limits reduce endpoint and payload counts; tune them only after
reviewing the program rules and the dry-run plan. If a stateful class is not
allowed by the program, remove that module from the selected profile/config
instead of granting it authorization.

If the program does not permit either stateful class, change the profile to
`standard` and add `--validate`; that enables first-order validation without
the `validation` profile's built-in `business_logic` and `second_order` stages.
If only one stateful class is permitted, enable it explicitly in the config,
allowlist only that module, and dry-run again.

The dry-run costs are upper-bound estimates for the modules included in its
plan. They are not a total packet count, and external-tool traffic is not
covered by the shared HTTP request cap.

## 2. Run the approved scan

After reviewing the dry-run output and confirming the authorization details,
run the same command with `--dry-run` removed:

```bash
TARGET=app.example.com
./.venv/bin/python -m apex_fuzzer.cli \
  --domain "$TARGET" \
  --config examples/bounty-strict.yaml \
  --profile validation \
  --strict \
  --auth-ref PROGRAM-1234-TARGET-5678 \
  --ack-state-change \
  --max-requests 250 \
  --max-state-changes 20 \
  --stop-on-candidate \
  --cooldown-ms 500 \
  --output output/bounty-scan
```

The CLI flags are intentional per-run acknowledgments and caps. `--ack-state-change`
does not create program authorization; it records the operator's acknowledgment
that the selected modules can write data. A strict refusal exits before scan
traffic. Keep the output directory private because reports can contain
application data and evidence.

## Scope, impact, and limits

- Start with a single exact host. Add targets only after confirming each one
  is in scope; do not assume a parent domain includes every subdomain.
- `passive` is the lowest-impact profile: it still sends read-only discovery
  HTTP/HTTPS probes, but disables Nuclei, validation payloads, OAST, parameter
  mining, AI, and takeover checks. Local/private targets skip public archive
  lookups. `standard` adds Nuclei and parameter mining. `deep` also enables
  authorization-matrix, stored-XSS,
  business-logic, browser, and takeover modules. `validation` enables
  stateful business-logic and stored-XSS checks. Use stateful profiles only
  when those activities are explicitly permitted.
- Do not enable `--race`, takeover claiming, login workflows, or stored-SSRF
  without explicit program permission and a separately reviewed plan.
- `--max-requests` and `--max-state-changes` cap requests handled by the
  application's shared HTTP budget. External tools such as Nuclei, sqlmap,
  Dalfox, or Arjun may make their own network requests; configure their
  per-tool limits as well and do not treat the global cap as a packet-level
  firewall.
- `scan.rate_limit` controls Nuclei's request rate; it is not a universal
  rate limit for every tool. Avoid denial-of-service, resource-exhaustion,
  destructive, and out-of-scope testing.
- A candidate is a lead for manual review, not by itself a reportable bug.
  Confirm impact and reproduce safely within the program's rules.
