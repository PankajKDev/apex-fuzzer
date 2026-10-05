# Known limitations

Apex-Fuzzer is an evidence-oriented scanner and orchestrator. A clean run is
not proof that an application is secure, and program policy decides which
tests are eligible. Exclude denial of service, resource exhaustion, brute
force, destructive actions, and any disallowed activity.

## Coverage limits

- **Nuclei findings are leads.** Coverage depends on the installed template
  set and each template's request/evidence behavior. Review and reproduce
  findings safely.
- **Deep class-specific checks are uneven.** SQLi, XSS, SSRF, access control,
  stored XSS, business logic, race conditions, takeover, and open redirect
  have dedicated paths with different evidence gates. SSTI, XXE, traversal,
  command injection, JWT/OAuth, GraphQL, WebSocket, and CORS remain partial,
  template-assisted, or context-only. See the
  [coverage matrix](bounty-class-tool-matrix.md) for per-class limits.
- **Open redirect input selection is narrow.** It tests only observed,
  redirect-like GET query parameters, up to 10 endpoints and 3 fields each;
  body and header fields are not covered.
- **CORS results are candidates.** Apex uses configured cookie-authenticated
  contexts and flags an exact arbitrary-origin reflection with credentials
  enabled and a non-empty successful response. It does not run a browser
  cross-origin read, enforce browser cookie/SameSite rules, compare account
  data, or prove sensitive impact. Review the candidate in an authorized
  browser session.
- **Authorization tests need valid identities and ownership evidence.**
  Without realistic roles, tenants, and known resources, negative results
  are limited.
- **Stateful tests are opt-in and application-dependent.** Business-logic,
  stored-XSS/SSRF, and race checks need program permission and sometimes
  operator-supplied readback assertions. Generic value changes alone do not
  prove impact.
- **No test covers every endpoint or identity.** Check `coverage.json` for
  `not_tested`, `untestable`, `inconclusive`, and `blocked` classes. A missing
  finding is not a negative result.

## Operational limits

- The shared request budget applies to Apex's HTTP client. Nuclei, sqlmap,
  Dalfox, Arjun, Katana, httpx, and other subprocesses may have independent
  request behavior; use their individual caps and inspect the plan.
- Subprocesses follow redirects themselves, outside the scope gate. Apex
  only hands them scope-filtered inputs (`probe-input.txt`,
  `nuclei-input.txt`) and scope-filters their findings afterwards, but a
  redirect chain inside a subprocess is untrusted discovery, never proof.
- Soft-404 baselines are recorded (`soft404.json`), not yet enforced:
  matched fetches are tagged for triage, but no endpoint is dropped on
  template match alone. Treat a 200-everything host as suspect inventory
  until the follow-up filtering pass lands.
- `--dry-run` sends no scan requests, but its cost estimate is not a packet
  count for external tools.
- A configured authorization context can be expired, incomplete, or
  inappropriate for a target. Validate access and scope before a scan; keep
  credentials out of commands, reports, and shared artifacts.
- Browser and external-tool prerequisites affect coverage. Missing tools may
  leave classes untested or candidate-only.
- Dynamic responses, WAF behavior, asynchronous processing, and transient
  network failures can leave evidence inconclusive. Re-run only with a
  reviewed budget and program-permitted rate.

## Sample output

[`sample-artifacts/`](sample-artifacts/) contains synthetic, sanitized
examples of a negative result, an inconclusive result, and a verified effect.
They illustrate the result taxonomy; they are not findings from a real target
or a claim that each result is automatically reportable.
