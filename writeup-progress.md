# Writeup Corpus Progress — web, bounty-eligible only

> Corpus: `~/writeups/writeups.json` — 6421 records, each with
> `Links[] / Authors[] / Programs[] / Bugs[] / Bounty / PublicationDate / AddedDate`.
> Scope of this file: **web vulnerability classes with a paid bounty**
> (`Bounty` set and not `-`). Non-web and bounty-ineligible labels excluded
> (see filter). Updated 2026-10-05.

## Filter (reproducible)

```python
# WEB+PAID selection: 1539 / 6421 records, 247 unique bug labels
paid = Bounty not in ('', '-', '0')
web  = Bugs minus NON_WEB minus INELIGIBLE, non-empty
NON_WEB = {Android, iOS, Windows, Memory corruption, Buffer Overflow,
  Local Privilege Escalation, CI/CD, Supply chain attack, Browser hacking,
  Cloud, AWS misconfiguration, Security code review, Cryptographic issues,
  Privacy issue, Hardcoded credentials, Components with known vulnerabilities}
INELIGIBLE = {DoS, Bruteforce, Self-XSS, Weak credentials, Clickjacking}
# NOTE: tail labels still leak a few non-web stragglers
# (Use-After-Free, Container escape, DLL Hijacking) — filter is approximate.
```

Paid overall: 1615 / 6421. Web+paid after exclusions: **1539**.

## Web+paid class ranking (count = writeups carrying the label; multi-label)

| # | class | paid writeups | tool status |
|---|-------|---------------|-------------|
| 219 | Information disclosure | 219 | DONE — version-banner/header sweep + 404-handler error disclosure (informational; nuclei templates remain for deeper paths) |
| 165 | IDOR | 165 | DONE — harvest→swap (graded high/medium/void) + write replay + GraphQL replay |
| 150 | Account takeover | 150 | DONE (engine) — 7 ATO chain rules over recorded findings (reset/XSS/OAuth/OTP/SQLi/CORS paths); chains hypothesize with missing links, rendered in report |
| 137 | Logic flaw | 137 | PARTIAL — business-logic mutations + invariants; needs operator invariants |
| 137 | XSS (generic) | 137 | DONE — prescreen + Dalfox + browser execution replay |
| 135 | RCE | 135 | VECTOR — via SSTI/deser/upload/nuclei; no dedicated RCE engine (by design) |
| 95 | Broken authorization | 95 | DONE (proof) — BFLA cells on POST/PUT/PATCH replay the low-priv observed shape with privileged readback; only persisted markers confirm |
| 78 | CSRF | 78 | PARTIAL — `b1ca9e7` token-misconfig sweep; no state-change proof |
| 75 | Stored XSS | 75 | DONE — inert-canary correlation + render-sink grading |
| 68 | SSRF | 68 | DONE — per-request-nonce OAST sweep + bypass variants + stored triggers |
| 50 | Open redirect | 50 | DONE — observed-query validator, `.invalid` marker, never follows |
| 46 | Reflected XSS | 46 | DONE — same XSS path |
| 40 | SQL injection | 40 | DONE — prescreen (query/body/header/cookie/XML/multipart) + pinned sqlmap |
| 39 | Privilege escalation | 39 | DONE (proof) — same BFLA proof path as Broken authZ |
| 38 | Authentication bypass | 38 | PARTIAL — differential + MFA transition; no systematic claim-level JWT attacks |
| 34 | Subdomain takeover | 34 | DONE — tko-subs confirmed + subzy fallback |
| 31 | Password reset | 31 | DONE — enumeration oracle (echo-guarded) + reset-link host poisoning; login-username-gated, nothing redeemed/followed |
| 31 | Broken Access Control | 31 | PARTIAL — same authz-matrix path as IDOR/BFLA |
| 29 | OAuth | 29 | PARTIAL — authorize-URL analysis + PKCE-strip/OAST-redirect observe-only probes |
| 26 | Blind XSS | 26 | DONE — `23f90f5` blind-XSS OAST correlation |
| 25 | HTML injection | 25 | PARTIAL — prescreen-adjacent reflection; no dedicated engine |
| 24 | 2FA / MFA bypass | 24 | PARTIAL — pre/post-MFA transition checks; OTP-bypass flows open |
| 24 | GraphQL | 24 | PARTIAL — `d1852c9` introspection probe + variables + operation replay; schema-driven gen open |
| 23 | Path traversal | 23 | DONE — operator-marker proof only, depth-capped |
| 20 | Unrestricted file upload | 20 | PARTIAL — `4227448` upload workflow review (review-level, not execution proof) |
| 17 | Web cache poisoning | 17 | MANUAL — deception triple done; poisoning stays manual (disruptive) |
| 17 | DOM XSS | 17 | PARTIAL — browser replay covers query/fragment/cookie sources |
| 14 | CORS misconfiguration | 14 | DONE — candidate probe + opt-in Chromium read proof |
| 12 | Race condition | 12 | DONE (gated) — generic/single-use/idempotency/inventory + verification; never for DoS |
| 11 | LFI | 11 | PARTIAL — marker proof covers path-like fields; no local-file exfil |
| 11 | CRLF injection | 11 | DONE — `0e893df` header probe (reflection never upgrades alone) |
| 11 | OS command injection | 11 | PARTIAL — `6e0120a` error-oracle prescreen; no timing/DNS confirmation |
| 11 | OTP bypass | 11 | DONE — wrong-code baseline + empty/omitted-code probes; ack-gated, mixed signals inconclusive |
| 11 | Broken authentication | 11 | PARTIAL — session/JWT modeling + login engine; brute force excluded |
| 10 | Host header injection | 10 | DONE — `0e893df` host-override redirect probe |
| 8 | HTTP request smuggling | 8 | DOCUMENTED EXCLUSION — needs raw-socket desync (library normalizes framing) + connection-poisoning risk falls under excluded DoS scope; no generic nuclei template either |
| 6 | Mass assignment | 6 | DONE — self-object privileged-field injection + own readback (swap-grade candidate, write-gated) |
| 8 | Web cache deception | 8 | DONE — anon/victim/re-read triple + HIT vocabulary |
| 8 | Payment bypass/tampering | 8+8 | PARTIAL — business-logic abuse values; needs per-target invariants |
| 8 | Universal XSS | 8 | PARTIAL — same XSS path; browser-version-dependent |
| 7 | XXE | 7 | DONE — nonce-correlated OAST on retained XML text; containers fail closed |
| 7 | Insecure deserialization | 7 | DONE — type-confusion error oracle over JSON params (candidate only, ack-gated); CVE templates still run in Nuclei |
| 7 | SOP bypass / postMessage | 7 / 13 | OPEN |
| 6 | Mass assignment | 6 | DONE — self-object privileged-field injection + own readback (swap-grade candidate, write-gated) |
| 6 | WAF bypass | 6 | PARTIAL — WAF-aware mutation ladder; no generative bypass |
| 5 | HTTP parameter pollution | 5 | DONE — baseline/duplicate/repeat-control oracle (read-only GETs) |
| 4 | SSTI | 4 | DONE — paired inert arithmetic on leads; common syntaxes only |
| 4 | File upload (label variant) | 4 | PARTIAL — same as Unrestricted file upload |

## Where we left off (last commits → writeup classes)

- Attack chains (working tree): 7 ATO rules → Account takeover (150)
- Template batch (working tree): HPP + mass assignment + deser oracle
  (smuggling excluded) → HPP (5), Mass assignment (6), Deser (7)
- Info disclosure (working tree): banners + error pages →
  Information disclosure (219)
- OTP bypass (working tree): empty/omitted-code probes → OTP (11)
- Password-reset flows (working tree): enumeration + poisoning →
  Password reset (31)
- BFLA state-changing proof (working tree): `prove_bfla()` + hook →
  Broken authZ (95), Priv esc (39)
- `0e893df` JWT confusion replay (caller-owned Bearer tokens) + Host-override /
  CRLF probes + auth-flow lead hints → JWT/session (38+11), Host (10), CRLF (11)
- `4227448` file-upload workflow review → upload (20+4)
- `23f90f5` blind-XSS OAST correlation → Blind XSS (26)
- `6e0120a` CMDi error-oracle prescreen → OS CMDi (11)
- `b1ca9e7` clickjacking + CSRF-token misconfiguration sweep → CSRF (78)
- `0ac6457` SARIF export + finding explainer → triage for all classes
- `8acdc63` scope ports + soft-404 baseline → scope correctness, FP reduction
- Suite green at checkpoint: 835 passed, 2 skipped (3.12).

## Next (ROI order, by paid-writeup count × gap)

1. ~~**BFLA state-changing proof**~~ DONE 2026-10-05 (working tree):
   `prove_bfla()` + authz-matrix hook, `tests/test_bfla_proof.py` (14).
2. ~~**Password-reset flows (31)**~~ DONE 2026-10-05 (working tree):
   `validation/reset_flow.py` + `reset_probe`, `tests/test_reset_flow.py` (15).
3. ~~**OTP bypass (11)**~~ DONE 2026-10-05 (working tree):
   `validation/otp_bypass.py` + `otp_bypass_probe`, `tests/test_otp_bypass.py` (12).
4. ~~**Info-disclosure probe (219)**~~ DONE 2026-10-05 (working tree):
   `validation/info_disclosure.py` + `info_disclosure_probe`, `tests/test_info_disclosure.py` (12).
5. ~~**Template-first batch (8/5/6/7)**~~ DONE 2026-10-05 (working tree):
   live nuclei-templates inventory (no generic detectors) + HPP oracle
   (`tests/test_param_pollution.py` 10), mass assignment
   (`tests/test_mass_assignment.py` 10), deser oracle
   (`tests/test_deser_oracle.py` 9); smuggling documented exclusion.
6. ~~**ATO kill-chain (150)**~~ DONE 2026-10-06 (working tree):
   `main/chains/` (7 ATO rules) + orchestrator step + report section,
   `tests/test_chains.py` (12).

Queue complete: every web bounty-eligible class with a paid writeup
now has a probe, a chain rule, or a documented exclusion.

## Lab validation (2026-10-06, /tmp/opencode/virtuallab2, 15/15)

Validation-profile scan against a purpose-built loopback app: all 9
new-probe findings fire, all 4 hardened controls stay silent, BFLA
confirms to verified-effect, chains reset-enum-assists +
reset-plus-otp build. Lab caught 4 bugs (orchestrator self,
sarif import, anonymous-tester preference, api-spec merge drop) —
all fixed with regression tests.
