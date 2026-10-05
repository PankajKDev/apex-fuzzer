# Bug bounty class and tool coverage matrix

This matrix describes Apex-Fuzzer's current **web application** coverage and
which gaps justify further integration. “Covered” means the named path exists
in the current checkout; it does not promise that every program, endpoint, or
technology is testable. Program policy controls whether a class or technique
is eligible. Exclude denial of service, resource exhaustion, brute force,
credential stuffing, destructive actions, and any program-prohibited tests.

## Coverage definitions

- **Deep / evidence path:** Apex has a class-aware workflow and a stated
  evidence threshold beyond a generic scanner alert.
- **Template-assisted:** Nuclei or another installed tool can report matches,
  but Apex does not yet provide class-specific candidate selection and
  confirmation. Counts as a lead, not complete deep coverage.
- **Context / manual:** useful discovery or passive parsing exists; active
  class verification depends on the operator or an external workflow.
- **Not covered:** no reliable, dedicated workflow is present.

Nuclei is deliberately treated as template-assisted for generic classes:
template availability, tags, request behavior, and evidence strength vary.
Its output is not proof that an application-aware test was performed.

## Current coverage

| Class | Current path | Coverage | Main gap / evidence threshold |
|---|---|---|---|
| SQL injection | Query/form/JSON/multipart/header/cookie mutation prescreen (lead-independent sweep in validation runs), plus retained-request XML text-field controls for a unique observed simple element; parameter-pinned sqlmap for query/form/JSON, and exact-shape sqlmap via ephemeral raw-request file when one retained browser request matches the in-scope endpoint and candidate parameter | Deep / evidence path for supported shapes | Supported via raw file: GET query, form-urlencoded, JSON (incl. nested names), textual XML with declared XML content type and one unique plain-text element. Still gated: non-GET bodies need state-change authorization; multipart, binary/undecodable, oversized (>1 MB), malformed, unsupported-method, out-of-scope, and ambiguous multi-identity matches stay inconclusive/blocked without sending. Time-delay payloads are excluded; differential results remain candidates; no enumeration. |
| Reflected / DOM XSS | Mutation prescreen (GET query plus observed form/JSON/XML/multipart/header/cookie bodies), parameter-pinned Dalfox (GET query only), same-origin Playwright replay over query, fragment, and cookie sources | Deep / evidence path for supported shapes | XSS prescreen reuses one retained in-scope request per finding, preserves method/headers/content-type/peers, and requires state-change authorization for non-GET bodies; GET-body, unsupported-method, and ambiguous shapes stay inconclusive without sending. Dalfox stays GET-query only; browser falls back to fragment then cookie sinks with the same marker. Confirm only when the browser observes the unique execution marker; missing browser support remains candidate/inconclusive. |
| Stored XSS | Bounded inert canary persistence and render correlation, opt-in | Deep / evidence path | Requires explicit program permission because it writes canary data. Confirm only on correlated render evidence. |
| SSRF | Application-aware sink ranking, per-request callback correlation, bounded parser-bypass variants (decimal/hex/octal/IPv6/zero-IP, backslash, userinfo-decoy) with fresh nonces, token-reflection readback flag; local lab collector supported | Deep / evidence path for fetch proof | A callback proves an outbound fetch, not internal data access. Bypass hits stay callback-grade; a reflected token is a recorded full-read signal that never upgrades alone. Redirect-following and DNS rebinding need controlled infrastructure and stay manual procedures. Stored SSRF is separately opt-in. |
| BOLA / IDOR / BFLA | Identity-aware GET object swaps, method matrix, differential identity comparisons; optional authenticated browser capture retains per-identity observed request shapes in memory, including multipart field-name/filename/content-type metadata | Deep for supported read-access paths; write/operation proof incomplete | Authenticated capture is opt-in, same-origin and read-method only; persisted artifacts redact credentials and omit bodies (multipart persists only safe shape metadata plus body length). It does not replay writes or perform application-specific readback. Stateful write proof is opt-in (`authorization.write_replay` + state-change acknowledgment, test accounts/objects only): the attacker's observed POST/PUT/PATCH request replays with only the victim ID swapped, and only a clean owner readback showing newly persisted attacker values confirms (`verified-effect`); clean re-reads refute to inconclusive. Multipart validation/replay remains unimplemented. |
| Business logic | Bounded value mutations plus optional user-defined readback invariants | Deep when assertions exist; otherwise candidate | Generic value changes cannot establish impact without an application-specific invariant and safe readback. Stateful, opt-in. |
| Race conditions | Synchronized requests with generic/single-use/idempotency/inventory profiles and verification | Deep / evidence path, gated | Burst requests are disabled by default and must be explicitly allowed. Never use for DoS/resource-exhaustion. |
| Subdomain takeover | Subzy fingerprinting and tko-subs provider validation | Fingerprint / gated claim | Fingerprint is not proof. Claiming is a separate high-impact action and remains opt-in/authorization-gated. |
| Known CVEs, exposed panels, misconfiguration | Nuclei templates | Template-assisted | Depends on installed template set, tags, protocol support, and response checks. Review exact template and reproduce safely. |
| Open redirect | Apex observed-field validator plus Nuclei templates | Bounded active validation | Apex tests only redirect-like query names present in discovered GET endpoints; it caps endpoints/fields, uses a unique `.invalid` host, never follows redirects, and confirms only a 3xx `Location` containing the exact marker host. It does not yet inspect body/header redirect inputs. |
| SSTI | Nuclei lead plus paired inert arithmetic validation (`{{...}}`, `${...}`) on an observed parameter | Bounded active validation | Confirms only when both distinct expressions render to exact values inside unique markers. Query inputs use GET; observed POST body fields require `safety.allow_state_change`. Other template syntaxes, non-reflected sinks, and engine-specific contexts remain untested. |
| Path traversal / LFI | Nuclei lead plus bounded GET checks for a configured harmless marker file | Marker-confirmed, operator-configured | Requires an exact relative path and exact known file contents (8+ characters); caps depth at six, uses only observed path-like query parameters, and never probes standard sensitive files. No marker configured means no request. |
| XXE | Nuclei lead plus one external-entity callback probe on retained observed XML POST request material (XML, SVG, SOAP, XMP text; sniffed when undeclared) | Bounded active validation, state-change gated | Confirms only a nonce-correlated OAST interaction. Requires a live OAST provider, observed XML body, and `safety.allow_state_change`; sends no local-file entity. Office/OLE/binary containers fail closed to isolated fixtures. |
| OS command injection | Nuclei templates only | Template-assisted | No Apex validator. Commix is maintained and broad, but its normal detection techniques execute commands; integration needs a strictly bounded, non-destructive proof contract first. |
| NoSQL / LDAP / expression injection | Nuclei templates and generic mutation candidates | Template-assisted / weak | No dedicated parameter-aware controls or reliable class-specific confirmation. Do not label generic error changes as confirmed injection. |
| CORS / security headers / cookie flags | Bounded arbitrary-Origin probe using configured cookie-authenticated identities; optional Chromium `fetch(..., credentials: include)` proof | Candidate by default; browser-confirmed when the configured cookie is sent and JavaScript reads a non-empty successful response | The browser stage is opt-in (`validation.cors_browser`), origin/target requests are restricted, and response bodies are omitted. Loopback browser checks pass for SameSite=None and Lax behavior. |
| CSRF | Tokenless state-changing form sweep (informational) plus opt-in Chromium cross-site execution proof: null-origin auto-submit with victim session, cookie-sent + 2xx server acceptance | High finding on proven execution; denial with a working same-origin baseline is a genuine negative | Proof needs `validation.csrf_browser`, state-change ack, Playwright, and a victim session; persistence of the state change is not verified (confirm readback). Loopback checks pass for Lax-denied and None+Secure-executed. |
| JWT / OAuth / session flaws | Passive JWT/OAuth/session modeling plus caller-owned Bearer replay: signature confusion (alg-none, empty signature) and claim tampering (exp removal, audience mismatch, privilege upgrade/injection with the original signature kept); MFA transition checks (pre- vs post-MFA test sessions), OAuth authorize-URL analysis (state/implicit), and bounded PKCE-strip and OAST-redirect probes (observe-only, no redemption) | Deep for MFA gating and OAuth transitions; candidate-grade for JWT claim validation | Claim acceptance proves only non-rejection — confirm the privilege takes effect, not just acceptance. Keep weak-secret brute force excluded; MFA/OAuth probes need configured test sessions. |
| GraphQL authorization | Same-operation variable-swap replay (query operations only; mutations never replayed) with ownership-graded comparison; variable-aware SQLi/XSS prescreens | Deep for supported read paths | Owner baseline fetched first on the same operation; completed denials are genuine negatives. Field-level policies and introspection-driven planning remain manual. |
| SSRF chains / second-order fetch | OpenAPI-aware input ranking, related trigger selection, correlated callbacks | Deep / opt-in | Persistence and trigger actions can change state. Keep separately authorized and bounded. |
| HTTP Parameter Pollution | Baseline vs duplicated-parameter GET plus a repeat-value control over observed query fields; second-occurrence blanking separates precedence effects from input echo | Bounded active validation (read-only) | No generic Nuclei template covers HPP (verified against nuclei-templates `generic/` + `fuzzing/` 2026-10-05); CVE-specific templates still run in the Nuclei stage. Identical handling is a genuine negative; echo-only differences are not candidates. |
| Mass assignment | Self-object replay of the tester's observed mutating shape with `role` / `is_admin` added (`apex-mass-probe` value, never a real privilege), verified via own-object readback | Bounded active validation, write-gated | Same `authorization.write_replay` + state-change gate as write replay; test accounts/objects only. Persistence proves binder acceptance and stays candidate (impact needs human judgment, like swaps); completed 4xx denials against a 200 own-object baseline are genuine negatives. Already-bound fields and XML/multipart shapes fail closed. No generic Nuclei template covers mass assignment. |
| Insecure deserialization | Type-confusion error oracle (scalar control + array/object probes) over JSON body params; deserializer exception families (jackson/gson/php/pickle/yaml/java/dotnet/ruby-marshal) | Candidate-only error oracle, state-change gated | Exception text proves a deserializer choked, never gadget reachability — confirm in an isolated fixture. Product-specific deserialization CVEs (fastjson, …) still run as Nuclei templates; no generic Nuclei detector exists. |
| HTTP request smuggling | None (documented exclusion) | Manual procedure only | No generic Nuclei template exists either. Desync probing needs raw-socket framing (the HTTP client library normalizes it away) and risks connection poisoning, which falls under the excluded DoS/resource-exhaustion scope. Test smuggling manually against isolated targets with dedicated tooling. |
| postMessage / SOP | Static sweep over cached first-party bundles: unguarded message handlers, wildcard-targetOrigin posts (graded by nearby sensitive tokens), document.domain assignment | Static candidates (medium/low, possible confidence) | No code excerpts persisted — evidence keeps file, line, and marker family. Dynamic confirmation (victim session interaction) stays manual. |

## Maintained tool fit

| Tool | Best-fit use in Apex | Integration decision |
|---|---|---|
| Nuclei + ProjectDiscovery templates | Broad CVE, exposure, and configuration checks | Already integrated. Keep it as the breadth layer; use template metadata and request costs before adding template-specific behavior. |
| sqlmap | SQLi engine and parameter-level confirmation | Already integrated. Preserve candidate parameter pinning, single retained-request selection (no identity fanout), exact origin/path matching, and raw-file (`-r`) use only for supported text shapes inside a private temporary directory that is deleted after the run. Persist only fixed result signals, not free-form sqlmap output; retain boolean/error/union techniques by default, time/concurrency caps, and no enumeration. Time-based confirmation joins only under explicit opt-in (`validation.sqli_time_based` / `--sqli-time`, bounded `--time-sec`); stacked queries stay excluded (possible writes). The external process has a 180-second cap but does not yet consume Apex's shared HTTP request budget. |
| Dalfox | XSS discovery and structured results | Already integrated. Keep browser execution as the higher evidence threshold for confirmation. |
| Interactsh client | OOB registration, callbacks, and interaction collection | Wrapper implemented; custom REST and local collector paths remain for compatibility. |
| Commix | OS command-injection detection and exploitation | Do not wire directly into the normal scan. Evaluate only after a safe detection profile can be enforced and measured. The upstream tool documents command-execution techniques. |
| SSTImap | Broad template-engine detection and exploitation | Apex now has a lead-driven, non-executing paired-expression proof. Keep SSTImap out of the normal scan; consider a bounded opt-in adapter only if measured engine coverage justifies it. |
| OWASP ZAP / Wapiti | Broad active web DAST | Do not add as another full crawler/scanner now; it would duplicate Nuclei and multiply traffic. Reconsider only for a demonstrated protocol or coverage gap with deterministic scope, rate, and evidence controls. |

Primary project references: [Nuclei](https://github.com/projectdiscovery/nuclei),
[Nuclei templates](https://github.com/projectdiscovery/nuclei-templates),
[sqlmap](https://github.com/sqlmapproject/sqlmap),
[Dalfox](https://github.com/hahwul/dalfox),
[Interactsh](https://github.com/projectdiscovery/interactsh),
[Commix](https://github.com/commixproject/commix),
[SSTImap](https://github.com/vladko312/SSTImap), and the current
[generic open-redirect template](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/generic/open-redirect-generic.yaml).

## Recommended implementation order

1. **Request fidelity and parser coverage:** XML SQLi now mutates one unique,
   observed simple text element while preserving the raw body and headers in
   the differential prescreen. SQLi plugins additionally reuse one retained
   browser request per finding through sqlmap's raw-request file: GET query,
   form-urlencoded, JSON (incl. nested names), and textual XML are supported
   when a single in-scope shape matches the candidate parameter; multipart,
   binary/undecodable, oversized, malformed, unsupported-method, out-of-scope,
   and ambiguous multi-identity shapes stay inconclusive/blocked without
   sending, with one thread, no retries, bounded timeout, no enumeration, and
   no credential/body values in findings or logs. Observed `multipart/form-data` is now captured
   safely: exact body bytes plus method/URL/headers stay runtime-only,
   field names feed the endpoint parameter model (file and credential/CSRF-like
   values blanked, no file content invented), and persisted traffic keeps only
   field name/filename/per-part content type/size plus body length with URL
   userinfo/fragments stripped and sensitive query/header values redacted.
   Multipart prescreen replay is implemented for observed text-only bodies; multipart BOLA write replay remains unimplemented. Non-query XSS is now
   covered by the mutation prescreen for observed form/JSON/XML bodies
   (Dalfox itself remains GET-query only); header/cookie parameters and
   GraphQL introspection-driven planning remains manual. Extend XML
   through controlled integration fixtures next. Keep
   using maintained engines rather than adding another generic payload engine.
2. **Stateful BOLA/BFLA proof:** the capture foundation can now retain
   identity-specific request shapes in memory without persisting secrets or
   bodies. Next, connect those shapes to owner/attacker comparisons and
   application-specific readback; only exercise reversible test-owned changes
   under explicit authorization. Add GraphQL operation-aware checks.
3. **SSRF chain proof:** add isolated tests for renderer/import sinks,
   parser/redirect/rebinding controls, and stored-response readback. Keep
   callback-only confirmation separate from proof of internal data access.
4. **Authentication and cache coverage:** model MFA/OAuth transitions using
   test accounts and safe outcome assertions; unique-key deception probing
   is implemented (poisoning stays manual).
5. **SSTI follow-through:** measure paired-arithmetic behavior against
   actual template-engine fixtures and tune syntax coverage without adding
   code execution, file reads, or shell checks. A loopback Jinja2 fixture
   exercises the paired-arithmetic validator; other engines and contexts
   still need measured coverage.
6. **XXE and traversal/LFI follow-through:** verify retained-request behavior
   and operator-supplied marker setup in controlled local applications. Local
   lxml and file-endpoint integration fixtures now cover callback correlation
   and marker-only traversal, and the XXE test exercises Nuclei-shaped raw
   request extraction. A real controlled Nuclei scan is still needed to
   verify framework-specific request retention.
   Prefer Nuclei for known CVE cases and keep local-file reads out of XXE.
7. **Command injection and active JWT:** require separate threat models,
   opt-in policy controls, and measured false-positive/traffic evidence before
   adding active adapters.

Reassess this matrix when tool integrations or program policies change. Do not
count passive discovery or a broad template match as deep coverage.

## Writeup-derived gap review (2026-10-04)

I screened 48 hunter-submitted HackerOne disclosure entries by public title and
available synopsis: 10 each for SSRF and IDOR, and 7 each for SQLi, XSS, OAuth,
and business logic. I then read 8 detailed, publicly accessible writeups/case
studies: NahamSec's Lyft PDF-renderer SSRF, the GitLab DNS-rebinding SSRF
report, the Starbucks XML/time-based SQLi, a time-based blind SQLi writeup,
the MTN account-modification IDOR, the Yelp cookie/XSS account-takeover case,
a GraphQL stored-XSS chain, and an MFA-bypass case. The public HackerOne report
index is a selected disclosure collection, not a random or representative
sample; many linked report bodies require JavaScript or are blocked to
automated readers. This is a qualitative coverage analysis, not a measured
recall benchmark or a claim that all 48 report narratives were available in
full.

The repeated gaps are request/workflow coverage and impact proof, rather than
the absence of more generic payloads:

| Priority | Gap evidenced by the writeups | Apex limitation | Work to add before claiming coverage |
|---|---|---|---|
| P1 | Non-query and structured inputs: XML SQLi, headers/cookies, GraphQL variables, file uploads and renderer/import inputs recur in real findings. | SQLi differential checks now support retained XML bodies when the selected unique element and observed headers are available, and sqlmap reuses one retained shape via its raw-request file for GET query, form-urlencoded, JSON, and textual XML. Observed multipart bodies are captured (exact bytes runtime-only; field names/filenames/per-part content types extracted; file contents, credentials, CSRF values, and raw bodies never persisted). SQLMap stays inconclusive for multipart (1.8.4 finds no testable params; prescreen covers text fields), binary, oversized, malformed, unsupported-method, out-of-scope, and ambiguous multi-identity shapes; header/cookie prescreens are implemented (identity carriers excluded; sqlmap/Dalfox stay query/body); GraphQL introspection-driven planning remains manual; multipart prescreen replay is implemented (byte-exact single text-field replacement; file parts untouched) while sqlmap stays inconclusive there and uploaded document formats are not replayed natively. | Continue exact request replay for candidate-specific headers/cookies, GraphQL variables, and multipart/upload-parser flows. Keep unsupported/ambiguous XML and SQLMap multipart/binary inconclusive. |
| P1 | IDOR impact often requires a paired identity, victim-owned object ID, non-GET action, and readback; GraphQL operations and cross-tenant roles are common. | GET swaps remain the strongest active path. Optional authenticated capture now keeps per-identity requests in memory, but BFLA does not yet replay them and has no application-specific write readback. GraphQL is not operation/field aware. | Add owner/attacker comparison and opt-in stateful replay for explicitly test-owned objects, with configured readback assertions. Add operation-aware GraphQL authorization checks. |
| P1 | SSRF disclosures include full-response/readback, renderer and import chains, redirect/parser/filter bypasses, and DNS rebinding—not only an outbound callback. | OAST confirms callback interaction; it does not prove internal response access. Current probes use ordinary canary URLs and do not model a later fetch/render/readback chain or DNS-rebinding behavior. | Extend sink and trigger correlation for stored/second-order fetches; add safe local fixtures for parser divergence, redirect handling and rebinding. Report callback-only evidence separately from internal data/impact proof. |
| P1 | Exploitability is contextual: the Yelp and GraphQL XSS cases needed a browser-visible victim flow and a chain to account impact; MFA cases depended on the order in which session state was issued. | Browser validation confirms a narrow execution/readability condition, while authentication support is mainly passive/workflow modeling and does not systematically verify MFA/OAuth state transitions or account-linking outcomes. | Add explicit, test-account-only browser workflows for cookie/DOM/fragment inputs and auth transitions (pre/post-MFA session, OAuth state/redirect handling, account linking), with safe end-state assertions. |
| P2 | XXE reports include SVG, XMP/image metadata, office documents, SOAP and upload pipelines, often where the final impact is SSRF or file disclosure. | Apex's active XXE validator only modifies retained XML POST text bodies and confirms OAST; it does not parse/rebuild these container formats. | Reuse established file-format tooling in isolated fixtures; initially confirm only harmless callback behavior and keep file-read proof out of normal scans. |
| P2 | Web cache poisoning/deception appears as a chain to user data leaks and stored XSS, and is bounty-eligible when impact is demonstrated. | Unique-key deception probing (anonymous/victim/re-read triple, HIT plus victim-body equality required) runs in validation passes; poisoning and shared-state tests stay manual. | Extend only with more HIT-signal vocabularies and unkeyed-input analysis; never write shared cache entries. |
| P2 | Business-logic reports depend on domain-specific invariants such as price, quantity, invitation, ownership, or workflow state. | Apex's generic mutations cannot infer these semantics; reliable proof requires operator-supplied invariants and safe state verification. | Expand declarative workflow/readback assertions and coverage reporting; keep unknown business rules as manual-review leads. |

The report archive and representative detailed sources are linked here:
[HackerOne report index](https://github.com/reddelexc/hackerone-reports),
[SSRF report index](https://github.com/reddelexc/hackerone-reports/blob/master/docs/tops_by_bug_type/TOPSSRF.md),
[IDOR report index](https://github.com/reddelexc/hackerone-reports/blob/master/docs/tops_by_bug_type/TOPIDOR.md),
[SQLi report index](https://github.com/reddelexc/hackerone-reports/blob/master/docs/tops_by_bug_type/TOPSQLI.md),
[XSS report index](https://github.com/reddelexc/hackerone-reports/blob/master/docs/tops_by_bug_type/TOPXSS.md),
[OAuth report index](https://github.com/reddelexc/hackerone-reports/blob/master/docs/tops_by_bug_type/TOPOAUTH.md),
[business-logic report index](https://github.com/reddelexc/hackerone-reports/blob/master/docs/tops_by_bug_type/TOPBUSINESSLOGIC.md),
[NahamSec's Lyft SSRF writeup](https://www.nahamsec.com/posts/my-expense-report-resulted-in-a-server-side-request-forgery-ssrf-on-lyft),
[GitLab's disclosed DNS-rebinding report](https://gitlab.com/gitlab-org/gitlab-foss/-/issues/63959),
[Starbucks XML/time-based SQLi case](https://www.hackerone.com/blog/8-high-impact-bugs-and-how-hackerone-customers-avoided-breach-sql-injection),
[time-based blind SQLi writeup](https://bmacharia.com/blog/exploiting-blind-sql-injection),
[MTN IDOR case](https://www.hackerone.com/blog/how-idor-vulnerability-led-user-profile-modification),
[Yelp XSS-to-account-takeover case](https://www.hackerone.com/blog/how-cross-site-scripting-vulnerability-led-account-takeover),
[GraphQL stored-XSS writeup](https://www.pmnh.site/post/witeup_lhe_graphql_stored_xss/), and
[MFA-bypass case](https://www.hackerone.com/blog/how-inadequate-authentication-logic-led-mfa-bypass-and-account-takeover).
