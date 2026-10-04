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
| SQL injection | Mutation prescreen, paired boolean controls, parameter-pinned sqlmap with bounded boolean/error techniques | Deep / evidence path | sqlmap confirmation is tool-dependent; time-delay payloads are excluded from the prescreen. Keep evidence and candidate status conservative. |
| Reflected / DOM XSS | Mutation prescreen, parameter-pinned Dalfox, same-origin Playwright replay | Deep / evidence path | Confirm only when the browser observes the unique execution marker; missing browser support remains candidate/inconclusive. |
| Stored XSS | Bounded inert canary persistence and render correlation, opt-in | Deep / evidence path | Requires explicit program permission because it writes canary data. Confirm only on correlated render evidence. |
| SSRF | Application-aware sink ranking, per-request Interactsh callback correlation; local lab collector supported | Deep / evidence path | Callback proves an outbound interaction, not internal data access or impact. Stored SSRF is separately opt-in. |
| BOLA / IDOR / BFLA | Identity-aware object swaps, method matrix, differential identity comparisons | Deep / evidence path | Requires meaningful, authorized identities and ownership evidence; state-changing verbs need strict authorization. |
| Business logic | Bounded value mutations plus optional user-defined readback invariants | Deep when assertions exist; otherwise candidate | Generic value changes cannot establish impact without an application-specific invariant and safe readback. Stateful, opt-in. |
| Race conditions | Synchronized requests with generic/single-use/idempotency/inventory profiles and verification | Deep / evidence path, gated | Burst requests are disabled by default and must be explicitly allowed. Never use for DoS/resource-exhaustion. |
| Subdomain takeover | Subzy fingerprinting and tko-subs provider validation | Fingerprint / gated claim | Fingerprint is not proof. Claiming is a separate high-impact action and remains opt-in/authorization-gated. |
| Known CVEs, exposed panels, misconfiguration | Nuclei templates | Template-assisted | Depends on installed template set, tags, protocol support, and response checks. Review exact template and reproduce safely. |
| Open redirect | Apex observed-field validator plus Nuclei templates | Bounded active validation | Apex tests only redirect-like query names present in discovered GET endpoints; it caps endpoints/fields, uses a unique `.invalid` host, never follows redirects, and confirms only a 3xx `Location` containing the exact marker host. It does not yet inspect body/header redirect inputs. |
| SSTI | Nuclei/template signals only | Template-assisted | No Apex parameter-aware arithmetic/control pair or engine-specific confirmation. SSTImap supports broad SSTI and code-execution workflows, so direct automation is not a safe drop-in. |
| Path traversal / LFI | Nuclei and technology/CVE templates | Template-assisted | No Apex validator chooses a known non-sensitive marker or confirms a controlled file read. Generic file-read payloads can expose data; keep manual and program-specific. |
| XXE | Nuclei templates and shared Interactsh infrastructure | Template-assisted | No XML request-shape parser or safe, class-aware XXE validator. A callback alone needs parser/request evidence and nonce correlation before confirmation. |
| OS command injection | Nuclei templates only | Template-assisted | No Apex validator. Commix is maintained and broad, but its normal detection techniques execute commands; integration needs a strictly bounded, non-destructive proof contract first. |
| NoSQL / LDAP / expression injection | Nuclei templates and generic mutation candidates | Template-assisted / weak | No dedicated parameter-aware controls or reliable class-specific confirmation. Do not label generic error changes as confirmed injection. |
| CORS / security headers / cookie flags | Bounded arbitrary-Origin probe using configured cookie-authenticated identities | Candidate-level active validation | Exact origin reflection + `Access-Control-Allow-Credentials: true` + a non-empty successful response creates a candidate only. Browser cookie/SameSite behavior and sensitive cross-origin readability are not confirmed. |
| JWT / OAuth / session flaws | Passive JWT/OAuth/session modeling; login/session workflow support | Context / partial | No systematic claim-level JWT attack validator. Keep weak-secret brute force excluded; active token manipulation requires an authorized identity and clear access-control evidence. |
| GraphQL authorization / introspection | API-spec and endpoint discovery; authz workflows where operations become endpoints | Context / partial | No GraphQL operation-aware query/mutation planner or field-level authorization oracle. Avoid expensive/deep introspection by default. |
| SSRF chains / second-order fetch | OpenAPI-aware input ranking, related trigger selection, correlated callbacks | Deep / opt-in | Persistence and trigger actions can change state. Keep separately authorized and bounded. |

## Maintained tool fit

| Tool | Best-fit use in Apex | Integration decision |
|---|---|---|
| Nuclei + ProjectDiscovery templates | Broad CVE, exposure, and configuration checks | Already integrated. Keep it as the breadth layer; use template metadata and request costs before adding template-specific behavior. |
| sqlmap | SQLi engine and parameter-level confirmation | Already integrated. Preserve candidate parameter pinning, boolean/error-only defaults, time/concurrency caps, and no enumeration. |
| Dalfox | XSS discovery and structured results | Already integrated. Keep browser execution as the higher evidence threshold for confirmation. |
| Interactsh client | OOB registration, callbacks, and interaction collection | Wrapper implemented; custom REST and local collector paths remain for compatibility. |
| Commix | OS command-injection detection and exploitation | Do not wire directly into the normal scan. Evaluate only after a safe detection profile can be enforced and measured. The upstream tool documents command-execution techniques. |
| SSTImap | Broad template-engine detection and exploitation | Do not wire into the normal scan yet. First add Apex request-shape selection and a non-executing paired-expression proof; invoke SSTImap only in an explicit, bounded opt-in path if its behavior can be constrained. |
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

1. **SSTI:** implement request-shape aware, paired inert arithmetic controls
   first. Keep code execution, file reads, and shell checks out of automated
   confirmation.
2. **XXE and traversal/LFI:** design from explicit XML/file inputs and
   application-specific safe markers. Prefer Nuclei for known CVE cases until
   a safe parameter-aware oracle is defined.
3. **Command injection, JWT, and GraphQL:** require separate threat models,
   opt-in policy controls, and measured false-positive/traffic evidence before
   adding active adapters.

Reassess this matrix when tool integrations or program policies change. Do not
count passive discovery or a broad template match as deep coverage.
