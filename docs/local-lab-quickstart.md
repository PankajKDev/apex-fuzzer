# Local discovery lab quickstart

This walkthrough exercises endpoint discovery against a static site on
loopback. It does not run vulnerability payloads or change application state.
The `passive` profile still sends read-only HTTP/HTTPS discovery probes to the
lab; it is the lowest-impact profile, not a zero-request mode.

## 1. Serve the sample site

From the repository root, start the local web server:

```bash
python -m http.server 8765 \
  --bind 127.0.0.1 \
  --directory docs/local-lab/site
```

The sample site is static and intentionally non-vulnerable. It includes a
small link graph, a query-string example, and an OpenAPI document. Keep this
server bound to loopback.

## 2. Run the lowest-impact scan

In another terminal, from the repository root:

```bash
python -m apex_fuzzer.cli \
  --domain http://127.0.0.1:8765 \
  --profile passive \
  --output output/local-lab
```

This profile disables Nuclei, validation payloads, OAST, parameter mining,
AI, and takeover checks. When the target is loopback/private, Apex skips
ParamSpider and public Wayback/Gau lookups so the local target is not sent to
those services. If installed, httpx, Katana, and hakrawler may make discovery
requests to the loopback server. httpx may try both HTTP and HTTPS; the sample
server only speaks HTTP, so its log can include harmless local TLS handshake
errors.

Review `output/local-lab/127.0.0.1:8765/endpoints.jsonl`,
`coverage.json`, `metrics.json`, and `report.html`. Stop the local server with
Ctrl-C when finished.

## 3. Safety and expected result

- Requests stay on `127.0.0.1:8765`; the public archive lookups are skipped
  for loopback and private IP targets.
- The passive profile does not run the open-redirect or CORS validators.
- The static search page does not process its query parameter, and the lab
  contains no vulnerability fixture. Zero findings is expected and does not
  demonstrate that active validators work.
- This workflow is for discovery and report-path familiarization. To test
  active validators, use a purpose-built local vulnerable lab and a separate
  explicitly authorized validation profile.
