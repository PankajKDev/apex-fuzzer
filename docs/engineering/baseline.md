# Baseline — stateful safety & evidence workstream

Recorded before any Milestone 1 changes. Reference point for
regressions in detection behavior, budgets, and finding IDs.

- Commit SHA: `de6cd0d77937e658832f3511d2b818ec667efefa` (main)
- Branch for this work: `fix/stateful-safety-and-evidence`
- Test command: `.venv/bin/python -m pytest tests/ -q`
- Results at baseline: **230 passed** (3.12), **230 passed + 4 skipped**
  (3.10, live-Chromium tests skip without Playwright there)
- Python: 3.12.3 (dev venv) + 3.10 (CI matrix)
- Key deps: requests 2.34.2, PyYAML 6.0.3, colorama 0.4.6,
  pytest 9.1.1, playwright 1.63.0 (optional extra)
- Suite runtime: ~10 s (3.12, includes live-browser tests)

## Known risks at baseline (being fixed in this workstream)

1. **Race consistency check is vacuous** (`logic/race.py`):
   `len({tuple(rr.hashes)}) == 1` is always true — varied all-200
   responses with no IDs were counted "clean" → false `negative`.
   Fix: `len(set(rr.hashes)) == 1`; ambiguous rounds stay
   `inconclusive` (Rule 7).
2. **Finding IDs unstable across processes**: `abs(hash(...))` is
   seed-randomized → resume dedup, evidence links, and regression
   comparison break. Fix: SHA-256 `stable_finding_id()`.
3. **Request costs undercounted**: race concurrency×rounds and
   business-logic baselines/mutations/replays consume one budget
   unit per endpoint regardless of actual traffic. Fix: `RequestPlan`
   reservation before each sweep.
4. **No fail-closed authorization** for stateful/burst/claiming
   modules: `--race`, `--business-logic`, takeover claims, and
   stored-XSS persistence run on flags alone. Fix: opt-in strict
   mode with auth-ref, allowlist, validity window, ack.

## Expected behavior for state-changing probes (unchanged by M1)

- Every mutating sweep honors scope → budget → rate limit.
- `blocked`/`error`/`inconclusive` are never recorded as negatives.
- Findings require behavioral evidence (callbacks, shape matches
  with baselines, unescaped rendering, invariant violations).
- New strict mode only *adds* gates; default (non-strict) behavior
  is byte-for-byte the baseline behavior.
