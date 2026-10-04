# Release checklist

Run this checklist from a clean checkout for each release candidate. Record
the commit, Python versions, commands, and results in the release notes.

## Scope and authorization

- [ ] Review current program eligibility; exclude DoS/resource exhaustion,
      destructive actions, and any prohibited class.
- [ ] Confirm the `passive` local-lab quickstart stays on loopback and skips
      public archive lookups for private targets.
- [ ] Review strict preflight behavior with a synthetic authorized target and
      a deliberately invalid/missing authorization reference. Confirm refusal
      occurs before scan traffic.
- [ ] Verify stateful checks remain disabled or fail closed without the
      required strict authorization, allowlist, time window, request budget,
      and per-run acknowledgment.
- [ ] Do not run an authenticated release test against a bounty target. Use a
      controlled fixture with synthetic identities and data.

## Detection and compatibility

- [ ] Run focused unit, negative, and failure-path tests for every changed
      validator; tests must not contact external targets.
- [ ] Run the full suite and coverage floor on Python 3.10 and 3.12.
- [ ] Run `make lint`, `make typecheck`, and `make build`.
- [ ] Check `git diff --check`, package contents, and clean sdist install/import.
- [ ] Confirm stable finding IDs across two runs over the same deterministic
      fixtures; random probe markers must not enter ID inputs.
- [ ] Review `coverage.json`: blocked, inconclusive, untestable, and
      not-tested paths must not be reported as negative.
- [ ] Verify finding taxonomy compatibility: `result_status` values are
      documented, old findings load with derived statuses, and report/evidence
      output preserves negative, inconclusive, and verified-effect states.
- [ ] Recheck the auth-gated CORS and redirect candidate wording against the
      actual evidence thresholds; neither may overstate browser impact.

## Documentation and release artifacts

- [ ] Review the [local-lab quickstart](local-lab-quickstart.md),
      [known limitations](known-limitations.md), and
      [sample artifacts](sample-artifacts/); confirm all examples are
      synthetic and contain no credentials or real target data.
- [ ] Update README and `progress.md` for code, config, metrics, coverage,
      and behavior changes. Explain breaking/additive output schema changes.
- [ ] Check CLI `--help`, `--doctor`, config parsing, and the strict
      zero-network `--dry-run` path.
- [ ] Review dependencies and external-tool versions/flags; document tool
      traffic that is outside Apex's shared request budget.
- [ ] Run dependency audit and secret scanning; inspect the package manifest
      and generated artifacts for accidental local files.
- [ ] Update the changelog/version and attach the test/build evidence to the
      release candidate.
- [ ] Obtain maintainer review before tagging or publishing.
