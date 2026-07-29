---
phase: 01-evidence-and-safety-foundation
reviewed: 2026-07-29T21:39:21Z
depth: deep
baseline: 46f9c1d
fixed_by: 274f39f
findings:
  critical: 3
  warning: 0
  open: 0
status: clean_after_fixes
---

# Phase 1: Independent Post-Fix Review

The first fix report was not accepted on self-attestation alone. A second
goal-backward review traced untrusted task configuration through persistence,
normal runner return through terminalization, and admitted steps through
stored observations.

## Findings and Resolution

### R2-01: Allowed request containers could still persist raw content

`steps` and `targets` were allowlisted only at the top level. A value such as
`{"steps": [{"data": "RAW-CUSTOM-UDP-BYTES"}]}` therefore reached SQLite.
Credential assignment text such as `access_token=...` and `password: ...` also
escaped the value detector.

**Resolution:** Every request field now has an exact scalar/sequence schema,
`HistoryStore.create_task()` reapplies that projection, and credential
assignment patterns are centrally rejected/redacted.

### R2-02: A runner could return an empty successful task

A runner could return without admitting or completing any work. The service
then persisted `completed` with zero evidence despite a non-empty authorized
plan. A step could also be marked complete without any observation.

**Resolution:** Normal completion now requires all authorized steps to be
completed, and each step must record at least one bound observation before
completion. Cancellation and failure may still retain honest partial progress.

### R2-03: Step evidence lacked authoritative endpoint metadata

An observation was checked against an admitted address and attempt, but a
runner could still attach TCP-only evidence to a UDP step or supply ambiguous
port/transport metadata.

**Resolution:** The task core injects reserved plan-step ID, requested target,
port, transport, and DNS-change fields; runners cannot override them.
Obviously transport-incompatible evidence kinds are rejected. DNS preflight
was also moved behind duplicate/concurrency admission checks.

## Verification

- `python -m unittest discover -s tests -v`: 115 passed, 3 expected
  Windows-only skips for POSIX permission bits.
- Clean wheel and temporary-venv console/module parity passed inside the suite.
- `python -m compileall -q src tests`: passed.
- `ruff check src tests`: passed.
- `git diff --check`: passed.
- Direct reproductions for nested raw request content and credential assignment
  text now raise `HistoryError`.

## Remaining Trust Boundary

Mercury does not attempt to sandbox arbitrary Python imported into its own
process. Built-in runners are trusted implementation code and there is no v1
plugin SDK. The core nevertheless validates their plan consumption and stored
evidence so ordinary implementation mistakes fail closed.

**Verdict:** clean for the Phase 1 contract.

