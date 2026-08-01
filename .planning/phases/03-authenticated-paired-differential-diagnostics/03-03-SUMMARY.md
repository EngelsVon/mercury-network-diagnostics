---
phase: 03-authenticated-paired-differential-diagnostics
plan: "03"
subsystem: authenticated-paired-orchestration
tags: [python, asyncio, peer-control, paired-diagnostics, cli]
requires:
  - phase: 03-01
    provides: authenticated bounded peer frames and application-owned listener lifecycle
  - phase: 03-02
    provides: source-bound paired listener evidence and fixed data-plane profiles
provides:
  - authenticated fixed-manifest paired role coordination
  - canonical endpoint-labelled directional evidence matrix
  - facade-only paired CLI and authoritative JSON projection
affects: [phase-04, peer-control, cli]
tech-stack:
  added: []
  patterns: [fixed manifest control body, independently admitted role executors, pure cited matrix projection]
key-files:
  created: []
  modified: [src/mercury/peer.py, src/mercury/paired.py, src/mercury/app.py, src/mercury/render.py, tests/test_paired.py, tests/test_cli.py]
key-decisions:
  - "Peer submit frames accept only the paired-v1 manifest and a fixed role label; they cannot nominate targets, ports, payloads, scopes, resolvers, or runners."
  - "Each authenticated endpoint returns its own terminal canonical result; aggregation labels observations by endpoint and role before deriving the one paired-health conclusion."
  - "Human paired output begins with cited directional matrix rows while JSON remains result_to_wire of the identical application result."
metrics:
  duration: approximately 45 minutes
  completed: 2026-08-02
---

# Phase 03 Plan 03: Authenticated Paired Orchestration Summary

**Authenticated fixed-manifest role swapping joins independently admitted endpoint evidence into one cited A→B/B→A diagnostic result.**

## Accomplishments

- Extended strict peer frames with only fixed paired-manifest submit/status/result envelopes, retaining bounded codec validation for a remote canonical result and rejecting all scan selectors.
- Added server-side paired control handlers and a client-side authenticated coordinator that performs capability, submit, and result retrieval before building one endpoint-labelled result with an honest partial/failed/healthy conclusion.
- Wired paired handlers and runners through `MercuryApplication`; the CLI remains a facade and its human projection starts with the directional matrix while JSON preserves the exact canonical result.
- Added controlled loopback regression coverage for role swapping, source-safe frame content, partial uncertainty, CLI JSON identity, matrix citations, and the explicit opt-in two-machine procedure.

## Task Commits

1. Task 1 — `3d26fd0` feat(03-03): compose authenticated paired roles
2. Task 2 — `6cef689` feat(03-03): project paired results through CLI
3. Task 3 — `3720330` test(03-03): cover paired continuation gate

## Verification

- `python -m unittest tests.test_peer tests.test_paired tests.test_cli -v` — passed (36 tests)
- `python -m unittest discover -s tests -v` — passed (210 tests; 3 Windows permission-model skips)
- `python -m compileall -q src tests` — passed
- `ruff check src tests` — passed
- `git diff --check` — passed

## Deviations from Plan

### Auto-fixed Issues

1. [Rule 1 - Bug] Made generated peer correlations valid for the strict frame grammar.
   - **Found during:** Task 3 full-suite verification
   - **Issue:** `secrets.token_urlsafe()` may begin with `_` or `-`, while correlation IDs must begin alphanumeric.
   - **Fix:** Prefix generated correlations with `p` before authenticated frame construction.
   - **Files modified:** `src/mercury/paired.py`, `tests/test_paired.py`
   - **Commit:** `3720330`

## Two-Machine Verification

The automated gate is loopback-only. A later, explicit opt-in smoke may use only the user-authorized Ubuntu peer at its configured address, temporary restrictive-permission certificate/token files, the fixed manifest, sanitized copied evidence, and cleanup of those temporary remote files. It must not initiate SSH automatically.

## Self-Check: PASSED

- Confirmed all six implementation/test files exist.
- Confirmed commits `3d26fd0`, `6cef689`, and `3720330` exist in Git history.
