---
phase: 02-local-snapshot-and-layered-diagnosis
plan: "02"
subsystem: evidence-policy-task-boundary
tags: [schema, probe-kind, authorization, budgets, sqlite, unittest]
requires:
  - phase: 02-01
    provides: Passive inventory services and platform adapters
provides:
  - Exact schema 1.0/1.1 result reading with typed TLS, ping and path evidence
  - Sparse probe compilation with digest-bound identity and explicit scope kinds
  - Service-bound probe observations and safe history event projections
affects: [phase-02-03, diagnosis, peer]
tech-stack:
  added: []
  patterns: [exact-schema-vocabulary, sparse-probe-identity, service-bound-evidence]
key-files:
  created: []
  modified: [src/mercury/models.py, src/mercury/planner.py, src/mercury/policy.py, src/mercury/tasks.py, src/mercury/history.py]
key-decisions:
  - "Schema readers accept only the implemented 1.0 and 1.1 vocabulary."
  - "Probe identity is sparse and digest-bound; no probe uses a dummy port or transport."
requirements-completed: [DIAG-01, DIAG-03, DIAG-04]
duration: 1h
completed: 2026-08-01
---

# Phase 02 Plan 02: Schema and Admission Boundary Summary

**Schema 1.1, sparse authorized probes, and service-bound evidence establish the safe Phase 2 execution boundary.**

## Accomplishments

- Added exact schema-version/evidence vocabulary checks and typed TLS, native ping and path evidence.
- Compiled finite `ProbeSpec` inputs into canonical steps with digest, scope, logical-packet and reservation accounting.
- Bound runner observations to the admitted probe, direction, target and immutable identity fields; history retains only explicit event projections.

## Task Commits

1. Schema vocabulary — `c815fa5`
2. Sparse probe plans — `53f7b87`
3. Prepared evidence binding — `8749282`

## Verification

- `python -m unittest discover -s tests -q` — 149 passed, 3 skipped.
- `python -m compileall -q src tests` — passed.
- `git diff --check` — passed.

## Deviations from Plan

None - plan executed with the existing standard library and `psutil` runtime boundary.

## Next Phase Readiness

Plan 02-03 can add immutable profiles and real bounded protocol/native runners on the now-authoritative sparse plan boundary.

## Self-Check: PASSED
