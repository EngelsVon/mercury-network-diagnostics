---
phase: 01-evidence-and-safety-foundation
plan: "01"
subsystem: evidence-storage
tags: [python, dataclasses, json, sqlite, schema]
requires: []
provides:
  - Immutable versioned evidence, conclusion, capability, progress, and result models
  - Strict deterministic JSON codec with compatible-major validation
  - Transactional, retained, secret-free local SQLite history
affects: [phase-2, phase-3, phase-4, phase-5, cli, web, peer]
tech-stack:
  added: [CPython-3.11+, psutil, sqlite3]
  patterns: [canonical-domain-models, strict-boundary-parsing, typed-persistence-projection]
key-files:
  created: [src/mercury/models.py, src/mercury/codec.py, src/mercury/history.py]
  modified: [pyproject.toml, src/mercury/__init__.py]
key-decisions:
  - "Protocol evidence and semantic disposition remain separate axes."
  - "History stores canonical source evidence, not arbitrary frontend dictionaries."
patterns-established:
  - "Frozen typed core values are reconstructed at every wire/storage boundary."
  - "Silence, timeout, refusal, unavailable, error, and cancellation remain distinct."
requirements-completed: [EVID-01, EVID-02, EVID-03, HIST-01]
duration: combined phase execution
completed: 2026-07-30
---

# Phase 1 Plan 01: Evidence Ledger Summary

**Immutable evidence contracts, deterministic JSON, and transactional bounded SQLite history form one durable source of truth.**

## Performance

- **Duration:** Combined with the Phase 1 implementation and review cycle
- **Started:** 2026-07-30T02:50:38+08:00
- **Completed:** 2026-07-30T05:39:21+08:00
- **Tasks:** 3
- **Primary files:** 8

## Accomplishments

- Added exact-type, deeply immutable canonical result models and complete
  evidence/disposition truth tables.
- Added stable JSON encoding plus strict duplicate, size, number, version, enum,
  timestamp, and reference validation.
- Added SQLite lifecycle/event history with migrations, owner leases, atomic
  terminal writes, retention-on-read, and current-user file handling.
- Replaced arbitrary request persistence with field-by-field projections and
  centralized credential/raw-content rejection.

## Task Commits

The baseline landed in `e198fbe`; deep-review corrections were committed
atomically in `1b2385d`, `0c0801e`, `3ada82c`, `2267be5`, `14da19c`,
`e30dccc`, `c87b629`, and `274f39f`.

## Decisions Made

- One schema serves CLI, future WebUI, reports, and peer correlation.
- Compatible `1.x` documents are accepted; unsupported majors fail closed.
- Explicit history parents are never chmodded; only Mercury-created private
  directories are tightened.

## Deviations from Plan

Deep review exposed mutable constructors, incomplete secret filtering, unsafe
parent permission changes, and non-atomic lifecycle paths. All were fixed
before this plan was accepted; no product scope was added.

## User Setup Required

None.

## Next Phase Readiness

Policy, planner, task execution, and every later presentation adapter can
consume one stable evidence ledger.

