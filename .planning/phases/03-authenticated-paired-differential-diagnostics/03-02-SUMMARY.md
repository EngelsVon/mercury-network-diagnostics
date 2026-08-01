---
phase: 03-authenticated-paired-differential-diagnostics
plan: "02"
subsystem: network-security
tags: [asyncio, tcp, udp, paired-diagnostics, evidence]
requires:
  - phase: 03-01
    provides: authenticated peer-control boundary and immutable plan contracts
provides:
  - source-bound, expiring TCP and UDP listener leases
  - admitted paired evidence phases with canonical budget and persistence checks
  - controlled loopback tests for fixed TCP/UDP profiles
affects: [03-03, paired-orchestration, cli]
tech-stack:
  added: []
  patterns: [fixed lease profile, TaskContext.record_paired, sparse mixed-payload plan validation]
key-files:
  created: [tests/test_paired.py]
  modified: [src/mercury/paired.py, src/mercury/tasks.py, src/mercury/planner.py]
key-decisions:
  - "Paired listener bytes must be reserved by immutable TCP/UDP steps before binding."
  - "Paired labels are evidence metadata only; direction remains fixed by the phase."
patterns-established:
  - "Pair listeners admit exact compiled steps and use TaskContext.record_paired for every observation."
  - "Mixed TCP/UDP sparse plans recompile exactly rather than flattening payload metadata."
requirements-completed: [PEER-02, PEER-05, PEER-06]
duration: 45min
completed: 2026-08-02
---

# Phase 3 Plan 02: Paired data-plane Summary

**A finite authenticated-source TCP/UDP lease records fixed-profile directional evidence through the existing task budgets and history model.**

## Accomplishments

- Added plan-bound numeric endpoint, expiry, source, fixed nonce/tag, and byte-reservation validation.
- Implemented one TCP preface listener and one bounded UDP echo listener, both cleaned up on stop, expiry, or cancellation.
- Added `TaskContext.record_paired`, preserving admitted-step, evidence-kind, output, event, and persistence checks.
- Added loopback tests for admission, expiry, evidence codec round trip, TCP/UDP replies, and UDP tampering.

## Task Commits

1. **Tasks 1-2: paired leases, canonical evidence, and finite listeners** - `1bb8c4c` (feat)

## Decisions Made

- The listener rejects traffic before it can produce evidence or a reply unless source and fixed profile exactly match.
- UDP silence is recorded as `SILENT`/inconclusive; listener shutdown without TCP acceptance records an inconclusive timeout.

## Deviations from Plan

### Auto-fixed Issues

1. **Sparse plan validation could not represent a fixed UDP payload next to a no-payload TCP admission step.**
   - Fixed exact sparse-plan recompilation for mixed payload metadata in `planner.py`.
   - Verified by paired plan construction and the task/model regression suites.

**Impact:** Necessary to reserve the actual finite paired byte profile without weakening plan validation.

## User Setup Required

None. External two-machine smoke remains deferred until all Phase 3 automation is complete.

## Next Phase Readiness

03-03 can compose these fixed listeners with authenticated control into the role-swapped application and CLI facade.

---
*Phase: 03-authenticated-paired-differential-diagnostics*
*Completed: 2026-08-02*
