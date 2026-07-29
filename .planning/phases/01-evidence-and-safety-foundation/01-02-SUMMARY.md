---
phase: 01-evidence-and-safety-foundation
plan: "02"
subsystem: policy-execution
tags: [authorization, budgets, dns, asyncio, cancellation]
requires:
  - phase: 01-01
    provides: Canonical evidence and transactional history
provides:
  - Strict target and scope normalization
  - Immutable finite probe plans with aggregate ceilings and confirmations
  - Cancellable persisted task execution with authoritative step evidence
affects: [phase-2-probes, phase-3-peer, phase-4-discovery]
tech-stack:
  added: []
  patterns: [recompile-at-trust-boundary, finite-step-admission, fail-closed-terminalization]
key-files:
  created: [src/mercury/policy.py, src/mercury/planner.py, src/mercury/tasks.py]
  modified: [src/mercury/history.py]
key-decisions:
  - "Every authorized plan is deterministically rebuilt at authorization and submission."
  - "UDP payload approvals bind length and SHA-256; raw bytes are never persisted."
patterns-established:
  - "Core admission owns DNS recheck, rate/concurrency gates, payload verification, and accounting."
  - "A successful task requires evidence-backed completion of every finite step."
requirements-completed: [EVID-04, SAFE-01, SAFE-02, SAFE-03, SAFE-04]
duration: combined phase execution
completed: 2026-07-30
---

# Phase 1 Plan 02: Safety and Task Core Summary

**Canonical scope grants compile into finite digest-bound steps enforced by a cancellable, persisted task core.**

## Performance

- **Duration:** Combined with the Phase 1 implementation and review cycle
- **Started:** 2026-07-30T02:50:38+08:00
- **Completed:** 2026-07-30T05:39:21+08:00
- **Tasks:** 3
- **Primary files:** 5

## Accomplishments

- Rejects malformed, ambiguous, multicast, unspecified, and limited-broadcast
  destinations; non-loopback work requires explicit expiring scope.
- Compiles address/port/transport/attempt/payload tuples into immutable steps
  and enforces all host, port, attempt, datagram, byte, rate, concurrency,
  duration, event, and output ceilings.
- Rechecks current DNS answers inside scope at admission and permits bounded
  in-scope rotation without cardinality growth.
- Persists truthful cancelled/failed partial results, recovers expired foreign
  leases, and prevents healthy runner conclusions from overriding terminal
  truth.
- Binds every successful step to at least one observation with authoritative
  step ID, target, port, transport, attempt, and DNS-change metadata.

## Task Commits

Baseline: `e198fbe`. Review fixes: `d1cdba3`, `90e2f2f`, `4c97cc5`,
`89d0cce`, `91e3f60`, `5cee7a7`, `11c0606`, `92f127c`, `52b6304`,
and `274f39f`.

## Decisions Made

- “All packet kinds” is rejected as non-finite; v1 permits only built-in
  profiles or explicitly hashed UDP content.
- UDP/ICMP silence remains inconclusive.
- In-process built-in runners are trusted code, but their stored evidence and
  plan consumption are still validated by the core.

## Deviations from Plan

The initial runner abstraction admitted arbitrary aliases, incomplete success,
and weak observation binding. Deep review replaced those paths with finite
step IDs, exact metadata, and evidence-backed completion.

## User Setup Required

None.

## Next Phase Readiness

Phase 2 can add real inventory and probes without creating a second scheduler
or bypassing authorization and evidence semantics.

