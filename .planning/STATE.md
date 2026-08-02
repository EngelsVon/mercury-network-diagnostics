# Project State

## Project Reference

See: `.planning/PROJECT.md` (updated 2026-08-02)

**Core value:** Within an explicitly declared private-network scope, identify every tested transport or application carrier that can convey a correlated message between two configured endpoints, and show the exact coverage gaps.

**Current focus:** Phase 2 — Peer Receivers and Coverage Matrix (implement configured receiver leases and directional correlations).

## Current Position

- The prior `.planning/` content was intentionally deleted by the user and has not been restored.
- A fresh codebase map was created at `.planning/codebase/` from the current source tree.
- Existing code is a completed evidence-first diagnostic product with TCP-only active discovery, bounded plans, local history, Web UI, and mutually authenticated paired diagnostics.
- The requested internal-coverage pivot has been captured as five unstarted phases, twenty-six v1 requirements, and one executable plan per phase.
- The peer-receiver and tunnel-exposure contract is recorded in .planning/TUNNEL-COVERAGE.md.
- Phase 1 is complete: every active entry point now admits only the explicit private-address allowlist, including post-resolution rechecks; public profiles and examples were removed.

## Constraints to Preserve

- The product must reject public targets at canonical policy boundaries, including DNS resolution/rechecks and native-tool invocation.
- Active work still requires a minimal explicit attestation, canonical containment, and immutable aggregate ceilings.
- Duration `0` does not mean unlimited; it means no extra operator-selected early cutoff within the hard maximum duration and other ceilings.
- Every profile is a finite recorded coverage item. A positive carrier is actionable; a negative result is scoped to the matrix and never claims universal absence of tunnelling.
- Generic Nmap argv, arbitrary peer destination control, and credential brute forcing remain excluded.
- Peer mTLS/token/pinning/replay controls and non-loopback Web TLS/token controls remain mandatory.
- Tests must never use the supplied peer endpoint or any real non-loopback scan target.

## Environment Notes

- Current branch: `master`.
- The worktree contains the user's deletion of the former planning tree; it is intentionally left uncommitted.
- Python: 3.13.5.
- Nmap executable discovered locally: `D:\\Nmap\\nmap.exe`; no code currently invokes it.
- Runtime dependency policy: `psutil` only.

## Phase Status

| Phase | Name | Status | Requirements |
|-------|------|--------|--------------|
| 1 | Private-Scope Policy Migration | Complete (2026-08-02) | SCOPE-01..03 |
| 2 | Peer Receivers and Coverage Matrix | Planned | COVER-01..08 |
| 3 | Multi-Range Internal Mapping Engine | Planned | MAP-01..04 |
| 4 | Native Coverage and Operator Surfaces | Planned | NMAP-01..03, SURF-01..02, PEER-01, HIST-01 |
| 5 | Verification, Documentation, and Release Migration | Planned | QUAL-01..03, DOC-01 |

## Next Action

Execute `.planning/phases/02-peer-receivers-and-coverage-matrix/02-01-PLAN.md` next. Then execute Phases 3 through 5 strictly in roadmap order; configured peer receivers are delivered before the coverage assessment is exposed.

---

*Last updated: 2026-08-02 after completing Phase 1 private-scope migration*
