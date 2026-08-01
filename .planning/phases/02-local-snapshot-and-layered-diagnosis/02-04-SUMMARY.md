---
phase: 02
plan: "04"
subsystem: cli
tags: [application-facade, cli, renderers, installation, smoke, ci]
requires: [02-01, 02-02, 02-03]
provides: [mercury-application, status-cli, diagnose-cli, phase2-platform-gate]
affects: [phase-03, phase-05]
tech-stack:
  added: []
  patterns: ["single application facade", "same-result JSON and human projection", "sanitized installed-wheel platform artifact"]
key-files:
  created:
    - src/mercury/app.py
    - tests/test_phase2_smoke.py
    - .github/workflows/phase2-passive-status.yml
    - .planning/artifacts/phase2/ubuntu-24.04-status.json
    - .planning/artifacts/phase2/windows-current-status.json
  modified:
    - src/mercury/cli.py
    - src/mercury/render.py
    - tests/test_cli.py
    - tests/test_installation.py
    - README.md
key-decisions:
  - "CLI and future presentation adapters call MercuryApplication; renderers only project canonical TaskResult evidence."
  - "v1 release support is Windows and Ubuntu; macOS remains non-release compatibility code."
  - "Platform sign-off stores only sanitized capability states and the access-switch limitation."
requirements-completed: [INVT-01, INVT-02, INVT-03, DIAG-01, DIAG-02, DIAG-03, DIAG-04]
duration: "continued session"
completed: 2026-08-01
---

# Phase 02 Plan 04: CLI, projections, and platform sign-off Summary

**Mercury now exposes passive inventory and authorized layered diagnosis through one application facade, faithful CLI projections, stable health exits, and installed-wheel platform sign-off.**

## Accomplishments

- Added `MercuryApplication`, `mercury status`, and `mercury diagnose`.
- Added pure status/diagnosis renderers, offline wheel help parity, loopback facade smoke, and CLI contract regressions.
- Added Windows/Ubuntu CI platform gate plus sanitized installed-wheel passive-status evidence from Windows and Ubuntu 24.04.
- Updated v1 support promise to Windows and Ubuntu; macOS is not a release target.

## Verification

- Full suite passed: 186 tests, 3 skipped.
- Compile, Ruff, and diff checks passed.
- Windows current host and Ubuntu 24.04 installed-wheel passive `status --json` artifacts were schema-valid and retained explicit switch-not-observable evidence.

## Commits

- `d450dbe`, `f935424`, `c04db7f` — facade, smoke, and CLI contracts.
- `9563417`, `5ca7085` — Windows/Ubuntu platform gate and support scope.

## Deviations from Plan

User-directed scope change: Windows and Ubuntu replace macOS as v1 release targets. Existing macOS adapter code and fixtures remain non-release compatibility coverage.

## Issues Encountered

None.

## Next Phase Readiness

Phase 2 is complete. Phase 3 can build paired diagnostics on the fixed facade, compiled-plan, task-service, and evidence contracts.

## Self-Check: PASSED

---
*Phase: 02-local-snapshot-and-layered-diagnosis*
*Completed: 2026-08-01*
