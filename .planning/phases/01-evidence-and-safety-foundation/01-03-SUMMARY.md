---
phase: 01-evidence-and-safety-foundation
plan: "03"
subsystem: cli-testing-packaging
tags: [argparse, cli, unittest, wheel, venv]
requires:
  - phase: 01-01
    provides: Canonical model and history
  - phase: 01-02
    provides: Authorized plans and task lifecycle
provides:
  - One module/console CLI implementation with stable JSON errors and exit codes
  - Human and JSON projections over the same typed values
  - Adversarial standard-library acceptance and clean-install parity tests
affects: [phase-2-cli, phase-5-packaging, release]
tech-stack:
  added: [setuptools]
  patterns: [thin-cli-adapter, offline-deterministic-tests, clean-wheel-verification]
key-files:
  created: [src/mercury/cli.py, src/mercury/render.py, tests/test_installation.py]
  modified: [README.md, pyproject.toml, tests/test_cli.py, tests/test_contracts.py]
key-decisions:
  - "CLI and future WebUI project the same application values rather than duplicating behavior."
  - "Tests never scan public or unowned networks."
patterns-established:
  - "Invalid JSON-mode arguments produce structured stderr and stable exit codes."
  - "Installed console and module entry points are compared from an empty directory."
requirements-completed: [TEST-01]
duration: combined phase execution
completed: 2026-07-30
---

# Phase 1 Plan 03: CLI and Acceptance Summary

**One thin CLI exposes model, plan, synthetic lifecycle, and history behavior with clean-wheel parity and adversarial contracts.**

## Performance

- **Duration:** Combined with the Phase 1 implementation and review cycle
- **Started:** 2026-07-30T02:50:38+08:00
- **Completed:** 2026-07-30T05:39:21+08:00
- **Tasks:** 3
- **Primary files:** 7

## Accomplishments

- Added `version`, `model`, `plan`, `history`, and explicitly offline
  `task synthetic` commands through one argparse implementation.
- Added stable JSON/human projections and success, failed, partial, policy,
  usage, and internal exit semantics.
- Added exhaustive enum, model, scope, DNS, budget, lifecycle, retention,
  cancellation, output, persistence, and packaging regressions.
- Built and installed a wheel in a temporary venv and compared the console
  script with `python -m mercury` from an empty directory.

## Task Commits

Baseline: `e198fbe`. CLI/contract hardening: `338e0d1`, `46f9c1d`, and
`274f39f`.

## Decisions Made

- The synthetic command never opens a network socket and exists only to verify
  the shared task lifecycle.
- No framework, frontend toolchain, ORM, broker, or plugin SDK was introduced.

## Deviations from Plan

Clean-install parity and malformed-argument JSON behavior received dedicated
regressions after deep review showed checkout-only tests were insufficient.

## User Setup Required

None.

## Next Phase Readiness

The CLI is ready to receive Phase 2 `status` and `diagnose` commands as thin
projections over shared services.

