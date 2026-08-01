---
phase: 05-webui-reports-and-release-hardening
plan: "03"
subsystem: release
tags: [uv, wheel, clean-install, windows, ubuntu, documentation]
requires:
  - phase: 05-01
    provides: packaged Web assets and web command
  - phase: 05-02
    provides: reports and history commands
provides:
  - wheel content and clean-install entry-point verification
  - Windows/Ubuntu controlled operator smoke instructions
  - complete user safety, Web, discovery and report documentation
affects: [v1-release]
tech-stack:
  added: []
  patterns: [wheel-content assertion, clean virtual-environment console/module parity]
key-files:
  created: []
  modified: [README.md, src/mercury/web/__init__.py, tests/test_installation.py]
key-decisions:
  - "Release checks remain isolated, fixture/loopback-only; no remote scan or SSH smoke is automated."
  - "Web startup prints only its bound URL and never token material."
patterns-established:
  - "The isolated wheel test asserts Web package data and CLI/agent/Web help parity."
requirements-completed: [PACK-01, PACK-02, TEST-02, TEST-03, DOCS-01]
duration: not separately tracked
completed: 2026-08-02
---

# Phase 05 Plan 03: Release verification and user documentation Summary

**Mercury v1 now builds as one installable wheel with verified Web assets, controlled Windows/Ubuntu operator smoke instructions, and complete safety documentation.**

## Accomplishments

- Asserted packaged dashboard assets and clean virtual-environment parity for console and module entry points, including agent and Web help.
- Documented `uv` checkout workflow, Windows/Ubuntu capability limits, authorized discovery, mTLS peer use, Web trust boundary, reporting and troubleshooting.
- Added a bound Web URL startup message without exposing tokens.

## Task Commits

1. **Tasks 1-3: clean-install gate, release matrix and documentation** - `f288dcb` (`feat(05-03): harden release verification docs`)

## Deviations from Plan

None - existing controlled fixture and loopback suites already covered the required success, refusal, timeout, silence, DNS, delay, asymmetric, Web and platform-degradation cases; the release plan adds their installation/documentation gate.

## Self-Check: PASSED

- `uv run --no-sync python -m unittest discover -s tests -q` — 241 passed, 3 skipped
- `uv run --no-sync python -m compileall -q src tests`
- `uv run --no-sync ruff check src tests`
- `uv build`
- isolated wheel installation test — console/module parity plus CLI, agent, Web and static asset checks
- `git diff --check`

## Next Phase Readiness

All Phase 5 plans are complete; phase verification can close the v1 roadmap.
