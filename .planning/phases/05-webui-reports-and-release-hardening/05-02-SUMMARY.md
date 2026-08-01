---
phase: 05-webui-reports-and-release-hardening
plan: "02"
subsystem: history-reports
tags: [history, redaction, reports, stdlib-html]
requires:
  - phase: 05-01
    provides: authenticated Web broker and MercuryApplication facade
provides:
  - deterministic default-redacted JSON and self-contained HTML task reports
  - evidence-cited compatible history comparisons
  - CLI and Web history report/comparison projections
affects: [05-03-release-hardening]
tech-stack:
  added: []
  patterns: [central report redaction, facade-owned history reads]
key-files:
  created: [src/mercury/reports.py, tests/test_reports.py]
  modified: [src/mercury/app.py, src/mercury/cli.py, src/mercury/web/__init__.py, tests/test_cli.py, tests/test_web.py]
key-decisions:
  - "Credentials are always redacted; explicit retention only applies to identifiers and raw payload values."
  - "History comparison reports evidence absence as missing, never as a reachability conclusion."
patterns-established:
  - "CLI and Web project facade-owned history methods rather than opening persistence directly."
requirements-completed: [HIST-02, HIST-03]
duration: not separately tracked
completed: 2026-08-02
---

# Phase 05 Plan 02: History comparison and safe reports Summary

**Mercury can now compare compatible completed runs and export deterministic JSON or self-contained HTML reports with safe default redaction.**

## Accomplishments

- Added central recursive redaction for secrets, identifiers, addresses, MACs, hostnames and payloads.
- Added evidence-cited changed/unchanged/missing comparison that preserves uncertainty.
- Added facade-backed `history compare`/`history export` CLI commands and authenticated Web history routes.

## Task Commits

1. **Tasks 1-3: reports, comparison, CLI/Web projections** - `870c01e` (`feat(05-02): add redacted history reports`)
2. **Post-verification UI completion: dashboard history comparison and HTML report entry** - `c68d745` (`feat(phase5): expose history reports in dashboard`)

## Deviations from Plan

**[Rule 3 - Blocking]** The planned `src/mercury/web.py` path remains `src/mercury/web/__init__.py` because the package-data static directory owns the `mercury.web` import path; this follows the 05-01 package-layout correction.

## Self-Check: PASSED

- `uv run --no-sync python -m unittest discover -s tests -q` — 240 passed, 3 skipped
- `uv run --no-sync ruff check src tests`
- `git diff --check`

## Next Phase Readiness

05-03 can validate wheel packaging, controlled Windows/Ubuntu checks and complete the README.
