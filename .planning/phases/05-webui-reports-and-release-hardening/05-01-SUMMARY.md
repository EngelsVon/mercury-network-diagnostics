---
phase: 05-webui-reports-and-release-hardening
plan: "01"
subsystem: webui
tags: [stdlib-http, csrf, csp, asyncio, native-javascript]
requires:
  - phase: 04-safe-discovery-topology-and-routes
    provides: shared MercuryApplication discovery and trace facade operations
provides:
  - loopback-default WebUI with a bounded same-origin task API
  - accessible native dashboard for facade-backed status, diagnostics, discovery, trace and paired tasks
  - mercury web lifecycle command with TLS/token enforcement for remote binds
affects: [05-02-history-reports, 05-03-release-hardening]
tech-stack:
  added: []
  patterns: [stdlib ThreadingHTTPServer with a private asyncio task loop, per-session CSRF tokens, closed JSON task request shapes]
key-files:
  created: [src/mercury/web/__init__.py, src/mercury/web/static/index.html, src/mercury/web/static/app.js, src/mercury/web/static/style.css, tests/test_web.py]
  modified: [src/mercury/cli.py, tests/test_cli.py]
key-decisions:
  - "Keep task execution behind MercuryApplication; the HTTP adapter never performs probes."
  - "Use a package initializer for the Web implementation because a web.py module cannot coexist with the web/static package-data directory."
patterns-established:
  - "Web requests are fixed JSON shapes, validated before background scheduling."
  - "Non-loopback Web binds require TLS and a token; loopback sessions receive a distinct SameSite cookie and CSRF secret."
requirements-completed: [WEB-01, WEB-02, WEB-03, WEB-04]
duration: not separately tracked
completed: 2026-08-02
---

# Phase 05 Plan 01: Secure local WebUI and task API Summary

**A stdlib, same-origin protected Mercury dashboard now schedules and polls the shared diagnostics facade without creating a second probing implementation.**

## Performance

- **Duration:** Not separately tracked across the resumed implementation.
- **Completed:** 2026-08-02
- **Tasks:** 3
- **Files modified:** 8

## Accomplishments

- Added a loopback-default `ThreadingHTTPServer` with Host, token, session, CSRF, Origin, CSP and bounded-body controls.
- Added a native semantic HTML/CSS/JavaScript dashboard that launches status, diagnose, passive/authorized discovery, trace and paired facade tasks, then polls or cancels them.
- Added `mercury web` with narrow bind/port/certificate/key/token-file lifecycle options and controlled Web/CLI tests.

## Task Commits

1. **Tasks 1-3: Web server, dashboard, and CLI lifecycle** - `fdb5fd4` (`feat(05-01): add secure WebUI task API`)

## Files Created/Modified

- `src/mercury/web/__init__.py` - secure HTTP boundary, background task broker, and facade dispatcher.
- `src/mercury/web/static/index.html` and `app.js` - accessible dashboard and same-origin polling client.
- `src/mercury/cli.py` - `mercury web` lifecycle command.
- `tests/test_web.py` - security-boundary, facade, cancellation, and static UI coverage.

## Decisions Made

- A Web task opens its own SQLite history store in the broker loop, preserving the store's thread ownership contract.
- Remote bind stays stricter than the optional development relaxation mentioned in requirements: TLS and token are always required here.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Resolve the `web.py` and `web/` package-data name collision**

- **Found during:** Task 1 (Web server trust boundary)
- **Issue:** Python resolved `mercury.web` as the static-assets package, making the drafted sibling `web.py` implementation unreachable from the CLI.
- **Fix:** Placed the implementation in `src/mercury/web/__init__.py` and updated the plan's declared path.
- **Files modified:** `src/mercury/web/__init__.py`, `05-01-PLAN.md`
- **Verification:** CLI import and `mercury web --help` pass.
- **Committed in:** `fdb5fd4` (implementation; plan metadata follows)

---

**Total deviations:** 1 auto-fixed (1 blocking).
**Impact on plan:** Necessary package-layout correction only; public module naming and planned static assets remain unchanged.

## Issues Encountered

None remaining.

## User Setup Required

None - no external service configuration required. Remote use requires operator-provided TLS files and a local token file.

## Next Phase Readiness

The same task API can now expose history browsing, compatibility comparison and default-redacted report exports in 05-02.

## Self-Check: PASSED

- `uv run --no-sync python -m compileall -q src tests`
- `uv run --no-sync python -m unittest discover -s tests -q` — 235 passed, 3 skipped
- `uv run --no-sync ruff check src tests`
- `uv run --no-sync python -m mercury --help`
- `uv run --no-sync python -m mercury web --help`
- `git diff --check`
