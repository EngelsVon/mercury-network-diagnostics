---
phase: 05-webui-reports-and-release-hardening
status: passed
verified: 2026-08-02
---

# Phase 5 Verification

## Goal

Users can operate the shared engine from an accessible local dashboard, inspect
history/reports, and install a verified Windows/Ubuntu v1 release.

## Requirement evidence

| Requirement | Evidence | Status |
| --- | --- | --- |
| WEB-01 – WEB-04 | `src/mercury/web/__init__.py`, static dashboard, `tests/test_web.py` session/Host/Origin/CSRF/body/TLS coverage | Passed |
| HIST-02 – HIST-03 | `src/mercury/reports.py`, facade/CLI/Web routes, `tests/test_reports.py` | Passed |
| PACK-01 | `pyproject.toml` package data, clean wheel test asserting static assets and entry points | Passed |
| PACK-02 | Windows/Ubuntu adapters and controlled fixtures, explicit unsupported-platform test, README operator smoke | Passed |
| TEST-02 – TEST-03 | 241-test controlled suite covers DNS failure, connect success/refusal/timeout, UDP silence, paired directionality, Web security, peer mTLS/replay and platform degradation | Passed |
| DOCS-01 | README `uv` quick start, authorization, capability table, mTLS, Web, reports, semantics, troubleshooting and non-goals; documentation test | Passed |

## Verification commands

- `uv run --no-sync python -m compileall -q src tests`
- `uv run --no-sync python -m unittest discover -s tests -q` — 241 passed, 3 skipped
- `uv run --no-sync ruff check src tests`
- `uv build`
- `git diff --check`

The full suite was rerun after the dashboard history/report interaction was
added; the same 241 tests passed with 3 controlled skips.

## Release boundary

The automated suite remains fake/fixture/loopback controlled. Windows and
Ubuntu operator smoke is documented for an owned device/network; macOS and
other platforms are explicitly unsupported for v1. No remote or public scan
was performed for this phase.
