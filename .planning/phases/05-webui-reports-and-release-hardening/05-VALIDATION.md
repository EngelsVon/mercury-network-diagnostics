---
phase: 05
slug: webui-reports-and-release-hardening
status: ready
nyquist_compliant: true
created: 2026-08-02
---

# Phase 5 Validation Strategy

- Focused: `uv run --no-sync python -m unittest tests.test_web tests.test_reports tests.test_installation -v`
- Full: `uv run --no-sync python -m unittest discover -s tests -v`
- Static: `uv run --no-sync python -m compileall -q src tests` and
  `uvx ruff check --select E4,E7,E9,F src tests`
- Packaging: `uv build`, install the wheel in a temporary virtual environment,
  run `mercury --help`, and check packaged static assets.

All HTTP tests use loopback only. Controlled release checks never scan public
or unowned destinations.
