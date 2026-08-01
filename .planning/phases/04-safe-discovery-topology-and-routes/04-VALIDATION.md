---
phase: 04
slug: safe-discovery-topology-and-routes
status: ready
nyquist_compliant: true
created: 2026-08-02
---

# Phase 4 Validation Strategy

- Quick: `uv run --no-sync python -m unittest tests.test_discovery tests.test_trace -v`
- Full: `uv run --no-sync python -m unittest discover -s tests -v`
- Static: `uv run --no-sync python -m compileall -q src tests` and
  `uvx ruff check --select E4,E7,E9,F src tests`.

Controlled tests must never target public or unowned networks. Active tests use
loopback listeners, reserved documentation addresses with mocked sockets, or
injected command results.
