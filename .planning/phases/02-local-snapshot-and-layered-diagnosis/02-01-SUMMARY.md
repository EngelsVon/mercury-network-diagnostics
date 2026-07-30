---
phase: 02-local-snapshot-and-layered-diagnosis
plan: "01"
subsystem: inventory
tags: [psutil, platform, passive, evidence]
requires: [01-03]
provides: [passive-status-service, normalized-route-dns-records, platform-fixtures]
affects: [02-04, phase-3]
tech-stack:
  added: []
  patterns: [fixed-argv-platform-collectors, injected-passive-providers, bounded-evidence]
key-files:
  created:
    - src/mercury/platform/common.py
    - src/mercury/platform/windows.py
    - src/mercury/platform/linux.py
    - src/mercury/platform/macos.py
    - src/mercury/inventory.py
    - tests/test_platforms.py
    - tests/test_inventory.py
  modified:
    - src/mercury/platform/__init__.py
decisions:
  - "Status awaits injected local providers and never performs DNS, ping, trace, socket-connect, or authorization work."
  - "Access-switch identity remains explicitly unavailable until direct LLDP or managed evidence exists."
  - "Platform command output and inventory records have explicit bounds with typed degradation."
verification:
  - "python -m unittest tests.test_inventory tests.test_platforms tests.test_models tests.test_contracts -q"
  - "python -m unittest discover -s tests -q"
  - "python -m compileall -q src tests"
  - "python -m ruff check src tests"
  - "git diff --check"
commits:
  - "9e2627a feat(02-01): add bounded platform command boundary"
  - "67b7fd7 feat(02-01): add fixture-driven platform adapters"
  - "a6c25d2 feat(02-01): add passive local inventory service"
---

# Phase 02 Plan 01 Summary

Completed the passive inventory foundation for Mercury status.

The platform package now runs only fixed-argument, bounded native commands and
normalizes route/DNS facts from Windows, Linux, and macOS fixtures. The new
`collect_status()` application service accepts injected clock, system, psutil,
and platform providers, then returns a deterministic canonical `TaskResult`
without performing active network diagnostics.

Interface and platform records are sorted and capped at 256 interfaces, 4,096
addresses/routes, and 256 DNS servers. Limit breaches are visible as typed
capabilities and error observations. Missing fields and independent provider
failures are retained honestly rather than guessed or allowed to suppress good
facts. The sole topology conclusion says an access switch is not observable
without direct LLDP or managed evidence.

## Verification

- Targeted inventory/platform/model/contract tests: 52 passed.
- Full suite: 140 passed, 3 existing platform-inapplicable skips.
- Windows passive smoke: 173 observations, 117 routes, 21 DNS records,
  Unicode interface names, and the required switch limitation.

## Remaining Validation Gate

The current-host service smoke is complete. The separate Phase 2 sign-off
still requires installed `mercury status --json` artifacts from Windows, Linux,
and macOS after the CLI facade is added in Plan 02-04.
