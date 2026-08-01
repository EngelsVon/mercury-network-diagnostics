---
phase: 04-safe-discovery-topology-and-routes
plan: "01"
subsystem: safe-discovery-topology
tags: [python, psutil, tcp, lldp, windows, ubuntu]
requires:
  - phase: 01
    provides: immutable authorization plans and task budgets
  - phase: 02
    provides: bounded native platform command primitives
provides:
  - passive IPv4 network, neighbor-cache, Wi-Fi and direct-LLDP evidence
  - authorized, immutable TCP-only discovery profiles
  - facade-only discover CLI projections
affects: [phase-04, cli, webui]
tech-stack:
  added: []
  patterns: [fixed-argv passive commands, canonical TCP plan execution, digest-bound full-port confirmation]
key-files:
  created: [src/mercury/discovery.py, tests/test_discovery.py]
  modified: [src/mercury/app.py, src/mercury/cli.py, src/mercury/planner.py, src/mercury/render.py, tests/test_cli.py]
key-decisions:
  - "Passive discovery reads only local interfaces and fixed bounded platform commands; it never sends packets."
  - "Only IPv4 CIDRs may be actively enumerated, and the requested CIDR must be contained in an attested canonical scope."
  - "Gateway, neighbor cache, Wi-Fi AP and direct LLDP are separate evidence types; only direct LLDP may identify an infrastructure neighbor."
  - "The TCP timeout is included in each immutable step identity so execution cannot silently change it."
metrics:
  tests_added: 9
  completed: 2026-08-02
---

# Phase 04 Plan 01: Passive Context and Bounded TCP Discovery Summary

## Accomplishments

- Added passive IPv4 connected-network collection plus fixed-argv Windows/Ubuntu neighbor, Wi-Fi and optional LLDP readers. Missing tools and permissions are capabilities; a gateway or cache entry never becomes a switch claim.
- Added `DiscoveryRequest`, common/custom/full TCP port profiles, exact scope containment, full TCP digest confirmation, immutable per-step timeouts, and a TaskContext-backed TCP runner that preserves connect/refusal/timeout/error evidence.
- Added `MercuryApplication` and `mercury discover` routes. `discover --passive` cannot be combined with active flags; active discovery accepts only fixed TCP profile controls and preserves canonical JSON.

## Verification

- `uv run --no-sync python -m unittest discover -s tests -v` — passed (221 tests, 3 skipped)
- `uv run --no-sync python -m compileall -q src tests` — passed
- `uvx ruff check --select E4,E7,E9,F src tests` — passed
- `git diff --check` — passed

## Deviations from Plan

None. The standard library and existing `psutil`, planner, TaskContext and bounded-command primitives were sufficient.
