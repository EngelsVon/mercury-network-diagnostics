---
phase: 04-safe-discovery-topology-and-routes
plan: "02"
subsystem: native-route-trace
tags: [python, asyncio, tracert, traceroute, evidence]
requires:
  - phase: 01
    provides: immutable sparse plans and TaskContext admission
  - phase: 04-01
    provides: shared discovery/CLI facade pattern
provides:
  - bounded repeated native trace task service
  - raw parsed hop, unanswered-hop and alternate-hop evidence
  - facade-only trace CLI output
affects: [phase-04, cli, webui]
tech-stack:
  added: []
  patterns: [fixed native argv, bounded command output, per-repeat canonical step evidence]
key-files:
  created: [src/mercury/trace.py, tests/test_trace.py]
  modified: [src/mercury/app.py, src/mercury/cli.py, src/mercury/render.py, tests/test_cli.py]
key-decisions:
  - "A trace accepts exactly one numeric target in an attested scope, up to three repeats and eight hops."
  - "Each native invocation is one admitted step; its logical packet count is an explicit finite upper bound, not a claim about on-wire traffic."
  - "Raw hop lines, unanswered hops and alternate addresses remain evidence; rendering explicitly disclaims a certain route or switch inference."
metrics:
  tests_added: 8
  completed: 2026-08-02
---

# Phase 04 Plan 02: Repeated Native Route Evidence Summary

## Accomplishments

- Added fixed bounded `tracert.exe` (Windows) and `traceroute` (Ubuntu) argv construction, parser coverage for complete/incomplete/unanswered/alternate output, and explicit missing-tool, permission, timeout and parse-error evidence.
- Added `TraceRequest` and a repeated TaskContext-native trace service. Authorization, numeric target/scope containment, repeat count and hop count are all rejected before command execution.
- Added the shared application facade, `mercury trace`, canonical JSON projection and a human renderer that preserves repeats without asserting one certain route.

## Verification

- `uv run --no-sync python -m unittest tests.test_trace tests.test_cli -v` — passed
- `uv run --no-sync python -m mercury trace 127.0.0.1 --scope 127.0.0.0/8 --hops 1 --repeat 1 --timeout 0.2 --authorized` — passed with a loopback path-complete observation
- Full-suite verification is run before Phase 4 is marked complete.

## Deviations from Plan

None. Existing native command and canonical evidence primitives were sufficient.
