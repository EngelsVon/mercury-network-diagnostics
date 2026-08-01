---
gsd_state_version: 1.0
milestone: v1.0
milestone_name: milestone
status: complete
stopped_at: Phase 05 complete; v1 roadmap complete
last_updated: "2026-08-02T06:00:00Z"
last_activity: 2026-08-02 -- Phase 05 release, clean-install and documentation verification passed with uv
progress:
  total_phases: 5
  completed_phases: 5
  total_plans: 15
  completed_plans: 15
  percent: 100
---

# Project State

## Project Reference

See: `.planning/PROJECT.md` (updated 2026-07-30)

**Core value:** 在用户明确授权的网络范围内，以安全、可解释且可复现的方式定位节点间可达性故障及其网络层原因。  
**Current focus:** v1 milestone verification complete

## Current Position

Phase: 05 (webui-reports-and-release-hardening) — COMPLETE

Plan: 03 of 03
Status: v1 roadmap complete; Phase 05 verification passed
Last activity: 2026-08-02 -- clean wheel installation, controlled suite, release documentation and static asset packaging verified

Progress: [##########] 100%

## Performance Metrics

**Velocity:**

- Total plans completed: 15
- Average duration: not separately tracked (combined Phase 1 execution)
- Total execution time: approximately 2.8 hours

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| Phase 1 | 3 | approximately 2.8 hours | combined execution |

**Recent Trend:** Phase 03 completed with strict mTLS, token and pinned peer
control, finite source-bound TCP/UDP leases, and a Windows/Ubuntu controlled
smoke that produced TCP/UDP arrival and reply evidence.

## Accumulated Context

### Decisions

Full decisions live in `.planning/PROJECT.md`.

- Research: NARROW-GO — differentiation is evidence + paired directionality, not scanner breadth.
- Stack: Python standard library plus psutil; no Web framework/frontend build/ORM/task broker.
- Ponytail: full ladder remains active; minimalism never removes safety or runnable checks.
- Protocol: peer control uses operator-provisioned mTLS, certificate pins and a
  separate token; remote Web uses TLS/token; neither may become a scan oracle.

- Roadmap: the paired cross-layer differential slice precedes discovery/LLDP,
  which remains a bounded context feature rather than the product thesis.

- Phase 1: a successful task must complete every immutable step with at least
  one observation bound to authoritative step/target/port/transport metadata.

- Phase 1: persisted requests use exact per-field projections; credential text
  and raw custom content fail before SQLite.

- Phase 2: every active step has a digest-bound `ProbeKind`; runner evidence
  is core-bound to its approved step identity and per-step reservation.

### Pending Todos

None yet.

### Blockers/Concerns

- Validate Windows/Ubuntu route, DNS and neighbor adapters with real fixtures; macOS is not a v1 release target.
- Validate two-machine certificate setup before calling peer mode easy.
- Validate product value with real campus/enterprise incidents before adding breadth.

## Deferred Items

| Category | Item | Status | Deferred At |
|----------|------|--------|-------------|
| Integration | Nmap/iperf3 evidence import | v2 | Research |
| Distribution | Signed standalone executables | v2 | Research |
| Operations | Metrics/fleet controller | v2+ | Research |

## Session Continuity

Last session: 2026-08-01T14:08:17.964Z
Stopped at: Phase 03 context gathered; research and planning in progress

Resume file: .planning/phases/03-authenticated-paired-differential-diagnostics/03-CONTEXT.md
