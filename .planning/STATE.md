# Project State

## Project Reference

See: `.planning/PROJECT.md` (updated 2026-08-02)

**Core value:** Within an explicitly declared private-network scope, identify
every tested transport or application carrier that can convey a correlated
message between two configured endpoints, and show the exact coverage gaps.

**Current focus:** Milestone complete; ready for controlled operator deployment.

## Completed Work

- Phase 1: private-only literal, CIDR, hostname-resolution, peer, CLI, Web,
  and native-tool admission.
- Phase 2: fixed peer receivers and two-direction coverage for TCP, UDP, DNS,
  ICMP, TLS, HTTP, SSH banner, and local ARP/ND evidence.
- Phase 3: canonical multi-CIDR mapping with fixed profiles, ports, rate,
  concurrency, duration-zero semantics, immutable task plans, and history.
- Phase 4: fixed Nmap TCP connect/SYN, UDP, and SCTP-init profiles; bounded
  XML native evidence; CLI/Web mapping and coverage surfaces; accessible Web
  coverage evidence/gap rendering.
- Phase 5: requirement-focused controlled tests, package build, compilation,
  CLI help, and isolated wheel-install/import/help smoke.

## Verification Evidence

- `python -m unittest tests.test_policy tests.test_planner tests.test_discovery tests.test_tasks -v`: 83 passed.
- `python -m unittest tests.test_paired tests.test_peer tests.test_reports -v`: 53 passed.
- `python -m unittest tests.test_nmap_adapter tests.test_cli tests.test_web tests.test_history tests.test_contracts -v`: 70 passed, 3 Windows permission tests skipped.
- `python -m compileall -q src tests`, `python -m build`, and `python -m mercury --help`, `mapping --help`, `coverage --help`: passed.
- The built wheel was installed into an isolated temporary target with
  `--no-index --no-deps`; `import mercury` and `python -m mercury --help`
  passed with only that target on `PYTHONPATH`.

## Constraints Preserved

- Active target scope is loopback/RFC1918/ULA/scoped link-local only; public
  and documentation addresses are rejected before I/O.
- Attestation, immutable rate/concurrency/duration/event/output ceilings,
  mTLS/token/pin/replay controls, and Web TLS/token rules remain in force.
- Nmap has no caller-controlled argv, scripts, proxy, decoy, target-file, or
  payload interface. Peer control cannot accept third-party scan destinations.
- A positive result identifies a tested candidate carrier. Negative or silent
  evidence covers only the recorded finite profile, port, direction, packet
  shape, and time window; remaining gaps are displayed explicitly.

## Phase Status

| Phase | Name | Status | Requirements |
|-------|------|--------|--------------|
| 1 | Private-Scope Policy Migration | Complete | SCOPE-01..03 |
| 2 | Peer Receivers and Coverage Matrix | Complete | COVER-01..08 |
| 3 | Multi-Range Internal Mapping Engine | Complete | MAP-01..04 |
| 4 | Native Coverage and Operator Surfaces | Complete | NMAP-01..03, SURF-01..02, PEER-01, HIST-01 |
| 5 | Verification, Documentation, and Release Migration | Complete | QUAL-01..03, DOC-01 |

## Deployment Note

Use reciprocal administrator-provisioned peer files and fixed private receiver
ports for a real two-endpoint assessment. Automated verification never contacts
the supplied peer endpoint or any real non-loopback target.

---

*Last updated: 2026-08-02 after Phase 5 completion.*
