---
status: passed
phase: 04-safe-discovery-topology-and-routes
verified: 2026-08-02
requirements: [INVT-04, INVT-05, DISC-01, DISC-02, DISC-03, DISC-04, DISC-05]
---

# Phase 4 Verification: Safe Discovery, Topology Evidence, and Routes

## Goal Verdict: Passed

The shared service layer now provides passive-first local context, explicitly
authorized bounded TCP discovery, and repeated bounded native route evidence.
No CLI or renderer opens a socket or subprocess directly.

## Must-Have Evidence

| Requirement | Evidence | Result |
|---|---|---|
| INVT-04 | `collect_passive_discovery()` uses fixed Windows/Ubuntu neighbor commands; optional `lldpctl` data is retained only as direct LLDP evidence, with missing-tool capability output. | Passed |
| INVT-05 | Separate network, route, neighbor, Wi-Fi AP and LLDP observations; human output says a switch is not observable without direct LLDP. | Passed |
| DISC-01 | `mercury discover --passive` derives IPv4 prefixes, on-link route context and passive neighbors without active probes; IPv6 host enumeration is explicit unsupported evidence. | Passed |
| DISC-02 | `DiscoveryRequest` needs attestation and scope containment; `TaskContext` executes immutable TCP steps and records progress/connect/refusal/timeout evidence. | Passed |
| DISC-03 | Common/custom/full TCP profiles run through canonical budgets; full TCP has a digest-bound `AUTHORIZE FULL TCP` confirmation. | Passed |
| DISC-04 | Active enumeration rejects IPv6 CIDRs; passive neighbor cache retains existing IPv6 neighbors and `TraceRequest` accepts only explicit numeric addresses. | Passed |
| DISC-05 | `mercury trace` uses bounded fixed native argv and preserves raw, unanswered and alternate hop evidence per repeat. | Passed |

## Automated Checks

- `uv run --no-sync python -m unittest discover -s tests -v` — 227 passed, 3 skipped
- `uv run --no-sync python -m compileall -q src tests` — passed
- `uvx ruff check --select E4,E7,E9,F src tests` — passed
- `git diff --check` — passed
- Controlled loopback native trace — `path_complete` for `127.0.0.1`

## Scope and Limitations

- Passive discovery does not transmit packets.
- Active discovery is TCP-only, IPv4-only, scope-bound and budgeted.
- Traces are observed tool output, not a certain route, switch or topology map.
- Windows and Ubuntu are the v1 target platforms; missing tool/permission cases remain explicit evidence.
