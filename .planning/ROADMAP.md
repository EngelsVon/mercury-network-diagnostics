# Roadmap: Mercury Internal Coverage Assessment

## Overview

This roadmap builds a two-endpoint internal coverage assessment: Mercury sends tagged, finite protocol profiles from each endpoint, configured peer receivers witness arrival where possible, and results identify every tested carrier that may carry traffic across an expected isolation boundary. Phases are ordered so no new packet sender, peer receiver, or native Nmap adapter exists before canonical private-scope enforcement.

The coverage contract is defined in .planning/TUNNEL-COVERAGE.md. It requires reporting positive carrier findings and profile-specific gaps rather than asserting a universal absence of tunnels.

## Phase 1: Private-Scope Policy Migration

**Status:** Complete (2026-08-02)

**Goal:** Every active entry point refuses public and scope-escaping destinations before any network or native command activity, while retaining minimal operator attestation and canonical scope validation.

**Requirements:** SCOPE-01, SCOPE-02, SCOPE-03

**Success criteria:**

1. Literal addresses and CIDRs outside loopback, RFC1918 IPv4, IPv6 ULA, or scoped IPv6 link-local are rejected by the canonical policy before I/O.
2. Hostname resolution and DNS rechecks fail closed if any answer is public or outside the declared internal scope.
3. Diagnosis, discovery, trace, CLI plan, Web task parsing, and peer-config validation all share the private-only admission rule.
4. Public built-in profiles, CLI help, and test assumptions are removed or converted to private/loopback-safe equivalents.
5. Existing mTLS/token/pinning, attestation, and immutable plan validation remain covered by regression tests.

**Plans:** 1 complete
**UI hint:** no

## Phase 2: Peer Receivers and Coverage Matrix

**Status:** Complete (2026-08-02)

**Goal:** Give both configured Mercury endpoints a correlation-bound receive/acknowledgement surface for the supported coverage profiles and produce directional carrier evidence.

**Requirements:** COVER-02, COVER-03, COVER-04, COVER-05, COVER-06, COVER-07, COVER-08

**Success criteria:**

1. The exact supported profile matrix is implemented and serialized: TCP, UDP, DNS over UDP/TCP, ICMP echo, TLS, HTTP, SSH banner, local ARP/ND, and optional native profiles.
2. Each endpoint provisions only configured receiver profiles through the existing trusted peer control and records tagged arrival/acknowledgement evidence without accepting a third-party destination.
3. The coverage assessment runs each eligible profile in both directions and correlates sender and peer evidence using one short-lived lease/correlation identifier.
4. TCP, UDP, DNS, TLS, HTTP, SSH, and ICMP results preserve protocol-specific negative, silent, unavailable, and permission outcomes rather than collapsing them into reachability.
5. ARP/ND is reported as local-link-only and automatically non-applicable to a cross-subnet remote pair.
6. The final result lists candidate carriers and every coverage gap; it never claims all possible tunnels have been excluded.

**Plans:** 1 complete
**UI hint:** no

## Phase 3: Multi-Range Internal Mapping Engine

**Status:** Complete (2026-08-02)

**Goal:** Compile and execute one bounded multi-range mapping or coverage plan through the existing task lifecycle.

**Requirements:** MAP-01, MAP-02, MAP-03, MAP-04

**Success criteria:**

1. A request accepts multiple canonical private IPv4 CIDRs, configured peer endpoint pairs, selected finite profiles, and produces exactly one immutable aggregate plan.
2. The plan binds ranges, directions, receiver leases, ports, payload metadata, rate, concurrency, duration, and aggregate ceilings before I/O begins.
3. The effective result exposes logical attempt-start rate, concurrency, host/port/attempt/event/output ceilings, and clear accounting units.
4. A requested duration of 0 means no extra operator-selected early cutoff but still ends at immutable ceilings with terminal evidence explaining the reason.
5. Cancellation and persistence leave a valid bounded result and do not permit a runner to exceed admitted steps.

**Plans:** 1 complete
**UI hint:** no

## Phase 4: Native Coverage and Operator Surfaces

**Status:** Complete (2026-08-02)

**Goal:** Add optional Nmap-native profiles and expose all mapping/coverage functionality through the shared CLI, Web UI, peer, and history boundaries.

**Requirements:** COVER-01, NMAP-01, NMAP-02, NMAP-03, SURF-01, SURF-02, PEER-01, HIST-01

**Success criteria:**

1. Missing Nmap or missing native privilege produces typed capability evidence; available Nmap runs only a fixed TCP connect/SYN, UDP, or SCTP-init profile derived from a private admitted plan.
2. Fixed, bounded Nmap XML becomes versioned native-provenance observations without a generic argument pass-through or target-source escape.
3. CLI and Web UI create the same typed mapping/coverage requests through MercuryApplication and never perform I/O themselves.
4. The Web UI shows profile coverage, peer-receiver capability, per-direction progress, candidate carriers, evidence provenance, and explicit assessment gaps accessibly.
5. Peer mTLS/token/pinning/replay controls remain intact, and history/report output retains provenance while preserving existing secret filtering and redaction.

**Plans:** 1 complete
**UI hint:** yes

## Phase 5: Verification, Documentation, and Release Migration

**Status:** Complete (2026-08-02)

**Goal:** Demonstrate the private-only boundary and the exact coverage contract with controlled tests and accurate operator guidance.

**Requirements:** QUAL-01, QUAL-02, QUAL-03, DOC-01

**Success criteria:**

1. The full controlled suite verifies private-scope rejection before I/O, mapping ceilings, cancellation, sender/receiver correlation, and every supported profile's outcome semantics.
2. Fixture tests verify Nmap argv/XML behavior and CLI/Web/peer/history integration without launching a real non-loopback scan.
3. Packaging, compilation, and supported-platform-safe smoke commands pass.
4. README, CLI, and Web copy enumerate the actual coverage matrix, receiver prerequisites, ARP/ND cross-subnet boundary, native capability gaps, and the scoped meaning of a negative result.

**Plans:** 1 complete
**UI hint:** yes

## Phase 6: Bilingual Open-Source Release

**Status:** Complete (2026-08-13)

**Goal:** Publish a contributor-ready, bilingual Mercury repository with operator documentation and an installable intelligent-agent skill.

**Requirements:** DOC-02

**Success criteria:**

1. English and Simplified Chinese documentation cover installation, architecture, CLI, configuration, deployment, evidence semantics, testing, contribution, conduct, and private vulnerability reporting.
2. Apache-2.0 licensing, CI, dependency updates, issue forms, and pull-request guidance are present without publishing lab credentials or endpoint-specific configuration.
3. A concise `mercury-network-diagnostics` skill contains operational guardrails, command patterns, evidence semantics, UI metadata, and passes the skill validator.
4. Package metadata and public documentation point to the canonical GitHub repository.

**Plans:** 1 inline documentation release complete
**UI hint:** no

## Requirement Coverage

| Requirement | Phase |
|-------------|-------|
| SCOPE-01 | 1 |
| SCOPE-02 | 1 |
| SCOPE-03 | 1 |
| COVER-01 | 4 |
| COVER-02 | 2 |
| COVER-03 | 2 |
| COVER-04 | 2 |
| COVER-05 | 2 |
| COVER-06 | 2 |
| COVER-07 | 2 |
| COVER-08 | 2 |
| MAP-01 | 3 |
| MAP-02 | 3 |
| MAP-03 | 3 |
| MAP-04 | 3 |
| NMAP-01 | 4 |
| NMAP-02 | 4 |
| NMAP-03 | 4 |
| SURF-01 | 4 |
| SURF-02 | 4 |
| PEER-01 | 4 |
| HIST-01 | 4 |
| QUAL-01 | 5 |
| QUAL-02 | 5 |
| QUAL-03 | 5 |
| DOC-01 | 5 |
| DOC-02 | 6 |

**Coverage:** 27 of 27 v1 requirements are mapped exactly once.

---

*Roadmap created: 2026-08-02*
*Last updated: 2026-08-13 after completing the bilingual open-source release*
