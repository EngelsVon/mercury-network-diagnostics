# Phase 1: Private-Scope Policy Migration - Context

**Gathered:** 2026-08-02
**Status:** Ready for planning
**Source:** Replanning decision and tunnel-exposure coverage contract

<domain>
## Phase Boundary

This phase changes the canonical active-target policy so all active Mercury entry points are restricted to loopback, RFC1918 IPv4, IPv6 ULA, or scoped IPv6 link-local destinations. It removes public profile behavior and public examples. It does not add peer receivers, coverage probes, Nmap execution, or UI controls; those begin only after this policy boundary is verified.

</domain>

<decisions>
## Implementation Decisions

### Internal address admission

- D-01: Use an explicit allowlist, not the broad Python is_private property: IPv4 loopback, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, IPv6 loopback, fc00::/7, and scoped IPv6 link-local.
- D-02: Continue to reject unspecified, multicast, and limited-broadcast destinations before the internal allowlist check.
- D-03: Internal hostnames may be parsed, but every planned and rechecked answer must satisfy the address allowlist and declared scope before I/O.

### Enforcement locations

- D-04: Put the address/CIDR allowlist at the canonical policy layer so ScopeGrant, parse_target resolution, active discovery, trace, profile compilation, CLI planning, Web service calls, peer configuration, and future Nmap paths inherit it.
- D-05: Do not add a second presenter-specific private-range validator.
- D-06: Remove or disable public built-in diagnosis profiles rather than silently permitting them through a special case.

### Evidence and testing

- D-07: A rejected public literal, CIDR, or DNS answer must fail before a socket, resolver-dependent native command, or Nmap subprocess is invoked.
- D-08: Controlled tests use loopback, fakes, and RFC1918 addresses only; the operator-supplied peer endpoint is never encoded in tests or planning artifacts.
- D-09: Existing peer mTLS, token, certificate pinning, local-attestation, and immutable plan validation are regression requirements and remain unchanged in this phase.

### the agent's Discretion

- Exact helper names, placement within policy.py, and the minimum set of public-profile compatibility changes.
- Whether public built-in profiles are removed entirely or retained as rejected legacy input, provided normal active behavior cannot select them.

</decisions>

<canonical_refs>
## Canonical References

### Product and requirements

- .planning/PROJECT.md — project constraints, coverage assessment semantics, and hard boundaries.
- .planning/REQUIREMENTS.md — SCOPE-01, SCOPE-02, and SCOPE-03 acceptance requirements.
- .planning/ROADMAP.md — Phase 1 success criteria and dependency order.
- .planning/TUNNEL-COVERAGE.md — downstream coverage contract that relies on private scope.

### Existing source patterns

- src/mercury/policy.py — Target parsing, ScopeGrant, target authorization, DNS resolution, and resolution recheck.
- src/mercury/profiles.py — built-in diagnosis profile selection and compilation.
- src/mercury/discovery.py — active DiscoveryRequest and ScopeGrant creation.
- src/mercury/trace.py — native trace request and ScopeGrant creation.
- src/mercury/peer.py — peer configuration parsing and non-loopback trust boundary.
- src/mercury/cli.py — active command parsing and stable policy error mapping.
- src/mercury/web/__init__.py — service-only request parser.

### Existing verification

- tests/test_policy.py — target/scope/resolution behavior and plan validation.
- tests/test_profiles.py — profile compilation expectations.
- tests/test_discovery.py — discovery admission and runner behavior.
- tests/test_trace.py — trace admission behavior.
- tests/test_peer.py — peer trust and configuration behavior.
- tests/test_cli.py and tests/test_web.py — user-facing policy routing.

</canonical_refs>

<specifics>
## Specific Ideas

- Documentation-address ranges are deliberately rejected in runtime policy even when they are useful in no-I/O fake tests.
- A Phase 2 peer receiver must not be buildable on an address that Phase 1 would reject.
- The availability of Nmap at the development-machine path is irrelevant until Phase 4; this phase only prevents a future native adapter from escaping policy.

</specifics>

<deferred>
## Deferred Ideas

- TCP, UDP, DNS, ICMP, TLS, HTTP, SSH, ARP/ND, and Nmap coverage profiles are deferred to phases 2–4.
- Receiver leases, peer arrival receipts, and tunnel-carrier conclusions are deferred to Phase 2.
- CLI and Web coverage controls are deferred to Phase 4.

</deferred>

---

*Phase: 01-private-scope-policy-migration*
*Context gathered: 2026-08-02 during internal coverage replanning*
