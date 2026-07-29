# Phase 1: Evidence and Safety Foundation - Context

**Gathered:** 2026-07-30
**Status:** Ready for planning
**Mode:** Autonomous smart-discuss defaults

<domain>
## Phase Boundary

Establish the installable Python package, one versioned evidence/result contract,
canonical target authorization, immutable work budgets, cancellable task
lifecycle, and bounded local SQLite history. This phase provides test doubles
and a synthetic task but does not yet implement real inventory or network
probes.

</domain>

<decisions>
## Implementation Decisions

### Evidence contract
- Use frozen standard-library dataclasses and string enums; JSON is the public
  interoperability boundary, not Python object identity.
- Every document carries `schema_version`, task ID, task kind, direction,
  requested/effective configuration, timestamps, observations, conclusions,
  capabilities, progress, and terminal state.
- Preserve protocol truth on two axes. `disposition` is one of `positive`,
  `negative`, `inconclusive`, `unavailable`, `error`, or `cancelled`;
  `evidence_kind` distinguishes at least DNS answer/failure, TCP connected/
  refused/reset, network/host/ICMP unreachable, timeout, silent/no-response,
  UDP application reply, peer-observed arrival, TLS handshake, HTTP response,
  unsupported, permission denied, and execution error. Generic success/error
  strings must not erase protocol evidence.
- Conclusions cite observation IDs, carry `high`/`medium`/`low`/`unknown`
  confidence, and may list alternative explanations.

### Authorization and budgets
- Parse IP literals, host names, and CIDRs into typed targets before any active
  operation; canonicalize CIDRs and reject URL syntax, ambiguous numeric hosts,
  and invalid ports. Preserve a validated IPv6 scope/interface ID separately
  for link-local literals; reject a scope ID on non-link-local addresses and
  return typed `unsupported` evidence if the platform cannot use it.
- The operator must explicitly attest authorization for any non-loopback active
  target. Full-port mode and custom UDP payloads have separate exact
  confirmation gates.
- DNS names are authorized as names and every resolved address is checked again
  immediately before connection, preventing resolution from escaping policy.
- A frozen aggregate plan reserves hosts, ports, attempts/packets, sent bytes,
  global/per-target rate, concurrency, duration, event count, and output bytes
  up front. Absolute ceilings are 1,024 hosts, 65,535 ports, 100,000 attempts,
  200,000 packets, 64 MiB sent, 1,000 packets/s globally, 100 packets/s per
  target, 256 workers, 3,600 seconds, 100,000 events, and 64 MiB output.
  Configurable defaults are lower; no flag may raise these absolute values.
  Rate means logical attempt admission per second. Packet/datagram and sent
  byte limits count Mercury-generated UDP datagrams/application payload bytes;
  TCP/TLS/HTTP count logical attempts and application bytes. Mercury does not
  claim to count kernel retransmissions, framing, or exact on-wire bytes.

### Task lifecycle and persistence
- Task states are `pending`, `running`, `completed`, `failed`, and `cancelled`;
  cancellation is cooperative and always persists the valid observations
  already collected.
- One `TaskService` owns submission, progress, cancellation, finalization, and
  history. CLI and later WebUI call this service rather than implementing task
  behavior.
- SQLite stores the request, immutable effective plan, status, and source
  result as versioned JSON so local comparisons remain useful. It uses a
  per-user data directory and restrictive file permissions where the OS
  exposes them. Secrets, tokens, private keys, invitation material, and
  unbounded custom payloads are rejected from persistence. Export redaction is
  a later, separate boundary.
- A bounded synthetic task is included solely to verify lifecycle behavior
  without touching a network.

### Package and command surface
- Use a `src/mercury` layout, `pyproject.toml`, CPython 3.11+, and one runtime
  dependency (`psutil`); no framework, ORM, broker, or plugin abstraction.
- `python -m mercury` and the `mercury` console script share the same argparse
  entry point. Phase 1 exposes `version`, `model`, `plan`, `history`, and a
  hidden/developer synthetic task command.
- JSON output is stable and machine-readable; human output is a projection of
  the same result object. Errors use structured stderr and intentional exit
  codes.
- Tests use `unittest`, temporary directories, injected clocks/resolvers, and
  no public network access.

### the agent's Discretion
- Exact module boundaries, SQLite indexes, default soft budget values, and
  human-output wording may be selected for the smallest clear implementation,
  provided the hard safety semantics above remain visible and tested.

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- This is a greenfield repository; there is no product code to preserve.
- `.planning/research/STACK.md`, `PITFALLS.md`, and `PONYTAIL.md` define the
  approved standard-library-first implementation and trust boundaries.

### Established Patterns
- Ponytail full mode requires stopping at the first sufficient implementation
  rung and rejects speculative abstractions.
- Product documents use requirement IDs and evidence-backed acceptance
  criteria; tests should name the covered IDs where useful.

### Integration Points
- Phase 2 will add inventory and probe producers that emit this phase's
  observations.
- Phases 2 and 3 will reuse authorization, cost preview, budgets, progress, and
  cancellation.
- Phases 3 through 5 will reuse the same task service, JSON codec, and history.

</code_context>

<specifics>
## Specific Ideas

The defining UX is honest partial knowledge: UDP/ICMP silence is inconclusive,
and an inferred gateway or route hop is never presented as a directly observed
switch.

</specifics>

<deferred>
## Deferred Ideas

- Real network inventory and probes are Phase 2.
- Pinned mTLS/token peer control and paired differential diagnosis are Phase 3.
- Discovery, topology evidence, and route enrichment are Phase 4.
- WebUI, report export, and release hardening are Phase 5.

</deferred>
