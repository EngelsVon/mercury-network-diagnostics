# Phase 3: Authenticated Paired Differential Diagnostics - Context

**Gathered:** 2026-08-01
**Status:** Ready for planning
**Mode:** Autonomous smart-discuss defaults (requested project continuation)

<domain>
## Phase Boundary

Deliver a deliberately small, two-endpoint diagnostic mode: explicitly paired
Mercury agents mutually authenticate, independently authorize the same finite
plan, then run equivalent evidence collection with A→B and B→A roles. It
must explain observed directional and protocol differences without accepting a
general-purpose remote scan request. This phase does not add subnet discovery,
route/topology enrichment, a WebUI, report export, or a centralized control
plane.

</domain>

<decisions>
## Implementation Decisions

### Pair trust and control boundary

- **D-01:** Pairing is operator-provisioned file configuration, not an in-band
  enrollment flow. Each endpoint is configured with its own certificate/key,
  CA file containing the allowed peer client certificate(s), expected peer
  certificate SHA-256 pin(s), a distinct shared control token, and a fixed peer
  identity/address set. Secrets and private-key material are accepted only as
  paths, never written to task history, JSON output, audit records, or errors.
- **D-02:** A non-loopback peer listener must require TLS, a server
  certificate/key, client-certificate verification, pin match, and token. The
  only relaxation is an explicit `--unsafe-development` loopback-only path that
  records a high-visibility audited capability/evidence warning. There is no
  implicit fallback to cleartext, token-only, or server-only TLS.
- **D-03:** Use a compact versioned length-prefixed JSON control frame with a
  strict known-field decoder, maximum frame size, maximum nesting/string
  limits, correlation ID, peer identity, issued/expiry timestamps, and a
  random nonce. Reject malformed/unknown-version/oversized frames before
  dispatch. Maintain a bounded, expiring per-peer nonce cache and reject a
  replay without re-running work.
- **D-04:** Control operations are limited to capability negotiation, submit
  an immutable paired plan, read the correlated bounded result, and cancel the
  caller's own correlated request. The receiver recompiles/revalidates its
  received plan and local scope/budgets at admission; it never trusts remote
  cost, DNS, authorization, or result claims.

### Fixed paired data plane

- **D-05:** A paired request may address only the configured mutually paired
  endpoint identity and its explicit configured addresses/ports. Reverse work
  is source-bound to the authenticated peer configuration plus the plan's
  endpoint declaration; no request may nominate a third-party host, CIDR,
  hostname resolution result, listener port, or payload.
- **D-06:** Keep the v1 profile finite and built in: one bounded TCP listener
  and one nonce-tagged UDP echo listener with short expiries and hard byte/frame
  limits. The UDP datagram carries a version, plan ID, nonce and fixed-size
  opaque tag; it produces distinct sent, peer-arrived, peer-replied and
  received observations. Missing any arrival/reply stays `silent` or
  `inconclusive`, never becomes an asserted packet loss or firewall cause.
- **D-07:** Listener lifetimes are bound to the immutable plan's expiry and
  cancellation; they bind only their configured peer-safe address and selected
  finite ports. TCP acceptance checks the negotiated plan/correlation before
  application evidence is emitted. Existing canonical `TaskContext.admit()`
  and plan reservations remain the sole active-I/O accounting gate.

### Differential result and operator experience

- **D-08:** Each endpoint collects a passive snapshot and executes the same
  bounded DNS, peer-path, TCP, UDP, and allowlisted TLS/HTTP layers when those
  steps are included. Local native-tool capability differences remain local
  typed evidence, not peer failures.
- **D-09:** The paired result is one versioned canonical task document with
  endpoint-labelled evidence and a fixed A→B/B→A layer matrix. Explanations
  cite source observations and use only bounded language: for example,
  `A→B TCP refused while B→A connected`; they may name plausible alternatives
  but do not diagnose a firewall, route, or switch without direct evidence.
- **D-10:** Add `mercury agent` for controlled listener lifecycle and
  `mercury paired` for submission/projection. CLI remains parsing/rendering
  only and uses shared application services. Human output leads with the
  directional matrix; `--json` remains the complete authoritative document and
  preserves the established healthy/failed/partial exit semantics.

### Verification and deployment

- **D-11:** Tests use repository-owned ephemeral test CA/certificates,
  loopback peers, injected clocks/transports, and explicitly controlled
  listener fixtures. They cover non-loopback startup denial, mTLS/pin/token
  failure, replay, malformed/oversized frames, expired or escalated plans,
  third-party target rejection, TCP connect/refusal/timeout, UDP reply/silent,
  DNS differences, and directional asymmetry. Tests never contact public or
  unowned targets.
- **D-12:** The user-authorized Ubuntu SSH host may be used only after the
  controlled tests pass, for an opt-in two-machine smoke against its explicitly
  configured address. Certificates/tokens are created with restrictive remote
  permissions, output is sanitized before being copied into planning evidence,
  and temporary remote test files are removed after the test.

### the agent's Discretion

The planner may choose concrete module names, exact bounded frame and payload
sizes, CA fixture generation mechanics, certificate subject names, default
plan TTL, local audit representation, and concise human wording. It must use
the standard library plus `psutil`, favor `ssl`/`asyncio`, and preserve the
existing evidence, scope, budget, persistence, and presentation boundaries.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Product and safety contract

- `AGENTS.md` — Ponytail ladder, Windows/Ubuntu support target, mTLS/token
  trust boundary, scope/budget invariants, and controlled-test rules.
- `.planning/PROJECT.md` — accepted NARROW-GO product scope and the original
  mTLS + independent-token decision.
- `.planning/REQUIREMENTS.md` — SAFE-05 and PEER-01 through PEER-06 define the
  complete Phase 3 requirement set.
- `.planning/ROADMAP.md` — Phase 3 boundary, success criteria, and technical
  continuation gate.
- `.planning/STATE.md` — current phase position and Phase 2 completion state.

### Existing architecture

- `.planning/phases/01-evidence-and-safety-foundation/01-CONTEXT.md` — locked
  evidence, authorization, immutable budget, lifecycle, and history rules.
- `.planning/phases/02-local-snapshot-and-layered-diagnosis/02-CONTEXT.md` —
  shared facade, sparse probe identity, layered probe semantics, and CLI rules.
- `src/mercury/models.py` — canonical wire/evidence/result types and schema
  vocabulary to extend conservatively.
- `src/mercury/policy.py` — scope grant, hostname resolution recheck, expiry,
  and exact active-target authorization.
- `src/mercury/planner.py` — immutable sparse probe plan, digest, costs,
  confirmations, and canonical revalidation.
- `src/mercury/tasks.py` — service-owned admission/evidence binding,
  cancellation, output ceilings, and bounded persistence.
- `src/mercury/app.py` — single presentation-independent application facade.
- `src/mercury/cli.py` and `src/mercury/render.py` — thin CLI, JSON/human
  projection, and stable exit conventions.
- `src/mercury/diagnosis.py` and `src/mercury/profiles.py` — existing bounded
  local layered execution to reuse rather than duplicate.

### Verified local baseline

- `tests/test_phase2_smoke.py` and `tests/test_installation.py` — controlled
  facade/install patterns and public-network prohibition.
- `tests/fixtures/tls/README.md` — repository-owned TLS fixture handling.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets

- `ScopeGrant`, exact target authorization and expiring resolution snapshots
  already prevent scope escape and should validate both sides of a pair.
- `ProbeSpec`/`preview_probe_plan`, `ProbePlan`, `TaskContext`, and
  `TaskService` already provide immutable step identities, reservations,
  cancellation, output ceilings, and auditable result persistence.
- `MercuryApplication` is the required seam for CLI and later WebUI services;
  its constructor injection style supports controlled peer test transports.
- Existing diagnosis runners preserve per-layer DNS/TCP/TLS/HTTP evidence and
  renderers project canonical results rather than probing directly.

### Established Patterns

- A planned active step must be admitted exactly once and produce only evidence
  allowed for its bound probe identity, direction, target, port and attempt.
- Strict schema/enum decoding rejects unknown data rather than claiming
  forward compatibility; bounded native subprocess work uses argument arrays.
- Secrets and raw custom payloads fail persistence checks; loopback fixtures
  are the only ordinary test network.

### Integration Points

- New peer transport/listener services belong behind `MercuryApplication`,
  consume `ProbePlan`/`TaskService`, and feed canonical observations.
- `cli.py` needs parser/dispatch additions only; render additions consume the
  paired result model.
- Existing TLS loopback helpers and test CA fixtures can seed peer security and
  two-endpoint controlled integration tests.

</code_context>

<specifics>
## Specific Ideas

The requested product slice is evidence-linked directionality, not remote
automation breadth. The supplied Ubuntu endpoint is authorized for a final
controlled, two-machine smoke once the same behavior is protected by local
tests; it is not a license for third-party scans.

</specifics>

<deferred>
## Deferred Ideas

- Human-verifiable short-code certificate enrollment remains v2 (PAIR-01).
- Passive discovery, topology/LLDP and repeated route analysis remain Phase 4.
- Web dashboard, history comparison/export, packaging hardening and broad lab
  coverage remain Phase 5.
- Fleet management, arbitrary remote APIs, custom peer payloads, generic proxy
  support and a central coordinator remain out of the Phase 3 scope.

</deferred>

---

*Phase: 03-authenticated-paired-differential-diagnostics*
*Context gathered: 2026-08-01*
