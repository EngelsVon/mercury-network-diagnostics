# Phase 2: Local Snapshot and Layered Diagnosis - Context

**Gathered:** 2026-07-30
**Status:** Ready for planning
**Mode:** Autonomous smart-discuss defaults, constrained by the accepted roadmap

<domain>
## Phase Boundary

Deliver a useful ordinary-user `mercury status` and `mercury diagnose` on
Windows, Linux, and macOS. The phase covers host/interface facts, routes,
default gateways, DNS configuration, bounded DNS/TCP/TLS/HTTP/native-ping
evidence, one minimal native path sample, the `basic` and China-oriented
profiles, stable JSON, human projections, and deterministic health exit codes.

This phase does not implement a peer listener or paired diagnosis, active
subnet discovery, neighbor/LLDP collection, repeated route analysis, a WebUI,
or report export. Those remain in Phases 3 through 5.

</domain>

<decisions>
## Implementation Decisions

### Shared core and evidence contract

- **D-01:** Add one small application facade used by both CLI commands and the
  future WebUI. `cli.py` only parses input and renders returned canonical
  results; it must not enumerate interfaces, invoke native tools, resolve
  names, or open sockets directly.
- **D-02:** Every collected fact and probe result must retain a source,
  timestamp, duration, disposition, evidence kind, and bounded structured
  detail. Platform/probe failures become typed observations or capabilities;
  one unavailable source must not erase successfully collected evidence.
- **D-03:** Evolve the immutable plan so every active step has a finite,
  canonical probe identity included in its ID, digest, serialized preview, and
  service-bound observation metadata. DNS, native ping, and native path actions
  must not be disguised with dummy TCP ports or transports. When the wire
  contract gains fields or evidence kinds, increment the model schema minor
  version. Do not claim arbitrary forward compatibility: strict decoders must
  accept only the exact schema versions and enum vocabulary they implement.
- **D-04:** Add protocol-specific evidence kinds where the Phase 1 vocabulary
  is insufficient, including verified TLS failure, native ping reply/failure,
  and path-hop/path-completion evidence. Do not collapse them into generic
  execution errors, and keep timeout or no reply inconclusive.

### Passive local snapshot

- **D-05:** `status` is passive: it may read `psutil`, files, platform APIs, and
  read-only native command output, but sends no diagnostic packet and requires
  no authorization attestation.
- **D-06:** Use `psutil` for host-independent interface addresses/statistics and
  thin per-OS adapters for routes/default gateways and DNS configuration.
  Adapters return normalized records plus explicit provenance/capability
  state. Prefer structured native output where stable; isolate text parsers
  behind recorded fixtures for Windows, Linux, and macOS.
- **D-07:** Report hostname, OS, Mercury/Python versions, collection time,
  interface name/up state, IPv4/IPv6 address and prefix, MAC, MTU, and speed
  when available. Missing MAC/speed/prefix or an unsupported native source is
  `unavailable`, not fabricated or fatal.
- **D-08:** Keep default gateway, route entries, DNS servers, route hops,
  neighbors, Wi-Fi APs, and LLDP infrastructure as distinct concepts.
  Phase 2 must explicitly state that the directly attached access switch is
  not observable without direct LLDP/managed evidence; it may never relabel a
  gateway or first hop as a switch.
- **D-09:** Native commands use argument arrays, bounded execution time and
  output, no shell interpolation, and locale-resistant/structured modes when
  available. Missing tools, permission denial, nonzero exit, timeout, and
  parse failure are distinct capability/evidence states.

### Layered diagnosis

- **D-10:** Active non-loopback diagnosis always requires the existing explicit
  authorization attestation. Built-in profiles are finite conveniences, not
  implicit consent. The exact profile/custom hostnames, addresses, ports, and
  transports shown in the preview are the authorized scope, and hostname
  addresses are rechecked immediately before connection.
- **D-11:** Profiles are immutable versioned data. `basic` contains local
  prerequisites, system DNS resolution, at least one raw public-IP TCP check,
  and DNS/TCP/TLS/HTTPS checks across multiple conservative public targets.
  `china` uses the same layers with multiple commonly reachable mainland-China
  HTTPS targets. A profile must not enumerate hosts, ports, UDP payloads, or
  third-party networks.
- **D-12:** The researcher may select the exact built-in public endpoints, but
  must prefer stable operator-owned HTTPS services, use at least three
  independent operators per regional profile, document that endpoints can
  change, and ensure automated tests replace them with controlled fixtures or
  loopback servers. No normal test may contact or scan a public target.
- **D-13:** Repeated `--target HOST:PORT` values add exact custom checks;
  bracketed IPv6 `[ADDRESS]:PORT` is supported. A hostname target gets DNS plus
  TCP evidence; port 443 additionally gets verified TLS and HTTPS evidence,
  port 80 gets bounded HTTP evidence, and other ports remain TCP-only. URLs,
  CIDRs, ambiguous unbracketed IPv6-with-port input, wildcard ports, and
  implicit port ranges are rejected.
- **D-14:** Use one logical attempt per planned probe by default, a 3-second
  per-operation timeout, a user-configurable timeout constrained to
  0.1–30 seconds, bounded concurrency, and the Phase 1 aggregate ceilings.
  A minimal path sample is one native invocation with at most 8 hops and a
  bounded total duration. Repeated/multi-mode route analysis is Phase 4.
- **D-15:** Native ping and path commands are optional capability adapters.
  Their missing-tool/permission state and silence remain visible but cannot by
  themselves prove Internet failure. Path output preserves normalized hop
  evidence, unanswered hops, exit status, and bounded sanitized diagnostics;
  it does not claim a stable or unique route.
- **D-16:** DNS, TCP, TLS, and HTTP remain separate observations even when they
  concern the same endpoint. A valid HTTP response of any status proves an
  HTTP exchange and retains the status as application evidence; TCP refusal is
  explicit negative service evidence; TLS certificate/hostname verification
  is enabled by default; timeout and native-ping silence are inconclusive.

### Classification and CLI

- **D-17:** Conclusions describe only the selected endpoints and observed
  layers, never “the Internet is up/down” as a universal fact. Healthy means
  the required local prerequisites and every required profile layer have at
  least one direct positive observation. Failed requires no positive
  DNS/TCP/TLS/HTTP reachability evidence plus at least one explicit negative or
  execution error. All mixed, unavailable-only, or silence-only cases are
  partial. Optional ping/path evidence supplies context but cannot turn silence
  into failure.
- **D-18:** Human and `--json` output are projections of the same `TaskResult`.
  Retain the established exit constants: healthy/completed diagnosis is
  `EXIT_OK` (0), failed diagnosis is `EXIT_FAILED` (1), and partial diagnosis is
  `EXIT_PARTIAL` (4); existing usage, policy, and internal-error codes remain
  unchanged.
- **D-19:** Human output is concise but evidence-linked: summarize overall
  health, then local context and per-layer/target outcomes with duration and
  short error/degradation text. JSON remains the authoritative complete
  document and is deterministic apart from IDs/timestamps/timings.

### Verification and maintenance

- **D-20:** Unit and integration tests use `unittest`, injected clocks,
  resolvers/connectors/subprocess runners, recorded platform fixtures, and
  loopback TCP/TLS/HTTP servers. Tests cover success, refusal, timeout,
  resolution failure, TLS verification failure, HTTP status handling,
  native-tool missing/timeout/parse error, and health/exit-code projection.
- **D-21:** Keep the runtime dependency set at standard library plus `psutil`.
  Use small functions and concrete adapters; do not add a network framework,
  raw-packet engine, generic plugin registry, dependency-injection container,
  or a second result model.

### the agent's Discretion

The researcher/planner may choose exact module names, normalized route/DNS
record fields, platform command variants, stable default endpoint names,
bounded raw-output limits, and human wording, provided all decisions above and
Phase 2 requirements remain testable. Prefer the smallest implementation that
does not weaken authorization, provenance, evidence semantics, or platform
degradation behavior.

</decisions>

<specifics>
## Specific Ideas

The motivating incident is “the network appears down, but one layer or port
still works.” The CLI should make a pattern such as “DNS answers, raw TCP works,
TLS fails, HTTPS is unavailable” immediately visible without turning that
pattern into an unsupported root-cause claim.

Ponytail full mode applies: use `psutil`, the Python standard library, and
native OS tools before writing custom machinery. The product value is the
evidence-linked layered comparison that Phase 3 will run from both endpoints,
not scanner breadth.

</specifics>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Product and phase contract

- `.planning/PROJECT.md` — accepted NARROW-GO product scope and non-goals.
- `.planning/REQUIREMENTS.md` — INVT-01 through INVT-03 and DIAG-01 through
  DIAG-04 are the complete Phase 2 requirement set.
- `.planning/ROADMAP.md` — Phase 2 boundary, success criteria, and later-phase
  exclusions.
- `AGENTS.md` — Ponytail ladder, stack, safety, topology, and testing rules.

### Architecture and research

- `.planning/research/PONYTAIL.md` — pinned Ponytail review and reuse decision.
- `.planning/research/STACK.md` — standard-library plus `psutil` stack and
  native-command strategy.
- `.planning/research/ARCHITECTURE.md` — shared facade, policy core, thin
  platform adapters, and evidence invariants.
- `.planning/research/PITFALLS.md` — network-semantics, platform, and
  dual-use failure modes.

### Existing foundation

- `.planning/phases/01-evidence-and-safety-foundation/01-CONTEXT.md` — locked
  evidence, authorization, budget, lifecycle, persistence, and CLI decisions.
- `.planning/phases/01-evidence-and-safety-foundation/01-VERIFICATION.md` —
  verified Phase 1 behavior and residual boundaries.
- `src/mercury/models.py` — canonical observation/conclusion/result contract.
- `src/mercury/planner.py` and `src/mercury/policy.py` — immutable plan,
  authorization, resolution recheck, and budgets.
- `src/mercury/tasks.py` — authoritative step admission/evidence binding,
  cancellation, and persistence.
- `src/mercury/cli.py` and `src/mercury/render.py` — current thin CLI and
  projection/exit-code conventions.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets

- Frozen model dataclasses, explicit evidence/disposition enums, codec, and
  schema-major compatibility checks already provide the result boundary.
- `ScopeGrant`, hostname pre-resolution/recheck, `PlanPreview`/`ProbePlan`,
  hard budgets, and `TaskContext.admit()` provide the active-I/O trust boundary.
- `TaskService`, cancellation, bounded SQLite history, and safe persistence
  projection already provide task execution and lifecycle behavior.
- Existing CLI JSON/error handling and render helpers establish stable entry
  point and exit-code conventions.

### Established Patterns

- Successful planned steps require at least one observation before completion.
- `TaskContext` injects authoritative step/target/port/transport/DNS-change
  metadata and rejects runner attempts to forge reserved fields.
- All result conclusions cite observation IDs; UDP/ICMP silence remains
  inconclusive; raw sensitive input is not persisted.

### Integration Points

- Inventory collectors and platform adapters feed canonical observations and
  capabilities through the shared application facade.
- Layered probes extend, rather than bypass, planner authorization and
  `TaskService` admission.
- Phase 3 reuses the same profile/probe runners and result classifier for
  role-swapped paired diagnosis.
- Phase 4 enriches the deliberately minimal path adapter and adds
  neighbor/LLDP/discovery evidence without changing Phase 2 topology claims.

</code_context>

<deferred>
## Deferred Ideas

- Pinned-mTLS/token peer control, reverse roles, UDP peer data plane, and
  directional A-to-B/B-to-A comparison are Phase 3.
- Passive subnet candidates, active bounded discovery, ARP/NDP, Wi-Fi AP,
  optional LLDP, and repeated/multi-mode route analysis are Phase 4.
- WebUI, history comparison, redacted report export, packaging matrix, and
  broad controlled-lab verification are Phase 5.
- Full TCP ranges, custom UDP payloads, and advanced finite matrices remain
  behind their later independent confirmation gates.

</deferred>

---

*Phase: 02-local-snapshot-and-layered-diagnosis*
*Context gathered: 2026-07-30*
