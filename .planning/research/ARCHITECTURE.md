# Architecture Research

**Domain:** Cross-platform, local-first network reachability diagnostics with
paired endpoints  
**Project:** Mercury  
**Researched:** 2026-07-30  
**Recommended style:** Python modular monolith with one shared asynchronous
engine and thin CLI, loopback HTTP/polling, peer, storage, and platform adapters
**Overall confidence:** MEDIUM-HIGH

## Accepted v1 Planning Baseline

This file records the architecture deep dive, including stronger or more
complex options. The accepted requirements and `ROADMAP.md` take precedence
where they narrow those options:

- Peer control uses operator-provisioned mTLS, exact configured certificate
  fingerprints, and a separately rotatable bearer token. Mercury v1 does not
  implement invitation or private-CA lifecycle UX.
- The local WebUI uses bounded short polling. The persisted event sequence is
  retained so resumable SSE can be added only if polling is measured to be
  insufficient.
- Build order is foundation → local snapshot/probes → paired differential
  vertical slice → discovery/topology/routes → WebUI/release. The later
  “Suggested Build Order” is research input, not the execution plan.
- SQLite retains local source evidence in a current-user-only location while
  excluding credentials and unbounded payloads; reports apply central
  redaction.

## Architecture Decision

Build Mercury as **one package and one ordinary-user process**. CLI and WebUI
must invoke the same application service, planner, scheduler, probe registry,
classifiers, and persistence schema. Platform-specific collection and the peer
wire protocol sit behind narrow adapters; they do not fork product behavior.

The architectural center is a policy boundary:

```text
untrusted request
    ↓
normalize identity/targets → authorize scope → cost immutable plan
    ↓
bounded scheduler → probe/platform I/O → immutable observations
    ↓
evidence classifier → findings with confidence and alternatives
    ↓
commit task/events/result → CLI / JSON / SSE / WebUI / redacted report
```

No CLI flag, HTTP handler, peer message, or probe implementation may bypass
scope validation, plan costing, hard budgets, cancellation, or audit.

### Non-negotiable invariants

1. **Evidence before verdict.** TCP refusal, timeout, DNS failure, ICMP error,
   UDP reply, UDP silence, and peer-observed arrival remain distinct.
2. **Direction is data.** Every attempt and observation names origin node,
   destination node/address, transport, and direction. Reverse reachability is
   run separately; it is never inferred from the forward result.
3. **Peer identity is a certificate pin, not an IP address.**
4. **The receiver authorizes peer work independently.** Pairing is not a grant
   for arbitrary scans.
5. **All work is pre-costed and bounded.** A probe cannot spawn work outside its
   immutable plan.
6. **Ordinary-user baseline first.** Privileged capabilities are optional and
   visibly degraded.
7. **A transparent L2 switch is `unknown` without direct evidence.** Gateway,
   ARP/NDP neighbor, and first route hop are not relabeled as “switch.”
8. **Persist, then publish.** A resumable event cursor reflects committed task
   state, not an in-memory-only progress stream.
9. **Unknown protocol/risk input fails closed.** Unknown diagnostic capability
   fails visible as unavailable, not as an empty success.

## Standard Architecture

### System overview

```text
┌──────────────────────────── Presentation / ingress ────────────────────────────┐
│  CLI (direct)       Loopback HTTP + SSE       Peer control adapter (mTLS)     │
│       └───────────────────┬──────────────────────────────┘                     │
├───────────────────────────┴ Application facade ────────────────────────────────┤
│  task submission · capability query · cancellation · history · report/export  │
├────────────────────────── Policy and execution core ───────────────────────────┤
│  target normalizer → policy engine → plan compiler → bounded scheduler         │
│                                             │                                  │
│                   probe registry → executors → observation classifiers         │
├────────────────────────────── Ports / adapters ─────────────────────────────────┤
│  stdlib sockets/DNS/TLS   Windows/Linux/macOS facts   peer data-plane listener │
│  optional native tools    optional future helper     TCP/UDP nonce correlation │
├──────────────────────── Evidence / event state ─────────────────────────────────┤
│  SQLite task + event log · peer pins/policy · audit · redaction · event broker │
└─────────────────────────────────────────────────────────────────────────────────┘
```

For WebUI mode, the process has one dedicated `asyncio` engine thread.
`ThreadingHTTPServer` handlers submit coroutines with
`asyncio.run_coroutine_threadsafe()` and never access sockets, policy, or
SQLite directly. CLI mode calls the same asynchronous application service with
`asyncio.run()` and needs no local daemon.

### Component responsibilities

| Component | Owns | Must not own |
|-----------|------|--------------|
| Application facade | Use cases and authorization context passed to the core | Socket semantics or HTTP formatting |
| Target normalizer | IP/CIDR/hostname/port canonicalization, resolution snapshot, IPv6 scope IDs | Authorization decisions |
| Policy engine | Allowed scope, risk tier, peer policy, forbidden targets, confirmation record | Probe execution |
| Plan compiler | Finite steps, estimated packets/bytes/time/events, effective clamped budget | Dynamic unbounded discovery |
| Scheduler | Global/per-target limits, deadlines, retries, cancellation, task state | Result interpretation |
| Probe registry | Built-in probe descriptors, required capabilities, cost/run/classify functions | Third-party code loading in v1 |
| Platform facts | Interfaces, addresses, routes, DNS, neighbors, Wi-Fi, LLDP provenance/capability | Topology certainty not present in evidence |
| Classifiers | Deterministic observation → finding rules with alternatives/confidence | Network I/O |
| Store | Schema migration, transactions, task/event/peer/audit persistence, retention | Presentation |
| Event broker | Post-commit fan-out, bounded subscriber queues, cursor replay coordination | Authoritative history |
| Local HTTP/SSE | Same-origin browser API, static assets, session/CSRF checks, projections | Direct probe calls |
| Peer control | TLS identity, framing, version/state/replay checks, remote task ingress | Granting itself scan scope |
| Peer data plane | Prepared TCP/UDP listeners, per-attempt authentication, arrival evidence | General echo/scanning service |
| Redactor/reporter | Central privacy policy and deterministic export | Mutating stored source evidence |
| Optional helper | A future fixed set of privileged operations | Web, parsing, database, arbitrary commands/packets |

## Recommended Project Structure

The structure follows the Python recommendation in `STACK.md` while keeping
security and I/O boundaries testable. It is a destination, not permission to
scaffold every file on day one.

```text
pyproject.toml
src/mercury/
├── __init__.py
├── __main__.py
├── cli.py                 # argparse, human/JSON projections only
├── app.py                 # application facade/use cases
├── models.py              # versioned dataclasses/enums and validation
├── policy.py              # scope grants, peer policy, risk decisions
├── planner.py             # finite plan expansion and cost calculation
├── scheduler.py           # bounded asyncio execution/cancellation
├── events.py              # task state machine, cursor broker
├── store.py               # sqlite3 migrations/transactions/retention
├── redact.py              # report/export privacy policy
├── probes/
│   ├── registry.py        # built-in profiles and probe descriptors
│   ├── socket.py          # TCP/UDP/TLS/application probes
│   └── route.py           # ping/trace adapters and classification inputs
├── platform/
│   ├── common.py          # capability/result types and safe subprocess wrapper
│   ├── linux.py
│   ├── windows.py
│   └── macos.py
├── peer/
│   ├── auth.py            # provisioning, certificate pins, peer policy
│   ├── protocol.py        # bounded versioned JSON frames/state machine
│   ├── control.py         # asyncio TLS client/server
│   └── dataplane.py       # prepared authenticated TCP/UDP listeners
└── web/
    ├── server.py          # loopback HTTP API, SSE, session/Origin/Host checks
    └── static/
        ├── index.html
        ├── app.js
        └── style.css
tests/
├── unit/                  # policy, planner, classifier, schema, redaction
├── fixtures/              # recorded OS command/API outputs
├── contract/              # platform, store, HTTP/SSE, peer protocol adapters
├── integration/           # loopback TCP/UDP/DNS and two-node processes
└── lab/                   # Linux netns/netem/firewall scenarios
```

### Structure rationale

- **Plain core modules:** the domain is not large enough for a framework,
  dependency-injection container, repository layer, or service graph.
- **`platform/`:** three real OS implementations plus test fakes justify a
  narrow adapter contract.
- **`probes/`:** keeps network I/O and probe-specific classification away from
  transport/UI code; the registry is internal, not a public plugin SDK.
- **`peer/`:** remote input is a separate trust boundary and needs isolated
  protocol/security tests.
- **`web/`:** Python documents `http.server` as providing only basic security;
  it is therefore a loopback presentation adapter, not Mercury's exposed peer
  server.
- **`store.py`:** one SQLite implementation is enough. Add a repository
  abstraction only if a second store actually appears.

## Canonical Domain Model

Use dataclasses/enums with explicit `schema_version` and validators. Wire,
storage, CLI JSON, and reports may share canonical field names, but each
boundary parses into domain objects instead of passing untrusted dictionaries.

| Model | Required content |
|-------|------------------|
| `Capability` | name, state (`available`, `unsupported`, `permission_denied`, `missing_tool`, `error`), evidence source/version, detail |
| `AuthorizationScope` | normalized networks/hosts, ports/transports, issuer, confirmation time, expiry, purpose |
| `ProbeBudget` | max targets, ports, attempts, concurrency, packets/bytes, duration, events/output |
| `TaskRequest` | task/profile/version, requested targets, requester kind/id, authorization reference |
| `ProbePlan` | immutable effective steps, policy snapshot/digest, calculated cost, warnings |
| `ProbeAttempt` | task/attempt/probe IDs, origin, destination, transport, payload profile, deadlines, direction |
| `Observation` | origin node, local wall and monotonic timing, outcome, OS/ICMP/application evidence, bounded raw reference |
| `Finding` | classification, confidence, candidate explanations, supporting observation IDs, limitations |
| `TaskEvent` | task ID, monotonic sequence, timestamp, type, bounded payload/schema |
| `PeerRecord` | stable node ID, certificate/SPKI pin, endpoint, allowed actions/scope/budget, created/rotated/revoked times |
| `AuditEntry` | actor, decision, effective plan digest, accepted/rejected reason, task/peer IDs |

### Evidence semantics

Do not use `is_online` or `is_open` as source-of-truth fields.

```text
TCP: connected | refused | timed_out | network_unreachable | reset | error
UDP: application_reply | peer_observed_arrival | icmp_unreachable |
     local_error | silent_after_attempts
Route hop: responded | no_response | admin_prohibited | unreachable
Topology fact: observed | inferred | unknown
```

`Finding` may summarize these, but it must retain observation references and
alternatives. A later classifier improvement can re-derive findings from
stored observations without inventing evidence.

### L2 truth model

Keep these node/fact types distinct:

| Fact | Evidence source | What it can establish |
|------|-----------------|-----------------------|
| Interface/address | OS/psutil | Local endpoint configuration |
| ARP/NDP neighbor | OS neighbor cache | Protocol-to-link address for an on-link neighbor |
| Default gateway | Route table | Selected L3 next hop |
| First traceroute response | TTL/hop-limit probe | A responding L3 hop on that sampled flow |
| Wi-Fi AP/BSSID | OS Wi-Fi API/tool | Associated wireless infrastructure |
| LLDP/CDP advertisement | Captured/managed protocol source | Advertised adjacent infrastructure, subject to source trust |
| Access switch with no advertisement/admin data | None | **Unknown / not observable** |

ARP resolves network addresses to link addresses and IPv6 Neighbor Discovery
finds on-link neighbors/routers; neither reveals a transparent intermediate
bridge. The UI must not draw an inferred gateway as a switch.

## Architectural Patterns

### Pattern 1: Modular monolith with ports/adapters

**What:** A single application core receives typed requests. CLI, HTTP, peer,
SQLite, OS facts, and sockets are adapters around it.

**Why here:** Local tasks share process state and budgets. Microservices would
add authentication, deployment, failure, and schema problems without creating
useful isolation.

**Trade-off:** A bad in-process parser can affect the whole app. Keep untrusted
parsers small, bounded, and fixture-tested; isolate only a future privileged
helper.

### Pattern 2: Plan before execute

**What:** Convert a request into an immutable, costed `ProbePlan` before opening
any socket.

```python
request -> normalize -> policy.decide -> planner.compile -> scheduler.run
```

The planner computes targets × ports × transports × profiles × retries and
rejects or clamps against both user and absolute budgets. Scheduler workers
consume only plan steps; probes cannot recursively discover and schedule work.

**Trade-off:** Adaptive diagnosis needs follow-up work. Represent it as a new
bounded plan revision with its own event/audit record, never an invisible
unbounded branch.

### Pattern 3: Evidence ledger plus derived findings

**What:** Persist normalized observations and task state; derive concise
findings separately.

**Why here:** UDP silence, ICMP filtering, multipath routing, and platform
permission failures are ambiguous. Evidence survives reclassification and
allows two nodes' observations to be correlated.

**Trade-off:** More fields than a boolean result. Bound raw evidence and retain
coarse attempts rather than every packet.

### Pattern 4: Capability-driven degradation

**What:** Platform adapters return a typed capability result before/alongside
data.

```python
Capability(name="lldp", state="missing_tool", detail="lldpctl not installed")
```

UI and CLI render unavailable/denied/not-observed separately. They never turn a
missing tool or permission error into “no neighbors.”

**Trade-off:** Capability matrices require OS contract tests, but prevent false
diagnoses and scattered `sys.platform` branches.

### Pattern 5: Separate peer control and diagnostic data planes

**What:** A mutually authenticated TLS control channel authorizes/prepares a
test. Separate TCP/UDP sockets carry the packet flow being diagnosed.

**Why here:** Testing the control connection only proves the control transport.
Prepared listeners let Mercury correlate arrival on the actual requested
transport/port while keeping authorization out of unauthenticated packets.

**Trade-off:** A port may be privileged, occupied, NAT-unreachable, or blocked.
`BindFailed`/`NotConfigured` is evidence; never commandeer another service.

### Pattern 6: Persisted sequence plus resumable SSE

**What:** Each task event gets a strictly increasing per-task `seq` in the same
transaction as its state/result change. After commit, the event broker fans it
out. Browser SSE uses `id: <seq>` and reconnects from `Last-Event-ID`.

**Why here:** Task progress is one-way server → browser. SSE is smaller than a
WebSocket protocol and naturally reconnects. HTTP POST handles commands.

**Trade-off:** `ThreadingHTTPServer` uses one thread per local SSE client. A
single-user loopback UI makes this acceptable. Close slow subscribers and let
them replay; retain polling as a fallback.

## Task Runtime and Event Flow

### Engine ownership

- One engine thread owns the `asyncio` loop, scheduler, active task map,
  SQLite connection, and event sequencing.
- CLI mode runs that engine in the main thread.
- Web mode starts it once in a dedicated thread. Handler threads submit
  application calls with `run_coroutine_threadsafe()` and await bounded
  futures.
- HTTP handlers never share an event loop, SQLite connection, or mutable task
  object.
- SQLite uses its default same-thread safety rule. Small, aggregated commits
  run in the engine thread. Introduce a dedicated store worker only if measured
  write latency blocks probes.

### Task state machine

```text
accepted → planned → queued → running → finalizing
                           ↘ cancelling → cancelled
              any state ───────────────→ failed
finalizing → completed
```

Transitions are validated and persisted. Cancellation:

1. records `cancelling`;
2. stops admission of new plan steps;
3. cancels the task's `TaskGroup`;
4. closes listeners/sockets and terminates bounded subprocesses;
5. persists partial observations and a final `cancelled` event.

Python's `asyncio.TaskGroup` provides structured ownership; swallowing
`CancelledError` inside probes is forbidden unless cleanup re-raises it.

### Event volume and backpressure

Emit:

- task/phase transitions;
- plan and effective budget;
- aggregate progress counters;
- notable observations/findings;
- warnings/capability changes;
- final summary.

Do not emit/store one event per sent packet in normal mode. Each subscriber has
a bounded queue. On overflow, mark it stale and close; reconnect replays from
SQLite. SSE heartbeats are comments, not stored task events.

## Local API and WebUI Boundary

### Recommended loopback API

```text
POST /api/v1/tasks                 validate and submit
GET  /api/v1/tasks/{id}            snapshot/result
GET  /api/v1/tasks/{id}/events     SSE, cursor/Last-Event-ID
POST /api/v1/tasks/{id}/cancel     request cancellation
GET  /api/v1/capabilities          platform/probe capability matrix
GET  /api/v1/history               bounded cursor history
POST /api/v1/reports/{id}          redacted export
```

The server binds explicit loopback addresses only (`127.0.0.1` and, when
supported, `::1`). Non-loopback WebUI binding is out of the default v1 path;
Python documents `http.server` as implementing only basic security.

### Browser security

- Generate an unguessable per-launch session secret with `secrets`.
- Use a same-origin, `HttpOnly`, `SameSite=Strict` session cookie; do not put
  secrets in URLs, logs, or `localStorage`.
- Validate `Host` and `Origin` for every state-changing request and require a
  custom CSRF header issued in the initial page response.
- Use `POST` for mutation, body/field/target size limits, no redirects to
  operator-supplied destinations, and a restrictive CSP.
- Bundle HTML/CSS/JS with `importlib.resources`; no CDN or runtime third-party
  script.
- EventSource may use the same-origin cookie. SSE payload is JSON-encoded and
  never interpolated as HTML.

The WebUI is a projection of application results. It must display source,
direction, confidence, capability degradation, and candidate explanations—not
invent a separate red/green classifier.

## Peer Pairing, Authentication, and Protocol

This phase needs a dedicated threat model and security review. The design below
uses standard TLS and HMAC primitives; it does not invent encryption.

### Identity and certificate provisioning

Every peer-enabled node has:

- a stable random `node_id`;
- an operator-supplied TLS certificate/private key and trust roots;
- protected local storage for the key path/credentials;
- a peer table pinning the exact peer certificate or SPKI fingerprint;
- a per-peer allowed action/scope/budget policy.

Mercury v1 should not generate/manage a private CA. Organizational certificates
or explicitly provisioned test certificates are prerequisites. A certificate
change requires explicit rotation/re-pairing.

### Explicit pairing workflow

1. On node A, an operator starts `peer pair --listen --ttl 5m`. The pairing
   endpoint is temporary and server-authenticated with A's configured TLS cert.
2. A generates a high-entropy, single-use invitation secret in memory and
   presents endpoint, `node_id`, certificate fingerprint, expiry, and secret as
   a protected invitation (paste prompt/file/QR). A short six-digit value must
   never be the only credential.
3. The operator imports the invitation on B. B verifies A's certificate chain
   and exact fingerprint before sending the invitation secret; secrets are not
   passed in a command-line argument or URL.
4. B sends its `node_id`, certificate/fingerprint, capabilities, and requested
   policy over the server-authenticated TLS bootstrap. A shows the fingerprint
   and policy for local confirmation.
5. Both sides store explicit peer records/pins; A consumes the invitation.
6. Normal control sessions require mutual TLS (`CERT_REQUIRED`) and an exact
   non-revoked pin. Pairing endpoints are closed outside the short workflow.

This bootstrap is manual by design. A friendlier PAKE/QR workflow is a later
security-researched feature, not a reason to accept a bearer secret as a
permanent peer identity.

### Control transport

Use `asyncio.start_server(..., ssl=context)` rather than exposing
`http.server` remotely. The control stream uses:

- TLS 1.3 target minimum; Phase implementation must fail visibly if the
  packaged TLS stack cannot meet the policy;
- required client certificate plus exact pin/peer-record lookup;
- four-byte network-order length prefix followed by UTF-8 JSON;
- maximum frame size checked before allocation (for example 256 KiB);
- read/write/idle deadlines and a cap on outstanding messages;
- no TLS/application early data for state-changing requests.

The framing is not a crypto protocol. TLS provides confidentiality/integrity/
peer certificate authentication; Mercury provides strict task authorization
and replay/state checks.

### Versioned envelope

```json
{
  "protocol": "mercury-peer",
  "major": 1,
  "minor": 0,
  "message_type": "task.prepare",
  "message_id": "uuid",
  "task_id": "uuid",
  "issued_at": "RFC3339",
  "expires_at": "RFC3339",
  "body": {}
}
```

Rules:

- major version must match; minor features are selected from a negotiated
  capability intersection;
- unknown message/probe/risk types are rejected;
- unknown optional response fields may be ignored;
- `message_id`/`task_id` uniqueness, expiry, and legal state transition are
  checked per authenticated peer;
- accepted IDs remain in the durable task/audit store through their replay
  window;
- errors use stable codes (`unauthorized_scope`, `budget_exceeded`,
  `unsupported_probe`, `bind_failed`, `replay`, `expired`, `version_mismatch`)
  and bounded human detail.

### Control state machine

```text
mTLS + pin verified
    ↓
hello(capabilities, versions)
    ↓
task.prepare(requested listener/profile/scope/budget)
    ↓
receiver policy: reject | clamp | accept
    ↓
listener.ready(bound endpoint, attempt nonce/key expiry)
    ↓
attempt.start → observation* → task.finish
                     ↘ cancel → task.cancelled
```

The receiver persists the effective plan and audit decision before returning
`listener.ready`. It never accepts “connect to arbitrary target” from a peer.

## Directional TCP/UDP Data Plane

### Prepared listener rule

A peer may request a temporary listener only when the receiving node's policy
allows the transport, port, bind address, duration, packet/byte count, and
paired destination. The listener:

- has an absolute expiry and bounded attempts/bytes;
- uses a fresh per-attempt random secret delivered only over mTLS control;
- authenticates each small envelope with HMAC and constant-time comparison;
- records the actual observed source endpoint and nonce;
- replies no larger than the request and is rate-limited;
- closes on completion, cancellation, expiry, or control-session loss.

An occupied or privileged port returns a capability/bind observation. Mercury
does not stop or impersonate the existing service. A normal client-side probe
may still test that service, but it cannot claim peer-correlated arrival.

### TCP attempt

```text
A control → B: prepare TCP listener
B control → A: ready(port, nonce/key, expiry)
A data    → B: connect + bounded authenticated attempt envelope
B data    → A: authenticated acknowledgement
B control → A: accepted/received observation
A merges: local connect/send/ack + B's receive evidence
```

Positive connection and B's nonce match prove A → B arrival at the
application listener. Refusal/timeout remain A-side observations with candidate
causes; B cannot prove that a dropped SYN never existed.

### UDP attempt

```text
A control → B: prepare UDP listener
B control → A: ready(port, nonce/key, expiry)
A data    → B: bounded authenticated datagram(s)
B data    → A: bounded authenticated acknowledgement
B control → A: datagram-arrival observation(s)
A records: reply | ICMP error | local error | silence
```

- B's authenticated arrival proves the tested A → B datagram reached B.
- A's authenticated acknowledgement proves a response returned for that
  flow, but it does **not** replace a separately initiated B → A test.
- No arrival, no ICMP error, and no acknowledgement is `silent/inconclusive`,
  never `open` or `closed`.
- UDP uses aggregate rate control as required by RFC 8085 and a small
  non-amplifying payload.

### Reverse direction

Run the same preparation with roles swapped. Findings compare:

```text
A → B TCP/UDP evidence
B → A TCP/UDP evidence
```

Do not compare wall clocks for one-way latency unless clock synchronization is
independently established. Use each node's monotonic duration and correlate
attempts by IDs/nonces.

## Probe Registry

The v1 registry is a plain built-in mapping, not a dynamic plugin system.

Each descriptor declares:

```text
id + version
risk tier
input/profile schema
required capabilities
cost estimator
plan-step compiler
async executor
observation classifier
```

Recommended initial probes:

- local interface/route/DNS facts;
- DNS resolution and direct-IP comparison;
- TCP connect;
- bounded UDP application profile;
- TLS handshake/certificate summary;
- HTTP(S) expected status/body marker;
- native ping/traceroute adapters with explicit capability limits;
- paired TCP/UDP arrival profile.

Discovery is a planner/profile using passive candidates plus bounded probes,
not a special scanner that bypasses policy. Arbitrary payload code, raw packet
templates, and third-party in-process plugins are out of scope.

## Policy, Budget, and Safety Enforcement

### Scope compilation

1. Parse literals/CIDRs with `ipaddress`; preserve IPv6 scope/interface where
   applicable.
2. Normalize IPv4-mapped IPv6 and reject malformed/ambiguous forms.
3. Resolve a hostname once for the plan, record all A/AAAA results and resolver
   provenance, and enforce every resolved address against scope.
4. Connect to the validated address while retaining intended hostname/SNI
   where the profile requires it; do not follow target-changing redirects.
5. Intersect user request, local absolute policy, and (for peers) per-peer
   policy.
6. Record requested versus effective scope and any clamp/rejection.

### Hierarchical budget

Enforce all of:

- absolute task targets/ports/attempts/duration/output;
- global active sockets/subprocesses;
- per-interface/subnet/destination token buckets;
- per-protocol packet/byte rates;
- retry spacing/backoff;
- bounded queue and event/subscriber sizes.

Advanced matrix mode first shows calculated cardinality/time/traffic, then
requires explicit confirmation. Confirmation cannot raise compiled absolute
ceilings.

### Audit

Persist accepted and rejected active requests with actor, authorization scope,
policy version/digest, requested/effective budget, target summary, time, and
reason. Redacted user reports are separate from the protected local audit
record.

## Capability and Privilege Architecture

### Ordinary-user process

| Capability | Baseline | Degradation |
|------------|----------|-------------|
| Interfaces/addresses/link/MTU | `psutil` | Field-specific unavailable/error |
| TCP/UDP/TLS/HTTP | stdlib sockets | OS error/timeout observation |
| DNS | stdlib/OS resolver | Resolver error/provenance |
| Routes/neighbors/Wi-Fi | platform adapter/tool | unsupported/missing/parse/permission |
| Ping/trace | native tool where available | unsupported/permission/filtered ambiguity |
| LLDP | consume deployed structured source such as `lldpctl -f json` | not observable |
| Low ports/raw sockets/capture | unavailable unless separately enabled | explicit privileged capability missing |

Safe subprocess wrapper requirements:

- executable/argument arrays only—no shell interpolation;
- capability/version detection;
- timeout, output-size cap, cancellation/termination;
- captured exit code/stdout/stderr and locale/source metadata;
- parser fixture version;
- typed parse error rather than empty data.

### Optional future privileged helper

Only build after a phase-specific spike proves that raw ICMP/trace/LLDP value
cannot be obtained safely otherwise. The helper:

- is a separate minimal binary/process;
- communicates over an OS-ACL-protected named pipe/Unix socket;
- authenticates the invoking local user/process;
- exposes fixed typed operations with its own target/budget validation;
- cannot execute arbitrary commands, craft arbitrary payloads, serve WebUI, or
  access the database;
- drops privilege/capabilities whenever possible.

Never elevate the whole Mercury process.

## Persistence and Recovery

Use SQLite through stdlib `sqlite3`, explicit migrations, foreign keys enabled,
and one engine-owned connection.

```text
tasks(
  id, schema_version, origin_kind, origin_id, status,
  created_at, updated_at,
  request_json, authorization_json, policy_json, plan_json,
  result_json, error_code
)

task_events(
  task_id, seq, created_at, event_type, payload_json,
  PRIMARY KEY(task_id, seq)
)

peers(
  node_id PRIMARY KEY, cert_fingerprint, endpoint, policy_json,
  created_at, rotated_at, revoked_at
)

audit_events(
  id PRIMARY KEY, created_at, actor_json, decision,
  task_id, peer_id, policy_digest, detail_json
)

schema_migrations(version PRIMARY KEY, applied_at)
```

`result_json` is a self-contained versioned evidence result for easy export.
`task_events` remains normalized because cursor replay is a real query
requirement. Do not normalize every observation until comparison/query needs
justify it.

### Commit/publish rule

1. In one transaction, update task/result and insert next event sequence.
2. Commit.
3. Publish immutable event to bounded subscribers.

After a crash between commit and publish, an SSE reconnect replays the event.
After a crash before commit, it never appears as authoritative.

### Retention/privacy

- Bound tasks/events by age and count; compaction never removes an active task.
- Store raw payload only when necessary and size-limited; prefer hash/profile
  ID and normalized evidence.
- Store no plaintext invitation secret; retain only consumed/revoked audit
  metadata.
- Keep TLS private keys outside result/history DB with restrictive OS
  permissions.
- Central redactor handles public IPs, MACs, hostnames, tokens, peer endpoints,
  and payload content for exports.

## Key Data Flows

### Local CLI diagnosis

```text
CLI args
  → TaskRequest
  → application.submit
  → normalize/policy/plan preview
  → scheduler(TaskGroup + budgets)
  → observations/findings
  → SQLite events/result
  → human table or canonical JSON
```

### Web task and live progress

```text
Browser POST + CSRF
  → HTTP handler
  → run_coroutine_threadsafe(application.submit)
  → task ID

Browser EventSource(after seq)
  → replay committed task_events
  → subscribe bounded broker queue
  → SSE id/data frames
  → reconnect with Last-Event-ID on loss
```

### Authorized discovery

```text
interface/routes/neighbors
  → passive candidate facts
  → user selects explicit CIDR/hosts
  → normalize + scope grant + cost preview
  → bounded plan
  → global/per-target scheduler
  → evidence-backed host/service findings
```

### Paired directional test

```text
pair record + mTLS pin
  → hello/capability intersection
  → prepare listener under receiver policy
  → ready with per-attempt secret/nonce
  → TCP or UDP data-plane attempt
  → sender + receiver observations
  → reverse roles and repeat
  → correlate by task/attempt IDs
  → directional matrix with uncertainty
```

## Scaling Considerations

Mercury is local-first; “users” are not the useful scale axis.

| Scale | Architecture adjustment |
|-------|-------------------------|
| One operator, tens of targets | One process, one SQLite DB, modest worker pool, SSE, in-memory active state |
| Site diagnostics, hundreds/thousands of planned attempts | Hierarchical rate limits, adaptive ordering, aggregate events, retention/compaction; still one process |
| Repeated large subnet/full-port work | Require explicit advanced policy, shard into bounded plan revisions, checkpoint/cancel; do not raise absolute safety ceilings casually |
| Fleet/multi-user coordination | Separate future product/phase with central identity, tenancy, scheduler, and relay threat model; not v1 |

### Likely bottlenecks

1. **Sockets/ephemeral ports/link/IDS limits**, not CPU. Bound concurrency and
   rate; close promptly; avoid retry storms.
2. **Event/result volume.** Aggregate progress and store observations, not raw
   packet telemetry.
3. **Platform subprocess latency/parsing.** Cache capability/version checks and
   run independent adapters concurrently within budget.
4. **SQLite writes** only after aggregation grows; add a store worker/WAL after
   measurement, not preemptively.

## Anti-Patterns to Avoid

### Frontends that execute probes

**Problem:** CLI and Web handlers grow separate socket/command paths.  
**Consequence:** Different semantics and missing policy in one path.  
**Instead:** Both call `Application`; handlers only parse/project.

### Generic remote scan RPC

**Problem:** `scan(host, ports, payload)` trusts the peer caller.  
**Consequence:** Internal scan oracle, reflection, SSRF-like pivot.  
**Instead:** allowlisted built-in profiles, per-peer policy, receiver-side
planning/budgets, prepared paired endpoints only.

### IP address as peer identity

**Problem:** trust is tied to source/control IP or bearer token alone.  
**Consequence:** NAT churn, spoofing, token reuse, confused deputy.  
**Instead:** mTLS certificate pin + peer record + explicit policy.

### Whole-process elevation

**Problem:** Web server/parsers/database run as root/Administrator.  
**Consequence:** large privilege-escalation surface.  
**Instead:** ordinary-user baseline; optional fixed-operation helper later.

### In-memory-only events

**Problem:** progress looks live but disappears on crash/reconnect.  
**Consequence:** irreproducible diagnosis and stuck task state.  
**Instead:** assign/persist sequence before SSE publish.

### Cross-node wall-clock latency

**Problem:** subtract timestamps from unsynchronized hosts.  
**Consequence:** false one-way latency.  
**Instead:** local monotonic durations; correlate IDs; report clock uncertainty.

### Dynamic probe/plugin loading in v1

**Problem:** arbitrary code/payload extensions are exposed early.  
**Consequence:** supply-chain and dual-use expansion.  
**Instead:** compiled-in registry with stable descriptors and tests.

### `http.server` exposed as the peer daemon

**Problem:** a basic local server is treated as hardened remote infrastructure.  
**Consequence:** unnecessary HTTP attack surface.  
**Instead:** loopback-only WebUI; small bounded asyncio TLS peer protocol.

### Topology certainty from L3 facts

**Problem:** gateway/first hop/MAC vendor is displayed as access switch.  
**Consequence:** users troubleshoot the wrong device.  
**Instead:** evidence type + provenance + `unknown`.

## Integration Points

### External/system boundaries

| Boundary | Integration | Important constraints |
|----------|-------------|-----------------------|
| OS interfaces | `psutil` | Normalize optional fields; preserve source |
| Routes/neighbors/DNS/Wi-Fi | OS adapter/native structured output where possible | Locale/version fixtures, timeout, capability status |
| Ping/trace | Native command adapter | Permission/filtering uncertainty, no human-output regex in domain code |
| LLDP | Existing managed/daemon structured output | Capability-gated; lldpd does not support Windows |
| Browser | loopback HTTP + SSE | Host/Origin/CSRF/session/CSP; bounded streams |
| Peer | asyncio TLS + pinned client cert + bounded JSON frames | Version/replay/state/policy/budget checks |
| TCP/UDP data plane | temporary authenticated listeners | no amplification, expiry, receiver allowlist |
| SQLite | one engine-owned connection | transactions, foreign keys, migrations, retention |
| Reports | local files/stdout | central redaction and explicit raw-evidence opt-in |

### Internal boundaries

| Boundary | Communication | Contract |
|----------|---------------|----------|
| CLI/Web/peer → app | typed request/application calls | no network I/O in presentation |
| App → policy/planner | domain dataclasses | decision + immutable plan or stable rejection |
| Scheduler → probes | bounded `PlanStep` | cancellation/deadline/budget already attached |
| Probe/platform → classifier | normalized observations/capabilities | no presentation strings as truth |
| Engine → store | transaction methods | engine thread owns connection |
| Store → event broker | committed immutable event | sequence is replay cursor |
| Peer control → app | authenticated peer context + request | receiver policy applied exactly like local policy |

## Suggested Build Order

1. **Foundation and truth model**
   - versioned models, observation/finding semantics;
   - target normalization, policy, budgets, immutable plans;
   - task state/events, SQLite migrations, fake clock/socket;
   - classifier/policy tests for refusal/timeout/UDP silence/L2 unknown.
2. **Ordinary-user local engine and CLI**
   - capability inventory and three OS adapters;
   - DNS/TCP/UDP/TLS/HTTP probes;
   - bounded scheduler/cancellation;
   - human/JSON CLI using the application facade.
3. **Local API, streaming, and minimal WebUI**
   - dedicated engine runtime bridge;
   - loopback session/Origin/Host/CSRF controls;
   - persisted cursor + resumable SSE;
   - task preview/cancel/evidence UI.
4. **Peer identity and control security**
   - certificate provisioning assumptions and explicit pairing;
   - pinning/mTLS, versioned framing, replay/state checks;
   - per-peer policy and audit;
   - independent threat-model/security review gate.
5. **Directional peer data plane**
   - prepared authenticated TCP and UDP listeners;
   - sender/receiver correlation and reverse-role execution;
   - asymmetry, replay, spoof, expiry, amplification, and bind-failure tests.
6. **Discovery, routing, and topology evidence**
   - passive candidates, authorized bounded scan;
   - repeated trace profiles and path uncertainty;
   - neighbor/Wi-Fi/optional LLDP with direct/inferred/unknown labels.
7. **History, reports, and release hardening**
   - comparison/redaction/retention;
   - controlled netns/netem/firewall E2E;
   - Windows/macOS smoke, clean-machine packaging.
8. **Advanced matrix only after telemetry proves need**
   - explicit preview/second confirmation;
   - finite versioned payload profiles and immutable absolute ceilings.

### Ordering rationale

Policy and evidence semantics precede I/O so every later entry point inherits
them. Local probes precede peer work so the data plane reuses proven executors
and classifiers. Peer identity/control precedes listener code so no
unauthenticated echo service ships. Discovery/routing follows the same bounded
scheduler. Advanced scanning remains last because it multiplies every safety
and semantic risk.

## Verification Architecture

| Layer | Required tests |
|-------|----------------|
| Models/classifiers | Table-driven round-trip/version and all evidence combinations |
| Policy/planner | IPv4/IPv6/mapped/scope/DNS rebinding, cost overflow, absolute ceilings |
| Scheduler | fake time, cancellation, no post-cancel admission, queue/rate bounds |
| Platform adapters | golden fixtures for Windows/Linux/macOS success/missing/locale/error |
| Store/events | migrations, state transitions, commit-before-publish, SSE replay/gap/backpressure |
| Local API | loopback bind, Host/Origin/CSRF/session, limits, no direct probe path |
| Peer control | wrong/untrusted/rotated cert, expired invitation, replay, bad version/state, oversized frame, peer budget escalation |
| Peer data plane | TCP success/refusal/timeout; UDP arrival/reply/ICMP/silence; spoofed HMAC; amplification bound; reverse asymmetry |
| Network lab | netns/netem loss/delay/duplicate, firewall reject/drop, DNS interception, asymmetric rules |
| Native CI | Windows/macOS unprivileged capability smoke and packaging |

No test suite should require broad public scanning.

## Confidence Assessment and Research Flags

| Area | Confidence | Basis / next validation |
|------|------------|-------------------------|
| Modular monolith/shared engine | HIGH | Strong dependency fit and direct requirement |
| Evidence/policy/plan boundaries | HIGH | Required by UDP/L2 ambiguity and dual-use safety |
| Capability adapters | HIGH | Cross-platform facts/privileges demonstrably differ |
| SQLite event/result store | HIGH | Local scale and stdlib support; schema remains small |
| Loopback HTTP + SSE | MEDIUM-HIGH | Standard browser/Python primitives; spike backpressure/reconnect |
| Dedicated asyncio engine thread | MEDIUM | Official thread-safe submission exists; integration spike required |
| Manual cert-pinned pairing/mTLS | MEDIUM | Standard primitives, but provisioning/rotation UX needs threat review |
| Custom bounded JSON control framing | MEDIUM | Small surface, but requires protocol fuzz/state/replay testing |
| Temporary peer listeners across NAT/firewalls | MEDIUM | Technically sound on reachable hosts; real two-machine validation needed |
| L2 switch identification | HIGH confidence in limitation | Only direct advertisement/managed evidence should support a claim |
| Optional privileged helper | LOW until needed | Defer and research per OS before designing |

### Phase-specific research flags

- **Peer phase:** threat model, certificate renewal/revocation, pairing
  usability, TLS packaging, NAT/interface selection.
- **Platform inventory/routing:** verify structured APIs/tools and locale
  behavior on each OS.
- **Web runtime:** measure thread/SSE/SQLite behavior under cancellation and
  reconnect.
- **Packaging:** test wheel first; frozen artifacts only after stable behavior.
- **Privileged capability:** separate research before any helper/raw socket.

## Sources

All sources accessed 2026-07-30.

### Python/runtime (HIGH confidence, official)

- Python 3.13 `asyncio` tasks, cancellation, `TaskGroup`, and
  `run_coroutine_threadsafe()`:
  https://docs.python.org/3.13/library/asyncio-task.html
- Python `http.server` and its “basic security checks” warning:
  https://docs.python.org/3.13/library/http.server.html
- Python TLS contexts, certificate verification, and protocol versions:
  https://docs.python.org/3.13/library/ssl.html
- Python `sqlite3`, transactions, thread behavior, and `check_same_thread`:
  https://docs.python.org/3.13/library/sqlite3.html
- Python IP address/network parsing:
  https://docs.python.org/3.13/library/ipaddress.html
- Python cryptographically strong tokens:
  https://docs.python.org/3.13/library/secrets.html
- Python packaged resource access:
  https://docs.python.org/3.13/library/importlib.resources.html

### Protocol/security/browser (HIGH confidence, official/standards)

- IETF RFC 8446, TLS 1.3—client authentication and 0-RTT replay concerns:
  https://www.rfc-editor.org/rfc/rfc8446.html
- IETF RFC 8085, UDP usage guidelines—aggregate congestion control, ICMP, and
  middlebox considerations:
  https://www.rfc-editor.org/rfc/rfc8085.html
- MDN, server-sent events/EventSource:
  https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events/Using_server-sent_events
- OWASP CSRF Prevention Cheat Sheet—Origin/custom-header/SameSite defenses:
  https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- OWASP SSRF Prevention Cheat Sheet—IP validation, allowlists, and DNS pinning:
  https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- SQLite foreign-key enforcement:
  https://www.sqlite.org/foreignkeys.html

### Network semantics/topology (HIGH/MEDIUM as noted)

- Nmap UDP scan response/state semantics, including `open|filtered` for silence:
  https://nmap.org/book/scan-methods-udp-scan.html
- IETF RFC 826, ARP maps protocol addresses to local-network/Ethernet
  addresses:
  https://www.rfc-editor.org/rfc/rfc826.html
- IETF RFC 4861, IPv6 Neighbor Discovery finds on-link neighbors and routers:
  https://www.rfc-editor.org/rfc/rfc4861.html
- lldpd README—LLDP delivers link-layer notifications to adjacent equipment,
  supported OSes, and current lack of Windows support:
  https://github.com/lldpd/lldpd/blob/master/README.md
- Linux network namespaces:
  https://man7.org/linux/man-pages/man7/network_namespaces.7.html
- Linux `tc-netem` controlled impairment:
  https://man7.org/linux/man-pages/man8/tc-netem.8.html

### Reference pattern

- Ponytail's canonical-core/thin-adapter description at the inspected commit:
  https://github.com/DietrichGebert/ponytail/blob/16f29800fd2681bdf24f3eb4ccffe38be3baec6b/docs/agent-portability.md

---
*Architecture research for Mercury*  
*Researched: 2026-07-30*
