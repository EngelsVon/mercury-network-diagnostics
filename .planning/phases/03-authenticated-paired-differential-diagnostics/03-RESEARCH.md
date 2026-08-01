# Phase 3: Authenticated Paired Differential Diagnostics - Research

**Researched:** 2026-08-01  
**Domain:** bounded peer-to-peer diagnostic control and differential evidence  
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01:** Pairing is operator-provisioned file configuration, not an in-band enrollment flow. Each endpoint is configured with its own certificate/key, CA file containing the allowed peer client certificate(s), expected peer certificate SHA-256 pin(s), a distinct shared control token, and a fixed peer identity/address set. Secrets and private-key material are accepted only as paths, never written to task history, JSON output, audit records, or errors.
- **D-02:** A non-loopback peer listener must require TLS, a server certificate/key, client-certificate verification, pin match, and token. The only relaxation is an explicit `--unsafe-development` loopback-only path that records a high-visibility audited capability/evidence warning. There is no implicit fallback to cleartext, token-only, or server-only TLS.
- **D-03:** Use a compact versioned length-prefixed JSON control frame with a strict known-field decoder, maximum frame size, maximum nesting/string limits, correlation ID, peer identity, issued/expiry timestamps, and a random nonce. Reject malformed/unknown-version/oversized frames before dispatch. Maintain a bounded, expiring per-peer nonce cache and reject a replay without re-running work.
- **D-04:** Control operations are limited to capability negotiation, submit an immutable paired plan, read the correlated bounded result, and cancel the caller's own correlated request. The receiver recompiles/revalidates its received plan and local scope/budgets at admission; it never trusts remote cost, DNS, authorization, or result claims.
- **D-05:** A paired request may address only the configured mutually paired endpoint identity and its explicit configured addresses/ports. Reverse work is source-bound to the authenticated peer configuration plus the plan's endpoint declaration; no request may nominate a third-party host, CIDR, hostname resolution result, listener port, or payload.
- **D-06:** Keep the v1 profile finite and built in: one bounded TCP listener and one nonce-tagged UDP echo listener with short expiries and hard byte/frame limits. The UDP datagram carries a version, plan ID, nonce and fixed-size opaque tag; it produces distinct sent, peer-arrived, peer-replied and received observations. Missing any arrival/reply stays `silent` or `inconclusive`, never becomes an asserted packet loss or firewall cause.
- **D-07:** Listener lifetimes are bound to the immutable plan's expiry and cancellation; they bind only their configured peer-safe address and selected finite ports. TCP acceptance checks the negotiated plan/correlation before application evidence is emitted. Existing canonical `TaskContext.admit()` and plan reservations remain the sole active-I/O accounting gate.
- **D-08:** Each endpoint collects a passive snapshot and executes the same bounded DNS, peer-path, TCP, UDP, and allowlisted TLS/HTTP layers when those steps are included. Local native-tool capability differences remain local typed evidence, not peer failures.
- **D-09:** The paired result is one versioned canonical task document with endpoint-labelled evidence and a fixed A→B/B→A layer matrix. Explanations cite source observations and use only bounded language: for example, `A→B TCP refused while B→A connected`; they may name plausible alternatives but do not diagnose a firewall, route, or switch without direct evidence.
- **D-10:** Add `mercury agent` for controlled listener lifecycle and `mercury paired` for submission/projection. CLI remains parsing/rendering only and uses shared application services. Human output leads with the directional matrix; `--json` remains the complete authoritative document and preserves the established healthy/failed/partial exit semantics.
- **D-11:** Tests use repository-owned ephemeral test CA/certificates, loopback peers, injected clocks/transports, and explicitly controlled listener fixtures. They cover non-loopback startup denial, mTLS/pin/token failure, replay, malformed/oversized frames, expired or escalated plans, third-party target rejection, TCP connect/refusal/timeout, UDP reply/silent, DNS differences, and directional asymmetry. Tests never contact public or unowned targets.
- **D-12:** The user-authorized Ubuntu SSH host may be used only after the controlled tests pass, for an opt-in two-machine smoke against its explicitly configured address. Certificates/tokens are created with restrictive remote permissions, output is sanitized before being copied into planning evidence, and temporary remote test files are removed after the test.

### the agent's Discretion

The planner may choose concrete module names, exact bounded frame and payload sizes, CA fixture generation mechanics, certificate subject names, default plan TTL, local audit representation, and concise human wording. It must use the standard library plus `psutil`, favor `ssl`/`asyncio`, and preserve the existing evidence, scope, budget, persistence, and presentation boundaries.

### Deferred Ideas (OUT OF SCOPE)

- Human-verifiable short-code certificate enrollment remains v2 (PAIR-01).
- Passive discovery, topology/LLDP and repeated route analysis remain Phase 4.
- Web dashboard, history comparison/export, packaging hardening and broad lab coverage remain Phase 5.
- Fleet management, arbitrary remote APIs, custom peer payloads, generic proxy support and a central coordinator remain out of the Phase 3 scope.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|---|---|---|
| SAFE-05 | Non-loopback agent startup requires TLS certificate/key, trusted client certificate, and access token; only audited unsafe development may relax mTLS. | Two explicit `ssl.SSLContext` constructors, start-time configuration validation, and a loopback-only override. [VERIFIED: .planning/REQUIREMENTS.md; Context7 /python/cpython ssl] |
| PEER-01 | Version/capability/audit agent; mTLS, certificate pins, rotating bearer token; no secret in URL/result/history/log. | Strict framed control protocol, post-handshake SHA-256 pin comparison, token redaction boundary. [VERIFIED: .planning/REQUIREMENTS.md; src/mercury/tasks.py] |
| PEER-02 | One bounded-plan temporary TCP/UDP test listener and explicit port status. | Lease listeners to accepted plan expiry/cancellation and produce typed listener-status observations. [VERIFIED: .planning/REQUIREMENTS.md; 03-CONTEXT.md] |
| PEER-03 | Verify peer/capabilities, negotiate fixed role-swapped layers, compare endpoint evidence. | Use local recompilation/revalidation, then one shared application service orchestrates both endpoint results. [VERIFIED: .planning/REQUIREMENTS.md; src/mercury/app.py; src/mercury/planner.py] |
| PEER-04 | Show A→B/B→A send/arrival/reply/receive evidence and a linked layer matrix. | Extend the canonical model with endpoint/correlation fields and derive matrix rows only from cited observations. [VERIFIED: .planning/REQUIREMENTS.md; src/mercury/models.py] |
| PEER-05 | Reverse TCP only to source IP of current authenticated control connection; no third-party target. | Bind reverse destination to TLS peer socket address plus configured peer address and declared endpoint; ignore any target supplied by a frame. [VERIFIED: .planning/REQUIREMENTS.md; 03-CONTEXT.md] |
| PEER-06 | Finite built-in UDP or <=1400-byte explicit payload, independent confirmation and budgets; no “all packet kinds” claim. | Reuse `PayloadMetadata`, `ProbePlan`, `TaskContext.admit()` and `account_io()`; do not add a payload DSL. [VERIFIED: .planning/REQUIREMENTS.md; src/mercury/planner.py; src/mercury/tasks.py] |
</phase_requirements>

## Summary

Implement peer mode as a narrow control/data-plane addition behind `MercuryApplication`: authenticated TLS streams admit four control operations, while existing plan compilation, `TaskContext.admit()`, accounting, cancellation, persistence, and rendering remain the only execution/presentation paths. This preserves Phase 1/2 trust boundaries instead of creating a remote probe engine. [VERIFIED: src/mercury/app.py; src/mercury/planner.py; src/mercury/tasks.py; 03-CONTEXT.md]

Use CPython 3.13 standard-library `asyncio` streams and `ssl`; no runtime package should be added. `asyncio.start_server` accepts an SSL context and a bounded reader limit, `StreamReader.readexactly()` detects truncated frames, and datagram endpoints support the finite UDP echo role. [CITED: https://docs.python.org/3/library/asyncio-stream.html; Context7 /python/cpython asyncio streams/protocols] The installed runtime is CPython 3.13.5 and the project permits only `psutil>=7,<8`, currently 7.0.0. [VERIFIED: pyproject.toml; local `python --version`; local `pip show psutil`]

**Primary recommendation:** Build three small vertical slices in roadmap order: mTLS/token framed control and replay/audit; expiring source-bound TCP/UDP listeners; then paired orchestration, canonical matrix, CLI projections, and controlled tests. [VERIFIED: .planning/ROADMAP.md]

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|---|---|---|---|
| Peer listener admission, mTLS, pin and token validation | API / Backend | — | It is a network trust boundary and must reject before dispatch. [VERIFIED: AGENTS.md; 03-CONTEXT.md] |
| Strict control framing/replay/correlation/audit | API / Backend | Database / Storage | Live replay state is bounded memory; sanitized audit/result metadata is persisted through existing history. [VERIFIED: 03-CONTEXT.md; src/mercury/tasks.py] |
| Scope, budget, DNS recheck and active-I/O admission | API / Backend | — | Existing `ProbePlan`/`TaskContext` are the canonical policy and accounting gate. [VERIFIED: src/mercury/planner.py; src/mercury/tasks.py] |
| Temporary TCP/UDP test listeners and reverse source binding | API / Backend | — | Socket peer address and plan lease are server-side authority; presentation must not probe. [VERIFIED: AGENTS.md; 03-CONTEXT.md] |
| Paired matrix, JSON and human CLI projection | CLI / Presentation | API / Backend | The service returns canonical evidence; CLI only parses/renders it. [VERIFIED: AGENTS.md; src/mercury/cli.py; src/mercury/render.py] |

## Project Constraints (from AGENTS.md)

- Use CPython 3.11+ (develop/test on 3.13), standard library plus only `psutil`; use `unittest` and controlled owned-network tests. [VERIFIED: AGENTS.md]
- Do not add frameworks, ORM, broker, plugin SDK, custom crypto, or speculative abstraction; apply the Ponytail ladder and make the smallest correct implementation. [VERIFIED: AGENTS.md]
- Non-loopback listeners require TLS/token; peer agents additionally require trusted client certificate (mTLS). Active work must pass canonical scope policy and immutable aggregate ceilings. [VERIFIED: AGENTS.md]
- Preserve TCP refusal, timeout, UDP reply, ICMP unreachable, silent, unsupported, permission denied and error as distinct evidence; silence is never success/failure. [VERIFIED: AGENTS.md; src/mercury/models.py]
- CLI and future WebUI call the same services and never probe from presentation code. [VERIFIED: AGENTS.md]

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---|---|---|---|
| CPython `asyncio` | 3.13.5 available | TLS streams, deadlines, TCP/UDP listener lifecycle. | It supplies `start_server`, `readexactly`, task cancellation, and datagram endpoints without a dependency. [VERIFIED: local `python --version`; CITED: https://docs.python.org/3/library/asyncio-stream.html; Context7 /python/cpython] |
| CPython `ssl` + `hashlib` + `hmac` | 3.13.5 available | mTLS, CA validation, SHA-256 certificate pins, constant-time token/pin comparison. | `PROTOCOL_TLS_CLIENT`/`SERVER`, `CERT_REQUIRED`, `load_cert_chain`, and `load_verify_locations` match the required trust model. [CITED: https://docs.python.org/3/library/ssl.html; Context7 /python/cpython ssl] |
| CPython `json`, `struct`, `secrets`, `datetime` | 3.13.5 available | Versioned bounded frames, nonce generation, timestamp/expiry decoding. | These cover the locked compact control format; add no serialization or protocol package. [VERIFIED: 03-CONTEXT.md; ASSUMED] |

### Supporting

| Library | Version | Purpose | When to Use |
|---|---|---|---|
| Existing `ProbePlan` / `TaskContext` / `TaskService` | repository current | Immutable revalidation, reservations, cancellation, event/output ceilings, history. | Every active data-plane action, including a listener-side response, must be admitted here. [VERIFIED: src/mercury/planner.py; src/mercury/tasks.py] |
| Existing `MercuryApplication` | repository current | Presentation-independent composition/injection seam. | Add paired service methods and inject clocks/transports in tests. [VERIFIED: src/mercury/app.py; 03-CONTEXT.md] |
| `psutil` | 7.0.0 installed; `>=7,<8` declared | Existing local snapshot support. | Reuse through Phase 2 collection; peer mode adds no psutil-specific code. [VERIFIED: pyproject.toml; local `pip show psutil`; src/mercury/inventory.py] |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|---|---|---|
| `asyncio`/`ssl` streams | HTTP/gRPC/WebSocket peer API | Violates the one-runtime-dependency/minimalism constraint and broadens the remote API surface. [VERIFIED: AGENTS.md; 03-CONTEXT.md] |
| Versioned fixed JSON frames | Generic RPC/schema framework | Adds a framework and forward-compatible dispatch surface where D-03 requires strict known fields. [VERIFIED: AGENTS.md; 03-CONTEXT.md] |
| Static repository-owned test PEM fixtures | Runtime certificate generation dependency | Production needs operator paths; tests must run without undeclared runtime tooling. [VERIFIED: tests/fixtures/tls/README.md; pyproject.toml] |

**Installation:** No Phase 3 runtime installation. Keep `psutil>=7,<8` unchanged. [VERIFIED: pyproject.toml]

**Version verification:** CPython 3.13.5 and psutil 7.0.0 were verified locally on 2026-08-01. [VERIFIED: local environment]

## Architecture Patterns

### System Architecture Diagram

```text
`mercury paired` / `mercury agent`
        | parsing + projection only
        v
MercuryApplication paired service
        |                         \
        | local compile/revalidate  \  TLS stream: fixed peer address only
        v                             v
ProbePlan + ScopeGrant + TaskService  PeerAgent control listener
        |                              | mTLS CA validation -> SHA-256 pin -> token
        |                              | frame bounds/version/expiry/nonce replay check
        |                              v
        |                       independently compile/revalidate local plan
        |                              |
        +-- role A→B / B→A -----------+-- expiring TCP + nonce UDP listeners
        |                              |
        v                              v
TaskContext.admit -> bounded evidence -> canonical endpoint-labelled TaskResult
                                             |
                                             v
                                  paired matrix + cited, bounded conclusions
```

The request can enter only through the paired service; the remote peer receives a finite plan and never a free-form destination or payload. [VERIFIED: 03-CONTEXT.md]

### Recommended Project Structure

```text
src/mercury/
├── peer.py          # peer config, SSL contexts, strict frames, replay cache, agent lifecycle
├── paired.py        # pair-only plan validation, listener leases, role-swapped orchestration/matrix
├── app.py           # thin paired service composition/injection additions
├── cli.py           # `agent` and `paired` parser/dispatch only
├── render.py        # evidence-linked directional matrix projection only
└── models.py        # conservative canonical paired metadata/evidence additions
tests/
├── test_peer.py     # control security, frame, replay, secret-redaction unit tests
└── test_paired.py   # loopback data-plane, matrix and controlled asymmetry integration tests
```

Keep this as two focused modules, not a generic transport framework. [ASSUMED]

### Pattern 1: Construct contexts by role, then pin after handshake

**What:** Build a server context with a certificate chain, CA trust store and `CERT_REQUIRED`; build a client context with its own certificate chain and CA trust store. After the successful TLS handshake, obtain the binary peer certificate, SHA-256 it, and compare only to configured pins before accepting a control frame. [CITED: https://docs.python.org/3/library/ssl.html; Context7 /python/cpython ssl]

**When to use:** Every non-loopback peer connection; the audited unsafe development branch remains loopback only. [VERIFIED: 03-CONTEXT.md]

**Example:**

```python
# Sources: Python ssl docs; Context7 /python/cpython ssl
server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
server.load_cert_chain(config.certificate_path, config.private_key_path)
server.load_verify_locations(cafile=config.peer_ca_path)
server.verify_mode = ssl.CERT_REQUIRED

reader, writer = await asyncio.open_connection(
    config.peer_host, config.control_port, ssl=client_context,
    server_hostname=config.peer_server_name,
)
ssl_object = writer.get_extra_info("ssl_object")
peer_der = ssl_object.getpeercert(binary_form=True)
if not hmac.compare_digest(hashlib.sha256(peer_der).hexdigest(), config.expected_pin):
    raise PeerAuthenticationError("configured peer certificate pin did not match")
```

Do not serialize `config`, the token, or DER certificate into an observation/error; record only a categorical authentication outcome and a configured peer identity. [VERIFIED: 03-CONTEXT.md; src/mercury/tasks.py]

### Pattern 2: Reject a frame before its body is read or dispatched

**What:** Read a fixed 4-byte unsigned-big-endian length, reject zero or over-limit lengths, then use `readexactly(length)` under the operation deadline. Decode UTF-8/JSON strictly: reject duplicate keys, non-object root, unknown/missing fields, unacceptable types, unknown protocol version, excessive nesting/string fields, non-finite numeric values, expired timestamps, and correlation/identity mismatch. [CITED: https://docs.python.org/3/library/asyncio-stream.html; VERIFIED: 03-CONTEXT.md; src/mercury/models.py]

**When to use:** Negotiation, submission, read-result, and cancellation; no operation bypasses this decoder. [VERIFIED: 03-CONTEXT.md]

**Anti-patterns to avoid:**

- **`reader.read()` then parse:** permits an unbounded allocation/read; use validated length plus `readexactly`. [CITED: https://docs.python.org/3/library/asyncio-stream.html]
- **Permissive `dict.get()` decoding or ignored fields:** turns future/unrecognized input into implicit capability; enumerate fields and reject extras. [VERIFIED: 03-CONTEXT.md; ASSUMED]
- **Evicting a live nonce merely to make room:** may allow a replay during its validity window; reject new control admission while the bounded cache is full, after removing only expired entries. [ASSUMED]

### Pattern 3: Data-plane roles are derived, never supplied by the peer

**What:** The negotiated plan declares its own paired endpoint identities, finite listener ports and expiry. For reverse TCP/UDP, obtain the current TLS connection `peername`, compare it with the authenticated configuration and plan endpoint, and use that exact address/selected port; do not use a `target`, CIDR, hostname result, listener port or arbitrary payload from the control frame. [VERIFIED: 03-CONTEXT.md; src/mercury/policy.py]

**When to use:** All A→B/B→A probes and temporary listener setup. TCP acceptance first checks plan ID/correlation/lease; UDP validates fixed fields and opaque tag before emitting arrival/reply evidence. [VERIFIED: 03-CONTEXT.md]

### Pattern 4: Matrix is a pure projection of canonical evidence

**What:** Store endpoint label, correlation ID, layer/probe, direction and phase (`sent`, `arrived`, `replied`, `received`) in canonical observations. Derive one fixed row per negotiated layer/direction, cite source observation IDs, and retain inconclusive UDP silence exactly as already modelled. [VERIFIED: src/mercury/models.py; 03-CONTEXT.md]

**Anti-patterns to avoid:**

- **Infer “firewall”, “packet loss”, route cause, or switch from a missing UDP phase:** record `silent`/`inconclusive` with alternatives and limitations. [VERIFIED: AGENTS.md; src/mercury/models.py]
- **Render from transient peer protocol data:** build the document from locally canonicalized TaskResults only. [VERIFIED: src/mercury/tasks.py; 03-CONTEXT.md]

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---|---|---|---|
| TLS/mTLS and certificate-chain validation | TLS parser, certificate verifier, custom encryption | `ssl.SSLContext`, CA files, `CERT_REQUIRED`, `load_cert_chain`, `load_verify_locations` | TLS/certificate validation is security-sensitive and the stdlib provides it. [CITED: https://docs.python.org/3/library/ssl.html] |
| Token/pin comparison | Equality check with bespoke timing mitigation | `hmac.compare_digest` | Standard-library constant-time comparison is appropriate for same-type secret values. [CITED: https://docs.python.org/3/library/hmac.html] |
| Task ceilings/cancellation/history | Peer-specific task runner or separate database | Existing `TaskService` and `TaskContext` | They already reserve steps, enforce output/event/accounting bounds, cancel, and sanitize persistence. [VERIFIED: src/mercury/tasks.py] |
| Plan authorization/resolution | “Remote approved” boolean or custom peer scope | Existing `ProbePlan`/`ScopeGrant` revalidation | Both endpoints must independently validate the immutable plan and current resolution. [VERIFIED: src/mercury/planner.py; src/mercury/policy.py] |
| UDP listener/event loop | Thread-per-port listener | `loop.create_datagram_endpoint` with one finite protocol | CPython supplies event-loop datagram lifecycle without a dependency. [CITED: https://docs.python.org/3/library/asyncio-protocol.html; Context7 /python/cpython] |

**Key insight:** Custom control framing is justified only because the locked v1 surface is four finite operations; all cryptography, task enforcement, and evidence lifecycle must reuse established implementations. [VERIFIED: 03-CONTEXT.md; AGENTS.md]

## Common Pitfalls

### Pitfall 1: Treating CA validation as the configured peer identity

**What goes wrong:** A valid chain alone can authenticate a certificate issued by the trusted CA but not necessarily the specifically configured agent. [CITED: https://docs.python.org/3/library/ssl.html; ASSUMED]

**How to avoid:** Require CA/client-certificate verification, hostname verification where configured, and exact SHA-256 pin match before token/frame processing. [VERIFIED: 03-CONTEXT.md; CITED: https://docs.python.org/3/library/ssl.html]

**Warning signs:** A peer with a valid CA-issued but unpinned certificate reaches capability negotiation. [ASSUMED]

### Pitfall 2: Validating only the sender's costing or DNS results

**What goes wrong:** The remote agent becomes a scan oracle or spends work outside its local grant. [VERIFIED: 03-CONTEXT.md]

**How to avoid:** Deserialize into a strict request, rebuild/revalidate the finite plan and local `ScopeGrant`, and admit each actual step through `TaskContext.admit()`. [VERIFIED: 03-CONTEXT.md; src/mercury/planner.py; src/mercury/tasks.py]

### Pitfall 3: Replay cache that is bounded but insecure

**What goes wrong:** An LRU eviction of a non-expired nonce lets a captured frame be replayed. [ASSUMED]

**How to avoid:** Prune only expired entries first; if the remaining per-peer cache reaches its hard bound, reject the request and audit a non-secret reason. [ASSUMED]

### Pitfall 4: Listener and task lifetime divergence

**What goes wrong:** A listener remains reachable after cancellation or plan expiry. [VERIFIED: 03-CONTEXT.md]

**How to avoid:** Create listener lease tasks under the task cancellation token and close transports/servers in `finally`; check expiry before accept/datagram reply. `asyncio.wait_for` cancels an awaitable when its timeout is reached. [CITED: https://docs.python.org/3/library/asyncio-task.html; VERIFIED: 03-CONTEXT.md]

### Pitfall 5: Test certificates generated during every test run

**What goes wrong:** The target workstation has no `openssl` executable, so such tests would silently add an undeclared external prerequisite. [VERIFIED: local environment; pyproject.toml]

**How to avoid:** Commit repository-owned, explicitly test-only CA/server/client PEM fixtures generated once in a controlled development environment; production configuration always uses operator paths. Existing fixtures presently document only a CA and server certificate/key, so mTLS client fixture material is a Wave 0 gap. [VERIFIED: tests/fixtures/tls/README.md]

## Code Examples

Verified patterns from official sources:

### Bounded stream frame read

```python
# Source: https://docs.python.org/3/library/asyncio-stream.html
header = await asyncio.wait_for(reader.readexactly(4), timeout=CONTROL_TIMEOUT_S)
size = struct.unpack("!I", header)[0]
if not 0 < size <= MAX_CONTROL_FRAME_BYTES:
    raise FrameError("frame size outside configured bound")
payload = await asyncio.wait_for(reader.readexactly(size), timeout=CONTROL_TIMEOUT_S)
```

`readexactly()` raises `IncompleteReadError` on premature EOF; convert it to a non-secret protocol rejection/audit event. [CITED: https://docs.python.org/3/library/asyncio-stream.html]

### Finite UDP echo listener

```python
# Source: https://docs.python.org/3/library/asyncio-protocol.html
transport, protocol = await asyncio.get_running_loop().create_datagram_endpoint(
    lambda: PairedUdpProtocol(lease=lease, authenticated_peer=peer_address),
    local_addr=(config.safe_bind_address, negotiated_udp_port),
)
try:
    await lease.wait_for_expiry_or_cancellation()
finally:
    transport.close()
```

`PairedUdpProtocol.datagram_received` must first reject unconfigured source, expired lease, wrong fixed length/version/plan/nonce/tag, then call the existing admission/accounting path before replying. [VERIFIED: 03-CONTEXT.md; src/mercury/tasks.py; ASSUMED]

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|---|---|---|---|
| A generic remote diagnostic/scan request | Pair-only operator-provisioned mTLS + pin + token with fixed roles | Locked for Phase 3 | No third-party target or arbitrary payload can enter peer control. [VERIFIED: 03-CONTEXT.md] |
| Separate command implementations | Shared application facade and canonical evidence | Phase 2 baseline | `agent`/`paired` extend service calls; CLI does not probe. [VERIFIED: src/mercury/app.py; src/mercury/cli.py] |
| “UDP no reply = failure” | `SILENT` as inconclusive and peer-arrival as direct evidence | Existing schema | Matrix preserves uncertainty rather than asserting cause. [VERIFIED: src/mercury/models.py] |

**Deprecated/outdated:** A token-only or server-only-TLS peer listener is prohibited by the locked Phase 3 trust model. [VERIFIED: 03-CONTEXT.md]

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|---|---|---|
| A1 | Rejecting when a per-peer replay cache is full (rather than evicting a live nonce) is the intended bounded-cache policy. | Architecture Patterns / Pitfalls | A different documented eviction policy could affect availability; live eviction risks replay acceptance. |
| A2 | Two focused peer modules (`peer.py`, `paired.py`) are sufficient without a protocol framework. | Recommended Project Structure | Module placement may need adjustment to existing naming patterns. |
| A3 | JSON decoding must explicitly reject duplicate keys/non-finite values in addition to locked known-field/bounds rules. | Architecture Patterns | A permissive decoder could make request canonicalization ambiguous. |

## Open Questions

1. **Exact frame, string, replay and default-lease limits**
   - What we know: D-03/D-06 require hard bounds and the planner has discretion over their numbers. [VERIFIED: 03-CONTEXT.md]
   - What's unclear: Exact values were not locked. [VERIFIED: 03-CONTEXT.md]
   - Recommendation: Choose values from the existing result/output ceilings, document them in one peer configuration dataclass, and test exact boundary acceptance/rejection. [ASSUMED]
2. **Test client certificate material**
   - What we know: Existing committed TLS fixtures contain test CA and server material; `openssl` is unavailable in this development environment. [VERIFIED: tests/fixtures/tls/README.md; local environment]
   - What's unclear: Whether the existing server certificate has client-auth EKU is not documented. [VERIFIED: tests/fixtures/tls/README.md]
   - Recommendation: Add explicitly test-only client cert/key PEM material signed by the fixture CA before writing mTLS integration tests. [ASSUMED]

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|---|---|---|---|---|
| CPython | Agent/control/listeners/tests | ✓ | 3.13.5 | — [VERIFIED: local environment] |
| `asyncio` / `ssl` | mTLS control + TCP/UDP | ✓ | CPython stdlib | — [VERIFIED: local CPython; CITED: https://docs.python.org/3/library/ssl.html] |
| `unittest` | controlled tests | ✓ | CPython stdlib | — [VERIFIED: local `python -m unittest --help`] |
| `openssl` CLI | optional one-time PEM fixture generation | ✗ | — | Generate/commit test-only fixtures from an authorized workstation; runtime has no CLI dependency. [VERIFIED: local environment; tests/fixtures/tls/README.md] |
| SSH | opt-in post-test two-machine smoke | ✓ | installed (version not queried safely) | Skip until explicit authorized host/run is requested. [VERIFIED: local command availability; 03-CONTEXT.md] |

**Missing dependencies with no runtime fallback:** None; OpenSSL is not a runtime dependency. [VERIFIED: pyproject.toml]

**Missing dependencies with fallback:** `openssl` CLI for fixture creation; committed test-only fixture material removes it from normal test execution. [VERIFIED: local environment; tests/fixtures/tls/README.md]

## Validation Architecture

### Test Framework

| Property | Value |
|---|---|
| Framework | `unittest` / `IsolatedAsyncioTestCase` (CPython 3.13.5) [VERIFIED: tests/test_phase2_smoke.py; local `python --version`] |
| Config file | none — discovery is CLI/default unittest behavior. [VERIFIED: repository file scan] |
| Quick run command | `python -m unittest tests.test_peer tests.test_paired -v` (Wave 0 files) |
| Full suite command | `python -m unittest discover -s tests -v` [VERIFIED: AGENTS.md] |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|---|---|---|---|---|
| SAFE-05 | Non-loopback denies absent cert/key/CA/token; unsafe mode only loopback and audits warning. | unit | `python -m unittest tests.test_peer.PeerStartupTests -v` | ❌ Wave 0 |
| PEER-01 | mTLS CA/pin/token/version/capability failures reject; secrets never persist. | unit + loopback integration | `python -m unittest tests.test_peer.ControlSecurityTests -v` | ❌ Wave 0 |
| PEER-02 | TCP/UDP lease exposes active/busy/expired/permission statuses and closes on cancel. | integration | `python -m unittest tests.test_paired.ListenerLeaseTests -v` | ❌ Wave 0 |
| PEER-03 | Pair negotiates immutable plan; receiver recompiles/rechecks scope/budget/expiry. | unit + integration | `python -m unittest tests.test_paired.PlanAdmissionTests -v` | ❌ Wave 0 |
| PEER-04 | A→B/B→A phase evidence produces cited fixed matrix; DNS/refusal/timeout/asymmetry remain typed. | integration | `python -m unittest tests.test_paired.MatrixTests -v` | ❌ Wave 0 |
| PEER-05 | Frame cannot nominate third-party and reverse destination equals authenticated source. | security integration | `python -m unittest tests.test_paired.SourceBindingTests -v` | ❌ Wave 0 |
| PEER-06 | Built-in/<=1400 payload gates, confirmation, packet/byte/rate ceiling, UDP reply/silent semantics. | unit + integration | `python -m unittest tests.test_paired.UdpProfileTests -v` | ❌ Wave 0 |

### Sampling Rate

- **Per task commit:** `python -m unittest tests.test_peer tests.test_paired -v` after Wave 0. [ASSUMED]
- **Per wave merge:** `python -m unittest discover -s tests -v`. [VERIFIED: AGENTS.md]
- **Phase gate:** Full suite green plus controlled loopback evidence for DNS difference, TCP refusal, TCP timeout/drop, UDP reply, UDP silence, and asymmetric direction. [VERIFIED: .planning/ROADMAP.md]

### Wave 0 Gaps

- [ ] `tests/test_peer.py` — strict decoder, mTLS/pin/token, replay/expiry and persistence-redaction tests.
- [ ] `tests/test_paired.py` — loopback finite TCP/UDP listener, source binding, role swap and matrix tests.
- [ ] `tests/fixtures/tls/peer-client-cert.pem` and `peer-client-key.pem` — repository-owned test-only mTLS client fixture (or equivalent static names).
- [ ] Injected wall/monotonic clock and stream/datagram seams in the new peer service — deterministic expiry/replay/silent tests.

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---|---|---|
| V2 Authentication | yes | mTLS CA validation + explicit SHA-256 certificate pin + independently compared bearer token. [VERIFIED: 03-CONTEXT.md; CITED: https://docs.python.org/3/library/ssl.html] |
| V3 Session Management | yes | Correlation ID, issuance/expiry, bounded per-peer nonce replay cache; no token in URL/history/log. [VERIFIED: 03-CONTEXT.md] |
| V4 Access Control | yes | Fixed configured peer identity/address and source-bound reverse target; independently recompiled local plan/scope/budget. [VERIFIED: 03-CONTEXT.md] |
| V5 Input Validation | yes | Strict known-field frame decoder, hard frame/string/nesting limits, payload limit, immutable plan validation. [VERIFIED: 03-CONTEXT.md; src/mercury/models.py; src/mercury/planner.py] |
| V6 Cryptography | yes | CPython `ssl`, `hashlib.sha256`, and `hmac.compare_digest`; no custom cryptography. [CITED: https://docs.python.org/3/library/ssl.html; https://docs.python.org/3/library/hmac.html; Context7 /python/cpython] |

### Known Threat Patterns for asyncio/ssl peer control

| Pattern | STRIDE | Standard Mitigation |
|---|---|---|
| Missing/invalid client certificate or wrong pin | Spoofing | `CERT_REQUIRED`, configured CA, post-handshake exact pin check, reject before control dispatch. [VERIFIED: 03-CONTEXT.md; CITED: https://docs.python.org/3/library/ssl.html] |
| Captured valid submit frame replay | Repudiation / Tampering | Per-peer nonce with expiry, bounded cache, audit rejection, no re-run. [VERIFIED: 03-CONTEXT.md] |
| Oversized/malformed control frame | Denial of service | Check fixed length before body read; reader limit, deadline, strict decoder. [CITED: https://docs.python.org/3/library/asyncio-stream.html; VERIFIED: 03-CONTEXT.md] |
| Remote request names third-party target/payload/port | Elevation of privilege | Derive destination/listeners from authenticated peer configuration and immutable plan; receiver revalidates locally. [VERIFIED: 03-CONTEXT.md] |
| Token/private key appears in evidence/history/error | Information disclosure | Paths only for configuration; categorical/sanitized audit fields and persistence safety checks. [VERIFIED: 03-CONTEXT.md; src/mercury/tasks.py] |

## Sources

### Primary (HIGH confidence)

- [Context7 `/python/cpython`](https://context7.com/python/cpython) — `ssl` TLS context/certificate setup; `asyncio.start_server`, `readexactly`, datagram endpoint and timeout behavior (queried 2026-08-01).
- [Python `ssl` documentation](https://docs.python.org/3/library/ssl.html) — TLS contexts, certificate chains, CA locations, verification and peer certificate access.
- [Python asyncio streams documentation](https://docs.python.org/3/library/asyncio-stream.html) — TLS servers, bounded stream reader and exact reads.
- [Python asyncio protocols documentation](https://docs.python.org/3/library/asyncio-protocol.html) — datagram endpoints/protocol lifecycle.
- [Python asyncio task documentation](https://docs.python.org/3/library/asyncio-task.html) — timeout cancellation behavior.
- [Mercury Phase 3 context](03-CONTEXT.md) — locked security/data-plane/product decisions.
- [Mercury source: planner/tasks/models/app](../../../src/mercury/) — existing canonical trust, accounting, evidence and facade boundaries.

### Secondary (MEDIUM confidence)

- [Python `hmac` documentation](https://docs.python.org/3/library/hmac.html) — standard constant-time comparison API.
- [OWASP ASVS project](https://owasp.org/www-project-application-security-verification-standard/) — category vocabulary used by repository security enforcement.

### Tertiary (LOW confidence)

- None. Design inferences are individually marked `[ASSUMED]` and listed above.

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH — locked stdlib/psutil constraints and current environment were verified.
- Architecture: HIGH — Phase 3 locked decisions map directly onto existing immutable plan/task/facade seams.
- Pitfalls: MEDIUM — critical project-specific hazards are locked/verified; replay cache full behavior is explicitly an assumption.

**Research date:** 2026-08-01  
**Valid until:** 2026-08-31 (stdlib/project architecture; recheck before dependency or CPython-version change).
