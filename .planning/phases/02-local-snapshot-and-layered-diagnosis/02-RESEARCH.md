# Phase 2: Local Snapshot and Layered Diagnosis - Research

**Researched:** 2026-07-30  
**Domain:** Cross-platform passive network inventory and bounded layered reachability diagnosis  
**Confidence:** HIGH for the repository integration and core probe design; MEDIUM-HIGH for untested Linux/macOS command fixtures and public endpoint durability

<user_constraints>
## User Constraints (from CONTEXT.md)

The three subsections below are copied verbatim from `02-CONTEXT.md`. [VERIFIED: `.planning/phases/02-local-snapshot-and-layered-diagnosis/02-CONTEXT.md`]

### Locked Decisions

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
  contract gains fields or evidence kinds, increment the compatible model
  schema minor version and preserve major-version compatibility.
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
  `china` uses the same layers with multiple commonly reachable
  mainland-China HTTPS targets. A profile must not enumerate hosts, ports, UDP
  payloads, or third-party networks.
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

### Deferred Ideas (OUT OF SCOPE)

- Pinned-mTLS/token peer control, reverse roles, UDP peer data plane, and
  directional A-to-B/B-to-A comparison are Phase 3.
- Passive subnet candidates, active bounded discovery, ARP/NDP, Wi-Fi AP,
  optional LLDP, and repeated/multi-mode route analysis are Phase 4.
- WebUI, history comparison, redacted report export, packaging matrix, and
  broad controlled-lab verification are Phase 5.
- Full TCP ranges, custom UDP payloads, and advanced finite matrices remain
  behind their later independent confirmation gates.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| INVT-01 | Show hostname, OS, Mercury/Python versions, collection time, and local capability/degradation reasons. | The passive snapshot contract, application facade, capability matrix, and host-fact observation design below provide the implementation seam. [VERIFIED: `.planning/REQUIREMENTS.md`] |
| INVT-02 | Show interface name/state, IPv4/IPv6 addresses and prefixes, MAC, MTU, and speed when available. | The `psutil.net_if_addrs()`/`net_if_stats()` mapping and missing-value rules below cover every field without fabrication. [CITED: https://github.com/giampaolo/psutil/blob/v7.2.2/docs/index.rst] |
| INVT-03 | Show default gateways, routes, and DNS servers, with explicit unavailable/error evidence when collection cannot be structured. | The Windows/Linux/macOS command and parser matrix below specifies normalized fields, provenance, and degradation states. [VERIFIED: `.planning/REQUIREMENTS.md`; CITED: platform sources in `## Sources`] |
| DIAG-01 | Run a basic diagnosis that separates local prerequisites, route, DNS, raw-IP TCP, TLS, and HTTPS evidence. | The sparse action plan, `basic-v1` profile, probe outcome table, and classifier below define the full flow. [VERIFIED: `.planning/REQUIREMENTS.md`] |
| DIAG-02 | Select a mainland-China profile or add exact `host:port` targets and a bounded timeout. | The `china-v1` profile and strict custom target grammar below are implementation-ready. [VERIFIED: `.planning/REQUIREMENTS.md`] |
| DIAG-03 | Each DNS/TCP/TLS/HTTP/native-ping probe reports layer, duration, attempt count, and error evidence. | Canonical action identities, service-bound metadata, monotonic timing, and protocol-specific evidence mapping below provide this contract. [VERIFIED: `src/mercury/models.py`, `src/mercury/tasks.py`] |
| DIAG-04 | Human and stable JSON projections share one result and exit healthy/partial/failed consistently. | The facade/result flow and deterministic health decision table below separate diagnostic health from task lifecycle. [VERIFIED: `src/mercury/cli.py`, `src/mercury/render.py`] |
</phase_requirements>

## Summary

Phase 2 should extend the Phase 1 foundation, not build a parallel diagnostics
path. Phase 1 already provides frozen observations/results, strict JSON,
hostname scope rechecks, immutable budgeted steps, authoritative evidence
binding, cancellation, and bounded SQLite persistence; its 115-test suite
passes on the current Windows/Python 3.13.5 environment with three
POSIX-only skips. [VERIFIED: `src/mercury/models.py`, `src/mercury/planner.py`,
`src/mercury/tasks.py`, `.planning/phases/01-evidence-and-safety-foundation/01-VERIFICATION.md`,
local `python -m unittest discover -s tests -v`]

The central planning change is to replace Phase 1's homogeneous
`targets × ports × transports` expansion with a finite sparse list of typed
actions. The current `ProbeStep` requires a port and TCP/UDP transport and
`TaskContext.record()` trusts the runner-supplied `Observation.probe`, so it
cannot honestly represent DNS, native ping, native path, or a passive local
snapshot. The action kind and all meaningful parameters must participate in
the step ID, plan digest, preview, policy check, cost, and service-bound
observation detail. [VERIFIED: `src/mercury/planner.py:216`,
`src/mercury/planner.py:608`, `src/mercury/tasks.py:535`]

Implement inventory as one passive collector returning canonical observations
and capabilities. `status` calls it through the new application facade and
returns a `TaskResult` with `Progress(0, 0, 0)` rather than inventing an active
port. `diagnose` reuses the same collector through a finite
`local_snapshot` action, then executes separately costed DNS, TCP, TLS, HTTP,
native-ping, and native-path actions through `TaskService`. [VERIFIED:
`Progress` permits total zero in `src/mercury/models.py`; RECOMMENDATION based
on D-01, D-03, D-05, and D-21]

**Primary recommendation:** add a small `MercuryApplication` facade, a
fixture-driven passive inventory/platform layer, a sparse canonical action
plan, bounded protocol/native runners, versioned `basic-v1`/`china-v1`
profiles, and one pure deterministic diagnosis classifier; leave CLI as
parsing and projection only.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|--------------|----------------|-----------|
| CLI grammar and human/JSON output | Presentation (`cli.py`, `render.py`) | Application facade | Presentation selects a projection and exit code but performs no I/O. [VERIFIED: D-01, `AGENTS.md`] |
| Status use case | Application facade | Passive inventory collector | The facade owns use-case orchestration and returns the public `TaskResult`. [VERIFIED: D-01, D-21] |
| Host/interface facts | Passive inventory collector | `psutil` | `psutil` owns cross-platform NIC facts; the collector normalizes missing values and provenance. [CITED: https://github.com/giampaolo/psutil/blob/v7.2.2/docs/index.rst] |
| Routes/default gateways/DNS configuration | OS adapter | Inventory collector | Windows, Linux, and macOS expose different native sources; the collector merges typed records without hiding source failure. [VERIFIED: D-06, D-09] |
| Profile/custom target expansion | Plan compiler | Scope policy | The compiler creates finite actions; policy authorizes their exact names, addresses, kinds, ports, and transports. [VERIFIED: `src/mercury/planner.py`, D-10] |
| DNS/TCP/TLS/HTTP execution | Probe runner | Task service | The runner performs one prepared action; the service owns admission, budgets, resolution recheck, evidence binding, and persistence. [VERIFIED: `src/mercury/tasks.py`] |
| Native ping/path execution | OS adapter | Probe runner | Command shape and parser are platform-specific; action identity, budget, and evidence semantics remain canonical. [VERIFIED: D-15] |
| Diagnostic health | Pure classifier | Application/CLI projection | Health is derived from observations and required actions, not from process/task lifecycle. [VERIFIED: D-17, current `_derive_conclusion()` behavior in `src/mercury/tasks.py`] |
| History | Existing SQLite store | Task service | Existing source-result persistence remains authoritative; no new result store is needed. [VERIFIED: `src/mercury/history.py`, Phase 1 verification] |

## Project Constraints (from AGENTS.md)

The directives below are actionable repository constraints and have the same
authority as the locked context. [VERIFIED: `AGENTS.md`]

- Read and keep `.planning/PROJECT.md`, `.planning/REQUIREMENTS.md`,
  `.planning/ROADMAP.md`, and `.planning/STATE.md` synchronized; execute phases
  in roadmap order and count a requirement complete only when behavior and
  tests pass.
- Apply Ponytail full mode at pinned v4.8.4/commit
  `16f29800fd2681bdf24f3eb4ccffe38be3baec6b`: existing repository, standard
  library, native platform, and installed dependency precede custom code.
- Do not add speculative abstractions, one-implementation factories,
  frameworks, frontend build systems, ORMs, brokers, plugin SDKs, or custom
  cryptography.
- Do not simplify away trust-boundary validation, authorization, hard scan
  budgets, error/data-loss handling, accessibility, or runnable checks.
- Keep CPython 3.11+ and standard library plus `psutil`; develop/test on the
  available Python 3.13 interpreter.
- Use semantic HTML/native JavaScript later; Phase 2 adds no WebUI or Node
  tooling.
- Preserve refusal, timeout, UDP response, ICMP unreachable, silence,
  unsupported, permission denied, and execution error as distinct semantics.
- Every conclusion retains evidence, direction, timing, provenance, and
  confidence; inference is never presented as fact.
- Never call a gateway, route hop, or ARP neighbor a switch; only direct
  LLDP/managed evidence can identify that infrastructure.
- All active work goes through canonical scope policy and immutable aggregate
  ceilings; do not claim kernel retransmission or exact on-wire accounting.
- Peer/listener security and arbitrary third-party scan prevention remain
  mandatory, although their implementation is deferred beyond Phase 2.
- CLI and future WebUI must call the same service functions; presentation code
  performs no network probes.
- Tests use `unittest` and controlled networks only; no public/unowned target is
  contacted by normal tests.

## Standard Stack

### Core

| Library/runtime | Version | Purpose | Why Standard |
|-----------------|---------|---------|--------------|
| CPython | `>=3.11`; local `3.13.5` | Runtime, dataclasses, asyncio, sockets, TLS, HTTP, subprocesses, platform/file parsing | Locked project runtime; Python 3.11 supplies `asyncio.timeout()` and the existing package already targets 3.11–3.13. [VERIFIED: `pyproject.toml`, local `python --version`; CITED: https://docs.python.org/3/library/asyncio-task.html#asyncio.timeout] |
| `psutil` | Keep declared `>=7.0,<8`; registry current `7.2.2` (published 2026-01-28); local `7.0.0` | Cross-platform interface addresses and statistics | `net_if_addrs()` returns multiple IPv4/IPv6/MAC records per NIC and `net_if_stats()` returns up state, speed, MTU, duplex, and flags. [VERIFIED: PyPI JSON and local import; CITED: https://github.com/giampaolo/psutil/blob/v7.2.2/docs/index.rst] |
| Existing Mercury core | model schema `1.0` before this phase; recommend `1.1` | Evidence/result codec, scope, plan, task service, budgets, cancellation, history | These trust and lifecycle boundaries passed independent Phase 1 verification and must be extended, not bypassed. [VERIFIED: `.planning/phases/01-evidence-and-safety-foundation/01-VERIFICATION.md`] |

### Supporting standard-library/native capabilities

| Capability | Version/policy | Purpose | When to Use |
|------------|----------------|---------|-------------|
| `socket`, `asyncio` | CPython stdlib | System DNS, concrete-address TCP, deadlines, bounded workers | All DNS/TCP/TLS actions; connect to `PreparedStep.address`, never re-resolve the logical hostname in the connector. [CITED: https://docs.python.org/3/library/socket.html#socket.getaddrinfo; VERIFIED: `src/mercury/tasks.py`] |
| `ssl` | CPython/OpenSSL bundled with runtime | Verified TLS with system trust and SNI/hostname checks | Use `ssl.create_default_context()`; distinguish certificate verification from generic handshake/local execution failures. [CITED: https://docs.python.org/3/library/ssl.html#ssl.create_default_context] |
| `http.client` | CPython stdlib | Standards-aware status/header parsing | Use a concrete-address connection helper, `HEAD /`, no redirects, no body requirement, bounded timeout, and the logical host for `Host`/SNI. [CITED: https://docs.python.org/3/library/http.client.html] |
| `ipaddress` | CPython stdlib | Address/prefix canonicalization and custom `host:port` validation | Reuse the existing target policy; strip an IPv6 scope only for prefix arithmetic and preserve it as separate identity data. [VERIFIED: `src/mercury/policy.py`] |
| `asyncio.create_subprocess_exec` | CPython stdlib | Argument-array native command execution | Platform inventory, ping, and path; read stdout/stderr incrementally under byte and time ceilings. [CITED: https://docs.python.org/3/library/asyncio-subprocess.html#asyncio.create_subprocess_exec] |
| Windows NetTCPIP/DnsClient PowerShell cmdlets | Windows PowerShell 5.1 baseline on this host | Structured active route, interface metric, and configured DNS records | Windows adapter only; emit selected scalar properties as UTF-8 JSON. [VERIFIED: local `Get-Command`; CITED: Microsoft sources below] |
| Linux `ip -j` plus `/etc/resolv.conf` | OS supplied | JSON routes and resolver-visible nameservers | Linux adapter; optionally enrich with valid JSON from `resolvectl status`, but never make systemd-resolved a requirement. [CITED: https://github.com/iproute2/iproute2/blob/main/man/man8/ip.8; https://man7.org/linux/man-pages/man5/resolv.conf.5.html] |
| macOS `route`, `netstat`, `scutil` | OS supplied | Default route, route table, and current DNS resolver blocks | macOS adapter with recorded text fixtures and numeric output flags. [CITED: Apple open-source man pages in `## Sources`] |
| Native `ping` / `tracert` / `traceroute` | Optional OS supplied | Context-only ICMP reply and bounded one-shot path evidence | Diagnose only; missing/permission/parse/timeout states remain explicit and never fail status. [VERIFIED: D-15] |

### Alternatives Considered

Locked decisions remove the need for a library comparison. [VERIFIED:
D-21, `AGENTS.md`]

| Instead of | Rejected addition | Tradeoff |
|------------|-------------------|----------|
| `socket.getaddrinfo` | `dnspython`/async resolver dependency | A custom resolver could expose server-level details, but it would not be the same system resolver path and violates the one-dependency lock. |
| `ssl` + `http.client` | `requests`, `httpx`, `aiohttp` | Easier convenience APIs do not justify a runtime dependency and can accidentally reconnect by hostname outside the prepared address. |
| Native route/DNS sources | `netifaces`, WMI wrappers, NetworkManager bindings | They add dependencies and still do not provide one uniform cross-platform route/DNS truth. |
| Native ping/path | Raw ICMP/traceroute engine | It adds privilege, packet, parser, and platform complexity explicitly excluded from v1. |

**Installation:**

```powershell
python -m pip install -e .
```

No Phase 2 runtime package should be added. [VERIFIED: `pyproject.toml`, D-21]

**Version verification:**

```powershell
python --version
python -c "import psutil; print(psutil.__version__)"
python -m pip index versions psutil
```

The registry returned `psutil 7.2.2`; its first release file is dated
2026-01-28, while this machine has 7.0.0. Keep the existing compatible range
and test the used API on the installed minimum-family version instead of
pinning merely because a newer patch exists. [VERIFIED: PyPI JSON, pip index,
local import]

## Architecture Patterns

### System Architecture Diagram

```text
mercury status ──────────────┐
                             v
                       MercuryApplication
                             |
                    passive inventory collector
                     /          |           \
             psutil facts   OS route/DNS   typed degradation
                     \          |           /
                      canonical observations
                             |
                  TaskResult Progress(0,0,0)
                             |
                    human / stable JSON

mercury diagnose
       |
 profile/custom parser ──> sparse action compiler
                              |
                 preview exact names/addresses/kinds/
                      ports/transports/costs
                              |
                authorized? ──no──> policy result
                              |
                             yes
                              v
                   existing TaskService admission
                              |
          ┌───────────┬───────┼───────┬────────────┐
          v           v       v       v            v
       system DNS    TCP     TLS     HTTP      native ping/path
          |           |       |       |            |
          └───────────┴───────┴───────┴────────────┘
                              |
                 service-bound observations
                              |
                pure diagnosis health classifier
                              |
                       one TaskResult
                              |
              human / JSON / exit 0,4,1
```

The two entry points share collectors, models, policy, runners, classifier, and
rendering; only `diagnose` enters active authorization/admission. [VERIFIED:
D-01, D-05, `AGENTS.md`]

### Recommended Project Structure

```text
src/mercury/
├── app.py                    # MercuryApplication.status()/diagnose()
├── inventory.py              # host/interface normalization; shared snapshot collector
├── platform/
│   ├── common.py             # bounded command result + direct sys.platform dispatch
│   ├── windows.py            # PowerShell JSON and ping/tracert fixtures
│   ├── linux.py              # ip JSON, resolv.conf, ping/traceroute fixtures
│   └── macos.py              # route/netstat/scutil and ping/traceroute fixtures
├── profiles.py               # frozen basic-v1/china-v1 definitions
├── probes.py                 # DNS/TCP/TLS/HTTP runners and errno mapping
├── diagnosis.py              # sparse action compilation + pure health classifier
├── models.py                 # add evidence kinds; retain canonical TaskResult
├── planner.py                # sparse ActionIdentity/ProbeStep and cost reservations
├── policy.py                 # exact action/name/address/port authorization
├── tasks.py                  # authoritative kind/detail binding and per-step ceilings
├── cli.py                    # argparse and facade dispatch only
└── render.py                 # status/diagnosis projections
tests/
├── fixtures/platform/{windows,linux,macos}/
├── fixtures/tls/             # test-only CA/server cert/key, never production credentials
├── test_inventory.py
├── test_platforms.py
├── test_profiles.py
├── test_probes.py
├── test_diagnosis.py
└── test_cli.py               # extend existing projection/exit tests
```

Use direct `sys.platform` selection among three concrete modules; do not add an
adapter base class, plugin registry, or dependency-injection container.
[VERIFIED: D-21, Ponytail ladder in `AGENTS.md`]

### Component Responsibilities

| Component | Owns | Must not own |
|-----------|------|--------------|
| `MercuryApplication` | Status/diagnose use-case orchestration and the returned canonical result | Parsing `argparse`, formatting output, or protocol I/O |
| Inventory collector | Host/interface facts, invoking one selected OS adapter, normalized observations/capabilities | Active ping/path, topology inference, or CLI wording |
| Platform modules | Fixed argv, parser, normalized route/DNS/ping/path records, bounded raw diagnostics | Policy, profile selection, health classification |
| Sparse plan compiler | Exact finite actions and per-action reservations | Dynamic work discovered during execution |
| `TaskService`/`TaskContext` | Authorization recheck, rate/concurrency/duration/event/output enforcement, authoritative metadata binding | “Internet” conclusions |
| Probe runner | Execute only an admitted prepared action and map direct outcomes to evidence | Resolve/connect to an address not supplied by admission |
| Classifier | Pure observations + required step metadata → one diagnosis conclusion | Network/file/subprocess I/O |
| CLI/render | Input grammar, same-result projections, stable exit mapping | Inventory, resolution, socket, SSL, HTTP, subprocess calls |

### Pattern 1: Sparse Canonical Action Identity

**What:** Replace the Phase 1 cross-product assumption with one frozen
descriptor per actual operation. Optional fields are validated by action kind;
`None` means “not applicable,” never a dummy zero/port. [VERIFIED: current
cross-product in `src/mercury/planner.py:613`; RECOMMENDATION required by D-03]

**Recommended shape:**

```python
from dataclasses import dataclass
from enum import StrEnum

class ActionKind(StrEnum):
    LOCAL_SNAPSHOT = "local_snapshot"
    SYSTEM_DNS = "system_dns"
    TCP_CONNECT = "tcp_connect"
    TLS_HANDSHAKE = "tls_handshake"
    HTTP_EXCHANGE = "http_exchange"
    NATIVE_PING = "native_ping"
    NATIVE_PATH = "native_path"

@dataclass(frozen=True, slots=True)
class ActionIdentity:
    kind: ActionKind
    target: str                   # logical/canonical target, or "local"
    address: str | None = None    # concrete admitted address when applicable
    port: int | None = None
    transport: str | None = None  # "tcp" only where it is a true wire layer
    server_name: str | None = None
    http_scheme: str | None = None
    max_hops: int | None = None

    def to_wire(self) -> dict[str, object]:
        return {
            "kind": self.kind.value,
            "target": self.target,
            "address": self.address,
            "port": self.port,
            "transport": self.transport,
            "server_name": self.server_name,
            "http_scheme": self.http_scheme,
            "max_hops": self.max_hops,
        }
```

Validation must enforce this matrix:

| Kind | Address | Port/transport | Extra identity |
|------|---------|----------------|----------------|
| `local_snapshot` | none | none | target exactly `local` |
| `system_dns` | none | none | canonical hostname only |
| `tcp_connect` | concrete | required / `tcp` | source hostname/resolution slot on the step |
| `tls_handshake` | concrete | required / `tcp` | `server_name` required |
| `http_exchange` | concrete | required / `tcp` | scheme `http` or `https`; server name/Host required |
| `native_ping` | concrete | none | no claimed transport |
| `native_path` | concrete | none | `max_hops` exactly 8 in built-in v1 |

Hash `identity.to_wire()`, attempt, resolution slot, required/optional role, and
cost to create `step-<sha256>`. Include the same wire object in the preview and
digest. `TaskContext.record()` must reject a runner-supplied `probe` that does
not equal the planned action kind and must bind `action_kind`, `plan_step_id`,
planned target/address, optional port/transport, and DNS-change state as
reserved detail. [VERIFIED: current service already binds step/target/port/
transport/DNS-change in `src/mercury/tasks.py`; RECOMMENDATION extends the same
trust boundary]

Add `action_kinds` to the exact scope grant (or an equivalent validated plan
envelope) so non-port actions are authorized without pretending to be TCP/UDP.
`permits_action()` checks kind first and port/transport only when semantically
present. [VERIFIED: D-03 and D-10; prescriptive research conclusion]

### Pattern 2: Per-Action Observation and Output Reservations

One action can legitimately produce several correlated observations; Phase 1
already tests that behavior, while its current estimate assumes roughly one
observation and 512 output bytes per step. A path action can produce up to
eight hop observations plus completion, so leaving the estimate unchanged
would undercost events/output. [VERIFIED: `tests/test_models.py`,
`src/mercury/planner.py:846`]

Extend `StepCost` with `max_observations` and `max_output_bytes`; sum these into
the plan estimates and enforce them per step inside `TaskContext.record()`.
Recommended reservations are one observation for DNS/TCP/TLS/HTTP/ping, a
small fixed number for the aggregated local snapshot, and nine for an
eight-hop path plus completion. Global Phase 1 event/output ceilings remain
the outer bound. [VERIFIED: SAFE-02 and D-14; prescriptive research conclusion]

### Pattern 3: Passive Snapshot as Canonical Evidence

`status` should not manufacture an active plan. The facade collects host,
interface, route, and DNS categories independently, converts each successful
category to `LOCAL_FACT` observations, converts each failure to typed
unavailable/error evidence plus a `Capability`, and returns one completed
`TaskResult` with zero progress. [VERIFIED: `Progress(0,0,0)` is valid in
`src/mercury/models.py`; RECOMMENDATION based on D-02 and D-05]

For `diagnose`, a real `local_snapshot` action calls the same collector and
binds its observations to the active task. This is reuse, not a second result
model. [VERIFIED: D-01 and D-21; prescriptive research conclusion]

Recommended fixed ceilings:

- at most 256 interface records, 4,096 route records, and 256 DNS server
  records;
- at most 1 MiB captured stdout+stderr per native invocation;
- at most 8 KiB of sanitized diagnostic text retained per command;
- final status result checked against the existing default 8 MiB output
  ceiling, with an explicit truncation/error observation if a record ceiling
  is reached.

These are planning constants, not claims about typical machine size.

### Pattern 4: Thin, Independently Failing Platform Sources

Each source returns `(records, capability, provenance)` and never an empty list
that looks like success. Addresses/stats, routes, and DNS are collected in
separate `try` blocks so one source failure cannot erase the others.
[VERIFIED: D-02, D-06]

Use a shared bounded subprocess result containing fixed argv identifier,
return code, duration, stdout/stderr bytes, timeout flag, output-limit flag,
and decode diagnostics. Read both pipes concurrently in chunks; do not call
`communicate()` without an independent output ceiling, because its returned
data is accumulated in memory. [CITED:
https://docs.python.org/3/library/asyncio-subprocess.html#asyncio.subprocess.Process.communicate]

### Pattern 5: Plan-Time DNS Failure Is Data, Not Whole-Profile Abort

The current `ResolutionSnapshot` rejects an empty address set and
`preview_plan()` resolves every hostname before compiling steps; one failed
profile hostname therefore aborts the entire preview. [VERIFIED:
`src/mercury/policy.py:116`, `src/mercury/planner.py:755`]

Compile one logical `system_dns` action for every hostname even if planning
resolution fails. Compile address-specific TCP/TLS/HTTP actions only for
addresses present in the bounded planning snapshot. At execution, DNS can
produce a typed failure or answer; if an originally unresolved name now
answers, report that fact and a limitation that address probes were not in the
authorized immutable plan. The operator can rerun to obtain a new exact
preview. Never dynamically add connection actions after authorization.
[VERIFIED: D-02, D-03, and the Phase 1 immutable-plan contract; prescriptive research conclusion]

When a hostname recheck changes, shrinks, grows, or escapes scope, the task
service—not the runner—must create a service-bound no-I/O rejection
observation for that known step and complete it without opening a socket.
Current admission raises before a runner can record evidence, so this requires
a small authoritative `admit_or_reject`/preflight-failure seam rather than a
runner workaround. [VERIFIED: `TaskContext.admit()` and `record()` in
`src/mercury/tasks.py`]

### Pattern 6: Task Lifecycle and Diagnostic Health Are Separate

A completed diagnosis can validly conclude `failed` reachability; conversely,
a cancelled/engine-failed task may retain partial positive evidence. The
current generic `_derive_conclusion()` maps any negative observation in a
completed task to failed health and can conflict with D-17. [VERIFIED:
`src/mercury/tasks.py:693`]

Have the diagnosis runner/facade add one reserved
`diagnosis-health` conclusion from a pure classifier. Keep task state for
lifecycle only, and have rendering/exit selection read that conclusion. The
generic task summary should not compete as a second reachability verdict.
[VERIFIED: D-17 and D-18; prescriptive research conclusion]

### Anti-Patterns to Avoid

- **Dummy ports/transports:** they corrupt scope, cost, previews, and evidence
  binding for DNS/ping/path. [VERIFIED: D-03]
- **One generic platform parser:** Windows JSON, Linux JSON/files, and macOS
  text have different failure and provenance semantics. [VERIFIED: D-06]
- **Connect by logical hostname after admission:** this performs an
  unreviewed second resolution and bypasses `PreparedStep.address`.
  [VERIFIED: SAFE-04 and `TaskContext.admit()`]
- **Generic “probe error” strings:** map direct protocol outcomes before
  sanitizing bounded detail. [VERIFIED: D-04, D-16]
- **Every route/DNS record is “active”:** preserve all configured/scoped
  records and state; do not guess the kernel/resolver's exact current choice.
  [VERIFIED: local Windows inspection]
- **Native return code as universal truth:** output and exit semantics vary;
  require parser-supported positive/negative evidence and retain ambiguous
  output as inconclusive/error. [CITED: platform command docs below]
- **HTTP redirects/body following:** one bounded `HEAD /` exchange is enough;
  any valid status is evidence and no redirect target has been authorized.
  [VERIFIED: D-13, D-16]

## Passive Inventory Details

### Host and Interface Collection

Collect host metadata with `socket.gethostname()`, `platform.system()`,
`platform.release()`, `platform.version()`, `platform.machine()`,
`platform.python_version()`, and Mercury/psutil package versions. Each source
gets a collection timestamp, monotonic duration, source name, and explicit
error/capability if unavailable. [CITED:
https://docs.python.org/3/library/platform.html; VERIFIED: D-07]

Join the union of names from `psutil.net_if_addrs()` and
`psutil.net_if_stats()` and preserve Unicode names exactly. An interface can
have multiple addresses per family. Treat `psutil.AF_LINK` as MAC; report
`speed == 0` as unavailable because psutil documents zero as undetermined.
[CITED: https://github.com/giampaolo/psutil/blob/v7.2.2/docs/index.rst]

For each IP address:

- preserve the raw address and a separate IPv6 scope ID;
- derive prefix length from the netmask with `ipaddress.ip_interface`;
- if the netmask is missing/invalid, retain the address and set prefix
  availability/error rather than dropping the record;
- retain point-to-point/broadcast data only as optional source detail;
- do not infer “physical,” “Wi-Fi,” “VPN,” or “switch” from interface name.

These rules are recommendations based on the documented psutil shape and D-07.

### Normalized Route Record

Use one internal frozen record with only optional fields that all three
adapters can honestly populate:

```text
family, destination_cidr, is_default, gateway,
interface_name, interface_index,
route_metric, interface_metric, effective_metric,
preferred_source, protocol, scope, route_type, flags,
source, source_record_index
```

`gateway=None` plus `on_link=true` is different from an unknown gateway.
Default gateways are route records whose destination is `0.0.0.0/0` or
`::/0`; preserve multiple candidates. [CITED:
https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netroute?view=windowsserver2025-ps]

### Normalized DNS Server Record

```text
address, family, interface_name, interface_index,
resolver_order, scoped_domain, source, configuration_state
```

Call records “configured” or “resolver-visible,” not universally “in use.”
Windows can return tunnel, disconnected-interface, and legacy placeholder
entries; macOS can have default and supplemental domain-scoped resolvers; a
Linux `resolv.conf` entry can be a local systemd-resolved stub rather than an
upstream server. [VERIFIED: local Windows inspection; CITED:
https://github.com/apple-oss-distributions/configd/blob/main/scutil.tproj/scutil.8;
https://man7.org/linux/man-pages/man5/resolv.conf.5.html]

### Platform Collection Matrix

| Platform/source | Fixed read-only invocation | Parser/result rules |
|-----------------|----------------------------|---------------------|
| Windows routes | PowerShell 5.1 fixed script around `Get-NetRoute -PolicyStore ActiveStore`, selecting `DestinationPrefix`, `NextHop`, `InterfaceIndex`, `InterfaceAlias`, `RouteMetric`, `InterfaceMetric`, `Protocol`, and `State`, then `ConvertTo-Json -Compress -Depth 4` | Force UTF-8 output, require a JSON array, preserve Unicode aliases and all IPv4/IPv6 defaults. Effective metric is route metric + interface metric; do not rank on `RouteMetric` alone. [VERIFIED: local PowerShell 5.1 output; CITED: https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netroute?view=windowsserver2025-ps] |
| Windows interface metrics/state | `Get-NetIPInterface` selected scalar properties → JSON | Join by `(AddressFamily, InterfaceIndex)`; absence is unknown, not zero. [CITED: https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netipinterface?view=windowsserver2025-ps] |
| Windows DNS | `Get-DnsClientServerAddress` selected `InterfaceAlias`, `InterfaceIndex`, `AddressFamily`, `ServerAddresses` → JSON | Preserve every configured address and join interface state; never call all rows currently effective. [CITED: https://learn.microsoft.com/en-us/powershell/module/dnsclient/get-dnsclientserveraddress?view=windowsserver2025-ps] |
| Linux routes | `ip -j -4 route show table main` and `ip -j -6 route show table main` | Parse JSON only; canonicalize `default`; preserve `gateway`, `dev`, `prefsrc`, `metric`, `protocol`, `scope`, and `type`. Missing `ip`, bad JSON, and nonzero exit are distinct capability states. [CITED: https://github.com/iproute2/iproute2/blob/main/man/man8/ip.8] |
| Linux DNS baseline | Read `/etc/resolv.conf` as bounded text | Parse only line-oriented `nameserver` directives and preserve order. Detect/report a symlink or loopback stub; do not claim upstream DNS visibility. [CITED: https://man7.org/linux/man-pages/man5/resolv.conf.5.html] |
| Linux DNS enrichment | If present, `resolvectl status --json=short --no-pager` | Consume only valid JSON from versions that support it; otherwise keep the resolv.conf result and record enrichment unavailable/parse-error. `resolvectl status` describes global/per-link settings. [CITED: https://www.freedesktop.org/software/systemd/man/latest/resolvectl.html] |
| macOS default route | `/sbin/route -n get default` and `/sbin/route -n get -inet6 default` | Parse key/value fixtures; nonzero for an absent family is a family-specific unavailable result, not total failure. `-n` avoids name lookup. [CITED: https://github.com/apple-oss-distributions/network_cmds/blob/main/route.tproj/route.8] |
| macOS route table | `/usr/sbin/netstat -rn -f inet` and `-f inet6` | Parse section/header-aware recorded fixtures; retain flags and interface. Never assume fixed column widths without fixture coverage. [CITED: https://github.com/apple-oss-distributions/network_cmds/blob/main/netstat.tproj/netstat.1] |
| macOS DNS | `/usr/sbin/scutil --dns` | Parse resolver blocks, order, domain, nameserver, interface index, flags/reach; preserve default and supplemental scopes. [CITED: https://github.com/apple-oss-distributions/configd/blob/main/scutil.tproj/scutil.8] |

Record fixtures for empty output, one record, many records, malformed/truncated
output, CRLF/LF, Unicode interface aliases, VPN/tunnel entries, IPv4+IPv6
defaults, missing fields, permission errors, missing commands, nonzero exits,
timeouts, and output overflow. [VERIFIED: D-20; local Windows inspection]

## Layered Probe and Profile Design

### Exact Built-In Profiles

Treat aliases `basic` and `china` as selectors for immutable definitions whose
effective names are `basic-v1` and `china-v1`. Persist the effective version and
entire action preview. A later endpoint change creates `*-v2`; it never
silently mutates historical `*-v1`. [VERIFIED: D-11]

| Profile | Raw public-IP TCP action | HTTPS endpoints (one DNS + address-specific TCP/TLS/HEAD action set each) | Optional context target |
|---------|--------------------------|--------------------------------------------------------------------------|-------------------------|
| `basic-v1` | `1.1.1.1:53` | `www.cloudflare.com:443`, `www.microsoft.com:443`, `www.apple.com:443` | one native ping and one max-8-hop path action to `1.1.1.1` |
| `china-v1` | `223.5.5.5:53` | `www.baidu.com:443`, `www.qq.com:443`, `www.aliyun.com:443` | one native ping and one max-8-hop path action to `223.5.5.5` |

Cloudflare documents `1.1.1.1` as its public resolver; Alibaba DNS documents
`223.5.5.5` for Public DNS. The HTTPS names are operator-owned public sites
from three independent operators in each row. This selection is a versioned
diagnostic recommendation, not a guarantee of present or future reachability.
[CITED: https://developers.cloudflare.com/1.1.1.1/ip-addresses/;
https://www.alidns.com/;
https://www.cloudflare.com/; https://www.microsoft.com/; https://www.apple.com/;
https://www.baidu.com/; https://www.tencent.com/; https://www.alibabagroup.com/]

Normal tests replace every address/name with fakes or loopback servers. No test
resolves, connects, pings, or traces these public targets. [VERIFIED: D-12,
`AGENTS.md`]

### Strict Custom Target Grammar

Use a dedicated small parser before existing target normalization:

1. reject strings containing `://`, `/`, `*`, whitespace, commas, or range
   syntax;
2. parse `[IPv6-or-scoped-link-local]:PORT` only when the closing bracket is
   followed by exactly one decimal port;
3. otherwise require exactly one colon and parse `HOST:PORT`;
4. reject unbracketed input containing more than one colon;
5. validate port as exact integer `1..65535`;
6. pass the host part to existing `parse_target()` and reject CIDR/network
   kinds;
7. canonicalize and deduplicate the `(host, port)` pair while preserving the
   deterministic sorted preview.

Validate timeout with `math.isfinite()` and `0.1 <= timeout <= 30.0`; argparse's
`float` alone accepts `nan` and `inf`. [VERIFIED: D-13, D-14;
RECOMMENDATION based on existing strict parsing in `src/mercury/policy.py`]

Action expansion:

| Target | Actions |
|--------|---------|
| Hostname, any port | `system_dns` plus one TCP action per authorized planning address |
| Address, any port | TCP only |
| Port 443 | Add verified TLS and HTTPS `HEAD /` per concrete address |
| Port 80 | Add bounded plain HTTP `HEAD /` per concrete address |
| Other port | No TLS/HTTP inference; TCP only |

### Probe Execution Rules

All network runners use the concrete `PreparedStep.address`; hostname is used
only for DNS identity, TLS SNI/verification, and HTTP `Host`. [VERIFIED:
SAFE-04, `src/mercury/tasks.py`]

| Layer/outcome | Evidence kind | Disposition | Required detail |
|---------------|---------------|-------------|-----------------|
| DNS answers | `DNS_ANSWER` | positive | canonical unique A/AAAA addresses, resolver API/source, answer count |
| `gaierror` name-not-found | `DNS_FAILURE` | negative | bounded `gaierror.errno`, category |
| temporary resolver failure / timeout | `DNS_FAILURE` or `TIMEOUT` | inconclusive | category, no universal outage claim |
| TCP connected | `TCP_CONNECTED` | positive | address, port, family |
| connection refused | `TCP_REFUSED` | negative | errno/winerror |
| reset/unreachable | existing specific kind | negative | errno/winerror |
| socket timeout | `TIMEOUT` | inconclusive | operation `tcp` |
| verified TLS | `TLS_HANDSHAKE` | positive | TLS version, cipher name, ALPN if any; no certificate body |
| certificate/hostname rejection | **new** `TLS_VERIFICATION_FAILED` | negative | verify code/message, bounded |
| other peer TLS handshake rejection | **new** `TLS_HANDSHAKE_FAILED` | negative or error according to direct/local cause | SSL reason/category |
| valid HTTP status, including 4xx/5xx | `HTTP_RESPONSE` | positive | status, bounded reason, protocol version; do not follow redirect |
| native parsed reply | **new** `NATIVE_PING_REPLY` | positive | responder, RTT when parseable |
| native explicit failure | **new** `NATIVE_PING_FAILURE` or existing ICMP kind | negative/error only when direct output supports it | return code and parser category |
| native no reply/ambiguous output | `SILENT` | inconclusive | return code, bounded diagnostic |
| responding path hop | **new** `PATH_HOP` | positive | hop index, responder address(es), RTT samples |
| unanswered hop | **new** `PATH_HOP_UNANSWERED` | inconclusive | hop index |
| destination proven reached | **new** `PATH_COMPLETE` | positive | destination address and hop index |
| max-hop/timeout/no proof | **new** `PATH_INCOMPLETE` | inconclusive | last hop, exit status, reason |

Map Python exception subclasses first (`ConnectionRefusedError`,
`ConnectionResetError`, `TimeoutError`), then portable `errno` values, then a
bounded `EXECUTION_ERROR`; do not pattern-match localized exception prose.
[CITED: https://docs.python.org/3/library/exceptions.html#ConnectionError]

### TCP/TLS/HTTP Mechanics

- TCP and TLS may use `asyncio.open_connection()` with the concrete address and
  an outer `asyncio.timeout()`. For TLS, pass
  `ssl.create_default_context()` and the logical host/IP as `server_hostname`.
  [CITED: https://docs.python.org/3/library/asyncio-stream.html#asyncio.open_connection;
  https://docs.python.org/3/library/ssl.html#ssl.create_default_context]
- Keep TCP, TLS, and HTTP as separate planned connections/attempts so timing
  and failure layers are not inferred from one combined call. [VERIFIED: D-16]
- For HTTP, use a tiny concrete `http.client.HTTPConnection`/
  `HTTPSConnection` helper whose `connect()` dials the prepared address while
  `Host` and SNI use the logical target. Send `HEAD /` with
  `Connection: close`, retain any valid status as positive exchange evidence,
  read no body, and follow no redirect. [CITED:
  https://docs.python.org/3/library/http.client.html; VERIFIED: D-16]
- Close writers/sockets in `finally`; bound close/shutdown waits and never let
  cleanup overwrite the primary observation. [CITED:
  https://docs.python.org/3/library/asyncio-stream.html#asyncio.StreamWriter.wait_closed]

### DNS Timeout Limitation

The system `getaddrinfo()` API is the correct resolver path and supports both
IPv4 and IPv6, but the underlying synchronous OS resolver call is not
guaranteed to be interruptible merely because its asyncio future is cancelled.
[CITED: https://docs.python.org/3/library/socket.html#socket.getaddrinfo]

Use `loop.getaddrinfo()` under the per-operation timeout, cap DNS worker
concurrency, record timeout as inconclusive, and do not claim kernel DNS packet
or cancellation precision. Add an integration test with an injected delayed
resolver. A killable resolver helper process is an upgrade only if real target
platform testing proves an OS resolver can keep Mercury past the hard task
deadline; do not add a DNS library preemptively. [VERIFIED: Ponytail rules and
Phase 1 logical-attempt accounting; prescriptive research conclusion]

### Native Command Matrix

Always apply an outer process deadline and byte ceiling; command-specific
timeouts are defense in depth. Use numeric/no-reverse-DNS flags and an already
authorized concrete address. [VERIFIED: D-09, D-14]

| Platform | Ping | Minimal path |
|----------|------|--------------|
| Windows | `ping.exe -n 1 -w <ms> -4|-6 <address>` | `tracert.exe -d -h 8 -w <per-hop-ms> -4|-6 <address>` |
| Linux | `ping -n -c 1 -W <seconds> -4|-6 <address>` | `traceroute -n -m 8 -q 1 -w <per-hop-seconds> -4|-6 <address>` when installed |
| macOS IPv4 | `/sbin/ping -n -c 1 -W <ms> <address>` | `/usr/sbin/traceroute -n -m 8 -q 1 -w <seconds> <address>` |
| macOS IPv6 | `/sbin/ping6 -n -c 1 -W <ms> <address>` | `/usr/sbin/traceroute6 -n -m 8 -q 1 -w <seconds> <address>` |

Windows documents `-n` count and `-w` milliseconds; `tracert` documents `-h`
maximum hops and `-w` wait. These exact dash-prefixed forms were also checked
against the local Windows 11 command help. Apple's man pages document numeric output,
millisecond ping wait, and traceroute `-m`, `-q`, and seconds-based `-w`.
[CITED: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ping;
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/tracert;
https://github.com/apple-oss-distributions/network_cmds/blob/main/ping.tproj/ping.8;
https://github.com/apple-oss-distributions/network_cmds/blob/main/traceroute.tproj/traceroute.8]

Set path per-hop wait from the total operation timeout divided across eight
hops, then kill at the total deadline and parse partial output. Never infer a
stable route, symmetry, gateway identity, or switch identity from this one
sample. [VERIFIED: D-08, D-14, D-15]

## Deterministic Evidence and Health Classification

### Required Local Prerequisites

For public profiles, define local prerequisites as:

1. at least one up non-loopback interface with a usable IPv4 or IPv6 address;
2. at least one default-route record for a matching usable family.

Configured DNS absence is visible degradation, but a direct `DNS_ANSWER` can
still prove the system resolver worked. A default route with an on-link next
hop remains a route and must not require a fabricated gateway address.
[VERIFIED: D-17 and normalized route semantics; prescriptive research conclusion]

### Decision Table

The classifier receives the immutable plan/profile and service-bound
observations. It ignores optional ping/path for overall health and produces
one evidence-linked `diagnosis-health` conclusion. [VERIFIED: D-17]

| Condition, evaluated in order | Health | Confidence |
|-------------------------------|--------|------------|
| Required local prerequisites are satisfied; every required DNS/TCP/TLS/HTTP layer has a direct positive; and no required action has only negative/error/inconclusive/unavailable evidence | `healthy` | `high` |
| There is no positive DNS/TCP/TLS/HTTP evidence anywhere, and at least one required reachability action has explicit negative or execution-error evidence | `failed` | `high` for the selected actions only |
| Any positive mixed with negative/error/inconclusive/unavailable; a required layer has no positive; local prerequisites are missing/unavailable; only silence exists; only unavailable/error capability evidence exists; or no decisive evidence exists | `partial` | `medium`, `low`, or `unknown` according to direct support |

This order implements D-17 literally: positives plus contradictory/missing
required evidence are mixed and therefore partial; silence never produces
failed. [VERIFIED: D-17]

Do not reuse `TaskState` as health. A successfully executed diagnosis with
explicit refusals may have `TaskState.COMPLETED` and `Health.FAILED`; an engine
failure after useful observations may have `TaskState.FAILED` and
`Health.PARTIAL`. [VERIFIED: `TaskState` and `Health` are separate enums in
`src/mercury/models.py`]

### Exit Mapping

| Diagnosis conclusion | Exit |
|----------------------|------|
| `healthy` | `EXIT_OK` = 0 |
| `failed` | `EXIT_FAILED` = 1 |
| `partial` | `EXIT_PARTIAL` = 4 |
| input grammar error | existing `EXIT_USAGE` = 2 |
| authorization/policy failure | existing `EXIT_POLICY` = 3 |
| uncaught internal boundary error | existing `EXIT_INTERNAL` = 70 |

[VERIFIED: D-18, constants in `src/mercury/cli.py`]

## Wire Compatibility and Persistence

Bump `MODEL_SCHEMA_VERSION` from `1.0` to `1.1` when new evidence kinds/action
metadata ship; keep `DB_SCHEMA_VERSION` unchanged unless the SQLite table
shape itself changes. Existing 1.0 `TaskResult` rows contain no new enum values
and must continue to decode under 1.1. [VERIFIED: `src/mercury/__init__.py`,
`src/mercury/codec.py`, D-03]

Current code accepts every same-major minor (for example 1.7) but decodes enums
strictly and rejects unknown top-level fields, so an old binary cannot actually
understand arbitrary future minor semantics. [VERIFIED:
`tests/test_models.py:test_compatible_minor_schema_round_trips`,
`src/mercury/codec.py`]

Make compatibility directional and honest: a 1.1 reader accepts 1.0 and 1.1;
it rejects a higher unknown minor until that wire vocabulary is supported.
Update the compatibility test accordingly. This preserves same-major backward
reading without falsely promising forward parsing of unknown evidence kinds.
[VERIFIED: current fail-closed model validation; prescriptive research conclusion]

`project_history_request()` is an exact allowlist. Add only the new safe
diagnosis fields (effective profile version, canonical custom targets, timeout,
and non-secret authorization metadata) or valid Phase 2 submissions will fail
before SQLite. Do not persist raw headers, response bodies, tokens, or
unbounded command output. [VERIFIED: `src/mercury/history.py`,
`tests/test_history.py`]

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Interface enumeration | Per-OS ioctl/WMI/sysctl stack | `psutil.net_if_addrs()` and `net_if_stats()` | Existing dependency already normalizes the required portable NIC facts. [CITED: psutil docs] |
| IP/CIDR/IPv6 scope validation | Regex address parser | Existing `policy.py` + `ipaddress` | Phase 1 already handles canonicalization, dangerous forms, and scoped link-local addresses. [VERIFIED: `src/mercury/policy.py`] |
| TLS trust/hostname verification | Certificate parser or custom crypto | `ssl.create_default_context()` | It loads trusted CAs and sets `CERT_REQUIRED`; custom validation is security-critical and unnecessary. [CITED: Python ssl docs] |
| General HTTP stack | Redirect/cookie/body client | `http.client` for one bounded HEAD exchange | Only status-layer evidence is required; redirects would add unauthorized destinations. [CITED: Python http.client docs; VERIFIED: D-16] |
| Raw ICMP/traceroute | Packet crafting/capture engine | Native ping/path commands | Cross-platform privilege and ICMP semantics are not Phase 2's differentiator. [VERIFIED: D-15, D-21] |
| Route kernel ABI parser | `/proc` hex tables, routing sockets, WMI wrappers | Structured native output where present; fixture text parsing only at the edge | Native tools expose platform semantics with less custom privileged code. [VERIFIED: D-06] |
| New scheduler/budget service | Separate probe task system | Existing `TaskService`/`TaskContext` | Phase 1 already enforces the immutable trust boundary and persistence. [VERIFIED: Phase 1 verification] |
| Dynamic endpoint discovery | Remote endpoint catalog/update service | Frozen `basic-v1`/`china-v1` data | Remote mutation would change authorized work and reproducibility. [VERIFIED: D-11] |
| Generic adapter/plugin framework | Registry, factories, DI container | Three direct OS modules and one direct dispatch | Exactly three built-in platforms do not justify extension machinery. [VERIFIED: D-21, Ponytail] |

**Key insight:** custom machinery is justified only for Mercury's canonical
evidence, sparse authorization, and deterministic classification; the actual
facts/protocol mechanics should use psutil, stdlib, or native OS capabilities.

## Common Pitfalls

### Pitfall 1: Extending the Cartesian Plan with Fake Values

**What goes wrong:** DNS/ping/path acquire fake port 0/53 or fake TCP/UDP
transport, corrupting previews, authorization, cost, and provenance.  
**Why it happens:** Phase 1's `ProbeStep` requires both fields. [VERIFIED:
`src/mercury/planner.py`]  
**How to avoid:** Implement sparse `ActionIdentity` before any real runner.  
**Warning signs:** conditionals such as “ignore port for ping,” or observations
whose `probe` is not digest-bound.

### Pitfall 2: One DNS Failure Prevents Every Other Profile Check

**What goes wrong:** `preview_plan()` aborts when one hostname has no planning
answer, so raw-IP and other-operator evidence disappear.  
**Why it happens:** `ResolutionSnapshot` forbids empty addresses. [VERIFIED:
`src/mercury/policy.py`]  
**How to avoid:** Keep a logical DNS action and compile address actions only
for successful bounded snapshots; never dynamically expand later.  
**Warning signs:** a `socket.gaierror` escapes the whole facade.

### Pitfall 3: Re-resolving Inside TCP/TLS/HTTP

**What goes wrong:** the runner connects to a DNS answer that was not in the
authorized/prepared plan.  
**Why it happens:** convenience APIs are called with the hostname rather than
`PreparedStep.address`.  
**How to avoid:** dial the concrete prepared address and use the logical name
only for SNI/Host. [VERIFIED: SAFE-04]  
**Warning signs:** `open_connection(step.target, ...)` or
`HTTPSConnection(hostname)` without an overridden concrete dial.

### Pitfall 4: Treating Lifecycle Failure as Network Health

**What goes wrong:** a completed refused service is a failed task, or a task
engine error overwrites partial positive diagnosis.  
**Why it happens:** current generic summary derives health from all
dispositions. [VERIFIED: `src/mercury/tasks.py:693`]  
**How to avoid:** reserve one pure diagnosis-health conclusion and map exit
from it; keep `TaskState` separate.  
**Warning signs:** CLI exit is selected only from `result.state`.

### Pitfall 5: Selecting the Wrong Windows Default/DNS

**What goes wrong:** the lowest `RouteMetric` is declared active, or tunnel and
disconnected DNS rows are all called current.  
**Why it happens:** Windows route choice combines route and interface metric,
and DNS cmdlets report per-interface configuration. [CITED: Microsoft
Get-NetRoute/Get-DnsClientServerAddress docs; VERIFIED: local inspection]  
**How to avoid:** preserve all defaults, both metrics, address family,
interface state, and source; label DNS configured rather than universally
effective.  
**Warning signs:** one scalar `default_gateway` or `dns_servers: [str]` without
interface/provenance.

### Pitfall 6: Unbounded or Locale-Blind Subprocess Parsing

**What goes wrong:** a child fills memory/output budgets, a localized line is
misclassified, or one malformed row erases valid sources.  
**Why it happens:** unbounded `communicate()`, shell strings, and English-only
regexes.  
**How to avoid:** fixed argv, numeric/JSON modes, concurrent bounded pipe
reads, independent source results, and recorded localized/Unicode fixtures.  
**Warning signs:** `shell=True`, `split()` on assumed English headings, or raw
stdout persisted without a byte cap.

### Pitfall 7: TLS/HTTP Collapse

**What goes wrong:** TCP success is reported as TLS/HTTPS success, a certificate
failure becomes a generic exception, or HTTP 404 is called network failure.  
**Why it happens:** one convenience request hides layers.  
**How to avoid:** separate planned attempts and observations; verified TLS is
mandatory; any valid HTTP status proves an exchange. [VERIFIED: D-16]  
**Warning signs:** one boolean `https_ok` or disabled certificate checks.

### Pitfall 8: Ping/Path Overclaim

**What goes wrong:** no echo reply becomes “host down,” one trace becomes “the
route,” or hop 1 becomes “the switch.”  
**Why it happens:** ICMP filtering, missing hops, load balancing, and return
path effects are ignored. [VERIFIED: `.planning/research/PITFALLS.md`]  
**How to avoid:** optional context only; unanswered/timeout is inconclusive;
retain hop evidence and explicit limitations.  
**Warning signs:** optional native evidence changes failed/healthy directly.

### Pitfall 9: Under-Costing Multi-Observation Actions

**What goes wrong:** an eight-hop action emits nine observations although the
preview reserved one event/output unit.  
**Why it happens:** Phase 1 estimate is step-count based. [VERIFIED:
`src/mercury/planner.py`]  
**How to avoid:** per-step observation/output ceilings summed into aggregate
estimates and enforced at `record()`.  
**Warning signs:** path runners can append until the global limit.

### Pitfall 10: Tests Touch Public Profiles

**What goes wrong:** CI scans or depends on networks Mercury does not own,
becoming flaky and violating authorization policy.  
**Why it happens:** profile constants are exercised literally.  
**How to avoid:** injected resolver/connector/subprocess fixtures and loopback
servers; reserve public smoke for explicit authorized human validation.  
**Warning signs:** a test contains a public profile hostname or `1.1.1.1` in a
live connector expectation.

## Code Examples

### Interface Normalization

```python
# Source: https://github.com/giampaolo/psutil/blob/v7.2.2/docs/index.rst
def collect_interfaces(psutil_module=psutil) -> tuple[InterfaceRecord, ...]:
    addresses = psutil_module.net_if_addrs()
    stats = psutil_module.net_if_stats()
    records = []
    for name in sorted(set(addresses) | set(stats)):
        stat = stats.get(name)
        records.append(
            InterfaceRecord(
                name=name,
                is_up=None if stat is None else stat.isup,
                mtu=None if stat is None or stat.mtu <= 0 else stat.mtu,
                speed_mbps=(
                    None if stat is None or stat.speed == 0 else stat.speed
                ),
                addresses=normalize_addresses(addresses.get(name, ())),
                source="psutil.net_if_addrs+net_if_stats",
            )
        )
    return tuple(records)
```

### Verified TLS to an Authorized Concrete Address

```python
# Source: https://docs.python.org/3/library/asyncio-stream.html#asyncio.open_connection
# Source: https://docs.python.org/3/library/ssl.html#ssl.create_default_context
async def probe_tls(prepared, timeout_s: float):
    context = ssl.create_default_context()
    async with asyncio.timeout(timeout_s):
        reader, writer = await asyncio.open_connection(
            prepared.address,
            prepared.step.identity.port,
            ssl=context,
            server_hostname=prepared.step.identity.server_name,
            ssl_handshake_timeout=timeout_s,
            ssl_shutdown_timeout=min(timeout_s, 1.0),
        )
    try:
        ssl_object = writer.get_extra_info("ssl_object")
        return ssl_object.version(), ssl_object.cipher()
    finally:
        writer.close()
        try:
            async with asyncio.timeout(min(timeout_s, 1.0)):
                await writer.wait_closed()
        except (TimeoutError, OSError):
            pass
```

### Pure Health Classifier Skeleton

```python
# Source: Phase 2 CONTEXT.md D-17
def classify_diagnosis(plan, observations, local_prerequisites) -> Health:
    required = required_action_outcomes(plan, observations)
    reachability = reachability_observations(observations)
    positive_layers = {
        layer_for(item) for item in reachability
        if item.disposition is Disposition.POSITIVE
    }
    required_layers = required_reachability_layers(plan)

    if (
        local_prerequisites is True
        and required_layers <= positive_layers
        and all(outcome.has_positive_only for outcome in required)
    ):
        return Health.HEALTHY
    if (
        not any(item.disposition is Disposition.POSITIVE for item in reachability)
        and any(
            item.disposition in {Disposition.NEGATIVE, Disposition.ERROR}
            for item in reachability
        )
    ):
        return Health.FAILED
    return Health.PARTIAL
```

### Bounded Native Command Shape

```python
# Source: https://docs.python.org/3/library/asyncio-subprocess.html
process = await asyncio.create_subprocess_exec(
    *argv,
    stdin=asyncio.subprocess.DEVNULL,
    stdout=asyncio.subprocess.PIPE,
    stderr=asyncio.subprocess.PIPE,
    limit=64 * 1024,
)
# Read stdout and stderr concurrently in fixed chunks, count their combined
# bytes, kill on the explicit ceiling, and wrap the whole operation in the
# planned deadline. Do not substitute process.communicate() without that cap.
```

## State of the Art

| Old/current foundation | Phase 2 approach | When changed | Impact |
|------------------------|------------------|--------------|--------|
| Homogeneous target × port × transport plan | Sparse kind-validated action list | Model schema 1.1 / Phase 2 | DNS/ping/path/local snapshot gain honest identity and exact cost. [VERIFIED: repository + D-03] |
| Runner supplies free-form observation probe | Service verifies/binds planned action kind | Phase 2 | Prevents evidence from claiming a different probe than the admitted step. [VERIFIED: current `TaskContext.record()` gap] |
| One observation estimate per step | Per-action observation/output reservation | Phase 2 | Path hops remain inside event/output ceilings. [VERIFIED: current planner estimate] |
| Generic task-disposition summary | Dedicated pure diagnosis-health conclusion | Phase 2 | Lifecycle and reachability no longer conflict. [VERIFIED: current `_derive_conclusion()`] |
| Text route parsing everywhere | PowerShell JSON on Windows, `ip -j` on Linux, fixture text parsing only where macOS requires it | Current native capabilities | Reduces locale/column fragility while preserving platform provenance. [CITED: Microsoft/iproute2/Apple docs] |
| TLS failure as generic execution error | Certificate and handshake-specific evidence kinds | Model schema 1.1 | Users can see TCP-positive/TLS-negative incidents directly. [VERIFIED: D-04, D-16] |

**Deprecated/outdated for this phase:**

- Using `result.state` as the diagnosis exit decision. [VERIFIED: D-18]
- Calling a native ping/path hostname rather than the admitted concrete
  address. [VERIFIED: SAFE-04]
- Persisting or presenting a single guessed Windows DNS/default route without
  interface and metric provenance. [VERIFIED: local Windows inspection]
- Accepting arbitrary higher same-major schema minors while rejecting their
  unknown enums/fields. [VERIFIED: current codec/tests]

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| — | None. Endpoint durability and untested platform output are explicitly validation gaps rather than assumed facts. | — | — |

All factual claims in this research were checked against the repository,
official documentation/registries, or the local Windows environment. No
`[ASSUMED]` claim is used.

## Open Questions

1. **What exact Linux/macOS fixture variants occur on the supported release matrix?**
   - What we know: the official commands and fields are documented, and Windows
     PowerShell 5.1 was inspected locally. [CITED/VERIFIED: platform sources]
   - What's unclear: this Windows host cannot capture real Linux/macOS outputs,
     localized errors, or missing-tool behavior.
   - Recommendation: Wave 0 records sanitized fixtures on at least one current
     Linux and macOS host, then cross-platform CI treats parser drift as a
     release gate; this does not block planning.

2. **Will the selected public profile endpoints remain appropriate from
   mainland and global networks?**
   - What we know: each set names three independent operator-owned HTTPS sites
     and a documented public resolver address. [CITED: profile sources]
   - What's unclear: no operator guarantees universal reachability, and this
     research intentionally performed no active public test.
   - Recommendation: keep `basic-v1`/`china-v1` immutable, perform explicit
     authorized manual validation before release, and create a new profile
     version for any endpoint replacement.

3. **Can a target OS resolver outlive Mercury's visible DNS timeout?**
   - What we know: `getaddrinfo()` wraps the OS C resolver and asyncio timeout
     cancellation does not document termination of that underlying call.
     [CITED: Python socket/asyncio docs]
   - What's unclear: practical shutdown behavior differs by resolver/platform.
   - Recommendation: test delayed injected resolvers and real offline DNS on
     each OS; retain stdlib system resolution unless it demonstrably violates
     the hard task deadline, then use a bounded killable helper as the named
     upgrade trigger.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|-------------|-----------|---------|----------|
| CPython | All Phase 2 work | ✓ | 3.13.5 local; project floor 3.11 | — |
| `psutil` | Interface facts | ✓ | 7.0.0 local; 7.2.2 registry current | Keep declared `>=7,<8`; no alternate interface library |
| Windows PowerShell | Windows route/DNS structured adapter | ✓ | 5.1.26100.8875 | Typed capability degradation if cmdlet/source fails |
| `Get-NetRoute`, `Get-NetIPInterface`, `Get-DnsClientServerAddress` | Windows inventory | ✓ | OS modules NetTCPIP/DnsClient | Typed unavailable/error; preserve psutil facts |
| `ping.exe`, `tracert.exe` | Optional native context | ✓ | Windows 10.0.26100 binaries | Missing-tool capability; overall diagnosis continues |
| Linux `ip`, `resolvectl`, `ping`, `traceroute` | Linux adapters | Not auditable on this Windows host | — | `/etc/resolv.conf` for DNS baseline; typed missing-tool for route/ping/path |
| macOS `route`, `netstat`, `scutil`, `ping`, `traceroute` | macOS adapters | Not auditable on this Windows host | — | Typed capability degradation plus fixture/CI verification |
| Node/frontend framework | None | Not required | — | Standard library only |

[VERIFIED: local command/version probes; `pyproject.toml`; official package
registry]

**Missing dependencies with no fallback:**

- None on the current Windows development host. Linux/macOS real-output
  validation requires those OS CI/runners before Phase 2 is declared
  cross-platform complete. [VERIFIED: environment audit]

**Missing dependencies with fallback:**

- Native ping/path tools are optional; report `missing_tool` and continue.
- Linux `resolvectl` is optional; parse bounded `/etc/resolv.conf` and report
  upstream/per-link visibility limitations.
- A failed route/DNS source does not suppress psutil or other successful source
  evidence.

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Python `unittest` on CPython 3.11–3.13 |
| Config file | none |
| Existing baseline | 115 passed, 3 Windows-inapplicable POSIX permission skips on 2026-07-30 |
| Quick run command | `python -m unittest tests.test_inventory tests.test_platforms tests.test_profiles tests.test_probes tests.test_diagnosis -v` |
| Full suite command | `python -m unittest discover -s tests -v` |

[VERIFIED: repository test files and local full-suite run]

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| INVT-01 | Host/version/time and independent capability degradation | unit | `python -m unittest tests.test_inventory -v` | ❌ Wave 0 |
| INVT-02 | NIC address/prefix/MAC/MTU/speed normalization, Unicode, missing fields | unit | `python -m unittest tests.test_inventory -v` | ❌ Wave 0 |
| INVT-03 | Windows/Linux/macOS route/DNS fixtures and unavailable/error states | unit/contract | `python -m unittest tests.test_platforms -v` | ❌ Wave 0 |
| DIAG-01 | Finite basic profile, local/DNS/raw-IP TCP/TLS/HTTPS action layers | unit/integration | `python -m unittest tests.test_profiles tests.test_diagnosis -v` | ❌ Wave 0 |
| DIAG-02 | China profile, strict custom target grammar, timeout bounds | unit | `python -m unittest tests.test_profiles -v` | ❌ Wave 0 |
| DIAG-03 | DNS/TCP/TLS/HTTP/ping outcomes, timing, attempts, typed errors | unit/loopback integration | `python -m unittest tests.test_probes -v` | ❌ Wave 0 |
| DIAG-04 | Same-result human/JSON projection and 0/4/1 exit matrix | unit/CLI integration | `python -m unittest tests.test_diagnosis tests.test_cli -v` | `tests/test_cli.py` exists; Phase 2 cases ❌ |

### Required Test Matrix

1. **Model/plan contracts:** every action-kind field matrix; stable ID/digest;
   mutation rejection; action kind service binding; no dummy port/transport;
   per-step observation/output boundary; schema 1.0 read by 1.1 and unknown
   higher-minor rejection.
2. **Inventory:** independent psutil address/stats failures; multiple addresses;
   IPv6 scope/netmask; missing prefix/MAC/speed; speed zero; Unicode interface;
   output/record truncation; explicit switch-not-observable limitation.
3. **Platform fixtures:** structured one-vs-array JSON; malformed/truncated
   JSON; CRLF/LF; multiple Windows default routes with combined metrics;
   tunnel/disconnected/legacy DNS; Linux default/on-link/IPv6 routes and
   resolv.conf stub; macOS default/supplemental resolvers and missing IPv6
   default.
4. **Authorization:** exact profile/custom preview; unattested non-loopback
   rejection; DNS answer escape; cardinality change; service-created
   preflight-rejection evidence; connector receives only prepared address.
5. **Protocol outcomes:** DNS answer/NXDOMAIN/temporary/timeout; TCP success,
   refusal, reset, unreachable, timeout; TLS success, hostname/cert failure,
   other handshake failure; HTTP 200/204/301/404/500 all valid positive
   exchanges; malformed/oversized response error; no redirects.
6. **Native tools:** missing, permission denied, nonzero, timeout, output
   overflow, parse failure, direct reply, silence, responding/unanswered hops,
   completion/incompletion, max eight hops.
7. **Classifier:** exhaustive table for healthy, no-positive explicit failure,
   positive+negative mixed, missing required layer, unavailable-only,
   silence-only, optional ping/path changes, cancelled/engine-failed lifecycle,
   and evidence references.
8. **CLI:** `status` and `diagnose` call only the facade; strict bracketed IPv6;
   `nan`/`inf` timeout rejection; JSON/human same `TaskResult`; exit constants;
   no public target calls.

### Controlled Integration Fixtures

- Use loopback `asyncio.start_server()` for TCP and a minimal HTTP responder.
- Commit a clearly labeled test-only CA/server certificate/key with
  `localhost`/loopback SANs; tests load it explicitly for verified TLS and use
  the same server without the test CA for verification failure. No test
  runtime depends on OpenSSL or generates cryptographic material.
- Inject timeouts/drops at the resolver/connector/subprocess boundary instead
  of sending packets to a public black hole.
- Keep fixture addresses in loopback or IANA documentation ranges and never
  call the built-in public profile constants through a real connector.

[VERIFIED: D-20, `AGENTS.md`; RECOMMENDATION for deterministic tests]

### Sampling Rate

- **Per task commit:** run the directly affected test module plus existing
  `tests.test_policy` and `tests.test_tasks` when plan/admission changes.
- **Per wave merge:** `python -m unittest discover -s tests -v`.
- **Phase gate:** full suite green, clean wheel/module/console parity retained,
  passive `status` smoke on Windows/Linux/macOS, and controlled loopback
  diagnosis smoke before `$gsd-verify-work`.

### Wave 0 Gaps

- [ ] `tests/test_inventory.py` — INVT-01/02 facts and degradation
- [ ] `tests/test_platforms.py` — INVT-03 parser/capability contracts
- [ ] `tests/fixtures/platform/windows/*` — Unicode, metrics, DNS source, errors
- [ ] `tests/fixtures/platform/linux/*` — `ip -j`, resolv.conf/stub, errors
- [ ] `tests/fixtures/platform/macos/*` — route/netstat/scutil, errors
- [ ] `tests/test_profiles.py` — DIAG-01/02 profile/target/timeout contracts
- [ ] `tests/test_probes.py` — DIAG-03 outcome and loopback contracts
- [ ] `tests/test_diagnosis.py` — D-17 classifier and action planner
- [ ] `tests/fixtures/tls/*` — test-only trusted/untrusted TLS fixtures
- [ ] Extend `tests/test_cli.py` — DIAG-04 projection/exit/facade boundary

No new test framework installation is needed. [VERIFIED: existing
`unittest` suite]

## Security Domain

Security enforcement is enabled at ASVS level 1 in `.planning/config.json`.
[VERIFIED: `.planning/config.json`]

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | no in Phase 2 | Local CLI only; peer/listener authentication is Phase 3 |
| V3 Session Management | no in Phase 2 | No Web/session surface |
| V4 Access Control | yes | Exact `ScopeGrant`, action-kind/target/port policy, digest-bound immutable plan, immediate address recheck |
| V5 Input Validation | yes | `argparse`, `ipaddress`, exact enum/dataclass validation, strict `host:port`, fixed subprocess argv |
| V6 Cryptography | yes | `ssl.create_default_context()` with certificate/hostname verification; never custom crypto |
| V7 Error/Logging | yes | Bounded sanitized error detail, no secrets/raw bodies, explicit capability and protocol states |
| V13 API/Web Service | no in Phase 2 | No listener or remote API |

[CITED: https://owasp.org/www-project-application-security-verification-standard/;
VERIFIED: Phase boundary and repository controls]

### Known Threat Patterns for This Stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| DNS rebinding/scope escape | Elevation of privilege / SSRF-like scope bypass | Authorize name and every concrete address; recheck immediately; connect only to `PreparedStep.address`; service records no-I/O rejection |
| Command injection | Tampering / elevation | Fixed executable and argv, no shell, no user interpolation into PowerShell script, numeric concrete address only |
| Plan/evidence identity forgery | Tampering / repudiation | Action identity in SHA-256 step/digest; `TaskContext` binds reserved action metadata and rejects conflicting runner detail |
| Unbounded action/output cardinality | Denial of service | Exact sparse steps, per-step observation/output reservations, aggregate Phase 1 ceilings, fixed workers, deadlines/cancellation |
| TLS interception accepted as success | Spoofing | Default CA + hostname/IP verification; specific verification-failure evidence; no insecure override |
| Redirect scope escape | Elevation / information disclosure | HEAD only, retain 3xx status, never follow redirect |
| Raw native output leaks or poisons persistence | Information disclosure / denial | Byte cap, Unicode replacement, control/NUL sanitization, bounded diagnostic snippets, existing secret-free persistence checks |
| False topology/Internet verdict | Spoofing/repudiation of evidence | Evidence-linked conclusions, endpoint-limited language, silence partial, no switch inference |

## Sources

All sources were accessed on 2026-07-30. Context7 was attempted first but its
CLI quota was exhausted; official documentation/registries were used as the
required fallback. [VERIFIED: local Context7 CLI response]

### Primary (HIGH confidence)

- Mercury repository:
  - `AGENTS.md`
  - `.planning/PROJECT.md`, `.planning/REQUIREMENTS.md`,
    `.planning/ROADMAP.md`, `.planning/STATE.md`
  - `02-CONTEXT.md`
  - Phase 1 models, policy, planner, tasks, history, codec, CLI, render, tests,
    context, and verification
- psutil 7.2.2 API:
  https://github.com/giampaolo/psutil/blob/v7.2.2/docs/index.rst
- psutil registry metadata:
  https://pypi.org/pypi/psutil/json
- Python socket/getaddrinfo:
  https://docs.python.org/3/library/socket.html#socket.getaddrinfo
- Python asyncio streams/timeouts/subprocess:
  https://docs.python.org/3/library/asyncio-stream.html
  and https://docs.python.org/3/library/asyncio-subprocess.html
- Python SSL:
  https://docs.python.org/3/library/ssl.html#ssl.create_default_context
- Python HTTP client:
  https://docs.python.org/3/library/http.client.html
- Microsoft `Get-NetRoute`:
  https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netroute?view=windowsserver2025-ps
- Microsoft `Get-NetIPInterface`:
  https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netipinterface?view=windowsserver2025-ps
- Microsoft `Get-DnsClientServerAddress`:
  https://learn.microsoft.com/en-us/powershell/module/dnsclient/get-dnsclientserveraddress?view=windowsserver2025-ps
- Microsoft ping/tracert:
  https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ping
  and https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/tracert
- iproute2 `ip`/route man sources:
  https://github.com/iproute2/iproute2/blob/main/man/man8/ip.8
  and https://github.com/iproute2/iproute2/blob/main/man/man8/ip-route.8
- Linux `resolv.conf(5)`:
  https://man7.org/linux/man-pages/man5/resolv.conf.5.html
- systemd `resolvectl`:
  https://www.freedesktop.org/software/systemd/man/latest/resolvectl.html
- Apple open-source route/netstat/ping/traceroute man pages:
  https://github.com/apple-oss-distributions/network_cmds/tree/main
- Apple open-source `scutil(8)`:
  https://github.com/apple-oss-distributions/configd/blob/main/scutil.tproj/scutil.8
- Cloudflare resolver addresses:
  https://developers.cloudflare.com/1.1.1.1/ip-addresses/
- Alibaba Public DNS addresses:
  https://www.alidns.com/
- OWASP ASVS:
  https://owasp.org/www-project-application-security-verification-standard/

### Secondary (MEDIUM confidence)

- Official public operator homepages used only to select versioned profile
  names; they are not reachability guarantees:
  https://www.cloudflare.com/, https://www.microsoft.com/,
  https://www.apple.com/, https://www.baidu.com/, https://www.tencent.com/,
  https://www.alibabagroup.com/

### Tertiary (LOW confidence)

- None.

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH — locked and registry/docs verified; no new dependency.
- Repository architecture: HIGH — inspected implementation and all 115 current
  tests passed locally.
- Sparse plan/security seams: HIGH — required directly by locked decisions and
  confirmed by current code limitations.
- Windows inventory commands: HIGH — official docs plus local PowerShell 5.1
  inspection.
- Linux/macOS parser specifics: MEDIUM-HIGH — official upstream man pages, but
  no live host was available in this research session.
- Probe semantics/classifier: HIGH — locked decision table plus Python official
  APIs and existing evidence invariants.
- Public endpoint durability: MEDIUM — versioned operator-owned choices, but no
  universal availability guarantee and no active test performed.

**Research date:** 2026-07-30  
**Valid until:** 2026-08-29; revalidate public profile endpoints and
Linux/macOS fixtures before release even if the core architecture remains
unchanged.
