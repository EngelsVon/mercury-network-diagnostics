# Pitfalls Research

**Domain:** Cross-platform active network diagnostics and cooperating-agent reachability testing  
**Researched:** 2026-07-30  
**Confidence:** HIGH for protocol/safety findings; MEDIUM for cross-platform packaging until stack spike

## Executive warning

Mercury is inherently dual use. Its useful behavior—discovering hosts, ports,
routes, and partial policy holes—is also behavior monitored as reconnaissance.
The product remains defensible only if authorization, bounded scope,
rate/budget controls, authentication, evidence semantics, and auditability are
part of the core engine rather than UI disclaimers.

“Test every port with every packet type” is not a finite product requirement.
Ports alone give 65,535 candidates per transport; an application payload is an
arbitrary byte string, and IP has additional protocols and extension behavior.
Mercury should offer hypothesis-oriented profiles and a budgeted matrix, never
claim exhaustive packet-space coverage.

## Critical Pitfalls

### Pitfall 1: Treating silence as a diagnostic verdict

**What goes wrong:**  
UDP silence is labeled “open”, ICMP silence is labeled “host down”, or a TCP
timeout is labeled “firewall” without alternatives. Users receive confident but
false root-cause statements.

**Why it happens:**  
Connection-oriented mental models are applied to UDP and ICMP. Middleboxes may
drop errors, hosts may rate-limit ICMP, and firewalls can drop or reject
differently. Nmap deliberately uses the state `open|filtered` when a UDP probe
gets no response.

**How to avoid:**  
Use an evidence model with observation, direction, attempt count, timing,
payload profile, OS error, response/ICMP evidence, candidate explanations, and
confidence. Reserve `reachable` for positive evidence; represent `silent`,
`rejected`, `closed`, `filtered-likely`, and `inconclusive` separately.
Correlate client and cooperating-server event logs when both ends run Mercury.

**Warning signs:**  
Boolean `is_open` / `is_online` fields; tests that assert timeout means closed;
UI badges with no evidence drill-down.

**Phase to address:**  
Foundation/data model before any scanner or UI.

---

### Pitfall 2: Building an unauthenticated internal-network scan oracle

**What goes wrong:**  
A WebUI/API exposed beyond loopback lets a browser, compromised host, or remote
caller direct Mercury to probe arbitrary internal addresses. A peer daemon can
be used for SSRF-like pivoting, reflection, or lateral reconnaissance.

**Why it happens:**  
“Enter an IP and test it” is implemented as a generic URL/IP endpoint, while
target validation, DNS rebinding, IPv4-mapped IPv6, redirects, and peer identity
are treated as web-layer details.

**How to avoid:**  
Bind local control to loopback by default; require authentication for any remote
binding. Canonicalize IP literals, resolve once under policy, re-check every
resolved IPv4/IPv6 address against the task’s explicit CIDR allowlist, reject
redirect-driven target changes, and enforce policy in the engine. Pair peers
with short-lived human-verifiable codes and mutually authenticated sessions;
bind every task to the authenticated peer and a declared target set. Never
accept raw socket destinations from an untrusted UI request.

**Warning signs:**  
`POST /scan {"host": ...}` directly invokes sockets; `0.0.0.0` default bind;
no authorization object in a task; hostname validation occurs before a second
DNS lookup; no audit trail.

**Phase to address:**  
Foundation security model and again during peer/WebUI integration.

---

### Pitfall 3: Letting scan cardinality or concurrency explode

**What goes wrong:**  
Subnet × port × protocol × payload × retry combinations create millions of
probes, exhaust file descriptors/ephemeral ports, flood a constrained link,
trigger IDS, or freeze the WebUI. UDP can transmit at line rate without native
congestion control.

**Why it happens:**  
Nested loops are easy to write; “all ports” is mistaken for a harmless option;
per-worker limits are used without an aggregate destination/network budget.

**How to avoid:**  
Compile every request into a costed plan before execution. Enforce global and
per-destination token buckets, maximum targets/ports/payload bytes/retries/
duration/events, bounded queues, structured cancellation, adaptive backoff, and
an immutable absolute ceiling. Default discovery should be passive → local
subnets only → sampled/common probes → explicit expansion. Estimate duration
and packet count in the UI before a task starts.

**Warning signs:**  
Unbounded task spawning; one semaphore per scanner but no shared limiter;
millions of progress events retained in memory; cancel only hides the task.

**Phase to address:**  
Probe scheduler before subnet discovery and matrix testing.

---

### Pitfall 4: Claiming a directly connected switch from IP-layer guesses

**What goes wrong:**  
The default gateway, first traceroute hop, ARP neighbor, or NIC vendor is shown
as “your switch”. On switched Ethernet the actual access switch may be
transparent and absent from the IP path.

**Why it happens:**  
Layer-2 adjacency, Layer-3 next hop, Wi-Fi access point, and physical switch are
collapsed into one topology node.

**How to avoid:**  
Model facts separately: interface, L2 neighbor, default gateway, first L3 hop,
Wi-Fi BSSID/AP, and infrastructure advertisement. Only name a switch when LLDP/
CDP or a managed source supplies evidence. Report LLDP capture capability and
privilege/platform limitations; otherwise say “not observable from this host”.

**Warning signs:**  
Gateway IP displayed under “Switch”; topology lacks source/confidence;
cross-platform tests assume LLDP availability.

**Phase to address:**  
Local inventory/topology phase.

---

### Pitfall 5: Mistaking one traceroute for the path

**What goes wrong:**  
Per-flow load balancing, NAT, ICMP filtering, asymmetric return paths, or route
changes create missing or apparently looping hops. A single classic traceroute
is presented as the canonical route.

**Why it happens:**  
Traceroute varies flow-identifying fields and routers may hash them onto
different equal-cost paths. The responding address describes the return of an
ICMP error, not necessarily full forward/reverse symmetry.

**How to avoid:**  
Keep a stable flow identifier for a trace profile where possible, support ICMP/
UDP/TCP trace variants, run repeated samples, display non-responsive hops and
path alternatives, and compare both Mercury directions rather than forcing a
single path. Never infer the exact filtering hop solely from the last response.

**Warning signs:**  
One array of hop IPs with no run/probe metadata; hop changes treated as parser
bugs; asterisks rendered as failure.

**Phase to address:**  
Routing analysis phase.

---

### Pitfall 6: Delegating semantics to shell output parsers

**What goes wrong:**  
Localized Windows output, changed flags, missing binaries, permission errors,
or platform differences silently corrupt results. CLI and WebUI behave
differently because each shells out independently.

**Why it happens:**  
`ping`, `tracert`, `route`, `arp`, `ip`, and `netsh` make a fast prototype.

**How to avoid:**  
Use native/library APIs for interfaces, routes, DNS, sockets, and neighbor
tables where stable. Put unavoidable command adapters behind typed capability
interfaces with locale-independent invocation, version detection, fixtures,
timeouts, captured stderr, and an explicit `unsupported` result. Both frontends
must call the same engine.

**Warning signs:**  
Regexes over human output in domain services; missing capability inventory;
platform checks scattered through UI code.

**Phase to address:**  
Foundation and local inventory.

---

### Pitfall 7: Designing the peer protocol without replay and identity controls

**What goes wrong:**  
Captured tasks can be replayed, results can be spoofed, a stale agent can be
confused with the intended IP owner, or two users on a shared network can
commandeer each other’s listener.

**Why it happens:**  
IP address is treated as identity and TLS is postponed until after the protocol
is built.

**How to avoid:**  
Pair identities, not IPs. Use a well-reviewed mutually authenticated secure
channel, transcript-bound task IDs, nonces, expirations, monotonically tracked
session/task state, size limits, and version negotiation. The server must
authorize each probe profile and budget independently; the client cannot grant
itself capabilities.

**Warning signs:**  
Plain JSON over a fixed open TCP port; bearer secret in URL; no clock/replay
tests; results lack peer fingerprint.

**Phase to address:**  
Peer protocol phase before bidirectional probes.

---

### Pitfall 8: Testing only the developer’s healthy LAN

**What goes wrong:**  
Dropped packets, delayed/duplicated UDP, ICMP rate limiting, DNS hijacking,
NAT, IPv6 scope IDs, interface churn, captive portals, and asymmetric rules are
untested. The demo works but real incident diagnosis lies.

**Why it happens:**  
Network failures are nondeterministic on a normal development machine and raw
socket tests are hard in shared CI.

**How to avoid:**  
Separate pure classification from I/O; replay recorded normalized observations;
use Linux network namespaces plus `tc netem`/firewall rules for controlled E2E
scenarios; use fake clocks and deterministic budgets; add Windows/macOS
capability smoke jobs; test cancellation and partial result persistence. Never
run broad public scans in CI.

**Warning signs:**  
Only localhost success tests; sleeps in tests; no timeout/refusal/silence
fixtures; CI needs administrator privileges for all tests.

**Phase to address:**  
Every phase, with the controlled network lab established in foundation.

## Technical Debt Patterns

| Shortcut | Immediate Benefit | Long-term Cost | When Acceptable |
|----------|-------------------|----------------|-----------------|
| Store only final booleans | Simple UI | Evidence and reclassification are impossible | Never |
| Separate CLI and WebUI implementations | Fast parallel demos | Semantic drift and duplicate platform bugs | Never |
| Parse human command output everywhere | Quick OS coverage | Locale/version fragility | Only behind one tested adapter |
| In-memory task/event history only | No database work | Crash loses incident evidence; WebUI reconnect fails | Prototype spike only |
| One fixed “common ports” list | Easy scan profile | Misses context and becomes stale | Seed profile if versioned/configurable |
| Privileged process for the whole app | Easy raw sockets | Large attack surface | Never; isolate optional helper |
| Roll a custom cipher/handshake | Small dependency set | Identity/replay vulnerabilities | Never |

## Integration Gotchas

| Integration | Common Mistake | Correct Approach |
|-------------|----------------|------------------|
| DNS | Checking only resolver success | Record server used, A/AAAA answers, latency, validation target, and direct-IP comparison |
| Public reachability | One vendor endpoint becomes a false outage | Use small policy-defined multi-provider set and distinguish DNS/TCP/TLS/HTTP |
| LLDP/CDP | Assuming ordinary sockets see frames on every OS | Capability-gated passive capture/helper; clearly report unavailable |
| OS route/neighbor APIs | Forcing fields into one lossy schema | Preserve raw provenance plus normalized, optional fields |
| WebSocket/SSE progress | One event per packet without backpressure | Aggregate counters; bounded event stream; resumable cursor |
| IPv6 | Treating address text like IPv4 | Preserve scope/interface IDs; canonicalize; cover link-local and multiple routes |
| Captive portal checks | Calling any HTTP redirect “internet works” | Compare expected status/body/TLS and expose interception evidence |

## Performance Traps

| Trap | Symptoms | Prevention | When It Breaks |
|------|----------|------------|----------------|
| One coroutine/goroutine per full matrix cell | Memory/socket spikes | Bounded worker queues and hierarchical budgets | Tens of thousands of cells |
| Retaining every packet event | UI/database growth | Aggregate by attempt/result; sampled debug traces | Long/full-port scans |
| Fast retry on UDP silence | Link/ICMP rate-limit amplification | Exponential or profile-defined spacing with aggregate limiter | Low-bandwidth or filtered networks |
| Serial timeout per port | Hours-long runs | Safe bounded concurrency and adaptive ordering | Hundreds of silent ports |
| Reverse DNS for every discovered address | DNS storms and misleading delay | Opt-in/batched lookup with cache and budget | Medium subnets upward |
| Full history sent on every WebUI reconnect | Large latency/memory use | Cursor pagination and compact snapshots | Thousands of observations |

## Security Mistakes

| Mistake | Risk | Prevention |
|---------|------|------------|
| Scan without recorded authorization/scope | Policy/legal incident | Explicit CIDR/host scope, consent record, visible target/cost preview |
| Remote API bound publicly by default | Network scan oracle | Loopback default, authenticated opt-in bind, firewall guidance |
| Trust hostname after a single validation | DNS rebinding / policy escape | Canonicalize and enforce on resolved addresses at connection time |
| Accept peer-requested unlimited probes | DoS / reflection | Server-side profile allowlist and immutable budgets |
| Run all code privileged | Engine/UI compromise gains root/admin | Nonprivileged core plus minimal audited helper |
| Log raw network identities forever | Privacy/asset inventory leak | Retention limits, encryption/permissions, export redaction |
| Put pairing secret in URL/CLI history | Credential disclosure | Interactive input/short-lived code, protected storage, rotation |
| Load arbitrary probe plugins in-process | Code execution/supply-chain risk | Signed/built-in registry first; isolated extension model later |

## UX Pitfalls

| Pitfall | User Impact | Better Approach |
|---------|-------------|-----------------|
| Red/green “internet” light | Hides partial failures | Layered status: link, gateway, DNS, public IP, TLS/HTTP targets |
| False precision | Users chase the wrong device/hop | Evidence, provenance, confidence, alternatives |
| Scanner-centric forms | Users must know ports/protocols first | Start with diagnostic questions/profiles, then advanced controls |
| Dangerous option one click away | Accidental broad scans | Preview, typed scope, time/packet estimate, second confirmation |
| “0% packet loss = healthy” | Ignores latency/jitter/path/policy | Multi-signal summary with baseline/context |
| Silent privilege degradation | Missing data looks like “none found” | Capability panel explaining unavailable/denied/not observed |

## “Looks Done But Isn’t” Checklist

- [ ] **Reachability:** refusal, timeout, ICMP unreachable, DNS failure, TLS
  interception, and positive application response are distinct.
- [ ] **UDP:** silence remains inconclusive unless peer/ICMP/application
  evidence narrows it.
- [ ] **Topology:** switch/gateway/AP facts include source and confidence.
- [ ] **Routing:** repeated/multipath and opposite-direction observations work.
- [ ] **Scope:** IPv4, IPv6, hostnames, mapped addresses, and DNS rebinding are
  policy-tested.
- [ ] **Cancellation:** sockets/workers stop and partial results are finalized.
- [ ] **WebUI:** remote binding is authenticated and loopback is the default.
- [ ] **Peer:** pairing, replay, expiry, version mismatch, and budget rejection
  have tests.
- [ ] **Packaging:** a clean Windows/Linux/macOS machine can run the documented
  baseline without developer tooling.
- [ ] **Reports:** secrets and identifiers are redacted by default and exports
  retain evidence/provenance.

## Recovery Strategies

| Pitfall | Recovery Cost | Recovery Steps |
|---------|---------------|----------------|
| Boolean result schema shipped | HIGH | Introduce versioned observations, migrate legacy status to low-confidence evidence |
| Scan oracle exposed | HIGH | Disable remote bind, rotate peer identities, audit tasks, add engine policy boundary |
| Unbounded scheduler | MEDIUM | Add plan compiler/budgets, then make all probes consume permits |
| Shell parsing everywhere | HIGH | Inventory adapters, add golden fixtures, replace highest-risk sources incrementally |
| Misidentified topology | MEDIUM | Change labels/schema, retain source evidence, communicate uncertainty |
| Weak peer handshake | HIGH | Replace protocol with reviewed secure channel; invalidate old pairings |

## Pitfall-to-Phase Mapping

| Pitfall | Prevention Phase | Verification |
|---------|------------------|--------------|
| Ambiguous protocol verdicts | Foundation | Table-driven classifier tests for all evidence combinations |
| Scan oracle / scope escape | Foundation + WebUI/peer | SSRF-style canonicalization and authorization tests |
| Work explosion | Scheduler | Property tests prove every plan stays within hard budgets |
| Switch overclaim | Inventory/topology | Fixtures with gateway-only, LLDP, Wi-Fi, and unavailable cases |
| Traceroute false path | Routing | ECMP/missing-hop/repeated-run controlled scenarios |
| Shell parser fragility | Platform adapters | Locale/error/missing-command fixtures on all OS jobs |
| Peer spoof/replay | Peer protocol | Replay, wrong identity, expiry, downgrade, oversized-task tests |
| Healthy-LAN-only testing | Test lab | Netns/netem success/drop/reject/delay/duplicate/DNS interception E2E |

## Sources

- Nmap Project, “UDP Scan (-sU)” — response-to-state table and
  `open|filtered` semantics:
  https://nmap.org/book/scan-methods-udp-scan.html (accessed 2026-07-30).
- Nmap Project, “Legal Issues” — written authorization and provider-policy
  guidance: https://nmap.org/book/legal-issues.html (accessed 2026-07-30).
- IETF RFC 8085, *UDP Usage Guidelines* — aggregate congestion control, ICMP
  validation, transient errors, and filtering:
  https://www.rfc-editor.org/rfc/rfc8085.html (accessed 2026-07-30).
- OWASP, *Server Side Request Forgery Prevention Cheat Sheet* — canonical IP
  validation, allowlisting, defense in depth, and DNS-pinning caveats:
  https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
  (accessed 2026-07-30).
- lldpd project README — LLDP as adjacent link-layer notification, OS support,
  and privilege separation:
  https://github.com/lldpd/lldpd/blob/master/README.md
  (accessed 2026-07-30).
- libparistraceroute README — traceroute resilient to per-flow load balancing:
  https://github.com/libparistraceroute/libparistraceroute
  (accessed 2026-07-30).
- Linux man-pages, `network_namespaces(7)` — isolated network stacks:
  https://man7.org/linux/man-pages/man7/network_namespaces.7.html
  (accessed 2026-07-30).
- Linux man-pages, `tc-netem(8)` — controlled delay, loss, duplication,
  corruption, and reordering:
  https://man7.org/linux/man-pages/man8/tc-netem.8.html
  (accessed 2026-07-30).
- IETF RFC 791, *Internet Protocol* — protocol field and datagram structure:
  https://www.rfc-editor.org/rfc/rfc791.html (accessed 2026-07-30).

## Limitations and bias check

- Legal rules vary by jurisdiction; the report gives product safety guidance,
  not legal advice.
- LLDP/CDP availability is NIC, switch-policy, driver, privilege, and OS
  dependent. No claim is made that it universally reveals an access switch.
- Network namespace/netem coverage is Linux-specific and must be complemented
  by native Windows/macOS smoke and adapter tests.
- Nmap documentation is authoritative for Nmap’s classifier but not proof that
  Mercury must copy its exact implementation; the semantic caution is the
  transferable finding.

---
*Pitfalls research for: Mercury network diagnostics*  
*Researched: 2026-07-30*
