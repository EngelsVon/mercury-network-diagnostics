# Project Research Summary

**Project:** Mercury（墨丘利）  
**Domain:** Cross-platform local and paired-endpoint network diagnostics  
**Researched:** 2026-07-30  
**Decision:** **NARROW-GO**  
**Overall confidence:** MEDIUM-HIGH

## Executive Summary

Mercury has value only as an explanatory workflow, not as a new scanner. Mature
tools already own ICMP/path visualization, host/port discovery, packet
generation, throughput, centralized blackbox monitoring, overlay diagnostics,
and LLDP. The unmet combination is a local-first tool that gathers a layered
host snapshot, performs bounded progressive checks, correlates evidence from
two authenticated endpoints in both directions, and renders the same
uncertainty-aware result through CLI, JSON, WebUI, history, and a redacted
report.

The lean implementation is a Python modular monolith using the standard
library plus `psutil`. It reuses native `ping`/route-trace commands and optional
`lldpctl` rather than implementing raw ICMP/LLDP or a packet engine. The WebUI
is semantic HTML/native JavaScript served locally; SQLite stores bounded
versioned results. Remote peer control requires TLS and a token, permits only
peer/self/connect-back measurements, and cannot be used as an arbitrary
third-party scan oracle.

The main risks are false certainty (especially UDP, traceroute, and “direct
switch”), accidental scan explosion, and dual-use remote control. Evidence and
confidence, normalized authorization scope, immutable budgets, safe
non-loopback defaults, and controlled failure tests therefore precede scanner,
peer, and UI breadth.

## Research question and method

**Question:** Does Mercury provide enough value beyond existing network tools,
and what is the smallest safe architecture that can prove it?

**Method:**

1. inspected the referenced Ponytail repository, exact commit, skill, package
   metadata, license and release/API metadata;
2. compared official documentation/repositories for Nmap/Nping/Ncat, MTR,
   Trippy, iperf3, Netshoot, Blackbox Exporter, Tailscale, NetBird, RIPE Atlas,
   LibreSpeed and lldpd;
3. checked protocol and security claims against IETF RFC 8085, Nmap’s documented
   UDP state table, OWASP SSRF guidance and Linux namespace/netem manuals;
4. compared Python/Go/Rust against the actual v1 capability and deployment
   needs;
5. searched for cancellation conditions and unsafe/unsupported parts rather
   than assuming the idea should ship.

**Inclusion:** maintained official docs/source repositories and standards that
directly affect the proposed workflow.  
**Exclusion:** marketing-only feature lists, unverifiable package-version
claims, vulnerability/exploit features and unrelated global monitoring.

## Key Findings

### Recommended Stack

Use CPython `>=3.11` (local development has 3.13.5), `psutil==7.2.2`, and the
standard library: `argparse`, `asyncio`, `socket`, `ssl`, `http.server`,
`sqlite3`, `ipaddress`, `subprocess`, `dataclasses`, `json`, and
`importlib.resources`. Use `setuptools` only to build/install the package.

**Core technologies:**

- **Python stdlib:** engine, CLI, concurrent probes, TLS/HTTP, storage and tests
  — lowest code/dependency surface for validating network semantics.
- **psutil:** portable interface/address/link facts — the one demonstrated
  standard-library gap.
- **Native OS tools:** ping/trace/routes and optional `lldpctl` — reuse platform
  behavior instead of a privileged packet stack.
- **Semantic HTML/CSS/JS:** accessible local dashboard — no Node/frontend
  framework.

Go remains the contingency if clean-machine deployment data proves Python is
the adoption bottleneck; no portability abstraction or rewrite scaffolding is
added now.

### Expected Features

**Must have (table stakes):**

- host, interface, route, DNS, neighbor and capability snapshot;
- layered DNS/TCP/TLS/HTTP/native-ping diagnosis across multiple targets;
- structured observations, evidence, uncertainty and machine-readable JSON;
- passive network discovery plus explicit, bounded active TCP discovery;
- route trace with raw evidence and honest missing/multipath interpretation;
- authenticated peer health/capability and selected TCP/UDP echo tests;
- safe scope/budget preview, cancellation, audit and partial results;
- local WebUI using the same core, task progress/history and redacted export;
- Windows/Linux/macOS ordinary-user baseline with visible degradation.

**Should have (competitive):**

- bidirectional peer evidence correlation and asymmetry explanation;
- partial-policy profiles such as DNS-works/HTTPS-blocked;
- optional LLDP evidence without switch overclaiming;
- comparable saved runs/reports across devices.

**Defer or reuse:**

- throughput (`iperf3`);
- deep service/port scan (`nmap`);
- packet crafting (`nping`/Scapy);
- packet capture/LLDP daemon;
- vulnerability detection;
- hosted fleet controller, monitoring exporter and plugin marketplace;
- exhaustive “all packet kinds”, which is not finite.

### Architecture Approach

One process and package enforce a single flow: request → canonical scope and
budget → immutable plan → platform/probe observations → confidence-aware
classification → events/SQLite → CLI/JSON/WebUI/report. Remote endpoints use
pinned mTLS plus a separate token, negotiate one bounded role-swapped
cross-layer plan, and expose only expiring authenticated data-plane listeners;
no API may request an arbitrary third-party destination.

The architecture deep dive also evaluated resumable SSE and certificate-pinned
mTLS. Mercury v1 uses short polling for the single-user local WebUI, but adopts
mTLS for the remotely exposed peer control plane: the certificate identifies
the endpoint and a constant-time-checked bearer token remains an independent
authorization factor. This is the smallest reviewed design that does not treat
a reusable token as peer identity. Tokens never travel in URLs or logs, and the
receiver re-authorizes every bounded peer plan. SSE should be added only after
a measured polling limitation.

**Major components:**

1. **Model/classifier** — versioned observation, conclusion, task and capability
   schema.
2. **Policy/plan compiler** — target canonicalization, authorization and hard
   aggregate budgets.
3. **Inventory adapter** — psutil and minimal Windows/Linux/macOS native
   adapters, optional LLDP JSON.
4. **Probe/task engine** — bounded DNS/TCP/TLS/HTTP/UDP/native ping/trace and
   cancellation.
5. **Peer control/listeners** — pinned mTLS/token, selected expiring TCP/UDP
   ports, source-bound reverse roles and a cross-layer differential matrix.
6. **History/presentation** — SQLite, CLI/JSON, polling WebUI, report redaction.

### Critical Pitfalls

1. **Silence is not a verdict** — preserve `silent/inconclusive` and supporting
   evidence; UDP no-response is not “open” or “closed”.
2. **Scan oracle** — loopback defaults, pinned mTLS/token remote control, canonical
   allowlists and no arbitrary peer destinations.
3. **Work explosion** — compile/cost every plan, aggregate token buckets and
   immutable host/port/attempt/packet/byte/rate/time/output ceilings.
4. **Switch/path overclaim** — separate gateway, L2 neighbor, route hop, AP and
   LLDP facts with source/confidence.
5. **Healthy-LAN bias** — deterministic classifier fixtures plus namespace/
   netem drop/reject/delay/duplicate/asymmetric tests and native OS smoke jobs.

## Devil’s Advocate Checkpoint

**Strongest counterargument:** every underlying measurement exists already;
operators capable of diagnosing networks may prefer scripts, Nmap, MTR and
iperf3, while less experienced users may misapply an active scanner.

**Response:** the project is justified only by correlated evidence, safe
progressive workflow and shared presentation. The roadmap places an early
working CLI before peer/WebUI expansion, so the hypothesis can be tested. If
paired results do not explain controlled asymmetric/partial failures better
than two saved command outputs, Mercury must stop expanding.

**Confirmation-bias controls:**

- commoditized features are explicitly non-differentiating;
- immediate no-go triggers, ten counterarguments, and explicit lab/operator
  gates are recorded in `FEATURES.md`;
- unsupported “direct switch” and “all packet kinds” claims were removed;
- Go’s distribution advantage and Python’s packaging weakness remain open
  validation items.

**Verdict:** PASS with narrowed scope.

## Ethics and Dual-Use Checkpoint

Active discovery and port/protocol testing can trigger incident response or be
used for reconnaissance. Remote command surfaces can expose internal networks.
The product is ethically acceptable only with:

- explicit user-owned/authorized scope and logged consent;
- passive/low-impact default and previewed, bounded escalation;
- no exploits, credential attacks, evasion or public mass scanning;
- peer authentication, safe binding and no arbitrary third-party scan;
- rate/size/retention limits and default report redaction;
- warnings that laws and provider policies vary.

These are implementation requirements, not documentation-only conditions.

**Verdict:** CLEARED CONDITIONALLY; a high-severity policy/authentication bypass
blocks release.

## Implications for Roadmap

### Phase 1: Evidence and Safety Foundation

**Rationale:** Every active feature and frontend depends on trustworthy,
bounded semantics.  
**Delivers:** package/CLI skeleton, versioned models, policy/budget compiler,
task state/history, baseline tests.  
**Avoids:** boolean-result schema, unbounded work, frontend-specific behavior.

### Phase 2: Local Snapshot and Layered Diagnosis

**Rationale:** Produces the first independently useful product and validates the
stack before peer/UI complexity.  
**Delivers:** interfaces/routes/DNS capability, DNS/TCP/TLS/HTTP/native ping
profiles, CLI/JSON and honest conclusions.  
**Avoids:** shell parser sprawl, switch overclaim and single-target false outage.

### Phase 3: Authenticated Paired Differential Diagnostics

**Rationale:** The only defensible product wedge is validated before
commoditized discovery breadth.  
**Delivers:** pinned mTLS/token control, expiring TCP/UDP listeners, a
role-swapped snapshot/DNS/path/TCP/UDP/TLS/HTTP plan, source-bound reverse
roles, and an evidence-linked A→B/B→A matrix.  
**Avoids:** scan oracle, replay/reflection, token-as-identity and an Nping echo
wrapper mistaken for a product.

### Phase 4: Safe Discovery, Topology Evidence and Routes

**Rationale:** Context enrichment reuses the proven policy and paired evidence
engine but is not the product thesis.  
**Delivers:** passive candidates, ARP/NDP and optional LLDP evidence, explicit
bounded TCP discovery, IPv6-safe behavior, repeated native route traces and
cancellation.  
**Avoids:** surprise subnet scans, unsupported switch claims and one-route
certainty.

### Phase 5: WebUI, History, Reports and Release Hardening

**Rationale:** Presentation projects a proven engine and provides the deployable
whole.  
**Delivers:** accessible polling dashboard, task control/history, redacted
report, clean install, cross-platform and controlled-network E2E documentation.  
**Avoids:** duplicate frontend logic, framework bloat and demo-only quality.

### Phase Ordering Rationale

- Policy/data semantics precede every active or remote feature.
- The paired vertical slice precedes discovery/LLDP so the product hypothesis
  is tested before commodity breadth.
- WebUI is last so it cannot drive a duplicate engine or premature API.
- Deep scanner/throughput/capture breadth is absent; existing tools cover it.

### Research Flags

- **Phase 1:** validate Python packaging and platform capability result schema.
- **Phase 2:** verify structured route/DNS extraction on all three OSes.
- **Phase 3:** threat-model mTLS/token/listener reflection and source-bound
  reverse checks before protocol code.
- **Phase 4:** verify neighbor/LLDP/trace parsers against representative native
  fixtures without claiming transparent switches.
- **Phase 5:** test clean machines and accessibility; add frozen binaries only
  on evidence.

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Product value | MEDIUM | Clear integration gap; no direct user interviews yet |
| Stack | MEDIUM-HIGH | Official APIs/versions verified; packaging spike pending |
| Protocol semantics | HIGH | RFC/Nmap primary sources agree on UDP/ICMP limits |
| Architecture | MEDIUM-HIGH | Standard modular-monolith pattern; peer ergonomics pending |
| Safety pitfalls | HIGH | Well-established authorization/SSRF/congestion concerns |
| Ponytail applicability | HIGH | Exact upstream skill/commit/license inspected |

### Gaps to Address

- **User validation:** expose an early CLI and test with campus/enterprise
  incidents before adding scan breadth.
- **Cross-platform routes/neighbors:** native fixtures and smoke jobs are
  mandatory; no training-data assumptions.
- **Peer certificate UX:** document provided-certificate flow first; add helper
  only after real friction.
- **Time correlation:** clocks may differ; use nonces and per-end monotonic
  timing rather than absolute timestamps for causal claims.

## Sources

### Primary (HIGH confidence)

- IETF RFC 8085 — UDP congestion/ICMP semantics:
  https://www.rfc-editor.org/rfc/rfc8085.html
- Nmap UDP scan state table and authorization discussion:
  https://nmap.org/book/scan-methods-udp-scan.html and
  https://nmap.org/book/legal-issues.html
- OWASP SSRF Prevention Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- Ponytail exact skill and MIT license:
  https://github.com/DietrichGebert/ponytail/tree/16f29800fd2681bdf24f3eb4ccffe38be3baec6b
- Python/psutil/setuptools official documentation and PyPI metadata, listed in
  `STACK.md`.

### Secondary (MEDIUM confidence)

- Official tool/project repositories and docs listed in `FEATURES.md`.
- lldpd and libparistraceroute project documentation listed in `PITFALLS.md`.
- Linux namespaces/netem manuals for controlled test design.

### Tertiary / unresolved

- The proposition that no closer maintained all-in-one competitor exists.
- The user demand for paired correlation and local Web history.
- Maintainer-published Ponytail benchmark percentages.

All web sources accessed 2026-07-30. AI-assisted research tools were used;
claims included in the design were checked against the linked primary or
official sources. Legal guidance is not legal advice.

---
*Research completed: 2026-07-30*  
*Ready for roadmap: yes*
