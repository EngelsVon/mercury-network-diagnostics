# Roadmap: Mercury（墨丘利）

## Overview

Mercury v1 is built from evidence and safety outward. It first establishes one
versioned result/task model and unavoidable scope budgets, then ships a useful
local snapshot/diagnosis CLI. The product-defining authenticated, role-swapped
two-endpoint diagnosis comes next. Only after that core works does Mercury add
bounded discovery, LLDP/neighbor context and route analysis, followed by the
WebUI, reports, packaging and cross-platform release verification over the same
engine.

## Phases

- [x] **Phase 1: Evidence and Safety Foundation** - Establish the package, versioned observations, policy/budgets, task lifecycle and local history.
- [x] **Phase 2: Local Snapshot and Layered Diagnosis** - Deliver a useful Windows/Ubuntu CLI for network facts and multi-layer reachability.
- [ ] **Phase 3: Authenticated Paired Differential Diagnostics** - Run one bounded cross-layer plan from both Mercury endpoints and explain directional differences.
- [ ] **Phase 4: Safe Discovery, Topology Evidence, and Routes** - Add passive-first subnet context, bounded TCP discovery, honest route evidence, neighbors and optional LLDP.
- [ ] **Phase 5: WebUI, Reports, and Release Hardening** - Ship the shared-engine dashboard, reports, compatibility checks, documentation and end-to-end verification.

## Phase Details

### Phase 1: Evidence and Safety Foundation

**Goal**: Every later frontend and active probe uses a versioned,
confidence-aware result model and an immutable authorized budget.  
**Depends on**: Nothing  
**Requirements**: EVID-01, EVID-02, EVID-03, EVID-04, SAFE-01, SAFE-02, SAFE-03, SAFE-04, HIST-01, TEST-01  
**UI hint**: no  
**Success Criteria**:

1. A developer can install/run one `mercury` entry point and receive a versioned JSON
   task/result containing observations, conclusions and capabilities.
2. An active request outside its normalized authorized scope or hard host/port/
   attempt/packet/byte/rate/concurrency/duration/event/output ceiling is
   rejected before network I/O.
3. A long synthetic task can be cancelled and persists a valid partial result
   to bounded local SQLite history.
4. Table-driven standard-library tests distinguish success, refusal, timeout,
   silence, unsupported, permission and error states.

**Plans**: 3 plans

Plans:

- [x] 01-01: Create the lean Python package, result/capability models, JSON codec and SQLite history.
- [x] 01-02: Implement target canonicalization, scope authorization, cost preview, hard budgets and cancellable task execution.
- [x] 01-03: Add baseline model/policy/history/task tests and installation/version commands.

### Phase 2: Local Snapshot and Layered Diagnosis

**Goal**: A user can explain local network context and partial Internet
reachability from CLI/JSON without false topology or protocol certainty.  
**Depends on**: Phase 1  
**Requirements**: INVT-01, INVT-02, INVT-03, DIAG-01, DIAG-02, DIAG-03, DIAG-04  
**UI hint**: no  
**Success Criteria**:

1. On Windows and Ubuntu, `mercury status` reports host, interfaces, routes,
   DNS and explicit capability/degradation evidence.
2. Gateway and locally observed facts retain their provenance; the output
   explicitly says an access switch is not observable until Phase 4 supplies
   direct neighbor/LLDP evidence.
3. `mercury diagnose` separately reports DNS, TCP, TLS, HTTP and native-ping
   observations for multiple default/configured targets with timing and errors.
4. Human output and JSON project the same result and exit healthy/partial/failed
   consistently.
5. A minimal native path adapter yields bounded hop evidence for reuse by the
   paired plan; Phase 4 adds repeated-route UX and topology enrichment.

**Plans**: 4 plans

Plans:

**Wave 1**
- [x] 02-01: Implement psutil inventory and minimal Windows/Ubuntu route and DNS adapters; report macOS and other platforms as explicitly unsupported.
- [x] 02-02: Upgrade the canonical schema, sparse probe identity, exact admission/binding, per-step budgets, history projection and terminal finalization.

**Wave 2** *(blocked on Wave 1 completion)*
- [x] 02-03: Implement immutable basic/China/custom profiles, bounded DNS/TCP/TLS/HTTP/native probes and endpoint-scoped diagnosis.

**Wave 3** *(blocked on Wave 2 completion)*
- [x] 02-04: Add the shared application facade, `status`/`diagnose` projections, stable exits, controlled smoke, installation parity and documentation.

### Phase 3: Authenticated Paired Differential Diagnostics

**Goal**: Two explicitly configured Mercury endpoints can execute the same
bounded cross-layer plan with swapped roles and explain endpoint/direction/
protocol differences without exposing a generic scan oracle.  
**Depends on**: Phase 2  
**Requirements**: SAFE-05, PEER-01, PEER-02, PEER-03, PEER-04, PEER-05, PEER-06  
**UI hint**: no  
**Success Criteria**:

1. A non-loopback agent refuses startup without a server certificate/key,
   trusted pinned client certificate and token unless an explicit audited
   unsafe-development override is supplied.
2. Authenticated peers negotiate protocol/capabilities and independently
   authorize one immutable, expiring plan; bad credentials, replay, oversized
   frames, budget escalation and arbitrary third-party targets are rejected.
3. The paired plan collects both local snapshots and role-swapped DNS, peer
   path, TCP/UDP, and allowlisted TLS/HTTP evidence. Nonce-tagged
   sent/arrived/replied/received observations preserve UDP silence as
   inconclusive.
4. CLI/JSON presents an A→B/B→A layer matrix with evidence-linked explanations
   and source-bound reverse checks rather than a list of disconnected probes.

**Technical continuation gate:** Phase 3 verification must demonstrate
controlled DNS difference, TCP refusal, TCP timeout/drop, UDP reply, UDP
silence, and asymmetric direction without false certainty or scope escape.
Failure stops autonomous execution before Phase 4. The five-operator product
preference gate remains external field validation and blocks scope expansion
beyond this bounded v1, not completion of the requested implementation.

**Plans**: 3 plans

Plans:

- [x] 03-01: Threat-model and implement versioned framed mTLS/token peer control, identity/capability negotiation, replay limits and audit.
- [ ] 03-02: Implement expiring authenticated TCP/UDP data-plane listeners, source-bound reverse roles and finite payload profiles.
- [ ] 03-03: Implement the role-swapped cross-layer plan, differential matrix, CLI and peer security/controlled E2E tests.

### Phase 4: Safe Discovery, Topology Evidence, and Routes

**Goal**: Users can enrich a proven diagnosis with authorized local candidates,
direct topology evidence and sampled routes without surprise scans or
misleading silence/path claims.  
**Depends on**: Phase 3  
**Requirements**: INVT-04, INVT-05, DISC-01, DISC-02, DISC-03, DISC-04, DISC-05  
**UI hint**: no  
**Success Criteria**:

1. `mercury discover --passive` derives visible IPv4 networks and neighbor
   candidates without active packets and refuses IPv6 enumeration.
2. An authorized CIDR scan uses a bounded common/custom/full TCP port plan,
   shows progress, obeys cancellation and retains connect/refuse/timeout
   evidence; full mode requires its independent confirmation.
3. `mercury trace` repeats available native modes with timeouts and retains raw,
   missing-hop and alternate-path evidence without declaring a single certain
   route.
4. Gateway, passive ARP/NDP neighbor, first route hop, Wi-Fi AP and LLDP
   infrastructure remain distinct; without direct LLDP evidence the access
   switch is reported as not observable.

**Plans**: 2 plans

Plans:

- [ ] 04-01: Implement passive candidates, ARP/NDP, Wi-Fi AP and optional LLDP evidence plus authorized bounded TCP discovery and full-port safety gate.
- [ ] 04-02: Implement native repeated route tracing, normalized hop evidence, CLI projections and discovery/trace/topology tests.

### Phase 5: WebUI, Reports, and Release Hardening

**Goal**: Users can operate the proven engine from an accessible local WebUI,
inspect history/reports and install a verified cross-platform v1 release.  
**Depends on**: Phase 4  
**Requirements**: WEB-01, WEB-02, WEB-03, WEB-04, HIST-02, HIST-03, PACK-01, PACK-02, TEST-02, TEST-03, DOCS-01  
**UI hint**: yes  
**Success Criteria**:

1. `mercury web` serves an accessible, same-origin-protected loopback dashboard
   (Host/Origin/session/CSRF/CSP/body limits) that displays current
   facts and the A↔B matrix, and submits/polls/cancels diagnose, paired,
   authorized discovery and route tasks through the same services as the CLI.
2. CLI/WebUI history opens completed/partial tasks, compares two compatible
   runs, and exports default-redacted JSON or self-contained HTML without
   leaking tokens.
3. Ordinary-user smoke tests pass on Windows/Ubuntu with explicit
   capability degradation; controlled tests cover success, refusal, silence,
   DNS failure, delay and asymmetric direction without public scanning.
4. A clean user can install one package containing CLI, agent and Web assets,
   and follow documented authorization, mTLS/token, semantics, limitations and
   troubleshooting. The controlled lab gate covers at least twelve layered,
   silent and asymmetric cases; broader discovery remains frozen until a
   separate five-operator value study validates it.

**Plans**: 3 plans

Plans:

- [ ] 05-01: Implement the stdlib HTTP task API and accessible native HTML/CSS/JS dashboard with polling/cancellation.
- [ ] 05-02: Implement history browsing, centralized redaction and JSON/self-contained HTML reports.
- [ ] 05-03: Complete controlled/cross-platform E2E, clean-install packaging, security/code/Ponytail reviews and user documentation.

## Progress

**Execution Order:** Phase 1 → Phase 2 → Phase 3 → Phase 4 → Phase 5

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Evidence and Safety Foundation | 3/3 | Complete | 2026-07-30 |
| 2. Local Snapshot and Layered Diagnosis | 4/4 | Complete | 2026-08-01 |
| 3. Authenticated Paired Differential Diagnostics | 0/3 | Not started | - |
| 4. Safe Discovery, Topology Evidence, and Routes | 0/2 | Not started | - |
| 5. WebUI, Reports, and Release Hardening | 0/3 | Not started | - |

---
*Roadmap created: 2026-07-30*  
*Coverage: 42/42 v1 requirements mapped exactly once*
