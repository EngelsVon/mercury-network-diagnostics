# Requirements: Mercury

**Defined:** 2026-08-02
**Core Value:** Within an explicitly declared private-network scope, identify every tested transport or application carrier that can convey a correlated message between two configured endpoints, and show the exact coverage gaps.

## v1 Requirements

### Private Scope

- [x] **SCOPE-01**: An operator can submit active work only for loopback, RFC1918 IPv4, IPv6 ULA, or scoped IPv6 link-local literal/CIDR destinations; public, documentation, multicast, unspecified, and broadcast targets are rejected before DNS, sockets, or native subprocesses run. *(Phase 1, 2026-08-02)*
- [x] **SCOPE-02**: An operator can use an internal hostname only when every resolved and rechecked address remains inside the declared private scope; any public or scope-escaping answer fails the task before connection. *(Phase 1, 2026-08-02)*
- [x] **SCOPE-03**: The product no longer exposes built-in public diagnosis profiles or public-target examples as supported active behavior. *(Phase 1, 2026-08-02)*

### Peer-Correlated Coverage

- [ ] **COVER-01**: An operator can select a finite named coverage matrix containing TCP connect/tagged exchange, UDP tagged exchange, DNS over UDP/TCP, ICMP echo, TLS handshake, HTTP exchange, SSH banner, local ARP/IPv6-ND evidence, and optional native Nmap TCP/UDP/SCTP profiles.
- [ ] **COVER-02**: A configured Mercury peer can provision only its configured short-lived receiver profiles and records correlation ID, protocol/profile, source/destination tuple, arrival time, payload digest/length, and reply result for every received test message.
- [ ] **COVER-03**: A two-endpoint assessment runs each selected receiver-capable profile independently in both directions and correlates sender evidence with peer arrival/acknowledgement evidence.
- [ ] **COVER-04**: TCP and UDP coverage results preserve connection/refusal/reset, tagged arrival, acknowledgement, ICMP unreachable, timeout, silent, permission-denied, and execution-error semantics separately.
- [ ] **COVER-05**: DNS, TLS, HTTP, and SSH coverage use standards-compliant fixed request/handshake/banner exchanges against configured test receivers and never perform credential or login attempts.
- [ ] **COVER-06**: ICMP echo records native reply/unreachable/timeout outcomes and adds peer arrival evidence only when the platform exposes a privileged capture/observer capability; otherwise it reports the capability gap.
- [ ] **COVER-07**: ARP and IPv6 Neighbor Discovery are reported only as same-link evidence and are explicitly marked not applicable for cross-subnet remote-pair reachability.
- [ ] **COVER-08**: An assessment lists positive candidate carriers, attempted profiles, unavailable/permission-denied/skipped/non-applicable profiles, and never claims that all possible tunnelling methods have been eliminated.

### Mapping Plans

- [ ] **MAP-01**: An operator can declare multiple IPv4 private CIDRs in one mapping request; overlapping inputs are canonicalized, deduplicated, and compiled into one immutable plan.
- [ ] **MAP-02**: An operator can set logical attempt-start rate and concurrency within immutable ceilings, and the effective values plus accounting units appear in the result.
- [ ] **MAP-03**: An operator can set a finite duration ceiling; a requested duration of 0 means no additional operator-selected early cutoff, not unlimited work, and the result states when an immutable ceiling stops the run.
- [ ] **MAP-04**: The exact selected coverage profiles, receiver leases, ports, payload metadata, rate, concurrency, duration, directions, and limits are bound into the immutable plan before any active step is admitted.

### Optional Native Nmap

- [ ] **NMAP-01**: When Nmap is installed, an operator can choose documented fixed internal TCP connect/SYN, UDP, or SCTP-init coverage profiles; Mercury derives argv only from an admitted private plan and reports unavailable capability when Nmap is absent or lacks required privilege.
- [ ] **NMAP-02**: Mercury parses bounded Nmap XML into the versioned evidence model with explicit native provenance and preserves the difference between native open/closed/filtered/open-or-filtered, timeout/silence, parser failure, and unsupported profile.
- [ ] **NMAP-03**: Mercury never accepts arbitrary Nmap flags, scripts, target files, proxy/decoy configuration, or a target that escaped its canonical private plan.

### Service, Peer, and History

- [ ] **SURF-01**: CLI and Web UI submit the same internal mapping or paired coverage request through MercuryApplication; no presentation code opens a scan socket or native subprocess directly.
- [ ] **SURF-02**: The Web UI displays accessible coverage-profile, range, port, rate, duration, direction, receiver-capability, progress, cancellation, candidate-carrier, provenance, and gap information while its non-loopback listener retains TLS/token protections.
- [ ] **PEER-01**: Mercury peer communication keeps mTLS, configured certificate pinning, token/replay checks, and closed configured destinations; peer control cannot accept an arbitrary mapping target or receiver profile.
- [ ] **HIST-01**: Local task history records the effective private plan, receiver/provenance evidence, immutable limits, and terminal reason while preserving credential/token/private-key filtering and default report redaction.

### Verification and Documentation

- [ ] **QUAL-01**: Controlled tests prove that public and DNS-escaped targets fail before I/O, private multi-range mapping respects rate/duration/output ceilings, and cancellation is safe.
- [ ] **QUAL-02**: Controlled tests prove sender/receiver correlation and directional semantics for every supported coverage profile, including receiver-capability gaps and cross-subnet ARP/ND non-applicability.
- [ ] **QUAL-03**: Controlled tests prove Nmap argv/XML handling, CLI/Web shared-service routing, history safety, and peer trust controls without a real non-loopback scan.
- [ ] **DOC-01**: README, CLI help, Web copy, and release smoke instructions describe the supported coverage matrix, peer receiver prerequisites, hard ceilings, zero-duration semantics, Nmap capability limits, ARP/ND boundary, and assessment-gap semantics accurately.

## v2 Requirements

### Internal Inventory

- **INV-01**: Operator can compare two internal coverage assessments and highlight changed candidate carriers without treating absent output as proof of closure.
- **INV-02**: Operator can import an administrator-maintained private CIDR inventory file after explicit local validation and preview.

## Out of Scope

| Feature | Reason |
|---------|--------|
| Public or Internet scanning | Mercury is intentionally limited to private-network diagnostics. |
| Active work without a declared scope and local attestation | The canonical trust boundary must remain explicit. |
| No-limit duration/rate/concurrency/budget mode | Immutable ceilings prevent host, network, and data-loss hazards. |
| Generic Nmap command forwarding | Arbitrary flags can bypass scope, provenance, and control-plane protections. |
| Proof that no possible tunnel or packet sequence can work | A finite probe matrix cannot establish that universal negative; coverage gaps must remain visible. |
| Password or credential brute forcing | It is not reachability diagnosis and risks account harm. |
| Peer-directed third-party scans | A peer must not become a remote scanning relay. |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| SCOPE-01 | Phase 1 | Complete |
| SCOPE-02 | Phase 1 | Complete |
| SCOPE-03 | Phase 1 | Complete |
| COVER-01 | Phase 2 | Pending |
| COVER-02 | Phase 2 | Pending |
| COVER-03 | Phase 2 | Pending |
| COVER-04 | Phase 2 | Pending |
| COVER-05 | Phase 2 | Pending |
| COVER-06 | Phase 2 | Pending |
| COVER-07 | Phase 2 | Pending |
| COVER-08 | Phase 2 | Pending |
| MAP-01 | Phase 3 | Pending |
| MAP-02 | Phase 3 | Pending |
| MAP-03 | Phase 3 | Pending |
| MAP-04 | Phase 3 | Pending |
| NMAP-01 | Phase 4 | Pending |
| NMAP-02 | Phase 4 | Pending |
| NMAP-03 | Phase 4 | Pending |
| SURF-01 | Phase 4 | Pending |
| SURF-02 | Phase 4 | Pending |
| PEER-01 | Phase 4 | Pending |
| HIST-01 | Phase 4 | Pending |
| QUAL-01 | Phase 5 | Pending |
| QUAL-02 | Phase 5 | Pending |
| QUAL-03 | Phase 5 | Pending |
| DOC-01 | Phase 5 | Pending |

**Coverage:**

- v1 requirements: 26 total
- Mapped to phases: 26
- Unmapped: 0 ✅

---

*Requirements defined: 2026-08-02*
*Last updated: 2026-08-02 after Phase 1 private-scope verification*
