# Mercury

## What This Is

Mercury is a local-first internal-network analysis and mapping tool for administrators diagnosing whether ACL or isolation changes still leave an internal host, port, or bounded protocol profile reachable. It will retain its versioned evidence model and shared CLI/Web service layer while moving its active target policy from general authorized diagnostics to a strictly private-network-only product.

The product is for operators investigating their own internal network during a controlled outage, segmentation change, or port-leak investigation. Its output must state what was observed for each direction and attempt; a timeout or silence is never proof that a port is closed.

## Core Value

Within an explicitly declared private-network scope, show reproducible evidence of the internal reachability that remains, including the uncertainty that prevents a definitive claim.

## Requirements

### Validated

- ✅ **BASE-01**: Passive local interface, route, DNS, neighbour, Wi-Fi, and direct-LLDP collection is available with typed capability evidence.
- ✅ **BASE-02**: The common task engine compiles immutable plans, admits exact steps, supports cancellation, and records versioned observations.
- ✅ **BASE-03**: CLI and Web UI call the same `MercuryApplication` service boundary; browser code does not probe the network.
- ✅ **BASE-04**: Local SQLite history and reports reject secret material and redact identifiers by default.
- ✅ **BASE-05**: Non-loopback peer control uses TLS, token authentication, certificate pinning, and a closed paired operation profile.
- ✅ **SCOPE-01..03**: Active destinations, resolved answers, profiles, peer configuration, CLI/Web guidance, and service entry points enforce the explicit private-only admission rule. *(Validated in Phase 1, 2026-08-02.)*

### Active

- [ ] Provide one private mapping request that accepts multiple internal CIDRs, finite transport/port profiles, rate, concurrency, and duration parameters.
- ✅ Use paired, correlation-bound Mercury receivers to witness inbound TCP, UDP, DNS, ICMP (where the platform can observe it), TLS, HTTP, SSH-banner, and local-link ARP/ND coverage profiles in both directions. *(Phase 2, 2026-08-02.)*
- ✅ Produce a tunnel-exposure coverage matrix that flags every tested carrier with positive arrival or reply evidence and lists every unavailable, skipped, and non-applicable profile. *(Phase 2, 2026-08-02.)*
- [ ] Optionally use the locally installed Nmap executable through a fixed, policy-derived adapter, never an arbitrary Nmap command line.
- [ ] Expose the same mapping service through CLI and Web UI while preserving peer trust controls, local evidence history, cancellation, redaction, and hard ceilings.
- [ ] Replace the deleted project plan with requirements, roadmap, phase state, and a codebase map that make the product pivot executable.

### Out of Scope

- Public-IP, Internet, or arbitrary DNS-name scanning — Mercury is restricted to local private ranges so the tool cannot be used as a general Internet scanner.
- Unattested or unscoped active work — a minimal explicit operator attestation and canonical target scope remain mandatory at the trust boundary.
- Unlimited time, rate, concurrency, host, port, event, byte, or output work — immutable aggregate ceilings protect the host and network even when the requested duration is `0`.
- Generic Nmap argv, NSE scripts, target-file imports, proxy/decoy options, raw packet crafting, or a remote scan relay — these would bypass Mercury's internal-only policy and evidence accounting.
- A claim that all possible tunnel mechanisms are absent — packet payloads and state sequences are unbounded, so the product must report the finite coverage matrix rather than a false universal negative.
- Credential, password, or login brute forcing — authentication probing is unrelated to reachability evidence and risks account harm.

## Context

- The existing product already has a strong evidence model: TCP refusal, timeout, UDP application reply, ICMP unreachable, silent, unsupported, permission denied, and execution error are distinct values.
- `src/mercury/discovery.py` currently offers one IPv4 CIDR and TCP-only profiles; `src/mercury/policy.py` currently permits public addresses when attested.
- The current README states that Mercury is not a scanner and includes public-profile examples. Both the implementation and documentation need a coordinated product-pivot migration.
- Nmap is installed at `D:\\Nmap\\nmap.exe` on this development system, but it is not currently a project dependency or integration.
- The user supplied a private peer test endpoint, but it is not recorded in project files and must not be contacted by automated tests or by this planning task.

## Constraints

- **Internal-only policy**: Active targets, CIDRs, scope grants, and post-resolution addresses must be loopback, RFC1918 IPv4, IPv6 ULA, or scoped IPv6 link-local — public and documentation ranges must fail before I/O.
- **Authorization boundary**: Retain a minimal explicit local attestation and declared containment check for non-loopback active work — repository instructions forbid dropping trust-boundary validation.
- **Resource safety**: Retain immutable aggregate host, port, attempt, rate, concurrency, duration, event, logical-byte, and output ceilings — repository instructions forbid unbounded scans.
- **Evidence integrity**: Preserve direction, timing, provenance, confidence, and distinct protocol outcomes — a reachability inference must not be rendered as fact.
- **Coverage assessment**: A positive peer-correlated arrival is a candidate carrier for tunnelling; a negative conclusion is limited to the emitted coverage matrix and must show its gaps.
- **Peer security**: Preserve non-loopback mTLS, token, pinning, replay protection, and the fixed peer-operation surface — a peer must not become an arbitrary scan proxy.
- **Stack**: CPython 3.11+, standard library plus `psutil`, `unittest`, semantic HTML/CSS/native JavaScript — no new framework or scanner package.
- **Native Nmap**: Treat Nmap as an optional OS capability whose fixed argv is created only from an admitted Mercury plan — no arbitrary operator flags or scripts.
- **Test safety**: Tests use fakes, fixtures, or loopback only — no test contacts the supplied peer or scans any real non-loopback target.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Reposition Mercury as an internal-network mapping tool | The target use case is ACL/isolation leak detection, not public endpoint diagnosis | Adopted in Phase 1 |
| Enforce private-only scope at the canonical policy layer | All presenters and future native adapters then receive the same rejection behavior | Adopted in Phase 1 |
| Keep a minimum attestation, audit trail, and immutable ceilings | These are mandatory repository trust and safety invariants; private address space alone does not establish authority | Pending |
| Interpret requested duration `0` as “no operator-selected early cutoff” within hard ceilings | Preserves scan-to-completion intent without offering an unbounded operation | Pending |
| Implement a peer-correlated coverage matrix | TCP, UDP, DNS, ICMP, TLS, HTTP, SSH-banner, local ARP/ND, and fixed native Nmap profiles need receiver-side evidence and directional results | Pending |
| Treat positive coverage as a tunnel-carrier finding, not a proof of a deployed tunnel | A confirmed carrier establishes bypass potential; no finite test proves every conceivable packet sequence absent | Pending |
| Make Nmap optional and policy-derived | The installed native binary can add value without becoming a generic command-execution bypass | Pending |
| Preserve peer mTLS and fixed peer destination rules | Peer-to-peer communication needs authenticated trust and must not enable third-party scanning | Pending |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition:**

1. Move validated requirements to the Validated list with their phase reference.
2. Move rejected requirements to Out of Scope with a reason.
3. Add newly discovered requirements to Active.
4. Record significant implementation decisions in Key Decisions.
5. Confirm that What This Is still accurately describes the shipped product.

**After each milestone:**

1. Review all requirements and evidence semantics.
2. Recheck the private-network-only boundary against every active entry point.
3. Audit exclusions to prevent a generic scanner or remote relay from creeping back in.
4. Refresh Context with supported platform, Nmap capability, and operator feedback findings.

---

*Last updated: 2026-08-02 after Phase 1 private-scope migration*
