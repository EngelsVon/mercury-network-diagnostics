# Codebase Concerns

**Analysis Date:** 2026-08-02

## Product-Scope Mismatch

**Current public-capable policy:**

- Issue: `src/mercury/policy.py` permits any non-multicast address or CIDR that an operator attests and includes in a `ScopeGrant`; built-in diagnosis profiles in `src/mercury/profiles.py` and `README.md` include public targets.
- Impact: this conflicts with the requested internal-network-only product positioning.
- Safe modification: add a canonical private-network admission rule that is enforced on literal targets, CIDRs, scope grants, DNS answers, trace targets, and any future native adapter before a socket/subprocess is started.

**Single-range TCP discovery request:**

- Issue: `DiscoveryRequest` in `src/mercury/discovery.py` accepts exactly one IPv4 CIDR and a fixed TCP profile.
- Impact: it cannot represent a consolidated multi-range internal mapping job, an operator-selected rate, or an explicit duration policy.
- Safe modification: introduce one immutable scan request/plan type while retaining `TaskService` as the only executor.

## Security Considerations

**Plan, budget, and scope protections are core invariants:**

- Risk: bypassing `ScopeGrant`, `PlanPreview`, `TaskService`, or their ceilings would allow presentation code or a native tool to create untracked, unbounded work.
- Current mitigation: `src/mercury/planner.py` creates digest-bound plans and `src/mercury/tasks.py` validates/admit steps.
- Recommendation: extend these values for internal mapping rather than add a parallel scanner. Do not implement an unlimited value or an arbitrary Nmap argument pass-through.

**Peer control is deliberately closed:**

- Risk: changing `src/mercury/peer.py` to accept a generic scan destination would turn a trusted peer into a third-party scan relay.
- Current mitigation: peer profiles are preconfigured, token-gated, mutually authenticated, and pin certificates.
- Recommendation: retain mTLS, token, replay protection, and fixed endpoint constraints even if local scan UX is simplified.

**Nmap is present but not integrated:**

- Risk: a generic shell-out would permit Nmap scripts, file imports, proxy/decoy flags, or targets that bypass Mercury policy.
- Current mitigation: no source module invokes Nmap today.
- Recommendation: if implemented, build a fixed argv from a validated internal plan and parse only bounded XML output.

## Evidence-Model Gaps

**Current discovery is TCP connection only:**

- Files: `src/mercury/discovery.py` and `src/mercury/probes.py`.
- Impact: the current UI cannot report an internal-map job as a distinct task with scan-wide metadata, multi-range provenance, or native-tool evidence.
- Safe modification: add only evidence kinds with precise semantics; keep TCP refusal, UDP response, ICMP unreachable, timeout, and silence distinct.

## Fragile Areas

**Versioned model and codec coupling:**

- Files: `src/mercury/models.py`, `src/mercury/codec.py`, `src/mercury/tasks.py`, and `tests/test_models.py`.
- Why fragile: a new evidence kind or result field affects enum compatibility, JSON conversion, task admissibility, renderers, reports, and tests.
- Safe modification: make schema changes in one phase with round-trip compatibility tests and explicit provenance fields.

**Documentation contains now-obsolete claims:**

- Files: `README.md` and `src/mercury/cli.py` help text.
- Why fragile: they currently describe Mercury as not a scanner and give public-profile examples.
- Safe modification: update prose and examples only after runtime enforcement and tests are in place, so docs cannot promise an unsafe mode.

## Test Coverage Gaps

**No Nmap adapter tests exist:**

- Risk: argv construction or XML parsing could silently escape policy or mislabel a native result.
- Priority: high if optional Nmap support is introduced.
- Approach: unit-test fixed argv, invalid range rejection, bounded XML size, and parser mappings with stored fixtures.

**No internal-only admission matrix exists:**

- Risk: one entry point could retain public or hostname-escape behavior while another rejects it.
- Priority: high for the product pivot.
- Approach: test the same private-address classifier through policy, discovery, trace, CLI, Web, and native-adapter entry points.

---

*Concerns audit: 2026-08-02*
*Update as the internal-mapping pivot is implemented*
