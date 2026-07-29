---
phase: 02
slug: local-snapshot-and-layered-diagnosis
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-07-30
---

# Phase 02 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Python standard-library `unittest` |
| **Config file** | none |
| **Quick run command** | `python -m unittest tests.test_inventory tests.test_platforms tests.test_profiles tests.test_probes tests.test_diagnosis -q` |
| **Full suite command** | `python -m unittest discover -s tests -q` |
| **Estimated runtime** | quick target under 30 seconds; full suite about 60 seconds after Phase 2 |

The pre-phase editable-install baseline is 115 passing tests with three
Windows-inapplicable POSIX permission skips. Automated tests must use injected
resolvers/connectors/subprocesses, static platform fixtures, and loopback
servers only. They must never resolve, connect, ping, or trace a built-in public
profile target.

---

## Sampling Rate

- **After every task commit:** Run the narrow test module(s) named in the task,
  plus `tests.test_policy` and `tests.test_tasks` whenever plan/admission code
  changes.
- **After every plan wave:** Run `python -m unittest discover -s tests -q`,
  `python -m compileall -q src tests`, Ruff, and `git diff --check`.
- **Before `$gsd-verify-work`:** The full suite, clean wheel/temporary-venv
  entry-point parity, and controlled loopback smoke must be green.
- **Max feedback latency:** 90 seconds.

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 02-01-01 | 01 | 1 | INVT-01, INVT-02 | T02-07, T02-08 | Bounded normalized facts; missing fields are unavailable, never fabricated | unit | `python -m unittest tests.test_inventory -q` | ❌ W0 | ⬜ pending |
| 02-01-02 | 01 | 1 | INVT-03 | T02-01, T02-07, T02-10 | Fixed argv/scripts, bounded output, independent route/DNS degradation, no switch inference | unit/fixture | `python -m unittest tests.test_platforms -q` | ❌ W0 | ⬜ pending |
| 02-02-01 | 02 | 2 | DIAG-01, DIAG-03 | T02-04, T02-05 | Digest-bound sparse probe identity; no Cartesian spill or dummy port/transport | contract/adversarial | `python -m unittest tests.test_models tests.test_policy tests.test_tasks tests.test_diagnosis -q` | partial | ⬜ pending |
| 02-02-02 | 02 | 2 | DIAG-01, DIAG-02, DIAG-03 | T02-02, T02-03, T02-06, T02-09 | Exact authorized addresses, numeric connect, no redirects, bounded cancellation, no public tests | unit/loopback | `python -m unittest tests.test_profiles tests.test_probes -q` | ❌ W0 | ⬜ pending |
| 02-02-03 | 02 | 2 | DIAG-04 | T02-04, T02-10 | Health derives only from cited selected-target evidence; silence remains partial | table-driven unit | `python -m unittest tests.test_diagnosis -q` | ❌ W0 | ⬜ pending |
| 02-03-01 | 03 | 3 | INVT-01, DIAG-04 | T02-08 | CLI delegates to the facade; human/JSON share one result and stable 0/4/1 exits | CLI integration | `python -m unittest tests.test_cli -q` | ✅ extend | ⬜ pending |
| 02-03-02 | 03 | 3 | INVT-01–03, DIAG-01–04 | T02-01–10 | Fixture and loopback coverage proves every semantic state without public traffic | controlled integration | `python -m unittest tests.test_inventory tests.test_platforms tests.test_profiles tests.test_probes tests.test_diagnosis tests.test_cli -q` | ❌ W0 | ⬜ pending |
| 02-03-03 | 03 | 3 | INVT-01–03, DIAG-01–04 | T02-08, T02-09 | Installed console/module parity and passive native smoke retain the same contract | packaging/smoke | `python -m unittest tests.test_installation -q` | ✅ extend | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

Task IDs are the expected roadmap decomposition. The planner must update this
map if it creates a different task split; every final task still needs an
automated command or an explicit Wave 0 dependency.

---

## Required Test Matrix

1. **Schema and plan identity**
   - Read supported `1.0` history under the new reader and round-trip `1.1`.
   - Reject unknown future minors and unknown probe/evidence kinds.
   - Changing probe kind, target/address, SNI, port/transport, timeout, hop cap,
     attempt, or cost changes the step ID/digest.
   - DNS/ping/path have no fabricated port or TCP/UDP transport.
2. **Authoritative execution**
   - Wrong probe label, evidence kind, target, attempt, or reserved detail is
     rejected.
   - Multi-hop maximum observations/events/output are reserved before I/O.
   - Cancellation closes sockets and kills/reaps native subprocesses.
3. **Passive inventory**
   - Independent host, psutil addresses/stats, route, and DNS success/failure.
   - Unicode aliases, multiple addresses/defaults/DNS servers, tunnels,
     missing prefix/MAC/speed, malformed/truncated/oversized native output.
   - Gateway, route hop, and access-switch-not-observable remain distinct.
4. **Protocol evidence**
   - DNS answer/NXDOMAIN/temporary/timeout.
   - TCP connect/refuse/reset/unreachable/timeout.
   - TLS verified, certificate/hostname rejection, other handshake failure.
   - HTTP 200/204/301/404/500 all prove an exchange; malformed/oversized
     response fails visibly; redirects are never followed.
   - Native reply, explicit unreachable, silence, unanswered/responding hops,
     complete/incomplete path, missing tool, permission, timeout, parse error.
5. **Profiles, classification, and CLI**
   - Exact immutable `basic-v1`/`china-v1` operations and strict `HOST:PORT`.
   - IPv6 brackets and scope, duplicate canonicalization, timeout finite/range.
   - Healthy, failed, mixed, missing-layer, unavailable-only, silence-only,
     cancelled, and engine-failed cases cite the right observations.
   - Human and JSON project one `TaskResult`; exits are healthy 0, failed 1,
     partial 4, with existing policy/usage/internal codes unchanged.

---

## Wave 0 Requirements

- [ ] `tests/test_inventory.py` — INVT-01/02 passive facts and degradation.
- [ ] `tests/test_platforms.py` — INVT-03 Windows/Linux/macOS parsers and
  command boundaries.
- [ ] `tests/fixtures/platform/windows/*` — Unicode, combined route metrics,
  multiple/default routes, DNS sources, missing/error/overflow.
- [ ] `tests/fixtures/platform/linux/*` — `ip -j`, resolv.conf/stub, IPv4/IPv6,
  missing/error/overflow.
- [ ] `tests/fixtures/platform/macos/*` — route/netstat/scutil IPv4/IPv6/scoped
  DNS, missing/error/overflow.
- [ ] `tests/test_profiles.py` — DIAG-01/02 exact profiles, targets, timeouts.
- [ ] `tests/test_probes.py` — DIAG-03 protocol/native outcome matrix.
- [ ] `tests/test_diagnosis.py` — sparse plan and D-17 health classifier.
- [ ] `tests/fixtures/tls/*` — clearly labeled test-only CA/server material
  excluded from package data and never persisted.
- [ ] Extend `tests/test_cli.py` and `tests/test_installation.py` for DIAG-04.

No framework installation is needed. Each implementation task creates its test
file/fixture before or with the behavior it verifies.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Native Windows passive snapshot | INVT-01–03 | Real adapters, Unicode names, VPN/TUN and effective OS data cannot be proven by fixtures alone | As an ordinary user, run `mercury status --json`; verify host/interfaces/default routes/DNS have provenance and the switch is explicitly not observable. This sends no packets. |
| Native Linux/macOS snapshot command availability | INVT-01–03 | Current executor is Windows | Run the same passive command on release-matrix runners; compare normalized facts with native commands and retain degradation. This remains a Phase 5 release gate if runners are unavailable now. |
| Built-in public endpoint suitability | DIAG-01, DIAG-02 | Automated public traffic is forbidden and endpoint reachability is regional/time-dependent | Only an explicitly authorized operator may run `basic-v1`/`china-v1`; verify output claims only selected endpoints/layers. Endpoint validation never blocks controlled automated correctness. |

---

## Validation Sign-Off

- [ ] All final tasks have `<automated>` verification or Wave 0 dependencies.
- [ ] Sampling continuity: no three consecutive tasks lack automated feedback.
- [ ] Wave 0 creates every missing test/fixture before dependent behavior.
- [ ] No watch-mode flags or public/unowned network operations.
- [ ] Feedback latency remains below 90 seconds.
- [ ] All applicable HIGH threats have adversarial automated checks.
- [ ] `nyquist_compliant: true` and `wave_0_complete: true` are set after plans
  and tests are finalized.

**Approval:** pending plan-checker and implementation verification
