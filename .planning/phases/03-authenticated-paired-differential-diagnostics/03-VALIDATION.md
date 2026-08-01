---
phase: 03
slug: authenticated-paired-differential-diagnostics
status: complete
nyquist_compliant: true
wave_0_complete: true
created: 2026-08-01
---

# Phase 03 — Validation Strategy

## Test Infrastructure

| Property | Value |
|---|---|
| **Framework** | `unittest` / `IsolatedAsyncioTestCase` |
| **Config file** | none |
| **Quick run command** | `python -m unittest tests.test_peer tests.test_paired -v` |
| **Full suite command** | `python -m unittest discover -s tests -v` |
| **Estimated runtime** | under 60 seconds |

## Sampling Rate

- **After every task commit:** Run `python -m unittest tests.test_peer tests.test_paired -v` once Wave 0 exists.
- **After every plan wave:** Run `python -m unittest discover -s tests -v`.
- **Before verification:** Run the full suite, `python -m compileall -q src tests`, `ruff check src tests`, and `git diff --check`.
- **Max feedback latency:** 60 seconds.

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---|---|---|---|---|---|---|---|---|---|
| 03-01-01 | 01 | 1 | SAFE-05, PEER-01 | T-03-01 | mTLS/pin/token/startup/frame/replay rejection; no secret persistence | unit + loopback | `python -m unittest tests.test_peer -v` | Wave 0 | pending |
| 03-02-01 | 02 | 2 | PEER-02, PEER-05, PEER-06 | T-03-02 | leased finite listeners reject expired, unbound or arbitrary-source work; UDP silence stays inconclusive | integration | `python -m unittest tests.test_paired.ListenerLeaseTests tests.test_paired.SourceBindingTests tests.test_paired.UdpProfileTests -v` | Wave 0 | pending |
| 03-03-01 | 03 | 3 | PEER-03, PEER-04 | T-03-03 | role swap emits cited A→B/B→A matrix and preserves DNS/refusal/timeout/asymmetry distinctions | integration | `python -m unittest tests.test_paired.MatrixTests tests.test_cli -v` | Wave 0 | pending |

## Wave 0 Requirements

- [ ] `tests/test_peer.py` — static test-only mTLS fixture coverage; strict frame, token/pin, replay/expiry and redaction tests.
- [ ] `tests/test_paired.py` — controlled TCP/UDP lease, source-binding, silence, role-swap and matrix tests.
- [ ] `tests/fixtures/tls/peer-client-cert.pem` and `tests/fixtures/tls/peer-client-key.pem` — repository-owned mTLS client fixture, generated once rather than during tests.
- [ ] Injected wall/monotonic clock and stream/datagram seams in the peer service for deterministic expiry/replay/silence tests.

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|---|---|---|---|
| Two-machine authenticated smoke | SAFE-05, PEER-01 through PEER-06 | Requires the user-authorized Ubuntu endpoint and ephemeral credentials; it must not run in CI. | After all automated gates pass, provision temporary restrictive-permission configuration on the paired Windows/Ubuntu hosts, run only the documented pair profile against the explicit peer address, sanitize the artifact, then remove temporary remote files. |

## Validation Sign-Off

- [x] All tasks have automated verification or Wave 0 dependencies.
- [x] Sampling continuity permits no three unverified tasks.
- [x] Wave 0 covers each currently missing peer test/fixture.
- [x] No watch-mode flags are used.
- [x] Feedback latency target is below 60 seconds.
- [x] `nyquist_compliant: true` is set in frontmatter.

**Approval:** completed 2026-08-02 with uv-managed Windows verification and a user-authorized Ubuntu mTLS smoke.
