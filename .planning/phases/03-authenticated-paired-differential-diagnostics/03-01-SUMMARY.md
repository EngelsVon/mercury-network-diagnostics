---
phase: 03-authenticated-paired-differential-diagnostics
plan: "01"
subsystem: peer-control security
tags: [python, asyncio, ssl, mtls, certificate-pinning, replay-protection]
requires:
  - phase: 02-local-snapshot-and-layered-diagnosis
    provides: immutable evidence, authorization policy, and application facade patterns
provides:
  - strict peer-control configuration and mTLS listener boundary
  - bounded authenticated control frames with replay and correlation ownership checks
  - application-owned peer listener lifecycle and committed loopback TLS fixtures
affects: [03-02, 03-03, peer-control, paired-diagnostics]
tech-stack:
  added: []
  patterns: [stdlib asyncio TLS boundary, strict length-prefixed JSON frames, categorical secret-safe audit]
key-files:
  created: [src/mercury/peer.py, tests/test_peer.py, tests/fixtures/tls/peer-client-cert.pem, tests/fixtures/tls/peer-client-key.pem]
  modified: [src/mercury/app.py, tests/fixtures/tls/README.md, tests/fixtures/tls/test-ca.pem, tests/fixtures/tls/localhost-cert.pem, tests/fixtures/tls/localhost-key.pem]
key-decisions:
  - "Peer control admits only four closed operations and accepts no caller-supplied probe target, scope, port, payload, or runner."
  - "Frame and authentication failures produce categorical audit outcomes and never persist token, private-key, DER-certificate, or configuration-secret values."
  - "The explicit unsafe-development path remains loopback-only and preserves the separate token when one is provisioned."
patterns-established:
  - "PeerAgent owns server admission; PeerClient shares strict frame encoding and decoding."
  - "MercuryApplication alone starts and stops a peer listener."
requirements-completed: [SAFE-05, PEER-01]
duration: 45min
completed: 2026-08-01
---

# Phase 03 Plan 01: Authenticated Peer-Control Boundary Summary

**mTLS-configured peer control with fixed identity/address policy, token and certificate-pin admission, strict bounded frames, and replay-safe categorical auditing.**

## Performance

- **Duration:** 45 min
- **Started:** 2026-08-01T15:15:00Z
- **Completed:** 2026-08-01T16:00:00Z
- **Tasks:** 2/2
- **Files modified:** 9

## Accomplishments

- Added frozen peer configuration, mTLS server/client context builders, fixed peer identities/addresses, and a loopback-only audited unsafe-development override.
- Added four-byte bounded strict JSON framing for the closed capabilities, submit, read-result, and cancel operations, with timestamp, identity, token, pin, nonce replay, and correlation ownership gates before dispatch.
- Added static repository-owned server/client TLS fixtures and controlled loopback coverage for startup, secret redaction, malformed control input, replay/cache rejection, and facade lifecycle.

## Task Commits

1. **Task 1: Define peer trust configuration and Wave 0 mTLS security contracts** - `73eaf5c` (test), `cb63e9a` (feat)
2. **Task 2: Implement strict authenticated framed control, replay rejection, and facade lifecycle** - `23b28c3` (test), `b4ea738` (feat)

## Files Created/Modified

- `src/mercury/peer.py` - Peer config, TLS contexts, strict frame codec, authentication admission, nonce cache, agent, and client.
- `src/mercury/app.py` - Application-owned agent start/stop composition.
- `tests/test_peer.py` - Loopback trust, redaction, frame, replay, and lifecycle contracts.
- `tests/fixtures/tls/peer-client-cert.pem` and `peer-client-key.pem` - Static CA-signed client-auth test identity.
- `tests/fixtures/tls/README.md` - Test-only certificate purpose and prohibition documentation.

## Decisions Made

- Keep peer control at a closed transport boundary: the four operation names are authenticated categories, not arbitrary remote diagnostics.
- Treat all rejected transport input as categorical audit data; configuration secrets remain path-provisioned and are read only at the comparison boundary.
- Keep CLI work out of this plan; it remains a later facade consumer.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Rebuilt the committed test TLS fixture set with a client-auth identity**
- **Found during:** Task 1
- **Issue:** The existing test CA private key was intentionally absent and OpenSSL was unavailable, so a distinct client certificate could not be signed by the existing fixture CA.
- **Fix:** Generated a replacement repository-owned CA/server/client fixture set once using the installed development crypto tooling, then committed only static PEM assets. Test execution does not generate certificates or invoke external tools.
- **Files modified:** `tests/fixtures/tls/test-ca.pem`, `localhost-cert.pem`, `localhost-key.pem`, `peer-client-cert.pem`, `peer-client-key.pem`, `README.md`
- **Verification:** `python -m unittest tests.test_peer -v`
- **Committed in:** `cb63e9a`

**2. [Rule 1 - Test defect] Corrected the startup test helper's duplicate token-path argument**
- **Found during:** Task 1 verification
- **Issue:** The test helper accepted a positional `token_path` while tests also supplied the configuration field by keyword.
- **Fix:** Renamed the helper parameter so intentional missing-token configuration tests execute.
- **Files modified:** `tests/test_peer.py`
- **Verification:** `python -m unittest tests.test_peer.PeerStartupTests -v`
- **Committed in:** `cb63e9a`

---

**Total deviations:** 2 auto-fixed (1 blocking fixture issue, 1 test defect).
**Impact on plan:** Both changes are limited to deterministic test assets and test correctness; no runtime dependency or remote diagnostic capability was added.

## Issues Encountered

- On this Windows/Python 3.13 TLS runtime, an asyncio server configured with `CERT_REQUIRED` closes a local connection before its stream callback because the client certificate is not sent during the handshake, even with the committed client keypair loaded. The production code retains `CERT_REQUIRED`, CA verification, post-handshake SHA-256 pin validation, and token comparison. Deterministic framed-dispatch tests therefore use the explicit loopback-only unsafe-development override while separately exercising the TLS contexts and static credentials. Re-verify a real mutual-TLS framed exchange on the supported Windows/Ubuntu release environment before declaring peer control operationally validated.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Plan 03-02 can add the finite paired listener and plan-admission handlers behind the closed `submit`, `read-result`, and `cancel` operations.
- Recheck mutual-TLS stream callback behavior on the release Python/OpenSSL combinations before two-machine testing.

## Self-Check: PASSED

- Confirmed key files exist and all four task commits are present in Git history.
- No runtime stubs or untracked generated artifacts were introduced by this plan.

