---
phase: 02
plan: "03"
subsystem: diagnosis
tags: [profiles, resolver, tcp, tls, http, classifier, safety]
requires: [02-01, 02-02]
provides: [immutable-diagnosis-profiles, bounded-resolver, diagnosis-runner, health-classifier]
affects: [02-04, phase-03]
tech-stack:
  added: []
  patterns: ["frozen compiled diagnosis", "prepared numeric socket destination", "closed service-owned health conclusion"]
key-files:
  created:
    - tests/fixtures/tls/README.md
    - tests/fixtures/tls/test-ca.pem
    - tests/fixtures/tls/localhost-cert.pem
    - tests/fixtures/tls/localhost-key.pem
  modified:
    - src/mercury/profiles.py
    - src/mercury/resolver.py
    - src/mercury/probes.py
    - src/mercury/diagnosis.py
    - src/mercury/tasks.py
    - tests/test_profiles.py
    - tests/test_probes.py
    - tests/test_diagnosis.py
key-decisions:
  - "Diagnosis profiles compile only into the existing sparse ProbePlan; CompiledDiagnosis is a frozen validation and classifier-manifest companion."
  - "Protocol probes receive only TaskContext-admitted numeric PreparedStep destinations; hostnames remain logical DNS/SNI/Host identities."
  - "The TaskService owns the sole diagnosis-health derivation and preserves lifecycle failures as partial endpoint-scoped evidence."
requirements-completed: [DIAG-01, DIAG-02, DIAG-03, DIAG-04]
duration: "continued session"
completed: 2026-08-01
---

# Phase 02 Plan 03: Immutable profiles and bounded layered probes Summary

**Immutable basic/China/custom diagnosis plans now run bounded DNS, TCP, TLS, HTTP and optional native context through the canonical task lifecycle, ending in one evidence-linked endpoint health conclusion.**

## Performance

- **Duration:** continued across prior sessions
- **Completed:** 2026-08-01
- **Tasks:** 3/3
- **Files modified:** 13

## Accomplishments

- Added frozen `basic-v1`, `china-v1`, and strict custom `HOST:PORT` compilation with canonical targets and immutable required-group manifests.
- Isolated DNS resolution in the package-local helper and retained separate DNS, TCP, TLS, HTTP, timeout, refusal, reset, unreachable, verification, and error evidence.
- Rebound the canonical passive local snapshot into diagnosis execution and derived health solely in the closed `TaskService` terminal branch.
- Added committed test-only TLS CA/server fixtures with `localhost`, `127.0.0.1`, and `::1` SANs; no test depends on CPython's installation-private certificate files or test-time OpenSSL.
- Applied the aggregate monotonic task deadline to production DNS preflight and added resolver overflow/cancellation, source-boundary, and TCP failure regressions.

## Files Created/Modified

- `src/mercury/profiles.py` - immutable request/profile compilation and required-group validation.
- `src/mercury/resolver.py` and `src/mercury/_resolver_helper.py` - bounded isolated hostname resolution.
- `src/mercury/probes.py` - numeric prepared DNS/TCP/TLS/HTTP probe execution and cleanup.
- `src/mercury/diagnosis.py` and `src/mercury/tasks.py` - canonical runner and closed health classification path.
- `tests/test_profiles.py`, `tests/test_probes.py`, `tests/test_diagnosis.py` - hermetic profile, protocol, classifier, and lifecycle coverage.
- `tests/fixtures/tls/` - explicitly labelled loopback-only test CA and server material.

## Verification

- `python -m unittest tests.test_diagnosis tests.test_profiles tests.test_probes -q` — passed (31 tests).
- `python -m unittest tests.test_models tests.test_policy tests.test_tasks tests.test_inventory tests.test_diagnosis -q` — passed (95 tests).
- `python -m unittest discover -s tests -q` — passed (180 tests, 3 skipped).
- `python -m compileall -q src tests`, `ruff check src tests`, and `git diff --check` — passed.

## Commits

- `101c2f7` — immutable diagnosis profiles.
- `16048d9` — bounded protocol probes.
- `b26d6ff` through `3687d56` — service health branch, bindings, resolver classifications, TLS checks, manifest validation, and preflight helper use.
- `4cfeef3` — repository-owned TLS fixtures plus resolver/TCP and task-deadline regressions.

## Deviations from Plan

### Auto-fixed Issues

**[Rule 2 - Missing Critical] Committed portable TLS fixtures**

- **Found during:** Task 2 verification.
- **Issue:** The initial loopback TLS regression consumed CPython installation test data rather than repository-owned material.
- **Fix:** Added labelled test-only CA, certificate, and private key under `tests/fixtures/tls/`; the certificate carries DNS and both loopback IP SANs.
- **Verification:** Trusted and untrusted loopback TLS tests pass without using CPython certdata.
- **Committed in:** `4cfeef3`.

**Total deviations:** 1 auto-fixed (1 missing critical). **Impact:** closes a portability and reproducibility gap without adding a runtime dependency.

## Issues Encountered

None.

## Next Phase Readiness

02-04 can consume `CompiledDiagnosis`, `DiagnosisRunner`, `TaskService.submit_diagnosis`, and the fixed `diagnosis-health` conclusion without adding presentation-owned I/O or classification.

## Self-Check: PASSED

---
*Phase: 02-local-snapshot-and-layered-diagnosis*
*Completed: 2026-08-01*
