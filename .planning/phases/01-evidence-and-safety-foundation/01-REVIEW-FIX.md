---
phase: 1
fixed_at: 2026-07-29T21:25:54.2320740Z
review_path: .planning/phases/01-evidence-and-safety-foundation/01-REVIEW.md
iteration: 1
findings_in_scope: 18
fixed: 18
skipped: 0
status: all_fixed
---

# Phase 1: Code Review Fix Report

**Fixed at:** 2026-07-29T21:25:54.2320740Z  
**Source review:** `.planning/phases/01-evidence-and-safety-foundation/01-REVIEW.md`  
**Iteration:** 1

**Summary:**

- Findings in scope: 18
- Fixed: 18
- Skipped: 0

Semantic security, authorization, budget, cancellation, and state-machine
changes are marked as requiring human verification even though their focused
regressions and the complete test suite pass.

## Fixed Issues

### CR-01: Public plan objects bypass canonical authorization

**Status:** fixed: requires human verification  
**Files modified:** `src/mercury/cli.py`, `src/mercury/planner.py`,
`src/mercury/policy.py`, `src/mercury/tasks.py`, `tests/test_policy.py`,
`tests/test_tasks.py`  
**Commit:** 4c97cc5  
**Applied fix:** Added exact security-field validation and a shared canonical
plan-validation path that re-authorizes targets, recomputes costs and digests,
checks confirmations, and is invoked again at task submission.

### CR-02: Admission is not tied to finite authorized work

**Status:** fixed: requires human verification  
**Files modified:** `src/mercury/planner.py`, `src/mercury/tasks.py`,
`tests/test_policy.py`, `tests/test_tasks.py`  
**Commit:** 89d0cce  
**Applied fix:** Compiled requests into immutable finite probe steps with
scope, address, port, transport, attempt, and payload metadata; admission now
consumes each authorized step ID once and enforces preflight and I/O bounds.

### CR-03: Multicast, broadcast, and unspecified targets defeat host ceilings

**Status:** fixed: requires human verification  
**Files modified:** `src/mercury/policy.py`, `tests/test_policy.py`  
**Commit:** d1cdba3  
**Applied fix:** Rejected unspecified, multicast, limited-broadcast, and other
fan-out destinations during canonicalization and resolver-answer validation,
with IPv4 and IPv6 regression coverage.

### CR-04: Custom UDP confirmation is not bound to the payload

**Status:** fixed: requires human verification  
**Files modified:** `src/mercury/cli.py`, `src/mercury/planner.py`,
`src/mercury/tasks.py`, `tests/test_policy.py`  
**Commit:** 91e3f60  
**Applied fix:** Added approved UDP payload metadata (profile or length and
SHA-256) to finite steps and plan digests, derived the risk gate from that
metadata, and verified execution bytes without persisting raw payloads.

### CR-05: The hard output ceiling can be exceeded by a completed task

**Status:** fixed: requires human verification  
**Files modified:** `src/mercury/tasks.py`, `tests/test_tasks.py`  
**Commit:** 5cee7a7  
**Applied fix:** Bounded context collections and text at insertion, charged
the complete canonical result document against the output budget, and added a
bounded terminal fallback when the normal result cannot fit.

### CR-06: Finalization failures leave tasks permanently running

**Status:** fixed: requires human verification  
**Files modified:** `src/mercury/history.py`, `src/mercury/tasks.py`,
`tests/test_history.py`, `tests/test_tasks.py`  
**Commit:** 92f127c  
**Applied fix:** Guarded the complete terminalization path, added atomic
terminal event/state/result persistence, retained validated partial evidence
in a minimal failure fallback, and guaranteed in-memory cleanup.

### CR-07: Real task cancellation does not persist a cancelled partial result

**Status:** fixed: requires human verification  
**Files modified:** `src/mercury/cli.py`, `src/mercury/tasks.py`,
`tests/test_cli.py`, `tests/test_tasks.py`  
**Commit:** 52b6304  
**Applied fix:** Converted external `asyncio` cancellation into durable
cancelled finalization, shielded persistence from repeated cancellation, and
made the CLI await the persisted partial result before returning.

### CR-08: Arbitrary history mappings still persist credentials and raw content

**Status:** fixed: requires human verification  
**Files modified:** `src/mercury/history.py`, `src/mercury/tasks.py`,
`tests/test_history.py`, `tests/test_tasks.py`  
**Commit:** 14da19c  
**Applied fix:** Replaced arbitrary persistence with typed allowlisted
projections, centralized recursive secret detection and sanitization, reduced
payloads to metadata, and covered nested and compound credential bypasses.

### CR-09: Frozen canonical models accept mutable and unserializable values

**Status:** fixed  
**Files modified:** `src/mercury/models.py`, `tests/test_models.py`  
**Commit:** 1b2385d  
**Applied fix:** Enforced exact enum, model, scalar, and counter types in
canonical constructors, rejected booleans as integers, normalized sequences to
tuples, and added direct-constructor adversarial tests.

### CR-10: Terminal synthesis records evidence that contradicts execution

**Status:** fixed: requires human verification  
**Files modified:** `src/mercury/planner.py`, `src/mercury/tasks.py`,
`tests/test_tasks.py`  
**Commit:** 11c0606  
**Applied fix:** Separated task-level terminal evidence from probe progress and
always derived a truthful terminal summary so runner conclusions cannot
override failed or cancelled task state.

### CR-11: A custom history path changes permissions on its parent directory

**Status:** fixed  
**Files modified:** `src/mercury/history.py`, `tests/test_history.py`  
**Commit:** 2267be5  
**Applied fix:** Tightened permissions only on Mercury-created private
directories and preserved existing explicit parent-directory permissions while
creating the database with owner-only file access.

### WR-01: Authorized DNS rotation is rejected even when every new address is in scope

**Status:** fixed: requires human verification  
**Files modified:** `src/mercury/policy.py`, `tests/test_policy.py`  
**Commit:** 90e2f2f  
**Applied fix:** Allowed DNS answers to rotate within the authorized network
while continuing to reject any current resolver answer that escapes scope.

### WR-02: History permits illegal and internally inconsistent terminal transitions

**Status:** fixed: requires human verification  
**Files modified:** `src/mercury/__init__.py`, `src/mercury/history.py`,
`src/mercury/tasks.py`, `tests/test_contracts.py`, `tests/test_history.py`,
`tests/test_tasks.py`  
**Commit:** e30dccc  
**Applied fix:** Added schema-v2 owner/lease lifecycle fields, restricted normal
completion to compatible running tasks, and made expired foreign-task recovery
an atomic structured terminal transition.

### WR-03: Max-age retention is not enforced until a caller explicitly prunes

**Status:** fixed: requires human verification  
**Files modified:** `src/mercury/history.py`, `tests/test_history.py`  
**Commit:** c87b629  
**Applied fix:** Enforced retention during store initialization and before
history reads and listings while preserving live tasks.

### WR-04: Oversized JSON integers escape the codec error contract

**Status:** fixed  
**Files modified:** `src/mercury/codec.py`, `tests/test_models.py`  
**Commit:** 0c0801e  
**Applied fix:** Added bounded integer parsing and translated integer-limit
failures into the stable `CodecError` contract.

### WR-05: Versioning is duplicated and rejects compatible minor documents

**Status:** fixed  
**Files modified:** `pyproject.toml`, `src/mercury/__init__.py`,
`src/mercury/codec.py`, `src/mercury/models.py`, `src/mercury/planner.py`,
`tests/test_contracts.py`, `tests/test_models.py`  
**Commit:** 3ada82c  
**Applied fix:** Centralized package and schema versions, reused the schema
constant in plan serialization, and accepted documented compatible `1.x`
documents while rejecting unsupported major versions.

### WR-06: Argparse failures bypass stable structured CLI errors

**Status:** fixed  
**Files modified:** `src/mercury/cli.py`, `tests/test_cli.py`  
**Commit:** 338e0d1  
**Applied fix:** Routed parser errors through `CliError`, preserved normal
help/version exits, and emitted stable JSON errors when JSON mode was requested.

### WR-07: Phase acceptance tests omit the adversarial contract surface

**Status:** fixed  
**Files modified:** `src/mercury/tasks.py`, `tests/test_contracts.py`,
`tests/test_installation.py`, `tests/test_models.py`, `tests/test_policy.py`,
`tests/test_tasks.py`  
**Commit:** 46f9c1d  
**Applied fix:** Added complete enum and budget boundary tables, forged-plan,
target, payload, model, cancellation, history, evidence-binding, and
clean-wheel console/module parity regressions.

---

_Fixed: 2026-07-29T21:25:54.2320740Z_  
_Fixer: the agent (gsd-code-fixer)_  
_Iteration: 1_
