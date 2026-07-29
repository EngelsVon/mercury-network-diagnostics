---
phase: 01-evidence-and-safety-foundation
reviewed: 2026-07-29T19:38:05Z
depth: deep
files_reviewed: 20
files_reviewed_list:
  - pyproject.toml
  - README.md
  - src/mercury/__init__.py
  - src/mercury/__main__.py
  - src/mercury/models.py
  - src/mercury/codec.py
  - src/mercury/history.py
  - src/mercury/policy.py
  - src/mercury/planner.py
  - src/mercury/tasks.py
  - src/mercury/render.py
  - src/mercury/cli.py
  - tests/__init__.py
  - tests/helpers.py
  - tests/test_models.py
  - tests/test_history.py
  - tests/test_policy.py
  - tests/test_tasks.py
  - tests/test_cli.py
  - tests/test_contracts.py
findings:
  critical: 11
  warning: 7
  info: 0
  total: 18
status: issues_found
---

# Phase 1: Code Review Report

**Reviewed:** 2026-07-29T19:38:05Z  
**Depth:** deep  
**Files Reviewed:** 20  
**Status:** issues_found

## Summary

The package is small and its normal-path tests are readable, but the safety
foundation is not ready to support active probes. The deep review found eleven
release blockers: authorization objects can be forged, work admission is not
bound to finite authorized steps, fan-out destinations bypass the host model,
custom UDP confirmation is not payload-bound, output ceilings can be exceeded,
terminalization and interruption lose partial results, persistence filtering
still leaks secrets, canonical models accept invalid mutable values, terminal
evidence can contradict reality, and an explicit history path can change
permissions on an unrelated directory.

The import/call graph was traced across policy -> planner -> task service ->
history/codec and CLI/rendering. The socket-boundary DNS helper has no enforced
caller in the task path, while terminal state/event/result updates span
separate transactions.

Verification performed:

- `python -m unittest discover -s tests -v` fails in a clean, uninstalled
  checkout because the `src` package is not on `sys.path`.
- With `PYTHONPATH=src`, all 55 tests pass (one POSIX permission test is skipped
  on Windows).
- `python -m pip wheel . --no-deps --no-build-isolation` builds the wheel.
- Focused adversarial scripts reproduced the authorization, output-budget,
  interruption, model-mutability, persistence, DNS-rotation, and history
  consistency failures described below.

## Critical Issues

### CR-01 [BLOCKER]: Public plan objects bypass canonical authorization

**Files:** `src/mercury/policy.py:30`, `src/mercury/policy.py:75`,
`src/mercury/planner.py:99`, `src/mercury/planner.py:117`,
`src/mercury/planner.py:165`, `src/mercury/planner.py:439`

**Issue:** `Target`, `WorkEstimate`, `PlanPreview`, and `ProbePlan` are public
constructors without invariant checks. `ScopeGrant.attested` is not required to
be an actual boolean. `authorize_plan()` checks only confirmation strings and
scope expiry; it does not re-authorize targets, recompute cost, validate the
digest, or prove that `preview_plan()` created the object. A manually
constructed preview for `203.0.113.9`, with an empty unattested scope and an
attacker-controlled digest, is accepted. Likewise,
`ScopeGrant(attested="false")` is treated as attested because the string is
truthy. This defeats SAFE-02/SAFE-03 before any future runner is considered.

**Fix:** Make unsafe construction impossible at the service boundary. Validate
exact field types in every security dataclass, keep raw preview constructors
private, and add one `validate_plan()` path that re-canonicalizes targets,
re-authorizes them, recomputes cost and digest, and validates confirmations.
Call it from both `authorize_plan()` and `TaskService.submit()`.

### CR-02 [BLOCKER]: Admission is not tied to finite authorized work

**Files:** `src/mercury/policy.py:75`, `src/mercury/planner.py:117`,
`src/mercury/planner.py:183`, `src/mercury/tasks.py:110`,
`src/mercury/tasks.py:141`

**Issue:** The required finite `PlanStep` model does not exist. `ScopeGrant`
cannot constrain ports or transports. `TaskContext.admit()` accepts an
arbitrary caller-supplied string rather than a planned address/port/transport
step, so aliases can evade per-target rate tracking. DNS preflight and I/O
accounting are optional runner calls, not enforced boundaries. The new
`preflight_addresses()` helper is not called by `TaskService`; additionally, a
network target is rejected and any expanded address is also rejected because
it is not equal to the original network target. A runner can therefore act
before `admit()`, omit `account_io()`, choose an unplanned destination, or fail
to recheck DNS without the service detecting it.

**Fix:** Compile targets into immutable concrete steps containing address,
scope ID, port, transport, attempt number, and payload profile/hash. Add ports
and transports to `ScopeGrant`. Admit only a step ID, and have the core
executor—not individual probe implementations—perform DNS/address preflight,
rate admission, concurrency acquisition, and I/O accounting before passing
validated socket parameters to an adapter.

### CR-03 [BLOCKER]: Multicast, broadcast, and unspecified targets defeat host ceilings

**Files:** `src/mercury/policy.py:153`, `src/mercury/policy.py:186`,
`src/mercury/planner.py:312`, `src/mercury/cli.py:221`

**Issue:** Destination policy accepts `0.0.0.0`, `::`, IPv4/IPv6 multicast, and
`255.255.255.255`. The CLI then copies literal targets into the grant, and the
planner counts each as one host. Adversarial CLI previews for `224.0.0.1`,
`ff02::1`, and the limited broadcast address all exited successfully with
`hosts: 1` and no extra confirmation. One UDP datagram can reach multiple
receivers, so the immutable host/rate model no longer describes the work.

**Fix:** Reject unspecified, multicast, and limited-broadcast destinations in
the canonical address policy, including resolver answers. If multicast is ever
added, make it a separately authorized finite profile with explicit fan-out
semantics and budgeting; do not treat a group as one host.

### CR-04 [BLOCKER]: Custom UDP confirmation is not bound to the payload

**File:** `src/mercury/planner.py:117`, `src/mercury/planner.py:278`,
`src/mercury/planner.py:386`

**Issue:** The plan contains only `payload_bytes_per_attempt` and a caller
boolean. No payload bytes, built-in profile ID, or payload digest is represented
in the immutable plan. Two different custom payloads of the same length
therefore produce the same plan digest and confirmation phrase. A later runner
has no value against which to verify the bytes it sends.

**Fix:** Represent UDP content as either a fixed built-in profile identifier or
`{length, sha256}` metadata in each finite step. Include that metadata in the
plan digest, derive the custom-risk gate from it, and compare the execution
bytes to the approved hash. Persist only metadata, never the raw payload.

### CR-05 [BLOCKER]: The hard output ceiling can be exceeded by a completed task

**Files:** `src/mercury/tasks.py:160`, `src/mercury/tasks.py:189`,
`src/mercury/tasks.py:512`

**Issue:** Output accounting measures only encoded observations.
`requested_config`, effective configuration, conclusions, capabilities,
errors, collection framing, and the rest of the final document are not
charged. `add_conclusion()` and `add_capability()` have no count or byte bound.
An adversarial one-step task with `max_output_bytes=5000` completed and
persisted a 9,824-byte result. This directly violates the non-bypassable
SAFE-02 output ceiling.

**Fix:** Account the complete canonical wire document, including base fields
and every collection member. Bound conclusion/capability/error counts and text
at insertion. Before committing terminal state, encode once and reject or
truncate through a documented bounded fallback if the final byte count exceeds
the plan ceiling.

### CR-06 [BLOCKER]: Finalization failures leave tasks permanently running

**Files:** `src/mercury/tasks.py:456`, `src/mercury/tasks.py:512`,
`src/mercury/tasks.py:532`, `src/mercury/history.py:298`

**Issue:** Only `await runner(context)` is inside the error conversion block.
Result construction, terminal event insertion, secret validation, SQLite
finalization, and in-memory cleanup are outside it and are not one transaction.
A runner that raises a 5,000-character error is caught, but the unbounded
`context.errors` entry makes `TaskResult` raise `ModelError`; history remains
`running` with no result. Duplicate observation IDs, invalid conclusions,
secret-shaped result fields, clock anomalies, and storage errors fail the same
way. Accepted/running/terminal events and state changes can also disagree after
a mid-sequence failure.

**Fix:** Validate and bound data when it enters `TaskContext`, sanitize/truncate
exception text, and wrap the entire terminalization path in a guarded
`try/finally`. Add one HistoryStore transaction that writes the terminal event,
state, and result atomically. If normal result construction fails, persist a
minimal valid failed result while retaining already validated evidence, then
always clean up service state.

### CR-07 [BLOCKER]: Real task cancellation does not persist a cancelled partial result

**Files:** `src/mercury/tasks.py:402`, `src/mercury/tasks.py:433`,
`src/mercury/cli.py:380`, `src/mercury/cli.py:401`

**Issue:** `_execute()` handles only the custom
`CooperativeCancellation`. `asyncio.CancelledError` is a `BaseException` and
escapes without finalization. Cancelling a caller awaiting `TaskService.run()`
left the SQLite row `running`, with no result, both before and after reopening
the database. Ctrl-C through `asyncio.run()` follows this path, yet the CLI
reports a cancelled exit code. EVID-04's persisted partial-result guarantee is
therefore false for the ordinary operator interruption path.

**Fix:** Translate external task cancellation into the same terminal state as
the cooperative token and shield a short terminal persistence section from
further cancellation. In the CLI, signal `service.cancel(task_id)` and await
finalization before returning the partial exit code. Add explicit process
recovery/ownership semantics for genuinely interrupted rows.

### CR-08 [BLOCKER]: Arbitrary history mappings still persist credentials and raw content

**Files:** `src/mercury/history.py:23`, `src/mercury/history.py:48`,
`src/mercury/history.py:100`, `src/mercury/tasks.py:458`

**Issue:** Persistence safety is an exact normalized-key denylist. Current code
rejects some common names, but still accepted and round-tripped
`refresh_token`, `client_private_key`, `headers.X-API-Key`, a raw `body`, and a
string containing `Authorization: Bearer top-secret`. Raw exception strings
are also placed in results. Arbitrary mappings cannot support the requirement
that tokens, private keys, pairing material, and unredacted payloads are never
persisted.

**Fix:** Persist typed, allowlisted projections rather than caller-provided
dictionaries. Centralize recursive redaction for recognized authentication
headers and compound/suffixed credential keys, store only payload length/hash
metadata, and sanitize exception text before it enters evidence or history.
Add bypass tables for prefixes, suffixes, nested headers, and value leakage.

### CR-09 [BLOCKER]: “Frozen” canonical models accept mutable and unserializable values

**File:** `src/mercury/models.py:179`, `src/mercury/models.py:223`,
`src/mercury/models.py:253`, `src/mercury/models.py:270`,
`src/mercury/models.py:294`

**Issue:** Type annotations are not enforced or normalized. Sequence fields
retain caller-supplied lists, so a frozen result can be mutated after
construction. String values such as `"local_fact"` and `"local"` pass enum
comparisons in `Observation` but later crash serialization on `.value`.
`Progress(True, True, True)` and fractional counters are accepted. Similar
gaps exist for nested result/config/capability members. This violates the
immutable canonical contract and feeds the terminalization data-loss path.

**Fix:** In every `__post_init__`, require the exact enum/model/scalar type,
explicitly reject booleans where integers are expected, and convert accepted
sequences to tuples before validation. Validate every nested member and add
direct-constructor negative tests, not only JSON-decoder tests.

### CR-10 [BLOCKER]: Terminal synthesis records evidence that contradicts execution

**File:** `src/mercury/tasks.py:283`, `src/mercury/tasks.py:491`

**Issue:** When a runner fails before admission,
`_record_terminal_observation()` fabricates one admitted and completed work
unit. A three-step plan that failed before doing any work persisted
`admitted=1, completed=1`. Separately, any runner-provided conclusion suppresses
the derived terminal conclusion. A runner that recorded a healthy conclusion
and then raised produced state `failed` plus an execution-error observation,
but its only conclusion remained “healthy / Everything worked.” Both outcomes
violate Mercury's evidence-honesty contract.

**Fix:** Model task-level terminal evidence without consuming probe progress.
Always add a terminal summary for failure/cancellation, or reject custom
conclusions whose health/evidence is inconsistent with terminal state. Preserve
runner conclusions as scoped findings, never as an override of task truth.

### CR-11 [BLOCKER]: A custom history path changes permissions on its parent directory

**File:** `src/mercury/history.py:175`

**Issue:** On POSIX, `HistoryStore` unconditionally applies mode `0700` to
`database_path.parent`, even when that directory already existed and was
explicitly chosen by the user. `--data-path ./history.sqlite3` therefore
changes the current working directory's permissions; a path in a shared
directory can lock other users out of unrelated files. This is an out-of-scope
filesystem mutation and potential access/data-availability loss.

**Fix:** Track whether Mercury created its private application directory and
only tighten that newly created directory. For an explicit path, never chmod an
existing parent; create/open the database with owner-only file permissions and
validate or warn about an unsafe parent instead.

## Warnings

### WR-01 [WARNING]: Authorized DNS rotation is rejected even when every new address is in scope

**File:** `src/mercury/policy.py:309`

**Issue:** `recheck_resolution()` requires the sorted answer tuple to equal the
preview snapshot before it performs address-by-address scope checks. A change
from `192.0.2.10` to `192.0.2.11` was rejected even when the explicit grant was
`192.0.2.0/24`. Round-robin DNS and ordinary failover will therefore fail
despite satisfying SAFE-04.

**Fix:** Resolve immediately before use, validate every current answer against
the name and network grant, log answer changes as evidence, and connect only to
the validated returned addresses. Reject changes only when an answer escapes
scope.

### WR-02 [WARNING]: History permits illegal and internally inconsistent terminal transitions

**File:** `src/mercury/history.py:239`, `src/mercury/history.py:298`

**Issue:** `finish_task()` permits `pending -> terminal`, although the required
state machine is `pending -> running -> terminal`, and it does not verify that
stored and result task kinds/plans agree. A pending row with kind `wrong`
accepted a completed result whose kind was `synthetic`. `recover_interrupted()`
also marks rows failed without a terminal result or recovery event.

**Fix:** Allow normal finishing only from `running`; compare immutable identity,
kind, and plan digest before update. Implement recovery as an explicit atomic
transition that creates a valid structured failure result/event, with ownership
or lease checks so another live process is not misclassified.

### WR-03 [WARNING]: Max-age retention is not enforced until a caller explicitly prunes

**File:** `src/mercury/history.py:327`, `src/mercury/history.py:445`

**Issue:** Pruning runs after a successful finish or by direct call only.
Reopening a database 30 days after a result exceeded a one-day retention limit
still returned the expired row. An idle history therefore violates its
configured time bound indefinitely.

**Fix:** Prune on store initialization and before list/read operations (or on a
bounded maintenance schedule), while retaining the existing rule that live
tasks are not age-deleted.

### WR-04 [WARNING]: Oversized JSON integers escape the codec error contract

**File:** `src/mercury/codec.py:439`

**Issue:** `loads_document()` catches `JSONDecodeError` and `RecursionError` but
not the `ValueError` raised by Python's integer digit limit. A syntactically
valid object containing a 5,000-digit integer raises raw `ValueError` rather
than `CodecError`, producing inconsistent API and history error handling.

**Fix:** Supply a bounded `parse_int` or translate integer-limit `ValueError`
into `CodecError`, with a regression through `loads_document()` rather than
only `result_from_wire()`.

### WR-05 [WARNING]: Versioning is duplicated and rejects compatible minor documents

**Files:** `pyproject.toml:7`, `src/mercury/__init__.py:5`,
`src/mercury/codec.py:381`, `src/mercury/planner.py:135`

**Issue:** Package version exists independently in `pyproject.toml` and
`__init__.py`; plan schema `"1.0"` is hardcoded separately from
`MODEL_SCHEMA_VERSION`. The codec also requires exact equality, while the phase
contract calls for rejection of unsupported major versions. These paths will
drift or force a major break for a compatible minor revision.

**Fix:** Keep package and document versions in one source each, import the
schema constant in planner serialization, and parse/validate a documented
compatible major/minor range. Add drift and `1.x` compatibility tests.

### WR-06 [WARNING]: Argparse failures bypass stable structured CLI errors

**File:** `src/mercury/cli.py:390`

**Issue:** `parse_args()` runs outside the CLI exception boundary. For example,
`mercury --json plan` raises `SystemExit(2)` and prints argparse's human usage
text rather than the promised structured JSON error. In-process callers also
cannot rely on `main()` returning an exit code for invalid arguments.

**Fix:** Use an `ArgumentParser` subclass whose `error()` raises `CliError`, or
otherwise translate parse failures after preserving normal help/version exits.
Honor the detected JSON mode in the error projection.

### WR-07 [WARNING]: Phase acceptance tests omit the adversarial contract surface

**Files:** `tests/test_contracts.py:18`, `tests/test_contracts.py:38`,
`tests/test_policy.py:128`, `tests/test_tasks.py:117`

**Issue:** The truth table omits several evidence kinds and does not round-trip
all confidence values. Tests also omit forged plans/non-boolean attestation,
multicast and unspecified targets, port/transport scope, payload binding,
complete-output accounting, external asyncio cancellation, invalid direct
models, in-scope DNS rotation, retention on reopen, pending-to-terminal
rejection, and installed console/module parity. Consequently all tests pass
while the foundation's central safety contracts fail.

**Fix:** Add table-driven boundary and one-past-boundary tests for every enum and
budget dimension, plus the adversarial reproductions above. Run the same CLI
cases through `python -m mercury` and the installed console script from a clean
wheel environment.

---

_Reviewed: 2026-07-29T19:38:05Z_  
_Reviewer: the agent (gsd-code-reviewer)_  
_Depth: deep_
