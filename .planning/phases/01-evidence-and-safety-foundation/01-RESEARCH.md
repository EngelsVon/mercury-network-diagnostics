# Phase 1: Evidence and Safety Foundation - Research

**Researched:** 2026-07-30  
**Domain:** Versioned evidence contracts, target authorization, bounded
asynchronous task execution, and local SQLite history in Python  
**Confidence:** HIGH for Python/SQLite implementation patterns; MEDIUM-HIGH for
the initial numeric budget and retention defaults, which need operational
validation

## Accepted Planning Corrections

This research was drafted against an earlier context snapshot. The final
`01-CONTEXT.md`, requirements, and plans supersede it in four places:

1. Observations use separate `disposition` and `evidence_kind` axes so TCP
   reset/unreachable and UDP reply/peer-arrival evidence are not collapsed
   into a generic outcome.
2. A validated IPv6 scope/interface ID is preserved for link-local literals.
   Unsupported platform handling is typed degradation; v1 does not reject all
   scoped IPv6 at parse time.
3. Packet/byte/rate accounting is explicitly logical: attempt-start rate,
   Mercury-generated UDP datagrams/application payload bytes, and stream
   application bytes. Exact kernel retransmission/on-wire accounting is not
   claimed.
4. The accepted absolute ceiling table is the smaller, complete table in
   `01-CONTEXT.md` (including packet, byte, rate, and output dimensions), not
   the provisional table later in this research.

<user_constraints>
## User Constraints (from CONTEXT.md)

The following decisions are copied from `01-CONTEXT.md` and are
non-negotiable for planning.

### Locked Decisions

#### Evidence contract

- Use frozen standard-library dataclasses and string enums; JSON is the public
  interoperability boundary, not Python object identity.
- Every document carries `schema_version`, task ID, task kind, direction,
  requested/effective configuration, timestamps, observations, conclusions,
  capabilities, progress, and terminal state.
- Preserve protocol truth with distinct `success`, `refused`, `timeout`,
  `silent`, `unsupported`, `permission_denied`, `cancelled`, and `error`
  observation outcomes.
- Conclusions cite observation IDs, carry `high`/`medium`/`low`/`unknown`
  confidence, and may list alternative explanations.

#### Authorization and budgets

- Parse IP literals, host names, and CIDRs into typed targets before any active
  operation; canonicalize CIDRs and reject zone IDs, URL syntax, ambiguous
  numeric hosts, and invalid ports.
- The operator must explicitly attest authorization for any non-loopback active
  target. Full-port mode has a separate exact confirmation gate.
- DNS names are authorized as names and every resolved address is checked again
  immediately before connection, preventing resolution from escaping policy.
- A frozen aggregate plan reserves hosts, ports, attempts, concurrency,
  duration, and event count up front; both configurable limits and
  non-bypassable absolute ceilings apply.

#### Task lifecycle and persistence

- Task states are `pending`, `running`, `completed`, `failed`, and `cancelled`;
  cancellation is cooperative and always persists the valid observations
  already collected.
- One `TaskService` owns submission, progress, cancellation, finalization, and
  history. CLI and later WebUI call this service rather than implementing task
  behavior.
- SQLite stores the request, immutable effective plan, status, and result as
  versioned JSON. Retention is bounded by count and age and cleanup happens
  transactionally.
- A bounded synthetic task is included solely to verify lifecycle behavior
  without touching a network.

#### Package and command surface

- Use a `src/mercury` layout, `pyproject.toml`, CPython 3.11+, and one runtime
  dependency (`psutil`); no framework, ORM, broker, or plugin abstraction.
- `python -m mercury` and the `mercury` console script share the same argparse
  entry point. Phase 1 exposes `version`, `model`, `plan`, `history`, and a
  hidden/developer synthetic task command.
- JSON output is stable and machine-readable; human output is a projection of
  the same result object. Errors use structured stderr and intentional exit
  codes.
- Tests use `unittest`, temporary directories, injected clocks/resolvers, and
  no public network access.

### The Agent's Discretion

- Exact module boundaries, SQLite indexes, default soft budget values, and
  human-output wording may be selected for the smallest clear implementation,
  provided the hard safety semantics above remain visible and tested.

### Deferred Ideas (OUT OF SCOPE)

- Real network inventory and probes are Phase 2.
- Active discovery and route tracing are Phase 3.
- TLS/token peer control is Phase 4.
- WebUI, report export, and release hardening are Phase 5.

Do not turn the synthetic task into a hidden scanner, build a generic probe
plugin system, or implement Phase 2 platform adapters in this phase.
</user_constraints>

<architectural_responsibility_map>
## Architectural Responsibility Map

Mercury is one installable Python package and one process in Phase 1, with
logical boundaries rather than distributed tiers.

| Capability | Primary owner | Secondary owner | Rationale |
|------------|---------------|-----------------|-----------|
| CLI parsing and rendering | Presentation (`cli.py`) | Explicit model-to-human projection | CLI validates syntax and displays results; it never compiles policy or runs work itself |
| Evidence/result contract | Domain (`models.py`, `codec.py`) | Persistence | Every later producer and frontend depends on one versioned wire contract |
| Target canonicalization | Domain (`targets.py`) | Policy | Parsing must finish before authorization; raw target strings do not cross into execution |
| Scope, attestation, and budgets | Policy (`policy.py`) | Task service | Only the policy compiler may create an `AuthorizedPlan` |
| Task lifecycle and cancellation | Application service (`tasks.py`) | Built-in runner | One owner prevents CLI/WebUI state-machine drift |
| Synthetic execution | Built-in runner (`synthetic.py`) | Task context | It exercises lifecycle/event limits without any socket or subprocess |
| Bounded task history | Storage (`history.py`) | Codec | SQLite stores versioned JSON snapshots and indexed lifecycle metadata |
| Package metadata and entry points | Build (`pyproject.toml`, `__main__.py`) | CLI | The module and console entry point must call exactly the same `main()` |
| Tests | `unittest` contract tests | Temporary SQLite/fake resolver/fake clock | Phase 1 proves safety without public network access |
</architectural_responsibility_map>

<research_summary>
## Summary

Phase 1 should be a small, dependency-light safety kernel. The durable public
boundary is explicit versioned JSON. Inside the process, frozen dataclasses and
`StrEnum` make states legible, but the security-critical plan must also be
*deeply* immutable: it may contain only primitive values, tuples, and other
frozen records. `frozen=True` alone is shallow and does not make a nested list
or dictionary safe.

Every active task must begin as raw request data, become typed/canonical target
records, receive a cost preview, and then pass policy plus confirmation gates
before the compiler returns an `AuthorizedPlan`. DNS names require a second
check at the connection boundary: resolve again, reject the entire resolution
set if any address is outside the approved set/scope, and give the connector a
numeric address. Validating a hostname and later passing that hostname to
`open_connection()` would reintroduce an unchecked DNS lookup and defeat the
policy.

`TaskService` should use a cooperative `asyncio.Event` for normal user
cancellation, preserve already completed observations, and own all terminal
state transitions and SQLite finalization. SQLite receives one pending record
before execution and one atomic terminal update plus retention cleanup. Do not
persist one row per progress tick. The synthetic runner is sufficient to prove
success, failure, deadline, cancellation, event exhaustion, and restart
recovery before real probes exist.

**Primary recommendation:** implement one-way dependencies
`models/codec → targets/policy → tasks → cli`, with `history` beneath the
service, and make `AuthorizedPlan` the only input accepted by active execution.
</research_summary>

<standard_stack>
## Standard Stack

### Core

| Technology | Version/policy | Purpose | Why this phase should use it |
|------------|----------------|---------|------------------------------|
| CPython | `>=3.11`; develop/test locally on 3.13.5 | Runtime | 3.11 provides `StrEnum`, `TaskGroup`, `asyncio.timeout_at`, `datetime.UTC`, frozen/slotted dataclasses, and `tomllib` |
| Python standard library | Version shipped with each supported CPython | Models, JSON, targets, async lifecycle, CLI, SQLite, package metadata, tests | It covers every Phase 1 requirement without a framework |
| `psutil` | `7.2.2` | Sole runtime dependency and later cross-platform interface facts | The dependency is already approved; Phase 1 only verifies packaging/import/version and must not pull Phase 2 inventory forward |
| SQLite | Via `sqlite3`; local interpreter reports SQLite 3.49.1 | Bounded local history | Transactional, embedded, queryable, and already in CPython |
| `setuptools` | Build requirement `>=77`; current PyPI release 83.0.0 | Wheel and console entry point | Stable PEP 517 backend; no runtime dependency |

### Standard-library modules

| Module | Purpose | Prescriptive use |
|--------|---------|------------------|
| `dataclasses`, `enum` | Frozen records and string states | `@dataclass(frozen=True, slots=True, kw_only=True)` and `@unique class X(StrEnum)` |
| `json` | Public/persisted wire format | Explicit field mappers; `allow_nan=False`; duplicate-key rejection on decode |
| `datetime`, `time` | UTC timestamps and elapsed durations | `datetime.now(UTC)` for evidence; monotonic clock for duration/deadline |
| `uuid` | Task identity | `uuid4()` string; IDs are identifiers, not credentials |
| `hashlib` | Bind attestation to a canonical plan | SHA-256 of canonical plan JSON; never treat the digest as authentication |
| `ipaddress` | IP/CIDR parsing and containment | Normalize mapped IPv4; never use version-varying `is_private` as the authorization policy |
| `socket`, `asyncio` | DNS seam and lifecycle | `loop.getaddrinfo()` behind an injected resolver; no Phase 1 connection |
| `sqlite3` | History | Short explicit transactions, parameterized SQL, connection local to an operation |
| `argparse` | Commands | One parser and one `main(argv=None) -> int` |
| `importlib.metadata` | Installed versions | Report Mercury/psutil versions without duplicating version constants |
| `unittest`, `unittest.mock`, `tempfile` | Verification | Table-driven sync tests and `IsolatedAsyncioTestCase`; no public sockets |

### Development-only tool

| Tool | Current version | Purpose | Policy |
|------|-----------------|---------|--------|
| `build` | 1.5.0 | Produce sdist/wheel with `python -m build` | Development/CI dependency only; do not add to runtime dependencies |

### Alternatives considered

| Instead of | Could use | Why not in Phase 1 |
|------------|-----------|--------------------|
| Explicit dataclasses/codec | Pydantic | Adds a second validation/serialization model and runtime dependency for a small fixed contract |
| Direct SQL | SQLAlchemy | A single bounded table and migration version do not justify an ORM |
| `asyncio` service | Celery/Redis or another broker | Work is local and in-process; a broker would weaken the single task owner |
| Explicit resolver seam | A DNS client library | System resolver behavior is the desired baseline; fake `getaddrinfo` results are enough for policy tests |
| `unittest` | pytest/property-test dependencies | The required state tables and boundary cases are straightforward with subtests and deterministic fakes |
| Standard wheel first | PyInstaller/Nuitka | Standalone executables are v2; first prove clean wheel installation and resources |

### Packaging and install shape

Use distribution name `mercury-netdiag` (subject to a publication-name check),
import package `mercury`, and console command `mercury`. A distribution name
need not equal its import package.

```toml
[build-system]
requires = ["setuptools>=77"]
build-backend = "setuptools.build_meta"

[project]
name = "mercury-netdiag"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = ["psutil==7.2.2"]

[project.scripts]
mercury = "mercury.cli:main"

[tool.setuptools.packages.find]
where = ["src"]
```

`src/mercury/__main__.py` must contain only the shared dispatch:

```python
from .cli import main

raise SystemExit(main())
```

Recommended verification commands:

```powershell
python -m pip install -e .
python -m unittest discover -s tests -v
python -m pip install build==1.5.0
python -m build
python -m mercury version --json
mercury version --json
```

The last two outputs should be byte-equivalent except for intentionally
volatile timing fields (the version command should have none).
</standard_stack>

<architecture_patterns>
## Architecture Patterns

### System data flow

```text
argv / future HTTP request
          |
          v
   syntax-only parsing
          |
          v
 typed target canonicalization -------- invalid syntax ------> structured reject
          |
          v
 initial resolution snapshot (hostname only, injected seam)
          |
          v
 policy + absolute ceilings + cost preview
          |
          +------ over budget / missing attestation ----------> structured reject
          |
          v
 immutable AuthorizedPlan + plan digest
          |
          v
      TaskService ---- persist pending ----> SQLite history
          |
          v
 bounded built-in runner (Phase 1: synthetic only)
          |
          v
 observations -> conclusions -> progress -> terminal result
          |
          +---- cancel/deadline/error -----> same finalizer
          |
          v
 atomic terminal save + retention cleanup
          |
          v
 JSON codec ------> CLI human projection / stable JSON

Future hostname connection boundary:
approved name -> resolve again -> check every answer -> numeric endpoint
                                             |
                              changed/out-of-scope answer -> no connector call
```

### Recommended project structure

```text
pyproject.toml
src/
└── mercury/
    ├── __init__.py       # Package marker only
    ├── __main__.py       # SystemExit(cli.main())
    ├── cli.py            # argparse, exit codes, JSON/human projection
    ├── models.py         # Enums and frozen evidence/task records
    ├── codec.py          # Explicit versioned wire encode/decode
    ├── targets.py        # Typed IP/name/CIDR/port canonicalization
    ├── policy.py         # Limits, estimate, attestation, AuthorizedPlan
    ├── tasks.py          # TaskService, lifecycle, cancellation, event ledger
    ├── history.py        # SQLite schema, transactions, retention, recovery
    └── synthetic.py      # One built-in no-network lifecycle runner
tests/
├── test_models_codec.py
├── test_targets_policy.py
├── test_tasks.py
├── test_history.py
├── test_cli.py
└── test_packaging.py
```

Keep this direction of dependencies:

```text
models <- codec
models <- targets <- policy
models + codec <- history
models + policy + history <- tasks <- synthetic
all application modules <- cli
```

`models.py` must not import CLI, SQLite, resolver, or task-service code.
`policy.py` must not import presentation code. `history.py` stores wire
documents through `codec.py`; it does not reconstruct policy from ad hoc SQL
columns. `cli.py` may assemble dependencies but may not reach around
`TaskService`.

### Component responsibilities

| Component | Owns | Must not own |
|-----------|------|--------------|
| `models.py` | State enums, evidence/result/capability/conclusion records and invariants | JSON parser, SQL, target parsing, clocks |
| `codec.py` | Schema-version dispatch, explicit field mapping, canonical JSON | Policy decisions or implicit dataclass dumping |
| `targets.py` | Raw text to `IpTarget`, `NetworkTarget`, or `NameTarget`; canonical ports | Authorization, DNS caching, socket connection |
| `policy.py` | Scope grants, initial name resolution snapshot, work estimate, hard ceilings, confirmation binding | Running probes or mutable counters |
| `tasks.py` | Pending/running/terminal transition, event ledger, cancellation, deadline, finalization | Raw target input or arbitrary caller-supplied coroutines |
| `history.py` | DB schema/version, immutable request/plan storage, result updates, retention/recovery | Model interpretation or network behavior |
| `synthetic.py` | Deterministic steps through a supplied `TaskContext` | Socket, subprocess, psutil inventory, its own persistence |
| `cli.py` | Syntax, structured stderr, output selection, signal/exit mapping | Duplicate policy/task logic |

### Pattern 1: A versioned wire contract, not `asdict()`

Use separate versions for:

- `MODEL_SCHEMA_VERSION` — public JSON document;
- `DB_SCHEMA_VERSION` — SQLite layout (`PRAGMA user_version`);
- package version — release identity;
- future peer protocol version — Phase 4.

They will evolve at different rates and must not be aliases.

Recommended model invariants:

| Record | Required invariants |
|--------|---------------------|
| `Observation` | Unique ID within task, explicit outcome/direction/provenance, UTC start time, non-negative monotonic duration, positive attempt |
| `Conclusion` | Confidence is explicit; every cited observation ID exists; alternatives are preserved |
| `Capability` | State/reason distinguishes available, unsupported, permission denied, and error |
| `Progress` | `0 <= completed <= total`; emitted events never exceed plan; `truncated` is explicit |
| `TaskResult` | Schema/task/kind/config/timestamps/observations/conclusions/capabilities/progress/state all present |
| `AuthorizedPlan` | Contains no mutable list/dict/set; includes policy version, effective scope, approved name-address snapshot, estimate, ceilings, attestation, and digest |

Use explicit `*_to_wire()` and `*_from_wire_v1()` functions. Do not use
`dataclasses.asdict()` as the public serializer: it couples every internal field
addition to the wire format and does not provide schema validation or enum/time
encoding rules.

Canonical JSON for persistence/digests should use:

```python
json.dumps(
    wire_value,
    ensure_ascii=False,
    sort_keys=True,
    separators=(",", ":"),
    allow_nan=False,
)
```

Decode untrusted JSON with a byte/character limit, reject duplicate object
keys through `object_pairs_hook`, reject `NaN`/`Infinity` through
`parse_constant`, require exact field types (remember `bool` is an `int`
subclass), and dispatch on `schema_version` before constructing records.

### Pattern 2: Typed targets before policy

Accept port as a separate argument from host text. This avoids ambiguous
`host:port` parsing and bracket rules. Parse in this order:

1. reject leading/trailing whitespace, NUL, URL/userinfo/query syntax, and `%`
   zone identifiers;
2. if `/` is present, parse with `ip_network(..., strict=False)`, show the
   canonical network in preview, and bind confirmation to that canonical value;
3. otherwise try `ip_address()`;
4. normalize exact IPv4-mapped IPv6 addresses to IPv4; reject mapped IPv6 CIDRs
   in v1 rather than implementing error-prone prefix conversion;
5. if not numeric, IDNA-encode and lowercase a hostname, remove one trailing
   root dot, validate total/label lengths, and reject wildcard/URL syntax;
6. validate ports as integers `1..65535` and canonicalize ranges into sorted,
   merged intervals without expanding them.

Do not use `IPv4Address.is_private` or `is_global` as authorization. Their
classification tables changed in Python 3.13, and “private” is not equivalent
to “operator authorized.” Use explicit exact addresses/CIDRs in the scope
grant. Explicitly reject unusable destinations such as unspecified and
multicast addresses. Loopback exemption should be tested against the explicit
networks `127.0.0.0/8` and `::1/128`.

`strict=False` can broaden `192.0.2.7/24` to `192.0.2.0/24`; it is acceptable
only because the preview displays the canonical range and the attestation is
bound to the resulting digest. Never silently execute merely because the raw
input had a host address.

### Pattern 3: Scope-bound DNS recheck

For a hostname plan:

1. authorize the canonical name;
2. resolve during planning through an injected resolver;
3. normalize/deduplicate every A/AAAA result;
4. show and freeze the initial address set in `AuthorizedPlan`;
5. immediately before every future connection attempt, resolve again;
6. reject the whole attempt if any current answer is not both inside the
   effective scope and in the plan-approved address set;
7. pass only an already checked numeric `sockaddr` to the connector.

This is deliberately fail-closed. A legitimate CDN address change can require
a new preview/attestation; that is safer than letting a previously approved
name move to a new internal or loopback destination. A current subset of the
approved set is acceptable. A mixed allowed/new set is rejected as a unit so
selection order cannot be attacker-controlled.

The production resolver seam should wrap:

```python
await asyncio.get_running_loop().getaddrinfo(
    canonical_name,
    port,
    family=socket.AF_UNSPEC,
    type=socket.SOCK_STREAM,
    proto=socket.IPPROTO_TCP,
)
```

Phase 1 tests supply results directly and a fake connector that records calls.
There is no real connection in this phase. Later code must not call
`asyncio.open_connection(hostname, ...)` after validation because that performs
another resolver lookup outside policy. It should create/connect a nonblocking
socket to the numeric endpoint; TLS may still use the original approved
hostname as `server_hostname` for SNI and certificate verification.

### Pattern 4: Costed immutable plan

Model at least these separate records:

- `AbsoluteCeilings` — source constants, not config;
- `ConfiguredLimits` — operator may tighten, never enlarge absolute ceilings;
- `WorkEstimate` — actual canonical host, distinct-port, total-attempt,
  concurrency, duration-cap, and event counts;
- `ScopeGrant` — canonical names/networks/addresses and non-loopback
  attestation;
- `DangerConfirmation` — profile plus the exact plan digest;
- `AuthorizedPlan` — frozen result of all checks.

Reject rather than truncate requested hosts or ports. Silent truncation makes
the recorded effective task differ from what the operator thought was tested.
Calculate cardinality without enumeration. Python integers do not overflow,
but stop multiplication as soon as it exceeds the relevant ceiling so huge
inputs remain cheap to reject. The executor and estimator must share the same
count functions, especially `/31`, `/32`, duplicate port ranges, and retry
semantics.

Recommended initial defaults:

| Resource | Soft default | Non-bypassable absolute ceiling | Notes |
|----------|-------------:|--------------------------------:|-------|
| Canonical hosts | 256 | 4,096 | Resolved unique addresses count; IPv6 CIDR enumeration remains forbidden |
| Distinct ports per host | 32 | 65,535 | Full range is possible only with separate digest-bound confirmation |
| Aggregate attempts | 8,192 | 262,144 | Product of hosts × ports × profiles × repeats; primary explosion guard |
| In-flight concurrency | 64 | 256 | A cap, never a work estimate |
| Task duration | 300 s | 3,600 s | Monotonic hard deadline; display this as worst-case bound |
| Emitted events | 20,000 | 300,000 | Reserve terminal slots before giving a runner permits |
| Serialized result bytes | 8 MiB | 32 MiB | Defense in depth because one event can otherwise contain unbounded text |

These numbers are initial policy, not protocol constants. Put them in one
module, name them in JSON, and write boundary tests. Config may lower them.
Raising absolute ceilings requires a code change/review. Reserve at least two
event slots for truncation and terminal-state evidence so a runner cannot
consume the entire ledger and make finalization unreportable.

The worst-case duration shown to the user is the task duration ceiling. A
concurrency-based estimate may be displayed separately as an estimate but must
not be called the worst case.

### Pattern 5: Cooperative lifecycle with one terminal finalizer

Use this state machine:

```text
pending -> running -> completed
                 \-> failed
                 \-> cancelled
pending ----------------> cancelled
```

Terminal states never transition. A cancellation that loses a race with a
completed finalization returns “already terminal” and must not rewrite the task
to cancelled.

Normal user cancellation should set an `asyncio.Event`; it should not begin
with `Task.cancel()`. The runner checks the event before scheduling a unit,
after every awaited boundary, and before emitting an observation, then raises a
small domain exception such as `TaskCancelled`. The service catches that and
uses the same terminal finalizer as success/failure. Preserve only complete,
valid observations; do not append half-built attempt records.

Use direct `Task.cancel()` only for process shutdown or after a bounded
cooperative grace period. Python documents that `CancelledError` should
generally be propagated after cleanup. The wrapper therefore persists a
cancelled partial result in a protected finalization task and re-raises direct
async cancellation. Do not broadly catch `BaseException`, and do not swallow
`CancelledError` inside probe code.

Use `asyncio.timeout_at(loop.time() + duration)` for the aggregate plan
deadline. `loop.time()` is monotonic. A duration-budget timeout is not a user
cancellation: finalize with a distinct error code such as
`task_duration_exhausted`.

`TaskGroup` is appropriate later for bounded child workers, but expected
network failures must be converted to `Observation` values inside each worker;
letting a routine refusal/timeout escape a task group would cancel unrelated
attempts. Unexpected invariant/programming errors should escape and fail the
task visibly.

### Pattern 6: Bounded SQLite history

Use one table for lifecycle snapshots; do not build an event-sourcing system in
Phase 1.

```sql
CREATE TABLE task_history (
    task_id              TEXT PRIMARY KEY,
    model_schema_version INTEGER NOT NULL,
    task_kind            TEXT NOT NULL,
    state                TEXT NOT NULL
                         CHECK (state IN
                           ('pending','running','completed','failed','cancelled')),
    created_at           TEXT NOT NULL,
    updated_at           TEXT NOT NULL,
    finished_at          TEXT,
    request_json         TEXT NOT NULL,
    plan_json            TEXT NOT NULL,
    result_json          TEXT
);

CREATE INDEX task_history_recent
    ON task_history(finished_at DESC, task_id DESC);
```

Set `PRAGMA user_version = 1` in an explicit migration function. If the DB
version is newer than supported, refuse to mutate it with an actionable error.
Do not conflate it with `MODEL_SCHEMA_VERSION`.

Insert the canonical request and plan exactly once before starting work. Never
use `INSERT OR REPLACE`, which deletes/reinserts and can accidentally replace
the immutable authorization snapshot. Updates may change only state,
timestamps, and result JSON. A small `BEFORE UPDATE OF request_json, plan_json`
trigger that raises `ABORT` is worthwhile defense in depth.

Open a connection per short storage operation with the default
`check_same_thread=True`; never share one connection across event-loop and Web
handler threads. Configure `foreign_keys=ON`, `busy_timeout=5000`, and attempt
`journal_mode=WAL` for the local state directory. Check the returned journal
mode and fall back visibly to the default journal if WAL is unavailable. Do
not set `check_same_thread=False` as a concurrency strategy.

Use `isolation_level=None` plus explicit `BEGIN IMMEDIATE`, `commit`, and
`rollback`, which behaves consistently across the supported Python 3.11-3.13
range. A connection context manager commits/rolls back but does not close the
connection; wrap it with `contextlib.closing` or close explicitly.

Final status/result update and retention cleanup belong to one transaction.
Recommended retention:

- default: terminal tasks younger than 30 days, at most 1,000;
- absolute configuration ceiling: 365 days and 10,000 terminal tasks;
- never prune `pending` or `running` rows;
- on startup, convert orphaned prior-process `pending`/`running` records to
  `failed` with code `process_interrupted`, preserving any stored snapshot;
- do not `VACUUM` on every cleanup.

Retention SQL should first delete terminal rows older than the cutoff, then
delete terminal rows outside the newest `N` ordered by
`finished_at DESC, task_id DESC`. Use parameters for all values. The whole
transaction rolls back if either final save or pruning fails.

Do not write every progress event to SQLite. Keep a bounded in-memory event
ledger, persist the pending record, and persist the terminal result. If later
crash-resilient progress is needed, add time/count-coalesced snapshots through
the same result column rather than an unbounded row stream.

### History location

Use a small stdlib path function and allow explicit injection:

| Platform | Default |
|----------|---------|
| Windows | `%LOCALAPPDATA%\Mercury\history.sqlite3` |
| macOS | `~/Library/Application Support/Mercury/history.sqlite3` |
| Linux/other POSIX | `$XDG_STATE_HOME/mercury/history.sqlite3`, else `~/.local/state/mercury/history.sqlite3` |

An explicit `--history PATH` or `MERCURY_STATE_DIR` is useful for tests and
portable operation, with CLI taking precedence. Create the containing
directory with `0700` and the DB with `0600` where POSIX permissions apply;
Windows relies on the user-profile ACL. Tests always inject a temporary path.

### `psutil` boundary in Phase 1

Do not call `psutil.net_if_addrs()` or `net_if_stats()` yet; those are Phase 2
inventory producers. Phase 1 should:

- declare exactly one runtime dependency;
- report the installed dependency version through
  `importlib.metadata.version("psutil")` in model/version output if useful;
- include a clean-install/import smoke test;
- leave `models`, `policy`, `tasks`, and `history` independent of psutil.

In Phase 2, psutil belongs behind a platform/inventory adapter and its objects
must be projected into Mercury observations immediately; never persist or
expose psutil named tuples as the public model.

### CLI contract

Use a single `main(argv: Sequence[str] | None = None) -> int`.

| Exit | Meaning |
|-----:|---------|
| 0 | Command completed successfully |
| 2 | argparse syntax or model validation error |
| 3 | Scope, attestation, danger confirmation, or budget rejection |
| 4 | Task/storage execution failed |
| 130 | User cancelled/interrupt; partial result was finalized first |

JSON success goes only to stdout. Structured errors go only to stderr and
include at least `schema_version`, stable `error.code`, message, and optional
field details. Human rendering consumes the same wire object; it never reads
private service state.

Recommended Phase 1 commands:

- `version [--json]` — Mercury, Python, psutil, model schema, and DB schema;
- `model [--json]` — a deterministic v1 sample/field contract, not a home-grown
  JSON Schema implementation;
- `plan ... [--json]` — canonical targets, resolved snapshot, work estimate,
  effective limits, required attestations, and digest; never executes;
- `history list|show|prune`;
- hidden `synthetic` — bounded step count/interval/failure injection for
  lifecycle tests.

On Ctrl+C, the synchronous CLI wrapper returns 130 only after the async command
has asked `TaskService` to cancel and awaited terminal persistence. Do not catch
`KeyboardInterrupt` and immediately exit around a now-closed event loop.

### Recommended implementation order

1. Package skeleton, enums/dataclasses, explicit codec, schema/round-trip tests.
2. SQLite schema/history/retention/recovery using those wire documents.
3. Typed targets, resolver seam, scope/attestation, budget estimate, plan
   digest.
4. `TaskService`, bounded event ledger, synthetic runner, cancellation/deadline
   finalizer.
5. CLI projections/exit codes and clean wheel/module/console parity tests.

This matches the roadmap while letting each later step use already-tested
lower boundaries.

### Anti-patterns to avoid

- **A mutable “config” dictionary passed to runners:** only an
  `AuthorizedPlan` may reach execution.
- **One DNS validation during request parsing:** re-resolve at use time and
  connect to a checked numeric address.
- **Boolean `authorized=True` stored without scope:** store canonical scope,
  policy version, attestation text/type, timestamp, and plan digest.
- **Silent plan clamping:** reject work that exceeds the effective limit.
- **`dataclasses.asdict()` as the wire schema:** explicit versioned mappers keep
  internal fields from leaking.
- **`datetime.utcnow()` and wall-clock deadlines:** use aware UTC for evidence
  and monotonic clocks for elapsed/deadline.
- **One `asyncio.create_task` per future probe cell:** later phases must consume
  bounded permits/queues from the plan.
- **`Task.cancel()` as normal UI cancellation:** cooperative token first,
  forced cancel only after a grace period/shutdown.
- **One SQLite row per packet/progress tick:** bounded result snapshots only.
- **A shared SQLite connection with `check_same_thread=False`:** short
  operation-local connections and serialized writes.
- **Generic repositories, factories, DI containers, runner plugins, or event
  buses:** explicit constructors and built-in task-kind dispatch are enough.
</architecture_patterns>

<dont_hand_roll>
## Don't Hand-Roll

| Problem | Do not build | Use instead | Why |
|---------|--------------|-------------|-----|
| IP/CIDR parsing | Regex or integer conversion | `ipaddress.ip_address` / `ip_network` plus explicit policy | IPv6, mapped addresses, host-bit canonicalization, and prefix math are subtle |
| DNS resolution | Custom UDP DNS client/cache | Event-loop `getaddrinfo` behind an injected seam | System resolver/search configuration is the baseline; policy needs results, not a DNS implementation |
| Async scheduler | Worker threads, home-grown futures, broker | `asyncio.Event`, `Lock`, `TaskGroup`, `timeout_at` | Correct cancellation and exception propagation already exist |
| JSON schema engine | Reflection over dataclasses or custom JSON Schema generator | Explicit v1 encode/decode functions and invariants | The contract is small; reflection leaks internal fields and obscures compatibility |
| Database abstraction | ORM/repository framework | Parameterized `sqlite3` statements in `HistoryStore` | One table, one migration version, and two transaction paths are clearer directly |
| Database durability | JSON files plus rename/locks | SQLite transaction | Concurrent readers, crash-safe commit, indexes, and retention are already solved |
| Deep immutability library | Proxy graph or mutable dict convention | Typed frozen records plus tuples/frozensets | The authorized plan has a known fixed shape |
| Authorization token/crypto | Signed custom plan token | In-process frozen plan plus SHA-256 confirmation digest | The digest binds human confirmation; it is not a remote trust credential |
| Version discovery | Duplicate `__version__` strings | `importlib.metadata.version()` | Package metadata remains the release source of truth |
| Test clock/resolver framework | Global monkeypatch framework | Constructor-injected callables/fakes and `unittest.mock` | Only a few effect seams exist |

**Key insight:** use the standard library for the mechanisms, but write
Mercury-specific policy explicitly. IP parsing, DNS resolution, cancellation,
JSON, and transactions are solved mechanisms; the exact authorization,
evidence semantics, and immutable limits are the product.
</dont_hand_roll>

<common_pitfalls>
## Common Pitfalls

### Pitfall 1: Shallow “immutable” authorization

**What goes wrong:** a frozen plan contains a list/dict that a caller mutates
after approval, changing targets or limits without recompilation.  
**Why it happens:** `frozen=True` prevents attribute assignment but does not
freeze referenced objects.  
**How to avoid:** security-critical records contain only primitives, tuples,
frozensets, and frozen child records; never expose a mutable backing mapping.  
**Warning signs:** `dict`, `list`, `set`, or `Any` appears in
`AuthorizedPlan`, `ScopeGrant`, or `WorkBudget`.

### Pitfall 2: DNS revalidation followed by hostname connection

**What goes wrong:** validation sees an approved address, then the connection
API resolves the hostname again to an unapproved address.  
**Why it happens:** `open_connection(hostname)` looks convenient after a
separate resolver check.  
**How to avoid:** re-resolve immediately before use, check every answer, and
pass a checked numeric endpoint to the connector. Reject mixed sets.  
**Warning signs:** a hostname string crosses from policy into socket-opening
code.

### Pitfall 3: Confirmation is not bound to the effective plan

**What goes wrong:** a broad/full-port request reuses an authorization flag
obtained for a smaller scope.  
**Why it happens:** confirmation is represented as a boolean.  
**How to avoid:** canonicalize first, hash the full effective plan, and store
attestation/danger confirmation with that digest. Any target/port/budget change
invalidates confirmation.  
**Warning signs:** `authorized: true` or `confirm_full: true` is accepted
without comparing a digest.

### Pitfall 4: Estimate and executor count different work

**What goes wrong:** duplicate ranges, retries, resolved addresses, `/31`,
profiles, or payload variants make actual attempts exceed the preview.  
**Why it happens:** UI math and runner loops are implemented separately.  
**How to avoid:** share canonical interval/host/count functions; reserve
aggregate attempts before execution; assert ledger counters never exceed the
plan.  
**Warning signs:** executor contains a multiplication axis absent from
`WorkEstimate`.

### Pitfall 5: IPv6 or CIDR input is enumerated during validation

**What goes wrong:** validation hangs or exhausts memory on a huge network.  
**Why it happens:** `list(network.hosts())` is used to count.  
**How to avoid:** use prefix/cardinality arithmetic, reject IPv6 discovery
plans, and stop products as soon as the ceiling is exceeded.  
**Warning signs:** `list(hosts())`, a set of all ports, or materialized
host×port cells in the planner.

### Pitfall 6: Cancellation loses partial evidence

**What goes wrong:** the task object is cancelled, the event loop closes, and
no terminal result reaches SQLite.  
**Why it happens:** UI cancellation calls `Task.cancel()` and assumes a
`finally` block will finish.  
**How to avoid:** cooperative event for normal cancellation, one service-owned
terminal finalizer, protected persistence on forced cancellation, and a CLI
that waits before returning 130.  
**Warning signs:** presentation code holds `asyncio.Task` handles or writes task
state.

### Pitfall 7: `CancelledError` is swallowed

**What goes wrong:** `TaskGroup`/timeouts misbehave and shutdown hangs.  
**Why it happens:** a broad exception handler treats cancellation like a probe
error.  
**How to avoid:** expected probe errors become observations; direct
`CancelledError` is cleaned up then propagated.  
**Warning signs:** `except BaseException`, or `except CancelledError: return`.

### Pitfall 8: Wall clock is used for deadlines/duration

**What goes wrong:** NTP/manual clock adjustments produce negative durations or
missed deadlines.  
**Why it happens:** persisted timestamps and elapsed timing are conflated.  
**How to avoid:** aware UTC wall time for evidence, monotonic nanoseconds/loop
time for duration and timeouts. Persist the computed duration, not a monotonic
absolute value.  
**Warning signs:** `finished_at - started_at` is the only elapsed measurement.

### Pitfall 9: JSON accepts ambiguous or non-portable values

**What goes wrong:** duplicate keys, NaN/Infinity, unknown fields, or bool-as-int
produce different interpretations across clients.  
**Why it happens:** default `json.loads`/`dumps` behavior is treated as schema
validation.  
**How to avoid:** input-size cap, duplicate-key hook, `allow_nan=False`,
`parse_constant` rejection, exact type/field checks, and version dispatch.  
**Warning signs:** decoding is followed directly by `Model(**value)`.

### Pitfall 10: SQLite context/threads are misunderstood

**What goes wrong:** connections leak, concurrent use throws
`ProgrammingError`, or writes interleave after setting
`check_same_thread=False`.  
**Why it happens:** the connection context manager is assumed to close, and a
thread check is mistaken for a lock.  
**How to avoid:** explicitly close, use short connection-local transactions,
and never share a connection between threads.  
**Warning signs:** a module-global connection or `check_same_thread=False`.

### Pitfall 11: Retention removes active/audit-critical state

**What goes wrong:** count cleanup deletes pending/running tasks or the record
being finalized.  
**Why it happens:** `DELETE ... ORDER BY ... LIMIT` is applied to the whole
table.  
**How to avoid:** prune terminal states only, use deterministic ordering, and
finalize plus cleanup in one transaction.  
**Warning signs:** retention predicate lacks an explicit terminal-state filter.

### Pitfall 12: Python-version-sensitive address labels become policy

**What goes wrong:** the same address is allowed on Python 3.11 and rejected on
3.13 because `ipaddress.is_private` classifications changed.  
**Why it happens:** convenience properties are treated as operator scope.  
**How to avoid:** explicit canonical grants and explicit unusable-address
rules; test on 3.11-3.13.  
**Warning signs:** `is_private` or `is_global` directly decides authorization.

### Pitfall 13: `asyncio.to_thread()` is assumed to stop work

**What goes wrong:** cancelling the await leaves a blocking thread running and
side effects continue after task cancellation.  
**Why it happens:** coroutine cancellation is confused with thread
termination.  
**How to avoid:** Phase 1 needs no thread offload. Future native commands use
cancellable subprocesses/timeouts; any thread work must be short/idempotent.  
**Warning signs:** long blocking runner passed to `to_thread` with no shutdown
strategy.

### Pitfall 14: Package tests only exercise the source tree

**What goes wrong:** editable import works, but the wheel misses modules/assets
or the console entry point differs from `python -m mercury`.  
**Why it happens:** unit tests never install the built artifact.  
**How to avoid:** build a wheel, install into a clean temporary venv in CI, run
both entry points, and inspect metadata/dependency count.  
**Warning signs:** packaging acceptance only runs `python -m unittest` from the
repository root.
</common_pitfalls>

<code_examples>
## Code Examples

These patterns are adapted from the linked Python standard-library
documentation. Names are illustrative; planners should preserve the contracts,
not necessarily copy every identifier.

### Frozen model and explicit JSON

```python
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum, unique
from typing import Final

MODEL_SCHEMA_VERSION: Final = 1


@unique
class Outcome(StrEnum):
    SUCCESS = "success"
    REFUSED = "refused"
    TIMEOUT = "timeout"
    SILENT = "silent"
    UNSUPPORTED = "unsupported"
    PERMISSION_DENIED = "permission_denied"
    CANCELLED = "cancelled"
    ERROR = "error"


@dataclass(frozen=True, slots=True, kw_only=True)
class Observation:
    observation_id: str
    outcome: Outcome
    direction: str
    target: str
    started_at: datetime
    duration_ms: int
    attempt: int
    provenance: str
    evidence: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if self.started_at.tzinfo is None:
            raise ValueError("started_at must be timezone-aware")
        if self.duration_ms < 0 or self.attempt < 1:
            raise ValueError("invalid timing/attempt")


def observation_to_wire(value: Observation) -> dict[str, object]:
    return {
        "observation_id": value.observation_id,
        "outcome": value.outcome.value,
        "direction": value.direction,
        "target": value.target,
        "started_at": value.started_at.astimezone(UTC).isoformat(
            timespec="milliseconds"
        ).replace("+00:00", "Z"),
        "duration_ms": value.duration_ms,
        "attempt": value.attempt,
        "provenance": value.provenance,
        "evidence": [{"name": k, "value": v} for k, v in value.evidence],
    }


def canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
```

Source: Python `dataclasses`, `enum`, `datetime`, and `json` documentation.

### Duplicate-key and non-finite JSON rejection

```python
def _pairs_without_duplicates(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON number: {value}")


def decode_json(text: str, *, max_chars: int = 32 * 1024 * 1024) -> object:
    if len(text) > max_chars:
        raise ValueError("JSON document exceeds hard limit")
    return json.loads(
        text,
        object_pairs_hook=_pairs_without_duplicates,
        parse_constant=_reject_constant,
    )
```

After decoding, each v1 mapper must check exact required/optional keys and
types; this function alone is not model validation.

Source: Python `json.loads` documentation for `object_pairs_hook` and
`parse_constant`.

### Typed target parsing

```python
from dataclasses import dataclass
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    ip_address,
    ip_network,
)


@dataclass(frozen=True, slots=True)
class IpTarget:
    address: IPv4Address | IPv6Address


@dataclass(frozen=True, slots=True)
class NetworkTarget:
    network: IPv4Network | IPv6Network


@dataclass(frozen=True, slots=True)
class NameTarget:
    ascii_name: str


def parse_target(raw: str) -> IpTarget | NetworkTarget | NameTarget:
    if not raw or raw != raw.strip() or "\x00" in raw or "%" in raw:
        raise ValueError("invalid target text or unsupported zone ID")

    if "/" in raw:
        network = ip_network(raw, strict=False)
        if isinstance(network.network_address, IPv6Address):
            if network.network_address.ipv4_mapped is not None:
                raise ValueError("mapped IPv6 CIDRs are unsupported")
        return NetworkTarget(network)

    try:
        address = ip_address(raw)
    except ValueError:
        address = None

    if address is not None:
        if isinstance(address, IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        if address.is_unspecified or address.is_multicast:
            raise ValueError("unusable active destination")
        return IpTarget(address)

    # Do not reinterpret a malformed/legacy-looking numeric address as DNS.
    if all(character in "0123456789." for character in raw):
        raise ValueError("ambiguous numeric hostname")

    if any(token in raw for token in ("://", "/", "@", "?", "#", "[", "]")):
        raise ValueError("URL/userinfo syntax is not a hostname")

    name = raw[:-1] if raw.endswith(".") else raw
    ascii_name = name.encode("idna").decode("ascii").lower()
    labels = ascii_name.split(".")
    if (
        not labels
        or len(ascii_name) > 253
        or any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not all(c.isalnum() or c == "-" for c in label)
            for label in labels
        )
    ):
        raise ValueError("invalid hostname")
    return NameTarget(ascii_name)
```

Source: Python `ipaddress` documentation. Hostname normalization uses the
stdlib IDNA codec; it is deliberately narrower than arbitrary URL parsing.

### DNS recheck before connector use

```python
import asyncio
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address

Ip = IPv4Address | IPv6Address


@dataclass(frozen=True, slots=True)
class NumericEndpoint:
    family: int
    address: Ip
    port: int


async def system_resolver(name: str, port: int) -> tuple[NumericEndpoint, ...]:
    infos = await asyncio.get_running_loop().getaddrinfo(
        name,
        port,
        family=socket.AF_UNSPEC,
        type=socket.SOCK_STREAM,
        proto=socket.IPPROTO_TCP,
    )
    found: set[tuple[int, Ip, int]] = set()
    for family, _type, _proto, _canon, sockaddr in infos:
        parsed = ip_address(sockaddr[0])
        if isinstance(parsed, IPv6Address) and parsed.ipv4_mapped is not None:
            parsed = parsed.ipv4_mapped
            family = socket.AF_INET
        if family == socket.AF_INET6 and len(sockaddr) >= 4 and sockaddr[3]:
            raise ValueError("scoped IPv6 result is outside v1 policy")
        found.add((family, parsed, port))
    return tuple(
        NumericEndpoint(family, address, target_port)
        for family, address, target_port in sorted(
            found, key=lambda item: (item[0], int(item[1]), item[2])
        )
    )


async def endpoints_for_connection(
    *,
    name: str,
    port: int,
    approved: frozenset[Ip],
    scope_permits: Callable[[Ip], bool],
    resolver: Callable[[str, int], Awaitable[tuple[NumericEndpoint, ...]]],
) -> tuple[NumericEndpoint, ...]:
    endpoints = await resolver(name, port)
    addresses = frozenset(endpoint.address for endpoint in endpoints)
    if not addresses:
        raise ValueError("name resolved to no addresses")
    if not addresses.issubset(approved):
        raise PermissionError("DNS answer changed outside approved plan")
    if not all(scope_permits(address) for address in addresses):
        raise PermissionError("DNS answer escaped authorized scope")
    return endpoints
```

Tests inject `resolver`; the future connector accepts `NumericEndpoint`, not a
hostname. Use domain exceptions/codes rather than bare `ValueError` and
`PermissionError` in production.

Source: Python `asyncio` event-loop and `socket.getaddrinfo` documentation;
the all-address allowlist/recheck policy follows OWASP SSRF guidance.

### Bounded product and digest-bound plan

```python
import hashlib
from collections.abc import Iterable


class BudgetExceeded(ValueError):
    pass


def bounded_product(factors: Iterable[int], *, ceiling: int) -> int:
    total = 1
    for factor in factors:
        if type(factor) is not int or factor < 0:
            raise ValueError("budget factors must be non-negative integers")
        total *= factor
        if total > ceiling:
            raise BudgetExceeded(f"attempts exceed absolute ceiling {ceiling}")
    return total


def plan_digest(plan_without_confirmation: dict[str, object]) -> str:
    payload = canonical_json(plan_without_confirmation).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
```

The digest covers canonical targets, approved DNS addresses, requested and
effective limits, work estimate, policy version, task kind, and profile. It
does not include the confirmation object that refers to it.

Source: Python `hashlib` and `json` documentation.

### Cooperative task cancellation/finalization

```python
import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field


class TaskCancelled(Exception):
    pass


@dataclass(slots=True)
class TaskContext:
    cancel_requested: asyncio.Event = field(default_factory=asyncio.Event)
    observations: list[Observation] = field(default_factory=list)
    max_runner_events: int = 0

    def checkpoint(self) -> None:
        if self.cancel_requested.is_set():
            raise TaskCancelled

    def emit(self, observation: Observation) -> None:
        self.checkpoint()
        if len(self.observations) >= self.max_runner_events:
            raise BudgetExceeded("event budget exhausted")
        self.observations.append(observation)


async def run_synthetic(
    context: TaskContext,
    *,
    steps: int,
    pause: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> None:
    for _index in range(steps):
        context.checkpoint()
        await pause(0)
        context.checkpoint()
        # Build one complete observation, then append atomically (no await).
        context.emit(make_synthetic_observation())


async def drive_task(service, handle, plan) -> None:
    deadline = asyncio.get_running_loop().time() + plan.limits.duration_seconds
    try:
        async with asyncio.timeout_at(deadline):
            await run_synthetic(handle.context, steps=plan.synthetic_steps)
    except TaskCancelled:
        await service.finalize_cancelled(handle)
    except TimeoutError:
        await service.finalize_failed(handle, code="task_duration_exhausted")
    except asyncio.CancelledError:
        handle.context.cancel_requested.set()
        finalizer = asyncio.create_task(
            service.finalize_cancelled(handle, code="service_cancelled")
        )
        await asyncio.shield(finalizer)
        raise
    except Exception as exc:
        await service.finalize_failed(handle, code="internal_error", cause=exc)
    else:
        await service.finalize_completed(handle)
```

In production, a service lock/compare-and-set guards terminal transitions.
Keep a strong reference to shielded tasks, as Python's asyncio documentation
requires.

Source: Python `asyncio` cancellation, task, `shield`, and timeout
documentation.

### Explicit SQLite transaction and retention

```python
import sqlite3
from contextlib import closing

TERMINAL = ("completed", "failed", "cancelled")


def connect(path: str) -> sqlite3.Connection:
    db = sqlite3.connect(path, timeout=5.0, isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA busy_timeout = 5000")
    return db


def finalize_and_prune(
    path: str,
    *,
    task_id: str,
    state: str,
    updated_at: str,
    finished_at: str,
    result_json: str,
    cutoff: str,
    keep_count: int,
) -> None:
    if state not in TERMINAL:
        raise ValueError("final state required")
    with closing(connect(path)) as db:
        try:
            db.execute("BEGIN IMMEDIATE")
            cursor = db.execute(
                """
                UPDATE task_history
                   SET state = ?, updated_at = ?, finished_at = ?,
                       result_json = ?
                 WHERE task_id = ?
                   AND state IN ('pending', 'running')
                """,
                (state, updated_at, finished_at, result_json, task_id),
            )
            if cursor.rowcount != 1:
                raise ValueError("unknown or already-terminal task")
            db.execute(
                """
                DELETE FROM task_history
                 WHERE state IN ('completed', 'failed', 'cancelled')
                   AND finished_at < ?
                """,
                (cutoff,),
            )
            db.execute(
                """
                DELETE FROM task_history
                 WHERE task_id IN (
                    SELECT task_id
                      FROM task_history
                     WHERE state IN ('completed', 'failed', 'cancelled')
                     ORDER BY finished_at DESC, task_id DESC
                     LIMIT -1 OFFSET ?
                 )
                """,
                (keep_count,),
            )
            db.commit()
        except BaseException:
            db.rollback()
            raise
```

The storage boundary may catch `BaseException` only to roll back and
immediately re-raise; application/task code must not use a broad catch to
translate cancellation into an ordinary error.

Source: Python `sqlite3` transaction/context documentation and SQLite
transaction/WAL documentation.
</code_examples>

<test_strategy>
## Test Strategy

All normal tests run with `python -m unittest discover -s tests -v`. Use
`subTest` for tables, `IsolatedAsyncioTestCase` for task behavior,
`TemporaryDirectory` for history, and injected resolver/UTC/monotonic/sleep
callables. No test resolves or scans a public host.

### Model/codec contract

- Every outcome, task state, direction, confidence, and capability state
  round-trips through JSON.
- Serialized field order/bytes are deterministic for the same value.
- Missing/extra fields, unsupported schema versions, wrong enum values,
  naive timestamps, negative durations, broken conclusion references, duplicate
  JSON keys, NaN/Infinity, oversized documents, and bool where int is required
  are rejected.
- Mutating source lists/dicts after construction cannot change an
  `AuthorizedPlan`.
- Terminal-state invariants are table-tested; partial observations are legal
  for `cancelled`.

### Target/scope tests

- IPv4, IPv6, canonical/noncanonical CIDR, `/31`, `/32`, exact loopback,
  Unicode/uppercase/trailing-dot hostname, invalid IDNA, URL/userinfo, leading
  zero numeric host, whitespace/NUL, zone ID, IPv4-mapped IPv6, mapped CIDR,
  unspecified, multicast, invalid/duplicate/overlapping ports.
- `192.0.2.7/24` previews `192.0.2.0/24`; confirmation for the raw text alone
  is insufficient.
- Non-loopback without attestation rejects before resolver/runner.
- Any target/port/profile/limit/address-snapshot change alters the plan digest
  and invalidates attestation/full-port confirmation.
- `is_private` is never mocked or used to decide scope.

### DNS rebinding matrix

Use a sequenced fake resolver and recording fake connector:

| Planning answer | Connection-time answer | Expected |
|-----------------|------------------------|----------|
| `192.0.2.10` | same | numeric connector may be called |
| `192.0.2.10` | empty/error | structured resolution failure; no connector |
| `192.0.2.10` | `127.0.0.1` | scope-changed rejection; no connector |
| `192.0.2.10` | `192.0.2.10, 127.0.0.1` | reject whole mixed set |
| two approved addresses | one approved address | allowed subset |
| IPv4 literal | fake DNS result | resolver must not be called |
| mapped IPv6 answer | corresponding approved IPv4 | normalize and apply one policy |
| scoped IPv6 sockaddr | any | unsupported/rejected in v1 |

Assert that every connector call receives a numeric `Ip`/sockaddr object and
never a hostname.

### Budget/property-style tables

Without adding a property-test dependency, generate deterministic boundary
tables:

- each resource at `0`, `1`, soft-1/soft/soft+1, hard-1/hard/hard+1;
- duplicate/merged ranges do not inflate or undercount ports;
- product axes include hosts, ports, profiles/payloads, and repeats;
- full TCP for one host fits attempts but fails without its digest-bound gate;
- four hosts × 65,535 attempts fits 262,140; the next cell fails;
- huge IPv6 networks reject without iteration or materialization;
- concurrency cannot exceed attempts or absolute ceiling;
- runner event permits leave terminal reserve and never exceed plan;
- serialized result bytes stop at the hard cap with explicit truncation/error.

### Task lifecycle/cancellation

- pending → running → completed, expected failure, task deadline, cancellation
  while pending, cancellation while running, repeated cancellation, and cancel
  vs complete race.
- Cancelled result contains only fully emitted observations, has terminal UTC
  timestamp and monotonic duration, and is in SQLite before `cancel()`/CLI
  returns.
- An expected synthetic step failure becomes a structured failed result.
- A forced `asyncio.Task.cancel()` finalizes partial state and propagates
  `CancelledError`.
- Event exhaustion and result-size exhaustion terminate within the reserved
  terminal budget.
- Fake sleep/clock means tests contain no timing sleeps.
- Submitting anything other than a compiled `AuthorizedPlan` is impossible at
  the public service API.

### SQLite history

- Fresh DB migration and exact `user_version`; unsupported newer DB refuses
  mutation.
- Pending insert stores request/plan; trigger rejects later plan mutation.
- Terminal finalization plus age/count pruning succeeds atomically.
- Inject a cleanup SQL failure and verify terminal update rolls back.
- Retention never deletes pending/running and deterministically keeps newest
  terminal rows on equal timestamps.
- Reopening marks orphaned pending/running tasks failed with
  `process_interrupted`.
- Corrupt/unsupported result JSON yields a visible read error, not an empty
  task.
- Quotes/control characters remain safe through parameterized SQL.
- Connection closes after success and exception; no global connection.
- History size is bounded by count, age, event count, and result bytes.

### CLI/package

- `main([...])` returns intentional exits and separates stdout/stderr.
- Human and JSON modes derive from the same wire result.
- `python -m mercury` and installed `mercury` console script match for
  `version`, `model`, and plan rejection.
- Ctrl+C synthetic integration returns 130 only after the history row is
  `cancelled`; keep this as a subprocess test with local temp history.
- Built wheel contains every `src/mercury` module, declares Python `>=3.11`,
  declares only `psutil==7.2.2` at runtime, and installs in a clean venv.
- CI matrix: CPython 3.11, 3.12, 3.13 on Windows/Linux/macOS; packaging smoke
  may run once per OS while pure contract tests run on every interpreter.

### Requirement coverage

| Requirement | Minimum Phase 1 proof |
|-------------|-----------------------|
| EVID-01 | Full versioned result round-trip and CLI JSON snapshot |
| EVID-02 | Outcome enum table; no boolean reachability field |
| EVID-03 | Conclusion references/confidence/alternatives validation |
| EVID-04 | Cooperative cancellation integration with persisted partial result |
| SAFE-01 | Canonical plan JSON includes target and exact count/duration preview |
| SAFE-02 | Boundary matrix plus execution ledger assertions |
| SAFE-03 | Loopback/non-loopback/full-port digest-bound gate tests |
| SAFE-04 | Typed target corpus and sequenced DNS rebinding tests |
| HIST-01 | Atomic lifecycle persistence, retention, recovery, and bounds |
| PACK-01 | Clean wheel install and module/console parity |
| TEST-01 | All above through stdlib `unittest`, no public network |
</test_strategy>

<sota_updates>
## Current Python Compatibility Notes

| Older/tempting approach | Current Phase 1 approach | Why it matters |
|-------------------------|--------------------------|----------------|
| Ad hoc string enums | `StrEnum` (Python 3.11+) | Public string values without third-party dependency |
| Manual child-task cleanup | `TaskGroup` for later bounded child workers | Structured cancellation is in stdlib, but expected probe errors must be values |
| `wait_for` around whole service | `asyncio.timeout_at` with monotonic absolute deadline (3.11+) | One explicit aggregate task deadline |
| `datetime.utcnow()` | `datetime.now(UTC)` | `utcnow()` is deprecated from 3.12 and returns naive time |
| Rely on stable `is_private` tables | Explicit scope networks | Python 3.13 corrected private/global classifications |
| Version-specific `sqlite3.autocommit` parameter | `isolation_level=None` and explicit `BEGIN` | The `autocommit` API arrived after the 3.11 floor |
| Assume `frozen=True` means deep immutable | Frozen records plus immutable nested types | Dataclass freezing only emulates attribute immutability |
| JSON file history | SQLite transaction and bounded retention | Crash/reader/query behavior is solved in stdlib |

The current local environment checked on 2026-07-30 is CPython 3.13.5 with
SQLite 3.49.1. Code must still run on the 3.11 floor and must not assume the
local SQLite version's newest features.
</sota_updates>

<open_questions>
## Open Questions

1. **Are the initial numeric safety ceilings appropriate on real campus and
   enterprise networks?**
   - Known: the proposed hard attempt ceiling permits one full TCP scan and up
     to four full-port host equivalents while remaining finite.
   - Unknown: acceptable duration/concurrency varies greatly by endpoint and
     policy.
   - Recommendation: ship the conservative constants above as named/versioned
     policy, allow only tightening in config, and change absolutes only from
     measured Phase 3 controlled tests.

2. **How much legitimate DNS churn should a frozen hostname plan tolerate?**
   - Known: exact approved-address snapshots prevent rebinding and are easy to
     explain/test.
   - Unknown: CDN/round-robin targets may change between preview and use.
   - Recommendation: fail closed and request a new preview/attestation in v1.
     A future explicit CIDR envelope may be added only with clear UX and tests;
     never silently trust a newly resolved address.

3. **What should the eventual published distribution name be?**
   - Known: import package and console command should remain `mercury`;
     distribution names can differ.
   - Unknown: index/name ownership has not been established.
   - Recommendation: use `mercury-netdiag` in project metadata unless a
     publication check selects another name; do not let this alter module/API
     design.

None of these questions blocks Phase 1 planning.
</open_questions>

<sources>
## Sources

All sources were accessed 2026-07-30. Context7 CLI lookup was attempted first
but its monthly quota was exhausted; official primary documentation and
official package metadata were used directly instead.

### Primary (HIGH confidence)

- Python 3.11 `dataclasses` — frozen/slots/keyword-only records:
  https://docs.python.org/3.11/library/dataclasses.html
- Python 3.11 `enum` — `StrEnum` and unique values:
  https://docs.python.org/3.11/library/enum.html
- Python 3.11 `json` — `allow_nan`, `object_pairs_hook`, and
  `parse_constant`:
  https://docs.python.org/3.11/library/json.html
- Python 3.11 `asyncio` tasks — cancellation, `TaskGroup`, `shield`,
  `timeout`, and `timeout_at`:
  https://docs.python.org/3.11/library/asyncio-task.html
- Python 3.11 event loop — asynchronous `getaddrinfo`:
  https://docs.python.org/3.11/library/asyncio-eventloop.html
- Python 3.11 `socket.getaddrinfo`:
  https://docs.python.org/3.11/library/socket.html
- Python 3.11 `ipaddress` — strict/canonical networks, mapped addresses, and
  address properties:
  https://docs.python.org/3.11/library/ipaddress.html
- Python 3.13 `ipaddress` — documented 3.13 private/global classification
  corrections:
  https://docs.python.org/3.13/library/ipaddress.html
- Python 3.11 `datetime` and monotonic `time`:
  https://docs.python.org/3.11/library/datetime.html and
  https://docs.python.org/3.11/library/time.html
- Python 3.11 `sqlite3` — transactions, thread checking, row factory, and
  parameterized SQL:
  https://docs.python.org/3.11/library/sqlite3.html
- SQLite WAL and PRAGMA documentation:
  https://www.sqlite.org/wal.html and
  https://www.sqlite.org/pragma.html#pragma_user_version
- Python 3.11 `unittest.IsolatedAsyncioTestCase`:
  https://docs.python.org/3.11/library/unittest.html
- Python packaging `pyproject.toml` guide and entry-point specification:
  https://packaging.python.org/en/latest/guides/writing-pyproject-toml/ and
  https://packaging.python.org/en/latest/specifications/entry-points/
- Setuptools `pyproject.toml` configuration:
  https://setuptools.pypa.io/en/latest/userguide/pyproject_config.html
- Official PyPI metadata checked on 2026-07-30:
  `psutil` 7.2.2, `setuptools` 83.0.0, and `build` 1.5.0:
  https://pypi.org/project/psutil/
  https://pypi.org/project/setuptools/
  https://pypi.org/project/build/
- OWASP SSRF Prevention Cheat Sheet — canonical validation, allowlists, DNS
  pinning/rebinding considerations, and checking all resolved addresses:
  https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

### Project-local primary context (HIGH confidence)

- `.planning/PROJECT.md`
- `.planning/REQUIREMENTS.md`
- `.planning/ROADMAP.md`
- `.planning/STATE.md`
- `.planning/phases/01-evidence-and-safety-foundation/01-CONTEXT.md`
- `.planning/research/SUMMARY.md`
- `.planning/research/STACK.md`
- `.planning/research/PITFALLS.md`
- `.planning/research/PONYTAIL.md`
- `AGENTS.md`

### Secondary/tertiary

None. Implementation recommendations above are based on project decisions,
official Python/SQLite/OWASP documentation, and official package metadata.
</sources>

<metadata>
## Metadata

**Research scope:**

- Core technology: CPython 3.11+ standard library and SQLite
- Runtime dependency: psutil packaging boundary only
- Patterns: versioned JSON, immutable plan compilation, DNS recheck,
  cooperative cancellation, transactional retention
- Pitfalls: scope/confirmation bypass, work explosion, cancellation loss,
  permissive JSON, SQLite concurrency, packaging drift

**Confidence breakdown:**

| Area | Confidence | Basis |
|------|------------|-------|
| Standard stack | HIGH | Locked project decision and official APIs/metadata |
| Evidence/codec architecture | HIGH | Small explicit contract using stable stdlib features |
| Authorization/DNS pattern | HIGH | OWASP guidance plus numeric-connector boundary |
| Task lifecycle | HIGH | Python 3.11 cancellation/timeout semantics |
| SQLite design | HIGH | Official Python/SQLite transaction behavior |
| Numeric limits/retention defaults | MEDIUM-HIGH | Conservative and internally consistent, but not field-tested |
| Cross-platform packaging | MEDIUM-HIGH | Wheel path is standard; clean OS matrix still needs execution |

**Valid until:** 2026-10-30 for implementation patterns. Recheck package
versions immediately before locking a release.
</metadata>

---

*Phase: 01-evidence-and-safety-foundation*  
*Research completed: 2026-07-30*  
*Ready for planning: yes*
