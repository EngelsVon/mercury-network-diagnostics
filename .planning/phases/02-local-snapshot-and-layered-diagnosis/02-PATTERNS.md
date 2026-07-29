# Phase 02 Pattern Map

**Phase:** Local Snapshot and Layered Diagnosis
**Mapped:** 2026-07-30
**Inputs:** `02-CONTEXT.md`, `02-RESEARCH.md`, Phase 1 source and tests

## Purpose

Map every likely Phase 2 file to the closest proven repository pattern. This is
not a new architecture: Phase 2 extends the canonical model/planner/task
service and adds thin collectors/runners behind a small application facade.

## Data Flow

```text
CLI parse
  -> MercuryApplication
     -> passive inventory -> platform adapter -> canonical TaskResult
     -> diagnosis request -> sparse planner -> TaskService
        -> admitted prepared action -> probe/native runner
        -> core-bound Observation -> pure health classifier
        -> canonical TaskResult
  -> render human or result_to_wire JSON
```

No new file may create a second result, authorization, scheduler, persistence,
or presentation-specific I/O path.

## File-to-Analog Map

| Phase 2 file | Role | Closest analog | Pattern to preserve |
|--------------|------|----------------|---------------------|
| `src/mercury/app.py` | Shared use-case facade | `cli._run_synthetic()` plus `TaskService` | Presentation delegates; service returns `(TaskResult, health)`-level data, not rendered text |
| `src/mercury/inventory.py` | Passive host/interface snapshot | `tasks._make_result()` and model constructors | One canonical result; frozen observations/capabilities; independent failure retention |
| `src/mercury/platform/common.py` | Bounded native-command record/runner | `TaskContext` resource checks and `history.sanitize_*` | Fixed argv, explicit timeout/output bounds, typed errors, sanitized detail |
| `src/mercury/platform/windows.py` | PowerShell JSON route/DNS and ping/path parser | `policy` edge parsing | Parse/normalize at trust boundary, reject malformed shapes, never infer missing facts |
| `src/mercury/platform/linux.py` | `ip -j`, resolv.conf, ping/path parser | `policy` edge parsing | Structured-first, exact fallback, fixture-driven degradation |
| `src/mercury/platform/macos.py` | route/netstat/scutil and ping/path parser | `policy` edge parsing | Narrow field parser, per-source failure, no global locale assumptions |
| `src/mercury/profiles.py` | Frozen `basic-v1`/`china-v1` data | `planner.DEFAULT_LIMITS` | Immutable constants with exact finite values; no registry/config framework |
| `src/mercury/probes.py` | DNS/TCP/TLS/HTTP/native runner | `SyntheticRunner` | Iterate only planned steps, `admit -> record -> complete_attempt`, expected failures become evidence |
| `src/mercury/diagnosis.py` | Sparse compilation and pure classifier | `planner.preview_plan()` and `tasks._derive_conclusion()` | Canonical deterministic plan plus evidence-linked conclusion; lifecycle and health remain separate |
| `src/mercury/models.py` | New evidence vocabulary/schema support | Existing enum/disposition truth table | Exhaustive enum mapping, strict validation, immutable data |
| `src/mercury/codec.py` | Exact 1.0/1.1 decoding | Existing strict wire decoders | Reject unknown fields/types; explicit version support |
| `src/mercury/planner.py` | Sparse action identity/cost | Existing `ProbeStep`, `_compile_steps`, preview digest | Every meaningful field participates in canonical ID/digest; legacy preview is a convenience |
| `src/mercury/policy.py` | Exact hostname/address/action scope | Existing `ScopeGrant` and resolution recheck | Attest name, authorize every exact address, fail closed on escape |
| `src/mercury/tasks.py` | Authoritative probe/evidence binding | Existing reserved detail injection | Runner cannot forge probe kind, target, transport, port, DNS-change, or cost |
| `src/mercury/history.py` | Safe request/plan projection | Existing `_REQUEST_KEYS`/projection | Add only explicit non-secret fields; no headers/body/raw native output |
| `src/mercury/cli.py` | `status`/`diagnose` grammar and exit mapping | Current `_dispatch()` | Parse/project only; structured error boundary remains centralized |
| `src/mercury/render.py` | Human status/layer summary | Existing pure `render_result()` | Pure function over canonical result, no psutil/socket/subprocess calls |
| `tests/test_inventory.py` | Host/NIC normalization | `test_models.py` | Table-driven exact types/boundaries/frozen results |
| `tests/test_platforms.py` | Three OS parser contracts | `test_policy.py` | `subTest` fixture tables, malformed/one-past/error cases |
| `tests/test_profiles.py` | Profile and custom grammar | `test_policy.py` | Exact canonical preview and boundary rejection |
| `tests/test_probes.py` | Protocol/native semantics | `test_tasks.py` | `IsolatedAsyncioTestCase`, injected I/O, loopback only |
| `tests/test_diagnosis.py` | Sparse plan/classifier | `test_policy.py` + `test_tasks.py` | Pure exhaustive health table plus adversarial binding |
| `tests/test_cli.py` | Same-result projection/exits | Existing direct `main()` capture | Assert JSON category/shape, stdout/stderr, stable constants |
| `tests/test_installation.py` | Wheel/entry parity | Existing clean temp wheel test | Extend stable cases; never rely on source cwd/import path |

## Canonical Model Pattern

Use frozen dataclasses and string enums exactly like `models.py`:

```python
@dataclass(frozen=True, slots=True)
class Observation:
    id: str
    probe: str
    disposition: Disposition
    evidence_kind: EvidenceKind
    direction: Direction
    target: str
    ...
```

Phase 2 additions must update the exhaustive `_KIND_DISPOSITIONS` mapping and
tests. Do not add free-form evidence kinds or boolean reachability fields.

`TaskResult` remains the only public result:

```python
@dataclass(frozen=True, slots=True)
class TaskResult:
    task_id: str
    task_kind: str
    ...
    observations: tuple[Observation, ...]
    conclusions: tuple[Conclusion, ...]
    capabilities: tuple[Capability, ...]
```

Inventory may construct a completed result with `Progress(0, 0, 0)`. Diagnosis
must use the existing task service so active work inherits budgets,
cancellation, history, and terminalization.

## Planner Pattern

Current `ProbeStep` is canonical and validates every field in
`__post_init__`; `to_wire()` drives both digest and persistence. Preserve that
shape while making actions sparse:

```python
@dataclass(frozen=True, slots=True)
class ProbeStep:
    id: str
    target: str
    address: str
    port: int
    transport: Transport
    attempt: int
    source_hostname: str | None
    resolution_slot: int | None
    payload: PayloadMetadata
    cost: StepCost
```

Required extension pattern:

- add a finite `ProbeKind`;
- make port/transport/address optional only for explicitly allowed kinds;
- add exact timeout/max-observation/path fields, not an open-ended options bag;
- validate field combinations in `__post_init__`;
- serialize every field in `to_wire()`;
- derive ID from the same canonical wire fields;
- keep legacy `preview_plan()` by translating TCP/UDP Cartesian inputs to
  explicit operations before the shared compiler.

Do not create a parallel `DiagnosticPlan` that bypasses `ProbePlan`,
`validate_plan()`, `TaskService`, or recovery.

## Task Binding Pattern

Real runners must follow the proven `SyntheticRunner` lifecycle:

```python
prepared = await context.admit(step.id)
context.record(observation, step_id=step.id)
context.complete_attempt(step.id)
```

Extend the existing reserved-detail injection:

```python
detail.update(
    {
        "plan_step_id": step_id,
        "planned_target": prepared.step.target,
        "port": prepared.step.port,
        "transport": prepared.step.transport.value,
        "dns_changed": prepared.dns_changed,
    }
)
```

Probe kind and any optional action-specific identity become reserved fields.
The core either overwrites `Observation.probe` with the planned kind or rejects
a mismatch. It also enforces a per-kind evidence allowlist. Expected refusal,
timeout, TLS rejection, HTTP status, native silence, and missing tools produce
observations/capabilities; they do not raise out of the runner.

## Policy Pattern

Reuse:

```python
authorize_targets((target,), grant, now=now)
addresses = recheck_resolution(snapshot, grant, now=now)
```

Profile/custom compilation may derive only exact `/32` and `/128` grants after
the operator attests the exact names. The preview shows and digest-binds every
answer/action. Each socket runner receives `PreparedStep.address`; passing the
hostname to a connector is a regression because it triggers an uncontrolled
second resolution.

## Passive Adapter Pattern

Adapters return normalized records and source capabilities. They do not return
CLI strings or conclusions.

Use one small command record:

```python
@dataclass(frozen=True, slots=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False
```

The production runner enforces:

- fixed executable and argument array;
- no `shell=True`;
- timeout and output byte limit;
- UTF-8/explicit Windows PowerShell encoding;
- child kill/reap on timeout;
- bounded sanitized diagnostics.

Tests inject `CommandResult` fixtures. Do not mock `subprocess` internals in
every parser test.

## Classifier Pattern

Follow `Conclusion` invariants: every result cites existing observation IDs and
states confidence/alternatives/limitations.

Add a pure domain classifier with one stable conclusion ID, for example
`diagnosis-health`. CLI looks up this conclusion and maps:

```text
healthy -> EXIT_OK (0)
failed  -> EXIT_FAILED (1)
partial -> EXIT_PARTIAL (4)
```

It must not map `TaskState.COMPLETED` directly to exit 0. Optional ping/path
cannot turn silence into failure. The generic lifecycle summary may coexist but
must not override the domain conclusion.

## Persistence Pattern

`history.py` intentionally projects exact request fields and rejects suspicious
content. Extend the allowlist only for:

- effective profile/version;
- canonical custom targets;
- finite timeout;
- non-secret authorization metadata;
- sparse plan wire fields already validated by planner models.

Never persist HTTP bodies, arbitrary headers, cookies, certificate bodies,
native raw dumps, tokens, payloads, or exception objects.

## Test Patterns

### Table-driven boundary tests

Mirror `test_policy.py`:

```python
for value, expected in cases:
    with self.subTest(value=value):
        self.assertEqual(parse(value), expected)
```

Every grammar/budget/parser table includes valid minimum/maximum, one-past,
malformed type, Unicode, duplicate, empty, timeout, and overflow cases.

### Async task/probe tests

Mirror `test_tasks.py`:

- `unittest.IsolatedAsyncioTestCase`;
- temporary `HistoryStore`;
- injected wall/monotonic clocks and resolver/connector/command runner;
- adversarial runner attempts to forge probe/target/reserved detail;
- cancellation before/during admission and native process timeout;
- no public endpoint.

### CLI tests

Mirror existing `test_cli.py`: invoke `main()` directly, capture
stdout/stderr, decode JSON, and assert exact exit constants. Patch only the
application facade so a presentation test cannot accidentally touch a network.

### Packaging tests

Extend the existing copied-clean-source wheel test. New command parity is
verified from an empty directory using both the console script and
`python -m mercury`.

## High-Risk Cross-File Links

| From | To | Required proof |
|------|----|----------------|
| `profiles.py` | `planner.py` | Exact sparse actions; no target/port union |
| `planner.py` | `tasks.py` | Probe identity and worst-case output/event cost are service-enforced |
| `tasks.py` | `probes.py` | Only prepared numeric addresses reach connectors |
| `probes.py` | `models.py` | Every expected outcome maps to an allowed evidence/disposition pair |
| `inventory.py` | platform modules | One source failure retains other observations and capability details |
| `diagnosis.py` | result conclusions | Health cites exact selected-action observations |
| `app.py` | CLI/future WebUI | Both entry points receive the same canonical result |
| `history.py` | new request/plan fields | Valid diagnosis persists; credential/body/raw-output variants fail |

## Files Not to Add

- No adapter base class, registry, or entry-point plugin.
- No custom DNS protocol, raw ICMP, packet capture, or HTTP parser.
- No second scheduler/result/SQLite repository.
- No Web/API/frontend files in Phase 2.
- No production certificate/key or public-live test.
- No discovery, neighbor, LLDP, peer, UDP payload, full-port, or repeated-route
  module.

---

*Pattern map is implementation guidance; `02-CONTEXT.md` and requirements
remain authoritative.*
