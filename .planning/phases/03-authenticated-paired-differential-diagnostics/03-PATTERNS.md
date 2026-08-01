# Phase 3: Authenticated Paired Differential Diagnostics - Pattern Map

**Mapped:** 2026-08-01  
**Files analyzed:** 12 planned new/modified files  
**Analogs found:** 12 / 12

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `src/mercury/peer.py` | service | request-response + event-driven | `src/mercury/probes.py`, `src/mercury/codec.py` | role-match |
| `src/mercury/paired.py` | service | request-response + event-driven | `src/mercury/diagnosis.py`, `src/mercury/tasks.py` | role-match |
| `src/mercury/app.py` | provider/facade | request-response | `src/mercury/app.py` | exact |
| `src/mercury/cli.py` | controller | request-response | `src/mercury/cli.py` | exact |
| `src/mercury/render.py` | utility | transform | `src/mercury/render.py` | exact |
| `src/mercury/models.py` | model | transform | `src/mercury/models.py` | exact |
| `src/mercury/codec.py` | codec/utility | transform | `src/mercury/codec.py` | exact |
| `tests/test_peer.py` | test | request-response + event-driven | `tests/test_models.py`, `tests/test_tasks.py` | role-match |
| `tests/test_paired.py` | test | event-driven | `tests/test_phase2_smoke.py`, `tests/test_tasks.py` | role-match |
| `tests/fixtures/tls/peer-client-cert.pem` | test fixture | file-I/O | `tests/fixtures/tls/localhost-cert.pem` | role-match |
| `tests/fixtures/tls/peer-client-key.pem` | test fixture | file-I/O | `tests/fixtures/tls/localhost-key.pem` | role-match |
| `tests/fixtures/tls/README.md` | config/documentation | file-I/O | `tests/fixtures/tls/README.md` | exact |

`planner.py`, `policy.py`, `tasks.py`, `profiles.py`, and `probes.py` are integration sources, not presumed Phase 3 edit targets. Reuse their boundaries first; modify them only where the new fixed paired semantics cannot be expressed without weakening their checks.

## Pattern Assignments

### `src/mercury/peer.py` (service, request-response + event-driven)

**Analogs:** `src/mercury/probes.py`; `src/mercury/codec.py`

**Imports and injected-I/O pattern** — [`probes.py`](../../../src/mercury/probes.py:7) lines 7-22:

```python
import asyncio
import ssl
import time
from collections.abc import Awaitable, Callable

Connector = Callable[..., Awaitable[tuple[asyncio.StreamReader, asyncio.StreamWriter]]]
```

Keep stream open/connect and clocks injectable where this makes controlled loopback tests deterministic. Use standard-library `asyncio`/`ssl`; do not introduce an RPC framework or custom TLS implementation.

**Strict known-field decoder** — [`codec.py`](../../../src/mercury/codec.py:115) lines 115-129:

```python
def _expect_fields(value: dict[str, Any], *, required: Iterable[str],
                   optional: Iterable[str] = (), field: str) -> None:
    required_set = set(required)
    allowed = required_set | set(optional)
    missing = required_set - value.keys()
    unknown = value.keys() - allowed
    if missing:
        raise CodecError(f"{field} is missing fields: {', '.join(sorted(missing))}")
    if unknown:
        raise CodecError(f"{field} has unknown fields: {', '.join(sorted(unknown))}")
```

Pair this with [`codec.py`](../../../src/mercury/codec.py:427) lines 427-480: duplicate-key rejection, non-finite-number rejection, UTF-8 decoding, bounded byte size, and normalized `CodecError`. The peer frame reader must first read the fixed four-byte length, reject zero/over-limit sizes, then call this strict decoder before dispatch.

**TLS result categorization** — [`probes.py`](../../../src/mercury/probes.py:179) lines 179-213:

```python
except ssl.SSLCertVerificationError:
    return _observation(prepared, EvidenceKind.TLS_VERIFICATION_FAILED,
                        Disposition.NEGATIVE, ...)
except ssl.SSLError as exc:
    return _observation(prepared, EvidenceKind.TLS_HANDSHAKE_FAILED,
                        Disposition.NEGATIVE,
                        detail={"category": type(exc).__name__})
```

For peer control, reject before dispatch and persist only a categorical authentication/audit outcome plus configured peer identity. Never serialize a token, DER certificate, configuration object, private-key data, or a token-bearing exception message.

**Integration cautions:** construct distinct client/server `SSLContext`s with CA verification and `CERT_REQUIRED`; after the handshake compare the configured SHA-256 pin and token using `hmac.compare_digest`. Derive the peer IP from `writer.get_extra_info("peername")`; never accept a destination, listener port, CIDR, hostname result, or payload from a control frame. The four permitted operations are capability negotiation, plan submit, correlated result read, and caller-owned correlated cancellation only.

---

### `src/mercury/paired.py` (service, request-response + event-driven)

**Analogs:** `src/mercury/diagnosis.py`; `src/mercury/tasks.py`; `src/mercury/probes.py`

**Plan-then-admit execution boundary** — [`diagnosis.py`](../../../src/mercury/diagnosis.py:127) lines 127-176:

```python
class DiagnosisRunner:
    async def __call__(self, context: TaskContext) -> None:
        if context.plan.digest != self.compiled.plan.digest:
            raise ValueError("diagnosis context plan does not match its compilation")
        for step in context.plan.preview.steps:
            if step.probe_kind in {ProbeKind.NATIVE_PING, ProbeKind.NATIVE_PATH}:
                await self.native_dispatcher(context, step.id)
            else:
                await self.protocol_dispatcher(context, step.id)
```

The paired runner must similarly receive a canonical immutable plan, not arbitrary peer input, and invoke the existing service/runner path rather than creating a second task system.

**Single accounting/admission gate** — [`tasks.py`](../../../src/mercury/tasks.py:476) lines 476-554:

```python
prepared = self.plan.preflight_step(step_id, **preflight_kwargs)
...
if next_datagrams > self.plan.preview.estimate.generated_datagrams:
    raise TaskError("step admission exceeded the datagram reservation")
if next_bytes > self.plan.preview.estimate.application_bytes:
    raise TaskError("step admission exceeded the application-byte reservation")
self._admitted_steps.add(step_id)
self._prepared_steps[step_id] = prepared
self.admitted += 1
return prepared
```

Do not call `account_io`: [`tasks.py`](../../../src/mercury/tasks.py:566) lines 566-569 deliberately reject runner-owned accounting. Every TCP listener action and UDP reply must correspond to an authorized, admitted finite plan step.

**Evidence binding** — [`tasks.py`](../../../src/mercury/tasks.py:571) lines 571-639 requires an admitted step and verifies target, attempt, probe, direction, evidence kind, reserved detail fields, event limits, and output limits before adding canonical step details.

**Integration caution (important):** current `TaskContext.record` hard-codes local/outbound directions at [`tasks.py`](../../../src/mercury/tasks.py:590). Paired `arrived`, `replied`, inbound, and reverse evidence therefore cannot be inserted by bypassing `record`. Design an explicit, narrowly validated paired evidence extension at this existing task boundary (or model A→B/B→A actions as fixed executable steps) so target, attempt, direction, evidence-kind allowlist, persistence safety, and ceilings stay enforced.

**Typed socket outcome pattern** — [`probes.py`](../../../src/mercury/probes.py:52) lines 52-80 maps refusal, reset, network/host unreachable, timeout, and execution error to distinct evidence. Preserve that distinction; UDP missing arrival/reply is `SILENT`/`INCONCLUSIVE`, not an asserted firewall, route, packet-loss, or switch diagnosis.

---

### `src/mercury/app.py` (provider/facade, request-response)

**Analog:** `src/mercury/app.py`

**Constructor injection and thin service composition** — [`app.py`](../../../src/mercury/app.py:46) lines 46-64:

```python
class MercuryApplication:
    def __init__(self, *, history: HistoryStore,
                 status_collector: Callable[..., object] = collect_status,
                 grant_factory: Callable[[DiagnosisRequest], ScopeGrant] = _default_grant,
                 compiler=compile_diagnosis, runner_factory=DiagnosisRunner,
                 service_factory=TaskService) -> None:
        self.history = history
        self.status_collector = status_collector
        self.grant_factory = grant_factory
        self.compiler = compiler
        self.runner_factory = runner_factory
        self.service_factory = service_factory
```

**Cancellation/final result shape** — [`app.py`](../../../src/mercury/app.py:72) lines 72-95:

```python
service = self.service_factory(self.history)
task_id = service.submit_diagnosis(compiled, self.runner_factory(compiled),
                                   requested_config={...})
try:
    result = await service.wait(task_id)
except asyncio.CancelledError:
    service.cancel(task_id)
    result = await asyncio.shield(service.wait(task_id))
if not isinstance(result, TaskResult):
    raise RuntimeError("diagnosis service returned an invalid result")
return result
```

Add small `agent` lifecycle and `paired` orchestration methods here, accepting injected peer factories/clocks/transports for tests. CLI and render modules must not create probes, listeners, or peer sockets directly.

---

### `src/mercury/cli.py` (controller, request-response)

**Analog:** `src/mercury/cli.py`

**Parser convention** — [`cli.py`](../../../src/mercury/cli.py:97) lines 97-139:

```python
def _add_json_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", default=argparse.SUPPRESS,
                        help="emit stable JSON instead of human-readable output")

subparsers = parser.add_subparsers(dest="command", required=True)
diagnose_parser = subparsers.add_parser("diagnose", help="run an authorized layered diagnosis")
...
_add_json_option(diagnose_parser)
```

Copy this for `agent` and `paired`: parse operator-supplied configuration paths and explicit unsafe-development flag only. Do not add tokens to URLs, defaults, history arguments, or human error output.

**Facade-only dispatch and stable projection** — [`cli.py`](../../../src/mercury/cli.py:389) lines 389-403:

```python
with HistoryStore(args.data_path) as history:
    application = MercuryApplication(history=history)
    result = asyncio.run(application.diagnose(request))
    _emit(result_to_wire(result), render_diagnosis(result), as_json=as_json)
    return diagnosis_exit_code(result)
```

**Exit semantics** — [`cli.py`](../../../src/mercury/cli.py:356) lines 356-367 map the one canonical diagnosis conclusion to healthy=0, failed=1, partial=4. Add a paired-result equivalent that requires exactly one paired-health conclusion; preserve the existing `--json` authoritative document and policy/input/internal boundaries at [`cli.py`](../../../src/mercury/cli.py:461).

---

### `src/mercury/render.py` (utility, transform)

**Analog:** `src/mercury/render.py`

**Projection-only rendering** — [`render.py`](../../../src/mercury/render.py:64) lines 64-83:

```python
def render_diagnosis(result: TaskResult) -> str:
    health = next((item for item in result.conclusions
                   if item.id == "diagnosis-health"), None)
    if health is None:
        raise RuntimeError("diagnosis-health conclusion contract violated")
    ...
    lines.append("Supporting observations: " + ", ".join(health.observation_ids))
    return "\n".join(lines)
```

Create `render_paired` as a pure projection of a completed canonical paired result: lead with fixed layer/direction matrix, show cited observation IDs, then bounded conclusions/limitations. Do not derive reachability from temporary peer frames or reclassify silence while rendering.

---

### `src/mercury/models.py` and `src/mercury/codec.py` (model/codec, transform)

**Analogs:** `src/mercury/models.py`; `src/mercury/codec.py`

**Immutable validated canonical values** — [`models.py`](../../../src/mercury/models.py:230) lines 230-281:

```python
@dataclass(frozen=True, slots=True)
class Observation:
    ...
    def __post_init__(self) -> None:
        ...
        allowed = _KIND_DISPOSITIONS[self.evidence_kind]
        if self.disposition not in allowed:
            raise ModelError(...)
        frozen = freeze_json(self.detail)
        if not isinstance(frozen, Mapping):
            raise ModelError("observation detail must be an object")
        object.__setattr__(self, "detail", frozen)
```

**Cited conclusion contract** — [`models.py`](../../../src/mercury/models.py:284) lines 284-324 requires at least one unique, validated observation ID. Paired matrix conclusions must cite the actual directional source observations.

**Task document invariant** — [`models.py`](../../../src/mercury/models.py:381) lines 381-474 validates terminal state, bounded collection sizes, compatible schema, unique observations/conclusions, known conclusion citations, and bounded errors. Extend conservatively: prefer endpoint/correlation/phase as bounded frozen observation detail or a small explicit immutable paired submodel. Do not make task/config/pair secrets serializable.

**Wire symmetry and field rejection** — [`codec.py`](../../../src/mercury/codec.py:338) lines 338-424 show `result_to_wire` and `result_from_wire`; whenever a new public canonical field is chosen, update both sides and exact required fields together. Maintain duplicate-key/non-finite rejections in [`codec.py`](../../../src/mercury/codec.py:427).

**Schema caution:** only update [`__init__.py`](../../../src/mercury/__init__.py:5) schema version/support set if the public document shape changes incompatibly. New evidence kinds also need deliberate compatibility membership in `models.py`; do not silently make an old schema claim it understands new paired evidence.

---

### `tests/test_peer.py` (test, request-response + event-driven)

**Analogs:** `tests/test_models.py`; `tests/test_tasks.py`

**Strict-decoder negative test pattern** — [`test_models.py`](../../../tests/test_models.py:300) lines 300-332:

```python
with self.assertRaisesRegex(CodecError, "duplicate"):
    result_from_json('{"schema_version":"1.0","schema_version":"1.0"}')
...
with self.assertRaisesRegex(CodecError, "unknown"):
    result_from_json(document)
```

Use equivalent focused tests for frame length, truncated/invalid UTF-8 JSON, duplicate/unknown fields, unknown protocol version, wrong type, nesting/string ceilings, expiry, identity/correlation mismatch, and replay/cache-full behavior.

**Async state/persistence fixture pattern** — [`test_tasks.py`](../../../tests/test_tasks.py:69) lines 69-127:

```python
class TaskTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.history = HistoryStore(Path(self.temporary.name) / "history.sqlite3")
        self.service = TaskService(self.history)
```

Use loopback server/client contexts, injected wall/monotonic clocks, and repository-owned PEM files. Assert mTLS/pin/token failures occur before control dispatch and that task/history/error wire data contain no token, private-key, DER-certificate, or config-secret value.

---

### `tests/test_paired.py` (test, event-driven)

**Analogs:** `tests/test_phase2_smoke.py`; `tests/test_tasks.py`

**Controlled-loopback facade test** — [`test_phase2_smoke.py`](../../../tests/test_phase2_smoke.py:38) lines 38-70:

```python
class Phase2SmokeTests(unittest.IsolatedAsyncioTestCase):
    async def test_loopback_diagnosis_round_trips_terminal_result(self) -> None:
        request = DiagnosisRequest(profile="custom", targets=("127.0.0.1:443",), authorized=True)
        ...
        result = await app.diagnose(request)
        record = history.list_tasks(limit=1)[0]
        self.assertEqual(record.result, result)
```

Use only loopback/owned listeners. Cover finite listener active/busy/expired/permission statuses, cancel cleanup, exact authenticated-source reverse binding, third-party target rejection, TCP connected/refused/timeout, UDP reply/silent, DNS difference, role swap, and matrix citations/asymmetry.

**Ceiling-regression test** — [`test_tasks.py`](../../../tests/test_tasks.py:886) lines 886-899 verifies that runner-owned I/O accounting fails. Paired listener/reply tests must prove the accepted immutable plan reserves all attempted data-plane work instead of adding an escape hatch.

---

### `tests/fixtures/tls/peer-client-cert.pem`, `peer-client-key.pem`, and `README.md` (test fixture/config, file-I/O)

**Analog:** [`tests/fixtures/tls/README.md`](../../../tests/fixtures/tls/README.md:1) lines 1-9:

```markdown
`test-ca.pem` is a private certificate authority used only by the controlled
loopback tests. `localhost-cert.pem` and `localhost-key.pem` form a server
certificate chain signed by that CA.
...
These files are intentionally committed test fixtures, are excluded from
package data, and must never be used for production listeners or trust stores.
```

Add repository-owned, test-only client certificate/key material signed by the existing test CA (and client-auth-capable as needed); document subject/SAN/EKU purpose. Do not generate certificates during every test run and do not repurpose test fixtures as production defaults.

## Shared Patterns

### Immutable scope, plan, and DNS revalidation

**Sources:** [`policy.py`](../../../src/mercury/policy.py:402), [`planner.py`](../../../src/mercury/planner.py:1348)  
**Apply to:** peer submit admission and every paired active/listener action.

```python
def authorize_targets(targets, grant, *, now=None) -> None:
    grant.assert_current(now)
    for target in targets:
        if target.is_loopback:
            continue
        if not grant.attested:
            raise PolicyError("non-loopback target ... requires explicit authorization attestation")
        if target.address is not None and not grant.permits_address(target.address):
            raise PolicyError("address ... is outside scope")

def validate_plan(plan: ProbePlan, *, now=None) -> ProbePlan:
    if type(plan) is not ProbePlan:
        raise ConfirmationError("plan must be ProbePlan")
    validate_preview(plan.preview, now=now or datetime.now(timezone.utc))
```

The receiver recompiles/revalidates against its own scope, current time, budgets, and DNS resolution. A peer's digest/cost/DNS result is input to validate, never evidence of authorization.

### Canonical evidence and uncertainty

**Sources:** [`models.py`](../../../src/mercury/models.py:50), [`probes.py`](../../../src/mercury/probes.py:52)  
**Apply to:** all A→B/B→A phases, matrix rows, and conclusions.

`EvidenceKind.SILENT` is distinct from `TCP_REFUSED`, `TIMEOUT`, `UDP_APPLICATION_REPLY`, and `PEER_OBSERVED_ARRIVAL`. Preserve the established typed disposition mapping and cite observations. Matrix text can report an observed directional difference and alternatives, but must not assert firewall, loss, route, gateway, or switch cause without direct evidence.

### Persistence/redaction and output ceilings

**Source:** [`tasks.py`](../../../src/mercury/tasks.py:641) lines 641-654:

```python
def _append_observation(self, observation: Observation) -> None:
    wire = observation_to_wire(observation)
    assert_persistence_safe(wire, path="$.result.observations[]")
    if self._event_count + 2 > self.plan.preview.limits.max_events:
        raise TaskError("task event budget exhausted")
    self._assert_output_fits(observations=(*self._observations, observation))
    self._observations.append(observation)
```

Use this existing canonical persistence path for sanitized audit/evidence. Record categorical peer authentication/listener outcomes only; never allow sensitive config or raw payload material into `requested_config`, observations, conclusions, errors, history, or JSON.

### Presentation boundary

**Sources:** [`app.py`](../../../src/mercury/app.py:46), [`cli.py`](../../../src/mercury/cli.py:389), [`render.py`](../../../src/mercury/render.py:64)  
**Apply to:** `agent`, `paired`, JSON, and human output.

CLI parses/dispatches to `MercuryApplication`; render functions project canonical results. Neither layer may start a peer listener, dial a peer, resolve a remote target, or infer conclusions.

## No Analog Found

| File/Concern | Role | Data Flow | Reason / Planner Guidance |
|---|---|---|---|
| mTLS server startup, pin/token gate, bounded nonce replay cache | service | request-response | No existing server-side peer-control analog. Compose the strict `codec.py` decoder with `asyncio`/`ssl` and the existing task/policy boundaries; keep it to the four locked operations. |
| Temporary nonce-tagged UDP echo lease | service | event-driven | No existing datagram listener analog. Use one finite `asyncio` datagram endpoint with plan expiry/cancellation cleanup; preserve task admission/evidence constraints. |
| Fixed endpoint-labelled directional matrix | model/utility | transform | No existing paired projection. Implement only as a deterministic projection of canonical cited observations, not a new diagnosis engine. |

## Metadata

**Analog search scope:** `src/mercury/{app,cli,codec,diagnosis,models,planner,policy,probes,profiles,render,tasks}.py`; `tests/{test_cli,test_models,test_phase2_smoke,test_tasks}.py`; `tests/fixtures/tls/`  
**Files scanned:** 18  
**Pattern extraction date:** 2026-08-01
