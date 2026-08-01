"""Finite, source-bound paired listener leases.

This module deliberately implements one small data-plane profile.  A lease is
not a remote probe API: its address, ports, correlation, and opaque payload are
all fixed by a locally validated plan and the authenticated peer source.
"""

from __future__ import annotations

import asyncio
import errno
import hashlib
import ipaddress
import math
import secrets
import struct
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from datetime import datetime, timedelta

from .codec import result_from_wire, result_to_wire
from .models import (
    Confidence,
    Conclusion,
    Direction,
    Disposition,
    EvidenceKind,
    Health,
    Observation,
    ProbeKind,
    TaskResult,
    utc_now,
)
from .planner import (
    DEFAULT_LIMITS, PayloadMetadata, ProbePlan, ProbeSpec, ProbeStep, StepCost, Transport,
    authorize_plan, preview_probe_plan, validate_plan,
)
from .peer import PEER_PROTOCOL_VERSION, PeerClient, PeerConfig, PeerError, PeerFrame
from .policy import ScopeGrant
from .tasks import TaskContext, TaskService

_TCP_REPLY = b"MRP1A"
_MAX_PAYLOAD = 1_400
_MATRIX_ORDER = {"local_snapshot": 0, "system_dns": 1, "native_path": 2, "tcp_connect": 3, "udp_exchange": 4, "tls_handshake": 5, "http_exchange": 6}
_PAIRED_MANIFEST = "paired-v1"
_ROLE_A_TO_B = "A-to-B"
_ROLE_B_TO_A = "B-to-A"

RoleExecutor = Callable[[str, str], Awaitable[TaskResult]]


class PairedError(RuntimeError):
    """A pair-only lease was rejected before listener I/O."""


@dataclass(frozen=True, slots=True)
class PairedRequest:
    """Operator input for the closed paired profile; no target/port/payload knob."""

    identity: str
    address: str
    config_path: str
    timeout_s: float
    authorized: bool
    unsafe_development: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.identity, str) or not self.identity or len(self.identity) > 64:
            raise PairedError("paired identity is invalid")
        object.__setattr__(self, "address", _address(self.address, "paired address"))
        if not isinstance(self.config_path, str) or not self.config_path or len(self.config_path) > 4096:
            raise PairedError("paired configuration path is invalid")
        if type(self.timeout_s) not in (int, float) or not 0.1 <= float(self.timeout_s) <= 30:
            raise PairedError("paired timeout must be within 0.1..30 seconds")
        object.__setattr__(self, "timeout_s", float(self.timeout_s))
        if type(self.authorized) is not bool or type(self.unsafe_development) is not bool:
            raise PairedError("paired authorization is invalid")


@dataclass(frozen=True, slots=True)
class PairedMatrixRow:
    layer: str
    direction: str
    outcome: str
    confidence: Confidence
    observation_ids: tuple[str, ...]
    limitations: tuple[str, ...]


class PairedRunner:
    """Add one evidence-cited paired-health conclusion to a shared runner.

    The supplied role runner is responsible for the admitted plan actions; this
    wrapper neither selects a destination nor creates an additional task or
    accounting system.  It is deliberately injectable so the authenticated
    control composition can run the exact same object on each endpoint.
    """

    def __init__(self, role_runner: Callable[[TaskContext], Awaitable[None]]) -> None:
        self._role_runner = role_runner

    async def __call__(self, context: TaskContext) -> None:
        await self._role_runner(context)
        observations = tuple(
            item for item in context.observations
            if "paired_endpoint" in item.detail
        )
        if not observations:
            raise PairedError("paired runner produced no endpoint-labelled evidence")
        dispositions = {item.disposition for item in observations}
        if dispositions == {Disposition.POSITIVE}:
            health, confidence, summary, limitations = (
                Health.HEALTHY, Confidence.HIGH,
                "All paired observations are direct positive evidence.", (),
            )
        elif Disposition.NEGATIVE in dispositions:
            health, confidence, summary, limitations = (
                Health.FAILED, Confidence.HIGH,
                "Paired observations include a direct negative outcome.", (),
            )
        else:
            health, confidence, summary, limitations = (
                Health.PARTIAL, Confidence.LOW,
                "One or more paired observations are inconclusive; silence is not a cause.",
                ("DNS, timeout, and UDP silence do not identify a firewall, loss, route, gateway, or switch.",),
            )
        context.add_conclusion(Conclusion(
            id="paired-health", title="Paired directional health", summary=summary,
            health=health, confidence=confidence,
            observation_ids=tuple(item.id for item in observations),
            limitations=limitations,
        ))


class PairedPeerService:
    """Closed server-side control handlers for one fixed paired manifest.

    A received submit contains only a manifest and a role label.  The local
    role executor owns compilation, scope/DNS revalidation, task admission and
    listener use; the authenticated peer never supplies any of those values.
    """

    def __init__(self, role_executor: RoleExecutor) -> None:
        self._role_executor = role_executor
        self._results: dict[str, TaskResult] = {}
        self._tasks: dict[str, asyncio.Task[None]] = {}

    @property
    def handlers(self) -> dict[str, Callable[[PeerFrame], Awaitable[dict[str, object]]]]:
        return {
            "capabilities": self.capabilities,
            "submit": self.submit,
            "read-result": self.read_result,
            "cancel": self.cancel,
        }

    async def capabilities(self, _frame: PeerFrame) -> dict[str, object]:
        return {"capabilities": [_PAIRED_MANIFEST]}

    async def submit(self, frame: PeerFrame) -> dict[str, object]:
        body = frame.body
        if body.get("manifest") != _PAIRED_MANIFEST or body.get("role") not in {_ROLE_A_TO_B, _ROLE_B_TO_A}:
            raise PairedError("paired manifest was not admitted")
        if frame.correlation_id in self._tasks or frame.correlation_id in self._results:
            raise PairedError("paired correlation is already active")
        task = asyncio.create_task(
            self._run_role(str(body["role"]), frame.correlation_id),
            name=f"mercury:paired:{frame.correlation_id}",
        )
        self._tasks[frame.correlation_id] = task
        return {"status": "accepted"}

    async def _run_role(self, role: str, correlation: str) -> None:
        result = await self._role_executor(role, correlation)
        if type(result) is not TaskResult or result.task_kind != "paired":
            raise PairedError("paired role executor returned an invalid result")
        self._results[correlation] = result

    async def read_result(self, frame: PeerFrame) -> dict[str, object]:
        task = self._tasks.get(frame.correlation_id)
        if task is not None:
            if not task.done():
                return {"status": "pending"}
            try:
                task.result()
            except (PairedError, asyncio.CancelledError) as exc:
                raise PairedError("paired role did not complete") from exc
            except Exception as exc:
                raise PairedError("paired role execution failed") from exc
            self._tasks.pop(frame.correlation_id, None)
        result = self._results.get(frame.correlation_id)
        return {"status": "pending"} if result is None else {"result": result_to_wire(result)}

    async def cancel(self, frame: PeerFrame) -> dict[str, object]:
        task = self._tasks.pop(frame.correlation_id, None)
        if task is not None:
            task.cancel()
        self._results.pop(frame.correlation_id, None)
        return {"status": "cancelled"}


class AuthenticatedPairedRunner:
    """Run both fixed roles through authenticated control and canonical output.

    The caller and peer each receive only their own fixed role label.  Their
    executors must independently admit the locally compiled work; this class
    only coordinates the already-closed protocol and joins its evidence.
    """

    def __init__(self, client: PeerClient, local_role_executor: RoleExecutor) -> None:
        self._client = client
        self._local_role_executor = local_role_executor

    async def run(self, request: PairedRequest) -> TaskResult:
        if type(request) is not PairedRequest or not request.authorized:
            raise PairedError("paired request requires explicit authorization")
        # Peer correlations must start alphanumeric; token_urlsafe may start
        # with '_' or '-', which the strict control grammar rightly rejects.
        correlation = "p" + secrets.token_urlsafe(18)
        expires_at = utc_now() + timedelta(seconds=request.timeout_s)
        submitted = False
        try:
            async with asyncio.timeout(request.timeout_s):
                capability = await self._request("capabilities", correlation, expires_at, {})
                capabilities = capability.body.get("capabilities")
                if not isinstance(capabilities, (list, tuple)) or _PAIRED_MANIFEST not in capabilities:
                    raise PairedError("configured peer does not admit the fixed paired manifest")
                # Submit first: the remote B-to-A role can bind its finite
                # listeners before local A-to-B sends the fixed probes.
                submitted_frame = await self._request(
                    "submit", correlation, expires_at,
                    {"manifest": _PAIRED_MANIFEST, "role": _ROLE_B_TO_A},
                )
                if submitted_frame.body != {"status": "accepted"}:
                    raise PairedError("configured peer did not admit the paired role")
                submitted = True
                local = await self._local_role_executor(_ROLE_A_TO_B, correlation)
                if type(local) is not TaskResult or local.task_kind != "paired":
                    raise PairedError("local paired role executor returned an invalid result")
                remote_result = await self._read_remote_result(correlation, expires_at)
                return _combine_role_results(request, local, remote_result, correlation)
        except TimeoutError as exc:
            raise PairedError("paired execution exceeded its finite deadline") from exc
        finally:
            if submitted:
                try:
                    await asyncio.shield(self._request("cancel", correlation, expires_at, {}))
                except (PeerError, OSError):
                    pass

    async def _read_remote_result(self, correlation: str, expires_at: datetime) -> TaskResult:
        while True:
            remote = await self._request("read-result", correlation, expires_at, {})
            if set(remote.body) == {"status"} and remote.body["status"] == "pending":
                await asyncio.sleep(0.01)
                continue
            if set(remote.body) != {"result"}:
                raise PairedError("configured peer returned an invalid paired result state")
            remote_result = result_from_wire(remote.body["result"])
            if remote_result.task_kind != "paired":
                raise PairedError("configured peer returned an invalid paired result")
            return remote_result

    async def _request(
        self,
        operation: str,
        correlation: str,
        expires_at: datetime,
        body: dict[str, object],
    ) -> PeerFrame:
        now = utc_now()
        return await self._client.request(PeerFrame(
            version=PEER_PROTOCOL_VERSION,
            operation=operation,
            correlation_id=correlation,
            identity=self._client.config.identity,
            issued_at=now,
            expires_at=expires_at,
            nonce=secrets.token_urlsafe(16),
            body=body,
        ))


def _combine_role_results(
    request: PairedRequest,
    local: TaskResult,
    remote: TaskResult,
    correlation: str,
) -> TaskResult:
    """Return one terminal document with both endpoint-labelled fact sets."""
    observations = (
        *_label_role_observations(local.observations, "A", _ROLE_A_TO_B, correlation),
        *_label_role_observations(remote.observations, "B", _ROLE_B_TO_A, correlation),
    )
    if not observations:
        raise PairedError("paired roles produced no observations")
    health = _paired_health(observations)
    started_at = min(local.started_at, remote.started_at)
    ended_at = max(local.ended_at, remote.ended_at)
    states = {local.state, remote.state}
    state = next(item for item in (local.state, remote.state) if item.value == "failed") if any(
        item.value == "failed" for item in states
    ) else next(item for item in (local.state, remote.state) if item.value == "cancelled") if any(
        item.value == "cancelled" for item in states
    ) else local.state
    if state.value not in {"completed", "failed", "cancelled"}:
        raise PairedError("paired role returned a non-terminal result")
    conclusion = Conclusion(
        id="paired-health",
        title="Paired directional health",
        summary={
            Health.HEALTHY: "Both independently admitted fixed roles produced positive evidence.",
            Health.FAILED: "A paired role recorded a direct negative outcome.",
            Health.PARTIAL: "Paired evidence is incomplete; silence and timeout do not identify a cause.",
        }[health],
        health=health,
        confidence=Confidence.HIGH if health is not Health.PARTIAL else Confidence.LOW,
        observation_ids=tuple(item.id for item in observations),
        limitations=() if health is not Health.PARTIAL else (
            "Observed asymmetry does not by itself identify a firewall, loss, route, gateway, or switch.",
        ),
    )
    return TaskResult(
        task_id=f"paired-{correlation}", task_kind="paired", direction=Direction.OUTBOUND,
        target=request.address, state=state, started_at=started_at, ended_at=ended_at,
        requested_config={"paired_manifest": _PAIRED_MANIFEST, "peer_identity": request.identity, "network_io": True},
        effective_config=replace(local.effective_config, profile=_PAIRED_MANIFEST),
        progress=replace(local.progress, admitted=local.progress.admitted + remote.progress.admitted,
                         completed=local.progress.completed + remote.progress.completed,
                         total=local.progress.total + remote.progress.total),
        observations=observations, conclusions=(conclusion,),
        capabilities=(*local.capabilities, *remote.capabilities),
        errors=(*local.errors, *remote.errors),
    )


def _label_role_observations(
    observations: tuple[Observation, ...], endpoint: str, role: str, correlation: str,
) -> tuple[Observation, ...]:
    labelled: list[Observation] = []
    for index, observation in enumerate(observations):
        detail = dict(observation.detail)
        detail.update({"paired_endpoint": endpoint, "paired_phase": role, "paired_correlation": correlation})
        direction = Direction.OUTBOUND if role == _ROLE_A_TO_B else Direction.INBOUND
        labelled.append(replace(
            observation, id=f"{endpoint}-{index}-{observation.id}", direction=direction, detail=detail,
        ))
    return tuple(labelled)


def _paired_health(observations: tuple[Observation, ...]) -> Health:
    dispositions = {item.disposition for item in observations}
    if Disposition.NEGATIVE in dispositions:
        return Health.FAILED
    if dispositions == {Disposition.POSITIVE}:
        return Health.HEALTHY
    return Health.PARTIAL


def paired_matrix(result: TaskResult) -> tuple[PairedMatrixRow, ...]:
    """Pure, cited projection of canonical endpoint-labelled observations."""
    if type(result) is not TaskResult:
        raise PairedError("paired matrix requires a canonical task result")
    grouped: dict[tuple[str, str], list[Observation]] = {}
    for item in result.observations:
        if "paired_endpoint" not in item.detail:
            continue
        direction = "A→B" if item.direction in {Direction.OUTBOUND, Direction.REVERSE} else "B→A"
        grouped.setdefault((item.probe, direction), []).append(item)
    rows: list[PairedMatrixRow] = []
    for (layer, direction), observations in sorted(
        grouped.items(), key=lambda pair: (_MATRIX_ORDER.get(pair[0][0], 99), pair[0][1]),
    ):
        last = observations[-1]
        limitations = ()
        confidence = Confidence.HIGH if last.disposition is Disposition.POSITIVE else Confidence.LOW
        if last.evidence_kind in {EvidenceKind.SILENT, EvidenceKind.TIMEOUT}:
            limitations = ("No arrival/reply was observed; silence is inconclusive.",)
        rows.append(PairedMatrixRow(
            layer=layer, direction=direction, outcome=last.evidence_kind.value,
            confidence=confidence, observation_ids=tuple(item.id for item in observations),
            limitations=limitations,
        ))
    return tuple(rows)


def _address(value: str, label: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise PairedError(f"{label} must be a numeric IP address") from exc


def _port(value: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65_535:
        raise PairedError(f"{label} must be a selected port")
    return value


@dataclass(frozen=True, slots=True)
class PairedEndpoint:
    identity: str
    # ``address`` is the authenticated remote source and immutable plan target.
    # ``local_address`` is only the local bind address; it never becomes a
    # reverse destination or replaces the peer-source check.
    address: str
    tcp_port: int
    udp_port: int
    local_address: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.identity, str) or not self.identity or len(self.identity) > 64:
            raise PairedError("paired identity is invalid")
        object.__setattr__(self, "address", _address(self.address, "paired address"))
        if self.local_address is not None:
            object.__setattr__(self, "local_address", _address(self.local_address, "paired local address"))
        object.__setattr__(self, "tcp_port", _port(self.tcp_port, "paired TCP port"))
        object.__setattr__(self, "udp_port", _port(self.udp_port, "paired UDP port"))
        if self.tcp_port == self.udp_port:
            raise PairedError("paired TCP and UDP ports must be distinct")

    @property
    def bind_address(self) -> str:
        return self.local_address or self.address


@dataclass(frozen=True, slots=True)
class PairedLease:
    """Immutable authority for exactly one bounded TCP/UDP listener pair."""

    plan: ProbePlan
    correlation_id: str
    endpoint: PairedEndpoint
    authenticated_source: str
    expires_at: datetime
    udp_nonce: str
    udp_tag: bytes

    def __post_init__(self) -> None:
        if type(self.plan) is not ProbePlan:
            raise PairedError("paired lease requires an authorized immutable plan")
        try:
            validate_plan(self.plan, now=self.plan.authorized_at)
        except Exception as exc:
            raise PairedError("paired lease plan is not currently valid") from exc
        if (
            not isinstance(self.correlation_id, str)
            or not self.correlation_id
            or len(self.correlation_id) > 64
            or not self.correlation_id.isascii()
        ):
            raise PairedError("paired correlation is invalid")
        source = _address(self.authenticated_source, "authenticated peer source")
        if source != self.endpoint.address:
            raise PairedError("authenticated source does not match configured endpoint")
        object.__setattr__(self, "authenticated_source", source)
        if not isinstance(self.expires_at, datetime) or self.expires_at.tzinfo is None:
            raise PairedError("paired lease expiry must be timezone-aware")
        if (
            self.expires_at <= self.plan.authorized_at
            or self.expires_at > self.plan.authorized_at + timedelta(minutes=30)
        ):
            raise PairedError("paired lease expiry is outside the finite lease window")
        if not isinstance(self.udp_nonce, str) or not 8 <= len(self.udp_nonce) <= 128 or not self.udp_nonce.isascii():
            raise PairedError("paired UDP nonce is invalid")
        if type(self.udp_tag) is not bytes or not 1 <= len(self.udp_tag) <= 64:
            raise PairedError("paired UDP tag is invalid")
        selected = {
            (step.address, step.port, step.transport): step
            for step in self.plan.preview.steps
        }
        tcp = selected.get((self.endpoint.address, self.endpoint.tcp_port, Transport.TCP))
        udp = selected.get((self.endpoint.address, self.endpoint.udp_port, Transport.UDP))
        if tcp is None or udp is None:
            raise PairedError("paired listener endpoint is outside immutable plan")
        # The immutable plan reserves the tiny fixed admission/reply bytes.  It
        # deliberately does not claim to count TCP retransmissions or framing.
        if (
            tcp.cost.application_bytes < len(encode_tcp_tag(self)) + len(_TCP_REPLY)
            or udp.cost.generated_datagrams < 1
            or udp.cost.application_bytes < len(encode_udp_tag(self))
        ):
            raise PairedError("paired listener bytes are not reserved by immutable plan")

    def assert_current(self, now: datetime) -> None:
        if not isinstance(now, datetime) or now.tzinfo is None or now >= self.expires_at:
            raise PairedError("paired lease has expired")


def encode_udp_tag(lease: PairedLease) -> bytes:
    """Return the sole built-in UDP validation payload (never user supplied)."""
    nonce = lease.udp_nonce.encode("ascii")
    # Each endpoint independently compiles a source-bound plan, so its digest
    # is intentionally local.  Correlation/tag are the shared, finite
    # data-plane identity established by authenticated control.
    payload = b"MRP1" + struct.pack("!B", len(nonce)) + nonce + lease.udp_tag
    if len(payload) > _MAX_PAYLOAD:
        raise PairedError("paired UDP payload exceeds 1400 bytes")
    return payload


def encode_tcp_tag(lease: PairedLease) -> bytes:
    """Return the fixed TCP admission preface for this lease."""
    correlation = lease.correlation_id.encode("ascii")
    if not correlation.isascii() or len(correlation) > 64:
        raise PairedError("paired correlation is invalid")
    return b"MRP1T" + struct.pack("!B", len(correlation)) + correlation


def is_valid_udp_tag(lease: PairedLease, payload: bytes) -> bool:
    """Check the fixed profile without exposing a permissive UDP parser."""
    if type(payload) is not bytes or len(payload) > _MAX_PAYLOAD:
        return False
    try:
        return payload == encode_udp_tag(lease)
    except PairedError:
        return False


class PairedListenerService:
    """Own the two finite listeners for one admitted paired task.

    Listener start admits the exact TCP and UDP steps.  A matching packet then
    records no more than the two observations reserved by each compiled step.
    Invalid traffic is ignored before evidence, persistence, or a reply.
    """

    def __init__(
        self,
        lease: PairedLease,
        *,
        context: TaskContext,
        now: Callable[[], datetime] = utc_now,
    ) -> None:
        if type(context) is not TaskContext or context.plan != lease.plan:
            raise PairedError("paired listener requires its lease task context")
        self.lease, self.context, self._now = lease, context, now
        self._tcp: asyncio.AbstractServer | None = None
        self._udp: asyncio.DatagramTransport | None = None
        self._tcp_step: ProbeStep | None = None
        self._udp_step: ProbeStep | None = None
        self._expiry: asyncio.Task[None] | None = None
        self._datagram_tasks: set[asyncio.Task[None]] = set()
        self._lock = asyncio.Lock()
        self._claimed_steps: set[str] = set()
        self.outcome = "pending"

    async def start(self) -> None:
        self.lease.assert_current(self._now())
        self._tcp_step = self._step(Transport.TCP, self.lease.endpoint.tcp_port)
        self._udp_step = self._step(Transport.UDP, self.lease.endpoint.udp_port)
        await self.context.admit(self._tcp_step.id)
        await self.context.admit(self._udp_step.id)
        try:
            self._tcp = await asyncio.start_server(
                self._handle_tcp,
                host=self.lease.endpoint.bind_address,
                port=self.lease.endpoint.tcp_port,
            )
            transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: _LeaseDatagram(self),
                local_addr=(self.lease.endpoint.bind_address, self.lease.endpoint.udp_port),
            )
            self._udp = transport
        except PermissionError:
            self.outcome = "permission_denied"
            await self.stop(mark_silence=True)
            raise
        except OSError:
            self.outcome = "busy"
            await self.stop(mark_silence=True)
            raise
        except asyncio.CancelledError:
            await self.stop(mark_silence=False)
            raise
        self.outcome = "active"
        self._expiry = asyncio.create_task(self._expire())

    async def stop(self, *, mark_silence: bool = True) -> None:
        if self._expiry is not None and self._expiry is not asyncio.current_task():
            self._expiry.cancel()
            self._expiry = None
        for task in tuple(self._datagram_tasks):
            task.cancel()
        if self._udp is not None:
            self._udp.close()
            self._udp = None
        if self._tcp is not None:
            server, self._tcp = self._tcp, None
            server.close()
            await server.wait_closed()
        if mark_silence:
            await self._complete_missing()
        if self.outcome == "active":
            self.outcome = "stopped"

    async def _expire(self) -> None:
        delay = max(0.0, (self.lease.expires_at - self._now()).total_seconds())
        await asyncio.sleep(delay)
        if self._now() >= self.lease.expires_at:
            self.outcome = "expired"
            await self.stop(mark_silence=True)

    def _step(self, transport: Transport, port: int) -> ProbeStep:
        matching = [
            step for step in self.lease.plan.preview.steps
            if step.address == self.lease.endpoint.address
            and step.port == port
            and step.transport is transport
        ]
        if len(matching) != 1:
            raise PairedError("paired listener requires one exact immutable plan step")
        return matching[0]

    async def _handle_tcp(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
    ) -> None:
        try:
            peer = writer.get_extra_info("peername")
            if not self._source_matches(peer):
                return
            self.lease.assert_current(self._now())
            assert self._tcp_step is not None
            async with asyncio.timeout(self._tcp_step.timeout_s):
                preface = await reader.readexactly(len(encode_tcp_tag(self.lease)))
            if preface != encode_tcp_tag(self.lease):
                return
            await self.context.cancellation.checkpoint()
            if not await self._claim_step(self._tcp_step.id):
                return
            await self._record_pair(
                self._tcp_step, EvidenceKind.PEER_OBSERVED_ARRIVAL,
                Disposition.POSITIVE, Direction.INBOUND, "arrived",
            )
            writer.write(_TCP_REPLY)
            await writer.drain()
            await self._record_pair(
                self._tcp_step, EvidenceKind.TCP_CONNECTED,
                Disposition.POSITIVE, Direction.REVERSE, "replied",
            )
            self.context.complete_attempt(self._tcp_step.id)
        except (PairedError, asyncio.IncompleteReadError, TimeoutError, OSError):
            return
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, RuntimeError):
                pass

    def _receive_datagram(self, data: bytes, address: tuple[str, int]) -> None:
        task = asyncio.create_task(self._handle_datagram(data, address))
        self._datagram_tasks.add(task)
        task.add_done_callback(self._datagram_tasks.discard)

    async def _handle_datagram(self, data: bytes, address: tuple[str, int]) -> None:
        try:
            if not self._source_matches(address) or not is_valid_udp_tag(self.lease, data):
                return
            self.lease.assert_current(self._now())
            await self.context.cancellation.checkpoint()
            assert self._udp_step is not None and self._udp is not None
            if not await self._claim_step(self._udp_step.id):
                return
            await self._record_pair(
                self._udp_step, EvidenceKind.PEER_OBSERVED_ARRIVAL,
                Disposition.POSITIVE, Direction.INBOUND, "arrived",
            )
            self._udp.sendto(data, address)
            await self._record_pair(
                self._udp_step, EvidenceKind.UDP_APPLICATION_REPLY,
                Disposition.POSITIVE, Direction.REVERSE, "replied",
            )
            self.context.complete_attempt(self._udp_step.id)
        except (PairedError, asyncio.CancelledError):
            return

    async def _record_pair(
        self,
        step: ProbeStep,
        kind: EvidenceKind,
        disposition: Disposition,
        direction: Direction,
        phase: str,
    ) -> None:
        instant = self._now()
        self.context.record_paired(
            Observation(
                id=f"paired-{self.lease.correlation_id}-{step.id[-8:]}-{phase}",
                probe=step.probe_kind.value,
                disposition=disposition,
                evidence_kind=kind,
                direction=direction,
                target=step.address or step.target,
                started_at=instant,
                ended_at=instant,
                duration_ms=0.0,
                attempt=step.attempt,
                source="mercury.paired",
            ),
            step_id=step.id,
            endpoint=self.lease.endpoint.identity,
            correlation_id=self.lease.correlation_id,
            phase=phase,
        )

    async def _complete_missing(self) -> None:
        for step, kind in (
            (self._tcp_step, EvidenceKind.TIMEOUT),
            (self._udp_step, EvidenceKind.SILENT),
        ):
            if step is None or not await self._claim_step(step.id):
                continue
            await self._record_pair(
                step, kind, Disposition.INCONCLUSIVE,
                Direction.OUTBOUND, "received",
            )
            self.context.complete_attempt(step.id)

    async def _claim_step(self, step_id: str) -> bool:
        async with self._lock:
            if step_id in self._claimed_steps:
                return False
            self._claimed_steps.add(step_id)
            return True

    def _source_matches(self, peer: object) -> bool:
        if not isinstance(peer, tuple) or not peer or not isinstance(peer[0], str):
            return False
        try:
            return _address(peer[0], "packet source") == self.lease.authenticated_source
        except PairedError:
            return False


class _LeaseDatagram(asyncio.DatagramProtocol):
    def __init__(self, service: PairedListenerService) -> None:
        self._service = service

    def datagram_received(self, data: bytes, address: tuple[str, int]) -> None:
        self._service._receive_datagram(data, address)


class _PairedReply(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.reply: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()

    def datagram_received(self, data: bytes, _address: tuple[str, int]) -> None:
        if not self.reply.done():
            self.reply.set_result(data)


class ConfiguredPairedExecutor:
    """Run exactly one local half of an operator-provisioned pair profile.

    The configuration supplies both data-plane ports and the peer address.  No
    frame, CLI value, or remote result selects a destination, port, payload, or
    scope.  Each endpoint recompiles its own two-step immutable plan.
    """

    def __init__(self, config: PeerConfig, history) -> None:
        if type(config) is not PeerConfig or not config.paired_enabled:
            raise PairedError("paired runtime requires a configured fixed profile")
        self._config, self._history = config, history

    async def __call__(self, role: str, correlation: str) -> TaskResult:
        if role not in {_ROLE_A_TO_B, _ROLE_B_TO_A}:
            raise PairedError("paired role is invalid")
        endpoint, lease = self._lease(correlation)
        service = TaskService(self._history)

        async def runner(context: TaskContext) -> None:
            if role == _ROLE_B_TO_A:
                listener = PairedListenerService(lease, context=context)
                await listener.start()
                try:
                    while context.completed < context.total:
                        await context.cancellation.checkpoint()
                        await asyncio.sleep(0.01)
                finally:
                    await listener.stop(mark_silence=True)
            else:
                await self._send_fixed_profile(context, lease)

        return await service.run(
            lease.plan, runner, task_kind="paired",
            requested_config={"purpose": "configured authenticated paired profile"},
        )

    def _lease(self, correlation: str) -> tuple[PairedEndpoint, PairedLease]:
        config = self._config
        assert config.paired_tcp_port is not None
        assert config.paired_udp_port is not None
        assert config.paired_timeout_s is not None
        remote = config.peer_addresses[0]
        endpoint = PairedEndpoint(
            config.identity, remote, config.paired_tcp_port, config.paired_udp_port,
            local_address=config.bind_host,
        )
        tag = _runtime_pair_tag(
            correlation, config.bind_host, remote,
            config.paired_tcp_port, config.paired_udp_port,
        )
        plan = _runtime_plan(endpoint, correlation, tag, config.paired_timeout_s)
        lease = PairedLease(
            plan=plan, correlation_id=correlation, endpoint=endpoint,
            authenticated_source=remote,
            expires_at=plan.authorized_at + timedelta(seconds=config.paired_timeout_s),
            udp_nonce=correlation, udp_tag=tag,
        )
        return endpoint, lease

    async def _send_fixed_profile(self, context: TaskContext, lease: PairedLease) -> None:
        await self._send_tcp(context, lease)
        await self._send_udp(context, lease)

    async def _send_tcp(self, context: TaskContext, lease: PairedLease) -> None:
        step = next(item for item in lease.plan.preview.steps if item.transport is Transport.TCP)
        prepared = await context.admit(step.id)
        started = context.wall_clock()
        kind, disposition = EvidenceKind.TCP_CONNECTED, Disposition.POSITIVE
        try:
            async with asyncio.timeout(step.timeout_s):
                reader, writer = await asyncio.open_connection(
                    lease.endpoint.address, lease.endpoint.tcp_port,
                    local_addr=(lease.endpoint.bind_address, 0),
                )
                try:
                    writer.write(encode_tcp_tag(lease))
                    await writer.drain()
                    if await reader.readexactly(len(_TCP_REPLY)) != _TCP_REPLY:
                        raise OSError("paired TCP reply was invalid")
                finally:
                    writer.close()
                    await writer.wait_closed()
        except TimeoutError:
            kind, disposition = EvidenceKind.TIMEOUT, Disposition.INCONCLUSIVE
        except OSError as exc:
            kind, disposition = _paired_socket_failure(exc, udp=False)
        context.record_paired(_paired_observation(
            prepared.step, kind, disposition, started, "paired TCP fixed profile",
        ), step_id=step.id, endpoint=lease.endpoint.identity,
            correlation_id=lease.correlation_id, phase="sent")
        context.complete_attempt(step.id)

    async def _send_udp(self, context: TaskContext, lease: PairedLease) -> None:
        step = next(item for item in lease.plan.preview.steps if item.transport is Transport.UDP)
        prepared = await context.admit(step.id)
        started = context.wall_clock()
        kind, disposition = EvidenceKind.UDP_APPLICATION_REPLY, Disposition.POSITIVE
        transport: asyncio.DatagramTransport | None = None
        try:
            protocol = _PairedReply()
            transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: protocol, local_addr=(lease.endpoint.bind_address, 0),
            )
            transport.sendto(encode_udp_tag(lease), (lease.endpoint.address, lease.endpoint.udp_port))
            reply = await asyncio.wait_for(protocol.reply, step.timeout_s)
            if reply != encode_udp_tag(lease):
                raise OSError("paired UDP reply was invalid")
        except TimeoutError:
            kind, disposition = EvidenceKind.SILENT, Disposition.INCONCLUSIVE
        except OSError as exc:
            kind, disposition = _paired_socket_failure(exc, udp=True)
        finally:
            if transport is not None:
                transport.close()
        context.record_paired(_paired_observation(
            prepared.step, kind, disposition, started, "paired UDP fixed profile",
        ), step_id=step.id, endpoint=lease.endpoint.identity,
            correlation_id=lease.correlation_id, phase="sent")
        context.complete_attempt(step.id)


def _runtime_pair_tag(correlation: str, left: str, right: str, tcp_port: int, udp_port: int) -> bytes:
    material = "|".join((correlation, *sorted((left, right)), str(tcp_port), str(udp_port)))
    return hashlib.sha256(material.encode("ascii")).digest()[:16]


def _runtime_plan(endpoint: PairedEndpoint, correlation: str, tag: bytes, timeout_s: float) -> ProbePlan:
    grant = ScopeGrant(
        networks=(ipaddress.ip_network(f"{endpoint.address}/{32 if ':' not in endpoint.address else 128}"),),
        ports=(endpoint.tcp_port, endpoint.udp_port), transports=("tcp", "udp"),
        attested=True, purpose="configured authenticated paired profile",
        expires_at=utc_now() + timedelta(seconds=timeout_s),
    )
    tcp_bytes = len(b"MRP1T") + 1 + len(correlation.encode("ascii")) + len(_TCP_REPLY)
    udp_bytes = len(b"MRP1") + 1 + len(correlation.encode("ascii")) + len(tag)
    preview = preview_probe_plan(
        specs=(
            ProbeSpec(ProbeKind.TCP_CONNECT, endpoint.address, address=endpoint.address,
                      port=endpoint.tcp_port, transport=Transport.TCP, timeout_s=timeout_s,
                      cost=StepCost(1, 0, tcp_bytes, logical_packets=1)),
            ProbeSpec(ProbeKind.UDP_EXCHANGE, endpoint.address, address=endpoint.address,
                      port=endpoint.udp_port, transport=Transport.UDP, timeout_s=timeout_s,
                      payload_metadata=PayloadMetadata("paired-v1", udp_bytes),
                      cost=StepCost(1, 1, udp_bytes, logical_packets=1)),
        ), grant=grant, profile=_PAIRED_MANIFEST,
        limits=replace(DEFAULT_LIMITS, max_duration_s=max(1, math.ceil(timeout_s))),
    )
    return authorize_plan(preview)


def _paired_socket_failure(exc: OSError, *, udp: bool) -> tuple[EvidenceKind, Disposition]:
    code = exc.errno if exc.errno is not None else exc.winerror
    if not udp and code in {errno.ECONNREFUSED, 10061}:
        return EvidenceKind.TCP_REFUSED, Disposition.NEGATIVE
    if code in {errno.ENETUNREACH, 10051}:
        return EvidenceKind.NETWORK_UNREACHABLE, Disposition.NEGATIVE
    if code in {errno.EHOSTUNREACH, 10065}:
        return EvidenceKind.HOST_UNREACHABLE, Disposition.NEGATIVE
    return EvidenceKind.EXECUTION_ERROR, Disposition.ERROR


def _paired_observation(
    step: ProbeStep, kind: EvidenceKind, disposition: Disposition,
    started: datetime, detail: str,
) -> Observation:
    ended = utc_now()
    return Observation(
        id=f"paired-send-{step.id[-12:]}", probe=step.probe_kind.value,
        disposition=disposition, evidence_kind=kind, direction=Direction.REVERSE,
        target=step.address or step.target, started_at=started, ended_at=ended,
        duration_ms=max(0.0, (ended - started).total_seconds() * 1000),
        attempt=step.attempt, source="mercury.paired", detail={"category": detail},
    )


__all__ = [
    "AuthenticatedPairedRunner", "ConfiguredPairedExecutor", "PairedEndpoint", "PairedError", "PairedLease", "PairedListenerService",
    "PairedMatrixRow", "PairedRequest", "PairedRunner", "paired_matrix",
    "PairedPeerService", "encode_tcp_tag", "encode_udp_tag", "is_valid_udp_tag",
]
