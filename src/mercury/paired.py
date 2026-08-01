"""Finite, source-bound paired listener leases.

This module deliberately implements one small data-plane profile.  A lease is
not a remote probe API: its address, ports, correlation, and opaque payload are
all fixed by a locally validated plan and the authenticated peer source.
"""

from __future__ import annotations

import asyncio
import ipaddress
import struct
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

from .models import (
    Confidence,
    Conclusion,
    Direction,
    Disposition,
    EvidenceKind,
    Health,
    Observation,
    TaskResult,
    utc_now,
)
from .planner import ProbePlan, ProbeStep, Transport, validate_plan
from .tasks import TaskContext

_TCP_REPLY = b"MRP1A"
_MAX_PAYLOAD = 1_400
_MATRIX_ORDER = {"local_snapshot": 0, "system_dns": 1, "native_path": 2, "tcp_connect": 3, "udp_exchange": 4, "tls_handshake": 5, "http_exchange": 6}


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
    plan = lease.plan.digest[:16].encode("ascii")
    nonce = lease.udp_nonce.encode("ascii")
    payload = b"MRP1" + plan + struct.pack("!B", len(nonce)) + nonce + lease.udp_tag
    if len(payload) > _MAX_PAYLOAD:
        raise PairedError("paired UDP payload exceeds 1400 bytes")
    return payload


def encode_tcp_tag(lease: PairedLease) -> bytes:
    """Return the fixed TCP admission preface for this lease."""
    correlation = lease.correlation_id.encode("ascii")
    if not correlation.isascii() or len(correlation) > 64:
        raise PairedError("paired correlation is invalid")
    return b"MRP1T" + lease.plan.digest[:16].encode("ascii") + struct.pack("!B", len(correlation)) + correlation


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


__all__ = [
    "PairedEndpoint", "PairedError", "PairedLease", "PairedListenerService",
    "PairedMatrixRow", "PairedRequest", "PairedRunner", "paired_matrix",
    "encode_tcp_tag", "encode_udp_tag", "is_valid_udp_tag",
]
