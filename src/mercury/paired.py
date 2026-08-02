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
import platform
import secrets
import ssl
import struct
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from datetime import datetime, timedelta

from .codec import result_from_wire, result_to_wire
from .models import (
    Confidence,
    Conclusion,
    CoverageOutcome,
    CoverageProfile,
    CoverageReceipt,
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
from .peer import PEER_PROTOCOL_VERSION, PeerClient, PeerConfig, PeerError, PeerFrame, ReceiverProfileConfig
from .policy import ScopeGrant
from .platform.common import CommandOutcome, CommandResult, run_command
from .tasks import TaskContext, TaskService

_TCP_REPLY = b"MRP1A"
_COVERAGE_REPLY = b"MRC2A"
_MAX_PAYLOAD = 1_400
_MATRIX_ORDER = {"local_snapshot": 0, "system_dns": 1, "native_path": 2, "tcp_connect": 3, "udp_exchange": 4, "tls_handshake": 5, "http_exchange": 6}
_PAIRED_MANIFEST = "paired-v1"
_COVERAGE_MANIFEST = "coverage-v2"
_ROLE_A_TO_B = "A-to-B"
_ROLE_B_TO_A = "B-to-A"
# The data-plane lease remains bounded by the configured profile.  Control gets
# a brief, fixed window afterwards solely to retrieve the terminal result and
# cancel retained state; otherwise a lease expiring on schedule races the final
# read-result frame.
_CONTROL_RESULT_GRACE_S = 2.0

RoleExecutor = Callable[[str, str], Awaitable[TaskResult]]
CoverageSenderExecutor = Callable[[str, str], Awaitable[TaskResult]]


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


@dataclass(frozen=True, slots=True)
class CoverageMatrixRow:
    """One finite profile/direction conclusion with its exact evidence scope."""

    profile: CoverageProfile
    direction: str
    outcome: CoverageOutcome
    observation_ids: tuple[str, ...]
    provenance: tuple[str, ...]
    limitations: tuple[str, ...]


DEFAULT_COVERAGE_PROFILES = (
    CoverageProfile.TCP_CONNECT,
    CoverageProfile.TCP_TAGGED,
    CoverageProfile.UDP_TAGGED,
    CoverageProfile.DNS_UDP,
    CoverageProfile.DNS_TCP,
    CoverageProfile.ICMP_ECHO,
    CoverageProfile.TLS_HANDSHAKE,
    CoverageProfile.HTTP_EXCHANGE,
    CoverageProfile.SSH_BANNER,
    CoverageProfile.ARP,
    CoverageProfile.IPV6_ND,
)


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

    def __init__(
        self,
        role_executor: RoleExecutor,
        *,
        coverage_registry: "CoverageLeaseRegistry | None" = None,
        coverage_sender_executor: CoverageSenderExecutor | None = None,
    ) -> None:
        self._role_executor = role_executor
        self._coverage_registry = coverage_registry
        self._coverage_sender_executor = coverage_sender_executor
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
        capabilities = [_PAIRED_MANIFEST]
        if self._coverage_registry is not None:
            capabilities.extend(self._coverage_registry.capabilities)
        return {"capabilities": capabilities}

    async def submit(self, frame: PeerFrame) -> dict[str, object]:
        body = frame.body
        manifest, role = body.get("manifest"), body.get("role")
        if role not in {_ROLE_A_TO_B, _ROLE_B_TO_A}:
            raise PairedError("paired manifest was not admitted")
        if manifest == _COVERAGE_MANIFEST:
            if self._coverage_registry is None:
                raise PairedError("coverage manifest was not admitted")
            # The two role names retain their paired meaning: the peer accepts
            # A-to-B by opening only its own configured receivers, while a
            # configured B-to-A executor sends only to its fixed peer address.
            # Legacy receiver-only agents intentionally keep accepting B-to-A
            # as a lease, which makes an upgrade a local configuration change.
            if role == _ROLE_B_TO_A and self._coverage_sender_executor is not None:
                if frame.correlation_id in self._tasks or frame.correlation_id in self._results:
                    raise PairedError("coverage correlation is already active")
                task = asyncio.create_task(
                    self._run_coverage_sender(role, frame.correlation_id),
                    name=f"mercury:coverage-send:{frame.correlation_id}",
                )
                self._tasks[frame.correlation_id] = task
                return {"status": "accepted"}
            await self._coverage_registry.start(frame.correlation_id, frame.expires_at)
            return {"status": "accepted"}
        if manifest != _PAIRED_MANIFEST:
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

    async def _run_coverage_sender(self, role: str, correlation: str) -> None:
        assert self._coverage_sender_executor is not None
        result = await self._coverage_sender_executor(role, correlation)
        if type(result) is not TaskResult or result.task_kind != "coverage":
            raise PairedError("coverage sender executor returned an invalid result")
        self._results[correlation] = result

    async def read_result(self, frame: PeerFrame) -> dict[str, object]:
        if self._coverage_registry is not None:
            receipts = self._coverage_registry.receipts_for(frame.correlation_id)
            if receipts is not None:
                return {"receipts": [_receipt_wire(receipt) for receipt in receipts]}
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
        if self._coverage_registry is not None:
            await self._coverage_registry.stop(frame.correlation_id)
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
        data_expires_at = utc_now() + timedelta(seconds=request.timeout_s)
        control_expires_at = data_expires_at + timedelta(seconds=_CONTROL_RESULT_GRACE_S)
        submitted = False
        try:
            async with asyncio.timeout(request.timeout_s + _CONTROL_RESULT_GRACE_S):
                capability = await self._request("capabilities", correlation, control_expires_at, {})
                capabilities = capability.body.get("capabilities")
                if not isinstance(capabilities, (list, tuple)) or _PAIRED_MANIFEST not in capabilities:
                    raise PairedError("configured peer does not admit the fixed paired manifest")
                # Submit first: the remote B-to-A role can bind its finite
                # listeners before local A-to-B sends the fixed probes.
                submitted_frame = await self._request(
                    "submit", correlation, control_expires_at,
                    {"manifest": _PAIRED_MANIFEST, "role": _ROLE_B_TO_A},
                )
                if submitted_frame.body != {"status": "accepted"}:
                    raise PairedError("configured peer did not admit the paired role")
                submitted = True
                local = await self._local_role_executor(_ROLE_A_TO_B, correlation)
                if type(local) is not TaskResult or local.task_kind != "paired":
                    raise PairedError("local paired role executor returned an invalid result")
                remote_result = await self._read_remote_result(correlation, control_expires_at)
                return _combine_role_results(request, local, remote_result, correlation)
        except TimeoutError as exc:
            raise PairedError("paired execution exceeded its finite deadline") from exc
        finally:
            if submitted:
                try:
                    await asyncio.shield(self._request("cancel", correlation, control_expires_at, {}))
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


@dataclass(frozen=True, slots=True)
class CoverageAssessmentRequest:
    """One authorized, finite two-endpoint coverage assessment."""

    identity: str
    address: str
    config_path: str
    timeout_s: float
    authorized: bool
    profiles: tuple[CoverageProfile, ...]
    unsafe_development: bool = False
    local_network: str | None = None
    peer_network: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.identity, str) or not self.identity or len(self.identity) > 64:
            raise PairedError("coverage identity is invalid")
        object.__setattr__(self, "address", _address(self.address, "coverage address"))
        if not isinstance(self.config_path, str) or not self.config_path or len(self.config_path) > 4096:
            raise PairedError("coverage configuration path is invalid")
        if type(self.timeout_s) not in (int, float) or not 0.1 <= float(self.timeout_s) <= 30:
            raise PairedError("coverage timeout must be within 0.1..30 seconds")
        object.__setattr__(self, "timeout_s", float(self.timeout_s))
        if type(self.authorized) is not bool or type(self.unsafe_development) is not bool:
            raise PairedError("coverage authorization is invalid")
        if not isinstance(self.profiles, (tuple, list)) or not self.profiles or any(
            type(item) is not CoverageProfile for item in self.profiles
        ) or len(set(self.profiles)) != len(self.profiles):
            raise PairedError("coverage profiles must be a non-empty unique sequence")
        supported = set(CoverageReceiverService._IMPLEMENTED) | {
            CoverageProfile.TCP_CONNECT, CoverageProfile.ICMP_ECHO,
            CoverageProfile.ARP, CoverageProfile.IPV6_ND,
        }
        unsupported = set(self.profiles) - supported
        if unsupported:
            raise PairedError("coverage assessment profiles need configured receivers")
        object.__setattr__(self, "profiles", tuple(self.profiles))
        if (self.local_network is None) != (self.peer_network is None):
            raise PairedError("local-link coverage needs both endpoint networks")
        if self.local_network is not None:
            try:
                local_network = ipaddress.ip_network(self.local_network, strict=False)
                peer_network = ipaddress.ip_network(self.peer_network, strict=False)
            except (TypeError, ValueError) as exc:
                raise PairedError("local-link coverage networks are invalid") from exc
            if not (local_network.is_private and peer_network.is_private):
                raise PairedError("local-link coverage networks must be private")
            object.__setattr__(self, "local_network", local_network.with_prefixlen)
            object.__setattr__(self, "peer_network", peer_network.with_prefixlen)


class AuthenticatedCoverageRunner:
    """Coordinate fixed receiver leases and fixed sends in both directions.

    The control frames contain only a manifest and role.  Destinations, ports,
    payload shapes, local bind addresses, and profile selection all originate
    from the two local peer configurations and are cross-checked through the
    peer capability advertisement before data-plane I/O begins.
    """

    def __init__(
        self,
        client: PeerClient,
        config: PeerConfig,
        history,
        *,
        coverage_sender: "ConfiguredCoverageExecutor | None" = None,
    ) -> None:
        if type(client) is not PeerClient or type(config) is not PeerConfig or not config.coverage_enabled:
            raise PairedError("coverage runner requires configured receivers")
        self._client, self._config, self._history = client, config, history
        self._sender = ConfiguredCoverageExecutor(config, history) if coverage_sender is None else coverage_sender

    async def run(self, request: CoverageAssessmentRequest) -> TaskResult:
        if type(request) is not CoverageAssessmentRequest or not request.authorized:
            raise PairedError("coverage assessment requires explicit authorization")
        if request.identity != self._config.identity or request.address != self._config.peer_addresses[0]:
            raise PairedError("coverage request does not match its configured peer")
        if set(request.profiles) != set(self._config.coverage_profiles):
            raise PairedError("coverage request profiles do not match the fixed local coverage configuration")
        correlation = "c" + secrets.token_urlsafe(16)
        forward, reverse = correlation + "f", correlation + "r"
        # Each profile has its configured receive window.  Control must remain
        # available across both sequential directions, not just the first one.
        control_expires_at = utc_now() + timedelta(
            seconds=request.timeout_s * len(request.profiles) * 2 + _CONTROL_RESULT_GRACE_S
        )
        local_registry = CoverageLeaseRegistry(self._config)
        submitted: list[str] = []
        local_started = False
        try:
            # A short capability frame is the only remote configuration fact
            # used here.  It can advertise fixed profile/port pairs but cannot
            # select a destination, listener, payload, or arbitrary command.
            capabilities = (await self._request("capabilities", correlation, control_expires_at, {})).body.get("capabilities")
            remote_ports = _coverage_capability_ports(capabilities)
            local_ports = {item.profile: item.port for item in self._config.receiver_profiles}
            if CoverageProfile.TCP_TAGGED in local_ports:
                local_ports[CoverageProfile.TCP_CONNECT] = local_ports[CoverageProfile.TCP_TAGGED]
            for profile in request.profiles:
                if profile in {CoverageProfile.ARP, CoverageProfile.IPV6_ND}:
                    continue
                if profile is CoverageProfile.ICMP_ECHO:
                    if remote_ports.get(profile) != 0:
                        raise PairedError("configured peer does not admit the ICMP coverage profile")
                    continue
                if remote_ports.get(profile) != local_ports.get(profile):
                    raise PairedError("configured peers do not agree on a coverage receiver profile/port")
            async with asyncio.timeout(request.timeout_s * len(request.profiles) * 2 + _CONTROL_RESULT_GRACE_S):
                forward_expires_at = utc_now() + timedelta(seconds=request.timeout_s)
                admitted = await self._request(
                    "submit", forward, forward_expires_at,
                    {"manifest": _COVERAGE_MANIFEST, "role": _ROLE_A_TO_B},
                )
                if admitted.body != {"status": "accepted"}:
                    raise PairedError("configured peer did not admit the coverage receiver lease")
                submitted.append(forward)
                active_profiles = tuple(item for item in request.profiles if item not in {CoverageProfile.ARP, CoverageProfile.IPV6_ND})
                if not active_profiles:
                    raise PairedError("coverage assessment selected no active profiles")
                local_forward = await self._sender(_ROLE_A_TO_B, forward, profiles=active_profiles)
                remote_receipts = await self._read_receipts(
                    forward, control_expires_at, request.profiles, self._config.bind_host,
                )

                reverse_expires_at = utc_now() + timedelta(seconds=request.timeout_s)
                await local_registry.start(reverse, reverse_expires_at)
                local_started = True
                admitted = await self._request(
                    "submit", reverse, reverse_expires_at,
                    {"manifest": _COVERAGE_MANIFEST, "role": _ROLE_B_TO_A},
                )
                if admitted.body != {"status": "accepted"}:
                    raise PairedError("configured peer did not admit the reverse coverage role")
                submitted.append(reverse)
                remote_reverse = await self._read_coverage_result(reverse, control_expires_at)
                local_receipts = _validate_coverage_receipts(
                    local_registry.receipts_for(reverse) or (), reverse, request.profiles, request.address,
                )
                return _combine_coverage_results(
                    request, local_forward, remote_reverse,
                    remote_receipts=remote_receipts, local_receipts=local_receipts,
                    forward_correlation=forward, reverse_correlation=reverse,
                )
        except TimeoutError as exc:
            raise PairedError("coverage assessment exceeded its finite deadline") from exc
        finally:
            if local_started:
                await local_registry.stop(reverse)
            for item in submitted:
                try:
                    await asyncio.shield(self._request("cancel", item, control_expires_at, {}))
                except (PeerError, OSError):
                    pass

    async def _read_receipts(
        self,
        correlation: str,
        expires_at: datetime,
        profiles: tuple[CoverageProfile, ...],
        expected_source: str,
    ) -> tuple[CoverageReceipt, ...]:
        expected = _receipt_profiles(profiles)
        while True:
            frame = await self._request("read-result", correlation, expires_at, {})
            receipts = frame.body.get("receipts")
            if not isinstance(receipts, list):
                raise PairedError("configured peer did not return coverage receipts")
            validated = _validate_coverage_receipts(
                tuple(_receipt_from_wire(item) for item in receipts), correlation, profiles, expected_source,
            )
            if {item.profile for item in validated} == expected or utc_now() >= expires_at:
                return validated
            await asyncio.sleep(0.01)

    async def _read_coverage_result(self, correlation: str, expires_at: datetime) -> TaskResult:
        while True:
            frame = await self._request("read-result", correlation, expires_at, {})
            if frame.body == {"status": "pending"}:
                await asyncio.sleep(0.01)
                continue
            if set(frame.body) != {"result"}:
                raise PairedError("configured peer returned an invalid coverage result state")
            result = result_from_wire(frame.body["result"])
            if result.task_kind != "coverage":
                raise PairedError("configured peer returned an invalid coverage result")
            return result

    async def _request(self, operation: str, correlation: str, expires_at: datetime, body: dict[str, object]) -> PeerFrame:
        now = utc_now()
        return await self._client.request(PeerFrame(
            version=PEER_PROTOCOL_VERSION, operation=operation, correlation_id=correlation,
            identity=self._client.config.identity, issued_at=now, expires_at=expires_at,
            nonce=secrets.token_urlsafe(16), body=body,
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


def _coverage_capability_ports(value: object) -> dict[CoverageProfile, int]:
    if not isinstance(value, (list, tuple)) or _COVERAGE_MANIFEST not in value:
        raise PairedError("configured peer does not admit the coverage manifest")
    ports: dict[CoverageProfile, int] = {}
    for item in value:
        if not isinstance(item, str):
            continue
        parts = item.split(":")
        if len(parts) != 3 or parts[0] != _COVERAGE_MANIFEST:
            continue
        try:
            profile, port = CoverageProfile(parts[1]), int(parts[2])
        except (ValueError, TypeError):
            continue
        if profile is CoverageProfile.ICMP_ECHO and port == 0:
            ports[profile] = port
        elif profile in CoverageReceiverService._IMPLEMENTED | {CoverageProfile.TCP_CONNECT} and 1 <= port <= 65_535:
            ports[profile] = port
    return ports


def _receipt_from_wire(value: object) -> CoverageReceipt:
    if not isinstance(value, dict) or set(value) != {
        "correlation_id", "profile", "source_address", "source_port", "destination_port",
        "arrived_at", "payload_sha256", "payload_length", "direction", "provenance", "reply_result",
    }:
        raise PairedError("configured peer returned an invalid coverage receipt")
    try:
        return CoverageReceipt(
            correlation_id=value["correlation_id"], profile=CoverageProfile(value["profile"]),
            source_address=value["source_address"], source_port=value["source_port"],
            destination_port=value["destination_port"],
            arrived_at=datetime.fromisoformat(value["arrived_at"]),
            payload_sha256=value["payload_sha256"], payload_length=value["payload_length"],
            direction=Direction(value["direction"]), provenance=value["provenance"],
            reply_result=value["reply_result"],
        )
    except (TypeError, ValueError) as exc:
        raise PairedError("configured peer returned an invalid coverage receipt") from exc


def _receipt_profiles(profiles: tuple[CoverageProfile, ...]) -> set[CoverageProfile]:
    return set(profiles) & CoverageReceiverService._IMPLEMENTED


def _validate_coverage_receipts(
    receipts: tuple[CoverageReceipt, ...],
    correlation: str,
    profiles: tuple[CoverageProfile, ...],
    expected_source: str,
) -> tuple[CoverageReceipt, ...]:
    expected = _receipt_profiles(profiles)
    filtered: list[CoverageReceipt] = []
    for receipt in receipts:
        if receipt.correlation_id != correlation:
            raise PairedError("coverage receipt correlation does not match its lease")
        if receipt.profile not in expected:
            raise PairedError("coverage receipt profile was not selected")
        if receipt.source_address != expected_source:
            raise PairedError("coverage receipt source does not match the configured peer")
        filtered.append(receipt)
    if len({item.profile for item in filtered}) != len(filtered):
        raise PairedError("coverage receiver recorded duplicate profile evidence")
    return tuple(filtered)


def _combine_coverage_results(
    request: CoverageAssessmentRequest,
    local_forward: TaskResult,
    remote_reverse: TaskResult,
    *,
    remote_receipts: tuple[CoverageReceipt, ...],
    local_receipts: tuple[CoverageReceipt, ...],
    forward_correlation: str,
    reverse_correlation: str,
) -> TaskResult:
    if local_forward.task_kind != "coverage" or remote_reverse.task_kind != "coverage":
        raise PairedError("coverage roles returned an invalid task result")
    observations = [
        *_label_coverage_sender(local_forward.observations, _ROLE_A_TO_B, forward_correlation, "A"),
        *_label_coverage_sender(remote_reverse.observations, _ROLE_B_TO_A, reverse_correlation, "B"),
    ]
    observations.extend(_receipt_observations(remote_receipts, _ROLE_A_TO_B, forward_correlation, request.address, "B"))
    observations.extend(_receipt_observations(local_receipts, _ROLE_B_TO_A, reverse_correlation, request.address, "A"))
    observations.extend(_local_link_scope_observations(request))
    if not observations:
        raise PairedError("coverage assessment produced no evidence")
    provisional = TaskResult(
        task_id=f"coverage-{forward_correlation[:-1]}", task_kind="coverage", direction=Direction.OUTBOUND,
        target=request.address, state=local_forward.state,
        started_at=min(local_forward.started_at, remote_reverse.started_at),
        ended_at=max(local_forward.ended_at, remote_reverse.ended_at),
        requested_config={
            "coverage_manifest": _COVERAGE_MANIFEST, "peer_identity": request.identity,
            "profiles": [item.value for item in request.profiles], "network_io": True,
        },
        effective_config=replace(local_forward.effective_config, profile=_COVERAGE_MANIFEST),
        progress=replace(
            local_forward.progress,
            admitted=local_forward.progress.admitted + remote_reverse.progress.admitted,
            completed=local_forward.progress.completed + remote_reverse.progress.completed,
            total=local_forward.progress.total + remote_reverse.progress.total,
        ),
        observations=tuple(observations), capabilities=(*local_forward.capabilities, *remote_reverse.capabilities),
        errors=(*local_forward.errors, *remote_reverse.errors),
    )
    rows = coverage_matrix(provisional, requested=request.profiles)
    candidates = tuple(row for row in rows if row.outcome is CoverageOutcome.CANDIDATE_CARRIER)
    gaps = tuple(row for row in rows if row.outcome is not CoverageOutcome.CANDIDATE_CARRIER)
    health = Health.HEALTHY if not gaps else Health.PARTIAL
    conclusion = Conclusion(
        id="coverage-assessment", title="Paired coverage assessment",
        summary=(
            f"{len(candidates)} tested profile/direction carrier(s) had direct arrival or reply evidence; "
            f"{len(gaps)} profile/direction row(s) remain gaps."
        ),
        health=health, confidence=Confidence.HIGH if candidates else Confidence.LOW,
        observation_ids=tuple(item.id for item in observations),
        limitations=(
            "This conclusion covers only the emitted profile, port/packet shape, direction, and time window.",
            "Untested packet formats, payloads, state sequences, and tunnel implementations remain outside this assessment.",
        ),
    )
    return replace(provisional, conclusions=(conclusion,))


def _label_coverage_sender(
    observations: tuple[Observation, ...], role: str, correlation: str, endpoint: str,
) -> tuple[Observation, ...]:
    labelled: list[Observation] = []
    for index, observation in enumerate(observations):
        detail = dict(observation.detail)
        detail.update({"paired_phase": role, "paired_correlation": correlation, "paired_endpoint": endpoint})
        labelled.append(replace(observation, id=f"{endpoint}-coverage-{index}-{observation.id}", detail=detail))
    return tuple(labelled)


def _receipt_observations(
    receipts: tuple[CoverageReceipt, ...], role: str, correlation: str, target: str, endpoint: str,
) -> tuple[Observation, ...]:
    observations: list[Observation] = []
    for index, receipt in enumerate(receipts):
        if receipt.correlation_id != correlation:
            continue
        kind = ProbeKind.UDP_EXCHANGE.value if receipt.profile in {CoverageProfile.UDP_TAGGED, CoverageProfile.DNS_UDP} else ProbeKind.TCP_CONNECT.value
        observations.append(Observation(
            id=f"{endpoint}-coverage-receipt-{index}-{receipt.profile.value}", probe=kind,
            disposition=Disposition.POSITIVE, evidence_kind=EvidenceKind.PEER_OBSERVED_ARRIVAL,
            direction=Direction.INBOUND, target=target, started_at=receipt.arrived_at,
            ended_at=receipt.arrived_at, duration_ms=0.0, source=receipt.provenance,
            detail={
                "coverage_profile": receipt.profile.value, "paired_phase": role,
                "paired_correlation": correlation, "paired_endpoint": endpoint,
                "receiver_source_address": receipt.source_address, "receiver_source_port": receipt.source_port,
                "receiver_destination_port": receipt.destination_port, "payload_sha256": receipt.payload_sha256,
                "payload_length": receipt.payload_length, "reply_result": receipt.reply_result,
            },
        ))
    return tuple(observations)


def _local_link_scope_observations(request: CoverageAssessmentRequest) -> tuple[Observation, ...]:
    profiles = tuple(item for item in request.profiles if item in {CoverageProfile.ARP, CoverageProfile.IPV6_ND})
    if not profiles or request.local_network is None or request.peer_network is None:
        return ()
    outcome = local_link_applicability(request.local_network, request.peer_network)
    if outcome is not CoverageOutcome.NOT_APPLICABLE:
        return ()
    instant = utc_now()
    observations: list[Observation] = []
    for profile in profiles:
        for role in (_ROLE_A_TO_B, _ROLE_B_TO_A):
            observations.append(Observation(
                id=f"local-link-{profile.value}-{role}", probe="local_link_scope",
                disposition=Disposition.UNAVAILABLE, evidence_kind=EvidenceKind.UNSUPPORTED,
                direction=Direction.LOCAL, target=request.address, started_at=instant, ended_at=instant,
                duration_ms=0.0, source="mercury.local_link_scope",
                detail={
                    "coverage_profile": profile.value, "paired_phase": role,
                    "coverage_outcome": CoverageOutcome.NOT_APPLICABLE.value,
                    "local_network": request.local_network, "peer_network": request.peer_network,
                },
            ))
    return tuple(observations)


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


def coverage_matrix(
    result: TaskResult,
    *,
    requested: tuple[CoverageProfile, ...] = DEFAULT_COVERAGE_PROFILES,
) -> tuple[CoverageMatrixRow, ...]:
    """Project finite profile evidence without inferring an untested carrier.

    A row is positive only when the canonical observations include a receiver
    arrival, peer acknowledgement, or protocol response.  Merely having a
    receiver lease is not evidence that a packet crossed the boundary.
    """
    if type(result) is not TaskResult:
        raise PairedError("coverage matrix requires a canonical task result")
    if not isinstance(requested, tuple) or not requested or any(
        type(profile) is not CoverageProfile for profile in requested
    ) or len(set(requested)) != len(requested):
        raise PairedError("coverage profiles must be a non-empty unique tuple")
    grouped: dict[tuple[CoverageProfile, str], list[Observation]] = {}
    for observation in result.observations:
        profile = _coverage_profile_for(observation)
        if profile is None or profile not in requested:
            continue
        direction = str(observation.detail.get("paired_phase", "local"))
        grouped.setdefault((profile, direction), []).append(observation)
    rows: list[CoverageMatrixRow] = []
    directions = (_ROLE_A_TO_B, _ROLE_B_TO_A)
    for profile in requested:
        profile_directions = tuple(
            direction for candidate, direction in grouped if candidate is profile
        ) or directions
        for direction in profile_directions:
            observations = grouped.get((profile, direction), [])
            if not observations:
                outcome = CoverageOutcome.SKIPPED
                limitations = ("This selected profile/direction has no emitted evidence.",)
            else:
                outcome = _coverage_outcome(observations)
                limitations = _coverage_limitations(profile, outcome)
            rows.append(CoverageMatrixRow(
                profile=profile, direction=direction, outcome=outcome,
                observation_ids=tuple(item.id for item in observations),
                provenance=tuple(sorted({item.source for item in observations})),
                limitations=limitations,
            ))
    return tuple(rows)


def _coverage_profile_for(observation: Observation) -> CoverageProfile | None:
    configured = observation.detail.get("coverage_profile")
    if isinstance(configured, str):
        try:
            return CoverageProfile(configured)
        except ValueError:
            return None
    return {
        ProbeKind.TCP_CONNECT.value: CoverageProfile.TCP_CONNECT,
        ProbeKind.UDP_EXCHANGE.value: CoverageProfile.UDP_TAGGED,
        ProbeKind.TLS_HANDSHAKE.value: CoverageProfile.TLS_HANDSHAKE,
        ProbeKind.HTTP_EXCHANGE.value: CoverageProfile.HTTP_EXCHANGE,
        ProbeKind.NATIVE_PING.value: CoverageProfile.ICMP_ECHO,
    }.get(observation.probe)


def _coverage_outcome(observations: list[Observation]) -> CoverageOutcome:
    if any(item.detail.get("coverage_outcome") == CoverageOutcome.NOT_APPLICABLE.value for item in observations):
        return CoverageOutcome.NOT_APPLICABLE
    kinds = {item.evidence_kind for item in observations}
    if kinds & {
        EvidenceKind.PEER_OBSERVED_ARRIVAL, EvidenceKind.PEER_ACKNOWLEDGEMENT,
        EvidenceKind.DNS_ANSWER, EvidenceKind.DNS_QUERY, EvidenceKind.TLS_HANDSHAKE,
        EvidenceKind.HTTP_RESPONSE, EvidenceKind.SSH_BANNER,
        EvidenceKind.UDP_APPLICATION_REPLY, EvidenceKind.TCP_CONNECTED,
        EvidenceKind.NATIVE_PING_REPLY,
    }:
        return CoverageOutcome.CANDIDATE_CARRIER
    if EvidenceKind.PERMISSION_DENIED in kinds:
        return CoverageOutcome.PERMISSION_DENIED
    if EvidenceKind.UNSUPPORTED in kinds:
        return CoverageOutcome.UNSUPPORTED
    if kinds & {EvidenceKind.TIMEOUT, EvidenceKind.SILENT, EvidenceKind.PATH_HOP_UNANSWERED}:
        return CoverageOutcome.INCONCLUSIVE
    if kinds & {
        EvidenceKind.TCP_REFUSED, EvidenceKind.TCP_RESET, EvidenceKind.NETWORK_UNREACHABLE,
        EvidenceKind.HOST_UNREACHABLE, EvidenceKind.ICMP_UNREACHABLE,
        EvidenceKind.ADMIN_PROHIBITED, EvidenceKind.TLS_VERIFICATION_FAILED,
        EvidenceKind.TLS_HANDSHAKE_FAILED, EvidenceKind.NATIVE_PING_FAILURE,
    }:
        return CoverageOutcome.DIRECT_NEGATIVE
    return CoverageOutcome.SKIPPED


def _coverage_limitations(profile: CoverageProfile, outcome: CoverageOutcome) -> tuple[str, ...]:
    scoped = "The outcome applies only to this emitted profile, port/packet shape, direction, and time window."
    if profile in {CoverageProfile.ARP, CoverageProfile.IPV6_ND}:
        return ("ARP/ND is local-link evidence only and cannot establish cross-subnet remote reachability.", scoped)
    if outcome is CoverageOutcome.INCONCLUSIVE:
        return ("Silence or timeout does not identify the blocking device or cause.", scoped)
    if outcome in {CoverageOutcome.UNSUPPORTED, CoverageOutcome.PERMISSION_DENIED, CoverageOutcome.SKIPPED}:
        return ("This is a coverage gap, not negative reachability evidence.", scoped)
    return (scoped,)


def local_link_applicability(left_network: str, right_network: str) -> CoverageOutcome:
    """Return the only valid ARP/ND scope classification for a remote pair."""
    try:
        left = ipaddress.ip_network(left_network, strict=False)
        right = ipaddress.ip_network(right_network, strict=False)
    except ValueError as exc:
        raise PairedError("local-link networks are invalid") from exc
    return CoverageOutcome.SKIPPED if left.version == right.version and left.overlaps(right) else CoverageOutcome.NOT_APPLICABLE


def icmp_coverage_evidence(result: CommandResult) -> tuple[EvidenceKind, Disposition, str]:
    """Classify the bounded native ICMP command without parsing locale-specific text."""
    if type(result) is not CommandResult:
        raise PairedError("ICMP coverage requires a bounded command result")
    if result.outcome is CommandOutcome.SUCCESS:
        return EvidenceKind.NATIVE_PING_REPLY, Disposition.POSITIVE, "native_echo_reply"
    if result.outcome is CommandOutcome.TIMEOUT:
        return EvidenceKind.TIMEOUT, Disposition.INCONCLUSIVE, "native_echo_timeout"
    if result.outcome is CommandOutcome.PERMISSION_DENIED:
        return EvidenceKind.PERMISSION_DENIED, Disposition.UNAVAILABLE, "native_permission_denied"
    if result.outcome is CommandOutcome.MISSING_TOOL:
        return EvidenceKind.UNSUPPORTED, Disposition.UNAVAILABLE, "native_icmp_unavailable"
    if result.outcome is CommandOutcome.NONZERO:
        return EvidenceKind.NATIVE_PING_FAILURE, Disposition.ERROR, "native_echo_nonzero_unclassified"
    return EvidenceKind.EXECUTION_ERROR, Disposition.ERROR, "native_echo_execution_error"


async def run_icmp_coverage(
    address: str,
    timeout_s: float,
    *,
    system: Callable[[], str] = platform.system,
    command_runner=run_command,
) -> CommandResult:
    """Run one fixed native echo request; never accept arbitrary ping argv."""
    target = _address(address, "ICMP address")
    if type(timeout_s) not in (int, float) or not 0.1 <= float(timeout_s) <= 30.0:
        raise PairedError("ICMP timeout must be within 0.1..30 seconds")
    milliseconds = max(100, math.ceil(float(timeout_s) * 1000))
    if system() == "Windows":
        argv = ("ping", "-n", "1", "-w", str(milliseconds), target)
    else:
        argv = ("ping", "-n", "-c", "1", "-W", str(max(1, math.ceil(float(timeout_s)))), target)
    return await command_runner(argv, min(30.0, float(timeout_s) + 1.0), 8_192)


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


class ConfiguredCoverageExecutor:
    """Send only the locally configured coverage records to the fixed peer.

    This deliberately has no public destination, port, payload, or profile
    argument.  The optional ``profiles`` argument is accepted solely from the
    in-process authenticated coordinator after it matched the remote capability
    table to this same immutable configuration.
    """

    def __init__(self, config: PeerConfig, history, *, icmp_runner=run_icmp_coverage) -> None:
        if type(config) is not PeerConfig or not config.coverage_enabled:
            raise PairedError("coverage runtime requires configured receivers")
        self._config, self._history, self._icmp_runner = config, history, icmp_runner

    async def __call__(
        self, role: str, correlation: str, *, profiles: tuple[CoverageProfile, ...] | None = None,
    ) -> TaskResult:
        if role not in {_ROLE_A_TO_B, _ROLE_B_TO_A}:
            raise PairedError("coverage role is invalid")
        selected = self._config.coverage_profiles if profiles is None else profiles
        selected = tuple(item for item in selected if item not in {CoverageProfile.ARP, CoverageProfile.IPV6_ND})
        configured = {item.profile: item for item in self._config.receiver_profiles}
        if not selected or any(profile not in configured and not (
            profile is CoverageProfile.TCP_CONNECT and CoverageProfile.TCP_TAGGED in configured
        ) and profile is not CoverageProfile.ICMP_ECHO for profile in selected):
            raise PairedError("coverage profile is not locally configured")
        plan = _coverage_runtime_plan(self._config, correlation, selected)
        service = TaskService(self._history)

        async def runner(context: TaskContext) -> None:
            for step, profile in zip(plan.preview.steps, selected, strict=True):
                receiver = None if profile is CoverageProfile.ICMP_ECHO else _coverage_receiver_for(configured, profile)
                await self._send(context, step, receiver, profile, correlation)

        return await service.run(
            plan, runner, task_kind="coverage",
            requested_config={"purpose": "configured paired coverage sender", "profile": _COVERAGE_MANIFEST},
        )

    async def _send(
        self, context: TaskContext, step: ProbeStep, receiver: ReceiverProfileConfig | None,
        profile: CoverageProfile, correlation: str,
    ) -> None:
        prepared = await context.admit(step.id)
        started = context.wall_clock()
        kind, disposition = EvidenceKind.EXECUTION_ERROR, Disposition.ERROR
        try:
            if profile is CoverageProfile.ICMP_ECHO:
                result = await self._icmp_runner(prepared.address or step.target, step.timeout_s)
                kind, disposition, _ = icmp_coverage_evidence(result)
            elif profile is CoverageProfile.TCP_CONNECT:
                assert receiver is not None
                reader, writer = await asyncio.open_connection(
                    self._config.peer_addresses[0], receiver.port, local_addr=(self._config.bind_host, 0),
                )
                writer.close()
                await writer.wait_closed()
                kind, disposition = EvidenceKind.TCP_CONNECTED, Disposition.POSITIVE
            elif profile is CoverageProfile.TCP_TAGGED:
                assert receiver is not None
                reader, writer = await asyncio.open_connection(
                    self._config.peer_addresses[0], receiver.port, local_addr=(self._config.bind_host, 0),
                )
                try:
                    writer.write(f"MRC2:{profile.value}:{correlation}".encode("ascii"))
                    await writer.drain()
                    if await asyncio.wait_for(reader.readexactly(len(_COVERAGE_REPLY)), step.timeout_s) != _COVERAGE_REPLY:
                        raise OSError("coverage TCP acknowledgement was invalid")
                finally:
                    writer.close()
                    await writer.wait_closed()
                kind, disposition = EvidenceKind.PEER_ACKNOWLEDGEMENT, Disposition.POSITIVE
            elif profile is CoverageProfile.UDP_TAGGED:
                assert receiver is not None
                protocol = _PairedReply()
                transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                    lambda: protocol, local_addr=(self._config.bind_host, 0),
                )
                try:
                    transport.sendto(
                        f"MRC2:{profile.value}:{correlation}".encode("ascii"),
                        (self._config.peer_addresses[0], receiver.port),
                    )
                    if await asyncio.wait_for(protocol.reply, step.timeout_s) != _COVERAGE_REPLY:
                        raise OSError("coverage UDP acknowledgement was invalid")
                finally:
                    transport.close()
                kind, disposition = EvidenceKind.PEER_ACKNOWLEDGEMENT, Disposition.POSITIVE
            elif profile is CoverageProfile.DNS_UDP:
                assert receiver is not None
                protocol = _PairedReply()
                transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                    lambda: protocol, local_addr=(self._config.bind_host, 0),
                )
                try:
                    query = _dns_coverage_query(correlation)
                    transport.sendto(query, (self._config.peer_addresses[0], receiver.port))
                    reply = await asyncio.wait_for(protocol.reply, step.timeout_s)
                    if reply[2:4] != b"\x81\x80":
                        raise OSError("coverage DNS reply was invalid")
                finally:
                    transport.close()
                kind, disposition = EvidenceKind.DNS_QUERY, Disposition.POSITIVE
            elif profile is CoverageProfile.DNS_TCP:
                assert receiver is not None
                reader, writer = await asyncio.open_connection(
                    self._config.peer_addresses[0], receiver.port, local_addr=(self._config.bind_host, 0),
                )
                try:
                    query = _dns_coverage_query(correlation)
                    writer.write(len(query).to_bytes(2, "big") + query)
                    await writer.drain()
                    reply = await asyncio.wait_for(reader.readexactly(int.from_bytes(await reader.readexactly(2), "big")), step.timeout_s)
                    if reply[2:4] != b"\x81\x80":
                        raise OSError("coverage DNS reply was invalid")
                finally:
                    writer.close()
                    await writer.wait_closed()
                kind, disposition = EvidenceKind.DNS_QUERY, Disposition.POSITIVE
            elif profile is CoverageProfile.HTTP_EXCHANGE:
                assert receiver is not None
                reader, writer = await asyncio.open_connection(
                    self._config.peer_addresses[0], receiver.port, local_addr=(self._config.bind_host, 0),
                )
                try:
                    marker = correlation.encode("ascii")
                    writer.write(b"GET /mercury/" + marker + b" HTTP/1.1\r\nHost: mercury.test\r\nX-Mercury-Correlation: " + marker + b"\r\n\r\n")
                    await writer.drain()
                    if not (await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), step.timeout_s)).startswith(b"HTTP/1.1 204"):
                        raise OSError("coverage HTTP response was invalid")
                finally:
                    writer.close()
                    await writer.wait_closed()
                kind, disposition = EvidenceKind.HTTP_RESPONSE, Disposition.POSITIVE
            elif profile is CoverageProfile.SSH_BANNER:
                assert receiver is not None
                reader, writer = await asyncio.open_connection(
                    self._config.peer_addresses[0], receiver.port, local_addr=(self._config.bind_host, 0),
                )
                try:
                    if await asyncio.wait_for(reader.readline(), step.timeout_s) != b"SSH-2.0-MercuryCoverage\r\n":
                        raise OSError("coverage SSH banner was invalid")
                    writer.write(b"SSH-2.0-Mercury-" + correlation.encode("ascii") + b"\r\n")
                    await writer.drain()
                finally:
                    writer.close()
                    await writer.wait_closed()
                kind, disposition = EvidenceKind.SSH_BANNER, Disposition.POSITIVE
            elif profile is CoverageProfile.TLS_HANDSHAKE:
                assert receiver is not None
                reader, writer = await asyncio.open_connection(
                    self._config.peer_addresses[0], receiver.port, local_addr=(self._config.bind_host, 0),
                    ssl=_coverage_tls_client_context(receiver), server_hostname=receiver.tls_server_name,
                )
                try:
                    await writer.drain()
                finally:
                    writer.close()
                    await writer.wait_closed()
                kind, disposition = EvidenceKind.TLS_HANDSHAKE, Disposition.POSITIVE
            else:
                kind, disposition = EvidenceKind.UNSUPPORTED, Disposition.UNAVAILABLE
        except TimeoutError:
            kind, disposition = EvidenceKind.TIMEOUT, Disposition.INCONCLUSIVE
        except ssl.SSLCertVerificationError:
            kind, disposition = EvidenceKind.TLS_VERIFICATION_FAILED, Disposition.NEGATIVE
        except ssl.SSLError:
            kind, disposition = EvidenceKind.TLS_HANDSHAKE_FAILED, Disposition.NEGATIVE
        except OSError as exc:
            kind, disposition = _paired_socket_failure(exc, udp=profile in {CoverageProfile.UDP_TAGGED, CoverageProfile.DNS_UDP})
        ended = context.wall_clock()
        context.record(Observation(
            id=f"coverage-send-{correlation[-12:]}-{profile.value}",
            probe=step.probe_kind.value, disposition=disposition, evidence_kind=kind,
            direction=Direction.OUTBOUND, target=prepared.address or step.target,
            started_at=started, ended_at=ended,
            duration_ms=max(0.0, (ended - started).total_seconds() * 1000),
            attempt=step.attempt, source="mercury.coverage_sender",
            detail={"coverage_profile": profile.value, "coverage_role": "fixed_send"},
        ), step_id=step.id)
        context.complete_attempt(step.id)


def _coverage_runtime_plan(config: PeerConfig, correlation: str, profiles: tuple[CoverageProfile, ...]) -> ProbePlan:
    receivers = {item.profile: item for item in config.receiver_profiles}
    specs: list[ProbeSpec] = []
    for profile in profiles:
        receiver = None if profile is CoverageProfile.ICMP_ECHO else _coverage_receiver_for(receivers, profile)
        if profile is CoverageProfile.ICMP_ECHO:
            kind, transport = ProbeKind.NATIVE_PING, None
        elif profile in {CoverageProfile.UDP_TAGGED, CoverageProfile.DNS_UDP}:
            kind, transport = ProbeKind.UDP_EXCHANGE, Transport.UDP
        elif profile is CoverageProfile.HTTP_EXCHANGE:
            kind, transport = ProbeKind.HTTP_EXCHANGE, Transport.TCP
        elif profile is CoverageProfile.TLS_HANDSHAKE:
            kind, transport = ProbeKind.TLS_HANDSHAKE, Transport.TCP
        else:
            kind, transport = ProbeKind.TCP_CONNECT, Transport.TCP
        tag_length = len(f"MRC2:{profile.value}:{correlation}".encode("ascii"))
        # ponytail: one legacy UDP payload slot cannot represent DNS and tag
        # shapes; StepCost retains exact byte accounting.  Upgrade when the
        # versioned plan model supports per-step payload metadata summaries.
        payload = PayloadMetadata("coverage-v2", 0)
        specs.append(ProbeSpec(
            kind, config.peer_addresses[0], address=config.peer_addresses[0], port=None if receiver is None else receiver.port,
            transport=transport, timeout_s=1.0 if receiver is None else receiver.timeout_s, payload_metadata=payload,
            server_name=(receiver.tls_server_name if kind is ProbeKind.TLS_HANDSHAKE else config.peer_addresses[0]) if kind in {ProbeKind.TLS_HANDSHAKE, ProbeKind.HTTP_EXCHANGE} else None,
            http_scheme="http" if kind is ProbeKind.HTTP_EXCHANGE else None,
            cost=StepCost(1, 1 if transport is Transport.UDP else 0, tag_length if receiver is not None else 0, logical_packets=1),
        ))
    grant = ScopeGrant(
        networks=(ipaddress.ip_network(f"{config.peer_addresses[0]}/{32 if ':' not in config.peer_addresses[0] else 128}"),),
        ports=tuple(_coverage_receiver_for(receivers, item).port for item in profiles if item is not CoverageProfile.ICMP_ECHO),
        transports=tuple(sorted({"udp" if item in {CoverageProfile.UDP_TAGGED, CoverageProfile.DNS_UDP} else "tcp" for item in profiles if item is not CoverageProfile.ICMP_ECHO})),
        attested=True, purpose="configured paired coverage sender",
        expires_at=utc_now() + timedelta(seconds=max(1.0 if item is CoverageProfile.ICMP_ECHO else _coverage_receiver_for(receivers, item).timeout_s for item in profiles)),
    )
    preview = preview_probe_plan(
        specs=tuple(specs), grant=grant, profile=_COVERAGE_MANIFEST,
        limits=replace(DEFAULT_LIMITS, max_duration_s=max(1, math.ceil(sum(1.0 if item is CoverageProfile.ICMP_ECHO else _coverage_receiver_for(receivers, item).timeout_s for item in profiles)))),
    )
    return authorize_plan(preview)


def _coverage_receiver_for(
    configured: dict[CoverageProfile, ReceiverProfileConfig], profile: CoverageProfile,
) -> ReceiverProfileConfig:
    receiver = configured.get(profile)
    if receiver is None and profile is CoverageProfile.TCP_CONNECT:
        receiver = configured.get(CoverageProfile.TCP_TAGGED)
    if receiver is None:
        raise PairedError("coverage profile is not locally configured")
    return receiver


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


@dataclass(frozen=True, slots=True)
class CoverageReceiverLease:
    """Short-lived authority for one fixed, locally configured receiver."""

    receiver: ReceiverProfileConfig
    correlation_id: str
    authenticated_source: str
    expires_at: datetime

    def __post_init__(self) -> None:
        if type(self.receiver) is not ReceiverProfileConfig:
            raise PairedError("coverage receiver must be locally configured")
        if not isinstance(self.correlation_id, str) or not self.correlation_id.isascii() or not 1 <= len(self.correlation_id) <= 64:
            raise PairedError("coverage correlation is invalid")
        object.__setattr__(self, "authenticated_source", _address(self.authenticated_source, "coverage authenticated source"))
        if type(self.expires_at) is not datetime or self.expires_at.tzinfo is None or self.expires_at <= utc_now():
            raise PairedError("coverage lease expiry is invalid")

    def assert_current(self, now: datetime) -> None:
        if type(now) is not datetime or now.tzinfo is None or now >= self.expires_at:
            raise PairedError("coverage lease has expired")


def encode_coverage_tag(lease: CoverageReceiverLease) -> bytes:
    """Return the only data-plane tag accepted by a coverage receiver."""
    return f"MRC2:{lease.receiver.profile.value}:{lease.correlation_id}".encode("ascii")


class CoverageReceiverService:
    """Receive fixed TCP/UDP/HTTP/SSH coverage records for a bounded lease.

    The service has no caller-specified bind, payload, or reply knob.  It is
    deliberately a small adapter used by the trusted peer coordinator; DNS and
    TLS require their dedicated standards-compliant adapters and are not
    silently emulated here.
    """

    _IMPLEMENTED = frozenset({
        CoverageProfile.TCP_TAGGED, CoverageProfile.UDP_TAGGED,
        CoverageProfile.DNS_UDP, CoverageProfile.DNS_TCP, CoverageProfile.TLS_HANDSHAKE,
        CoverageProfile.HTTP_EXCHANGE, CoverageProfile.SSH_BANNER,
    })

    def __init__(self, lease: CoverageReceiverLease, *, now: Callable[[], datetime] = utc_now, ssl_context: ssl.SSLContext | None = None) -> None:
        if type(lease) is not CoverageReceiverLease:
            raise PairedError("coverage receiver requires a lease")
        self.lease, self._now, self._ssl_context = lease, now, ssl_context
        self._tcp: asyncio.AbstractServer | None = None
        self._udp: asyncio.DatagramTransport | None = None
        self._expiry: asyncio.Task[None] | None = None
        self._receipts: list[CoverageReceipt] = []
        self._claimed = False

    @property
    def receipts(self) -> tuple[CoverageReceipt, ...]:
        return tuple(self._receipts)

    async def start(self) -> None:
        lease = self.lease
        lease.assert_current(self._now())
        if lease.receiver.profile not in self._IMPLEMENTED:
            raise PairedError(f"coverage receiver profile is unavailable: {lease.receiver.profile.value}")
        if lease.receiver.profile is CoverageProfile.TLS_HANDSHAKE and self._ssl_context is None:
            raise PairedError("TLS coverage receiver needs a configured certificate context")
        if lease.receiver.profile in {CoverageProfile.UDP_TAGGED, CoverageProfile.DNS_UDP}:
            transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: _CoverageDatagram(self), local_addr=(lease.receiver.bind_host, lease.receiver.port),
            )
            self._udp = transport
        else:
            self._tcp = await asyncio.start_server(
                self._handle_tcp, host=lease.receiver.bind_host, port=lease.receiver.port,
                ssl=self._ssl_context if lease.receiver.profile is CoverageProfile.TLS_HANDSHAKE else None,
            )
        self._expiry = asyncio.create_task(self._expire(), name=f"mercury:coverage:{lease.correlation_id}")

    async def stop(self) -> None:
        if self._expiry is not None and self._expiry is not asyncio.current_task():
            self._expiry.cancel()
        self._expiry = None
        if self._udp is not None:
            self._udp.close()
            self._udp = None
        if self._tcp is not None:
            server, self._tcp = self._tcp, None
            server.close()
            await server.wait_closed()

    async def _expire(self) -> None:
        await asyncio.sleep(max(0, (self.lease.expires_at - self._now()).total_seconds()))
        await self.stop()

    async def _handle_tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            if not self._source_matches(writer.get_extra_info("peername")):
                return
            self.lease.assert_current(self._now())
            profile = self.lease.receiver.profile
            tag = encode_coverage_tag(self.lease)
            async with asyncio.timeout(self.lease.receiver.timeout_s):
                if profile is CoverageProfile.TLS_HANDSHAKE:
                    tag = encode_coverage_tag(self.lease)
                elif profile is CoverageProfile.DNS_TCP:
                    size = int.from_bytes(await reader.readexactly(2), "big")
                    query = await reader.readexactly(size)
                    reply = _dns_coverage_reply(self.lease, query)
                    if reply is None:
                        return
                    writer.write(len(reply).to_bytes(2, "big") + reply)
                    tag = query
                elif profile is CoverageProfile.HTTP_EXCHANGE:
                    request = await reader.readuntil(b"\r\n\r\n")
                    expected = b"GET /mercury/" + self.lease.correlation_id.encode("ascii") + b" HTTP/1.1\r\n"
                    if not request.startswith(expected) or b"X-Mercury-Correlation: " + self.lease.correlation_id.encode("ascii") not in request:
                        return
                    writer.write(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                elif profile is CoverageProfile.SSH_BANNER:
                    writer.write(b"SSH-2.0-MercuryCoverage\r\n")
                    await writer.drain()
                    if await reader.readline() != b"SSH-2.0-Mercury-" + self.lease.correlation_id.encode("ascii") + b"\r\n":
                        return
                else:
                    if await reader.readexactly(len(tag)) != tag:
                        return
                    writer.write(_COVERAGE_REPLY)
                await writer.drain()
            self._record(writer.get_extra_info("peername"), tag, "acknowledged")
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, OSError, TimeoutError, PairedError):
            return
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, RuntimeError):
                pass

    def _receive_datagram(self, data: bytes, address: tuple[str, int]) -> None:
        if self._claimed or not self._source_matches(address):
            return
        try:
            self.lease.assert_current(self._now())
        except PairedError:
            return
        assert self._udp is not None
        if self.lease.receiver.profile is CoverageProfile.DNS_UDP:
            reply = _dns_coverage_reply(self.lease, data)
            if reply is None:
                return
            self._udp.sendto(reply, address)
            self._record(address, data, "dns_answered")
        elif data == encode_coverage_tag(self.lease):
            self._udp.sendto(_COVERAGE_REPLY, address)
            self._record(address, data, "acknowledged")

    def _record(self, peer: object, payload: bytes, reply_result: str) -> None:
        if self._claimed or not isinstance(peer, tuple) or len(peer) < 2 or not isinstance(peer[0], str) or type(peer[1]) is not int:
            return
        self._claimed = True
        now = self._now()
        self._receipts.append(CoverageReceipt(
            correlation_id=self.lease.correlation_id, profile=self.lease.receiver.profile,
            source_address=peer[0], source_port=peer[1], destination_port=self.lease.receiver.port,
            arrived_at=now, payload_sha256="sha256:" + hashlib.sha256(payload).hexdigest(),
            payload_length=len(payload), direction=Direction.INBOUND,
            provenance="mercury.coverage_receiver", reply_result=reply_result,
        ))

    def _source_matches(self, peer: object) -> bool:
        return isinstance(peer, tuple) and bool(peer) and isinstance(peer[0], str) and _address(peer[0], "coverage packet source") == self.lease.authenticated_source


class _CoverageDatagram(asyncio.DatagramProtocol):
    def __init__(self, service: CoverageReceiverService) -> None:
        self._service = service

    def datagram_received(self, data: bytes, address: tuple[str, int]) -> None:
        self._service._receive_datagram(data, address)


class CoverageLeaseRegistry:
    """Peer-control-owned lifecycle for the receiver table of one endpoint."""

    def __init__(self, config: PeerConfig, *, ssl_context: ssl.SSLContext | None = None) -> None:
        if type(config) is not PeerConfig or not config.coverage_enabled:
            raise PairedError("coverage registry requires configured receivers")
        self._config, self._ssl_context = config, ssl_context
        self._services: dict[str, tuple[CoverageReceiverService, ...]] = {}

    async def start(self, correlation_id: str, requested_expiry: datetime) -> None:
        if correlation_id in self._services:
            raise PairedError("coverage correlation is already active")
        if type(requested_expiry) is not datetime or requested_expiry.tzinfo is None:
            raise PairedError("coverage frame expiry is invalid")
        now = utc_now()
        services: list[CoverageReceiverService] = []
        try:
            for receiver in self._config.receiver_profiles:
                expiry = min(requested_expiry, now + timedelta(seconds=receiver.timeout_s))
                context = self._ssl_context
                if receiver.profile is CoverageProfile.TLS_HANDSHAKE and context is None:
                    context = _coverage_tls_server_context(receiver)
                service = CoverageReceiverService(CoverageReceiverLease(
                    receiver, correlation_id, self._config.peer_addresses[0], expiry,
                ), ssl_context=context)
                await service.start()
                services.append(service)
        except Exception:
            for service in services:
                await service.stop()
            raise
        self._services[correlation_id] = tuple(services)

    async def stop(self, correlation_id: str) -> None:
        for service in self._services.pop(correlation_id, ()):
            await service.stop()

    @property
    def receipts(self) -> tuple[CoverageReceipt, ...]:
        return tuple(receipt for services in self._services.values() for service in services for receipt in service.receipts)

    @property
    def capabilities(self) -> tuple[str, ...]:
        entries = [
            f"{_COVERAGE_MANIFEST}:{receiver.profile.value}:{receiver.port}"
            for receiver in self._config.receiver_profiles
        ]
        tcp = next((item for item in self._config.receiver_profiles if item.profile is CoverageProfile.TCP_TAGGED), None)
        if tcp is not None:
            entries.append(f"{_COVERAGE_MANIFEST}:{CoverageProfile.TCP_CONNECT.value}:{tcp.port}")
        if CoverageProfile.ICMP_ECHO in self._config.coverage_profiles:
            entries.append(f"{_COVERAGE_MANIFEST}:{CoverageProfile.ICMP_ECHO.value}:0")
        return (_COVERAGE_MANIFEST, *entries)

    def receipts_for(self, correlation_id: str) -> tuple[CoverageReceipt, ...] | None:
        services = self._services.get(correlation_id)
        return None if services is None else tuple(receipt for service in services for receipt in service.receipts)


def _receipt_wire(receipt: CoverageReceipt) -> dict[str, object]:
    return {
        "correlation_id": receipt.correlation_id, "profile": receipt.profile.value,
        "source_address": receipt.source_address, "source_port": receipt.source_port,
        "destination_port": receipt.destination_port, "arrived_at": receipt.arrived_at.isoformat(),
        "payload_sha256": receipt.payload_sha256, "payload_length": receipt.payload_length,
        "direction": receipt.direction.value, "provenance": receipt.provenance,
        "reply_result": receipt.reply_result,
    }


def _dns_coverage_reply(lease: CoverageReceiverLease, query: bytes) -> bytes | None:
    """Validate one normal A query for `<correlation>.mercury.test`."""
    if len(query) < 17 or query[2:4] != b"\x01\x00":
        return None
    labels = (lease.correlation_id, "mercury", "test")
    encoded_name = b"".join(bytes((len(label),)) + label.encode("ascii") for label in labels) + b"\x00"
    question = encoded_name + b"\x00\x01\x00\x01"
    if query[12:] != question:
        return None
    header = query[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
    answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\x7f\x00\x00\x01"
    return header + question + answer


def _coverage_tls_server_context(receiver: ReceiverProfileConfig) -> ssl.SSLContext:
    if receiver.profile is not CoverageProfile.TLS_HANDSHAKE or receiver.tls_certificate_path is None or receiver.tls_key_path is None:
        raise PairedError("TLS coverage receiver needs configured certificate material")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(receiver.tls_certificate_path, receiver.tls_key_path)
    except (OSError, ssl.SSLError) as exc:
        raise PairedError("TLS coverage certificate configuration is unusable") from exc
    return context


def _coverage_tls_client_context(receiver: ReceiverProfileConfig) -> ssl.SSLContext:
    if receiver.profile is not CoverageProfile.TLS_HANDSHAKE or receiver.tls_ca_path is None:
        raise PairedError("TLS coverage receiver needs configured CA material")
    try:
        return ssl.create_default_context(cafile=str(receiver.tls_ca_path))
    except (OSError, ssl.SSLError) as exc:
        raise PairedError("TLS coverage CA configuration is unusable") from exc


def _dns_coverage_query(correlation: str) -> bytes:
    labels = (correlation, "mercury", "test")
    encoded = b"".join(bytes((len(label),)) + label.encode("ascii") for label in labels) + b"\x00"
    return b"\x4d\x43\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + encoded + b"\x00\x01\x00\x01"


__all__ = [
    "AuthenticatedCoverageRunner", "AuthenticatedPairedRunner", "ConfiguredCoverageExecutor", "ConfiguredPairedExecutor", "CoverageAssessmentRequest", "CoverageLeaseRegistry", "CoverageMatrixRow", "CoverageReceiverLease", "CoverageReceiverService", "DEFAULT_COVERAGE_PROFILES", "PairedEndpoint", "PairedError", "PairedLease", "PairedListenerService",
    "PairedMatrixRow", "PairedRequest", "PairedRunner", "coverage_matrix", "encode_coverage_tag", "icmp_coverage_evidence", "local_link_applicability", "paired_matrix", "run_icmp_coverage",
    "PairedPeerService", "encode_tcp_tag", "encode_udp_tag", "is_valid_udp_tag",
]
