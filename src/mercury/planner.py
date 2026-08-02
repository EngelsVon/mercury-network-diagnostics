"""Finite, immutable work previews and digest-bound confirmations."""

from __future__ import annotations

import hashlib
import ipaddress
import math
import re
from dataclasses import dataclass, field, fields, replace
from datetime import datetime, timezone
from enum import StrEnum
from typing import Iterable, Mapping

from . import MODEL_SCHEMA_VERSION
from .codec import dumps_document
from .policy import (
    PolicyError,
    ResolutionSnapshot,
    Resolver,
    ScopeGrant,
    Target,
    TargetKind,
    authorize_targets,
    normalize_targets,
    recheck_resolution,
    resolve_for_plan,
)
from .models import CoverageProfile, ProbeKind


class BudgetError(ValueError):
    """Requested work exceeds a configured or absolute ceiling."""


class ConfirmationError(PermissionError):
    """A digest-bound high-risk confirmation is missing."""


class Transport(StrEnum):
    TCP = "tcp"
    UDP = "udp"
    SCTP = "sctp"


_PRIVATE_V4 = (
    ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"), ipaddress.ip_network("127.0.0.0/8"),
)


@dataclass(frozen=True, slots=True)
class InternalMappingRequest:
    """Finite, canonical operator input for one private multi-range assessment."""

    cidrs: tuple[str, ...]
    profiles: tuple[CoverageProfile, ...]
    ports: tuple[int, ...]
    rate: int
    concurrency: int
    duration_s: int
    authorized: bool

    def __post_init__(self) -> None:
        if type(self.authorized) is not bool or not self.authorized:
            raise PolicyError("internal mapping requires explicit authorization attestation")
        if not isinstance(self.cidrs, (tuple, list)) or not self.cidrs:
            raise PolicyError("internal mapping requires private IPv4 CIDRs")
        networks: list[ipaddress.IPv4Network] = []
        for value in self.cidrs:
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise PolicyError("internal mapping CIDR is invalid") from exc
            if not isinstance(network, ipaddress.IPv4Network) or not any(network.subnet_of(allowed) for allowed in _PRIVATE_V4):
                raise PolicyError("internal mapping CIDR is outside the private scope")
            networks.append(network)
        canonical = tuple(str(item) for item in ipaddress.collapse_addresses(networks))
        object.__setattr__(self, "cidrs", canonical)
        if not isinstance(self.profiles, (tuple, list)) or not self.profiles or any(type(item) is not CoverageProfile for item in self.profiles):
            raise BudgetError("internal mapping profiles are invalid")
        if len(set(self.profiles)) != len(self.profiles):
            raise BudgetError("internal mapping profiles must be unique")
        object.__setattr__(self, "profiles", tuple(sorted(self.profiles, key=lambda item: item.value)))
        if not isinstance(self.ports, (tuple, list)) or not self.ports or any(type(port) is not int or not 1 <= port <= 65535 for port in self.ports):
            raise BudgetError("internal mapping ports are invalid")
        object.__setattr__(self, "ports", tuple(sorted(set(self.ports))))
        if type(self.rate) is not int or not 1 <= self.rate <= ABSOLUTE_CEILINGS.max_global_rate:
            raise BudgetError("internal mapping rate is invalid")
        if type(self.concurrency) is not int or not 1 <= self.concurrency <= ABSOLUTE_CEILINGS.max_concurrency:
            raise BudgetError("internal mapping concurrency is invalid")
        if type(self.duration_s) is not int or not 0 <= self.duration_s <= ABSOLUTE_CEILINGS.max_duration_s:
            raise BudgetError("internal mapping duration is invalid")


@dataclass(frozen=True, slots=True)
class BudgetLimits:
    max_hosts: int
    max_ports: int
    max_attempts: int
    max_datagrams: int
    max_application_bytes: int
    max_global_rate: int
    max_target_rate: int
    max_concurrency: int
    max_duration_s: int
    max_events: int
    max_output_bytes: int
    max_logical_packets: int = 10_000

    def __post_init__(self) -> None:
        for item in fields(self):
            value = getattr(self, item.name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise BudgetError(f"{item.name} must be a positive integer")

    def to_wire(self) -> dict[str, int]:
        return {item.name: getattr(self, item.name) for item in fields(self)}

    def assert_within(self, ceiling: "BudgetLimits") -> None:
        for item in fields(self):
            value = getattr(self, item.name)
            maximum = getattr(ceiling, item.name)
            if value > maximum:
                raise BudgetError(
                    f"{item.name}={value} exceeds absolute ceiling {maximum}"
                )
        if self.max_target_rate > self.max_global_rate:
            raise BudgetError("max_target_rate cannot exceed max_global_rate")
        if self.max_concurrency > self.max_attempts:
            raise BudgetError("max_concurrency cannot exceed max_attempts")


ABSOLUTE_CEILINGS = BudgetLimits(
    max_hosts=1_024,
    max_ports=65_535,
    max_attempts=100_000,
    max_datagrams=200_000,
    max_application_bytes=64 * 1024 * 1024,
    max_global_rate=1_000,
    max_target_rate=100,
    max_concurrency=256,
    max_duration_s=3_600,
    max_events=100_000,
    max_output_bytes=64 * 1024 * 1024,
    max_logical_packets=200_000,
)

DEFAULT_LIMITS = BudgetLimits(
    max_hosts=256,
    max_ports=64,
    max_attempts=4_096,
    max_datagrams=10_000,
    max_application_bytes=8 * 1024 * 1024,
    max_global_rate=100,
    max_target_rate=10,
    max_concurrency=64,
    max_duration_s=300,
    max_events=10_000,
    max_output_bytes=8 * 1024 * 1024,
    max_logical_packets=10_000,
)


def compile_internal_mapping(
    request: InternalMappingRequest, *, limits: BudgetLimits = DEFAULT_LIMITS,
) -> "PlanPreview":
    """Compile the finite cross-product into the existing immutable preview."""
    if type(request) is not InternalMappingRequest or type(limits) is not BudgetLimits:
        raise BudgetError("internal mapping compilation input is invalid")
    native_profiles = {
        CoverageProfile.NMAP_TCP_CONNECT, CoverageProfile.NMAP_TCP_SYN,
        CoverageProfile.NMAP_UDP, CoverageProfile.NMAP_SCTP_INIT,
    }
    if any(profile in native_profiles for profile in request.profiles) and len(request.profiles) != 1:
        raise BudgetError("a native Nmap mapping selects exactly one closed profile per task")
    networks = tuple(ipaddress.ip_network(value) for value in request.cidrs)
    host_count = sum(max(1, network.num_addresses - (2 if network.prefixlen < 31 else 0)) for network in networks)
    if host_count > limits.max_hosts:
        raise BudgetError("internal mapping host estimate exceeds the configured ceiling")
    effective = replace(
        limits, max_global_rate=request.rate, max_target_rate=min(request.rate, limits.max_target_rate),
        max_concurrency=request.concurrency, max_duration_s=request.duration_s or limits.max_duration_s,
    )
    effective.assert_within(ABSOLUTE_CEILINGS)
    mapping = {
        CoverageProfile.UDP_TAGGED: (ProbeKind.UDP_EXCHANGE, Transport.UDP),
        CoverageProfile.DNS_UDP: (ProbeKind.UDP_EXCHANGE, Transport.UDP),
        CoverageProfile.TCP_CONNECT: (ProbeKind.TCP_CONNECT, Transport.TCP),
        CoverageProfile.TCP_TAGGED: (ProbeKind.TCP_CONNECT, Transport.TCP),
        CoverageProfile.DNS_TCP: (ProbeKind.TCP_CONNECT, Transport.TCP),
        CoverageProfile.TLS_HANDSHAKE: (ProbeKind.TLS_HANDSHAKE, Transport.TCP),
        CoverageProfile.HTTP_EXCHANGE: (ProbeKind.HTTP_EXCHANGE, Transport.TCP),
        CoverageProfile.SSH_BANNER: (ProbeKind.TCP_CONNECT, Transport.TCP),
        CoverageProfile.NMAP_TCP_CONNECT: (ProbeKind.NATIVE_PORT_SCAN, Transport.TCP),
        CoverageProfile.NMAP_TCP_SYN: (ProbeKind.NATIVE_PORT_SCAN, Transport.TCP),
        CoverageProfile.NMAP_UDP: (ProbeKind.NATIVE_PORT_SCAN, Transport.UDP),
        CoverageProfile.NMAP_SCTP_INIT: (ProbeKind.NATIVE_PORT_SCAN, Transport.SCTP),
    }
    specs: list[ProbeSpec] = []
    for network in networks:
        for host in network.hosts():
            for profile in request.profiles:
                selected = mapping.get(profile)
                if selected is None:
                    continue
                kind, transport = selected
                for port in request.ports:
                    udp = transport is Transport.UDP and kind is not ProbeKind.NATIVE_PORT_SCAN
                    payload = PayloadMetadata(
                        f"mapping-{profile.value}-outbound",
                        1 if udp else 0,
                    )
                    kwargs: dict[str, object] = {}
                    if kind in {ProbeKind.TLS_HANDSHAKE, ProbeKind.HTTP_EXCHANGE}:
                        kwargs = {"server_name": str(host), "http_scheme": "https" if kind is ProbeKind.HTTP_EXCHANGE else None}
                    cost = StepCost(1, 1 if udp else 0, 1 if udp else 0, logical_packets=1)
                    specs.append(ProbeSpec(kind, str(host), address=str(host), port=port, transport=transport, payload_metadata=payload, cost=cost, **kwargs))
    if not specs:
        raise BudgetError("internal mapping selected no port-capable profiles")
    transports = tuple(sorted({spec.transport.value for spec in specs if spec.transport is not None}))
    grant = ScopeGrant(networks=networks, ports=request.ports, transports=transports, attested=True, purpose="internal mapping")
    return preview_probe_plan(specs=tuple(specs), grant=grant, profile="internal-mapping-v1", limits=effective)


def authorize_internal_mapping(
    request: InternalMappingRequest, *, limits: BudgetLimits = DEFAULT_LIMITS,
    now: datetime | None = None,
) -> "ProbePlan":
    """Bind a canonical mapping request to the normal immutable plan digest."""
    return authorize_plan(compile_internal_mapping(request, limits=limits), now=now)


@dataclass(frozen=True, slots=True)
class WorkEstimate:
    hosts: int
    ports: int
    logical_attempts: int
    generated_datagrams: int
    application_bytes: int
    concurrency: int
    worst_case_duration_s: int
    events: int
    output_bytes: int
    global_attempt_start_rate: int
    target_attempt_start_rate: int
    logical_packets: int = 0

    def __post_init__(self) -> None:
        for item in fields(self):
            value = getattr(self, item.name)
            if type(value) is not int or value < 0:
                raise BudgetError(f"{item.name} must be a non-negative integer")
        for name in (
            "hosts",
            "logical_attempts",
            "concurrency",
            "worst_case_duration_s",
            "events",
            "output_bytes",
            "global_attempt_start_rate",
            "target_attempt_start_rate",
        ):
            if getattr(self, name) < 1:
                raise BudgetError(f"{name} must be positive")

    def to_wire(self) -> dict[str, int]:
        return {item.name: getattr(self, item.name) for item in fields(self)}


@dataclass(frozen=True, slots=True)
class PayloadMetadata:
    profile: str
    length: int
    sha256: str | None = None

    def __post_init__(self) -> None:
        if (
            type(self.profile) is not str
            or not self.profile
            or len(self.profile) > 128
        ):
            raise BudgetError("payload profile is invalid")
        if type(self.length) is not int or not 0 <= self.length <= 1_400:
            raise BudgetError("payload length must be within 0..1400")
        if self.sha256 is not None and (
            type(self.sha256) is not str
            or not re.fullmatch(r"[0-9a-f]{64}", self.sha256)
        ):
            raise BudgetError("payload sha256 must be lowercase SHA-256")

    @property
    def custom(self) -> bool:
        return self.sha256 is not None

    def to_wire(self) -> dict[str, object]:
        return {
            "profile": self.profile,
            "length": self.length,
            "sha256": self.sha256,
        }

    def verify(self, payload: bytes | None) -> None:
        if self.sha256 is None:
            if payload is not None:
                raise ConfirmationError(
                    "execution bytes are not allowed for a built-in payload profile"
                )
            return
        if type(payload) is not bytes:
            raise ConfirmationError(
                "custom UDP execution requires the approved payload bytes"
            )
        if len(payload) != self.length:
            raise ConfirmationError("custom UDP payload length does not match the plan")
        actual = hashlib.sha256(payload).hexdigest()
        if actual != self.sha256:
            raise ConfirmationError("custom UDP payload hash does not match the plan")


@dataclass(frozen=True, slots=True)
class StepCost:
    logical_attempts: int
    generated_datagrams: int
    application_bytes: int
    logical_packets: int = 0
    max_observations: int = 2
    max_capabilities: int = 0
    max_conclusions: int = 0
    max_errors: int = 0
    max_output_bytes: int = 16_384

    def __post_init__(self) -> None:
        if type(self.logical_attempts) is not int or self.logical_attempts != 1:
            raise BudgetError("step logical_attempts must equal one")
        for name in (
            "generated_datagrams", "application_bytes", "logical_packets",
            "max_capabilities", "max_conclusions", "max_errors",
        ):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise BudgetError(f"step {name} must be a non-negative integer")
        for name in ("max_observations", "max_output_bytes"):
            value = getattr(self, name)
            if type(value) is not int or value < 1:
                raise BudgetError(f"step {name} must be a positive integer")

    def to_wire(self) -> dict[str, int]:
        return {
            "logical_attempts": self.logical_attempts,
            "generated_datagrams": self.generated_datagrams,
            "application_bytes": self.application_bytes,
            "logical_packets": self.logical_packets,
            "max_observations": self.max_observations,
            "max_capabilities": self.max_capabilities,
            "max_conclusions": self.max_conclusions,
            "max_errors": self.max_errors,
            "max_output_bytes": self.max_output_bytes,
        }


@dataclass(frozen=True, slots=True)
class ProbeStep:
    id: str
    probe_kind: ProbeKind
    target: str
    address: str | None
    scope_id: str | None
    port: int | None
    transport: Transport | None
    attempt: int
    source_hostname: str | None
    resolution_slot: int | None
    payload: PayloadMetadata
    cost: StepCost
    server_name: str | None = None
    http_scheme: str | None = None
    max_hops: int | None = None
    timeout_s: float = 3.0
    required: bool = True

    def __post_init__(self) -> None:
        if type(self.id) is not str or not re.fullmatch(r"step-[0-9a-f]{64}", self.id):
            raise BudgetError("step id must be a canonical SHA-256 identifier")
        if type(self.probe_kind) is not ProbeKind:
            raise BudgetError("step probe_kind must be ProbeKind")
        if type(self.target) is not str:
            raise BudgetError("step target must be text")
        canonical_target = normalize_targets((self.target,))[0]
        if canonical_target.canonical != self.target:
            raise BudgetError("step target is not canonical")
        address_target = None
        if self.address is not None:
            if type(self.address) is not str:
                raise BudgetError("step address must be text")
            address_target = normalize_targets((self.address,))[0]
            if address_target.kind is not TargetKind.ADDRESS:
                raise BudgetError("step address must be a concrete address")
            if address_target.scope_id != self.scope_id:
                raise BudgetError("step scope ID does not match its address")
        elif self.scope_id is not None:
            raise BudgetError("addressless step cannot have a scope ID")
        if type(self.attempt) is not int or not 1 <= self.attempt <= 100:
            raise BudgetError("step attempt is invalid")
        if self.source_hostname is not None:
            if (
                type(self.source_hostname) is not str
                or canonical_target.hostname != self.source_hostname
                or type(self.resolution_slot) is not int
                or self.resolution_slot < 0
            ):
                raise BudgetError("step hostname resolution metadata is invalid")
        elif self.resolution_slot is not None:
            raise BudgetError("non-hostname step cannot have a resolution slot")
        if (
            type(self.timeout_s) not in (int, float)
            or not math.isfinite(float(self.timeout_s))
            or not 0.1 <= float(self.timeout_s) <= 30.0
        ):
            raise BudgetError("step timeout_s must be finite within 0.1..30")
        object.__setattr__(self, "timeout_s", float(self.timeout_s))
        if type(self.required) is not bool:
            raise BudgetError("step required must be a boolean")
        ported = {
            ProbeKind.TCP_CONNECT, ProbeKind.UDP_EXCHANGE,
            ProbeKind.TLS_HANDSHAKE, ProbeKind.HTTP_EXCHANGE,
            ProbeKind.NATIVE_PORT_SCAN,
        }
        if self.probe_kind in ported:
            if address_target is None or type(self.port) is not int or not 1 <= self.port <= 65_535:
                raise BudgetError("ported step requires a concrete address and port")
            expected = Transport.UDP if self.probe_kind is ProbeKind.UDP_EXCHANGE else Transport.TCP
            native_transport = self.probe_kind is ProbeKind.NATIVE_PORT_SCAN and self.transport in {
                Transport.TCP, Transport.UDP, Transport.SCTP,
            }
            if self.transport is not expected and not native_transport:
                raise BudgetError("step transport does not match probe kind")
        else:
            if self.port is not None or self.transport is not None:
                raise BudgetError("non-port probe cannot claim port or transport")
        if self.probe_kind is ProbeKind.LOCAL_SNAPSHOT and self.target != "local":
            raise BudgetError("local snapshot target must be local")
        if self.probe_kind is ProbeKind.SYSTEM_DNS and canonical_target.hostname is None:
            raise BudgetError("system DNS target must be a hostname")
        if self.probe_kind in {ProbeKind.LOCAL_SNAPSHOT, ProbeKind.SYSTEM_DNS} and address_target is not None:
            raise BudgetError("addressless probe cannot carry an address")
        if self.probe_kind in {ProbeKind.NATIVE_PING, ProbeKind.NATIVE_PATH} and address_target is None:
            raise BudgetError("native probe requires a concrete address")
        if self.probe_kind in {ProbeKind.TLS_HANDSHAKE, ProbeKind.HTTP_EXCHANGE}:
            if type(self.server_name) is not str or not self.server_name or len(self.server_name) > 253:
                raise BudgetError("TLS/HTTP probe requires bounded server_name")
        elif self.server_name is not None:
            raise BudgetError("server_name is not valid for this probe kind")
        if self.probe_kind is ProbeKind.HTTP_EXCHANGE:
            if self.http_scheme not in {"http", "https"}:
                raise BudgetError("HTTP probe requires http_scheme")
        elif self.http_scheme is not None:
            raise BudgetError("http_scheme is not valid for this probe kind")
        if self.probe_kind is ProbeKind.NATIVE_PATH:
            if type(self.max_hops) is not int or not 1 <= self.max_hops <= 8:
                raise BudgetError("native path requires max_hops within 1..8")
        elif self.max_hops is not None:
            raise BudgetError("max_hops is not valid for this probe kind")
        if self.probe_kind is not ProbeKind.UDP_EXCHANGE and self.payload.length:
            raise BudgetError("only UDP exchange can carry payload metadata")
        if type(self.payload) is not PayloadMetadata:
            raise BudgetError("step payload must be PayloadMetadata")
        if type(self.cost) is not StepCost:
            raise BudgetError("step cost must be StepCost")

    def to_wire(self) -> dict[str, object]:
        return {
            "id": self.id,
            "probe_kind": self.probe_kind.value,
            "target": self.target,
            "address": self.address,
            "scope_id": self.scope_id,
            "port": self.port,
            "transport": self.transport.value if self.transport is not None else None,
            "attempt": self.attempt,
            "source_hostname": self.source_hostname,
            "resolution_slot": self.resolution_slot,
            "server_name": self.server_name,
            "http_scheme": self.http_scheme,
            "max_hops": self.max_hops,
            "timeout_s": self.timeout_s,
            "required": self.required,
            "payload_metadata": self.payload.to_wire(),
            "cost": self.cost.to_wire(),
        }


@dataclass(frozen=True, slots=True)
class ProbeSpec:
    """Small sparse compiler input; only its compiled steps may execute."""

    probe_kind: ProbeKind
    target: str
    address: str | None = None
    scope_id: str | None = None
    port: int | None = None
    transport: Transport | None = None
    attempt: int = 1
    source_hostname: str | None = None
    resolution_slot: int | None = None
    server_name: str | None = None
    http_scheme: str | None = None
    max_hops: int | None = None
    timeout_s: float = 3.0
    required: bool = True
    payload_metadata: PayloadMetadata = field(default_factory=lambda: PayloadMetadata("none-v1", 0))
    cost: StepCost = field(default_factory=lambda: StepCost(1, 0, 0))

    def __post_init__(self) -> None:
        if type(self.payload_metadata) is not PayloadMetadata or type(self.cost) is not StepCost:
            raise BudgetError("probe payload_metadata and cost must be canonical")
        _build_probe_step(self, "step-" + ("0" * 64))

    def to_wire(self) -> dict[str, object]:
        return _build_probe_step(self, "step-" + ("0" * 64)).to_wire() | {"id": None}


def _build_probe_step(spec: ProbeSpec, identifier: str) -> ProbeStep:
    return ProbeStep(
        id=identifier, probe_kind=spec.probe_kind, target=spec.target,
        address=spec.address, scope_id=spec.scope_id, port=spec.port,
        transport=spec.transport, attempt=spec.attempt,
        source_hostname=spec.source_hostname, resolution_slot=spec.resolution_slot,
        payload=spec.payload_metadata, cost=spec.cost, server_name=spec.server_name,
        http_scheme=spec.http_scheme, max_hops=spec.max_hops,
        timeout_s=spec.timeout_s, required=spec.required,
    )


@dataclass(frozen=True, slots=True)
class PreparedStep:
    step: ProbeStep
    address: str | None
    dns_changed: bool = False

    def __post_init__(self) -> None:
        if type(self.step) is not ProbeStep:
            raise ConfirmationError("prepared step must reference ProbeStep")
        if self.address is None:
            if self.step.address is not None:
                raise ConfirmationError("prepared address is required for an address-bearing step")
        else:
            address = normalize_targets((self.address,))[0]
            if address.kind is not TargetKind.ADDRESS:
                raise ConfirmationError("prepared step address must be concrete")
            if self.address != self.step.address:
                raise ConfirmationError("prepared address differs from the digest-bound step")
        if type(self.dns_changed) is not bool:
            raise ConfirmationError("dns_changed must be a boolean")


@dataclass(frozen=True, slots=True)
class PlanPreview:
    profile: str
    targets: tuple[Target, ...]
    ports: tuple[int, ...]
    transports: tuple[str, ...]
    repeats: int
    payload_bytes_per_attempt: int
    datagrams_per_udp_attempt: int
    steps: tuple[ProbeStep, ...]
    scope: ScopeGrant
    resolutions: tuple[ResolutionSnapshot, ...]
    limits: BudgetLimits
    estimate: WorkEstimate
    required_confirmations: tuple[str, ...]
    created_at: datetime
    digest: str

    def __post_init__(self) -> None:
        if type(self.profile) is not str or not self.profile or len(self.profile) > 128:
            raise BudgetError("profile name is invalid")
        for attribute, item_type, name in (
            ("targets", Target, "targets"),
            ("resolutions", ResolutionSnapshot, "resolutions"),
            ("steps", ProbeStep, "steps"),
        ):
            value = getattr(self, attribute)
            if not isinstance(value, (list, tuple)):
                raise BudgetError(f"{name} must be a sequence")
            canonical = tuple(value)
            if any(type(item) is not item_type for item in canonical):
                raise BudgetError(f"{name} contains an invalid value")
            object.__setattr__(self, attribute, canonical)
        for attribute in ("ports", "transports", "required_confirmations"):
            value = getattr(self, attribute)
            if not isinstance(value, (list, tuple)):
                raise BudgetError(f"{attribute} must be a sequence")
            object.__setattr__(self, attribute, tuple(value))
        if not self.targets:
            raise BudgetError("plan must contain at least one target")
        if not self.steps:
            raise BudgetError("plan must contain at least one finite step")
        step_ids = tuple(step.id for step in self.steps)
        if len(step_ids) != len(set(step_ids)):
            raise BudgetError("plan step IDs must be unique")
        if any(type(port) is not int or not 1 <= port <= 65_535 for port in self.ports):
            raise BudgetError("plan contains an invalid port")
        if any(
            type(transport) is not str or transport not in {"tcp", "udp", "sctp"}
            for transport in self.transports
        ):
            raise BudgetError("plan contains an invalid transport")
        if (
            type(self.repeats) is not int
            or not 1 <= self.repeats <= 100
            or type(self.payload_bytes_per_attempt) is not int
            or not 0 <= self.payload_bytes_per_attempt <= 1_400
            or type(self.datagrams_per_udp_attempt) is not int
            or not 1 <= self.datagrams_per_udp_attempt <= 100
        ):
            raise BudgetError("plan contains invalid repeat or payload values")
        if type(self.scope) is not ScopeGrant:
            raise BudgetError("plan scope must be ScopeGrant")
        if type(self.limits) is not BudgetLimits:
            raise BudgetError("plan limits must be BudgetLimits")
        if type(self.estimate) is not WorkEstimate:
            raise BudgetError("plan estimate must be WorkEstimate")
        if any(
            type(item) is not str
            or item not in {"full_tcp", "full_udp", "custom_udp"}
            for item in self.required_confirmations
        ):
            raise BudgetError("plan contains an invalid confirmation kind")
        if len(set(self.required_confirmations)) != len(
            self.required_confirmations
        ):
            raise BudgetError("plan contains duplicate confirmation kinds")
        if (
            type(self.created_at) is not datetime
            or self.created_at.tzinfo is None
            or self.created_at.utcoffset() is None
        ):
            raise BudgetError("plan created_at must be timezone-aware")
        if type(self.digest) is not str or not re.fullmatch(
            r"[0-9a-f]{64}", self.digest
        ):
            raise BudgetError("plan digest must be lowercase SHA-256")

    def to_wire(self) -> dict[str, object]:
        return {
            "schema_version": MODEL_SCHEMA_VERSION,
            "profile": self.profile,
            "targets": [target.canonical for target in self.targets],
            "ports": list(self.ports),
            "transports": list(self.transports),
            "repeats": self.repeats,
            "payload_bytes_per_attempt": self.payload_bytes_per_attempt,
            "datagrams_per_udp_attempt": self.datagrams_per_udp_attempt,
            "steps": [step.to_wire() for step in self.steps],
            "scope": self.scope.to_wire(),
            "resolutions": [
                {
                    "hostname": item.hostname,
                    "addresses": list(item.addresses),
                    "resolved_at": item.resolved_at.astimezone(timezone.utc)
                    .isoformat(timespec="seconds")
                    .replace("+00:00", "Z"),
                }
                for item in self.resolutions
            ],
            "limits": self.limits.to_wire(),
            "estimate": self.estimate.to_wire(),
            "required_confirmations": list(self.required_confirmations),
            "created_at": self.created_at.astimezone(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
            "digest": self.digest,
        }


@dataclass(frozen=True, slots=True)
class ProbePlan:
    preview: PlanPreview
    confirmations: tuple[str, ...]
    authorized_at: datetime

    def __post_init__(self) -> None:
        if type(self.preview) is not PlanPreview:
            raise ConfirmationError("probe plan preview must be PlanPreview")
        if not isinstance(self.confirmations, (list, tuple)):
            raise ConfirmationError("confirmations must be a sequence")
        confirmations = tuple(self.confirmations)
        if any(type(item) is not str for item in confirmations):
            raise ConfirmationError("confirmations must contain text")
        if len(confirmations) != len(set(confirmations)):
            raise ConfirmationError("duplicate confirmations are not allowed")
        object.__setattr__(self, "confirmations", confirmations)
        if (
            type(self.authorized_at) is not datetime
            or self.authorized_at.tzinfo is None
            or self.authorized_at.utcoffset() is None
        ):
            raise ConfirmationError("authorized_at must be timezone-aware")

    @property
    def digest(self) -> str:
        return self.preview.digest

    def to_wire(self) -> dict[str, object]:
        return {
            **self.preview.to_wire(),
            "confirmations": list(self.confirmations),
            "authorized_at": self.authorized_at.astimezone(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
        }

    def step(self, step_id: str) -> ProbeStep:
        if type(step_id) is not str:
            raise ConfirmationError("step ID must be text")
        for step in self.preview.steps:
            if step.id == step_id:
                return step
        raise ConfirmationError("step ID is not part of the authorized plan")

    def preflight_step(
        self,
        step_id: str,
        *,
        resolver: Resolver | None = None,
        now: datetime | None = None,
        payload: bytes | None = None,
    ) -> PreparedStep:
        """Return service-validated socket parameters for one finite step."""
        step = self.step(step_id)
        step.payload.verify(payload)
        self.preview.scope.assert_current(now)
        target = normalize_targets((step.target,))[0]
        if step.probe_kind is not ProbeKind.LOCAL_SNAPSHOT:
            authorize_targets((target,), self.preview.scope, now=now)
        transport = step.transport.value if step.transport is not None else None
        if not target.is_loopback and not self.preview.scope.permits_probe(
            step.probe_kind, step.port, transport
        ):
            raise ConfirmationError("step probe kind, port, or transport escaped scope")
        if step.address is None:
            return PreparedStep(step=step, address=None)
        if step.source_hostname is None:
            return PreparedStep(step=step, address=step.address)
        snapshot = next(
            (
                item
                for item in self.preview.resolutions
                if item.hostname == step.source_hostname
            ),
            None,
        )
        if snapshot is None or step.resolution_slot is None:
            raise ConfirmationError("hostname step has no resolution reservation")
        if resolver is None:
            addresses = recheck_resolution(snapshot, self.preview.scope, now=now)
        else:
            addresses = recheck_resolution(
                snapshot,
                self.preview.scope,
                resolver=resolver,
                now=now,
            )
        if len(addresses) > len(snapshot.addresses):
            raise ConfirmationError(
                "DNS rotation exceeds the reserved address-step cardinality"
            )
        if step.resolution_slot >= len(addresses):
            raise ConfirmationError(
                "DNS rotation removed the address reserved for this step"
            )
        address = addresses[step.resolution_slot]
        if address != step.address:
            raise ConfirmationError("DNS rotation changed the digest-bound address")
        return PreparedStep(
            step=step,
            address=address,
            dns_changed=addresses != snapshot.addresses,
        )

    def preflight_addresses(
        self,
        target: Target,
        *,
        resolver: Resolver | None = None,
        now: datetime | None = None,
    ) -> tuple[str, ...]:
        """Re-authorize one concrete target immediately before socket use.

        Network targets must first be expanded into individual address targets;
        this keeps the socket boundary from silently turning one budgeted unit
        into an unbounded enumeration.
        """
        if target not in self.preview.targets:
            raise ConfirmationError("target is not part of the authorized plan")
        authorize_targets((target,), self.preview.scope, now=now)
        if target.address is not None:
            return (target.canonical,)
        if target.network is not None:
            return tuple(
                dict.fromkeys(
                    step.address
                    for step in self.preview.steps
                    if step.target == target.canonical
                )
            )
        snapshot = next(
            (
                item
                for item in self.preview.resolutions
                if item.hostname == target.hostname
            ),
            None,
        )
        if snapshot is None:
            raise ConfirmationError("authorized hostname has no resolution snapshot")
        if resolver is None:
            addresses = recheck_resolution(snapshot, self.preview.scope, now=now)
        else:
            addresses = recheck_resolution(
                snapshot,
                self.preview.scope,
                resolver=resolver,
                now=now,
            )
        if len(addresses) > len(snapshot.addresses):
            raise ConfirmationError(
                "DNS rotation exceeds the reserved address-step cardinality"
            )
        return addresses


def _checked_product(values: Iterable[int], *, ceiling: int, name: str) -> int:
    result = 1
    for value in values:
        if value < 0:
            raise BudgetError(f"{name} contains a negative factor")
        if value and result > ceiling // value:
            raise BudgetError(f"{name} exceeds ceiling {ceiling}")
        result *= value
    return result


def _assert_estimate_within(estimate: WorkEstimate, limits: BudgetLimits) -> None:
    comparisons = (
        ("hosts", estimate.hosts, limits.max_hosts),
        ("ports", estimate.ports, limits.max_ports),
        ("logical_attempts", estimate.logical_attempts, limits.max_attempts),
        (
            "generated_datagrams",
            estimate.generated_datagrams,
            limits.max_datagrams,
        ),
        ("logical_packets", estimate.logical_packets, limits.max_logical_packets),
        (
            "application_bytes",
            estimate.application_bytes,
            limits.max_application_bytes,
        ),
        ("concurrency", estimate.concurrency, limits.max_concurrency),
        (
            "worst_case_duration_s",
            estimate.worst_case_duration_s,
            limits.max_duration_s,
        ),
        ("events", estimate.events, limits.max_events),
        ("output_bytes", estimate.output_bytes, limits.max_output_bytes),
    )
    for name, actual, maximum in comparisons:
        if actual > maximum:
            raise BudgetError(f"{name}={actual} exceeds configured limit {maximum}")


def _step_identifier(value: dict[str, object]) -> str:
    digest = hashlib.sha256(dumps_document(value).encode("utf-8")).hexdigest()
    return f"step-{digest}"


def _compile_steps(
    *,
    targets: tuple[Target, ...],
    resolutions: tuple[ResolutionSnapshot, ...],
    ports: tuple[int, ...],
    transports: tuple[str, ...],
    repeats: int,
    payload: PayloadMetadata,
    datagrams_per_udp_attempt: int,
    timeout_s: float = 3.0,
) -> tuple[ProbeStep, ...]:
    snapshots = {item.hostname: item for item in resolutions}
    concrete: list[tuple[Target, str, str | None, int | None]] = []
    for target in targets:
        if target.address is not None:
            concrete.append((target, target.canonical, None, None))
        elif target.network is not None:
            concrete.extend(
                (target, str(address), None, None)
                for address in target.network.hosts()
            )
        else:
            snapshot = snapshots[target.hostname]
            concrete.extend(
                (target, address, target.hostname, slot)
                for slot, address in enumerate(snapshot.addresses)
            )

    steps: list[ProbeStep] = []
    for target, address, source_hostname, resolution_slot in concrete:
        address_target = normalize_targets((address,))[0]
        for port in ports:
            for transport_text in transports:
                transport = Transport(transport_text)
                datagrams = (
                    datagrams_per_udp_attempt
                    if transport is Transport.UDP
                    else 0
                )
                application_bytes = payload.length * (
                    datagrams if transport is Transport.UDP else 1
                )
                step_payload = (
                    payload
                    if transport is Transport.UDP
                    else PayloadMetadata(profile="none-v1", length=0)
                )
                cost = StepCost(
                    logical_attempts=1,
                    generated_datagrams=datagrams,
                    application_bytes=application_bytes,
                    logical_packets=datagrams if transport is Transport.UDP else 1,
                )
                for attempt in range(1, repeats + 1):
                    identity = {
                        "probe_kind": (
                            ProbeKind.UDP_EXCHANGE.value
                            if transport is Transport.UDP
                            else ProbeKind.TCP_CONNECT.value
                        ),
                        "target": target.canonical,
                        "address": address_target.canonical,
                        "scope_id": address_target.scope_id,
                        "port": port,
                        "transport": transport.value,
                        "attempt": attempt,
                        "source_hostname": source_hostname,
                        "resolution_slot": resolution_slot,
                        "payload_metadata": step_payload.to_wire(),
                        "cost": cost.to_wire(),
                        "timeout_s": timeout_s,
                    }
                    steps.append(
                        ProbeStep(
                            id=_step_identifier(identity),
                            probe_kind=(
                                ProbeKind.UDP_EXCHANGE
                                if transport is Transport.UDP
                                else ProbeKind.TCP_CONNECT
                            ),
                            target=target.canonical,
                            address=address_target.canonical,
                            scope_id=address_target.scope_id,
                            port=port,
                            transport=transport,
                            attempt=attempt,
                            source_hostname=source_hostname,
                            resolution_slot=resolution_slot,
                            payload=step_payload,
                            cost=cost,
                            timeout_s=timeout_s,
                        )
                    )
    return tuple(steps)


def result_envelope_upper_bound(
    plan_shape: Mapping[str, object],
    projected_request: Mapping[str, object] | None = None,
) -> int:
    """Bound the mutually exclusive service-terminal result envelope.

    The value is intentionally based on canonical JSON, so adding a terminal
    field cannot silently bypass the aggregate output reservation.
    """
    request = dict(projected_request or {})
    shapes = (
        {"plan": plan_shape, "request": request, "terminal": "normal", "error": None},
        {"plan": plan_shape, "request": request, "terminal": "finalization-error", "error": "x" * 4096},
        {"plan": plan_shape, "request": request, "terminal": "output-budget", "error": "x" * 4096},
    )
    return max(len(dumps_document(shape).encode("utf-8")) for shape in shapes)


def preview_probe_plan(
    *,
    specs: Iterable[ProbeSpec],
    grant: ScopeGrant,
    profile: str = "custom-v1",
    limits: BudgetLimits = DEFAULT_LIMITS,
    now: datetime | None = None,
) -> PlanPreview:
    """Compile a finite sparse probe list without a Cartesian expansion."""
    instant = now or datetime.now(timezone.utc)
    if type(grant) is not ScopeGrant or type(limits) is not BudgetLimits:
        raise BudgetError("grant and limits must be their canonical types")
    if type(profile) is not str or not profile or len(profile) > 128:
        raise BudgetError("profile name is invalid")
    if type(instant) is not datetime or instant.tzinfo is None or instant.utcoffset() is None:
        raise BudgetError("plan time must be a timezone-aware datetime")
    limits.assert_within(ABSOLUTE_CEILINGS)
    input_specs = tuple(specs)
    if not input_specs or any(type(spec) is not ProbeSpec for spec in input_specs):
        raise BudgetError("specs must be a non-empty ProbeSpec sequence")

    compiled: list[ProbeStep] = []
    target_values: list[str] = []
    snapshots: dict[str, dict[int, str]] = {}
    for spec in input_specs:
        target = normalize_targets((spec.target,))[0]
        if spec.probe_kind is not ProbeKind.LOCAL_SNAPSHOT:
            authorize_targets((target,), grant, now=instant)
        if spec.address is not None:
            address = normalize_targets((spec.address,))[0]
            authorize_targets((address,), grant, now=instant)
        if not target.is_loopback and not grant.permits_probe(
            spec.probe_kind,
            spec.port,
            spec.transport.value if spec.transport is not None else None,
        ):
            raise ConfirmationError("probe kind, port, or transport is outside scope")
        base = _build_probe_step(spec, "step-" + ("0" * 64))
        identity = base.to_wire()
        identity.pop("id")
        step = _build_probe_step(spec, _step_identifier(identity))
        compiled.append(step)
        target_values.append(step.target)
        if step.source_hostname is not None and step.address is not None:
            assert step.resolution_slot is not None
            slots = snapshots.setdefault(step.source_hostname, {})
            if step.resolution_slot in slots and slots[step.resolution_slot] != step.address:
                raise BudgetError("hostname resolution slots disagree")
            slots[step.resolution_slot] = step.address
    steps = tuple(compiled)
    if len({step.id for step in steps}) != len(steps):
        raise BudgetError("sparse probe specs produce duplicate step identities")
    resolutions = tuple(
        ResolutionSnapshot(
            hostname=hostname,
            addresses=tuple(address for _, address in sorted(slots.items())),
            resolved_at=instant,
        )
        for hostname, slots in sorted(snapshots.items())
        if tuple(slots) == tuple(range(len(slots)))
    )
    if len(resolutions) != len(snapshots):
        raise BudgetError("hostname resolution slots must be contiguous from zero")
    targets = normalize_targets(tuple(target_values))
    ports = tuple(sorted({step.port for step in steps if step.port is not None}))
    transports = tuple(sorted({step.transport.value for step in steps if step.transport is not None}))
    attempts = len(steps)
    packets = sum(step.cost.logical_packets for step in steps)
    if any(step.probe_kind is not ProbeKind.LOCAL_SNAPSHOT and step.cost.logical_packets == 0 for step in steps):
        raise BudgetError("active probes must reserve positive logical_packets")
    generated = sum(step.cost.generated_datagrams for step in steps)
    application = sum(step.cost.application_bytes for step in steps)
    plan_shape = {"steps": [step.to_wire() for step in steps], "scope": grant.to_wire()}
    envelope = result_envelope_upper_bound(plan_shape)
    estimate = WorkEstimate(
        hosts=max(1, len({step.address or step.target for step in steps})),
        ports=len(ports), logical_attempts=attempts, generated_datagrams=generated,
        application_bytes=application, concurrency=min(limits.max_concurrency, attempts),
        worst_case_duration_s=limits.max_duration_s,
        events=sum(step.cost.max_observations for step in steps) + 5,
        output_bytes=sum(step.cost.max_output_bytes for step in steps) + envelope,
        global_attempt_start_rate=limits.max_global_rate,
        target_attempt_start_rate=limits.max_target_rate, logical_packets=packets,
    )
    _assert_estimate_within(estimate, limits)
    payloads = {step.payload for step in steps if step.probe_kind is ProbeKind.UDP_EXCHANGE}
    if len(payloads) > 1:
        raise BudgetError("legacy UDP summary cannot represent heterogeneous payloads")
    payload = next(iter(payloads), PayloadMetadata("none-v1", 0))
    repeats = max(step.attempt for step in steps)
    draft = {
        "schema_version": MODEL_SCHEMA_VERSION, "profile": profile,
        "targets": [target.canonical for target in targets], "ports": list(ports),
        "transports": list(transports), "repeats": repeats,
        "payload_bytes_per_attempt": payload.length, "datagrams_per_udp_attempt": 1,
        "steps": [step.to_wire() for step in steps], "scope": grant.to_wire(),
        "resolutions": [{"hostname": item.hostname, "addresses": list(item.addresses)} for item in resolutions],
        "limits": limits.to_wire(), "estimate": estimate.to_wire(), "required_confirmations": [],
    }
    digest = hashlib.sha256(dumps_document(draft).encode("utf-8")).hexdigest()
    return PlanPreview(
        profile=profile, targets=targets, ports=ports, transports=transports,
        repeats=repeats, payload_bytes_per_attempt=payload.length,
        datagrams_per_udp_attempt=1, steps=steps, scope=grant,
        resolutions=resolutions, limits=limits, estimate=estimate,
        required_confirmations=(), created_at=instant, digest=digest,
    )


def preview_plan(
    *,
    target_values: Iterable[str],
    ports: Iterable[int],
    transports: Iterable[str],
    grant: ScopeGrant,
    profile: str = "custom-v1",
    repeats: int = 1,
    payload_bytes_per_attempt: int = 0,
    datagrams_per_udp_attempt: int = 1,
    limits: BudgetLimits = DEFAULT_LIMITS,
    resolver: Resolver | None = None,
    now: datetime | None = None,
    custom_udp_payload: bool = False,
    udp_payload: bytes | None = None,
    payload_sha256: str | None = None,
    payload_profile: str | None = None,
    timeout_s: float = 3.0,
) -> PlanPreview:
    instant = now or datetime.now(timezone.utc)
    if (
        type(instant) is not datetime
        or instant.tzinfo is None
        or instant.utcoffset() is None
    ):
        raise BudgetError("plan time must be a timezone-aware datetime")
    if type(grant) is not ScopeGrant:
        raise BudgetError("grant must be ScopeGrant")
    if type(limits) is not BudgetLimits:
        raise BudgetError("limits must be BudgetLimits")
    if type(timeout_s) not in (int, float) or not math.isfinite(float(timeout_s)) or not 0.1 <= float(timeout_s) <= 30.0:
        raise BudgetError("timeout_s must be finite within 0.1..30")
    timeout_s = float(timeout_s)
    targets = normalize_targets(target_values)
    authorize_targets(targets, grant, now=instant)
    limits.assert_within(ABSOLUTE_CEILINGS)
    if type(profile) is not str or not profile or len(profile) > 128:
        raise BudgetError("profile name is invalid")
    if type(repeats) is not int or not 1 <= repeats <= 100:
        raise BudgetError("repeats must be within 1..100")
    if (
        type(payload_bytes_per_attempt) is not int
        or not 0 <= payload_bytes_per_attempt <= 1_400
    ):
        raise BudgetError("payload bytes per attempt must be within 0..1400")
    if (
        type(datagrams_per_udp_attempt) is not int
        or not 1 <= datagrams_per_udp_attempt <= 100
    ):
        raise BudgetError("datagrams per UDP attempt must be within 1..100")
    if type(custom_udp_payload) is not bool:
        raise BudgetError("custom_udp_payload must be a boolean")
    if udp_payload is not None and type(udp_payload) is not bytes:
        raise BudgetError("udp_payload must be bytes")
    if udp_payload is not None:
        if (
            payload_bytes_per_attempt not in (0, len(udp_payload))
            or len(udp_payload) > 1_400
        ):
            raise BudgetError("udp_payload length conflicts with the payload budget")
        payload_bytes_per_attempt = len(udp_payload)
        computed_sha256 = hashlib.sha256(udp_payload).hexdigest()
        if payload_sha256 is not None and payload_sha256 != computed_sha256:
            raise BudgetError("payload_sha256 does not match udp_payload")
        payload_sha256 = computed_sha256
        custom_udp_payload = True
    if payload_sha256 is not None:
        if type(payload_sha256) is not str or not re.fullmatch(
            r"[0-9a-f]{64}", payload_sha256
        ):
            raise BudgetError("payload_sha256 must be lowercase SHA-256")
        custom_udp_payload = True
    if custom_udp_payload and payload_sha256 is None:
        raise BudgetError("custom UDP payload requires bytes or a SHA-256 digest")
    if payload_profile is not None and (
        type(payload_profile) is not str
        or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,127}", payload_profile)
    ):
        raise BudgetError("payload_profile is invalid")
    if payload_profile is not None and custom_udp_payload:
        raise BudgetError("custom UDP payload cannot use a built-in profile")

    canonical_ports: set[int] = set()
    for port in ports:
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65_535:
            raise BudgetError(f"invalid port {port!r}")
        canonical_ports.add(port)
    if not canonical_ports:
        raise BudgetError("at least one port is required")
    port_tuple = tuple(sorted(canonical_ports))

    canonical_transports: set[str] = set()
    for value in transports:
        if type(value) is not str or value.casefold() not in {"tcp", "udp"}:
            raise BudgetError("transports must contain only tcp and/or udp")
        canonical_transports.add(value.casefold())
    transport_tuple = tuple(sorted(canonical_transports))
    if not transport_tuple or any(
        value not in {"tcp", "udp"} for value in transport_tuple
    ):
        raise BudgetError("transports must contain only tcp and/or udp")
    for target in targets:
        if target.is_loopback:
            continue
        for port in port_tuple:
            for transport in transport_tuple:
                if not grant.permits_step(port, transport):
                    raise ConfirmationError(
                        f"{transport}/{port} is outside the authorized scope"
                    )

    resolutions: list[ResolutionSnapshot] = []
    for target in targets:
        if target.kind is TargetKind.HOSTNAME:
            kwargs = {"now": instant}
            if resolver is not None:
                kwargs["resolver"] = resolver
            resolutions.append(resolve_for_plan(target, grant, **kwargs))

    host_count = 0
    resolution_by_name = {item.hostname: item for item in resolutions}
    for target in targets:
        if target.hostname is not None:
            host_count += len(resolution_by_name[target.hostname].addresses)
        else:
            host_count += target.host_count
        if host_count > ABSOLUTE_CEILINGS.max_hosts:
            raise BudgetError(
                f"hosts exceed absolute ceiling {ABSOLUTE_CEILINGS.max_hosts}"
            )

    logical_attempts = _checked_product(
        (host_count, len(port_tuple), len(transport_tuple), repeats),
        ceiling=ABSOLUTE_CEILINGS.max_attempts,
        name="logical_attempts",
    )
    if custom_udp_payload:
        effective_payload_profile = "custom-sha256-v1"
    elif payload_profile is not None:
        effective_payload_profile = payload_profile
    elif payload_bytes_per_attempt:
        effective_payload_profile = "zero-bytes-v1"
    else:
        effective_payload_profile = "none-v1"
    payload = PayloadMetadata(
        profile=effective_payload_profile,
        length=payload_bytes_per_attempt,
        sha256=payload_sha256,
    )
    steps = _compile_steps(
        targets=targets,
        resolutions=tuple(resolutions),
        ports=port_tuple,
        transports=transport_tuple,
        repeats=repeats,
        payload=payload,
        datagrams_per_udp_attempt=datagrams_per_udp_attempt,
        timeout_s=timeout_s,
    )
    if len(steps) != logical_attempts:
        raise BudgetError("compiled step count does not match reserved attempts")
    generated_datagrams = sum(step.cost.generated_datagrams for step in steps)
    logical_packets = sum(step.cost.logical_packets for step in steps)
    application_bytes = sum(step.cost.application_bytes for step in steps)
    if generated_datagrams > ABSOLUTE_CEILINGS.max_datagrams:
        raise BudgetError(
            "generated_datagrams exceeds the absolute ceiling "
            f"{ABSOLUTE_CEILINGS.max_datagrams}"
        )
    if application_bytes > ABSOLUTE_CEILINGS.max_application_bytes:
        raise BudgetError(
            "application_bytes exceeds the absolute ceiling "
            f"{ABSOLUTE_CEILINGS.max_application_bytes}"
        )
    # accepted + running + cancellation request + terminal evidence + terminal
    events = logical_attempts + 5
    # Phase 1's public Cartesian preview keeps its established compact
    # reservation; sparse Phase 2 plans use result_envelope_upper_bound().
    output_bytes = logical_attempts * 512 + 4_096
    estimate = WorkEstimate(
        hosts=host_count,
        ports=len(port_tuple),
        logical_attempts=logical_attempts,
        generated_datagrams=generated_datagrams,
        application_bytes=application_bytes,
        concurrency=min(limits.max_concurrency, logical_attempts),
        worst_case_duration_s=limits.max_duration_s,
        events=events,
        output_bytes=output_bytes,
        global_attempt_start_rate=limits.max_global_rate,
        target_attempt_start_rate=limits.max_target_rate,
        logical_packets=logical_packets,
    )
    _assert_estimate_within(estimate, limits)

    required: list[str] = []
    if len(port_tuple) == 65_535 and port_tuple[0] == 1 and port_tuple[-1] == 65_535:
        if "tcp" in transport_tuple:
            required.append("full_tcp")
        if "udp" in transport_tuple:
            required.append("full_udp")
    if custom_udp_payload:
        if "udp" not in transport_tuple:
            raise BudgetError("custom UDP payload requires udp transport")
        required.append("custom_udp")

    draft = {
        "schema_version": MODEL_SCHEMA_VERSION,
        "profile": profile,
        "targets": [target.canonical for target in targets],
        "ports": list(port_tuple),
        "transports": list(transport_tuple),
        "repeats": repeats,
        "payload_bytes_per_attempt": payload_bytes_per_attempt,
        "datagrams_per_udp_attempt": datagrams_per_udp_attempt,
        "steps": [step.to_wire() for step in steps],
        "scope": grant.to_wire(),
        "resolutions": [
            {"hostname": item.hostname, "addresses": list(item.addresses)}
            for item in resolutions
        ],
        "limits": limits.to_wire(),
        "estimate": estimate.to_wire(),
        "required_confirmations": required,
    }
    digest = hashlib.sha256(dumps_document(draft).encode("utf-8")).hexdigest()
    return PlanPreview(
        profile=profile,
        targets=targets,
        ports=port_tuple,
        transports=transport_tuple,
        repeats=repeats,
        payload_bytes_per_attempt=payload_bytes_per_attempt,
        datagrams_per_udp_attempt=datagrams_per_udp_attempt,
        steps=steps,
        scope=grant,
        resolutions=tuple(resolutions),
        limits=limits,
        estimate=estimate,
        required_confirmations=tuple(required),
        created_at=instant,
        digest=digest,
    )


def confirmation_phrase(kind: str, digest: str) -> str:
    prefix = digest[:12]
    if kind == "full_tcp":
        return f"AUTHORIZE FULL TCP {prefix}"
    if kind == "full_udp":
        return f"AUTHORIZE FULL UDP {prefix}"
    if kind == "custom_udp":
        return f"AUTHORIZE CUSTOM UDP {prefix}"
    raise ConfirmationError(f"unknown confirmation kind {kind!r}")


def validate_preview(
    preview: PlanPreview,
    *,
    now: datetime | None = None,
) -> PlanPreview:
    """Recompile a public preview and require exact canonical equality."""
    if type(preview) is not PlanPreview:
        raise ConfirmationError("preview must be PlanPreview")
    instant = now or datetime.now(timezone.utc)
    if (
        type(instant) is not datetime
        or instant.tzinfo is None
        or instant.utcoffset() is None
    ):
        raise ConfirmationError("validation time must be timezone-aware")
    if preview.created_at > instant:
        raise ConfirmationError("plan preview was created in the future")
    preview.scope.assert_current(instant)
    snapshots = {item.hostname: item for item in preview.resolutions}
    hostname_targets = {
        step.source_hostname
        for step in preview.steps
        if step.source_hostname is not None
    }
    if set(snapshots) != hostname_targets:
        raise ConfirmationError("plan resolution snapshots do not match targets")
    # Sparse plans may deliberately combine a no-payload TCP admission step
    # with a fixed built-in UDP payload.  Recompile their exact step list
    # rather than forcing the legacy Cartesian payload summary to flatten it.
    if (
        preview.profile == "internal-mapping-v1"
        or
        any(step.probe_kind not in {ProbeKind.TCP_CONNECT, ProbeKind.UDP_EXCHANGE} for step in preview.steps)
        or len({step.payload for step in preview.steps}) > 1
    ):
        try:
            rebuilt = preview_probe_plan(
                specs=tuple(
                    ProbeSpec(
                        probe_kind=step.probe_kind, target=step.target, address=step.address,
                        scope_id=step.scope_id, port=step.port, transport=step.transport,
                        attempt=step.attempt, source_hostname=step.source_hostname,
                        resolution_slot=step.resolution_slot, server_name=step.server_name,
                        http_scheme=step.http_scheme, max_hops=step.max_hops,
                        timeout_s=step.timeout_s, required=step.required,
                        payload_metadata=step.payload, cost=step.cost,
                    ) for step in preview.steps
                ),
                grant=preview.scope, profile=preview.profile, limits=preview.limits,
                now=preview.created_at,
            )
        except (BudgetError, ConfirmationError, PolicyError, ValueError) as exc:
            raise ConfirmationError("sparse plan preview failed canonical recompilation") from exc
        if rebuilt != preview:
            raise ConfirmationError("sparse plan preview does not match canonical identity")
        return rebuilt
    payloads = {step.payload for step in preview.steps}
    if len(payloads) != 1:
        raise ConfirmationError("plan steps disagree about payload metadata")
    payload = next(iter(payloads))
    step_timeouts = {step.timeout_s for step in preview.steps}
    if len(step_timeouts) != 1:
        raise ConfirmationError("legacy plan steps disagree about timeout")

    def snapshot_resolver(hostname: str) -> tuple[str, ...]:
        return snapshots[hostname].addresses

    try:
        rebuilt = preview_plan(
            target_values=tuple(target.canonical for target in preview.targets),
            ports=preview.ports,
            transports=preview.transports,
            grant=preview.scope,
            profile=preview.profile,
            repeats=preview.repeats,
            payload_bytes_per_attempt=preview.payload_bytes_per_attempt,
            datagrams_per_udp_attempt=preview.datagrams_per_udp_attempt,
            limits=preview.limits,
            resolver=snapshot_resolver,
            now=preview.created_at,
            custom_udp_payload=payload.custom,
            payload_sha256=payload.sha256,
            payload_profile=None if payload.custom else payload.profile,
            timeout_s=next(iter(step_timeouts)),
        )
    except (BudgetError, ConfirmationError, KeyError, ValueError) as exc:
        raise ConfirmationError("plan preview failed canonical recompilation") from exc
    if rebuilt != preview:
        raise ConfirmationError(
            "plan preview does not match its canonical targets, cost, or digest"
        )
    return rebuilt


def _expected_confirmation_phrases(preview: PlanPreview) -> tuple[str, ...]:
    return tuple(
        confirmation_phrase(kind, preview.digest)
        for kind in preview.required_confirmations
    )


def authorize_plan(
    preview: PlanPreview,
    *,
    confirmations: Iterable[str] = (),
    now: datetime | None = None,
) -> ProbePlan:
    validate_preview(preview, now=now)
    if not isinstance(confirmations, (list, tuple)):
        confirmations = tuple(confirmations)
    supplied = tuple(confirmations)
    if any(type(item) is not str for item in supplied):
        raise ConfirmationError("confirmations must contain text")
    expected = _expected_confirmation_phrases(preview)
    if len(supplied) != len(set(supplied)):
        raise ConfirmationError("duplicate confirmations are not allowed")
    missing = set(expected) - set(supplied)
    unexpected = set(supplied) - set(expected)
    if missing:
        raise ConfirmationError(
            "missing confirmations: " + ", ".join(sorted(missing))
        )
    if unexpected:
        raise ConfirmationError(
            "unexpected confirmations: " + ", ".join(sorted(unexpected))
        )
    instant = now or datetime.now(timezone.utc)
    preview.scope.assert_current(instant)
    return ProbePlan(
        preview=preview,
        confirmations=supplied,
        authorized_at=instant,
    )


def validate_plan(
    plan: ProbePlan,
    *,
    now: datetime | None = None,
) -> ProbePlan:
    """Revalidate an authorized plan at every service trust boundary."""
    if type(plan) is not ProbePlan:
        raise ConfirmationError("plan must be ProbePlan")
    instant = now or datetime.now(timezone.utc)
    validate_preview(plan.preview, now=instant)
    if plan.authorized_at < plan.preview.created_at:
        raise ConfirmationError("plan was authorized before it was created")
    if plan.authorized_at > instant:
        raise ConfirmationError("plan authorization is in the future")
    expected = _expected_confirmation_phrases(plan.preview)
    if set(plan.confirmations) != set(expected) or len(plan.confirmations) != len(
        expected
    ):
        raise ConfirmationError("plan confirmations do not match the digest")
    return plan


__all__ = [
    "ABSOLUTE_CEILINGS",
    "DEFAULT_LIMITS",
    "BudgetError",
    "BudgetLimits",
    "ConfirmationError",
    "InternalMappingRequest",
    "PayloadMetadata",
    "PlanPreview",
    "PreparedStep",
    "ProbePlan",
    "ProbeSpec",
    "ProbeStep",
    "StepCost",
    "Transport",
    "WorkEstimate",
    "authorize_plan",
    "authorize_internal_mapping",
    "compile_internal_mapping",
    "confirmation_phrase",
    "preview_plan",
    "preview_probe_plan",
    "result_envelope_upper_bound",
    "validate_plan",
    "validate_preview",
]
