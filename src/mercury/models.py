"""Canonical, versioned evidence models.

The protocol-specific evidence kind and its semantic disposition are separate
on purpose. A TCP refusal and UDP silence are not two spellings of failure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
import ipaddress
import math
import re
from types import MappingProxyType
from typing import Any, Mapping, TypeAlias

from . import MODEL_SCHEMA_VERSION, is_compatible_model_schema

JsonScalar: TypeAlias = str | int | float | bool | None
FrozenJson: TypeAlias = JsonScalar | tuple["FrozenJson", ...] | Mapping[str, "FrozenJson"]


class ModelError(ValueError):
    """A canonical model invariant was violated."""


class TaskState(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Direction(StrEnum):
    LOCAL = "local"
    OUTBOUND = "outbound"
    INBOUND = "inbound"
    REVERSE = "reverse"


class Disposition(StrEnum):
    POSITIVE = "positive"
    NEGATIVE = "negative"
    INCONCLUSIVE = "inconclusive"
    UNAVAILABLE = "unavailable"
    ERROR = "error"
    CANCELLED = "cancelled"


class EvidenceKind(StrEnum):
    DNS_ANSWER = "dns_answer"
    DNS_FAILURE = "dns_failure"
    TCP_CONNECTED = "tcp_connected"
    TCP_REFUSED = "tcp_refused"
    TCP_RESET = "tcp_reset"
    NETWORK_UNREACHABLE = "network_unreachable"
    HOST_UNREACHABLE = "host_unreachable"
    ICMP_UNREACHABLE = "icmp_unreachable"
    ADMIN_PROHIBITED = "admin_prohibited"
    TIMEOUT = "timeout"
    SILENT = "silent"
    UDP_APPLICATION_REPLY = "udp_application_reply"
    PEER_OBSERVED_ARRIVAL = "peer_observed_arrival"
    TLS_HANDSHAKE = "tls_handshake"
    HTTP_RESPONSE = "http_response"
    LOCAL_FACT = "local_fact"
    UNSUPPORTED = "unsupported"
    PERMISSION_DENIED = "permission_denied"
    EXECUTION_ERROR = "execution_error"
    CANCELLED = "cancelled"
    TLS_VERIFICATION_FAILED = "tls_verification_failed"
    TLS_HANDSHAKE_FAILED = "tls_handshake_failed"
    NATIVE_PING_REPLY = "native_ping_reply"
    NATIVE_PING_FAILURE = "native_ping_failure"
    PATH_HOP = "path_hop"
    PATH_HOP_UNANSWERED = "path_hop_unanswered"
    PATH_COMPLETE = "path_complete"
    PATH_INCOMPLETE = "path_incomplete"
    PEER_ACKNOWLEDGEMENT = "peer_acknowledgement"
    DNS_QUERY = "dns_query"
    SSH_BANNER = "ssh_banner"
    NEIGHBOUR_FACT = "neighbour_fact"


class CoverageProfile(StrEnum):
    """Closed protocol profiles available to a paired coverage assessment."""

    TCP_CONNECT = "tcp_connect"
    TCP_TAGGED = "tcp_tagged"
    UDP_TAGGED = "udp_tagged"
    DNS_UDP = "dns_udp"
    DNS_TCP = "dns_tcp"
    ICMP_ECHO = "icmp_echo"
    TLS_HANDSHAKE = "tls_handshake"
    HTTP_EXCHANGE = "http_exchange"
    SSH_BANNER = "ssh_banner"
    ARP = "arp"
    IPV6_ND = "ipv6_nd"
    NMAP_TCP_CONNECT = "nmap_tcp_connect"
    NMAP_TCP_SYN = "nmap_tcp_syn"
    NMAP_UDP = "nmap_udp"
    NMAP_SCTP_INIT = "nmap_sctp_init"


class CoverageOutcome(StrEnum):
    """The finite, non-universal terminal labels for a coverage matrix row."""

    CANDIDATE_CARRIER = "candidate_carrier"
    DIRECT_NEGATIVE = "direct_negative"
    INCONCLUSIVE = "inconclusive_silence_or_timeout"
    UNSUPPORTED = "unsupported"
    PERMISSION_DENIED = "permission_denied"
    SKIPPED = "skipped"
    NOT_APPLICABLE = "not_applicable"


class ProbeKind(StrEnum):
    """Finite probe identities admitted by the Phase 2 execution boundary."""

    LOCAL_SNAPSHOT = "local_snapshot"
    SYSTEM_DNS = "system_dns"
    TCP_CONNECT = "tcp_connect"
    UDP_EXCHANGE = "udp_exchange"
    TLS_HANDSHAKE = "tls_handshake"
    HTTP_EXCHANGE = "http_exchange"
    NATIVE_PING = "native_ping"
    NATIVE_PATH = "native_path"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class CapabilityState(StrEnum):
    AVAILABLE = "available"
    UNSUPPORTED = "unsupported"
    PERMISSION_DENIED = "permission_denied"
    MISSING_TOOL = "missing_tool"
    ERROR = "error"


class Health(StrEnum):
    HEALTHY = "healthy"
    PARTIAL = "partial"
    FAILED = "failed"
    UNKNOWN = "unknown"


_KIND_DISPOSITIONS: dict[EvidenceKind, frozenset[Disposition]] = {
    EvidenceKind.DNS_ANSWER: frozenset({Disposition.POSITIVE}),
    EvidenceKind.DNS_FAILURE: frozenset(
        {Disposition.NEGATIVE, Disposition.INCONCLUSIVE, Disposition.ERROR}
    ),
    EvidenceKind.TCP_CONNECTED: frozenset({Disposition.POSITIVE}),
    EvidenceKind.TCP_REFUSED: frozenset({Disposition.NEGATIVE}),
    EvidenceKind.TCP_RESET: frozenset({Disposition.NEGATIVE}),
    EvidenceKind.NETWORK_UNREACHABLE: frozenset({Disposition.NEGATIVE}),
    EvidenceKind.HOST_UNREACHABLE: frozenset({Disposition.NEGATIVE}),
    EvidenceKind.ICMP_UNREACHABLE: frozenset({Disposition.NEGATIVE}),
    EvidenceKind.ADMIN_PROHIBITED: frozenset({Disposition.NEGATIVE}),
    EvidenceKind.TIMEOUT: frozenset({Disposition.INCONCLUSIVE}),
    EvidenceKind.SILENT: frozenset({Disposition.INCONCLUSIVE}),
    EvidenceKind.UDP_APPLICATION_REPLY: frozenset({Disposition.POSITIVE}),
    EvidenceKind.PEER_OBSERVED_ARRIVAL: frozenset({Disposition.POSITIVE}),
    EvidenceKind.TLS_HANDSHAKE: frozenset({Disposition.POSITIVE}),
    EvidenceKind.HTTP_RESPONSE: frozenset({Disposition.POSITIVE, Disposition.NEGATIVE}),
    EvidenceKind.LOCAL_FACT: frozenset({Disposition.POSITIVE}),
    EvidenceKind.UNSUPPORTED: frozenset({Disposition.UNAVAILABLE}),
    EvidenceKind.PERMISSION_DENIED: frozenset({Disposition.UNAVAILABLE}),
    EvidenceKind.EXECUTION_ERROR: frozenset({Disposition.ERROR}),
    EvidenceKind.CANCELLED: frozenset({Disposition.CANCELLED}),
    EvidenceKind.TLS_VERIFICATION_FAILED: frozenset({Disposition.NEGATIVE}),
    EvidenceKind.TLS_HANDSHAKE_FAILED: frozenset(
        {Disposition.NEGATIVE, Disposition.ERROR}
    ),
    EvidenceKind.NATIVE_PING_REPLY: frozenset({Disposition.POSITIVE}),
    EvidenceKind.NATIVE_PING_FAILURE: frozenset(
        {Disposition.NEGATIVE, Disposition.ERROR}
    ),
    EvidenceKind.PATH_HOP: frozenset({Disposition.POSITIVE}),
    EvidenceKind.PATH_HOP_UNANSWERED: frozenset({Disposition.INCONCLUSIVE}),
    EvidenceKind.PATH_COMPLETE: frozenset({Disposition.POSITIVE}),
    EvidenceKind.PATH_INCOMPLETE: frozenset({Disposition.INCONCLUSIVE}),
    EvidenceKind.PEER_ACKNOWLEDGEMENT: frozenset({Disposition.POSITIVE}),
    EvidenceKind.DNS_QUERY: frozenset({Disposition.POSITIVE}),
    EvidenceKind.SSH_BANNER: frozenset({Disposition.POSITIVE}),
    EvidenceKind.NEIGHBOUR_FACT: frozenset({Disposition.POSITIVE}),
}

_SCHEMA_10_EVIDENCE_KINDS = frozenset(
    kind for kind in EvidenceKind if kind.value not in {
        "tls_verification_failed", "tls_handshake_failed", "native_ping_reply",
        "native_ping_failure", "path_hop", "path_hop_unanswered",
        "path_complete", "path_incomplete", "peer_acknowledgement", "dns_query",
        "ssh_banner", "neighbour_fact",
    }
)
_SCHEMA_EVIDENCE_KINDS: Mapping[str, frozenset[EvidenceKind]] = MappingProxyType({
    "1.0": _SCHEMA_10_EVIDENCE_KINDS,
    "1.1": frozenset(EvidenceKind),
})


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _validate_datetime(value: datetime, name: str) -> None:
    if type(value) is not datetime or value.tzinfo is None:
        raise ModelError(f"{name} must be timezone-aware")
    if value.utcoffset() is None:
        raise ModelError(f"{name} must have a UTC offset")


def _validate_text(value: str, name: str, *, maximum: int = 4096) -> None:
    if type(value) is not str or not value.strip():
        raise ModelError(f"{name} must be a non-empty string")
    if len(value) > maximum:
        raise ModelError(f"{name} exceeds {maximum} characters")
    if "\x00" in value:
        raise ModelError(f"{name} contains NUL")


def freeze_json(value: Any, *, _depth: int = 0) -> FrozenJson:
    """Validate and deeply freeze JSON-compatible data."""
    if _depth > 32:
        raise ModelError("JSON value is nested too deeply")
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ModelError("non-finite numbers are not valid")
        return value
    if isinstance(value, Mapping):
        frozen: dict[str, FrozenJson] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ModelError("JSON object keys must be strings")
            if len(key) > 256:
                raise ModelError("JSON object key is too long")
            frozen[key] = freeze_json(item, _depth=_depth + 1)
        return MappingProxyType(frozen)
    if isinstance(value, (list, tuple)):
        return tuple(freeze_json(item, _depth=_depth + 1) for item in value)
    raise ModelError(f"unsupported JSON value type: {type(value).__name__}")


@dataclass(frozen=True, slots=True)
class Capability:
    name: str
    state: CapabilityState
    source: str
    detail: str = ""

    def __post_init__(self) -> None:
        _validate_text(self.name, "capability name", maximum=128)
        if type(self.state) is not CapabilityState:
            raise ModelError("capability state must be CapabilityState")
        _validate_text(self.source, "capability source", maximum=256)
        if type(self.detail) is not str:
            raise ModelError("capability detail must be text")
        if len(self.detail) > 4096:
            raise ModelError("capability detail exceeds 4096 characters")
        if "\x00" in self.detail:
            raise ModelError("capability detail contains NUL")


@dataclass(frozen=True, slots=True)
class CoverageReceipt:
    """Bounded peer-side arrival evidence; it never retains a raw test tag."""

    correlation_id: str
    profile: CoverageProfile
    source_address: str
    source_port: int
    destination_port: int
    arrived_at: datetime
    payload_sha256: str
    payload_length: int
    direction: Direction
    provenance: str
    reply_result: str

    def __post_init__(self) -> None:
        _validate_text(self.correlation_id, "receipt correlation", maximum=64)
        if not self.correlation_id.isascii():
            raise ModelError("receipt correlation must be ASCII")
        if type(self.profile) is not CoverageProfile:
            raise ModelError("receipt profile must be CoverageProfile")
        try:
            source = str(ipaddress.ip_address(self.source_address))
        except ValueError as exc:
            raise ModelError("receipt source address is invalid") from exc
        object.__setattr__(self, "source_address", source)
        for value, name in (
            (self.source_port, "receipt source port"),
            (self.destination_port, "receipt destination port"),
        ):
            if type(value) is not int or not 0 <= value <= 65_535:
                raise ModelError(f"{name} is invalid")
        _validate_datetime(self.arrived_at, "receipt arrival time")
        if not isinstance(self.payload_sha256, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", self.payload_sha256):
            raise ModelError("receipt payload digest is invalid")
        if type(self.payload_length) is not int or not 0 <= self.payload_length <= 65_535:
            raise ModelError("receipt payload length is invalid")
        if type(self.direction) is not Direction:
            raise ModelError("receipt direction must be Direction")
        _validate_text(self.provenance, "receipt provenance", maximum=256)
        _validate_text(self.reply_result, "receipt reply result", maximum=128)


@dataclass(frozen=True, slots=True)
class Observation:
    id: str
    probe: str
    disposition: Disposition
    evidence_kind: EvidenceKind
    direction: Direction
    target: str
    started_at: datetime
    ended_at: datetime
    duration_ms: float
    attempt: int = 1
    source: str = "mercury"
    detail: Mapping[str, FrozenJson] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for value, name, maximum in (
            (self.id, "observation id", 128),
            (self.probe, "probe", 128),
            (self.target, "target", 1024),
            (self.source, "source", 256),
        ):
            _validate_text(value, name, maximum=maximum)
        for value, expected, name in (
            (self.disposition, Disposition, "observation disposition"),
            (self.evidence_kind, EvidenceKind, "observation evidence_kind"),
            (self.direction, Direction, "observation direction"),
        ):
            if type(value) is not expected:
                raise ModelError(f"{name} must be {expected.__name__}")
        _validate_datetime(self.started_at, "observation started_at")
        _validate_datetime(self.ended_at, "observation ended_at")
        if self.ended_at < self.started_at:
            raise ModelError("observation ended_at precedes started_at")
        if type(self.duration_ms) not in (int, float):
            raise ModelError("observation duration_ms must be a number")
        duration = float(self.duration_ms)
        if not math.isfinite(duration) or not 0 <= duration <= 86_400_000:
            raise ModelError("observation duration_ms is out of range")
        object.__setattr__(self, "duration_ms", duration)
        if type(self.attempt) is not int or not 1 <= self.attempt <= 100_000:
            raise ModelError("observation attempt is out of range")
        allowed = _KIND_DISPOSITIONS[self.evidence_kind]
        if self.disposition not in allowed:
            raise ModelError(
                f"{self.evidence_kind.value} cannot have "
                f"{self.disposition.value} disposition"
            )
        frozen = freeze_json(self.detail)
        if not isinstance(frozen, Mapping):
            raise ModelError("observation detail must be an object")
        object.__setattr__(self, "detail", frozen)


@dataclass(frozen=True, slots=True)
class Conclusion:
    id: str
    title: str
    summary: str
    health: Health
    confidence: Confidence
    observation_ids: tuple[str, ...]
    alternatives: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _validate_text(self.id, "conclusion id", maximum=128)
        _validate_text(self.title, "conclusion title", maximum=512)
        _validate_text(self.summary, "conclusion summary", maximum=8192)
        if type(self.health) is not Health:
            raise ModelError("conclusion health must be Health")
        if type(self.confidence) is not Confidence:
            raise ModelError("conclusion confidence must be Confidence")
        for attribute, name in (
            ("observation_ids", "observation reference"),
            ("alternatives", "alternative"),
            ("limitations", "limitation"),
        ):
            value = getattr(self, attribute)
            if not isinstance(value, (list, tuple)):
                raise ModelError(f"{name} values must be a sequence")
            object.__setattr__(self, attribute, tuple(value))
        if not self.observation_ids:
            raise ModelError("conclusion must cite at least one observation")
        if len(set(self.observation_ids)) != len(self.observation_ids):
            raise ModelError("conclusion contains duplicate observation IDs")
        for collection, name in (
            (self.observation_ids, "observation reference"),
            (self.alternatives, "alternative"),
            (self.limitations, "limitation"),
        ):
            if len(collection) > 256:
                raise ModelError(f"too many {name} values")
            for value in collection:
                _validate_text(value, name, maximum=4096)


@dataclass(frozen=True, slots=True)
class Progress:
    admitted: int
    completed: int
    total: int

    def __post_init__(self) -> None:
        if any(
            type(value) is not int
            for value in (self.admitted, self.completed, self.total)
        ):
            raise ModelError("progress counters must be integers")
        if min(self.admitted, self.completed, self.total) < 0:
            raise ModelError("progress counters cannot be negative")
        if self.completed > self.admitted or self.admitted > self.total:
            raise ModelError("progress must satisfy completed <= admitted <= total")

    @property
    def fraction(self) -> float:
        return 1.0 if self.total == 0 else self.completed / self.total


@dataclass(frozen=True, slots=True)
class EffectiveConfig:
    profile: str
    targets: tuple[str, ...]
    authorized: bool
    policy_digest: str
    budget: Mapping[str, FrozenJson]
    warnings: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _validate_text(self.profile, "profile", maximum=128)
        _validate_text(self.policy_digest, "policy_digest", maximum=256)
        if type(self.authorized) is not bool:
            raise ModelError("effective authorized must be a boolean")
        if not isinstance(self.targets, (list, tuple)):
            raise ModelError("effective targets must be a sequence")
        if not isinstance(self.warnings, (list, tuple)):
            raise ModelError("effective warnings must be a sequence")
        object.__setattr__(self, "targets", tuple(self.targets))
        object.__setattr__(self, "warnings", tuple(self.warnings))
        if len(self.targets) > 4096:
            raise ModelError("too many effective targets")
        for target in self.targets:
            _validate_text(target, "effective target", maximum=1024)
        frozen = freeze_json(self.budget)
        if not isinstance(frozen, Mapping):
            raise ModelError("budget must be an object")
        object.__setattr__(self, "budget", frozen)
        for warning in self.warnings:
            _validate_text(warning, "warning", maximum=4096)


@dataclass(frozen=True, slots=True)
class TaskResult:
    task_id: str
    task_kind: str
    direction: Direction
    target: str
    state: TaskState
    started_at: datetime
    ended_at: datetime
    requested_config: Mapping[str, FrozenJson]
    effective_config: EffectiveConfig
    progress: Progress
    observations: tuple[Observation, ...] = ()
    conclusions: tuple[Conclusion, ...] = ()
    capabilities: tuple[Capability, ...] = ()
    errors: tuple[str, ...] = ()
    schema_version: str = MODEL_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for value, name, maximum in (
            (self.task_id, "task_id", 128),
            (self.task_kind, "task_kind", 128),
            (self.target, "target", 1024),
            (self.schema_version, "schema_version", 32),
        ):
            _validate_text(value, name, maximum=maximum)
        if type(self.direction) is not Direction:
            raise ModelError("task direction must be Direction")
        if type(self.state) is not TaskState:
            raise ModelError("task state must be TaskState")
        if type(self.effective_config) is not EffectiveConfig:
            raise ModelError("effective_config must be EffectiveConfig")
        if type(self.progress) is not Progress:
            raise ModelError("progress must be Progress")
        for attribute, item_type, maximum in (
            ("observations", Observation, 100_000),
            ("conclusions", Conclusion, 100_000),
            ("capabilities", Capability, 4096),
        ):
            value = getattr(self, attribute)
            if not isinstance(value, (list, tuple)):
                raise ModelError(f"{attribute} must be a sequence")
            canonical = tuple(value)
            if len(canonical) > maximum:
                raise ModelError(f"too many {attribute}")
            if any(type(item) is not item_type for item in canonical):
                raise ModelError(
                    f"{attribute} must contain only {item_type.__name__} values"
                )
            object.__setattr__(self, attribute, canonical)
        if not isinstance(self.errors, (list, tuple)):
            raise ModelError("errors must be a sequence")
        object.__setattr__(self, "errors", tuple(self.errors))
        if not is_compatible_model_schema(self.schema_version):
            raise ModelError(
                f"unsupported schema version {self.schema_version!r}; "
                "supported versions are '1.0', '1.1'"
            )
        allowed_kinds = _SCHEMA_EVIDENCE_KINDS[self.schema_version]
        for observation in self.observations:
            if observation.evidence_kind not in allowed_kinds:
                raise ModelError(
                    f"{observation.evidence_kind.value} is not valid for schema "
                    f"{self.schema_version}"
                )
        if self.state in (TaskState.PENDING, TaskState.RUNNING):
            raise ModelError("TaskResult must have a terminal state")
        _validate_datetime(self.started_at, "task started_at")
        _validate_datetime(self.ended_at, "task ended_at")
        if self.ended_at < self.started_at:
            raise ModelError("task ended_at precedes started_at")
        requested = freeze_json(self.requested_config)
        if not isinstance(requested, Mapping):
            raise ModelError("requested_config must be an object")
        object.__setattr__(self, "requested_config", requested)
        observation_ids = [item.id for item in self.observations]
        if len(observation_ids) != len(set(observation_ids)):
            raise ModelError("observation IDs must be unique")
        known = set(observation_ids)
        conclusion_ids: set[str] = set()
        for conclusion in self.conclusions:
            if conclusion.id in conclusion_ids:
                raise ModelError("conclusion IDs must be unique")
            conclusion_ids.add(conclusion.id)
            missing = set(conclusion.observation_ids) - known
            if missing:
                raise ModelError(
                    "conclusion cites unknown observations: "
                    + ", ".join(sorted(missing))
                )
        if len(self.errors) > 256:
            raise ModelError("too many task errors")
        for error in self.errors:
            _validate_text(error, "task error", maximum=4096)


def disposition_for(kind: EvidenceKind) -> Disposition:
    """Return the only/default disposition for a deterministic evidence kind."""
    values = _KIND_DISPOSITIONS[kind]
    if len(values) != 1:
        raise ModelError(f"{kind.value} permits multiple dispositions")
    return next(iter(values))


__all__ = [
    "Capability",
    "CapabilityState",
    "Conclusion",
    "Confidence",
    "CoverageOutcome",
    "CoverageProfile",
    "CoverageReceipt",
    "Direction",
    "Disposition",
    "EffectiveConfig",
    "EvidenceKind",
    "FrozenJson",
    "Health",
    "ModelError",
    "Observation",
    "Progress",
    "ProbeKind",
    "TaskResult",
    "TaskState",
    "disposition_for",
    "freeze_json",
    "utc_now",
]
