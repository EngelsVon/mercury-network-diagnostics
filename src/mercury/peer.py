"""Strict, operator-provisioned peer-control transport primitives.

The control channel deliberately has no discovery or probe API.  It admits a
configured peer only; later paired plans supply the closed handlers.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import math
import re
import secrets
import ssl
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Mapping, Protocol

from .codec import CodecError, result_from_wire
from .models import CoverageProfile
from .policy import PolicyError, TargetKind, parse_target


MAX_FRAME_BYTES = 16 * 1024
MAX_CONTROL_OPERATION_SECONDS = 10.0
PEER_PROTOCOL_VERSION = 1
_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_CORRELATION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_NONCE = re.compile(r"[A-Za-z0-9_-]{8,128}\Z")
_OPERATIONS = frozenset(("capabilities", "submit", "read-result", "cancel"))
_MAX_CLOCK_SKEW = timedelta(seconds=30)
_MAX_FRAME_LIFETIME = timedelta(minutes=10)


class PeerError(RuntimeError):
    """A sanitized peer-control failure."""


class PeerConfigurationError(PeerError):
    """Operator-provisioned peer configuration is incomplete or unsafe."""


class PeerProtocolError(PeerError):
    """An untrusted peer-control frame was rejected before dispatch."""


_RECEIVER_CAPABLE_PROFILES = frozenset({
    CoverageProfile.TCP_TAGGED, CoverageProfile.UDP_TAGGED,
    CoverageProfile.DNS_UDP, CoverageProfile.DNS_TCP,
    CoverageProfile.TLS_HANDSHAKE, CoverageProfile.HTTP_EXCHANGE,
    CoverageProfile.SSH_BANNER,
})


class _Server(Protocol):
    def close(self) -> None: ...

    async def wait_closed(self) -> None: ...


ServerFactory = Callable[..., Awaitable[_Server]]
WallClock = Callable[[], datetime]
MonotonicClock = Callable[[], float]


@dataclass(frozen=True, slots=True)
class ReceiverProfileConfig:
    """One administrator-provisioned local receiver; never a peer-frame input."""

    profile: CoverageProfile
    bind_host: str
    port: int
    timeout_s: float
    tls_certificate_path: Path | None = None
    tls_key_path: Path | None = None
    tls_ca_path: Path | None = None
    tls_server_name: str | None = None

    def __post_init__(self) -> None:
        if type(self.profile) is not CoverageProfile or self.profile not in _RECEIVER_CAPABLE_PROFILES:
            raise PeerConfigurationError("receiver profile is not receiver-capable")
        try:
            target = parse_target(self.bind_host)
        except PolicyError as exc:
            raise PeerConfigurationError("receiver bind host must be a private IP address") from exc
        if target.kind is not TargetKind.ADDRESS:
            raise PeerConfigurationError("receiver bind host must be an IP address")
        if isinstance(self.port, bool) or type(self.port) is not int or not 1 <= self.port <= 65535:
            raise PeerConfigurationError("receiver port is invalid")
        if type(self.timeout_s) not in (int, float) or not math.isfinite(float(self.timeout_s)) or not 0.1 <= float(self.timeout_s) <= 30.0:
            raise PeerConfigurationError("receiver timeout is invalid")
        object.__setattr__(self, "bind_host", target.canonical)
        object.__setattr__(self, "timeout_s", float(self.timeout_s))
        tls_values = (
            self.tls_certificate_path, self.tls_key_path,
            self.tls_ca_path, self.tls_server_name,
        )
        if self.profile is CoverageProfile.TLS_HANDSHAKE:
            if any(value is not None for value in tls_values) and not all(value is not None for value in tls_values):
                raise PeerConfigurationError("TLS receiver needs configured certificate, key, CA, and server name")
            if all(value is not None for value in tls_values) and any(not isinstance(value, Path) for value in tls_values[:3]):
                raise PeerConfigurationError("TLS receiver paths are invalid")
            if all(value is not None for value in tls_values) and (not isinstance(self.tls_server_name, str) or not self.tls_server_name or len(self.tls_server_name) > 255):
                raise PeerConfigurationError("TLS receiver server name is invalid")
        elif any(value is not None for value in tls_values):
            raise PeerConfigurationError("non-TLS receiver cannot define TLS material")


@dataclass(frozen=True, slots=True)
class PeerConfig:
    """Paths and fixed identities needed to create one peer-control listener."""

    identity: str
    bind_host: str
    control_port: int
    certificate_path: Path | None
    key_path: Path | None
    ca_path: Path | None
    token_path: Path | None
    peer_pins: tuple[str, ...]
    peer_addresses: tuple[str, ...]
    control_bind_host: str | None = None
    control_peer_addresses: tuple[str, ...] = ()
    unsafe_development: bool = False
    server_hostname: str | None = None
    paired_tcp_port: int | None = None
    paired_udp_port: int | None = None
    paired_timeout_s: float | None = None
    receiver_profiles: tuple[ReceiverProfileConfig, ...] = ()
    coverage_profiles: tuple[CoverageProfile, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.identity, str) or not _IDENTITY.fullmatch(self.identity):
            raise PeerConfigurationError("peer identity is invalid")
        try:
            bind_target = parse_target(self.bind_host)
        except PolicyError as exc:
            raise PeerConfigurationError("peer bind host must be a private IP address") from exc
        if bind_target.kind is not TargetKind.ADDRESS or bind_target.address is None:
            raise PeerConfigurationError("peer bind host must be an IP address")
        bound = bind_target.address
        control_bind_value = self.bind_host if self.control_bind_host is None else self.control_bind_host
        try:
            control_bind_target = parse_target(control_bind_value)
        except PolicyError as exc:
            raise PeerConfigurationError("peer control bind host must be a private IP address") from exc
        if control_bind_target.kind is not TargetKind.ADDRESS or control_bind_target.address is None:
            raise PeerConfigurationError("peer control bind host must be an IP address")
        if isinstance(self.control_port, bool) or not 0 <= self.control_port <= 65535:
            raise PeerConfigurationError("peer control port is invalid")
        if not self.peer_addresses:
            raise PeerConfigurationError("peer configuration requires fixed peer addresses")
        canonical_peers: set[str] = set()
        for address in self.peer_addresses:
            try:
                target = parse_target(address)
            except PolicyError as exc:
                raise PeerConfigurationError("peer address must be a private IP address") from exc
            if target.kind is not TargetKind.ADDRESS:
                raise PeerConfigurationError("peer address must be an IP address")
            canonical_peers.add(target.canonical)
        object.__setattr__(self, "bind_host", bind_target.canonical)
        object.__setattr__(self, "peer_addresses", tuple(sorted(canonical_peers)))
        control_values = self.control_peer_addresses or tuple(sorted(canonical_peers))
        canonical_controls: set[str] = set()
        for address in control_values:
            try:
                target = parse_target(address)
            except PolicyError as exc:
                raise PeerConfigurationError("peer control address must be a private IP address") from exc
            if target.kind is not TargetKind.ADDRESS:
                raise PeerConfigurationError("peer control address must be an IP address")
            canonical_controls.add(target.canonical)
        if not canonical_controls:
            raise PeerConfigurationError("peer configuration requires fixed control addresses")
        object.__setattr__(self, "control_bind_host", control_bind_target.canonical)
        object.__setattr__(self, "control_peer_addresses", tuple(sorted(canonical_controls)))
        if not isinstance(self.receiver_profiles, (tuple, list)) or any(
            type(item) is not ReceiverProfileConfig for item in self.receiver_profiles
        ):
            raise PeerConfigurationError("receiver profile table is invalid")
        receivers = tuple(self.receiver_profiles)
        if len(receivers) > 16 or len({item.profile for item in receivers}) != len(receivers):
            raise PeerConfigurationError("receiver profile table is invalid")
        if len({(item.bind_host, item.port) for item in receivers}) != len(receivers):
            raise PeerConfigurationError("receiver ports must not overlap")
        if any(
            item.profile is CoverageProfile.TLS_HANDSHAKE and item.tls_certificate_path is None
            for item in receivers
        ):
            raise PeerConfigurationError("TLS receiver needs configured certificate material")
        if not isinstance(self.coverage_profiles, (tuple, list)) or any(
            type(item) is not CoverageProfile for item in self.coverage_profiles
        ):
            raise PeerConfigurationError("coverage profile table is invalid")
        enabled = tuple(self.coverage_profiles)
        if not enabled:
            enabled = tuple(item.profile for item in receivers)
            if CoverageProfile.TCP_TAGGED in enabled:
                enabled = (*enabled, CoverageProfile.TCP_CONNECT)
        if len(enabled) > 16 or len(set(enabled)) != len(enabled):
            raise PeerConfigurationError("coverage profile table is invalid")
        allowed = _RECEIVER_CAPABLE_PROFILES | {
            CoverageProfile.TCP_CONNECT, CoverageProfile.ICMP_ECHO,
            CoverageProfile.ARP, CoverageProfile.IPV6_ND,
        }
        if any(item not in allowed for item in enabled):
            raise PeerConfigurationError("coverage profile is unavailable")
        if any(
            item not in {CoverageProfile.TCP_CONNECT, CoverageProfile.ICMP_ECHO, CoverageProfile.ARP, CoverageProfile.IPV6_ND} and item not in {receiver.profile for receiver in receivers}
            for item in enabled
        ):
            raise PeerConfigurationError("coverage profile lacks a configured receiver")
        if CoverageProfile.TCP_CONNECT in enabled and CoverageProfile.TCP_TAGGED not in {receiver.profile for receiver in receivers}:
            raise PeerConfigurationError("TCP connect coverage needs a configured TCP receiver")
        object.__setattr__(self, "coverage_profiles", tuple(sorted(enabled, key=lambda item: item.value)))
        object.__setattr__(self, "receiver_profiles", tuple(sorted(receivers, key=lambda item: item.profile.value)))
        for pin in self.peer_pins:
            if not isinstance(pin, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", pin):
                raise PeerConfigurationError("peer certificate pin is invalid")
        paired = (self.paired_tcp_port, self.paired_udp_port, self.paired_timeout_s)
        if any(value is not None for value in paired):
            if any(value is None for value in paired):
                raise PeerConfigurationError("paired configuration is incomplete")
            if len(self.peer_addresses) != 1:
                raise PeerConfigurationError("paired configuration requires one fixed peer address")
            if any(isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535
                   for port in (self.paired_tcp_port, self.paired_udp_port)):
                raise PeerConfigurationError("paired ports are invalid")
            if self.paired_tcp_port == self.paired_udp_port:
                raise PeerConfigurationError("paired TCP and UDP ports must differ")
            if (type(self.paired_timeout_s) not in (int, float)
                    or not math.isfinite(float(self.paired_timeout_s))
                    or not 0.1 <= float(self.paired_timeout_s) <= 30.0):
                raise PeerConfigurationError("paired timeout is invalid")
        if self.unsafe_development:
            if not bound.is_loopback:
                raise PeerConfigurationError("unsafe development is loopback-only")
            return
        if not bound.is_loopback:
            missing = [
                name
                for name, value in (
                    ("certificate", self.certificate_path),
                    ("key", self.key_path),
                    ("CA", self.ca_path),
                    ("token", self.token_path),
                )
                if value is None
            ]
            if missing:
                raise PeerConfigurationError(
                    "non-loopback peer configuration requires " + ", ".join(missing)
                )
            if not self.peer_pins:
                raise PeerConfigurationError("non-loopback peer configuration requires a pin")

    @property
    def bind_is_loopback(self) -> bool:
        target = parse_target(self.bind_host)
        assert target.address is not None
        return target.address.is_loopback

    @property
    def paired_enabled(self) -> bool:
        return self.paired_tcp_port is not None

    @property
    def coverage_enabled(self) -> bool:
        return bool(self.coverage_profiles)

    def validate_for_start(self) -> None:
        """Check all trusted files before constructing a listener."""
        if self.unsafe_development:
            return
        for name, value in (
            ("certificate", self.certificate_path),
            ("key", self.key_path),
            ("CA", self.ca_path),
            ("token", self.token_path),
        ):
            if value is None or not value.is_file():
                raise PeerConfigurationError(f"peer {name} path is unavailable")
        if not self.peer_pins:
            raise PeerConfigurationError("peer configuration requires a pin")


def load_peer_config(path: Path, *, unsafe_development: bool = False) -> PeerConfig:
    """Load one strict operator-provisioned peer configuration file.

    Configuration holds only paths to secret material.  It is intentionally
    decoded at the application boundary and never copied to a task result.
    """
    if not isinstance(path, Path) or not path.is_file():
        raise PeerConfigurationError("peer configuration path is unavailable")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PeerConfigurationError("peer configuration is invalid") from exc
    if not isinstance(value, dict):
        raise PeerConfigurationError("peer configuration must be an object")
    required = {"identity", "bind_host", "control_port", "peer_pins", "peer_addresses"}
    optional = {
        "certificate_path", "key_path", "ca_path", "token_path", "server_hostname",
        "paired", "receivers", "coverage_profiles", "control_bind_host", "control_peer_addresses",
    }
    if set(value) - required - optional or required - set(value):
        raise PeerConfigurationError("peer configuration fields are invalid")
    def path_value(name: str) -> Path | None:
        item = value.get(name)
        if item is None:
            return None
        if not isinstance(item, str) or not item or len(item) > 4096:
            raise PeerConfigurationError("peer configuration path is invalid")
        return (path.parent / item).resolve() if not Path(item).is_absolute() else Path(item)
    pins, addresses, controls = value["peer_pins"], value["peer_addresses"], value.get("control_peer_addresses", [])
    if not isinstance(pins, list) or not isinstance(addresses, list) or not isinstance(controls, list):
        raise PeerConfigurationError("peer configuration peer lists are invalid")
    paired = value.get("paired")
    if paired is not None and (
        not isinstance(paired, dict)
        or set(paired) != {"tcp_port", "udp_port", "timeout_s"}
    ):
        raise PeerConfigurationError("paired configuration fields are invalid")
    receivers = value.get("receivers", [])
    if not isinstance(receivers, list) or len(receivers) > 16:
        raise PeerConfigurationError("receiver configuration fields are invalid")
    receiver_profiles: list[ReceiverProfileConfig] = []
    for receiver in receivers:
        if not isinstance(receiver, dict) or set(receiver) - {"profile", "bind_host", "port", "timeout_s", "tls"} or {
            "profile", "bind_host", "port", "timeout_s"
        } - set(receiver):
            raise PeerConfigurationError("receiver configuration fields are invalid")
        try:
            profile = CoverageProfile(receiver["profile"])
        except (TypeError, ValueError) as exc:
            raise PeerConfigurationError("receiver profile is invalid") from exc
        tls = receiver.get("tls")
        if profile is CoverageProfile.TLS_HANDSHAKE:
            if not isinstance(tls, dict) or set(tls) != {"certificate_path", "key_path", "ca_path", "server_name"}:
                raise PeerConfigurationError("TLS receiver configuration fields are invalid")
            def tls_path(name: str) -> Path:
                item = tls[name]
                if not isinstance(item, str) or not item or len(item) > 4096:
                    raise PeerConfigurationError("TLS receiver path is invalid")
                return (path.parent / item).resolve() if not Path(item).is_absolute() else Path(item)
            receiver_profiles.append(ReceiverProfileConfig(
                profile=profile, bind_host=receiver["bind_host"], port=receiver["port"], timeout_s=receiver["timeout_s"],
                tls_certificate_path=tls_path("certificate_path"), tls_key_path=tls_path("key_path"),
                tls_ca_path=tls_path("ca_path"), tls_server_name=tls["server_name"],
            ))
        elif tls is not None:
            raise PeerConfigurationError("non-TLS receiver cannot define TLS material")
        else:
            receiver_profiles.append(ReceiverProfileConfig(
                profile=profile, bind_host=receiver["bind_host"], port=receiver["port"], timeout_s=receiver["timeout_s"],
            ))
    coverage_profiles = value.get("coverage_profiles", [])
    if not isinstance(coverage_profiles, list):
        raise PeerConfigurationError("coverage profile table is invalid")
    try:
        configured_coverage_profiles = tuple(CoverageProfile(item) for item in coverage_profiles)
    except (TypeError, ValueError) as exc:
        raise PeerConfigurationError("coverage profile is invalid") from exc
    return PeerConfig(
        identity=value["identity"], bind_host=value["bind_host"], control_port=value["control_port"],
        certificate_path=path_value("certificate_path"), key_path=path_value("key_path"),
        ca_path=path_value("ca_path"), token_path=path_value("token_path"),
        peer_pins=tuple(pins), peer_addresses=tuple(addresses),
        control_bind_host=value.get("control_bind_host"), control_peer_addresses=tuple(controls),
        unsafe_development=unsafe_development, server_hostname=value.get("server_hostname"),
        paired_tcp_port=None if paired is None else paired["tcp_port"],
        paired_udp_port=None if paired is None else paired["udp_port"],
        paired_timeout_s=None if paired is None else paired["timeout_s"],
        receiver_profiles=tuple(receiver_profiles), coverage_profiles=configured_coverage_profiles,
    )


@dataclass(frozen=True, slots=True)
class PeerAudit:
    """Categorical audit data safe to expose or persist."""

    identity: str
    operation: str
    occurred_at: datetime
    outcome: str


def _time_to_wire(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _time_from_wire(value: object, field: str) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise PeerProtocolError(f"peer {field} is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError as exc:
        raise PeerProtocolError(f"peer {field} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise PeerProtocolError(f"peer {field} is invalid")
    return parsed


def _validate_json(value: object, *, depth: int = 0) -> None:
    if depth > 8:
        raise PeerProtocolError("peer frame nesting exceeds the limit")
    if isinstance(value, str):
        if len(value) > 4096:
            raise PeerProtocolError("peer frame string exceeds the limit")
    elif isinstance(value, list):
        if len(value) > 32:
            raise PeerProtocolError("peer frame array exceeds the limit")
        for item in value:
            _validate_json(item, depth=depth + 1)
    elif isinstance(value, dict):
        if len(value) > 16:
            raise PeerProtocolError("peer frame object exceeds the limit")
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 64:
                raise PeerProtocolError("peer frame key is invalid")
            _validate_json(item, depth=depth + 1)
    elif value is not None and type(value) not in (bool, int, float):
        raise PeerProtocolError("peer frame JSON value is invalid")
    elif isinstance(value, float) and not math.isfinite(value):
        raise PeerProtocolError("peer frame number is invalid")


def _object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PeerProtocolError("peer frame contains duplicate fields")
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    raise PeerProtocolError(f"peer frame has invalid numeric value {value!r}")


def _loads_frame(payload: bytes) -> dict[str, object]:
    try:
        decoded = payload.decode("utf-8")
        value = json.loads(
            decoded,
            object_pairs_hook=_object_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, PeerProtocolError) as exc:
        raise PeerProtocolError("peer frame is malformed") from exc
    if not isinstance(value, dict):
        raise PeerProtocolError("peer frame must be an object")
    body = value.get("body")
    if value.get("operation") == "read-result" and isinstance(body, dict) and set(body) == {"result"}:
        # The canonical result has its own bounded codec validation below.
        shallow = dict(value)
        shallow["body"] = {"result": None}
        _validate_json(shallow)
    else:
        _validate_json(value)
    return value


def _expect_exact_fields(value: Mapping[str, object], *, required: tuple[str, ...]) -> None:
    missing = set(required) - value.keys()
    unknown = value.keys() - set(required)
    if missing or unknown:
        raise PeerProtocolError("peer frame fields are invalid")


@dataclass(frozen=True, slots=True)
class PeerFrame:
    """Immutable, bounded control data excluding the independent token."""

    version: int
    operation: str
    correlation_id: str
    identity: str
    issued_at: datetime
    expires_at: datetime
    nonce: str
    body: Mapping[str, object]

    def __post_init__(self) -> None:
        if type(self.version) is not int or self.version != PEER_PROTOCOL_VERSION:
            raise PeerProtocolError("peer protocol version is unsupported")
        if self.operation not in _OPERATIONS:
            raise PeerProtocolError("peer operation is unsupported")
        for value, pattern, label in (
            (self.correlation_id, _CORRELATION, "correlation"),
            (self.identity, _IDENTITY, "identity"),
            (self.nonce, _NONCE, "nonce"),
        ):
            if not isinstance(value, str) or not pattern.fullmatch(value):
                raise PeerProtocolError(f"peer {label} is invalid")
        for value, label in ((self.issued_at, "issued time"), (self.expires_at, "expiry")):
            if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
                raise PeerProtocolError(f"peer {label} is invalid")
        if self.expires_at <= self.issued_at or self.expires_at - self.issued_at > _MAX_FRAME_LIFETIME:
            raise PeerProtocolError("peer frame lifetime is invalid")
        if not isinstance(self.body, Mapping):
            raise PeerProtocolError("peer frame body must be an object")
        body = dict(self.body)
        # A read-result response contains a canonical TaskResult document.  It
        # is validated by the model codec below, rather than by the much
        # smaller control-frame object/nesting limits.  No request body may
        # carry a target, port, payload, scope, or runner.
        if not (self.operation == "read-result" and set(body) == {"result"}):
            _validate_json(body)
        if self.operation == "capabilities":
            if set(body) - {"capabilities"}:
                raise PeerProtocolError("peer capability body is invalid")
            capabilities = body.get("capabilities", ())
            if not isinstance(capabilities, (list, tuple)) or len(capabilities) > 16:
                raise PeerProtocolError("peer capability body is invalid")
            if any(not isinstance(item, str) or len(item) > 64 for item in capabilities):
                raise PeerProtocolError("peer capability body is invalid")
        elif self.operation == "submit":
            if body not in (
                {"manifest": "paired-v1", "role": "A-to-B"},
                {"manifest": "paired-v1", "role": "B-to-A"},
                {"manifest": "coverage-v2", "role": "A-to-B"},
                {"manifest": "coverage-v2", "role": "B-to-A"},
                {"status": "accepted"},
            ):
                raise PeerProtocolError("peer paired submit body is invalid")
        elif self.operation == "read-result":
            if not body:
                pass
            elif set(body) == {"status"} and body["status"] == "pending":
                pass
            elif set(body) == {"result"}:
                try:
                    result_from_wire(body["result"])
                except (CodecError, TypeError, ValueError) as exc:
                    raise PeerProtocolError("peer paired result body is invalid") from exc
            elif set(body) == {"receipts"} and isinstance(body["receipts"], list):
                _validate_json(body)
            else:
                raise PeerProtocolError("peer paired result body is invalid")
        elif self.operation == "cancel":
            if body not in ({}, {"status": "cancelled"}):
                raise PeerProtocolError("peer cancel body is invalid")
        object.__setattr__(self, "body", MappingProxyType(body))

    def to_wire(self) -> dict[str, object]:
        return {
            "version": self.version,
            "operation": self.operation,
            "correlation_id": self.correlation_id,
            "identity": self.identity,
            "issued_at": _time_to_wire(self.issued_at),
            "expires_at": _time_to_wire(self.expires_at),
            "nonce": self.nonce,
            "body": dict(self.body),
        }

    def to_json(self) -> bytes:
        return json.dumps(self.to_wire(), separators=(",", ":"), allow_nan=False).encode("utf-8")

    @classmethod
    def from_wire(cls, value: object) -> "PeerFrame":
        if not isinstance(value, dict):
            raise PeerProtocolError("peer frame must be an object")
        fields = (
            "version", "operation", "correlation_id", "identity", "issued_at", "expires_at", "nonce", "body"
        )
        _expect_exact_fields(value, required=fields)
        return cls(
            version=value["version"],  # type: ignore[arg-type]
            operation=value["operation"],  # type: ignore[arg-type]
            correlation_id=value["correlation_id"],  # type: ignore[arg-type]
            identity=value["identity"],  # type: ignore[arg-type]
            issued_at=_time_from_wire(value["issued_at"], "issued time"),
            expires_at=_time_from_wire(value["expires_at"], "expiry"),
            nonce=value["nonce"],  # type: ignore[arg-type]
            body=value["body"],  # type: ignore[arg-type]
        )

    @classmethod
    def from_json(cls, payload: bytes) -> "PeerFrame":
        return cls.from_wire(_loads_frame(payload))


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def create_server_ssl_context(config: PeerConfig) -> ssl.SSLContext:
    """Create the mTLS-only server context after configuration validation."""
    config.validate_for_start()
    if config.unsafe_development:
        raise PeerConfigurationError("unsafe development does not use a TLS context")
    assert config.certificate_path is not None
    assert config.key_path is not None
    assert config.ca_path is not None
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(config.certificate_path), str(config.key_path))
    context.load_verify_locations(cafile=str(config.ca_path))
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def create_client_ssl_context(
    config: PeerConfig,
    *,
    certificate_path: Path | None = None,
    key_path: Path | None = None,
) -> ssl.SSLContext:
    """Create a client context with CA verification and a configured certificate."""
    config.validate_for_start()
    if config.unsafe_development:
        raise PeerConfigurationError("unsafe development does not use a TLS context")
    assert config.ca_path is not None
    certificate = certificate_path or config.certificate_path
    key = key_path or config.key_path
    if certificate is None or key is None:
        raise PeerConfigurationError("peer client certificate path is unavailable")
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(config.ca_path))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(certificate), str(key))
    context.check_hostname = config.server_hostname is not None
    return context


def _token_from_path(path: Path | None) -> str:
    if path is None:
        raise PeerConfigurationError("peer token path is unavailable")
    try:
        token = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise PeerConfigurationError("peer token path is unavailable") from exc
    if not token or len(token) > 4096:
        raise PeerConfigurationError("peer token value is invalid")
    return token


def _pin_from_der(certificate: bytes) -> str:
    return "sha256:" + hashlib.sha256(certificate).hexdigest()


async def _read_length_prefixed(reader: asyncio.StreamReader) -> bytes:
    try:
        header = await asyncio.wait_for(reader.readexactly(4), MAX_CONTROL_OPERATION_SECONDS)
        size = int.from_bytes(header, "big")
        if not 0 < size <= MAX_FRAME_BYTES:
            raise PeerProtocolError("peer frame length is invalid")
        return await asyncio.wait_for(reader.readexactly(size), MAX_CONTROL_OPERATION_SECONDS)
    except (asyncio.IncompleteReadError, asyncio.TimeoutError) as exc:
        raise PeerProtocolError("peer frame is truncated") from exc


def _encode_authenticated(frame: PeerFrame, token: str) -> bytes:
    document = frame.to_wire()
    document["token"] = token
    return json.dumps(document, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _decode_authenticated(payload: bytes) -> tuple[PeerFrame, str]:
    document = _loads_frame(payload)
    fields = (
        "version", "operation", "correlation_id", "identity", "issued_at", "expires_at", "nonce", "body", "token"
    )
    _expect_exact_fields(document, required=fields)
    token = document.pop("token")
    if not isinstance(token, str) or not token or len(token) > 4096:
        raise PeerProtocolError("peer token is invalid")
    return PeerFrame.from_wire(document), token


class _NonceCache:
    def __init__(self, capacity: int = 1_024) -> None:
        self._capacity = capacity
        self._entries: dict[str, dict[str, datetime]] = {}

    def admit(self, identity: str, nonce: str, expiry: datetime, now: datetime) -> None:
        for owner, entries in tuple(self._entries.items()):
            for value, expires_at in tuple(entries.items()):
                if expires_at <= now:
                    del entries[value]
            if not entries:
                del self._entries[owner]
        entries = self._entries.setdefault(identity, {})
        if nonce in entries:
            raise PeerProtocolError("peer frame was replayed")
        if len(entries) >= self._capacity:
            raise PeerProtocolError("peer replay cache is full")
        entries[nonce] = expiry


class PeerAgent:
    """Application-owned lifecycle for a single configured peer-control listener."""

    def __init__(
        self,
        config: PeerConfig,
        *,
        server_factory: ServerFactory = asyncio.start_server,
        wall_clock: WallClock = _utc_now,
        monotonic_clock: MonotonicClock | None = None,
        handlers: Mapping[str, Callable[[PeerFrame], Awaitable[Mapping[str, object]] | Mapping[str, object]]] | None = None,
    ) -> None:
        if type(config) is not PeerConfig:
            raise PeerConfigurationError("peer agent requires PeerConfig")
        self.config = config
        self._server_factory = server_factory
        self._wall_clock = wall_clock
        self._monotonic_clock = monotonic_clock or __import__("time").monotonic
        self._server: _Server | None = None
        self._audit: list[PeerAudit] = []
        supplied = dict(handlers or {})
        if set(supplied) - _OPERATIONS:
            raise PeerConfigurationError("peer handler operation is invalid")
        self._handlers = supplied
        self._nonces = _NonceCache()
        self._correlations: dict[str, str] = {}

    @property
    def audit(self) -> tuple[PeerAudit, ...]:
        return tuple(self._audit)

    @property
    def server(self) -> _Server | None:
        return self._server

    async def start(self) -> None:
        if self._server is not None:
            raise PeerError("peer agent is already running")
        self.config.validate_for_start()
        ssl_context: ssl.SSLContext | None = None
        if self.config.unsafe_development:
            self._audit.append(
                PeerAudit(
                    identity=self.config.identity,
                    operation="startup",
                    occurred_at=self._wall_clock(),
                    outcome="unsafe-development-loopback",
                )
            )
        else:
            ssl_context = create_server_ssl_context(self.config)
        self._server = await self._server_factory(
            self._handle_connection,
            host=self.config.control_bind_host,
            port=self.config.control_port,
            ssl=ssl_context,
            limit=MAX_FRAME_BYTES + 4,
        )

    async def stop(self) -> None:
        if self._server is None:
            return
        server, self._server = self._server, None
        server.close()
        await server.wait_closed()

    def _audit_outcome(self, operation: str, outcome: str) -> None:
        self._audit.append(PeerAudit(
            identity=self.config.identity,
            operation=operation if operation in _OPERATIONS else "control",
            occurred_at=self._wall_clock(),
            outcome=outcome,
        ))

    def _authenticate(self, frame: PeerFrame, token: str, writer: asyncio.StreamWriter) -> None:
        now = self._wall_clock()
        if frame.issued_at > now + _MAX_CLOCK_SKEW or frame.expires_at <= now:
            raise PeerProtocolError("peer frame is expired")
        if frame.identity != self.config.identity:
            raise PeerProtocolError("peer identity is not configured")
        if self.config.unsafe_development:
            if self.config.token_path is not None and not hmac.compare_digest(
                token, _token_from_path(self.config.token_path)
            ):
                raise PeerProtocolError("peer token was rejected")
            return
        ssl_object = writer.get_extra_info("ssl_object")
        certificate = ssl_object.getpeercert(binary_form=True) if ssl_object is not None else None
        if not isinstance(certificate, bytes) or not certificate:
            raise PeerProtocolError("peer certificate is unavailable")
        pin = _pin_from_der(certificate)
        if not any(hmac.compare_digest(pin, expected) for expected in self.config.peer_pins):
            raise PeerProtocolError("peer certificate pin is not configured")
        if not hmac.compare_digest(token, _token_from_path(self.config.token_path)):
            raise PeerProtocolError("peer token was rejected")

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        operation = "control"
        try:
            frame, token = _decode_authenticated(await _read_length_prefixed(reader))
            operation = frame.operation
            self._authenticate(frame, token, writer)
            self._nonces.admit(frame.identity, frame.nonce, frame.expires_at, self._wall_clock())
            if frame.operation == "submit":
                self._correlations[frame.correlation_id] = frame.identity
            elif frame.operation in {"read-result", "cancel"}:
                if self._correlations.get(frame.correlation_id) != frame.identity:
                    raise PeerProtocolError("peer correlation is not owned by caller")
            handler = self._handlers.get(frame.operation)
            body: Mapping[str, object] = {}
            if handler is not None:
                returned = handler(frame)
                body = await returned if hasattr(returned, "__await__") else returned
                if not isinstance(body, Mapping):
                    raise PeerError("peer handler returned an invalid response")
            response = PeerFrame(
                version=PEER_PROTOCOL_VERSION,
                operation=frame.operation,
                correlation_id=frame.correlation_id,
                identity=self.config.identity,
                issued_at=self._wall_clock(),
                expires_at=self._wall_clock() + timedelta(minutes=1),
                nonce=secrets.token_urlsafe(16),
                body=body,
            )
            encoded = response.to_json()
            writer.write(len(encoded).to_bytes(4, "big") + encoded)
            await writer.drain()
            self._audit_outcome(operation, "accepted")
        except PeerProtocolError:
            self._audit_outcome(operation, "rejected-protocol")
        except PeerConfigurationError:
            self._audit_outcome(operation, "rejected-configuration")
        except (PeerError, OSError, ssl.SSLError):
            self._audit_outcome(operation, "rejected-transport")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass


class PeerClient:
    """Small client for the same strict peer-control framing contract."""

    def __init__(
        self,
        config: PeerConfig,
        *,
        certificate_path: Path | None = None,
        key_path: Path | None = None,
        open_connection: Callable[..., Awaitable[tuple[asyncio.StreamReader, asyncio.StreamWriter]]] = asyncio.open_connection,
    ) -> None:
        self.config = config
        self._certificate_path = certificate_path
        self._key_path = key_path
        self._open_connection = open_connection

    async def request(self, frame: PeerFrame) -> PeerFrame:
        if type(frame) is not PeerFrame:
            raise PeerProtocolError("peer client requires PeerFrame")
        context = None if self.config.unsafe_development else create_client_ssl_context(
            self.config, certificate_path=self._certificate_path, key_path=self._key_path,
        )
        host = self.config.control_peer_addresses[0]
        try:
            reader, writer = await self._open_connection(
                host,
                self.config.control_port,
                ssl=context,
                server_hostname=self.config.server_hostname if context is not None else None,
            )
        except (OSError, ssl.SSLError) as exc:
            raise PeerProtocolError("peer TLS connection failed") from exc
        try:
            if context is not None:
                ssl_object = writer.get_extra_info("ssl_object")
                certificate = ssl_object.getpeercert(binary_form=True) if ssl_object is not None else None
                pin = _pin_from_der(certificate) if isinstance(certificate, bytes) else ""
                if not any(hmac.compare_digest(pin, expected) for expected in self.config.peer_pins):
                    raise PeerProtocolError("peer certificate pin is not configured")
            token = _token_from_path(self.config.token_path)
            payload = _encode_authenticated(frame, token)
            writer.write(len(payload).to_bytes(4, "big") + payload)
            await writer.drain()
            return PeerFrame.from_json(await _read_length_prefixed(reader))
        except (PeerError, OSError, ssl.SSLError) as exc:
            if isinstance(exc, PeerError):
                raise
            raise PeerProtocolError("peer request failed") from exc
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass


__all__ = [
    "MAX_CONTROL_OPERATION_SECONDS",
    "MAX_FRAME_BYTES",
    "PEER_PROTOCOL_VERSION",
    "PeerAgent",
    "PeerAudit",
    "PeerClient",
    "PeerConfig",
    "PeerConfigurationError",
    "PeerError",
    "PeerFrame",
    "PeerProtocolError",
    "ReceiverProfileConfig",
    "create_client_ssl_context",
    "create_server_ssl_context",
    "load_peer_config",
]
