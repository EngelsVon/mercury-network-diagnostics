"""Strict, operator-provisioned peer-control transport primitives.

The control channel deliberately has no discovery or probe API.  It admits a
configured peer only; later paired plans supply the closed handlers.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import ssl
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol


MAX_FRAME_BYTES = 16 * 1024
MAX_CONTROL_OPERATION_SECONDS = 10.0
PEER_PROTOCOL_VERSION = 1
_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


class PeerError(RuntimeError):
    """A sanitized peer-control failure."""


class PeerConfigurationError(PeerError):
    """Operator-provisioned peer configuration is incomplete or unsafe."""


class _Server(Protocol):
    def close(self) -> None: ...

    async def wait_closed(self) -> None: ...


ServerFactory = Callable[..., Awaitable[_Server]]
WallClock = Callable[[], datetime]
MonotonicClock = Callable[[], float]


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
    unsafe_development: bool = False
    server_hostname: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.identity, str) or not _IDENTITY.fullmatch(self.identity):
            raise PeerConfigurationError("peer identity is invalid")
        try:
            bound = ipaddress.ip_address(self.bind_host)
        except ValueError as exc:
            raise PeerConfigurationError("peer bind host must be an IP address") from exc
        if isinstance(self.control_port, bool) or not 0 <= self.control_port <= 65535:
            raise PeerConfigurationError("peer control port is invalid")
        if not self.peer_addresses:
            raise PeerConfigurationError("peer configuration requires fixed peer addresses")
        for address in self.peer_addresses:
            try:
                ipaddress.ip_address(address)
            except ValueError as exc:
                raise PeerConfigurationError("peer address must be an IP address") from exc
        for pin in self.peer_pins:
            if not isinstance(pin, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", pin):
                raise PeerConfigurationError("peer certificate pin is invalid")
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
        return ipaddress.ip_address(self.bind_host).is_loopback

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


@dataclass(frozen=True, slots=True)
class PeerAudit:
    """Categorical audit data safe to expose or persist."""

    identity: str
    operation: str
    occurred_at: datetime
    outcome: str


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


class PeerAgent:
    """Application-owned lifecycle for a single configured peer-control listener."""

    def __init__(
        self,
        config: PeerConfig,
        *,
        server_factory: ServerFactory = asyncio.start_server,
        wall_clock: WallClock = _utc_now,
        monotonic_clock: MonotonicClock | None = None,
    ) -> None:
        if type(config) is not PeerConfig:
            raise PeerConfigurationError("peer agent requires PeerConfig")
        self.config = config
        self._server_factory = server_factory
        self._wall_clock = wall_clock
        self._monotonic_clock = monotonic_clock or __import__("time").monotonic
        self._server: _Server | None = None
        self._audit: list[PeerAudit] = []

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
            self._reject_before_protocol,
            host=self.config.bind_host,
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

    async def _reject_before_protocol(
        self, _reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Task 1 closes authenticated test connections; Task 2 adds dispatch."""
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
    "PeerConfig",
    "PeerConfigurationError",
    "PeerError",
    "create_server_ssl_context",
]
