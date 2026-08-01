"""Finite, source-bound paired listener lease contracts.

The data plane is deliberately not a remote probe API: a lease may name only
the numeric endpoint already approved by the locally revalidated plan.
"""

from __future__ import annotations

import asyncio
import ipaddress
import struct
from dataclasses import dataclass
from datetime import datetime

from .planner import ProbePlan


class PairedError(RuntimeError):
    """A pair-only lease was rejected before listener I/O."""


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
    address: str
    tcp_port: int
    udp_port: int

    def __post_init__(self) -> None:
        if not isinstance(self.identity, str) or not self.identity or len(self.identity) > 64:
            raise PairedError("paired identity is invalid")
        object.__setattr__(self, "address", _address(self.address, "paired address"))
        object.__setattr__(self, "tcp_port", _port(self.tcp_port, "paired TCP port"))
        object.__setattr__(self, "udp_port", _port(self.udp_port, "paired UDP port"))
        if self.tcp_port == self.udp_port:
            raise PairedError("paired TCP and UDP ports must be distinct")


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
        if not isinstance(self.correlation_id, str) or not self.correlation_id or len(self.correlation_id) > 64:
            raise PairedError("paired correlation is invalid")
        source = _address(self.authenticated_source, "authenticated peer source")
        if source != self.endpoint.address:
            raise PairedError("authenticated source does not match configured endpoint")
        object.__setattr__(self, "authenticated_source", source)
        if not isinstance(self.expires_at, datetime) or self.expires_at.tzinfo is None:
            raise PairedError("paired lease expiry must be timezone-aware")
        if not isinstance(self.udp_nonce, str) or not 8 <= len(self.udp_nonce) <= 128:
            raise PairedError("paired UDP nonce is invalid")
        if type(self.udp_tag) is not bytes or not 1 <= len(self.udp_tag) <= 64:
            raise PairedError("paired UDP tag is invalid")
        selected = {(step.port, step.transport.value if step.transport else None) for step in self.plan.preview.steps}
        if (self.endpoint.tcp_port, "tcp") not in selected or (self.endpoint.udp_port, "udp") not in selected:
            raise PairedError("paired listener port is outside immutable plan")

    def assert_current(self, now: datetime) -> None:
        if now.tzinfo is None or now >= self.expires_at:
            raise PairedError("paired lease has expired")


class PairedListenerService:
    """Owns the two finite listeners for one accepted lease.

    This is intentionally a lifecycle primitive: later task integration records
    admitted evidence, while this class never accepts a caller-selected target
    or port.
    """

    def __init__(self, lease: PairedLease, *, now: callable) -> None:
        self.lease = lease
        self._now = now
        self._tcp: asyncio.AbstractServer | None = None
        self._udp: asyncio.DatagramTransport | None = None

    async def start(self) -> None:
        self.lease.assert_current(self._now())
        try:
            self._tcp = await asyncio.start_server(
                self._reject_tcp,
                host=self.lease.endpoint.address,
                port=self.lease.endpoint.tcp_port,
            )
            transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: _LeaseDatagram(self.lease, self._now),
                local_addr=(self.lease.endpoint.address, self.lease.endpoint.udp_port),
            )
            self._udp = transport
        except (OSError, asyncio.CancelledError):
            await self.stop()
            raise

    async def stop(self) -> None:
        if self._udp is not None:
            self._udp.close()
            self._udp = None
        if self._tcp is not None:
            server, self._tcp = self._tcp, None
            server.close()
            await server.wait_closed()

    async def _reject_tcp(self, _reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        # No unauthenticated/application-selected TCP exchange is admitted here.
        writer.close()
        await writer.wait_closed()


class _LeaseDatagram(asyncio.DatagramProtocol):
    def __init__(self, lease: PairedLease, now: callable) -> None:
        self.lease, self._now = lease, now

    def datagram_received(self, _data: bytes, address: tuple[str, int]) -> None:
        # The future evidence layer will validate fixed plan/nonce/tag bytes.
        # Even before then, never answer a source other than the paired address.
        try:
            self.lease.assert_current(self._now())
        except PairedError:
            return
        if address[0] != self.lease.authenticated_source:
            return


def encode_udp_tag(lease: PairedLease) -> bytes:
    """Return the sole built-in UDP validation payload (never user supplied)."""
    plan = lease.plan.digest[:16].encode("ascii")
    nonce = lease.udp_nonce.encode("ascii")
    if len(nonce) > 128:
        raise PairedError("paired UDP nonce is invalid")
    payload = b"MRP1" + plan + struct.pack("!B", len(nonce)) + nonce + lease.udp_tag
    if len(payload) > 1_400:
        raise PairedError("paired UDP payload exceeds 1400 bytes")
    return payload


__all__ = ["PairedEndpoint", "PairedError", "PairedLease", "PairedListenerService", "encode_udp_tag"]
