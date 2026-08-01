"""Bounded protocol probes that consume only admitted numeric steps.

The task core owns admission, rechecks and budgets.  This module deliberately
does not resolve socket destinations or create additional work.
"""

from __future__ import annotations

import asyncio
import errno
import ssl
import time
from collections.abc import Awaitable, Callable
from datetime import datetime

from .models import Direction, Disposition, EvidenceKind, Observation, ProbeKind, utc_now
from .planner import PreparedStep
from .resolver import ResolutionResult, resolve_addresses
from .tasks import TaskContext

Connector = Callable[..., Awaitable[tuple[asyncio.StreamReader, asyncio.StreamWriter]]]
Resolver = Callable[..., Awaitable[ResolutionResult]]


def _observation(
    prepared: PreparedStep,
    kind: EvidenceKind,
    disposition: Disposition,
    *,
    started_at: datetime,
    elapsed_s: float,
    detail: dict[str, object] | None = None,
) -> Observation:
    """Create unbound evidence; ``TaskContext.record`` supplies step fields."""
    ended_at = utc_now()
    return Observation(
        id=f"probe-{prepared.step.id[5:21]}",
        probe=prepared.step.probe_kind.value,
        disposition=disposition,
        evidence_kind=kind,
        direction=Direction.OUTBOUND,
        target=prepared.address or prepared.step.target,
        started_at=started_at,
        ended_at=ended_at,
        duration_ms=max(0.0, elapsed_s * 1_000),
        attempt=prepared.step.attempt,
        source="mercury.probes",
        detail=detail or {},
    )


def _failure(
    prepared: PreparedStep,
    exc: BaseException,
    *,
    started_at: datetime,
    elapsed_s: float,
) -> Observation:
    if isinstance(exc, TimeoutError):
        return _observation(
            prepared, EvidenceKind.TIMEOUT, Disposition.INCONCLUSIVE,
            started_at=started_at, elapsed_s=elapsed_s, detail={"category": "timeout"},
        )
    code = getattr(exc, "errno", None)
    if code is None:
        code = getattr(exc, "winerror", None)
    if code in {errno.ECONNREFUSED, 10061}:
        kind, disposition, category = EvidenceKind.TCP_REFUSED, Disposition.NEGATIVE, "refused"
    elif code in {errno.ECONNRESET, 10054}:
        kind, disposition, category = EvidenceKind.TCP_RESET, Disposition.NEGATIVE, "reset"
    elif code in {errno.ENETUNREACH, 10051}:
        kind, disposition, category = EvidenceKind.NETWORK_UNREACHABLE, Disposition.NEGATIVE, "network_unreachable"
    elif code in {errno.EHOSTUNREACH, 10065}:
        kind, disposition, category = EvidenceKind.HOST_UNREACHABLE, Disposition.NEGATIVE, "host_unreachable"
    else:
        kind, disposition, category = EvidenceKind.EXECUTION_ERROR, Disposition.ERROR, type(exc).__name__
    return _observation(
        prepared, kind, disposition, started_at=started_at, elapsed_s=elapsed_s,
        detail={"category": category},
    )


async def dns_probe(
    prepared: PreparedStep,
    *,
    resolver: Resolver = resolve_addresses,
    hard_deadline: float | None = None,
    wall_clock: Callable[[], datetime] = utc_now,
    monotonic: Callable[[], float] = time.monotonic,
) -> Observation:
    """Resolve one admitted hostname without turning answers into new actions."""
    if prepared.step.probe_kind is not ProbeKind.SYSTEM_DNS:
        raise ValueError("DNS probe requires a system_dns prepared step")
    started_at, started = wall_clock(), monotonic()
    timeout = prepared.step.timeout_s
    if hard_deadline is not None:
        timeout = min(timeout, hard_deadline - started)
    if timeout < 0.1:
        return _observation(
            prepared, EvidenceKind.TIMEOUT, Disposition.INCONCLUSIVE,
            started_at=started_at, elapsed_s=monotonic() - started,
            detail={"category": "deadline_exhausted"},
        )
    try:
        result = await resolver(
            prepared.step.target, operation_timeout=timeout, hard_deadline=timeout,
        )
    except asyncio.CancelledError:
        raise
    except BaseException as exc:
        return _failure(prepared, exc, started_at=started_at, elapsed_s=monotonic() - started)
    elapsed = monotonic() - started
    if result.addresses:
        return _observation(
            prepared, EvidenceKind.DNS_ANSWER, Disposition.POSITIVE,
            started_at=started_at, elapsed_s=elapsed,
            detail={"addresses": result.addresses},
        )
    error = result.error or result.outcome.value
    if result.outcome.value == "nonzero" or error == "NoAddress":
        disposition = Disposition.NEGATIVE
    elif result.outcome.value == "timeout":
        disposition = Disposition.INCONCLUSIVE
    else:
        disposition = Disposition.ERROR
    return _observation(
        prepared, EvidenceKind.DNS_FAILURE, disposition,
        started_at=started_at, elapsed_s=elapsed, detail={"category": error},
    )


async def _connect(
    prepared: PreparedStep,
    *,
    connector: Connector,
    ssl_context: ssl.SSLContext | None = None,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Dial the digest-bound numeric address only (never the logical host)."""
    if prepared.address is None or prepared.step.port is None:
        raise ValueError("socket probe requires a prepared numeric address and port")
    kwargs: dict[str, object] = {}
    if ssl_context is not None:
        kwargs["ssl"] = ssl_context
        kwargs["server_hostname"] = prepared.step.server_name
    return await connector(prepared.address, prepared.step.port, **kwargs)


async def _close_writer(writer: asyncio.StreamWriter | None) -> None:
    if writer is None:
        return
    writer.close()
    try:
        await writer.wait_closed()
    except (OSError, RuntimeError, ssl.SSLError):
        pass


async def tcp_probe(
    prepared: PreparedStep,
    *,
    connector: Connector = asyncio.open_connection,
    wall_clock: Callable[[], datetime] = utc_now,
    monotonic: Callable[[], float] = time.monotonic,
) -> Observation:
    started_at, started, writer = wall_clock(), monotonic(), None
    try:
        async with asyncio.timeout(prepared.step.timeout_s):
            _, writer = await _connect(prepared, connector=connector)
        return _observation(prepared, EvidenceKind.TCP_CONNECTED, Disposition.POSITIVE,
                            started_at=started_at, elapsed_s=monotonic() - started)
    except asyncio.CancelledError:
        raise
    except BaseException as exc:
        return _failure(prepared, exc, started_at=started_at, elapsed_s=monotonic() - started)
    finally:
        await _close_writer(writer)


async def tls_probe(
    prepared: PreparedStep,
    *,
    connector: Connector = asyncio.open_connection,
    ssl_context_factory: Callable[[], ssl.SSLContext] = ssl.create_default_context,
    wall_clock: Callable[[], datetime] = utc_now,
    monotonic: Callable[[], float] = time.monotonic,
) -> Observation:
    started_at, started, writer = wall_clock(), monotonic(), None
    try:
        context = ssl_context_factory()
        async with asyncio.timeout(prepared.step.timeout_s):
            _, writer = await _connect(prepared, connector=connector, ssl_context=context)
        tls = writer.get_extra_info("ssl_object")
        detail = {
            "tls_version": tls.version() if tls is not None else None,
            "cipher": (tls.cipher() or (None,))[0] if tls is not None else None,
            "alpn": tls.selected_alpn_protocol() if tls is not None else None,
        }
        return _observation(prepared, EvidenceKind.TLS_HANDSHAKE, Disposition.POSITIVE,
                            started_at=started_at, elapsed_s=monotonic() - started, detail=detail)
    except asyncio.CancelledError:
        raise
    except ssl.SSLCertVerificationError:
        return _observation(prepared, EvidenceKind.TLS_VERIFICATION_FAILED, Disposition.NEGATIVE,
                            started_at=started_at, elapsed_s=monotonic() - started,
                            detail={"category": "verification"})
    except ssl.SSLError as exc:
        return _observation(prepared, EvidenceKind.TLS_HANDSHAKE_FAILED, Disposition.NEGATIVE,
                            started_at=started_at, elapsed_s=monotonic() - started,
                            detail={"category": type(exc).__name__})
    except BaseException as exc:
        return _failure(prepared, exc, started_at=started_at, elapsed_s=monotonic() - started)
    finally:
        await _close_writer(writer)


async def http_probe(
    prepared: PreparedStep,
    *,
    connector: Connector = asyncio.open_connection,
    ssl_context_factory: Callable[[], ssl.SSLContext] = ssl.create_default_context,
    wall_clock: Callable[[], datetime] = utc_now,
    monotonic: Callable[[], float] = time.monotonic,
) -> Observation:
    """Send one bounded HEAD request; redirects and response bodies are ignored."""
    started_at, started, writer = wall_clock(), monotonic(), None
    try:
        context = ssl_context_factory() if prepared.step.http_scheme == "https" else None
        async with asyncio.timeout(prepared.step.timeout_s):
            reader, writer = await _connect(prepared, connector=connector, ssl_context=context)
            request = (
                f"HEAD / HTTP/1.1\r\nHost: {prepared.step.server_name}\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
            writer.write(request)
            await writer.drain()
            header = await reader.readuntil(b"\r\n\r\n")
        if len(header) > 16_384:
            raise ValueError("header_limit")
        parts = header.split(b"\r\n", 1)[0].split(maxsplit=2)
        if len(parts) < 2 or not parts[0].startswith(b"HTTP/") or not parts[1].isdigit():
            raise ValueError("malformed_status")
        status = int(parts[1])
        if not 100 <= status <= 599:
            raise ValueError("invalid_status")
        return _observation(prepared, EvidenceKind.HTTP_RESPONSE, Disposition.POSITIVE,
                            started_at=started_at, elapsed_s=monotonic() - started,
                            detail={"status": status})
    except asyncio.CancelledError:
        raise
    except ssl.SSLCertVerificationError:
        return _observation(prepared, EvidenceKind.TLS_VERIFICATION_FAILED, Disposition.NEGATIVE,
                            started_at=started_at, elapsed_s=monotonic() - started,
                            detail={"category": "verification"})
    except ssl.SSLError as exc:
        return _observation(prepared, EvidenceKind.TLS_HANDSHAKE_FAILED, Disposition.NEGATIVE,
                            started_at=started_at, elapsed_s=monotonic() - started,
                            detail={"category": type(exc).__name__})
    except BaseException as exc:
        return _failure(prepared, exc, started_at=started_at, elapsed_s=monotonic() - started)
    finally:
        await _close_writer(writer)


async def run_protocol_probe(
    context: TaskContext,
    step_id: str,
    *,
    connector: Connector = asyncio.open_connection,
    resolver: Resolver = resolve_addresses,
) -> None:
    """Perform exactly one admitted protocol action and complete that attempt."""
    prepared = await context.admit(step_id)
    kind = prepared.step.probe_kind
    if kind is ProbeKind.SYSTEM_DNS:
        observation = await dns_probe(prepared, resolver=resolver, wall_clock=context.wall_clock,
                                      monotonic=context.monotonic)
    elif kind is ProbeKind.TCP_CONNECT:
        observation = await tcp_probe(prepared, connector=connector, wall_clock=context.wall_clock,
                                      monotonic=context.monotonic)
    elif kind is ProbeKind.TLS_HANDSHAKE:
        observation = await tls_probe(prepared, connector=connector, wall_clock=context.wall_clock,
                                      monotonic=context.monotonic)
    elif kind is ProbeKind.HTTP_EXCHANGE:
        observation = await http_probe(prepared, connector=connector, wall_clock=context.wall_clock,
                                       monotonic=context.monotonic)
    else:
        raise ValueError("unsupported protocol probe")
    context.record(observation, step_id=step_id)
    context.complete_attempt(step_id)


__all__ = ["dns_probe", "http_probe", "run_protocol_probe", "tcp_probe", "tls_probe"]
