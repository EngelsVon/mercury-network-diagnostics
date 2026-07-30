"""Shared, bounded platform command and record primitives.

This module is deliberately concrete.  Mercury has three built-in platform
adapters; it does not expose an adapter framework or execute shell strings.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from enum import StrEnum
import ipaddress
import math
import re
from typing import Awaitable, Callable

from mercury.history import sanitize_persisted_text
from mercury.models import Capability

MAX_COMMAND_OUTPUT_BYTES = 262_144
MAX_DIAGNOSTIC_CHARACTERS = 1_024
MAX_COMMAND_TIMEOUT_S = 30.0
MAX_PASSIVE_TIMEOUT_S = 5.0
_READ_CHUNK_BYTES = 65_536
_REAP_TIMEOUT_S = 1.0


class CommandOutcome(StrEnum):
    """Portable command outcomes; localized process text is not classified."""

    SUCCESS = "success"
    NONZERO = "nonzero"
    MISSING_TOOL = "missing_tool"
    PERMISSION_DENIED = "permission_denied"
    TIMEOUT = "timeout"
    OUTPUT_OVERFLOW = "output_overflow"
    ERROR = "error"


def _validate_text(
    value: object,
    name: str,
    *,
    required: bool = True,
    maximum: int = 1_024,
) -> str | None:
    if value is None and not required:
        return None
    if type(value) is not str:
        raise ValueError(f"{name} must be text")
    if required and not value.strip():
        raise ValueError(f"{name} must be non-empty")
    if len(value) > maximum:
        raise ValueError(f"{name} exceeds {maximum} characters")
    if any(ord(character) < 32 or character == "\x7f" for character in value):
        raise ValueError(f"{name} contains a control character")
    return value


def _validate_optional_nonnegative_int(value: object, name: str) -> int | None:
    if value is None:
        return None
    if type(value) is not int or value < 0:
        raise ValueError(f"{name} must be a non-negative integer or None")
    return value


def _validate_argv(argv: object) -> tuple[str, ...]:
    if type(argv) is not tuple or not argv:
        raise ValueError("command argv must be a non-empty tuple")
    for item in argv:
        if type(item) is not str or not item:
            raise ValueError("command argv entries must be non-empty strings")
        if "\x00" in item:
            raise ValueError("command argv entries cannot contain NUL")
    return argv


def _validate_timeout(timeout_s: object, *, maximum: float) -> float:
    if type(timeout_s) not in (int, float):
        raise ValueError("timeout_s must be a finite number")
    timeout = float(timeout_s)
    if not math.isfinite(timeout) or not 0.1 <= timeout <= maximum:
        raise ValueError(f"timeout_s must be between 0.1 and {maximum:g}")
    return timeout


def _validate_output_limit(max_output_bytes: object) -> int:
    if type(max_output_bytes) is not int or not (
        1 <= max_output_bytes <= MAX_COMMAND_OUTPUT_BYTES
    ):
        raise ValueError(
            f"max_output_bytes must be an integer between 1 and "
            f"{MAX_COMMAND_OUTPUT_BYTES}"
        )
    return max_output_bytes


@dataclass(frozen=True, slots=True)
class CommandResult:
    """A bounded subprocess result suitable for fixture-driven parsers."""

    argv: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str
    outcome: CommandOutcome
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    error_type: str | None = None

    def __post_init__(self) -> None:
        _validate_argv(self.argv)
        if self.returncode is not None and type(self.returncode) is not int:
            raise ValueError("command returncode must be an integer or None")
        if type(self.stdout) is not str or type(self.stderr) is not str:
            raise ValueError("command output must be decoded text")
        if len(self.stdout.encode("utf-8", "replace")) > MAX_COMMAND_OUTPUT_BYTES:
            raise ValueError("command stdout exceeds the absolute byte ceiling")
        if len(self.stderr.encode("utf-8", "replace")) > MAX_COMMAND_OUTPUT_BYTES:
            raise ValueError("command stderr exceeds the absolute byte ceiling")
        if type(self.outcome) is not CommandOutcome:
            raise ValueError("command outcome must be CommandOutcome")
        for value, name in (
            (self.stdout_bytes, "stdout_bytes"),
            (self.stderr_bytes, "stderr_bytes"),
        ):
            if type(value) is not int or not 0 <= value <= MAX_COMMAND_OUTPUT_BYTES:
                raise ValueError(f"{name} is outside the command byte ceiling")
        if self.outcome in (CommandOutcome.SUCCESS, CommandOutcome.NONZERO):
            if self.returncode is None:
                raise ValueError("completed commands require a return code")
        elif self.returncode is not None:
            raise ValueError("incomplete command outcomes cannot have a return code")
        if self.outcome is CommandOutcome.SUCCESS and self.returncode != 0:
            raise ValueError("successful commands require return code zero")
        if self.outcome is CommandOutcome.NONZERO and self.returncode == 0:
            raise ValueError("nonzero outcome requires a nonzero return code")
        if self.error_type is not None and (
            type(self.error_type) is not str
            or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", self.error_type)
        ):
            raise ValueError("error_type must be a bounded exception class name")

    @property
    def timed_out(self) -> bool:
        return self.outcome is CommandOutcome.TIMEOUT

    @property
    def output_overflowed(self) -> bool:
        return self.outcome is CommandOutcome.OUTPUT_OVERFLOW

    @property
    def diagnostic(self) -> str:
        """Return persistence-safe, bounded diagnostic text."""
        text = self.stderr if self.stderr else self.stdout
        return sanitize_persisted_text(
            text,
            maximum=MAX_DIAGNOSTIC_CHARACTERS,
        )


@dataclass(frozen=True, slots=True)
class RouteRecord:
    """Canonical route data shared by the three concrete adapters."""

    family: int
    destination: str
    source: str
    gateway: str | None = None
    interface_name: str | None = None
    interface_index: int | None = None
    route_metric: int | None = None
    interface_metric: int | None = None
    preferred_source: str | None = None
    protocol: str | None = None
    scope: str | None = None
    route_type: str | None = None
    state: str | None = None
    flags: tuple[str, ...] = ()
    on_link: bool | None = None
    source_record_index: int | None = None

    def __post_init__(self) -> None:
        if type(self.family) is not int or self.family not in (4, 6):
            raise ValueError("route family must be 4 or 6")
        try:
            network = ipaddress.ip_network(self.destination, strict=False)
        except (TypeError, ValueError) as exc:
            raise ValueError("route destination must be a valid prefix") from exc
        if network.version != self.family:
            raise ValueError("route destination family does not match")
        object.__setattr__(self, "destination", network.with_prefixlen)
        if self.gateway is not None:
            try:
                gateway = ipaddress.ip_address(self.gateway)
            except (TypeError, ValueError) as exc:
                raise ValueError("route gateway must be a valid address") from exc
            if gateway.version != self.family:
                raise ValueError("route gateway family does not match")
            object.__setattr__(self, "gateway", gateway.compressed)
        if self.preferred_source is not None:
            try:
                preferred = ipaddress.ip_address(self.preferred_source)
            except (TypeError, ValueError) as exc:
                raise ValueError("preferred source must be a valid address") from exc
            if preferred.version != self.family:
                raise ValueError("preferred source family does not match")
            object.__setattr__(self, "preferred_source", preferred.compressed)
        _validate_text(self.source, "route source", maximum=256)
        for attribute in (
            "interface_name",
            "protocol",
            "scope",
            "route_type",
            "state",
        ):
            _validate_text(
                getattr(self, attribute),
                f"route {attribute}",
                required=False,
                maximum=256,
            )
        for attribute in (
            "interface_index",
            "route_metric",
            "interface_metric",
            "source_record_index",
        ):
            _validate_optional_nonnegative_int(
                getattr(self, attribute),
                f"route {attribute}",
            )
        if self.interface_name is None and self.interface_index is None:
            raise ValueError("route requires an interface name or index")
        if not isinstance(self.flags, (tuple, list)):
            raise ValueError("route flags must be a sequence")
        flags = tuple(self.flags)
        if len(flags) > 64:
            raise ValueError("route has too many flags")
        for flag in flags:
            _validate_text(flag, "route flag", maximum=64)
        object.__setattr__(self, "flags", flags)
        if self.on_link is not None and type(self.on_link) is not bool:
            raise ValueError("route on_link must be a boolean or None")

    @property
    def is_default(self) -> bool:
        return self.destination in ("0.0.0.0/0", "::/0")

    @property
    def effective_metric(self) -> int | None:
        if self.route_metric is None or self.interface_metric is None:
            return None
        return self.route_metric + self.interface_metric


@dataclass(frozen=True, slots=True)
class DnsServerRecord:
    """Canonical configured/resolver-visible DNS server data."""

    family: int
    address: str
    source: str
    scope_id: str | None = None
    interface_name: str | None = None
    interface_index: int | None = None
    resolver_order: int | None = None
    scoped_domain: str | None = None
    configuration_state: str | None = None

    def __post_init__(self) -> None:
        if type(self.family) is not int or self.family not in (4, 6):
            raise ValueError("DNS family must be 4 or 6")
        if type(self.address) is not str or "%" in self.address:
            raise ValueError("DNS address must not embed an IPv6 scope")
        try:
            address = ipaddress.ip_address(self.address)
        except (TypeError, ValueError) as exc:
            raise ValueError("DNS address must be a valid address") from exc
        if address.version != self.family:
            raise ValueError("DNS address family does not match")
        object.__setattr__(self, "address", address.compressed)
        if self.scope_id is not None:
            if self.family != 6 or not address.is_link_local:
                raise ValueError("DNS scope is valid only for link-local IPv6")
            scope = _validate_text(
                self.scope_id,
                "DNS scope",
                maximum=256,
            )
            assert scope is not None
            if any(character in "/\\[]" for character in scope):
                raise ValueError("DNS scope contains unsafe characters")
        _validate_text(self.source, "DNS source", maximum=256)
        for attribute in (
            "interface_name",
            "scoped_domain",
            "configuration_state",
        ):
            _validate_text(
                getattr(self, attribute),
                f"DNS {attribute}",
                required=False,
                maximum=256,
            )
        for attribute in ("interface_index", "resolver_order"):
            _validate_optional_nonnegative_int(
                getattr(self, attribute),
                f"DNS {attribute}",
            )
        if self.interface_name is None and self.interface_index is None:
            raise ValueError("DNS server requires an interface name or index")


@dataclass(frozen=True, slots=True)
class PlatformRecords:
    routes: tuple[RouteRecord, ...] = ()
    dns_servers: tuple[DnsServerRecord, ...] = ()
    capabilities: tuple[Capability, ...] = ()

    def __post_init__(self) -> None:
        for attribute, item_type in (
            ("routes", RouteRecord),
            ("dns_servers", DnsServerRecord),
            ("capabilities", Capability),
        ):
            value = getattr(self, attribute)
            if not isinstance(value, (tuple, list)):
                raise ValueError(f"{attribute} must be a sequence")
            items = tuple(value)
            if any(type(item) is not item_type for item in items):
                raise ValueError(f"{attribute} contains an invalid record")
            object.__setattr__(self, attribute, items)


class _OutputOverflow(Exception):
    pass


async def _read_bounded(
    stream: asyncio.StreamReader,
    buffer: bytearray,
    maximum: int,
) -> None:
    while True:
        chunk = await stream.read(_READ_CHUNK_BYTES)
        if not chunk:
            return
        remaining = maximum - len(buffer)
        if len(chunk) > remaining:
            if remaining:
                buffer.extend(chunk[:remaining])
            raise _OutputOverflow
        buffer.extend(chunk)


def _close_stream_transport(stream: asyncio.StreamReader | None) -> None:
    if stream is None:
        return
    transport = getattr(stream, "_transport", None)
    close = getattr(transport, "close", None)
    if callable(close):
        try:
            close()
        except Exception:
            pass


async def _terminate_and_reap(
    process: asyncio.subprocess.Process,
    readers: tuple[asyncio.Task[None], asyncio.Task[None]],
) -> None:
    if process.returncode is None:
        try:
            process.kill()
        except OSError:
            pass
    for reader in readers:
        if not reader.done():
            reader.cancel()
    await asyncio.gather(*readers, return_exceptions=True)
    _close_stream_transport(process.stdout)
    _close_stream_transport(process.stderr)
    try:
        await asyncio.wait_for(process.wait(), timeout=_REAP_TIMEOUT_S)
    except (TimeoutError, OSError):
        pass


def _decode(buffer: bytearray) -> str:
    return bytes(buffer).decode("utf-8", "replace")


async def run_command(
    argv: tuple[str, ...],
    timeout_s: float = 5.0,
    max_output_bytes: int = MAX_COMMAND_OUTPUT_BYTES,
) -> CommandResult:
    """Execute fixed argv with bounded time, pipe bytes, and cleanup."""

    canonical_argv = _validate_argv(argv)
    timeout = _validate_timeout(timeout_s, maximum=MAX_COMMAND_TIMEOUT_S)
    maximum = _validate_output_limit(max_output_bytes)
    try:
        process = await asyncio.create_subprocess_exec(
            *canonical_argv,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        return CommandResult(
            canonical_argv,
            None,
            "",
            "",
            CommandOutcome.MISSING_TOOL,
            error_type="FileNotFoundError",
        )
    except PermissionError:
        return CommandResult(
            canonical_argv,
            None,
            "",
            "",
            CommandOutcome.PERMISSION_DENIED,
            error_type="PermissionError",
        )
    except OSError as exc:
        return CommandResult(
            canonical_argv,
            None,
            "",
            "",
            CommandOutcome.ERROR,
            error_type=type(exc).__name__,
        )

    if process.stdout is None or process.stderr is None:
        if process.returncode is None:
            process.kill()
        await process.wait()
        return CommandResult(
            canonical_argv,
            None,
            "",
            "",
            CommandOutcome.ERROR,
            error_type="MissingPipeError",
        )

    stdout = bytearray()
    stderr = bytearray()
    readers = (
        asyncio.create_task(
            _read_bounded(process.stdout, stdout, maximum),
            name="mercury:command-stdout",
        ),
        asyncio.create_task(
            _read_bounded(process.stderr, stderr, maximum),
            name="mercury:command-stderr",
        ),
    )
    outcome: CommandOutcome
    returncode: int | None
    try:
        async with asyncio.timeout(timeout):
            await asyncio.gather(*readers)
            returncode = await process.wait()
        outcome = (
            CommandOutcome.SUCCESS if returncode == 0 else CommandOutcome.NONZERO
        )
    except TimeoutError:
        outcome = CommandOutcome.TIMEOUT
        returncode = None
        await _terminate_and_reap(process, readers)
    except _OutputOverflow:
        outcome = CommandOutcome.OUTPUT_OVERFLOW
        returncode = None
        await _terminate_and_reap(process, readers)
    except asyncio.CancelledError:
        await _terminate_and_reap(process, readers)
        raise
    except Exception as exc:
        outcome = CommandOutcome.ERROR
        returncode = None
        await _terminate_and_reap(process, readers)
        return CommandResult(
            argv=canonical_argv,
            returncode=returncode,
            stdout=_decode(stdout),
            stderr=_decode(stderr),
            outcome=outcome,
            stdout_bytes=len(stdout),
            stderr_bytes=len(stderr),
            error_type=type(exc).__name__,
        )

    return CommandResult(
        argv=canonical_argv,
        returncode=returncode,
        stdout=_decode(stdout),
        stderr=_decode(stderr),
        outcome=outcome,
        stdout_bytes=len(stdout),
        stderr_bytes=len(stderr),
    )


CommandRunner = Callable[
    [tuple[str, ...], float, int],
    Awaitable[CommandResult],
]


async def run_passive_command(
    argv: tuple[str, ...],
    timeout_s: float = MAX_PASSIVE_TIMEOUT_S,
    max_output_bytes: int = MAX_COMMAND_OUTPUT_BYTES,
    *,
    runner: CommandRunner | None = None,
) -> CommandResult:
    """Apply inventory's stricter five-second ceiling before process creation."""

    timeout = _validate_timeout(timeout_s, maximum=MAX_PASSIVE_TIMEOUT_S)
    maximum = _validate_output_limit(max_output_bytes)
    command_runner = run_command if runner is None else runner
    return await command_runner(argv, timeout, maximum)


__all__ = [
    "CommandOutcome",
    "CommandResult",
    "CommandRunner",
    "DnsServerRecord",
    "MAX_COMMAND_OUTPUT_BYTES",
    "MAX_COMMAND_TIMEOUT_S",
    "MAX_DIAGNOSTIC_CHARACTERS",
    "MAX_PASSIVE_TIMEOUT_S",
    "PlatformRecords",
    "RouteRecord",
    "run_command",
    "run_passive_command",
]
