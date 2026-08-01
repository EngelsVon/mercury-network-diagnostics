"""Deadline-aware, killable system DNS resolution for diagnosis work."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path

from .platform.common import CommandOutcome, CommandResult, run_command
from .policy import PolicyError, parse_target

MAX_RESOLUTION_ROWS = 1_024
MAX_RESOLUTION_ADDRESSES = 64


@dataclass(frozen=True, slots=True)
class ResolutionResult:
    hostname: str
    addresses: tuple[str, ...]
    outcome: CommandOutcome
    error: str | None = None


async def resolve_addresses(
    hostname: str,
    *,
    operation_timeout: float,
    hard_deadline: float,
    command_runner=run_command,
) -> ResolutionResult:
    target = parse_target(hostname)
    if target.hostname is None:
        raise PolicyError("resolver accepts only canonical hostnames")
    timeout = min(operation_timeout, hard_deadline)
    if not 0.1 <= timeout <= 30.0:
        raise ValueError("resolution deadline must be within 0.1..30 seconds")
    helper = str(Path(__file__).with_name("_resolver_helper.py"))
    result: CommandResult = await command_runner(
        (sys.executable, helper, target.hostname), timeout_s=timeout, max_output_bytes=16_384
    )
    if result.outcome is not CommandOutcome.SUCCESS:
        return ResolutionResult(target.hostname, (), result.outcome, result.error_type)
    try:
        rows = json.loads(result.stdout)
    except (TypeError, ValueError):
        return ResolutionResult(target.hostname, (), CommandOutcome.ERROR, "MalformedResolverOutput")
    if not isinstance(rows, list) or len(rows) > MAX_RESOLUTION_ROWS:
        return ResolutionResult(target.hostname, (), CommandOutcome.ERROR, "ResolutionRowOverflow")
    addresses: dict[str, None] = {}
    for row in rows:
        if not isinstance(row, str):
            return ResolutionResult(target.hostname, (), CommandOutcome.ERROR, "MalformedResolverOutput")
        try:
            address = parse_target(row)
        except PolicyError:
            return ResolutionResult(target.hostname, (), CommandOutcome.ERROR, "MalformedResolverOutput")
        if address.address is None:
            return ResolutionResult(target.hostname, (), CommandOutcome.ERROR, "MalformedResolverOutput")
        addresses[address.canonical] = None
        if len(addresses) > MAX_RESOLUTION_ADDRESSES:
            return ResolutionResult(target.hostname, (), CommandOutcome.ERROR, "ResolutionAddressOverflow")
    if not addresses:
        return ResolutionResult(target.hostname, (), CommandOutcome.NONZERO, "NoAddress")
    return ResolutionResult(target.hostname, tuple(sorted(addresses)), CommandOutcome.SUCCESS)


__all__ = ["MAX_RESOLUTION_ADDRESSES", "MAX_RESOLUTION_ROWS", "ResolutionResult", "resolve_addresses"]
