"""Deadline-aware, killable system DNS resolution for diagnosis work."""

from __future__ import annotations

import json
import math
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
    if type(operation_timeout) not in (int, float) or not math.isfinite(float(operation_timeout)) or not 0.1 <= float(operation_timeout) <= 30.0:
        raise ValueError("operation timeout must be within 0.1..30 seconds")
    if type(hard_deadline) not in (int, float) or not math.isfinite(float(hard_deadline)):
        raise ValueError("hard deadline must be finite")
    timeout = min(operation_timeout, hard_deadline)
    if not 0.1 <= timeout <= 30.0:
        raise ValueError("resolution deadline must be within 0.1..30 seconds")
    helper = str(Path(__file__).with_name("_resolver_helper.py"))
    result: CommandResult = await command_runner(
        (sys.executable, "-I", helper, target.hostname), timeout_s=timeout, max_output_bytes=16_384
    )
    try:
        payload = json.loads(result.stdout)
    except (TypeError, ValueError):
        return ResolutionResult(target.hostname, (), CommandOutcome.ERROR, result.error_type or "MalformedResolverOutput")
    if result.outcome is not CommandOutcome.SUCCESS:
        if isinstance(payload, dict) and payload.get("error") == "NameNotFound":
            return ResolutionResult(target.hostname, (), CommandOutcome.NONZERO, "NameNotFound")
        return ResolutionResult(target.hostname, (), CommandOutcome.ERROR, "ResolverFailure")
    rows = payload
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
