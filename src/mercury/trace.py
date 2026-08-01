"""Bounded native route traces with evidence-preserving parsers.

Native tools are used only through fixed argv.  Their text is evidence, not a
topology oracle: unanswered hops and alternate responses remain visible and no
single path or Layer-2 device is asserted.
"""

from __future__ import annotations

import asyncio
import ipaddress
import math
import platform
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .history import HistoryStore
from .models import Direction, Disposition, EvidenceKind, Observation, ProbeKind, TaskResult
from .planner import DEFAULT_LIMITS, PayloadMetadata, ProbePlan, ProbeSpec, StepCost, authorize_plan, preview_probe_plan
from .platform.common import CommandOutcome, run_command
from .policy import PolicyError, ScopeGrant
from .tasks import TaskContext, TaskService


MAX_TRACE_REPEATS = 3
MAX_TRACE_HOPS = 8
MAX_TRACE_OUTPUT_BYTES = 65_536
_ADDRESS_RE = re.compile(r"(?<![0-9A-Fa-f:.])(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f:]{2,})(?![0-9A-Fa-f:.])")
_HOP_RE = re.compile(r"^\s*(\d{1,2})\s+(.+?)\s*$")


@dataclass(frozen=True, slots=True)
class TraceHop:
    hop: int
    addresses: tuple[str, ...]
    raw: str

    def __post_init__(self) -> None:
        if type(self.hop) is not int or not 1 <= self.hop <= MAX_TRACE_HOPS:
            raise ValueError("trace hop number is invalid")
        if not isinstance(self.addresses, (tuple, list)) or len(self.addresses) > 16:
            raise ValueError("trace hop addresses are invalid")
        normalized: list[str] = []
        for value in self.addresses:
            normalized.append(ipaddress.ip_address(value).compressed)
        if not isinstance(self.raw, str) or not self.raw or len(self.raw) > 1_024:
            raise ValueError("trace raw line is invalid")
        object.__setattr__(self, "addresses", tuple(dict.fromkeys(normalized)))

    @property
    def answered(self) -> bool:
        return bool(self.addresses)


@dataclass(frozen=True, slots=True)
class TraceRequest:
    target: str
    scope: str
    max_hops: int = MAX_TRACE_HOPS
    repeats: int = MAX_TRACE_REPEATS
    timeout_s: float = 1.0
    authorized: bool = False

    def __post_init__(self) -> None:
        address = ipaddress.ip_address(self.target)
        network = ipaddress.ip_network(self.scope, strict=False)
        if address.version != network.version or address not in network:
            raise PolicyError("trace target must be contained in the authorized scope")
        if type(self.max_hops) is not int or not 1 <= self.max_hops <= MAX_TRACE_HOPS:
            raise ValueError(f"max_hops must be within 1..{MAX_TRACE_HOPS}")
        if type(self.repeats) is not int or not 1 <= self.repeats <= MAX_TRACE_REPEATS:
            raise ValueError(f"repeats must be within 1..{MAX_TRACE_REPEATS}")
        if type(self.timeout_s) not in (int, float) or not math.isfinite(float(self.timeout_s)) or not 0.1 <= float(self.timeout_s) <= 5.0:
            raise ValueError("trace timeout must be within 0.1..5 seconds")
        if type(self.authorized) is not bool:
            raise ValueError("authorized must be boolean")
        object.__setattr__(self, "target", address.compressed)
        object.__setattr__(self, "scope", network.with_prefixlen)
        object.__setattr__(self, "timeout_s", float(self.timeout_s))


def default_trace_grant(request: TraceRequest) -> ScopeGrant:
    return ScopeGrant(
        networks=(ipaddress.ip_network(request.scope),), probe_kinds=(ProbeKind.NATIVE_PATH,),
        attested=request.authorized, purpose="authorized bounded native route trace",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=15),
    )


def compile_trace(request: TraceRequest, *, grant: ScopeGrant):
    if type(request) is not TraceRequest or type(grant) is not ScopeGrant:
        raise TypeError("trace request and grant must be canonical")
    if not request.authorized or not grant.attested:
        raise PolicyError("native trace requires explicit authorization attestation")
    # A native tool may make up to three bounded probes per TTL.  This is a
    # logical upper bound only; it intentionally makes no on-wire claim.
    cost = StepCost(
        1, 0, 0, logical_packets=request.max_hops * 3,
        max_observations=request.max_hops + 1, max_output_bytes=MAX_TRACE_OUTPUT_BYTES,
    )
    specs = tuple(
        ProbeSpec(
            probe_kind=ProbeKind.NATIVE_PATH, target=request.target, address=request.target,
            attempt=attempt, max_hops=request.max_hops,
            timeout_s=min(30.0, request.max_hops * request.timeout_s),
            payload_metadata=PayloadMetadata("none-v1", 0), cost=cost,
        )
        for attempt in range(1, request.repeats + 1)
    )
    return preview_probe_plan(specs=specs, grant=grant, profile="native-trace-v1", limits=DEFAULT_LIMITS)


def windows_trace_argv(target: str, *, max_hops: int, timeout_s: float) -> tuple[str, ...]:
    address = ipaddress.ip_address(target).compressed
    if not 1 <= max_hops <= MAX_TRACE_HOPS or not 0.1 <= timeout_s <= 5.0:
        raise ValueError("trace bounds are invalid")
    return ("tracert.exe", "-d", "-h", str(max_hops), "-w", str(math.ceil(timeout_s * 1_000)), address)


def linux_trace_argv(target: str, *, max_hops: int, timeout_s: float) -> tuple[str, ...]:
    address = ipaddress.ip_address(target).compressed
    if not 1 <= max_hops <= MAX_TRACE_HOPS or not 0.1 <= timeout_s <= 5.0:
        raise ValueError("trace bounds are invalid")
    return ("traceroute", "-n", "-m", str(max_hops), "-w", f"{timeout_s:.1f}", address)


def _addresses(text: str) -> tuple[str, ...]:
    values: list[str] = []
    for candidate in _ADDRESS_RE.findall(text):
        try:
            values.append(ipaddress.ip_address(candidate).compressed)
        except ValueError:
            continue
    return tuple(dict.fromkeys(values))


def _parse_trace(document: str, *, source: str) -> tuple[TraceHop, ...]:
    if len(document.encode("utf-8", "replace")) > MAX_TRACE_OUTPUT_BYTES:
        raise ValueError("native trace output exceeds the byte ceiling")
    hops: list[TraceHop] = []
    expected = 1
    for raw in document.splitlines():
        match = _HOP_RE.match(raw)
        if match is None:
            continue
        number = int(match.group(1))
        if number != expected or number > MAX_TRACE_HOPS:
            raise ValueError(f"{source} hop sequence is not bounded and contiguous")
        trimmed = raw.strip()[:1_024]
        hops.append(TraceHop(number, _addresses(match.group(2)), trimmed))
        expected += 1
    if not hops:
        raise ValueError(f"{source} has no parseable hop evidence")
    return tuple(hops)


def parse_windows_trace(document: str) -> tuple[TraceHop, ...]:
    return _parse_trace(document, source="tracert")


def parse_linux_trace(document: str) -> tuple[TraceHop, ...]:
    return _parse_trace(document, source="traceroute")


class TraceRunner:
    def __init__(self, request: TraceRequest, *, system: Callable[[], str] = platform.system, command_runner=run_command) -> None:
        self.request = request
        self.system = system
        self.command_runner = command_runner

    def _adapter(self) -> tuple[str, Callable[[str], tuple[TraceHop, ...]], tuple[str, ...]]:
        name = self.system().casefold()
        if name == "windows":
            return "windows.tracert", parse_windows_trace, windows_trace_argv(self.request.target, max_hops=self.request.max_hops, timeout_s=self.request.timeout_s)
        if name == "linux":
            return "linux.traceroute", parse_linux_trace, linux_trace_argv(self.request.target, max_hops=self.request.max_hops, timeout_s=self.request.timeout_s)
        raise PolicyError("native trace is supported only on Windows and Ubuntu")

    async def __call__(self, context: TaskContext) -> None:
        try:
            source, parser, argv = self._adapter()
        except PolicyError:
            # There is still one evidence record per authorized step; this is
            # explicit unsupported capability evidence, not an empty route.
            for step in context.plan.preview.steps:
                prepared = await context.admit(step.id)
                instant = context.wall_clock()
                context.record(Observation(f"trace-{prepared.step.attempt}-unsupported", ProbeKind.NATIVE_PATH.value, Disposition.UNAVAILABLE, EvidenceKind.UNSUPPORTED, Direction.OUTBOUND, prepared.address or prepared.step.target, instant, instant, 0, attempt=prepared.step.attempt, source="mercury.trace", detail={"reason": "windows_or_ubuntu_only"}), step_id=step.id)
                context.complete_attempt(step.id)
            return
        for step in context.plan.preview.steps:
            prepared = await context.admit(step.id)
            started_at, started = context.wall_clock(), context.monotonic()
            command_timeout = min(30.0, prepared.step.timeout_s)
            result = await self.command_runner(argv, command_timeout, MAX_TRACE_OUTPUT_BYTES)
            elapsed_ms = max(0.0, (context.monotonic() - started) * 1_000)
            target = prepared.address or prepared.step.target
            if result.outcome is CommandOutcome.MISSING_TOOL:
                context.record(Observation(f"trace-{prepared.step.attempt}-missing", ProbeKind.NATIVE_PATH.value, Disposition.UNAVAILABLE, EvidenceKind.UNSUPPORTED, Direction.OUTBOUND, target, started_at, context.wall_clock(), elapsed_ms, attempt=prepared.step.attempt, source=source, detail={"command": result.argv[0], "outcome": result.outcome.value}), step_id=step.id)
                context.complete_attempt(step.id)
                continue
            if result.outcome is CommandOutcome.PERMISSION_DENIED:
                context.record(Observation(f"trace-{prepared.step.attempt}-permission", ProbeKind.NATIVE_PATH.value, Disposition.UNAVAILABLE, EvidenceKind.PERMISSION_DENIED, Direction.OUTBOUND, target, started_at, context.wall_clock(), elapsed_ms, attempt=prepared.step.attempt, source=source, detail={"command": result.argv[0], "outcome": result.outcome.value}), step_id=step.id)
                context.complete_attempt(step.id)
                continue
            if result.outcome is CommandOutcome.TIMEOUT:
                context.record(Observation(f"trace-{prepared.step.attempt}-timeout", ProbeKind.NATIVE_PATH.value, Disposition.INCONCLUSIVE, EvidenceKind.TIMEOUT, Direction.OUTBOUND, target, started_at, context.wall_clock(), elapsed_ms, attempt=prepared.step.attempt, source=source, detail={"command": result.argv[0], "outcome": result.outcome.value}), step_id=step.id)
                context.complete_attempt(step.id)
                continue
            if result.outcome not in {CommandOutcome.SUCCESS, CommandOutcome.NONZERO}:
                context.record(Observation(f"trace-{prepared.step.attempt}-error", ProbeKind.NATIVE_PATH.value, Disposition.ERROR, EvidenceKind.EXECUTION_ERROR, Direction.OUTBOUND, target, started_at, context.wall_clock(), elapsed_ms, attempt=prepared.step.attempt, source=source, detail={"command": result.argv[0], "outcome": result.outcome.value, "error_type": result.error_type}), step_id=step.id)
                context.complete_attempt(step.id)
                continue
            try:
                hops = parser(result.stdout)
            except Exception as exc:
                context.record(Observation(f"trace-{prepared.step.attempt}-parse", ProbeKind.NATIVE_PATH.value, Disposition.ERROR, EvidenceKind.EXECUTION_ERROR, Direction.OUTBOUND, target, started_at, context.wall_clock(), elapsed_ms, attempt=prepared.step.attempt, source=source, detail={"outcome": result.outcome.value, "error_type": type(exc).__name__}), step_id=step.id)
                context.complete_attempt(step.id)
                continue
            ids: list[str] = []
            for hop in hops:
                kind = EvidenceKind.PATH_HOP if hop.answered else EvidenceKind.PATH_HOP_UNANSWERED
                disposition = Disposition.POSITIVE if hop.answered else Disposition.INCONCLUSIVE
                identifier = f"trace-{prepared.step.attempt}-hop-{hop.hop}"
                context.record(Observation(identifier, ProbeKind.NATIVE_PATH.value, disposition, kind, Direction.OUTBOUND, target, started_at, context.wall_clock(), elapsed_ms, attempt=prepared.step.attempt, source=source, detail={"hop": hop.hop, "addresses": list(hop.addresses), "raw": hop.raw, "repeat": prepared.step.attempt}), step_id=step.id)
                ids.append(identifier)
            complete = bool(hops[-1].addresses and target in hops[-1].addresses)
            final_kind = EvidenceKind.PATH_COMPLETE if complete else EvidenceKind.PATH_INCOMPLETE
            final_disposition = Disposition.POSITIVE if complete else Disposition.INCONCLUSIVE
            context.record(Observation(f"trace-{prepared.step.attempt}-complete", ProbeKind.NATIVE_PATH.value, final_disposition, final_kind, Direction.OUTBOUND, target, started_at, context.wall_clock(), elapsed_ms, attempt=prepared.step.attempt, source=source, detail={"last_hop": hops[-1].hop, "last_addresses": list(hops[-1].addresses), "repeat": prepared.step.attempt, "returncode": result.returncode}), step_id=step.id)
            context.complete_attempt(step.id)


async def run_trace(request: TraceRequest, *, history: HistoryStore, grant: ScopeGrant | None = None, service_factory=TaskService, runner_factory=TraceRunner) -> TaskResult:
    effective_grant = default_trace_grant(request) if grant is None else grant
    plan: ProbePlan = authorize_plan(compile_trace(request, grant=effective_grant))
    service = service_factory(history)
    task_id = service.submit(plan, runner_factory(request), task_kind="trace", requested_config={"profile": "native-trace-v1", "targets": [request.target], "repeats": request.repeats, "timeout_s": request.timeout_s, "purpose": "authorized bounded native route trace", "network_io": True})
    try:
        result = await service.wait(task_id)
    except asyncio.CancelledError:
        service.cancel(task_id)
        result = await asyncio.shield(service.wait(task_id))
    if type(result) is not TaskResult:
        raise RuntimeError("trace task returned an invalid result")
    return result


__all__ = [
    "MAX_TRACE_HOPS", "MAX_TRACE_REPEATS", "TraceHop", "TraceRequest", "TraceRunner",
    "compile_trace", "default_trace_grant", "linux_trace_argv", "parse_linux_trace",
    "parse_windows_trace", "run_trace", "windows_trace_argv",
]
