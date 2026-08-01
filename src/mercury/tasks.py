"""One bounded task lifecycle shared by every future presentation adapter."""

from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Callable, Protocol

from .codec import (
    capability_to_wire,
    conclusion_to_wire,
    observation_to_wire,
    dumps_document,
    result_to_json,
)
from .history import (
    HistoryRecord,
    HistoryStore,
    assert_persistence_safe,
    project_history_request,
    sanitize_exception,
    sanitize_persisted_text,
)
from .models import (
    Capability,
    Conclusion,
    Confidence,
    Direction,
    Disposition,
    EffectiveConfig,
    EvidenceKind,
    Health,
    Observation,
    Progress,
    ProbeKind,
    TaskResult,
    TaskState,
    utc_now,
)
from .planner import PreparedStep, ProbePlan, validate_plan
from .policy import Resolver


class TaskError(RuntimeError):
    """Task submission or lifecycle failed."""


MAX_CONTEXT_CONCLUSIONS = 256
MAX_CONTEXT_CAPABILITIES = 256
MAX_CONTEXT_ERRORS = 256
LEASE_FINALIZATION_GRACE_SECONDS = 60
_OUTPUT_BUDGET_ERROR = (
    "task result exceeded the output budget; detailed evidence was omitted"
)
_RESERVED_TASK_OBSERVATION_IDS = frozenset(
    {
        "task-cancelled",
        "task-execution-error",
        "task-finalization-error",
        "task-output-budget",
        "task-timeout",
    }
)
_RESERVED_STEP_DETAIL_KEYS = frozenset(
    {
        "plan_step_id",
        "probe_kind",
        "planned_target",
        "planned_address",
        "port",
        "transport",
        "scope_id",
        "source_hostname",
        "resolution_slot",
        "server_name",
        "http_scheme",
        "max_hops",
        "timeout_s",
        "required",
        "payload_metadata",
        "cost",
        "dns_changed",
        "preflight_rejected",
        "rejection_code",
    }
)
_ALLOWED_EVIDENCE = {
    ProbeKind.LOCAL_SNAPSHOT: frozenset({EvidenceKind.LOCAL_FACT, EvidenceKind.UNSUPPORTED, EvidenceKind.PERMISSION_DENIED, EvidenceKind.EXECUTION_ERROR}),
    ProbeKind.SYSTEM_DNS: frozenset({EvidenceKind.DNS_ANSWER, EvidenceKind.DNS_FAILURE, EvidenceKind.TIMEOUT, EvidenceKind.EXECUTION_ERROR}),
    ProbeKind.TCP_CONNECT: frozenset({EvidenceKind.TCP_CONNECTED, EvidenceKind.TCP_REFUSED, EvidenceKind.TCP_RESET, EvidenceKind.NETWORK_UNREACHABLE, EvidenceKind.HOST_UNREACHABLE, EvidenceKind.ADMIN_PROHIBITED, EvidenceKind.TIMEOUT, EvidenceKind.EXECUTION_ERROR}),
    ProbeKind.UDP_EXCHANGE: frozenset({EvidenceKind.UDP_APPLICATION_REPLY, EvidenceKind.ICMP_UNREACHABLE, EvidenceKind.NETWORK_UNREACHABLE, EvidenceKind.HOST_UNREACHABLE, EvidenceKind.ADMIN_PROHIBITED, EvidenceKind.TIMEOUT, EvidenceKind.SILENT, EvidenceKind.EXECUTION_ERROR}),
    ProbeKind.TLS_HANDSHAKE: frozenset({EvidenceKind.TLS_HANDSHAKE, EvidenceKind.TLS_VERIFICATION_FAILED, EvidenceKind.TLS_HANDSHAKE_FAILED, EvidenceKind.TCP_REFUSED, EvidenceKind.TCP_RESET, EvidenceKind.NETWORK_UNREACHABLE, EvidenceKind.HOST_UNREACHABLE, EvidenceKind.TIMEOUT, EvidenceKind.EXECUTION_ERROR}),
    ProbeKind.HTTP_EXCHANGE: frozenset({EvidenceKind.HTTP_RESPONSE, EvidenceKind.TLS_VERIFICATION_FAILED, EvidenceKind.TLS_HANDSHAKE_FAILED, EvidenceKind.TCP_REFUSED, EvidenceKind.TCP_RESET, EvidenceKind.NETWORK_UNREACHABLE, EvidenceKind.HOST_UNREACHABLE, EvidenceKind.TIMEOUT, EvidenceKind.EXECUTION_ERROR}),
    ProbeKind.NATIVE_PING: frozenset({EvidenceKind.NATIVE_PING_REPLY, EvidenceKind.NATIVE_PING_FAILURE, EvidenceKind.ICMP_UNREACHABLE, EvidenceKind.NETWORK_UNREACHABLE, EvidenceKind.HOST_UNREACHABLE, EvidenceKind.ADMIN_PROHIBITED, EvidenceKind.TIMEOUT, EvidenceKind.SILENT, EvidenceKind.UNSUPPORTED, EvidenceKind.PERMISSION_DENIED, EvidenceKind.EXECUTION_ERROR}),
    ProbeKind.NATIVE_PATH: frozenset({EvidenceKind.PATH_HOP, EvidenceKind.PATH_HOP_UNANSWERED, EvidenceKind.PATH_COMPLETE, EvidenceKind.PATH_INCOMPLETE, EvidenceKind.TIMEOUT, EvidenceKind.UNSUPPORTED, EvidenceKind.PERMISSION_DENIED, EvidenceKind.EXECUTION_ERROR}),
}


def _effective_config(plan: ProbePlan) -> EffectiveConfig:
    return EffectiveConfig(
        profile=plan.preview.profile,
        targets=tuple(target.canonical for target in plan.preview.targets),
        authorized=plan.preview.scope.attested,
        policy_digest=plan.digest,
        budget={
            "limits": plan.preview.limits.to_wire(),
            "estimate": plan.preview.estimate.to_wire(),
            "logical_units": {
                "rate": "attempt_starts_per_second",
                "datagrams": "mercury_generated_udp_datagrams",
                "bytes": "application_payload_bytes",
            },
        },
        warnings=(
            "Packet and byte counters exclude kernel retransmissions and framing.",
        ),
    )


def _result_target(effective: EffectiveConfig) -> str:
    joined = ",".join(effective.targets)
    if len(joined) <= 1_024:
        return joined
    return f"{effective.targets[0]} (+{len(effective.targets) - 1} more targets)"


def _make_result(
    *,
    task_id: str,
    task_kind: str,
    state: TaskState,
    started_at: datetime,
    ended_at: datetime,
    requested_config: dict[str, object],
    effective_config: EffectiveConfig,
    progress: Progress,
    observations: tuple[Observation, ...] = (),
    conclusions: tuple[Conclusion, ...] = (),
    capabilities: tuple[Capability, ...] = (),
    errors: tuple[str, ...] = (),
) -> TaskResult:
    return TaskResult(
        task_id=task_id,
        task_kind=task_kind,
        direction=Direction.LOCAL,
        target=_result_target(effective_config),
        state=state,
        started_at=started_at,
        ended_at=max(started_at, ended_at),
        requested_config=requested_config,
        effective_config=effective_config,
        progress=progress,
        observations=observations,
        conclusions=conclusions,
        capabilities=capabilities,
        errors=errors,
    )


def _result_bytes(result: TaskResult) -> int:
    return len(result_to_json(result).encode("utf-8"))


def _output_budget_evidence(
    instant: datetime,
) -> tuple[Observation, Conclusion]:
    observation = Observation(
        id="task-output-budget",
        probe="task_output",
        disposition=Disposition.ERROR,
        evidence_kind=EvidenceKind.EXECUTION_ERROR,
        direction=Direction.LOCAL,
        target="task",
        started_at=instant,
        ended_at=instant,
        duration_ms=0.0,
        source="mercury.tasks",
        detail={"scope": "aggregate_result"},
    )
    conclusion = Conclusion(
        id="task-output-summary",
        title="Task output was bounded",
        summary=(
            "The full result exceeded its authorized output ceiling; "
            "detailed evidence was omitted."
        ),
        health=Health.FAILED,
        confidence=Confidence.HIGH,
        observation_ids=(observation.id,),
        limitations=("Only the bounded terminal summary was retained.",),
    )
    return observation, conclusion


def _output_budget_result(
    *,
    task_id: str,
    task_kind: str,
    started_at: datetime,
    ended_at: datetime,
    requested_config: dict[str, object],
    effective_config: EffectiveConfig,
    progress: Progress,
) -> TaskResult:
    observation, conclusion = _output_budget_evidence(max(started_at, ended_at))
    return _make_result(
        task_id=task_id,
        task_kind=task_kind,
        state=TaskState.FAILED,
        started_at=started_at,
        ended_at=ended_at,
        requested_config=requested_config,
        effective_config=effective_config,
        progress=progress,
        observations=(observation,),
        conclusions=(conclusion,),
        errors=(_OUTPUT_BUDGET_ERROR,),
    )


def _recovered_task_result(
    record: HistoryRecord,
    recovered_at: datetime,
) -> TaskResult:
    plan = record.plan
    profile = plan.get("profile")
    if type(profile) is not str or not profile or len(profile) > 128:
        profile = "recovered-task"
    raw_targets = plan.get("targets")
    targets = (
        tuple(raw_targets)
        if isinstance(raw_targets, (list, tuple))
        and raw_targets
        and all(
            type(target) is str and target and len(target) <= 1_024
            for target in raw_targets
        )
        else ("task",)
    )
    scope = plan.get("scope")
    authorized = (
        scope.get("attested")
        if isinstance(scope, Mapping)
        and type(scope.get("attested")) is bool
        else False
    )
    digest = plan.get("digest")
    if type(digest) is not str or not digest:
        raise TaskError("recovery plan has no digest")
    limits = plan.get("limits")
    estimate = plan.get("estimate")
    limits = dict(limits) if isinstance(limits, Mapping) else {}
    estimate = dict(estimate) if isinstance(estimate, Mapping) else {}
    total = estimate.get("logical_attempts", 0)
    if type(total) is not int or total < 0:
        total = 0
    effective = EffectiveConfig(
        profile=profile,
        targets=targets,
        authorized=authorized,
        policy_digest=digest,
        budget={
            "limits": limits,
            "estimate": estimate,
            "logical_units": {
                "rate": "attempt_starts_per_second",
                "datagrams": "mercury_generated_udp_datagrams",
                "bytes": "application_payload_bytes",
            },
        },
        warnings=(
            "Volatile partial evidence was unavailable after process interruption.",
        ),
    )
    instant = max(record.created_at, recovered_at)
    observation = Observation(
        id="task-process-interrupted",
        probe="task_recovery",
        disposition=Disposition.ERROR,
        evidence_kind=EvidenceKind.EXECUTION_ERROR,
        direction=Direction.LOCAL,
        target="task",
        started_at=instant,
        ended_at=instant,
        duration_ms=0.0,
        source="mercury.tasks",
        detail={
            "error_type": "process_interrupted",
            "scope": "aggregate_task",
        },
    )
    result = _make_result(
        task_id=record.task_id,
        task_kind=record.task_kind,
        state=TaskState.FAILED,
        started_at=record.created_at,
        ended_at=instant,
        requested_config=dict(record.request),
        effective_config=effective,
        progress=Progress(admitted=0, completed=0, total=total),
        observations=(observation,),
        conclusions=_derive_conclusion(
            (observation,),
            state=TaskState.FAILED,
        ),
        errors=(
            "task owner lease expired; volatile partial evidence was unavailable",
        ),
    )
    return result


class CooperativeCancellation(Exception):
    """A runner observed the task's cancellation token."""


class Runner(Protocol):
    async def __call__(self, context: "TaskContext") -> None: ...


@dataclass(slots=True)
class CancellationToken:
    _event: asyncio.Event

    @classmethod
    def create(cls) -> "CancellationToken":
        return cls(asyncio.Event())

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def cancel(self) -> None:
        self._event.set()

    async def checkpoint(self) -> None:
        if self.cancelled:
            raise CooperativeCancellation

    async def wait_or_timeout(self, delay: float) -> None:
        if delay <= 0:
            await self.checkpoint()
            return
        try:
            await asyncio.wait_for(self._event.wait(), timeout=delay)
        except TimeoutError:
            return
        raise CooperativeCancellation


class TaskContext:
    def __init__(
        self,
        *,
        task_id: str,
        task_kind: str,
        plan: ProbePlan,
        requested_config: dict[str, object],
        started_at: datetime,
        history: HistoryStore,
        cancellation: CancellationToken,
        wall_clock: Callable[[], datetime],
        monotonic: Callable[[], float],
        resolver: Resolver | None,
    ) -> None:
        self.task_id = task_id
        self.task_kind = task_kind
        self.plan = plan
        self.requested_config = requested_config
        self.started_at = started_at
        self.effective_config = _effective_config(plan)
        self.history = history
        self.cancellation = cancellation
        self.wall_clock = wall_clock
        self.monotonic = monotonic
        self.resolver = resolver
        self._observations: list[Observation] = []
        self._conclusions: list[Conclusion] = []
        self._capabilities: list[Capability] = []
        self._errors: list[str] = []
        self.admitted = 0
        self.completed = 0
        self.generated_datagrams = 0
        self.application_bytes = 0
        self.logical_packets = 0
        # accepted + running already exist; reserve one cancellation event.
        self._event_count = 3
        self._next_global_start = self.monotonic()
        self._next_target_start: dict[str, float] = {}
        self._steps = {step.id: step for step in plan.preview.steps}
        self._admitted_steps: set[str] = set()
        self._prepared_steps: dict[str, PreparedStep] = {}
        self._observed_steps: set[str] = set()
        self._completed_steps: set[str] = set()
        self._step_counts = {
            step.id: {"observations": 0, "capabilities": 0, "conclusions": 0, "errors": 0, "output_bytes": 0}
            for step in plan.preview.steps
        }
        self._admission_lock = asyncio.Lock()

    @property
    def total(self) -> int:
        return self.plan.preview.estimate.logical_attempts

    @property
    def observations(self) -> tuple[Observation, ...]:
        return tuple(self._observations)

    @property
    def conclusions(self) -> tuple[Conclusion, ...]:
        return tuple(self._conclusions)

    @property
    def capabilities(self) -> tuple[Capability, ...]:
        return tuple(self._capabilities)

    @property
    def errors(self) -> tuple[str, ...]:
        return tuple(self._errors)

    def _candidate_result(
        self,
        *,
        observations: tuple[Observation, ...] | None = None,
        conclusions: tuple[Conclusion, ...] | None = None,
        capabilities: tuple[Capability, ...] | None = None,
        errors: tuple[str, ...] | None = None,
    ) -> TaskResult:
        return _make_result(
            task_id=self.task_id,
            task_kind=self.task_kind,
            state=TaskState.COMPLETED,
            started_at=self.started_at,
            ended_at=self.wall_clock(),
            requested_config=self.requested_config,
            effective_config=self.effective_config,
            progress=Progress(
                admitted=self.admitted,
                completed=self.completed,
                total=self.total,
            ),
            observations=observations
            if observations is not None
            else tuple(self._observations),
            conclusions=conclusions
            if conclusions is not None
            else tuple(self._conclusions),
            capabilities=capabilities
            if capabilities is not None
            else tuple(self._capabilities),
            errors=errors if errors is not None else tuple(self._errors),
        )

    def _assert_output_fits(self, **changes: object) -> None:
        try:
            candidate = self._candidate_result(**changes)
        except Exception as exc:
            raise TaskError("runner contribution would make the result invalid") from exc
        size = _result_bytes(candidate)
        if size > self.plan.preview.limits.max_output_bytes:
            raise TaskError(
                "task output budget exhausted "
                f"({size}>{self.plan.preview.limits.max_output_bytes} bytes)"
            )

    async def admit(
        self,
        step_id: str,
        *,
        payload: bytes | None = None,
    ) -> PreparedStep:
        if type(step_id) is not str or step_id not in self._steps:
            raise TaskError("runner requested an unknown plan step ID")
        await self.cancellation.checkpoint()
        async with self._admission_lock:
            await self.cancellation.checkpoint()
            if step_id in self._admitted_steps:
                raise TaskError("runner attempted to admit a plan step twice")
            if self.admitted >= self.total:
                raise TaskError("runner attempted to exceed the immutable plan")
            if (
                self.admitted - self.completed
                >= self.plan.preview.limits.max_concurrency
            ):
                raise TaskError("runner exceeded the in-flight concurrency ceiling")
            preflight_kwargs: dict[str, object] = {"now": self.wall_clock()}
            if self.resolver is not None:
                preflight_kwargs["resolver"] = self.resolver
            elif self._steps[step_id].source_hostname is not None:
                # Production hostname rechecks use the same bounded helper as
                # planning and system-DNS evidence.  The plan still performs
                # its normal exact slot/scope comparison synchronously over
                # this one finite answer set.
                from .resolver import resolve_addresses
                step = self._steps[step_id]
                resolved = await resolve_addresses(
                    step.source_hostname,
                    operation_timeout=step.timeout_s,
                    hard_deadline=step.timeout_s,
                )
                preflight_kwargs["resolver"] = lambda _hostname: resolved.addresses
            if payload is not None:
                preflight_kwargs["payload"] = payload
            prepared = self.plan.preflight_step(step_id, **preflight_kwargs)
            target_key = prepared.address or prepared.step.target
            now = self.monotonic()
            next_target = self._next_target_start.get(target_key, now)
            start_at = max(now, self._next_global_start, next_target)
            await self.cancellation.wait_or_timeout(max(0.0, start_at - now))
            actual_start = self.monotonic()
            self._next_global_start = (
                max(start_at, actual_start)
                + 1 / self.plan.preview.limits.max_global_rate
            )
            self._next_target_start[target_key] = (
                max(start_at, actual_start)
                + 1 / self.plan.preview.limits.max_target_rate
            )
            next_datagrams = (
                self.generated_datagrams
                + prepared.step.cost.generated_datagrams
            )
            next_bytes = (
                self.application_bytes + prepared.step.cost.application_bytes
            )
            next_packets = self.logical_packets + prepared.step.cost.logical_packets
            if next_datagrams > self.plan.preview.estimate.generated_datagrams:
                raise TaskError("step admission exceeded the datagram reservation")
            if next_bytes > self.plan.preview.estimate.application_bytes:
                raise TaskError(
                    "step admission exceeded the application-byte reservation"
                )
            if next_packets > self.plan.preview.estimate.logical_packets:
                raise TaskError("step admission exceeded the logical-packet reservation")
            self.generated_datagrams = next_datagrams
            self.application_bytes = next_bytes
            self.logical_packets = next_packets
            self._admitted_steps.add(step_id)
            self._prepared_steps[step_id] = prepared
            self.admitted += 1
            return prepared

    def complete_attempt(self, step_id: str) -> None:
        if type(step_id) is not str or step_id not in self._admitted_steps:
            raise TaskError("runner completed work that was not admitted")
        if step_id in self._completed_steps:
            raise TaskError("runner completed a plan step twice")
        if step_id not in self._observed_steps:
            raise TaskError("runner cannot complete a plan step without evidence")
        self._completed_steps.add(step_id)
        self.completed += 1

    def account_io(self, *, datagrams: int = 0, application_bytes: int = 0) -> None:
        raise TaskError(
            "I/O reservations are service-controlled by the authorized plan step"
        )

    def record(self, observation: Observation, *, step_id: str | None = None) -> None:
        if type(observation) is not Observation:
            raise TaskError("runner evidence must be an Observation")
        if self.admitted == 0:
            raise TaskError("runner produced evidence before admitting work")
        if step_id is None:
            raise TaskError("runner evidence must identify its admitted step")
        prepared = self._prepared_steps.get(step_id)
        if prepared is None:
            raise TaskError("runner attached evidence to an unadmitted plan step")
        if step_id in self._completed_steps:
            raise TaskError("runner attached evidence to a completed plan step")
        expected_target = prepared.address or prepared.step.target
        if observation.target != expected_target:
            raise TaskError("runner evidence target does not match its admitted step")
        if observation.attempt != prepared.step.attempt:
            raise TaskError("runner evidence attempt does not match its admitted step")
        if observation.probe != prepared.step.probe_kind.value:
            raise TaskError("runner evidence probe does not match its admitted step")
        expected_direction = (
            Direction.LOCAL
            if prepared.step.probe_kind is ProbeKind.LOCAL_SNAPSHOT
            else Direction.OUTBOUND
        )
        if observation.direction is not expected_direction:
            raise TaskError("runner evidence direction does not match its admitted step")
        if observation.evidence_kind not in _ALLOWED_EVIDENCE[prepared.step.probe_kind]:
            raise TaskError("runner evidence kind does not match its admitted probe")
        conflicting = _RESERVED_STEP_DETAIL_KEYS.intersection(observation.detail)
        if conflicting:
            raise TaskError(
                "runner cannot supply reserved step evidence fields: "
                + ", ".join(sorted(conflicting))
            )
        if observation.id in _RESERVED_TASK_OBSERVATION_IDS:
            raise TaskError("runner cannot use a reserved task observation ID")
        detail = dict(observation.detail)
        detail.update(
            {
                "plan_step_id": step_id,
                "probe_kind": prepared.step.probe_kind.value,
                "planned_target": prepared.step.target,
                "planned_address": prepared.step.address,
                "port": prepared.step.port,
                "transport": prepared.step.transport.value if prepared.step.transport else None,
                "scope_id": prepared.step.scope_id,
                "source_hostname": prepared.step.source_hostname,
                "resolution_slot": prepared.step.resolution_slot,
                "server_name": prepared.step.server_name,
                "http_scheme": prepared.step.http_scheme,
                "max_hops": prepared.step.max_hops,
                "timeout_s": prepared.step.timeout_s,
                "required": prepared.step.required,
                "payload_metadata": prepared.step.payload.to_wire(),
                "cost": prepared.step.cost.to_wire(),
                "dns_changed": prepared.dns_changed,
            }
        )
        bound_observation = replace(observation, detail=detail)
        counts = self._step_counts[step_id]
        contribution = len(dumps_document(observation_to_wire(bound_observation)).encode("utf-8"))
        if counts["observations"] >= prepared.step.cost.max_observations:
            raise TaskError("step observation reservation exhausted")
        if counts["output_bytes"] + contribution > prepared.step.cost.max_output_bytes:
            raise TaskError("step output reservation exhausted")
        self._append_observation(bound_observation)
        counts["observations"] += 1
        counts["output_bytes"] += contribution
        self._observed_steps.add(step_id)

    def _record_task_observation(self, observation: Observation) -> None:
        """Record aggregate terminal evidence without changing probe progress."""
        self._append_observation(observation)

    def _append_observation(self, observation: Observation) -> None:
        if type(observation) is not Observation:
            raise TaskError("runner evidence must be an Observation")
        wire = observation_to_wire(observation)
        assert_persistence_safe(wire, path="$.result.observations[]")
        if self._event_count + 2 > self.plan.preview.limits.max_events:
            raise TaskError("task event budget exhausted")
        candidate = (*self._observations, observation)
        self._assert_output_fits(observations=candidate)
        self._observations.append(observation)
        self._event_count += 1
        self.history.append_event(
            task_id=self.task_id,
            event_type="observation",
            payload={
                "observation_id": observation.id,
                "disposition": observation.disposition.value,
                "evidence_kind": observation.evidence_kind.value,
                "probe_kind": observation.probe,
                "plan_step_id": observation.detail.get("plan_step_id"),
                "preflight_rejected": observation.detail.get("preflight_rejected"),
                "rejection_code": observation.detail.get("rejection_code"),
                "observation_count": len(self._observations),
                "total": self.total,
            },
            occurred_at=observation.ended_at,
        )

    def add_conclusion(self, conclusion: Conclusion, *, step_id: str | None = None) -> None:
        if type(conclusion) is not Conclusion:
            raise TaskError("runner conclusion must be a Conclusion")
        if conclusion.id == "task-summary":
            raise TaskError("runner cannot use the reserved task-summary ID")
        if step_id is not None:
            counts = self._step_counts.get(step_id)
            if step_id not in self._admitted_steps or step_id in self._completed_steps or counts is None:
                raise TaskError("runner conclusion is not attributed to an admitted step")
            if counts["conclusions"] >= self._prepared_steps[step_id].step.cost.max_conclusions:
                raise TaskError("step conclusion reservation exhausted")
        if len(self._conclusions) >= MAX_CONTEXT_CONCLUSIONS:
            raise TaskError("too many task conclusions")
        assert_persistence_safe(
            conclusion_to_wire(conclusion),
            path="$.result.conclusions[]",
        )
        candidate = (*self._conclusions, conclusion)
        self._assert_output_fits(conclusions=candidate)
        self._conclusions.append(conclusion)
        if step_id is not None:
            self._step_counts[step_id]["conclusions"] += 1

    def add_capability(self, capability: Capability, *, step_id: str | None = None) -> None:
        if type(capability) is not Capability:
            raise TaskError("runner capability must be a Capability")
        if step_id is not None:
            counts = self._step_counts.get(step_id)
            if step_id not in self._admitted_steps or step_id in self._completed_steps or counts is None:
                raise TaskError("runner capability is not attributed to an admitted step")
            if counts["capabilities"] >= self._prepared_steps[step_id].step.cost.max_capabilities:
                raise TaskError("step capability reservation exhausted")
        if len(self._capabilities) >= MAX_CONTEXT_CAPABILITIES:
            raise TaskError("too many task capabilities")
        assert_persistence_safe(
            capability_to_wire(capability),
            path="$.result.capabilities[]",
        )
        candidate = (*self._capabilities, capability)
        self._assert_output_fits(capabilities=candidate)
        self._capabilities.append(capability)
        if step_id is not None:
            self._step_counts[step_id]["capabilities"] += 1

    def add_error(self, value: object, *, step_id: str | None = None) -> bool:
        if step_id is not None:
            counts = self._step_counts.get(step_id)
            if step_id not in self._admitted_steps or step_id in self._completed_steps or counts is None:
                raise TaskError("runner error is not attributed to an admitted step")
            if counts["errors"] >= self._prepared_steps[step_id].step.cost.max_errors:
                return False
        if len(self._errors) >= MAX_CONTEXT_ERRORS:
            return False
        message = sanitize_persisted_text(value, maximum=1_024)
        candidate = (*self._errors, message or "unspecified task error")
        try:
            self._assert_output_fits(errors=candidate)
        except TaskError:
            return False
        self._errors.append(candidate[-1])
        if step_id is not None:
            self._step_counts[step_id]["errors"] += 1
        return True


class SyntheticRunner:
    """Deterministic offline work used only for lifecycle verification."""

    def __init__(self, *, delay_s: float = 0.0) -> None:
        if not 0 <= delay_s <= 60:
            raise ValueError("synthetic delay must be within 0..60 seconds")
        self.delay_s = delay_s

    async def __call__(self, context: TaskContext) -> None:
        kinds = {
            ProbeKind.LOCAL_SNAPSHOT: EvidenceKind.LOCAL_FACT,
            ProbeKind.SYSTEM_DNS: EvidenceKind.DNS_ANSWER,
            ProbeKind.TCP_CONNECT: EvidenceKind.TCP_CONNECTED,
            ProbeKind.UDP_EXCHANGE: EvidenceKind.UDP_APPLICATION_REPLY,
            ProbeKind.TLS_HANDSHAKE: EvidenceKind.TLS_HANDSHAKE,
            ProbeKind.HTTP_EXCHANGE: EvidenceKind.HTTP_RESPONSE,
            ProbeKind.NATIVE_PING: EvidenceKind.NATIVE_PING_REPLY,
            ProbeKind.NATIVE_PATH: EvidenceKind.PATH_COMPLETE,
        }
        for index, step in enumerate(context.plan.preview.steps, 1):
            prepared = await context.admit(step.id)
            started_at = context.wall_clock()
            started_mono = context.monotonic()
            await context.cancellation.wait_or_timeout(self.delay_s)
            ended_mono = context.monotonic()
            ended_at = context.wall_clock()
            context.record(
                Observation(
                    id=f"{context.task_id}:obs:{index}",
                    probe=prepared.step.probe_kind.value,
                    disposition=Disposition.POSITIVE,
                    evidence_kind=kinds[prepared.step.probe_kind],
                    direction=(Direction.LOCAL if prepared.step.probe_kind is ProbeKind.LOCAL_SNAPSHOT else Direction.OUTBOUND),
                    target=prepared.address or prepared.step.target,
                    started_at=started_at,
                    ended_at=ended_at,
                    duration_ms=max(0.0, (ended_mono - started_mono) * 1000),
                    attempt=prepared.step.attempt,
                    source="mercury.synthetic",
                    detail={"index": index, "network_io": False},
                ),
                step_id=step.id,
            )
            context.complete_attempt(step.id)


def _derive_conclusion(
    observations: tuple[Observation, ...],
    *,
    state: TaskState,
) -> tuple[Conclusion, ...]:
    if not observations:
        return ()
    cited = observations[-256:]
    ids = tuple(item.id for item in cited)
    dispositions = {item.disposition for item in observations}
    if state is TaskState.FAILED:
        health = Health.FAILED
        confidence = Confidence.HIGH
        summary = "Task recorded an execution error; prior evidence is retained."
    elif state is TaskState.CANCELLED:
        health = Health.PARTIAL
        confidence = Confidence.HIGH
        summary = "Task was cancelled; this conclusion covers partial evidence only."
    elif dispositions == {Disposition.POSITIVE}:
        health = Health.HEALTHY
        confidence = Confidence.HIGH
        summary = "All completed observations produced direct positive evidence."
    elif Disposition.INCONCLUSIVE in dispositions:
        health = Health.PARTIAL
        confidence = Confidence.LOW
        summary = "One or more observations are inconclusive; silence is not a verdict."
    elif Disposition.NEGATIVE in dispositions:
        health = Health.FAILED
        confidence = Confidence.HIGH
        summary = "At least one observation produced explicit negative evidence."
    else:
        health = Health.PARTIAL
        confidence = Confidence.UNKNOWN
        summary = "The available evidence is incomplete."
    limitations = [
        "This conclusion does not infer facts not present in observations."
    ]
    if len(cited) != len(observations):
        limitations.append(
            "The task summary cites only the latest 256 observations."
        )
    return (
        Conclusion(
            id="task-summary",
            title="Task evidence summary",
            summary=summary,
            health=health,
            confidence=confidence,
            observation_ids=ids,
            alternatives=(
                "Review each protocol-specific observation before attributing root cause.",
            ),
            limitations=tuple(limitations),
        ),
    )


def _record_terminal_observation(
    context: TaskContext,
    observation: Observation,
) -> None:
    """Best-effort terminal evidence without risking loss of finalization."""
    try:
        context._record_task_observation(observation)
    except Exception as exc:
        context.add_error(
            "terminal evidence could not be recorded: "
            + sanitize_exception(exc)
        )


def _context_progress(context: TaskContext) -> Progress:
    total = context.total
    admitted = context.admitted if type(context.admitted) is int else 0
    completed = context.completed if type(context.completed) is int else 0
    admitted = min(total, max(0, admitted))
    completed = min(admitted, max(0, completed))
    return Progress(admitted=admitted, completed=completed, total=total)


def _terminal_result(
    context: TaskContext,
    *,
    state: TaskState,
    diagnosis_groups: tuple[object, ...] | None = None,
    ended_at: datetime,
) -> TaskResult:
    observations = tuple(context.observations)
    if diagnosis_groups is None:
        derived = _derive_conclusion(observations, state=state)
    else:
        # Closed service-owned branch: callers cannot substitute a classifier.
        from .diagnosis import classify_diagnosis
        derived = (classify_diagnosis(context.plan, diagnosis_groups, observations),)
    conclusions = (*context.conclusions, *derived)
    result = _make_result(
        task_id=context.task_id,
        task_kind=context.task_kind,
        state=state,
        started_at=context.started_at,
        ended_at=ended_at,
        requested_config=context.requested_config,
        effective_config=context.effective_config,
        progress=_context_progress(context),
        observations=observations,
        conclusions=conclusions,
        capabilities=tuple(context.capabilities),
        errors=tuple(context.errors),
    )
    if _result_bytes(result) <= context.plan.preview.limits.max_output_bytes:
        return result
    return _output_budget_result(
        task_id=context.task_id,
        task_kind=context.task_kind,
        started_at=context.started_at,
        ended_at=ended_at,
        requested_config=context.requested_config,
        effective_config=context.effective_config,
        progress=_context_progress(context),
    )


def _finalization_failure_result(
    context: TaskContext,
    exc: BaseException,
    *,
    ended_at: datetime,
) -> TaskResult:
    """Build a valid failed result from only revalidated context evidence."""
    sanitized = sanitize_exception(exc)
    error_type = sanitized.partition(":")[0]
    message = sanitize_persisted_text(
        f"task finalization failed: {sanitized}",
        maximum=1_024,
    )
    instant = max(context.started_at, ended_at)
    terminal = Observation(
        id="task-finalization-error",
        probe="task_finalization",
        disposition=Disposition.ERROR,
        evidence_kind=EvidenceKind.EXECUTION_ERROR,
        direction=Direction.LOCAL,
        target="task",
        started_at=instant,
        ended_at=instant,
        duration_ms=0.0,
        source="mercury.tasks",
        detail={
            "error_type": error_type,
            "message": message,
        },
    )
    observations: list[Observation] = []
    seen: set[str] = set()
    for observation in context.observations:
        if type(observation) is not Observation or observation.id in seen:
            continue
        try:
            assert_persistence_safe(
                observation_to_wire(observation),
                path="$.result.observations[]",
            )
        except Exception:
            continue
        observations.append(observation)
        seen.add(observation.id)
    if terminal.id not in seen:
        observations.append(terminal)
    capabilities: list[Capability] = []
    for capability in context.capabilities:
        if type(capability) is not Capability:
            continue
        try:
            assert_persistence_safe(
                capability_to_wire(capability),
                path="$.result.capabilities[]",
            )
        except Exception:
            continue
        capabilities.append(capability)
    errors = tuple(
        item
        for item in context.errors
        if type(item) is str and item
    )
    errors = (*errors[: MAX_CONTEXT_ERRORS - 1], message)
    try:
        result = _make_result(
            task_id=context.task_id,
            task_kind=context.task_kind,
            state=TaskState.FAILED,
            started_at=context.started_at,
            ended_at=ended_at,
            requested_config=context.requested_config,
            effective_config=context.effective_config,
            progress=_context_progress(context),
            observations=tuple(observations),
            conclusions=_derive_conclusion(
                tuple(observations),
                state=TaskState.FAILED,
            ),
            capabilities=tuple(capabilities),
            errors=errors,
        )
    except Exception:
        result = _output_budget_result(
            task_id=context.task_id,
            task_kind=context.task_kind,
            started_at=context.started_at,
            ended_at=ended_at,
            requested_config=context.requested_config,
            effective_config=context.effective_config,
            progress=_context_progress(context),
        )
    if _result_bytes(result) <= context.plan.preview.limits.max_output_bytes:
        return result
    return _output_budget_result(
        task_id=context.task_id,
        task_kind=context.task_kind,
        started_at=context.started_at,
        ended_at=ended_at,
        requested_config=context.requested_config,
        effective_config=context.effective_config,
        progress=_context_progress(context),
    )


class TaskService:
    def __init__(
        self,
        history: HistoryStore,
        *,
        wall_clock: Callable[[], datetime] = utc_now,
        monotonic: Callable[[], float] = time.monotonic,
        resolver: Resolver | None = None,
    ) -> None:
        self.history = history
        self._wall_clock = wall_clock
        self._monotonic = monotonic
        self._resolver = resolver
        self._owner_id = uuid.uuid4().hex
        self._tokens: dict[str, CancellationToken] = {}
        self._tasks: dict[str, asyncio.Task[TaskResult]] = {}
        self._results: dict[str, TaskResult] = {}
        self.history.recover_interrupted(
            _recovered_task_result,
            now=self._wall_clock(),
        )

    def submit(
        self,
        plan: ProbePlan,
        runner: Runner,
        *,
        task_kind: str,
        requested_config: dict[str, object] | None = None,
        task_id: str | None = None,
    ) -> str:
        if task_kind == "diagnose":
            raise TaskError("diagnose tasks must use submit_diagnosis")
        validation_time = self._wall_clock()
        validate_plan(plan, now=validation_time)
        identifier = task_id or str(uuid.uuid4())
        if identifier in self._tasks or identifier in self._results:
            raise TaskError(f"duplicate task ID {identifier!r}")
        request = project_history_request(dict(requested_config or {}))
        effective = _effective_config(plan)
        try:
            fallback = _output_budget_result(
                task_id=identifier,
                task_kind=task_kind,
                started_at=validation_time,
                ended_at=validation_time,
                requested_config=request,
                effective_config=effective,
                progress=Progress(
                    admitted=0,
                    completed=0,
                    total=plan.preview.estimate.logical_attempts,
                ),
            )
        except Exception as exc:
            raise TaskError("task metadata cannot form a valid result") from exc
        fallback_bytes = _result_bytes(fallback)
        if fallback_bytes > plan.preview.limits.max_output_bytes:
            raise TaskError(
                "max_output_bytes cannot hold the canonical task result "
                f"({fallback_bytes}>{plan.preview.limits.max_output_bytes} bytes)"
            )
        self.history.create_task(
            task_id=identifier,
            task_kind=task_kind,
            request=request,
            plan=plan.to_wire(),
            owner_id=self._owner_id,
            lease_expires_at=validation_time
            + timedelta(
                seconds=plan.preview.limits.max_duration_s
                + LEASE_FINALIZATION_GRACE_SECONDS
            ),
            created_at=validation_time,
            accepted_payload={
                "state": TaskState.PENDING.value,
                "plan_digest": plan.digest,
            },
        )
        token = CancellationToken.create()
        self._tokens[identifier] = token
        self._tasks[identifier] = asyncio.create_task(
            self._execute(
                identifier,
                plan,
                runner,
                task_kind=task_kind,
                requested_config=request,
                token=token,
                diagnosis_groups=None,
            ),
            name=f"mercury:{identifier}",
        )
        return identifier

    def submit_diagnosis(
        self,
        compiled: object,
        runner: Runner,
        *,
        requested_config: dict[str, object] | None = None,
        task_id: str | None = None,
    ) -> str:
        """Submit only a frozen profile compilation through the closed branch."""
        from .profiles import CompiledDiagnosis
        if type(compiled) is not CompiledDiagnosis:
            raise TaskError("diagnose tasks require CompiledDiagnosis")
        # Dataclass validation rejects noncanonical group members; plan
        # validation remains the normal trust-boundary check in _submit.
        compiled.validate()
        return self._submit_diagnosis(
            compiled.plan, runner, compiled.required_groups,
            requested_config=requested_config, task_id=task_id,
        )

    def _submit_diagnosis(
        self,
        plan: ProbePlan,
        runner: Runner,
        groups: tuple[object, ...],
        *,
        requested_config: dict[str, object] | None,
        task_id: str | None,
    ) -> str:
        validation_time = self._wall_clock()
        validate_plan(plan, now=validation_time)
        identifier = task_id or str(uuid.uuid4())
        if identifier in self._tasks or identifier in self._results:
            raise TaskError(f"duplicate task ID {identifier!r}")
        request = project_history_request(dict(requested_config or {}))
        effective = _effective_config(plan)
        try:
            fallback = _output_budget_result(
                task_id=identifier, task_kind="diagnose", started_at=validation_time,
                ended_at=validation_time, requested_config=request, effective_config=effective,
                progress=Progress(admitted=0, completed=0, total=plan.preview.estimate.logical_attempts),
            )
        except Exception as exc:
            raise TaskError("task metadata cannot form a valid result") from exc
        if _result_bytes(fallback) > plan.preview.limits.max_output_bytes:
            raise TaskError("max_output_bytes cannot hold the canonical task result")
        self.history.create_task(
            task_id=identifier, task_kind="diagnose", request=request, plan=plan.to_wire(),
            owner_id=self._owner_id,
            lease_expires_at=validation_time + timedelta(seconds=plan.preview.limits.max_duration_s + LEASE_FINALIZATION_GRACE_SECONDS),
            created_at=validation_time,
            accepted_payload={"state": TaskState.PENDING.value, "plan_digest": plan.digest},
        )
        token = CancellationToken.create()
        self._tokens[identifier] = token
        self._tasks[identifier] = asyncio.create_task(
            self._execute(identifier, plan, runner, task_kind="diagnose", requested_config=request,
                          token=token, diagnosis_groups=groups),
            name=f"mercury:{identifier}",
        )
        return identifier

    async def run(
        self,
        plan: ProbePlan,
        runner: Runner,
        *,
        task_kind: str,
        requested_config: dict[str, object] | None = None,
        task_id: str | None = None,
    ) -> TaskResult:
        identifier = self.submit(
            plan,
            runner,
            task_kind=task_kind,
            requested_config=requested_config,
            task_id=task_id,
        )
        return await self.wait(identifier)

    def cancel(self, task_id: str) -> bool:
        token = self._tokens.get(task_id)
        task = self._tasks.get(task_id)
        if token is None or task is None or task.done() or token.cancelled:
            return False
        token.cancel()
        self.history.append_event(
            task_id=task_id,
            event_type="cancelling",
            payload={"state": "cancelling"},
            occurred_at=self._wall_clock(),
        )
        return True

    async def wait(self, task_id: str) -> TaskResult:
        if task_id in self._results:
            return self._results[task_id]
        task = self._tasks.get(task_id)
        if task is None:
            raise TaskError(f"unknown task {task_id!r}")
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError as cancellation:
            self.cancel(task_id)
            task.cancel()
            while not task.done():
                try:
                    await asyncio.shield(task)
                except asyncio.CancelledError:
                    continue
            task.result()
            raise cancellation

    def result(self, task_id: str) -> TaskResult | None:
        return self._results.get(task_id)

    async def _execute(
        self,
        task_id: str,
        plan: ProbePlan,
        runner: Runner,
        *,
        task_kind: str,
        requested_config: dict[str, object],
        token: CancellationToken,
        diagnosis_groups: tuple[object, ...] | None,
    ) -> TaskResult:
        try:
            return await self._execute_inner(
                task_id,
                plan,
                runner,
                task_kind=task_kind,
                requested_config=requested_config,
                token=token,
                diagnosis_groups=diagnosis_groups,
            )
        finally:
            self._tokens.pop(task_id, None)
            self._tasks.pop(task_id, None)

    async def _execute_inner(
        self,
        task_id: str,
        plan: ProbePlan,
        runner: Runner,
        *,
        task_kind: str,
        requested_config: dict[str, object],
        token: CancellationToken,
        diagnosis_groups: tuple[object, ...] | None,
    ) -> TaskResult:
        started_at = self._wall_clock()
        context = TaskContext(
            task_id=task_id,
            task_kind=task_kind,
            plan=plan,
            requested_config=requested_config,
            started_at=started_at,
            history=self.history,
            cancellation=token,
            wall_clock=self._wall_clock,
            monotonic=self._monotonic,
            resolver=self._resolver,
        )
        try:
            failed = False
            cancelled = False
            try:
                self.history.mark_running(
                    task_id,
                    owner_id=self._owner_id,
                    lease_expires_at=started_at
                    + timedelta(
                        seconds=plan.preview.limits.max_duration_s
                        + LEASE_FINALIZATION_GRACE_SECONDS
                    ),
                    at=started_at,
                    event_payload={"state": TaskState.RUNNING.value},
                )
                async with asyncio.timeout(plan.preview.limits.max_duration_s):
                    await runner(context)
                    if token.cancelled:
                        raise CooperativeCancellation
                    if context.completed != context.total:
                        raise TaskError(
                            "runner returned before completing every authorized "
                            "plan step"
                        )
            except (CooperativeCancellation, asyncio.CancelledError):
                token.cancel()
                cancelled = True
                instant = self._wall_clock()
                _record_terminal_observation(
                    context,
                    Observation(
                        id="task-cancelled",
                        probe="task_cancellation",
                        disposition=Disposition.CANCELLED,
                        evidence_kind=EvidenceKind.CANCELLED,
                        direction=Direction.LOCAL,
                        target="task",
                        started_at=instant,
                        ended_at=instant,
                        duration_ms=0.0,
                        source="mercury.tasks",
                        detail={"scope": "aggregate_task"},
                    ),
                )
            except TimeoutError:
                failed = True
                context.add_error("task duration budget exhausted")
                instant = self._wall_clock()
                _record_terminal_observation(
                    context,
                    Observation(
                        id="task-timeout",
                        probe="task_deadline",
                        disposition=Disposition.INCONCLUSIVE,
                        evidence_kind=EvidenceKind.TIMEOUT,
                        direction=Direction.LOCAL,
                        target="task",
                        started_at=instant,
                        ended_at=instant,
                        duration_ms=0.0,
                        attempt=max(1, context.admitted),
                        source="mercury.tasks",
                        detail={"scope": "aggregate_task_deadline"},
                    ),
                )
            except Exception as exc:  # converted at the core boundary, never hidden
                failed = True
                sanitized = sanitize_exception(exc)
                error_type = sanitized.partition(":")[0]
                context.add_error(sanitized)
                instant = self._wall_clock()
                _record_terminal_observation(
                    context,
                    Observation(
                        id="task-execution-error",
                        probe="task_runner",
                        disposition=Disposition.ERROR,
                        evidence_kind=EvidenceKind.EXECUTION_ERROR,
                        direction=Direction.LOCAL,
                        target="task",
                        started_at=instant,
                        ended_at=instant,
                        duration_ms=0.0,
                        attempt=max(1, context.admitted),
                        source="mercury.tasks",
                        detail={
                            "error_type": error_type,
                            "message": sanitized,
                        },
                    ),
                )
            if token.cancelled and not cancelled:
                cancelled = True
                instant = self._wall_clock()
                _record_terminal_observation(
                    context,
                    Observation(
                        id="task-cancelled",
                        probe="task_cancellation",
                        disposition=Disposition.CANCELLED,
                        evidence_kind=EvidenceKind.CANCELLED,
                        direction=Direction.LOCAL,
                        target="task",
                        started_at=instant,
                        ended_at=instant,
                        duration_ms=0.0,
                        source="mercury.tasks",
                        detail={"scope": "aggregate_task"},
                    ),
                )
            ended_at = self._wall_clock()
            state = (
                TaskState.FAILED
                if failed
                else TaskState.CANCELLED
                if cancelled
                else TaskState.COMPLETED
            )
            try:
                result = _terminal_result(context, state=state, ended_at=ended_at,
                                          diagnosis_groups=diagnosis_groups)
            except Exception as exc:
                result = _finalization_failure_result(
                    context,
                    exc,
                    ended_at=ended_at,
                )
            try:
                self.history.finish_task(result, owner_id=self._owner_id)
            except Exception as exc:
                result = _finalization_failure_result(
                    context,
                    exc,
                    ended_at=self._wall_clock(),
                )
                self.history.finish_task(result, owner_id=self._owner_id)
            self._results[task_id] = result
            return result
        finally:
            self._tokens.pop(task_id, None)
            self._tasks.pop(task_id, None)


__all__ = [
    "CancellationToken",
    "CooperativeCancellation",
    "Runner",
    "SyntheticRunner",
    "TaskContext",
    "TaskError",
    "TaskService",
]
