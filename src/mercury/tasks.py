"""One bounded task lifecycle shared by every future presentation adapter."""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Protocol

from .codec import dumps_document, observation_to_wire
from .history import HistoryStore
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
    TaskResult,
    TaskState,
    utc_now,
)
from .planner import ProbePlan, validate_plan


class TaskError(RuntimeError):
    """Task submission or lifecycle failed."""


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
        plan: ProbePlan,
        history: HistoryStore,
        cancellation: CancellationToken,
        wall_clock: Callable[[], datetime],
        monotonic: Callable[[], float],
    ) -> None:
        self.task_id = task_id
        self.plan = plan
        self.history = history
        self.cancellation = cancellation
        self.wall_clock = wall_clock
        self.monotonic = monotonic
        self.observations: list[Observation] = []
        self.conclusions: list[Conclusion] = []
        self.capabilities: list[Capability] = []
        self.errors: list[str] = []
        self.admitted = 0
        self.completed = 0
        self.generated_datagrams = 0
        self.application_bytes = 0
        self._output_bytes = 0
        # accepted + running already exist; reserve one cancellation event.
        self._event_count = 3
        self._next_global_start = self.monotonic()
        self._next_target_start: dict[str, float] = {}
        self._admission_lock = asyncio.Lock()

    @property
    def total(self) -> int:
        return self.plan.preview.estimate.logical_attempts

    async def admit(self, target: str = "") -> None:
        async with self._admission_lock:
            await self.cancellation.checkpoint()
            if self.admitted >= self.total:
                raise TaskError("runner attempted to exceed the immutable plan")
            if (
                self.admitted - self.completed
                >= self.plan.preview.limits.max_concurrency
            ):
                raise TaskError("runner exceeded the in-flight concurrency ceiling")
            target_key = target or self.plan.preview.targets[0].canonical
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
            self.admitted += 1

    def complete_attempt(self) -> None:
        if self.completed >= self.admitted:
            raise TaskError("runner completed work that was not admitted")
        self.completed += 1

    def account_io(self, *, datagrams: int = 0, application_bytes: int = 0) -> None:
        if (
            isinstance(datagrams, bool)
            or isinstance(application_bytes, bool)
            or not isinstance(datagrams, int)
            or not isinstance(application_bytes, int)
            or datagrams < 0
            or application_bytes < 0
        ):
            raise TaskError("I/O accounting values must be non-negative integers")
        next_datagrams = self.generated_datagrams + datagrams
        next_bytes = self.application_bytes + application_bytes
        if next_datagrams > self.plan.preview.estimate.generated_datagrams:
            raise TaskError("runner exceeded the immutable datagram estimate")
        if next_bytes > self.plan.preview.estimate.application_bytes:
            raise TaskError("runner exceeded the immutable application-byte estimate")
        self.generated_datagrams = next_datagrams
        self.application_bytes = next_bytes

    def record(self, observation: Observation) -> None:
        if self.admitted == 0:
            raise TaskError("runner produced evidence before admitting work")
        encoded_bytes = len(
            dumps_document(observation_to_wire(observation)).encode("utf-8")
        )
        if (
            self._output_bytes + encoded_bytes
            > self.plan.preview.limits.max_output_bytes
        ):
            raise TaskError("task output budget exhausted")
        if self._event_count + 2 > self.plan.preview.limits.max_events:
            raise TaskError("task event budget exhausted")
        self._output_bytes += encoded_bytes
        self.observations.append(observation)
        self._event_count += 1
        self.history.append_event(
            task_id=self.task_id,
            event_type="observation",
            payload={
                "observation_id": observation.id,
                "disposition": observation.disposition.value,
                "evidence_kind": observation.evidence_kind.value,
                "observation_count": len(self.observations),
                "total": self.total,
            },
            occurred_at=observation.ended_at,
        )

    def add_conclusion(self, conclusion: Conclusion) -> None:
        self.conclusions.append(conclusion)

    def add_capability(self, capability: Capability) -> None:
        self.capabilities.append(capability)


class SyntheticRunner:
    """Deterministic offline work used only for lifecycle verification."""

    def __init__(self, *, delay_s: float = 0.0) -> None:
        if not 0 <= delay_s <= 60:
            raise ValueError("synthetic delay must be within 0..60 seconds")
        self.delay_s = delay_s

    async def __call__(self, context: TaskContext) -> None:
        for index in range(context.total):
            await context.admit()
            started_at = context.wall_clock()
            started_mono = context.monotonic()
            await context.cancellation.wait_or_timeout(self.delay_s)
            ended_mono = context.monotonic()
            ended_at = context.wall_clock()
            context.record(
                Observation(
                    id=f"{context.task_id}:obs:{index + 1}",
                    probe="synthetic",
                    disposition=Disposition.POSITIVE,
                    evidence_kind=EvidenceKind.LOCAL_FACT,
                    direction=Direction.LOCAL,
                    target="offline",
                    started_at=started_at,
                    ended_at=ended_at,
                    duration_ms=max(0.0, (ended_mono - started_mono) * 1000),
                    attempt=index + 1,
                    source="mercury.synthetic",
                    detail={"index": index + 1, "network_io": False},
                )
            )
            context.complete_attempt()


def _derive_conclusion(
    observations: tuple[Observation, ...],
    *,
    cancelled: bool,
    failed: bool,
) -> tuple[Conclusion, ...]:
    if not observations:
        return ()
    ids = tuple(item.id for item in observations)
    dispositions = {item.disposition for item in observations}
    if failed or Disposition.ERROR in dispositions:
        health = Health.FAILED
        confidence = Confidence.HIGH
        summary = "Task recorded an execution error; prior evidence is retained."
    elif cancelled:
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
            limitations=(
                "This conclusion does not infer facts not present in observations.",
            ),
        ),
    )


def _record_terminal_observation(
    context: TaskContext,
    observation: Observation,
) -> None:
    """Best-effort terminal evidence without risking loss of finalization."""
    if context.admitted == 0 and context.total > 0:
        context.admitted = 1
    try:
        context.record(observation)
        if context.completed < context.admitted:
            context.complete_attempt()
    except Exception as exc:
        context.errors.append(
            f"terminal evidence could not be recorded: {type(exc).__name__}: {exc}"
        )


class TaskService:
    def __init__(
        self,
        history: HistoryStore,
        *,
        wall_clock: Callable[[], datetime] = utc_now,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.history = history
        self._wall_clock = wall_clock
        self._monotonic = monotonic
        self._tokens: dict[str, CancellationToken] = {}
        self._tasks: dict[str, asyncio.Task[TaskResult]] = {}
        self._results: dict[str, TaskResult] = {}

    def submit(
        self,
        plan: ProbePlan,
        runner: Runner,
        *,
        task_kind: str,
        requested_config: dict[str, object] | None = None,
        task_id: str | None = None,
    ) -> str:
        validation_time = self._wall_clock()
        validate_plan(plan, now=validation_time)
        identifier = task_id or str(uuid.uuid4())
        if identifier in self._tasks or identifier in self._results:
            raise TaskError(f"duplicate task ID {identifier!r}")
        request = dict(requested_config or {})
        self.history.create_task(
            task_id=identifier,
            task_kind=task_kind,
            request=request,
            plan=plan.to_wire(),
            created_at=validation_time,
        )
        self.history.append_event(
            task_id=identifier,
            event_type="accepted",
            payload={
                "state": TaskState.PENDING.value,
                "plan_digest": plan.digest,
            },
            occurred_at=self._wall_clock(),
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
            ),
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
        return await task

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
    ) -> TaskResult:
        started_at = self._wall_clock()
        context = TaskContext(
            task_id=task_id,
            plan=plan,
            history=self.history,
            cancellation=token,
            wall_clock=self._wall_clock,
            monotonic=self._monotonic,
        )
        failed = False
        cancelled = False
        self.history.mark_running(task_id, at=started_at)
        self.history.append_event(
            task_id=task_id,
            event_type="running",
            payload={"state": TaskState.RUNNING.value},
            occurred_at=started_at,
        )
        try:
            async with asyncio.timeout(plan.preview.limits.max_duration_s):
                await runner(context)
        except CooperativeCancellation:
            cancelled = True
        except TimeoutError:
            failed = True
            context.errors.append("task duration budget exhausted")
            instant = self._wall_clock()
            _record_terminal_observation(
                context,
                Observation(
                    id=f"{task_id}:timeout",
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
            context.errors.append(f"{type(exc).__name__}: {exc}")
            instant = self._wall_clock()
            _record_terminal_observation(
                context,
                Observation(
                    id=f"{task_id}:error",
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
                        "error_type": type(exc).__name__,
                        "message": str(exc)[:2048],
                    },
                ),
            )
        if token.cancelled:
            cancelled = True
        ended_at = self._wall_clock()
        state = (
            TaskState.CANCELLED
            if cancelled
            else TaskState.FAILED
            if failed
            else TaskState.COMPLETED
        )
        observations = tuple(context.observations)
        conclusions = tuple(context.conclusions) or _derive_conclusion(
            observations, cancelled=cancelled, failed=failed
        )
        effective = EffectiveConfig(
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
        result = TaskResult(
            task_id=task_id,
            task_kind=task_kind,
            direction=Direction.LOCAL,
            target=",".join(effective.targets),
            state=state,
            started_at=started_at,
            ended_at=ended_at,
            requested_config=requested_config,
            effective_config=effective,
            progress=Progress(
                admitted=context.admitted,
                completed=context.completed,
                total=context.total,
            ),
            observations=observations,
            conclusions=conclusions,
            capabilities=tuple(context.capabilities),
            errors=tuple(context.errors),
        )
        self.history.append_event(
            task_id=task_id,
            event_type="terminal",
            payload={
                "state": state.value,
                "completed": context.completed,
                "total": context.total,
            },
            occurred_at=ended_at,
        )
        self.history.finish_task(result)
        self._results[task_id] = result
        self._tokens.pop(task_id, None)
        return result


__all__ = [
    "CancellationToken",
    "CooperativeCancellation",
    "Runner",
    "SyntheticRunner",
    "TaskContext",
    "TaskError",
    "TaskService",
]
