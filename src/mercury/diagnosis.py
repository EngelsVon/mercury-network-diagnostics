"""Canonical diagnosis execution and its bounded, evidence-only classifier."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence

from .inventory import collect_status
from .models import Confidence, Conclusion, Direction, Disposition, EvidenceKind, Health, Observation, ProbeKind, TaskResult
from .planner import ProbePlan
from .probes import run_protocol_probe
from .profiles import CompiledDiagnosis, ProbeGroupKey
from .tasks import TaskContext


def _group_matches(group: ProbeGroupKey, observation: Observation) -> bool:
    detail = observation.detail
    return (
        observation.probe == group.probe_kind.value
        and detail.get("planned_target", observation.target) == group.target
        and detail.get("port") == group.port
        and detail.get("server_name") == group.server_name
        and detail.get("http_scheme") == group.http_scheme
    )


def _local_prerequisites(observations: Sequence[Observation]) -> bool:
    """Require direct passive interface/address/default-route facts, not a gateway guess."""
    usable_families: set[int] = set()
    default_families: set[int] = set()
    up_interfaces = {
        str(item.detail.get("name"))
        for item in observations
        if item.probe == "local_snapshot" and item.detail.get("is_up") is True
    }
    for item in observations:
        detail = item.detail
        if item.probe == "local_snapshot" and detail.get("field") == "usable_address":
            family = detail.get("family")
            if type(family) is int:
                usable_families.add(family)
        elif item.probe == "local_snapshot" and detail.get("is_default") is True:
            family = detail.get("family")
            if type(family) is int:
                default_families.add(family)
    # Inventory copies currently preserve their original detail fields.  A
    # local-fact test fixture may instead provide an explicit usable address.
    return bool(up_interfaces) and bool(usable_families & default_families)


def classify_diagnosis(
    plan: ProbePlan,
    required_groups: Sequence[ProbeGroupKey],
    observations: Sequence[Observation],
) -> Conclusion:
    """Classify only selected endpoint evidence; no I/O, clocks, or providers."""
    del plan  # The already validated bounded plan is the authority for inputs.
    ordered = tuple(observations)
    cited = tuple(item.id for item in ordered[-16:])
    if not cited:
        # This function is called after the core's terminal evidence.  Keep a
        # defensive explicit failure for misuse rather than fabricating a ref.
        raise ValueError("diagnosis classification requires evidence")
    lifecycle_ids = {
        "task-cancelled", "task-timeout", "task-execution-error",
        "task-finalization-error", "task-output-budget",
    }
    if any(item.id in lifecycle_ids for item in ordered):
        health, confidence, summary = Health.PARTIAL, Confidence.LOW, "Selected endpoint diagnosis ended with partial lifecycle evidence."
    else:
        required = tuple(group for group in required_groups if group.probe_kind is not ProbeKind.LOCAL_SNAPSHOT)
        grouped = [tuple(item for item in ordered if _group_matches(group, item)) for group in required]
        positives = [item for group in grouped for item in group if item.disposition is Disposition.POSITIVE]
        explicit = [item for group in grouped for item in group if item.disposition in {Disposition.NEGATIVE, Disposition.ERROR}]
        all_positive = bool(required) and all(
            group and all(item.disposition is Disposition.POSITIVE for item in group)
            for group in grouped
        )
        if _local_prerequisites(ordered) and all_positive:
            health, confidence, summary = Health.HEALTHY, Confidence.HIGH, "Required local and selected endpoint layers produced direct positive evidence."
        elif not positives and explicit:
            health, confidence, summary = Health.FAILED, Confidence.HIGH, "Selected endpoint layers contain explicit negative or execution-error evidence without a direct reachability positive."
        else:
            health, confidence, summary = Health.PARTIAL, Confidence.LOW, "Selected endpoint evidence is mixed, incomplete, unavailable, or inconclusive."
    limitations = ["This conclusion covers only the selected endpoints and observed layers."]
    if len(ordered) > len(cited):
        limitations.append("Only the latest 16 observations are cited.")
    return Conclusion(
        id="diagnosis-health", title="Selected endpoint diagnosis health", summary=summary,
        health=health, confidence=confidence, observation_ids=cited,
        alternatives=("Review the cited layer observations before attributing a cause.",),
        limitations=tuple(limitations),
    )


ProtocolDispatcher = Callable[[TaskContext, str], Awaitable[None]]
SnapshotCollector = Callable[[], Awaitable[TaskResult]]


class DiagnosisRunner:
    """Run exactly the sparse actions already authorized in a diagnosis plan."""

    def __init__(
        self,
        compiled: CompiledDiagnosis,
        *,
        snapshot_collector: SnapshotCollector = collect_status,
        protocol_dispatcher: ProtocolDispatcher = run_protocol_probe,
    ) -> None:
        if type(compiled) is not CompiledDiagnosis:
            raise ValueError("compiled diagnosis must be canonical")
        self.compiled = compiled
        self.snapshot_collector = snapshot_collector
        self.protocol_dispatcher = protocol_dispatcher

    async def __call__(self, context: TaskContext) -> None:
        if context.plan.digest != self.compiled.plan.digest:
            raise ValueError("diagnosis context plan does not match its compilation")
        for step in context.plan.preview.steps:
            if step.probe_kind is ProbeKind.LOCAL_SNAPSHOT:
                prepared = await context.admit(step.id)
                snapshot = await self.snapshot_collector()
                # One bounded local fact keeps the existing sparse step's
                # reservation intact; the full passive result remains owned by
                # the status service and is not reinterpreted as topology.
                now = context.wall_clock()
                context.record(Observation(
                    id=f"{context.task_id}:local-snapshot", probe=ProbeKind.LOCAL_SNAPSHOT.value,
                    disposition=Disposition.POSITIVE, evidence_kind=EvidenceKind.LOCAL_FACT,
                    direction=Direction.LOCAL, target="local", started_at=now, ended_at=now,
                    duration_ms=0.0, attempt=prepared.step.attempt, source="mercury.inventory",
                    detail={"snapshot_observations": len(snapshot.observations)},
                ), step_id=step.id)
                context.complete_attempt(step.id)
                break
        for step in context.plan.preview.steps:
            if step.probe_kind in {ProbeKind.LOCAL_SNAPSHOT, ProbeKind.NATIVE_PING, ProbeKind.NATIVE_PATH}:
                continue
            await self.protocol_dispatcher(context, step.id)


__all__ = ["DiagnosisRunner", "classify_diagnosis"]
