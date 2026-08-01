"""Canonical diagnosis execution and its bounded, evidence-only classifier."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from dataclasses import replace
import ipaddress

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
    usable_addresses: set[tuple[str, int]] = set()
    default_routes: set[tuple[str, int]] = set()
    up_interfaces = {
        str(item.detail.get("name"))
        for item in observations
        if item.probe == "local_snapshot" and item.detail.get("is_up") is True
    }
    for item in observations:
        detail = item.detail
        if item.probe == "local_snapshot" and "address" in detail:
            family, name, address = detail.get("family"), detail.get("interface_name"), detail.get("address")
            if type(family) is int and type(name) is str and name in up_interfaces and type(address) is str:
                try:
                    if not ipaddress.ip_address(address).is_loopback:
                        usable_addresses.add((name, family))
                except ValueError:
                    pass
        elif item.probe == "local_snapshot" and detail.get("is_default") is True:
            family = detail.get("family")
            name = detail.get("interface_name")
            if type(family) is int and type(name) is str:
                default_routes.add((name, family))
    return bool(usable_addresses & default_routes)


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
        missing = any(not group for group in grouped)
        positives = [item for group in grouped for item in group if item.disposition is Disposition.POSITIVE]
        explicit = [item for group in grouped for item in group if item.disposition in {Disposition.NEGATIVE, Disposition.ERROR}]
        all_positive = bool(required) and all(
            group and all(item.disposition is Disposition.POSITIVE for item in group)
            for group in grouped
        )
        if _local_prerequisites(ordered) and all_positive:
            health, confidence, summary = Health.HEALTHY, Confidence.HIGH, "Required local and selected endpoint layers produced direct positive evidence."
        elif not missing and not positives and explicit:
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
NativeDispatcher = Callable[[TaskContext, str], Awaitable[None]]
_STEP_DETAIL_KEYS = frozenset({
    "plan_step_id", "probe_kind", "planned_target", "planned_address", "port",
    "transport", "scope_id", "source_hostname", "resolution_slot", "server_name",
    "http_scheme", "max_hops", "timeout_s", "required", "payload_metadata",
    "cost", "dns_changed", "preflight_rejected", "rejection_code",
})


async def _unavailable_native_action(context: TaskContext, step_id: str) -> None:
    """Keep optional native context honest until the platform adapter runs it."""
    prepared = await context.admit(step_id)
    now = context.wall_clock()
    context.record(Observation(
        id=f"{context.task_id}:{step_id[:16]}:native-unavailable",
        probe=prepared.step.probe_kind.value, disposition=Disposition.UNAVAILABLE,
        evidence_kind=EvidenceKind.UNSUPPORTED, direction=Direction.OUTBOUND,
        target=prepared.address or prepared.step.target, started_at=now, ended_at=now,
        duration_ms=0.0, attempt=prepared.step.attempt, source="mercury.diagnosis",
        detail={"category": "native_adapter_not_configured"},
    ), step_id=step_id)
    context.complete_attempt(step_id)


class DiagnosisRunner:
    """Run exactly the sparse actions already authorized in a diagnosis plan."""

    def __init__(
        self,
        compiled: CompiledDiagnosis,
        *,
        snapshot_collector: SnapshotCollector = collect_status,
        protocol_dispatcher: ProtocolDispatcher = run_protocol_probe,
        native_dispatcher: NativeDispatcher = _unavailable_native_action,
    ) -> None:
        if type(compiled) is not CompiledDiagnosis:
            raise ValueError("compiled diagnosis must be canonical")
        self.compiled = compiled
        self.snapshot_collector = snapshot_collector
        self.protocol_dispatcher = protocol_dispatcher
        self.native_dispatcher = native_dispatcher

    async def __call__(self, context: TaskContext) -> None:
        if context.plan.digest != self.compiled.plan.digest:
            raise ValueError("diagnosis context plan does not match its compilation")
        for step in context.plan.preview.steps:
            if step.probe_kind is ProbeKind.LOCAL_SNAPSHOT:
                prepared = await context.admit(step.id)
                snapshot = await self.snapshot_collector()
                for observation in snapshot.observations:
                    context.record(replace(
                        observation, probe=ProbeKind.LOCAL_SNAPSHOT.value,
                        direction=Direction.LOCAL, target="local", attempt=prepared.step.attempt,
                        detail={
                            (f"inventory_{key}" if key in _STEP_DETAIL_KEYS else key): value
                            for key, value in observation.detail.items()
                        },
                    ), step_id=step.id)
                for capability in snapshot.capabilities:
                    context.add_capability(capability, step_id=step.id)
                for conclusion in snapshot.conclusions:
                    if conclusion.id not in {"task-summary", "diagnosis-health"}:
                        context.add_conclusion(conclusion, step_id=step.id)
                for error in snapshot.errors:
                    context.add_error(error, step_id=step.id)
                context.complete_attempt(step.id)
                break
        for step in context.plan.preview.steps:
            if step.probe_kind is ProbeKind.LOCAL_SNAPSHOT:
                continue
            if step.probe_kind in {ProbeKind.NATIVE_PING, ProbeKind.NATIVE_PATH}:
                await self.native_dispatcher(context, step.id)
            else:
                await self.protocol_dispatcher(context, step.id)


__all__ = ["DiagnosisRunner", "classify_diagnosis"]
