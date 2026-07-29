from __future__ import annotations

from datetime import datetime, timedelta, timezone

from mercury.models import (
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
)


def sample_observation(
    *,
    observation_id: str = "obs-1",
    kind: EvidenceKind = EvidenceKind.TCP_CONNECTED,
    disposition: Disposition = Disposition.POSITIVE,
) -> Observation:
    started = datetime(2026, 7, 30, 1, 2, 3, tzinfo=timezone.utc)
    return Observation(
        id=observation_id,
        probe="test",
        disposition=disposition,
        evidence_kind=kind,
        direction=Direction.OUTBOUND,
        target="127.0.0.1:443",
        started_at=started,
        ended_at=started + timedelta(milliseconds=12),
        duration_ms=12,
        detail={"fixture": True},
    )


def sample_result(
    *,
    task_id: str = "task-1",
    state: TaskState = TaskState.COMPLETED,
    observation: Observation | None = None,
) -> TaskResult:
    observation = observation or sample_observation()
    return TaskResult(
        task_id=task_id,
        task_kind="synthetic",
        direction=Direction.LOCAL,
        target="offline",
        state=state,
        started_at=observation.started_at,
        ended_at=observation.ended_at,
        requested_config={"steps": 1},
        effective_config=EffectiveConfig(
            profile="synthetic-v1",
            targets=("offline",),
            authorized=False,
            policy_digest="sha256:test",
            budget={"max_attempts": 1},
        ),
        progress=Progress(admitted=1, completed=1, total=1),
        observations=(observation,),
        conclusions=(
            Conclusion(
                id="conclusion-1",
                title="Fixture",
                summary="Fixture conclusion",
                health=Health.HEALTHY,
                confidence=Confidence.HIGH,
                observation_ids=(observation.id,),
                alternatives=("None in fixture",),
                limitations=("Synthetic only",),
            ),
        ),
    )

