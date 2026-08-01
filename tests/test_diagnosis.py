from __future__ import annotations

import asyncio
import unittest

from mercury.history import HistoryStore
from mercury.models import Confidence, Direction, Disposition, EvidenceKind, Health, Observation, ProbeKind, utc_now
from mercury.policy import ScopeGrant
from mercury.profiles import DiagnosisRequest, compile_diagnosis
from mercury.diagnosis import classify_diagnosis
from mercury.tasks import SyntheticRunner, TaskError, TaskService


async def _compiled():
    return await compile_diagnosis(
        DiagnosisRequest(profile="custom", targets=("127.0.0.1:443",), authorized=True),
        grant=ScopeGrant(networks=()),
    )


def _observation(identifier: str, kind: EvidenceKind, disposition: Disposition, probe: ProbeKind, *, target: str = "127.0.0.1", detail=None) -> Observation:
    now = utc_now()
    return Observation(
        id=identifier, probe=probe.value, disposition=disposition, evidence_kind=kind,
        direction=Direction.OUTBOUND, target=target, started_at=now, ended_at=now,
        duration_ms=0, detail=detail or {},
    )


class HealthClassifierTests(unittest.TestCase):
    def test_explicit_failure_and_lifecycle_partial_are_distinct(self) -> None:
        compiled = asyncio.run(_compiled())
        tcp = _observation("tcp-refused", EvidenceKind.TCP_REFUSED, Disposition.NEGATIVE, ProbeKind.TCP_CONNECT,
                           detail={"planned_target": "127.0.0.1", "port": 443, "server_name": None, "http_scheme": None})
        result = classify_diagnosis(compiled.plan, compiled.required_groups, (tcp,))
        self.assertEqual(result.health, Health.FAILED)
        self.assertEqual(result.confidence, Confidence.HIGH)
        lifecycle = Observation(
            id="task-cancelled", probe="task_cancellation", disposition=Disposition.CANCELLED,
            evidence_kind=EvidenceKind.CANCELLED, direction=Direction.LOCAL, target="task",
            started_at=utc_now(), ended_at=utc_now(), duration_ms=0,
        )
        result = classify_diagnosis(compiled.plan, compiled.required_groups, (tcp, lifecycle))
        self.assertEqual(result.health, Health.PARTIAL)
        self.assertNotIn("Internet", result.summary)

    def test_missing_or_mixed_required_groups_are_partial(self) -> None:
        compiled = asyncio.run(_compiled())
        positive = _observation("tcp-connected", EvidenceKind.TCP_CONNECTED, Disposition.POSITIVE, ProbeKind.TCP_CONNECT,
                                detail={"planned_target": "127.0.0.1", "port": 443, "server_name": None, "http_scheme": None})
        result = classify_diagnosis(compiled.plan, compiled.required_groups, (positive,))
        self.assertEqual(result.health, Health.PARTIAL)
        self.assertEqual(result.id, "diagnosis-health")
        self.assertLessEqual(len(result.observation_ids), 16)


class DiagnosisLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_only_closed_service_submission_can_create_diagnosis(self) -> None:
        compiled = await _compiled()
        with HistoryStore(":memory:") as history:
            service = TaskService(history)
            with self.assertRaises(TaskError):
                service.submit(compiled.plan, SyntheticRunner(), task_kind="diagnose")
            identifier = service.submit_diagnosis(compiled, SyntheticRunner(), task_id="diagnosis-closed")
            result = await service.wait(identifier)
        conclusions = [item for item in result.conclusions if item.id == "diagnosis-health"]
        self.assertEqual(len(conclusions), 1)
        self.assertEqual(result.task_kind, "diagnose")


if __name__ == "__main__":
    unittest.main()
