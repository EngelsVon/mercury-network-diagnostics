from __future__ import annotations

import asyncio
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from mercury.history import HistoryStore
from mercury.models import (
    Direction,
    Disposition,
    EvidenceKind,
    Observation,
    TaskState,
)
from mercury.planner import DEFAULT_LIMITS, authorize_plan, preview_plan
from mercury.policy import ScopeGrant
from mercury.tasks import SyntheticRunner, TaskContext, TaskService


def synthetic_plan(steps: int):
    preview = preview_plan(
        target_values=("127.0.0.1",),
        ports=range(1, steps + 1),
        transports=("tcp",),
        grant=ScopeGrant(networks=()),
        profile="synthetic-v1",
    )
    return authorize_plan(preview)


def record_fixture(context: TaskContext, index: int) -> None:
    instant = context.wall_clock()
    context.record(
        Observation(
            id=f"{context.task_id}:custom:{index}",
            probe="custom-test",
            disposition=Disposition.POSITIVE,
            evidence_kind=EvidenceKind.LOCAL_FACT,
            direction=Direction.LOCAL,
            target="offline",
            started_at=instant,
            ended_at=instant,
            duration_ms=0,
            attempt=index,
            source="tests",
            detail={"index": index},
        )
    )
    context.complete_attempt()


class TaskTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "history.sqlite3"
        self.history = HistoryStore(self.path)
        self.service = TaskService(self.history)

    def tearDown(self) -> None:
        self.history.close()
        self.temporary.cleanup()

    async def test_synthetic_task_completes_and_persists(self) -> None:
        result = await self.service.run(
            synthetic_plan(3),
            SyntheticRunner(),
            task_kind="synthetic",
            requested_config={"steps": 3},
            task_id="complete",
        )
        self.assertEqual(result.state, TaskState.COMPLETED)
        self.assertEqual(result.progress.completed, 3)
        self.assertTrue(all(item.detail["network_io"] is False for item in result.observations))
        record = self.history.get_task("complete")
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(record.result, result)
        self.assertEqual(self.history.list_events("complete")[-1].event_type, "terminal")

    async def test_cancellation_persists_valid_partial_result(self) -> None:
        task_id = self.service.submit(
            synthetic_plan(10),
            SyntheticRunner(delay_s=0.03),
            task_kind="synthetic",
            requested_config={"steps": 10},
            task_id="cancel-me",
        )
        await asyncio.sleep(0.075)
        self.assertTrue(self.service.cancel(task_id))
        result = await self.service.wait(task_id)
        self.assertEqual(result.state, TaskState.CANCELLED)
        self.assertGreater(result.progress.completed, 0)
        self.assertLess(result.progress.completed, result.progress.total)
        self.assertLessEqual(result.progress.completed, result.progress.admitted)
        record = self.history.get_task(task_id)
        assert record is not None
        self.assertEqual(record.state, TaskState.CANCELLED)
        self.assertEqual(record.result, result)

    async def test_cancel_prevents_new_admission(self) -> None:
        task_id = self.service.submit(
            synthetic_plan(20),
            SyntheticRunner(delay_s=0.05),
            task_kind="synthetic",
            task_id="no-new-work",
        )
        await asyncio.sleep(0.01)
        self.service.cancel(task_id)
        result = await self.service.wait(task_id)
        admitted_at_terminal = result.progress.admitted
        await asyncio.sleep(0.08)
        self.assertEqual(result.progress.admitted, admitted_at_terminal)
        self.assertLessEqual(admitted_at_terminal, 1)

    async def test_runner_error_keeps_prior_evidence(self) -> None:
        async def broken(context: TaskContext) -> None:
            await context.admit()
            record_fixture(context, 1)
            await context.admit()
            raise RuntimeError("fixture failure")

        result = await self.service.run(
            synthetic_plan(3),
            broken,
            task_kind="synthetic",
            task_id="broken",
        )
        self.assertEqual(result.state, TaskState.FAILED)
        self.assertEqual(result.observations[0].evidence_kind, EvidenceKind.LOCAL_FACT)
        self.assertEqual(
            result.observations[-1].evidence_kind, EvidenceKind.EXECUTION_ERROR
        )
        self.assertIn("RuntimeError", result.errors[0])

    async def test_runner_cannot_exceed_immutable_total(self) -> None:
        async def excessive(context: TaskContext) -> None:
            await context.admit()
            record_fixture(context, 1)
            await context.admit()

        result = await self.service.run(
            synthetic_plan(1),
            excessive,
            task_kind="synthetic",
            task_id="excessive",
        )
        self.assertEqual(result.state, TaskState.FAILED)
        self.assertEqual(result.progress.total, 1)
        self.assertEqual(result.progress.completed, 1)

    async def test_unknown_or_finished_task_cannot_be_cancelled(self) -> None:
        self.assertFalse(self.service.cancel("missing"))
        result = await self.service.run(
            synthetic_plan(1),
            SyntheticRunner(),
            task_kind="synthetic",
            task_id="finished",
        )
        self.assertEqual(result.state, TaskState.COMPLETED)
        self.assertFalse(self.service.cancel("finished"))

    async def test_runner_cannot_exceed_planned_io_units(self) -> None:
        preview = preview_plan(
            target_values=("127.0.0.1",),
            ports=(9,),
            transports=("udp",),
            grant=ScopeGrant(networks=()),
            profile="io-accounting",
            payload_bytes_per_attempt=10,
        )
        plan = authorize_plan(preview)

        async def excessive_io(context: TaskContext) -> None:
            await context.admit()
            context.account_io(datagrams=2, application_bytes=20)

        result = await self.service.run(
            plan,
            excessive_io,
            task_kind="synthetic",
            task_id="io-excess",
        )
        self.assertEqual(result.state, TaskState.FAILED)
        self.assertIn("datagram estimate", result.errors[0])

    async def test_inflight_concurrency_is_enforced(self) -> None:
        async def no_completion(context: TaskContext) -> None:
            await context.admit()
            await context.admit()

        preview = preview_plan(
            target_values=("127.0.0.1",),
            ports=(1, 2),
            transports=("tcp",),
            grant=ScopeGrant(networks=()),
            limits=replace(DEFAULT_LIMITS, max_concurrency=1),
        )
        result = await self.service.run(
            authorize_plan(preview),
            no_completion,
            task_kind="synthetic",
            task_id="concurrency-excess",
        )
        self.assertEqual(result.state, TaskState.FAILED)
        self.assertIn("concurrency ceiling", result.errors[0])


if __name__ == "__main__":
    unittest.main()
