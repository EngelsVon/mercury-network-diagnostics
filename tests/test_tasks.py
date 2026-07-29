from __future__ import annotations

import asyncio
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from mercury.codec import result_to_json
from mercury.history import HistoryError, HistoryStore
from mercury.models import (
    Capability,
    CapabilityState,
    Conclusion,
    Confidence,
    Direction,
    Disposition,
    EvidenceKind,
    Health,
    Observation,
    TaskState,
)
from mercury.planner import (
    DEFAULT_LIMITS,
    ConfirmationError,
    authorize_plan,
    preview_plan,
)
from mercury.policy import ScopeGrant
from mercury.tasks import SyntheticRunner, TaskContext, TaskError, TaskService


def synthetic_plan(steps: int, *, limits=DEFAULT_LIMITS):
    preview = preview_plan(
        target_values=("127.0.0.1",),
        ports=range(1, steps + 1),
        transports=("tcp",),
        grant=ScopeGrant(networks=()),
        profile="synthetic-v1",
        limits=limits,
    )
    return authorize_plan(preview)


def record_fixture(context: TaskContext, index: int, step_id: str) -> None:
    instant = context.wall_clock()
    step = context.plan.step(step_id)
    context.record(
        Observation(
            id=f"{context.task_id}:custom:{index}",
            probe="custom-test",
            disposition=Disposition.POSITIVE,
            evidence_kind=EvidenceKind.LOCAL_FACT,
            direction=Direction.LOCAL,
            target=step.address,
            started_at=instant,
            ended_at=instant,
            duration_ms=0,
            attempt=step.attempt,
            source="tests",
            detail={"index": index},
        ),
        step_id=step_id,
    )
    context.complete_attempt(step_id)


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

    async def test_submit_revalidates_the_authorized_plan(self) -> None:
        plan = synthetic_plan(1)
        forged = replace(plan, preview=replace(plan.preview, digest="0" * 64))
        with self.assertRaises(ConfirmationError):
            self.service.submit(
                forged,
                SyntheticRunner(),
                task_kind="synthetic",
                task_id="forged",
            )
        self.assertIsNone(self.history.get_task("forged"))

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

    async def test_external_cancellation_persists_after_reopening(self) -> None:
        runner_started = asyncio.Event()

        async def non_cooperative_wait(context: TaskContext) -> None:
            runner_started.set()
            await asyncio.sleep(60)

        operation = asyncio.create_task(
            self.service.run(
                synthetic_plan(3),
                non_cooperative_wait,
                task_kind="synthetic",
                task_id="externally-cancelled",
            )
        )
        await runner_started.wait()
        operation.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await operation

        self.history.close()
        with HistoryStore(self.path) as reopened:
            record = reopened.get_task("externally-cancelled")
            assert record is not None and record.result is not None
            self.assertEqual(record.state, TaskState.CANCELLED)
            self.assertEqual(record.result.state, TaskState.CANCELLED)
            self.assertEqual(
                record.result.observations[-1].evidence_kind,
                EvidenceKind.CANCELLED,
            )

    async def test_service_start_recovers_only_expired_foreign_lease(
        self,
    ) -> None:
        plan = synthetic_plan(2)
        created_at = datetime(2026, 7, 1, tzinfo=timezone.utc)
        expired_at = created_at + timedelta(minutes=1)
        live_until = created_at + timedelta(hours=1)
        for task_id, lease_expires_at in (
            ("expired-owner", expired_at),
            ("live-owner", live_until),
        ):
            self.history.create_task(
                task_id=task_id,
                task_kind="synthetic",
                request={"steps": 2},
                plan=plan.to_wire(),
                owner_id=f"owner-{task_id}",
                lease_expires_at=lease_expires_at,
                created_at=created_at,
            )
            self.history.mark_running(
                task_id,
                owner_id=f"owner-{task_id}",
                lease_expires_at=lease_expires_at,
                at=created_at,
            )

        TaskService(
            self.history,
            wall_clock=lambda: created_at + timedelta(minutes=2),
        )

        recovered = self.history.get_task("expired-owner")
        assert recovered is not None and recovered.result is not None
        self.assertEqual(recovered.state, TaskState.FAILED)
        self.assertEqual(
            (
                recovered.result.progress.admitted,
                recovered.result.progress.completed,
                recovered.result.progress.total,
            ),
            (0, 0, 2),
        )
        self.assertEqual(
            recovered.result.observations[0].id,
            "task-process-interrupted",
        )
        self.assertEqual(
            recovered.result.observations[0].detail["error_type"],
            "process_interrupted",
        )
        self.assertEqual(
            self.history.list_events("expired-owner")[-1].event_type,
            "recovered",
        )
        live = self.history.get_task("live-owner")
        assert live is not None
        self.assertEqual(live.state, TaskState.RUNNING)
        self.assertIsNone(live.result)

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
            first, second = context.plan.preview.steps[:2]
            await context.admit(first.id)
            record_fixture(context, 1, first.id)
            await context.admit(second.id)
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

    async def test_failure_before_admission_preserves_zero_progress(self) -> None:
        async def fails_immediately(context: TaskContext) -> None:
            raise RuntimeError("failed before work")

        result = await self.service.run(
            synthetic_plan(3),
            fails_immediately,
            task_kind="synthetic",
            task_id="pre-admission-failure",
        )
        self.assertEqual(
            (result.progress.admitted, result.progress.completed, result.progress.total),
            (0, 0, 3),
        )
        self.assertEqual(
            result.observations[-1].evidence_kind,
            EvidenceKind.EXECUTION_ERROR,
        )
        summary = next(item for item in result.conclusions if item.id == "task-summary")
        self.assertEqual(summary.health, Health.FAILED)

    async def test_runner_conclusion_cannot_override_failed_summary(self) -> None:
        async def misleading(context: TaskContext) -> None:
            step = context.plan.preview.steps[0]
            await context.admit(step.id)
            record_fixture(context, 1, step.id)
            context.add_conclusion(
                Conclusion(
                    id="runner-finding",
                    title="Scoped runner finding",
                    summary="The completed probe produced positive evidence.",
                    health=Health.HEALTHY,
                    confidence=Confidence.HIGH,
                    observation_ids=(f"{context.task_id}:custom:1",),
                )
            )
            raise RuntimeError("later task failure")

        result = await self.service.run(
            synthetic_plan(1),
            misleading,
            task_kind="synthetic",
            task_id="truthful-terminal-summary",
        )
        self.assertEqual(result.state, TaskState.FAILED)
        conclusions = {item.id: item for item in result.conclusions}
        self.assertEqual(conclusions["runner-finding"].health, Health.HEALTHY)
        self.assertEqual(conclusions["task-summary"].health, Health.FAILED)

    async def test_cancellation_before_admission_records_task_evidence(self) -> None:
        running = asyncio.Event()

        async def waits_for_cancellation(context: TaskContext) -> None:
            running.set()
            await context.cancellation.wait_or_timeout(60)

        task_id = self.service.submit(
            synthetic_plan(3),
            waits_for_cancellation,
            task_kind="synthetic",
            task_id="cancel-before-admission",
        )
        await running.wait()
        self.assertTrue(self.service.cancel(task_id))
        result = await self.service.wait(task_id)
        self.assertEqual(result.state, TaskState.CANCELLED)
        self.assertEqual(
            (result.progress.admitted, result.progress.completed, result.progress.total),
            (0, 0, 3),
        )
        self.assertEqual(result.observations[-1].evidence_kind, EvidenceKind.CANCELLED)
        summary = next(item for item in result.conclusions if item.id == "task-summary")
        self.assertEqual(summary.health, Health.PARTIAL)

    async def test_exception_credentials_are_sanitized_before_persistence(self) -> None:
        async def leaks_secret(context: TaskContext) -> None:
            raise RuntimeError("Authorization: Bearer top-secret")

        result = await self.service.run(
            synthetic_plan(1),
            leaks_secret,
            task_kind="synthetic",
            task_id="sanitize-exception",
        )
        self.assertEqual(result.state, TaskState.FAILED)
        record = self.history.get_task("sanitize-exception")
        assert record is not None and record.result is not None
        serialized = result_to_json(record.result)
        self.assertNotIn("top-secret", serialized)
        self.assertIn("redacted", serialized)
        observation = next(
            item
            for item in record.result.observations
            if item.evidence_kind is EvidenceKind.EXECUTION_ERROR
        )
        self.assertIn("redacted", observation.detail["message"])

    async def test_runner_cannot_exceed_immutable_total(self) -> None:
        async def excessive(context: TaskContext) -> None:
            step = context.plan.preview.steps[0]
            await context.admit(step.id)
            record_fixture(context, 1, step.id)
            await context.admit(step.id)

        result = await self.service.run(
            synthetic_plan(1),
            excessive,
            task_kind="synthetic",
            task_id="excessive",
        )
        self.assertEqual(result.state, TaskState.FAILED)
        self.assertEqual(result.progress.total, 1)
        self.assertEqual(result.progress.completed, 1)

    async def test_observation_must_match_its_admitted_prepared_step(
        self,
    ) -> None:
        async def attempts_forged_evidence(context: TaskContext) -> None:
            step = context.plan.preview.steps[0]
            prepared = await context.admit(step.id)
            instant = context.wall_clock()
            observation = Observation(
                id="bound-observation",
                probe="custom-test",
                disposition=Disposition.POSITIVE,
                evidence_kind=EvidenceKind.LOCAL_FACT,
                direction=Direction.LOCAL,
                target=prepared.address,
                started_at=instant,
                ended_at=instant,
                duration_ms=0.0,
                attempt=prepared.step.attempt,
                source="tests",
            )
            with self.assertRaisesRegex(TaskError, "identify"):
                context.record(observation)
            with self.assertRaisesRegex(TaskError, "target"):
                context.record(
                    replace(observation, target="192.0.2.99"),
                    step_id=step.id,
                )
            with self.assertRaisesRegex(TaskError, "attempt"):
                context.record(
                    replace(
                        observation,
                        attempt=prepared.step.attempt + 1,
                    ),
                    step_id=step.id,
                )
            context.record(observation, step_id=step.id)
            context.complete_attempt(step.id)

        result = await self.service.run(
            synthetic_plan(1),
            attempts_forged_evidence,
            task_kind="synthetic",
            task_id="bound-observation",
        )
        self.assertEqual(result.state, TaskState.COMPLETED)
        self.assertEqual(len(result.observations), 1)
        self.assertEqual(result.observations[0].target, "127.0.0.1")

    async def test_complete_result_never_exceeds_output_budget(self) -> None:
        limits = replace(DEFAULT_LIMITS, max_output_bytes=5_000)

        async def floods_metadata(context: TaskContext) -> None:
            step = context.plan.preview.steps[0]
            await context.admit(step.id)
            record_fixture(context, 1, step.id)
            for index in range(100):
                context.add_capability(
                    Capability(
                        name=f"capability-{index}",
                        state=CapabilityState.AVAILABLE,
                        source="tests",
                        detail="x" * 1_000,
                    )
                )

        result = await self.service.run(
            synthetic_plan(1, limits=limits),
            floods_metadata,
            task_kind="synthetic",
            task_id="bounded-output",
        )
        self.assertEqual(result.state, TaskState.FAILED)
        self.assertTrue(
            any("output budget" in error for error in result.errors)
        )
        self.assertLessEqual(
            len(result_to_json(result).encode("utf-8")),
            limits.max_output_bytes,
        )
        record = self.history.get_task("bounded-output")
        assert record is not None and record.result is not None
        self.assertLessEqual(
            len(result_to_json(record.result).encode("utf-8")),
            limits.max_output_bytes,
        )

    async def test_context_collection_boundaries_are_enforced(self) -> None:
        async def fills_collections(context: TaskContext) -> None:
            step = context.plan.preview.steps[0]
            await context.admit(step.id)
            record_fixture(context, 1, step.id)
            observation_id = context.observations[0].id
            for index in range(256):
                context.add_conclusion(
                    Conclusion(
                        id=f"runner-conclusion-{index}",
                        title="Bounded conclusion",
                        summary="Bounded summary",
                        health=Health.HEALTHY,
                        confidence=Confidence.HIGH,
                        observation_ids=(observation_id,),
                    )
                )
                context.add_capability(
                    Capability(
                        name=f"runner-capability-{index}",
                        state=CapabilityState.AVAILABLE,
                        source="tests",
                    )
                )
                self.assertTrue(context.add_error(f"runner-error-{index}"))
            with self.assertRaisesRegex(TaskError, "conclusions"):
                context.add_conclusion(
                    Conclusion(
                        id="runner-conclusion-overflow",
                        title="Overflow",
                        summary="Overflow",
                        health=Health.HEALTHY,
                        confidence=Confidence.HIGH,
                        observation_ids=(observation_id,),
                    )
                )
            with self.assertRaisesRegex(TaskError, "capabilities"):
                context.add_capability(
                    Capability(
                        name="runner-capability-overflow",
                        state=CapabilityState.AVAILABLE,
                        source="tests",
                    )
                )
            self.assertFalse(context.add_error("runner-error-overflow"))

        result = await self.service.run(
            synthetic_plan(1),
            fills_collections,
            task_kind="synthetic",
            task_id="bounded-collections",
        )
        self.assertEqual(result.state, TaskState.COMPLETED)
        self.assertEqual(len(result.conclusions), 257)
        self.assertEqual(len(result.capabilities), 256)
        self.assertEqual(len(result.errors), 256)

    async def test_duration_budget_interrupts_non_cooperative_runner(self) -> None:
        limits = replace(DEFAULT_LIMITS, max_duration_s=1)

        async def never_finishes(context: TaskContext) -> None:
            await asyncio.sleep(60)

        result = await self.service.run(
            synthetic_plan(1, limits=limits),
            never_finishes,
            task_kind="synthetic",
            task_id="duration-budget",
        )
        self.assertEqual(result.state, TaskState.FAILED)
        self.assertEqual(
            result.observations[-1].evidence_kind,
            EvidenceKind.TIMEOUT,
        )
        self.assertIn("duration budget", result.errors[0])

    async def test_event_budget_allows_boundary_and_rejects_next(self) -> None:
        limits = replace(DEFAULT_LIMITS, max_events=6)

        async def fills_events(context: TaskContext) -> None:
            step = context.plan.preview.steps[0]
            await context.admit(step.id)
            instant = context.wall_clock()
            for index in range(2):
                context.record(
                    Observation(
                        id=f"event-boundary-{index}",
                        probe="custom-test",
                        disposition=Disposition.POSITIVE,
                        evidence_kind=EvidenceKind.LOCAL_FACT,
                        direction=Direction.LOCAL,
                        target=step.address,
                        started_at=instant,
                        ended_at=instant,
                        duration_ms=0.0,
                        attempt=step.attempt,
                        source="tests",
                    ),
                    step_id=step.id,
                )
            with self.assertRaisesRegex(TaskError, "event budget"):
                context.record(
                    Observation(
                        id="event-overflow",
                        probe="custom-test",
                        disposition=Disposition.POSITIVE,
                        evidence_kind=EvidenceKind.LOCAL_FACT,
                        direction=Direction.LOCAL,
                        target=step.address,
                        started_at=instant,
                        ended_at=instant,
                        duration_ms=0.0,
                        attempt=step.attempt,
                        source="tests",
                    ),
                    step_id=step.id,
                )
            context.complete_attempt(step.id)

        result = await self.service.run(
            synthetic_plan(1, limits=limits),
            fills_events,
            task_kind="synthetic",
            task_id="event-budget",
        )
        self.assertEqual(result.state, TaskState.COMPLETED)
        self.assertEqual(len(result.observations), 2)

    async def test_global_and_per_target_rate_units_are_enforced(self) -> None:
        class RecordingCancellation:
            def __init__(self) -> None:
                self.delays: list[float] = []

            async def checkpoint(self) -> None:
                return None

            async def wait_or_timeout(self, delay: float) -> None:
                self.delays.append(delay)

        limits = replace(
            DEFAULT_LIMITS,
            max_global_rate=4,
            max_target_rate=2,
        )

        async def admission_delays(targets, ports) -> list[float]:
            preview = preview_plan(
                target_values=targets,
                ports=ports,
                transports=("tcp",),
                grant=ScopeGrant(networks=()),
                limits=limits,
            )
            plan = authorize_plan(preview)
            cancellation = RecordingCancellation()
            context = TaskContext(
                task_id="rate-boundary",
                task_kind="synthetic",
                plan=plan,
                requested_config={},
                started_at=datetime(2026, 7, 30, tzinfo=timezone.utc),
                history=self.history,
                cancellation=cancellation,  # type: ignore[arg-type]
                wall_clock=lambda: datetime(
                    2026,
                    7,
                    30,
                    tzinfo=timezone.utc,
                ),
                monotonic=lambda: 0.0,
                resolver=None,
            )
            await context.admit(preview.steps[0].id)
            await context.admit(preview.steps[1].id)
            return cancellation.delays

        same_target = await admission_delays(("127.0.0.1",), (9, 10))
        distinct_targets = await admission_delays(
            ("127.0.0.1", "::1"),
            (9,),
        )
        self.assertAlmostEqual(same_target[-1], 1 / limits.max_target_rate)
        self.assertAlmostEqual(
            distinct_targets[-1],
            1 / limits.max_global_rate,
        )

    async def test_result_envelope_is_reserved_before_history_creation(self) -> None:
        limits = replace(DEFAULT_LIMITS, max_output_bytes=5_000)
        with self.assertRaisesRegex(TaskError, "canonical task result"):
            self.service.submit(
                synthetic_plan(1, limits=limits),
                SyntheticRunner(),
                task_kind="synthetic",
                requested_config={"purpose": "x" * 4_000},
                task_id="oversized-envelope",
            )
        self.assertIsNone(self.history.get_task("oversized-envelope"))

    async def test_result_construction_failure_uses_valid_evidence_fallback(self) -> None:
        async def corrupts_only_unvalidated_state(context: TaskContext) -> None:
            step = context.plan.preview.steps[0]
            await context.admit(step.id)
            record_fixture(context, 1, step.id)
            context._conclusions.append(object())  # type: ignore[arg-type]

        result = await self.service.run(
            synthetic_plan(1),
            corrupts_only_unvalidated_state,
            task_kind="synthetic",
            task_id="result-fallback",
        )
        self.assertEqual(result.state, TaskState.FAILED)
        kinds = {item.evidence_kind for item in result.observations}
        self.assertIn(EvidenceKind.LOCAL_FACT, kinds)
        self.assertIn(EvidenceKind.EXECUTION_ERROR, kinds)
        self.assertTrue(
            any("finalization failed" in item for item in result.errors)
        )
        record = self.history.get_task("result-fallback")
        assert record is not None
        self.assertEqual(record.result, result)

    async def test_transient_terminal_store_failure_persists_failed_fallback(
        self,
    ) -> None:
        original = self.history.finish_task
        attempts = 0

        def fails_once(result, **kwargs):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise HistoryError("transient terminal write failure")
            return original(result, **kwargs)

        self.history.finish_task = fails_once  # type: ignore[method-assign]
        result = await self.service.run(
            synthetic_plan(1),
            SyntheticRunner(),
            task_kind="synthetic",
            task_id="retry-terminal",
        )
        self.assertEqual(result.state, TaskState.FAILED)
        self.assertEqual(attempts, 2)
        self.assertIn(
            EvidenceKind.LOCAL_FACT,
            {item.evidence_kind for item in result.observations},
        )
        self.assertIn(
            EvidenceKind.EXECUTION_ERROR,
            {item.evidence_kind for item in result.observations},
        )
        record = self.history.get_task("retry-terminal")
        assert record is not None
        self.assertEqual(record.result, result)
        self.assertNotIn("retry-terminal", self.service._tasks)
        self.assertNotIn("retry-terminal", self.service._tokens)

    async def test_service_cleanup_survives_persistent_terminal_store_failure(
        self,
    ) -> None:
        def always_fails(result, **kwargs):
            raise HistoryError("persistent terminal write failure")

        self.history.finish_task = always_fails  # type: ignore[method-assign]
        with self.assertRaisesRegex(HistoryError, "persistent terminal"):
            await self.service.run(
                synthetic_plan(1),
                SyntheticRunner(),
                task_kind="synthetic",
                task_id="failed-terminal-write",
            )
        self.assertNotIn("failed-terminal-write", self.service._tasks)
        self.assertNotIn("failed-terminal-write", self.service._tokens)

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
            step = context.plan.preview.steps[0]
            await context.admit(step.id)
            context.account_io(datagrams=2, application_bytes=20)

        result = await self.service.run(
            plan,
            excessive_io,
            task_kind="synthetic",
            task_id="io-excess",
        )
        self.assertEqual(result.state, TaskState.FAILED)
        self.assertIn("service-controlled", result.errors[0])

    async def test_inflight_concurrency_is_enforced(self) -> None:
        async def no_completion(context: TaskContext) -> None:
            first, second = context.plan.preview.steps
            await context.admit(first.id)
            await context.admit(second.id)

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

    async def test_admission_consumes_only_known_step_ids_once(self) -> None:
        async def aliases(context: TaskContext) -> None:
            with self.assertRaisesRegex(TaskError, "unknown"):
                await context.admit("127.0.0.1")
            step = context.plan.preview.steps[0]
            prepared = await context.admit(step.id)
            self.assertEqual(prepared.step, step)
            self.assertEqual(prepared.address, "127.0.0.1")
            with self.assertRaisesRegex(TaskError, "twice"):
                await context.admit(step.id)
            context.complete_attempt(step.id)

        result = await self.service.run(
            synthetic_plan(1),
            aliases,
            task_kind="synthetic",
            task_id="step-ids",
        )
        self.assertEqual(result.state, TaskState.COMPLETED)


if __name__ == "__main__":
    unittest.main()
