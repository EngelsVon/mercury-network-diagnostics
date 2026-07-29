from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from mercury.history import HistoryError, HistoryStore
from mercury.models import TaskState

from tests.helpers import sample_result


class MutableClock:
    def __init__(self) -> None:
        self.value = datetime(2026, 7, 1, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.value


class HistoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "history.sqlite3"
        self.clock = MutableClock()
        self.store = HistoryStore(
            self.path, max_tasks=2, max_age_days=7, clock=self.clock
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def _create_and_finish(self, task_id: str):
        self.store.create_task(
            task_id=task_id,
            task_kind="synthetic",
            request={"steps": 1},
            plan={"digest": task_id},
            created_at=self.clock(),
        )
        self.store.mark_running(task_id, at=self.clock())
        result = sample_result(task_id=task_id)
        result = type(result)(
            task_id=result.task_id,
            task_kind=result.task_kind,
            direction=result.direction,
            target=result.target,
            state=result.state,
            started_at=self.clock(),
            ended_at=self.clock() + timedelta(seconds=1),
            requested_config=result.requested_config,
            effective_config=result.effective_config,
            progress=result.progress,
            observations=tuple(
                type(item)(
                    id=item.id,
                    probe=item.probe,
                    disposition=item.disposition,
                    evidence_kind=item.evidence_kind,
                    direction=item.direction,
                    target=item.target,
                    started_at=self.clock(),
                    ended_at=self.clock() + timedelta(milliseconds=12),
                    duration_ms=item.duration_ms,
                    attempt=item.attempt,
                    source=item.source,
                    detail=item.detail,
                )
                for item in result.observations
            ),
            conclusions=result.conclusions,
        )
        self.store.finish_task(result)
        return result

    def test_round_trip_and_reopen(self) -> None:
        saved = self._create_and_finish("task-1")
        record = self.store.get_task("task-1")
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(record.state, TaskState.COMPLETED)
        self.assertEqual(record.result, saved)
        self.store.close()
        self.store = HistoryStore(
            self.path, max_tasks=2, max_age_days=7, clock=self.clock
        )
        self.assertIsNotNone(self.store.get_task("task-1"))

    def test_event_sequence_and_replay(self) -> None:
        self.store.create_task(
            task_id="events",
            task_kind="synthetic",
            request={},
            plan={},
        )
        first = self.store.append_event(
            task_id="events", event_type="accepted", payload={"state": "pending"}
        )
        second = self.store.append_event(
            task_id="events", event_type="running", payload={"state": "running"}
        )
        self.assertEqual((first, second), (1, 2))
        replay = self.store.list_events("events", after=1)
        self.assertEqual([event.sequence for event in replay], [2])

    def test_credential_fields_are_never_persisted(self) -> None:
        for key in ("token", "bearer-token", "private_key", "clientSecret"):
            with self.subTest(key=key), self.assertRaises(HistoryError):
                self.store.create_task(
                    task_id=f"secret-{key}",
                    task_kind="synthetic",
                    request={"nested": {key: "sensitive"}},
                    plan={},
                    )
        self.assertEqual(self.store.list_tasks(), ())

    def test_unredacted_payload_fields_are_never_persisted(self) -> None:
        for key in ("payload", "raw_payload", "custom-payload", "requestBody"):
            with self.subTest(key=key), self.assertRaisesRegex(
                HistoryError, "unredacted content"
            ):
                self.store.create_task(
                    task_id=f"payload-{key}",
                    task_kind="fixture",
                    request={"nested": [{key: "do-not-store"}]},
                    plan={"payload_bytes_per_attempt": 12},
                )

        self.store.create_task(
            task_id="payload-metadata",
            task_kind="fixture",
            request={"payload_bytes": 12},
            plan={"payload_bytes_per_attempt": 12},
        )
        self.assertIsNotNone(self.store.get_task("payload-metadata"))

    def test_compound_credentials_headers_bodies_and_values_are_rejected(self) -> None:
        cases = (
            {"refresh_token": "secret"},
            {"client_private_key": "secret"},
            {"headers": {"X-API-Key": "secret"}},
            {"body": "raw response"},
            {"payload_metadata": "raw response"},
            {
                "targets": [
                    {
                        "raw_payload_metadata": {
                            "profile": "custom",
                            "length": 12,
                            "sha256": "0" * 64,
                        }
                    }
                ]
            },
            {"purpose": "Authorization: Bearer top-secret"},
        )
        for index, request in enumerate(cases, 1):
            with self.subTest(request=request), self.assertRaises(HistoryError):
                self.store.create_task(
                    task_id=f"bypass-{index}",
                    task_kind="fixture",
                    request=request,
                    plan={"digest": f"bypass-{index}"},
                )

    def test_history_request_projection_rejects_unknown_safe_fields(self) -> None:
        with self.assertRaisesRegex(HistoryError, "unsupported fields"):
            self.store.create_task(
                task_id="unknown-request-field",
                task_kind="fixture",
                request={"surprise": "not part of the typed projection"},
                plan={"digest": "unknown"},
            )

    def test_count_retention_prunes_oldest_terminal_tasks(self) -> None:
        for index in range(3):
            self.clock.value += timedelta(minutes=1)
            self._create_and_finish(f"task-{index}")
        records = self.store.list_tasks()
        self.assertEqual([record.task_id for record in records], ["task-2", "task-1"])

    def test_age_retention_does_not_delete_active_task(self) -> None:
        self._create_and_finish("old-terminal")
        self.store.create_task(
            task_id="active",
            task_kind="synthetic",
            request={},
            plan={},
        )
        self.clock.value += timedelta(days=8)
        self.store.prune()
        self.assertIsNone(self.store.get_task("old-terminal"))
        self.assertIsNotNone(self.store.get_task("active"))

    @unittest.skipIf(os.name == "nt", "POSIX permission bits are not Windows ACLs")
    def test_database_mode_is_owner_only_on_posix(self) -> None:
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    @unittest.skipIf(os.name == "nt", "POSIX permission bits are not Windows ACLs")
    def test_explicit_history_path_does_not_chmod_existing_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            parent.chmod(0o755)
            with self.assertWarns(RuntimeWarning):
                with HistoryStore(parent / "explicit.sqlite3"):
                    pass
            self.assertEqual(parent.stat().st_mode & 0o777, 0o755)

    @unittest.skipIf(os.name == "nt", "POSIX permission bits are not Windows ACLs")
    def test_new_history_directory_is_private(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / "mercury-private"
            with HistoryStore(parent / "history.sqlite3"):
                pass
            self.assertEqual(parent.stat().st_mode & 0o777, 0o700)

    def test_invalid_state_transition_is_rejected(self) -> None:
        self._create_and_finish("done")
        with self.assertRaises(HistoryError):
            self.store.mark_running("done")

    def test_terminal_event_state_and_result_commit_atomically(self) -> None:
        self.store.create_task(
            task_id="atomic-terminal",
            task_kind="synthetic",
            request={"steps": 1},
            plan={"digest": "sha256:test"},
        )
        self.store.mark_running("atomic-terminal")
        self.store._connection.execute(
            """
            CREATE TRIGGER reject_terminal_event
            BEFORE INSERT ON events
            WHEN NEW.event_type = 'terminal'
            BEGIN
                SELECT RAISE(ABORT, 'terminal event rejected');
            END
            """
        )
        with self.assertRaisesRegex(HistoryError, "atomically finish"):
            self.store.finish_task(sample_result(task_id="atomic-terminal"))
        record = self.store.get_task("atomic-terminal")
        assert record is not None
        self.assertEqual(record.state, TaskState.RUNNING)
        self.assertIsNone(record.result)
        self.assertNotIn(
            "terminal",
            [event.event_type for event in self.store.list_events("atomic-terminal")],
        )


if __name__ == "__main__":
    unittest.main()
