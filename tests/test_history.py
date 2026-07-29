from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from mercury import DB_SCHEMA_VERSION
from mercury.history import HistoryError, HistoryStore
from mercury.models import Progress, TaskState

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
        self.owner_id = "history-test-owner"

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def _create_task(self, **kwargs) -> None:
        self.store.create_task(
            owner_id=self.owner_id,
            lease_expires_at=self.clock() + timedelta(hours=1),
            **kwargs,
        )

    def _mark_running(self, task_id: str, **kwargs) -> None:
        self.store.mark_running(
            task_id,
            owner_id=self.owner_id,
            lease_expires_at=self.clock() + timedelta(hours=1),
            **kwargs,
        )

    def _finish_task(self, result, **kwargs) -> None:
        self.store.finish_task(result, owner_id=self.owner_id, **kwargs)

    @staticmethod
    def _recovery_result(record, recovered_at):
        result = sample_result(task_id=record.task_id, state=TaskState.FAILED)
        return replace(
            result,
            task_kind=record.task_kind,
            started_at=record.created_at,
            ended_at=max(record.created_at, recovered_at),
            requested_config=dict(record.request),
            effective_config=replace(
                result.effective_config,
                policy_digest=record.plan["digest"],
            ),
            progress=Progress(admitted=0, completed=0, total=1),
        )

    def _create_and_finish(self, task_id: str):
        result = sample_result(task_id=task_id)
        self._create_task(
            task_id=task_id,
            task_kind="synthetic",
            request={"steps": 1},
            plan={"digest": result.effective_config.policy_digest},
            created_at=self.clock(),
        )
        self._mark_running(task_id, at=self.clock())
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
        self._finish_task(result)
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
        self._create_task(
            task_id="events",
            task_kind="synthetic",
            request={},
            plan={"digest": "events"},
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
                self._create_task(
                    task_id=f"secret-{key}",
                    task_kind="synthetic",
                    request={"nested": {key: "sensitive"}},
                    plan={"digest": f"secret-{key}"},
                )
        self.assertEqual(self.store.list_tasks(), ())

    def test_unredacted_payload_fields_are_never_persisted(self) -> None:
        for key in ("payload", "raw_payload", "custom-payload", "requestBody"):
            with self.subTest(key=key), self.assertRaisesRegex(
                HistoryError, "unredacted content"
            ):
                self._create_task(
                    task_id=f"payload-{key}",
                    task_kind="fixture",
                    request={"nested": [{key: "do-not-store"}]},
                    plan={
                        "payload_bytes_per_attempt": 12,
                        "digest": f"payload-{key}",
                    },
                )

        self._create_task(
            task_id="payload-metadata",
            task_kind="fixture",
            request={"payload_bytes": 12},
            plan={
                "payload_bytes_per_attempt": 12,
                "digest": "payload-metadata",
            },
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
                self._create_task(
                    task_id=f"bypass-{index}",
                    task_kind="fixture",
                    request=request,
                    plan={"digest": f"bypass-{index}"},
                )

    def test_history_request_projection_rejects_unknown_safe_fields(self) -> None:
        with self.assertRaisesRegex(HistoryError, "unsupported fields"):
            self._create_task(
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
        self._create_task(
            task_id="active",
            task_kind="synthetic",
            request={},
            plan={"digest": "active"},
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
            self._mark_running("done")

    def test_fresh_database_uses_lease_schema(self) -> None:
        version = self.store._connection.execute(
            "PRAGMA user_version"
        ).fetchone()[0]
        columns = {
            row["name"]
            for row in self.store._connection.execute(
                "PRAGMA table_info(tasks)"
            ).fetchall()
        }
        indexes = {
            row["name"]
            for row in self.store._connection.execute(
                "PRAGMA index_list(tasks)"
            ).fetchall()
        }
        self.assertEqual(version, DB_SCHEMA_VERSION)
        self.assertIn("owner_id", columns)
        self.assertIn("lease_expires_at", columns)
        self.assertIn("tasks_active_lease_idx", indexes)

    def test_v1_database_migrates_active_rows_with_conservative_lease(
        self,
    ) -> None:
        legacy_path = Path(self.temporary.name) / "legacy.sqlite3"
        timestamp = "2026-07-01T00:00:00.000Z"
        connection = sqlite3.connect(legacy_path)
        connection.executescript(
            """
            CREATE TABLE tasks (
                task_id TEXT PRIMARY KEY,
                task_kind TEXT NOT NULL,
                state TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                request_json TEXT NOT NULL,
                plan_json TEXT NOT NULL,
                result_json TEXT
            );
            CREATE INDEX tasks_updated_at_idx
                ON tasks(updated_at DESC, task_id DESC);
            CREATE TABLE events (
                task_id TEXT NOT NULL
                    REFERENCES tasks(task_id) ON DELETE CASCADE,
                sequence INTEGER NOT NULL CHECK(sequence > 0),
                occurred_at TEXT NOT NULL,
                event_type TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                PRIMARY KEY(task_id, sequence)
            );
            PRAGMA user_version = 1;
            """
        )
        connection.executemany(
            """
            INSERT INTO tasks(
                task_id, task_kind, state, created_at, updated_at,
                request_json, plan_json, result_json
            ) VALUES (?, 'synthetic', ?, ?, ?, '{}', ?, NULL)
            """,
            (
                (
                    "legacy-running",
                    TaskState.RUNNING.value,
                    timestamp,
                    timestamp,
                    '{"digest":"legacy-running"}',
                ),
                (
                    "legacy-terminal",
                    TaskState.COMPLETED.value,
                    timestamp,
                    timestamp,
                    '{"digest":"legacy-terminal"}',
                ),
            ),
        )
        connection.commit()
        connection.close()

        with HistoryStore(legacy_path, clock=self.clock) as migrated:
            self.assertEqual(
                migrated._connection.execute(
                    "PRAGMA user_version"
                ).fetchone()[0],
                DB_SCHEMA_VERSION,
            )
            active = migrated._connection.execute(
                """
                SELECT owner_id, lease_expires_at FROM tasks
                WHERE task_id = 'legacy-running'
                """
            ).fetchone()
            terminal = migrated._connection.execute(
                """
                SELECT owner_id, lease_expires_at FROM tasks
                WHERE task_id = 'legacy-terminal'
                """
            ).fetchone()
            self.assertEqual(active["owner_id"], "legacy-v1")
            self.assertEqual(
                active["lease_expires_at"],
                "2026-07-01T01:01:00.000Z",
            )
            self.assertIsNone(terminal["owner_id"])
            self.assertIsNone(terminal["lease_expires_at"])

    def test_pending_task_cannot_finish_normally(self) -> None:
        result = sample_result(task_id="pending-terminal")
        self._create_task(
            task_id=result.task_id,
            task_kind=result.task_kind,
            request={"steps": 1},
            plan={"digest": result.effective_config.policy_digest},
        )
        with self.assertRaisesRegex(HistoryError, "state 'pending'"):
            self._finish_task(result)
        record = self.store.get_task(result.task_id)
        assert record is not None
        self.assertEqual(record.state, TaskState.PENDING)
        self.assertIsNone(record.result)
        self.assertEqual(self.store.list_events(result.task_id), ())

    def test_terminal_identity_and_owner_must_match_atomically(self) -> None:
        cases = (
            (
                "wrong-kind",
                {"task_kind": "other"},
                self.owner_id,
                "task kind",
            ),
            (
                "wrong-digest",
                {
                    "effective_config": replace(
                        sample_result().effective_config,
                        policy_digest="different",
                    )
                },
                self.owner_id,
                "plan digest",
            ),
            (
                "wrong-owner",
                {},
                "different-owner",
                "owner",
            ),
        )
        for task_id, changes, owner_id, message in cases:
            with self.subTest(task_id=task_id):
                result = replace(sample_result(task_id=task_id), **changes)
                plan_digest = (
                    "sha256:test"
                    if task_id == "wrong-digest"
                    else result.effective_config.policy_digest
                )
                self._create_task(
                    task_id=task_id,
                    task_kind="synthetic",
                    request={"steps": 1},
                    plan={"digest": plan_digest},
                )
                self._mark_running(task_id)
                with self.assertRaisesRegex(HistoryError, message):
                    self.store.finish_task(result, owner_id=owner_id)
                record = self.store.get_task(task_id)
                assert record is not None
                self.assertEqual(record.state, TaskState.RUNNING)
                self.assertIsNone(record.result)
                self.assertNotIn(
                    "terminal",
                    [
                        event.event_type
                        for event in self.store.list_events(task_id)
                    ],
                )

    def test_terminal_transition_clears_owner_and_lease(self) -> None:
        self._create_and_finish("cleared-lease")
        row = self.store._connection.execute(
            """
            SELECT owner_id, lease_expires_at FROM tasks
            WHERE task_id = 'cleared-lease'
            """
        ).fetchone()
        self.assertIsNone(row["owner_id"])
        self.assertIsNone(row["lease_expires_at"])

    def test_recovery_only_claims_expired_tasks(self) -> None:
        expires_at = self.clock() + timedelta(minutes=1)
        for task_id in ("expired-pending", "expired-running", "live-running"):
            lease = (
                self.clock() + timedelta(hours=1)
                if task_id == "live-running"
                else expires_at
            )
            self.store.create_task(
                task_id=task_id,
                task_kind="synthetic",
                request={"steps": 1},
                plan={"digest": "sha256:test"},
                owner_id=f"owner-{task_id}",
                lease_expires_at=lease,
                created_at=self.clock(),
            )
            if task_id != "expired-pending":
                self.store.mark_running(
                    task_id,
                    owner_id=f"owner-{task_id}",
                    lease_expires_at=lease,
                    at=self.clock(),
                )
        self.clock.value += timedelta(minutes=2)

        recovered = self.store.recover_interrupted(
            self._recovery_result,
            now=self.clock(),
        )

        self.assertEqual(recovered, 2)
        for task_id in ("expired-pending", "expired-running"):
            record = self.store.get_task(task_id)
            assert record is not None and record.result is not None
            self.assertEqual(record.state, TaskState.FAILED)
            self.assertEqual(record.result.state, TaskState.FAILED)
            event = self.store.list_events(task_id)[-1]
            self.assertEqual(event.event_type, "recovered")
            self.assertTrue(event.payload["recovered"])
            self.assertEqual(
                event.payload["error_type"],
                "process_interrupted",
            )
        live = self.store.get_task("live-running")
        assert live is not None
        self.assertEqual(live.state, TaskState.RUNNING)
        self.assertIsNone(live.result)

    def test_recovery_uses_stale_lease_compare_and_swap(self) -> None:
        expired = self.clock() + timedelta(minutes=1)
        self.store.create_task(
            task_id="renewed-during-recovery",
            task_kind="synthetic",
            request={"steps": 1},
            plan={"digest": "sha256:test"},
            owner_id="old-owner",
            lease_expires_at=expired,
            created_at=self.clock(),
        )
        self.store.mark_running(
            "renewed-during-recovery",
            owner_id="old-owner",
            lease_expires_at=expired,
            at=self.clock(),
        )
        self.clock.value += timedelta(minutes=2)

        def renew_before_result(record, recovered_at):
            self.store._connection.execute(
                """
                UPDATE tasks SET lease_expires_at = ?
                WHERE task_id = ?
                """,
                (
                    (self.clock() + timedelta(hours=1))
                    .isoformat(timespec="milliseconds")
                    .replace("+00:00", "Z"),
                    record.task_id,
                ),
            )
            self.store._connection.commit()
            return self._recovery_result(record, recovered_at)

        self.assertEqual(
            self.store.recover_interrupted(
                renew_before_result,
                now=self.clock(),
            ),
            0,
        )
        record = self.store.get_task("renewed-during-recovery")
        assert record is not None
        self.assertEqual(record.state, TaskState.RUNNING)
        self.assertIsNone(record.result)

    def test_recovery_event_and_result_commit_atomically(self) -> None:
        expired = self.clock() + timedelta(minutes=1)
        self.store.create_task(
            task_id="atomic-recovery",
            task_kind="synthetic",
            request={"steps": 1},
            plan={"digest": "sha256:test"},
            owner_id="dead-owner",
            lease_expires_at=expired,
            created_at=self.clock(),
        )
        self.clock.value += timedelta(minutes=2)
        self.store._connection.execute(
            """
            CREATE TRIGGER reject_recovery_event
            BEFORE INSERT ON events
            WHEN NEW.event_type = 'recovered'
            BEGIN
                SELECT RAISE(ABORT, 'recovery event rejected');
            END
            """
        )
        with self.assertRaisesRegex(HistoryError, "atomically recover"):
            self.store.recover_interrupted(
                self._recovery_result,
                now=self.clock(),
            )
        record = self.store.get_task("atomic-recovery")
        assert record is not None
        self.assertEqual(record.state, TaskState.PENDING)
        self.assertIsNone(record.result)

    def test_terminal_event_state_and_result_commit_atomically(self) -> None:
        self._create_task(
            task_id="atomic-terminal",
            task_kind="synthetic",
            request={"steps": 1},
            plan={"digest": "sha256:test"},
        )
        self._mark_running("atomic-terminal")
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
            self._finish_task(sample_result(task_id="atomic-terminal"))
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
