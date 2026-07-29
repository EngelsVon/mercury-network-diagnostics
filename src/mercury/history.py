"""Transactional, bounded local task history."""

from __future__ import annotations

import json
import os
import sqlite3
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from . import DB_SCHEMA_VERSION
from .codec import dumps_document, loads_document, result_from_json, result_to_json
from .models import TaskResult, TaskState, utc_now

MAX_TASKS_ABSOLUTE = 10_000
MAX_AGE_DAYS_ABSOLUTE = 365
MAX_EVENT_BYTES = 64 * 1024
MAX_AUX_JSON_BYTES = 8 * 1024 * 1024

_SECRET_KEYS = frozenset(
    {
        "token",
        "accesstoken",
        "bearertoken",
        "authorization",
        "proxyauthorization",
        "apikey",
        "password",
        "secret",
        "clientsecret",
        "privatekey",
        "privatekeydata",
        "invitation",
        "invitationsecret",
        "pairingsecret",
        "credential",
        "credentials",
        "cookie",
        "setcookie",
        "sessioncookie",
        "csrftoken",
    }
)

_RAW_CONTENT_KEYS = frozenset(
    {
        "payload",
        "rawpayload",
        "custompayload",
        "payloadhex",
        "payloadbase64",
        "requestbody",
        "responsebody",
    }
)


class HistoryError(RuntimeError):
    """History cannot safely perform the requested operation."""


@dataclass(frozen=True, slots=True)
class HistoryRecord:
    task_id: str
    task_kind: str
    state: TaskState
    created_at: datetime
    updated_at: datetime
    request: Mapping[str, Any]
    plan: Mapping[str, Any]
    result: TaskResult | None


@dataclass(frozen=True, slots=True)
class HistoryEvent:
    task_id: str
    sequence: int
    occurred_at: datetime
    event_type: str
    payload: Mapping[str, Any]


def default_history_path() -> Path:
    if sys.platform == "win32":
        root = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        return root / "Mercury" / "history.sqlite3"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Mercury" / "history.sqlite3"
    root = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return root / "mercury" / "history.sqlite3"


def _normalize_key(value: str) -> str:
    return "".join(character for character in value.casefold() if character.isalnum())


def _assert_secret_free(value: Any, *, path: str = "$", depth: int = 0) -> None:
    if depth > 32:
        raise HistoryError("history value is nested too deeply")
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise HistoryError(f"{path} contains a non-string key")
            normalized = _normalize_key(key)
            if normalized in _SECRET_KEYS:
                raise HistoryError(f"refusing to persist credential field {path}.{key}")
            if normalized in _RAW_CONTENT_KEYS:
                raise HistoryError(
                    f"refusing to persist unredacted content field {path}.{key}"
                )
            _assert_secret_free(item, path=f"{path}.{key}", depth=depth + 1)
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _assert_secret_free(item, path=f"{path}[{index}]", depth=depth + 1)


def _json_for_store(value: Mapping[str, Any], *, maximum: int) -> str:
    _assert_secret_free(value)
    text = dumps_document(value)
    if len(text.encode("utf-8")) > maximum:
        raise HistoryError(f"history JSON exceeds {maximum} bytes")
    return text


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _wire_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


class HistoryStore:
    """A single-engine-thread SQLite store.

    Web mode later owns this object on its engine thread. It intentionally does
    not opt out of sqlite3's same-thread safety check.
    """

    def __init__(
        self,
        path: str | os.PathLike[str] | None = None,
        *,
        max_tasks: int = 500,
        max_age_days: int = 30,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not 1 <= max_tasks <= MAX_TASKS_ABSOLUTE:
            raise HistoryError(
                f"max_tasks must be within 1..{MAX_TASKS_ABSOLUTE}"
            )
        if not 1 <= max_age_days <= MAX_AGE_DAYS_ABSOLUTE:
            raise HistoryError(
                f"max_age_days must be within 1..{MAX_AGE_DAYS_ABSOLUTE}"
            )
        self.path = (
            None
            if path == ":memory:"
            else Path(path) if path is not None else default_history_path()
        )
        self.max_tasks = max_tasks
        self.max_age_days = max_age_days
        self._clock = clock or utc_now
        database = ":memory:" if path == ":memory:" else str(self.path)
        if database != ":memory:":
            database_path = Path(database)
            database_path.parent.mkdir(parents=True, exist_ok=True)
            if os.name != "nt":
                try:
                    database_path.parent.chmod(0o700)
                except OSError:
                    pass
        self._connection = sqlite3.connect(database)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 5000")
        if database != ":memory:":
            self._connection.execute("PRAGMA journal_mode = WAL")
        self._migrate()
        if database != ":memory:" and os.name != "nt":
            try:
                Path(database).chmod(0o600)
            except OSError:
                pass

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> "HistoryStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _migrate(self) -> None:
        current = int(self._connection.execute("PRAGMA user_version").fetchone()[0])
        if current > DB_SCHEMA_VERSION:
            raise HistoryError(
                f"history schema {current} is newer than supported "
                f"{DB_SCHEMA_VERSION}"
            )
        if current == 0:
            with self._connection:
                self._connection.executescript(
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
                    """
                )
                self._connection.execute(f"PRAGMA user_version = {DB_SCHEMA_VERSION}")

    def recover_interrupted(self) -> int:
        now = _wire_time(self._clock())
        with self._connection:
            cursor = self._connection.execute(
                """
                UPDATE tasks SET state = ?, updated_at = ?
                WHERE state IN (?, ?)
                """,
                (
                    TaskState.FAILED.value,
                    now,
                    TaskState.PENDING.value,
                    TaskState.RUNNING.value,
                ),
            )
        return cursor.rowcount

    def create_task(
        self,
        *,
        task_id: str,
        task_kind: str,
        request: Mapping[str, Any],
        plan: Mapping[str, Any],
        created_at: datetime | None = None,
    ) -> None:
        timestamp = created_at or self._clock()
        request_json = _json_for_store(request, maximum=MAX_AUX_JSON_BYTES)
        plan_json = _json_for_store(plan, maximum=MAX_AUX_JSON_BYTES)
        try:
            with self._connection:
                self._connection.execute(
                    """
                    INSERT INTO tasks(
                        task_id, task_kind, state, created_at, updated_at,
                        request_json, plan_json, result_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
                    """,
                    (
                        task_id,
                        task_kind,
                        TaskState.PENDING.value,
                        _wire_time(timestamp),
                        _wire_time(timestamp),
                        request_json,
                        plan_json,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise HistoryError(f"task {task_id!r} already exists") from exc

    def mark_running(self, task_id: str, *, at: datetime | None = None) -> None:
        self._transition(
            task_id,
            expected=(TaskState.PENDING,),
            new_state=TaskState.RUNNING,
            at=at,
        )

    def finish_task(self, result: TaskResult) -> None:
        _assert_secret_free(
            json.loads(result_to_json(result)),
            path="$.result",
        )
        expected = (TaskState.RUNNING, TaskState.PENDING)
        with self._connection:
            row = self._connection.execute(
                "SELECT state FROM tasks WHERE task_id = ?", (result.task_id,)
            ).fetchone()
            if row is None:
                raise HistoryError(f"unknown task {result.task_id!r}")
            if TaskState(row["state"]) not in expected:
                raise HistoryError(
                    f"cannot finish task from state {row['state']!r}"
                )
            self._connection.execute(
                """
                UPDATE tasks
                SET state = ?, updated_at = ?, result_json = ?
                WHERE task_id = ?
                """,
                (
                    result.state.value,
                    _wire_time(result.ended_at),
                    result_to_json(result),
                    result.task_id,
                ),
            )
        self.prune()

    def _transition(
        self,
        task_id: str,
        *,
        expected: Iterable[TaskState],
        new_state: TaskState,
        at: datetime | None,
    ) -> None:
        expected_values = tuple(item.value for item in expected)
        placeholders = ",".join("?" for _ in expected_values)
        with self._connection:
            cursor = self._connection.execute(
                f"""
                UPDATE tasks SET state = ?, updated_at = ?
                WHERE task_id = ? AND state IN ({placeholders})
                """,
                (
                    new_state.value,
                    _wire_time(at or self._clock()),
                    task_id,
                    *expected_values,
                ),
            )
        if cursor.rowcount != 1:
            raise HistoryError(
                f"task {task_id!r} is missing or cannot transition to "
                f"{new_state.value}"
            )

    def append_event(
        self,
        *,
        task_id: str,
        event_type: str,
        payload: Mapping[str, Any],
        occurred_at: datetime | None = None,
    ) -> int:
        payload_json = _json_for_store(payload, maximum=MAX_EVENT_BYTES)
        with self._connection:
            row = self._connection.execute(
                "SELECT COALESCE(MAX(sequence), 0) + 1 FROM events WHERE task_id = ?",
                (task_id,),
            ).fetchone()
            sequence = int(row[0])
            try:
                self._connection.execute(
                    """
                    INSERT INTO events(
                        task_id, sequence, occurred_at, event_type, payload_json
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        task_id,
                        sequence,
                        _wire_time(occurred_at or self._clock()),
                        event_type,
                        payload_json,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise HistoryError(f"unknown task {task_id!r}") from exc
        return sequence

    def get_task(self, task_id: str) -> HistoryRecord | None:
        row = self._connection.execute(
            "SELECT * FROM tasks WHERE task_id = ?", (task_id,)
        ).fetchone()
        return None if row is None else self._record_from_row(row)

    def list_tasks(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[HistoryRecord, ...]:
        if not 1 <= limit <= 1000 or offset < 0:
            raise HistoryError("history pagination is out of range")
        rows = self._connection.execute(
            """
            SELECT * FROM tasks
            ORDER BY updated_at DESC, task_id DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        ).fetchall()
        return tuple(self._record_from_row(row) for row in rows)

    def list_events(
        self,
        task_id: str,
        *,
        after: int = 0,
        limit: int = 1000,
    ) -> tuple[HistoryEvent, ...]:
        if after < 0 or not 1 <= limit <= 10_000:
            raise HistoryError("event pagination is out of range")
        rows = self._connection.execute(
            """
            SELECT * FROM events
            WHERE task_id = ? AND sequence > ?
            ORDER BY sequence ASC
            LIMIT ?
            """,
            (task_id, after, limit),
        ).fetchall()
        return tuple(
            HistoryEvent(
                task_id=row["task_id"],
                sequence=int(row["sequence"]),
                occurred_at=_parse_time(row["occurred_at"]),
                event_type=row["event_type"],
                payload=loads_document(row["payload_json"]),
            )
            for row in rows
        )

    def prune(self, *, now: datetime | None = None) -> int:
        cutoff = _wire_time((now or self._clock()) - timedelta(days=self.max_age_days))
        terminal = (
            TaskState.COMPLETED.value,
            TaskState.FAILED.value,
            TaskState.CANCELLED.value,
        )
        with self._connection:
            old_cursor = self._connection.execute(
                """
                DELETE FROM tasks
                WHERE state IN (?, ?, ?) AND updated_at < ?
                """,
                (*terminal, cutoff),
            )
            excess_rows = self._connection.execute(
                """
                SELECT task_id FROM tasks
                WHERE state IN (?, ?, ?)
                ORDER BY updated_at DESC, task_id DESC
                LIMIT -1 OFFSET ?
                """,
                (*terminal, self.max_tasks),
            ).fetchall()
            if excess_rows:
                self._connection.executemany(
                    "DELETE FROM tasks WHERE task_id = ?",
                    ((row["task_id"],) for row in excess_rows),
                )
        return old_cursor.rowcount + len(excess_rows)

    @staticmethod
    def _record_from_row(row: sqlite3.Row) -> HistoryRecord:
        result_json = row["result_json"]
        return HistoryRecord(
            task_id=row["task_id"],
            task_kind=row["task_kind"],
            state=TaskState(row["state"]),
            created_at=_parse_time(row["created_at"]),
            updated_at=_parse_time(row["updated_at"]),
            request=loads_document(row["request_json"]),
            plan=loads_document(row["plan_json"]),
            result=result_from_json(result_json) if result_json is not None else None,
        )


__all__ = [
    "HistoryError",
    "HistoryEvent",
    "HistoryRecord",
    "HistoryStore",
    "default_history_path",
]
