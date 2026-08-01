"""Transactional, bounded local task history."""

from __future__ import annotations

import json
import math
import os
import re
import sqlite3
import sys
import warnings
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from . import DB_SCHEMA_VERSION
from .codec import dumps_document, loads_document, result_from_json, result_to_json
from .models import TaskResult, TaskState, utc_now

MAX_TASKS_ABSOLUTE = 10_000
MAX_AGE_DAYS_ABSOLUTE = 365
MAX_EVENT_BYTES = 64 * 1024
MAX_AUX_JSON_BYTES = 8 * 1024 * 1024
LEGACY_ACTIVE_LEASE_SECONDS = 3_660

_SECRET_KEY_PARTS = (
    "token",
    "authorization",
    "apikey",
    "password",
    "secret",
    "privatekey",
    "credential",
    "cookie",
    "pairingkey",
    "invitationkey",
)
_SENSITIVE_VALUE_PATTERNS = (
    re.compile(
        r"(?i)\b(?:authorization|proxy-authorization|x-api-key)\s*:\s*\S+"
    ),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{4,}"),
    re.compile(
        r"(?i)\b(?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|"
        r"api[_-]?key|password|passwd|client[_-]?secret|private[_-]?key|"
        r"pairing[_-]?key|credential|cookie|session[_-]?id)"
        r"\s*(?:=|:)\s*[\"']?[^\s,\"';]+"
    ),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)

_REQUEST_KEYS = frozenset(
    {
        "profile",
        "targets",
        "ports",
        "transports",
        "repeats",
        "steps",
        "delay_s",
        "network_io",
        "payload_bytes",
        "payload_length",
        "payload_sha256",
        "payload_profile",
        "datagrams",
        "timeout_s",
        "purpose",
    }
)
_PLAN_KEYS = frozenset(
    {
        "schema_version",
        "profile",
        "targets",
        "ports",
        "transports",
        "repeats",
        "payload_bytes_per_attempt",
        "datagrams_per_udp_attempt",
        "steps",
        "scope",
        "resolutions",
        "limits",
        "estimate",
        "required_confirmations",
        "created_at",
        "digest",
        "confirmations",
        "authorized_at",
    }
)
_EVENT_KEYS = frozenset(
    {
        "state",
        "plan_digest",
        "observation_id",
        "disposition",
        "evidence_kind",
        "observation_count",
        "total",
        "completed",
        "recovered",
        "error_type",
        "dns_changed",
        "hostname",
        "addresses",
        "probe_kind",
        "plan_step_id",
        "preflight_rejected",
        "rejection_code",
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


def _is_secret_key(normalized: str) -> bool:
    return any(part in normalized for part in _SECRET_KEY_PARTS)


def _assert_payload_metadata(value: Any, *, key: str, path: str) -> None:
    normalized = _normalize_key(key)
    if normalized in {
        "payloadbytes",
        "payloadbytesperattempt",
        "payloadlength",
        "maxapplicationbytes",
    }:
        if type(value) is not int or value < 0:
            raise HistoryError(f"{path}.{key} must be a non-negative integer")
        return
    if normalized == "payloadsha256":
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise HistoryError(f"{path}.{key} must be a lowercase SHA-256 digest")
        return
    if normalized == "payloadprofile":
        if not isinstance(value, str) or not value or len(value) > 128:
            raise HistoryError(f"{path}.{key} must be a bounded profile name")
        return
    if normalized == "payloadmetadata":
        if not isinstance(value, Mapping) or set(value) != {
            "profile",
            "length",
            "sha256",
        }:
            raise HistoryError(
                f"{path}.{key} must contain only profile, length, and sha256"
            )
        profile = value["profile"]
        length = value["length"]
        sha256 = value["sha256"]
        if not isinstance(profile, str) or not profile or len(profile) > 128:
            raise HistoryError(f"{path}.{key}.profile is invalid")
        if type(length) is not int or not 0 <= length <= 1_400:
            raise HistoryError(f"{path}.{key}.length is invalid")
        if sha256 is not None and (
            not isinstance(sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", sha256)
        ):
            raise HistoryError(f"{path}.{key}.sha256 is invalid")
        return
    raise HistoryError(f"refusing to persist unredacted content field {path}.{key}")


def _contains_sensitive_value(value: str) -> bool:
    return any(pattern.search(value) for pattern in _SENSITIVE_VALUE_PATTERNS)


def _assert_secret_free(value: Any, *, path: str = "$", depth: int = 0) -> None:
    if depth > 32:
        raise HistoryError("history value is nested too deeply")
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise HistoryError(f"{path} contains a non-string key")
            normalized = _normalize_key(key)
            if _is_secret_key(normalized):
                raise HistoryError(f"refusing to persist credential field {path}.{key}")
            if normalized == "body" or normalized.endswith("body"):
                raise HistoryError(
                    f"refusing to persist unredacted content field {path}.{key}"
                )
            if "payload" in normalized:
                _assert_payload_metadata(item, key=key, path=path)
            _assert_secret_free(item, path=f"{path}.{key}", depth=depth + 1)
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _assert_secret_free(item, path=f"{path}[{index}]", depth=depth + 1)
    elif isinstance(value, str) and _contains_sensitive_value(value):
        raise HistoryError(f"refusing to persist credential text at {path}")


def assert_persistence_safe(value: Any, *, path: str = "$") -> None:
    """Reject credentials and raw content before they reach SQLite."""
    _assert_secret_free(value, path=path)


def sanitize_persisted_text(value: object, *, maximum: int = 1_024) -> str:
    """Return bounded exception text that cannot retain recognized credentials."""
    try:
        text = str(value)
    except Exception:
        text = "<unprintable>"
    text = "".join(
        character if character >= " " and character != "\x7f" else " "
        for character in text
    )
    if _contains_sensitive_value(text):
        return "[sensitive detail redacted]"
    return text[:maximum]


def sanitize_exception(exc: BaseException) -> str:
    name = type(exc).__name__
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", name):
        name = "Exception"
    return f"{name}: {sanitize_persisted_text(exc)}"


def project_history_request(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise HistoryError("history request must be an object")
    _assert_secret_free(value, path="$.request")
    unknown = set(value) - _REQUEST_KEYS
    if unknown:
        raise HistoryError(
            "history request contains unsupported fields: "
            + ", ".join(sorted(str(item) for item in unknown))
        )

    projected: dict[str, Any] = {}
    for key, item in value.items():
        if key in {"profile", "payload_profile"}:
            if (
                type(item) is not str
                or not item
                or len(item) > 128
                or "\x00" in item
            ):
                raise HistoryError(f"history request {key} is invalid")
            projected[key] = item
        elif key == "purpose":
            if type(item) is not str or len(item) > 8_192 or "\x00" in item:
                raise HistoryError("history request purpose is invalid")
            projected[key] = item
        elif key == "targets":
            if (
                not isinstance(item, (list, tuple))
                or not item
                or len(item) > 4_096
            ):
                raise HistoryError("history request targets must be a bounded sequence")
            targets: list[str] = []
            for target in item:
                if (
                    type(target) is not str
                    or not target
                    or len(target) > 1_024
                    or "\x00" in target
                ):
                    raise HistoryError("history request target is invalid")
                targets.append(target)
            projected[key] = targets
        elif key == "ports":
            if (
                not isinstance(item, (list, tuple))
                or not item
                or len(item) > 65_535
            ):
                raise HistoryError("history request ports must be a bounded sequence")
            ports: list[int] = []
            for port in item:
                if type(port) is not int or not 1 <= port <= 65_535:
                    raise HistoryError("history request port is invalid")
                ports.append(port)
            projected[key] = ports
        elif key == "transports":
            if (
                not isinstance(item, (list, tuple))
                or not item
                or len(item) > 2
            ):
                raise HistoryError(
                    "history request transports must be a bounded sequence"
                )
            transports: list[str] = []
            for transport in item:
                if (
                    type(transport) is not str
                    or transport.casefold() not in {"tcp", "udp"}
                ):
                    raise HistoryError("history request transport is invalid")
                transports.append(transport.casefold())
            projected[key] = transports
        elif key in {"steps", "repeats", "datagrams"}:
            maximum = {
                "steps": 100_000,
                "repeats": 100,
                "datagrams": 200_000,
            }[key]
            if type(item) is not int or not 1 <= item <= maximum:
                raise HistoryError(f"history request {key} is invalid")
            projected[key] = item
        elif key in {"payload_bytes", "payload_length"}:
            if type(item) is not int or not 0 <= item <= 64 * 1024 * 1024:
                raise HistoryError(f"history request {key} is invalid")
            projected[key] = item
        elif key == "payload_sha256":
            if type(item) is not str or not re.fullmatch(r"[0-9a-f]{64}", item):
                raise HistoryError("history request payload_sha256 is invalid")
            projected[key] = item
        elif key in {"delay_s", "timeout_s"}:
            if type(item) not in (int, float):
                raise HistoryError(f"history request {key} is invalid")
            number = float(item)
            minimum = 0.0 if key == "delay_s" else 0.0
            if (
                not math.isfinite(number)
                or number < minimum
                or (key == "timeout_s" and number == 0)
                or number > 3_600
            ):
                raise HistoryError(f"history request {key} is invalid")
            projected[key] = number
        elif key == "network_io":
            if type(item) is not bool:
                raise HistoryError("history request network_io is invalid")
            projected[key] = item
        else:  # guarded by the top-level allowlist above
            raise HistoryError(f"history request {key} is unsupported")

    return json.loads(dumps_document(projected))


def _json_for_store(
    value: Mapping[str, Any],
    *,
    maximum: int,
    allowed_keys: frozenset[str] | None = None,
    path: str = "$",
) -> str:
    _assert_secret_free(value, path=path)
    if allowed_keys is not None:
        unknown = set(value) - allowed_keys
        if unknown:
            raise HistoryError(
                f"{path} contains unsupported fields: "
                + ", ".join(sorted(str(item) for item in unknown))
            )
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


def _validate_lifecycle_text(value: str, name: str) -> None:
    if type(value) is not str or not value.strip() or len(value) > 128:
        raise HistoryError(f"{name} must be bounded non-empty text")
    if "\x00" in value:
        raise HistoryError(f"{name} contains NUL")


def _validate_lifecycle_time(value: datetime, name: str) -> None:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise HistoryError(f"{name} must be timezone-aware")


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
            parent_existed = database_path.parent.exists()
            database_path.parent.mkdir(parents=True, exist_ok=True)
            if os.name != "nt":
                if not parent_existed:
                    try:
                        database_path.parent.chmod(0o700)
                    except OSError:
                        pass
                elif path is not None:
                    try:
                        parent_mode = database_path.parent.stat().st_mode & 0o077
                    except OSError:
                        parent_mode = 0
                    if parent_mode:
                        warnings.warn(
                            "explicit history parent is accessible by other users; "
                            "the existing directory was not modified",
                            RuntimeWarning,
                            stacklevel=2,
                        )
                descriptor = os.open(database_path, os.O_CREAT | os.O_RDWR, 0o600)
                os.close(descriptor)
        self._connection = sqlite3.connect(database)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 5000")
        if database != ":memory:":
            self._connection.execute("PRAGMA journal_mode = WAL")
        self._migrate()
        self.prune()
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
                        result_json TEXT,
                        owner_id TEXT,
                        lease_expires_at TEXT
                    );
                    CREATE INDEX tasks_updated_at_idx
                        ON tasks(updated_at DESC, task_id DESC);
                    CREATE INDEX tasks_active_lease_idx
                        ON tasks(state, lease_expires_at);
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

        if current == 1:
            with self._connection:
                self._connection.execute(
                    "ALTER TABLE tasks ADD COLUMN owner_id TEXT"
                )
                self._connection.execute(
                    "ALTER TABLE tasks ADD COLUMN lease_expires_at TEXT"
                )
                self._connection.execute(
                    """
                    CREATE INDEX tasks_active_lease_idx
                    ON tasks(state, lease_expires_at)
                    """
                )
                rows = self._connection.execute(
                    """
                    SELECT task_id, updated_at FROM tasks
                    WHERE state IN (?, ?)
                    """,
                    (TaskState.PENDING.value, TaskState.RUNNING.value),
                ).fetchall()
                self._connection.executemany(
                    """
                    UPDATE tasks SET owner_id = ?, lease_expires_at = ?
                    WHERE task_id = ?
                    """,
                    (
                        (
                            "legacy-v1",
                            _wire_time(
                                _parse_time(row["updated_at"])
                                + timedelta(seconds=LEGACY_ACTIVE_LEASE_SECONDS)
                            ),
                            row["task_id"],
                        )
                        for row in rows
                    ),
                )
                self._connection.execute(
                    f"PRAGMA user_version = {DB_SCHEMA_VERSION}"
                )

    def recover_interrupted(
        self,
        result_factory: Callable[[HistoryRecord, datetime], TaskResult],
        *,
        now: datetime | None = None,
    ) -> int:
        if not callable(result_factory):
            raise HistoryError("recovery result factory must be callable")
        timestamp = now or self._clock()
        _validate_lifecycle_time(timestamp, "recovery time")
        wire_now = _wire_time(timestamp)
        rows = self._connection.execute(
            """
            SELECT * FROM tasks
            WHERE state IN (?, ?)
              AND (
                  owner_id IS NULL
                  OR lease_expires_at IS NULL
                  OR lease_expires_at <= ?
              )
            ORDER BY updated_at ASC, task_id ASC
            """,
            (
                TaskState.PENDING.value,
                TaskState.RUNNING.value,
                wire_now,
            ),
        ).fetchall()
        recovered = 0
        for row in rows:
            record = self._record_from_row(row)
            result = result_factory(record, timestamp)
            if type(result) is not TaskResult or result.state is not TaskState.FAILED:
                raise HistoryError("recovery must produce a failed TaskResult")
            self._assert_result_identity(record, result)
            result_json = result_to_json(result)
            _assert_secret_free(json.loads(result_json), path="$.result")
            payload_json = _json_for_store(
                {
                    "state": TaskState.FAILED.value,
                    "completed": result.progress.completed,
                    "total": result.progress.total,
                    "recovered": True,
                    "error_type": "process_interrupted",
                    "plan_digest": result.effective_config.policy_digest,
                },
                maximum=MAX_EVENT_BYTES,
                allowed_keys=_EVENT_KEYS,
                path="$.event",
            )
            try:
                with self._connection:
                    cursor = self._connection.execute(
                        """
                        UPDATE tasks
                        SET state = ?, updated_at = ?, result_json = ?,
                            owner_id = NULL, lease_expires_at = NULL
                        WHERE task_id = ? AND state = ?
                          AND owner_id IS ? AND lease_expires_at IS ?
                        """,
                        (
                            TaskState.FAILED.value,
                            _wire_time(result.ended_at),
                            result_json,
                            record.task_id,
                            record.state.value,
                            row["owner_id"],
                            row["lease_expires_at"],
                        ),
                    )
                    if cursor.rowcount != 1:
                        continue
                    self._insert_event(
                        task_id=record.task_id,
                        event_type="recovered",
                        payload_json=payload_json,
                        occurred_at=result.ended_at,
                    )
            except sqlite3.Error as exc:
                raise HistoryError(
                    f"could not atomically recover task {record.task_id!r}"
                ) from exc
            recovered += 1
        return recovered

    def create_task(
        self,
        *,
        task_id: str,
        task_kind: str,
        request: Mapping[str, Any],
        plan: Mapping[str, Any],
        owner_id: str,
        lease_expires_at: datetime,
        created_at: datetime | None = None,
        accepted_payload: Mapping[str, Any] | None = None,
    ) -> None:
        timestamp = created_at or self._clock()
        _validate_lifecycle_text(task_id, "task_id")
        _validate_lifecycle_text(task_kind, "task_kind")
        _validate_lifecycle_text(owner_id, "owner_id")
        _validate_lifecycle_time(timestamp, "created_at")
        _validate_lifecycle_time(lease_expires_at, "lease_expires_at")
        if lease_expires_at <= timestamp:
            raise HistoryError("task lease must expire after creation")
        digest = plan.get("digest")
        if type(digest) is not str or not digest or len(digest) > 256:
            raise HistoryError("task plan must contain a bounded digest")
        request_json = _json_for_store(
            project_history_request(request),
            maximum=MAX_AUX_JSON_BYTES,
            allowed_keys=_REQUEST_KEYS,
            path="$.request",
        )
        plan_json = _json_for_store(
            plan,
            maximum=MAX_AUX_JSON_BYTES,
            allowed_keys=_PLAN_KEYS,
            path="$.plan",
        )
        accepted_json = (
            None
            if accepted_payload is None
            else _json_for_store(
                accepted_payload,
                maximum=MAX_EVENT_BYTES,
                allowed_keys=_EVENT_KEYS,
                path="$.event",
            )
        )
        if accepted_payload is not None and (
            accepted_payload.get("state") != TaskState.PENDING.value
            or accepted_payload.get("plan_digest") != plan.get("digest")
        ):
            raise HistoryError("accepted event does not match the pending task")
        try:
            with self._connection:
                self._connection.execute(
                    """
                    INSERT INTO tasks(
                        task_id, task_kind, state, created_at, updated_at,
                        request_json, plan_json, result_json,
                        owner_id, lease_expires_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
                    """,
                    (
                        task_id,
                        task_kind,
                        TaskState.PENDING.value,
                        _wire_time(timestamp),
                        _wire_time(timestamp),
                        request_json,
                        plan_json,
                        owner_id,
                        _wire_time(lease_expires_at),
                    ),
                )
                if accepted_json is not None:
                    self._insert_event(
                        task_id=task_id,
                        event_type="accepted",
                        payload_json=accepted_json,
                        occurred_at=timestamp,
                    )
        except sqlite3.IntegrityError as exc:
            raise HistoryError(f"task {task_id!r} already exists") from exc

    def mark_running(
        self,
        task_id: str,
        *,
        owner_id: str,
        lease_expires_at: datetime,
        at: datetime | None = None,
        event_payload: Mapping[str, Any] | None = None,
    ) -> None:
        timestamp = at or self._clock()
        _validate_lifecycle_text(task_id, "task_id")
        _validate_lifecycle_text(owner_id, "owner_id")
        _validate_lifecycle_time(timestamp, "running time")
        _validate_lifecycle_time(lease_expires_at, "lease_expires_at")
        if lease_expires_at <= timestamp:
            raise HistoryError("task lease must expire after start")
        payload_json = (
            None
            if event_payload is None
            else _json_for_store(
                event_payload,
                maximum=MAX_EVENT_BYTES,
                allowed_keys=_EVENT_KEYS,
                path="$.event",
            )
        )
        if (
            event_payload is not None
            and event_payload.get("state") != TaskState.RUNNING.value
        ):
            raise HistoryError("running event does not match the task transition")
        with self._connection:
            cursor = self._connection.execute(
                """
                UPDATE tasks
                SET state = ?, updated_at = ?, lease_expires_at = ?
                WHERE task_id = ? AND state = ? AND owner_id = ?
                """,
                (
                    TaskState.RUNNING.value,
                    _wire_time(timestamp),
                    _wire_time(lease_expires_at),
                    task_id,
                    TaskState.PENDING.value,
                    owner_id,
                ),
            )
            if cursor.rowcount != 1:
                raise HistoryError(
                    f"task {task_id!r} is missing or cannot transition to running"
                )
            if payload_json is not None:
                self._insert_event(
                    task_id=task_id,
                    event_type="running",
                    payload_json=payload_json,
                    occurred_at=timestamp,
                )

    def finish_task(
        self,
        result: TaskResult,
        *,
        owner_id: str,
        event_payload: Mapping[str, Any] | None = None,
    ) -> None:
        _validate_lifecycle_text(owner_id, "owner_id")
        result_json = result_to_json(result)
        _assert_secret_free(json.loads(result_json), path="$.result")
        payload = event_payload or {
            "state": result.state.value,
            "completed": result.progress.completed,
            "total": result.progress.total,
        }
        if (
            payload.get("state") != result.state.value
            or payload.get("completed") != result.progress.completed
            or payload.get("total") != result.progress.total
        ):
            raise HistoryError("terminal event does not match the task result")
        payload_json = _json_for_store(
            payload,
            maximum=MAX_EVENT_BYTES,
            allowed_keys=_EVENT_KEYS,
            path="$.event",
        )
        try:
            with self._connection:
                row = self._connection.execute(
                    "SELECT * FROM tasks WHERE task_id = ?", (result.task_id,)
                ).fetchone()
                if row is None:
                    raise HistoryError(f"unknown task {result.task_id!r}")
                record = self._record_from_row(row)
                if record.state is not TaskState.RUNNING:
                    raise HistoryError(
                        f"cannot finish task from state {row['state']!r}"
                    )
                if row["owner_id"] != owner_id:
                    raise HistoryError("task owner does not match terminal result")
                self._assert_result_identity(record, result)
                cursor = self._connection.execute(
                    """
                    UPDATE tasks
                    SET state = ?, updated_at = ?, result_json = ?,
                        owner_id = NULL, lease_expires_at = NULL
                    WHERE task_id = ? AND state = ? AND owner_id = ?
                    """,
                    (
                        result.state.value,
                        _wire_time(result.ended_at),
                        result_json,
                        result.task_id,
                        TaskState.RUNNING.value,
                        owner_id,
                    ),
                )
                if cursor.rowcount != 1:
                    raise HistoryError("task changed during terminal transition")
                self._insert_event(
                    task_id=result.task_id,
                    event_type="terminal",
                    payload_json=payload_json,
                    occurred_at=result.ended_at,
                )
        except sqlite3.Error as exc:
            raise HistoryError(
                f"could not atomically finish task {result.task_id!r}"
            ) from exc
        try:
            self.prune()
        except sqlite3.Error as exc:
            warnings.warn(
                f"history retention maintenance failed: {exc}",
                RuntimeWarning,
                stacklevel=2,
            )

    @staticmethod
    def _assert_result_identity(
        record: HistoryRecord,
        result: TaskResult,
    ) -> None:
        if record.task_id != result.task_id:
            raise HistoryError("task ID does not match terminal result")
        if record.task_kind != result.task_kind:
            raise HistoryError("task kind does not match terminal result")
        plan_digest = record.plan.get("digest")
        if (
            type(plan_digest) is not str
            or plan_digest != result.effective_config.policy_digest
        ):
            raise HistoryError("task plan digest does not match terminal result")

    def _insert_event(
        self,
        *,
        task_id: str,
        event_type: str,
        payload_json: str,
        occurred_at: datetime,
    ) -> int:
        row = self._connection.execute(
            "SELECT COALESCE(MAX(sequence), 0) + 1 FROM events WHERE task_id = ?",
            (task_id,),
        ).fetchone()
        sequence = int(row[0])
        self._connection.execute(
            """
            INSERT INTO events(
                task_id, sequence, occurred_at, event_type, payload_json
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                task_id,
                sequence,
                _wire_time(occurred_at),
                event_type,
                payload_json,
            ),
        )
        return sequence

    def append_event(
        self,
        *,
        task_id: str,
        event_type: str,
        payload: Mapping[str, Any],
        occurred_at: datetime | None = None,
    ) -> int:
        payload_json = _json_for_store(
            payload,
            maximum=MAX_EVENT_BYTES,
            allowed_keys=_EVENT_KEYS,
            path="$.event",
        )
        with self._connection:
            try:
                sequence = self._insert_event(
                    task_id=task_id,
                    event_type=event_type,
                    payload_json=payload_json,
                    occurred_at=occurred_at or self._clock(),
                )
            except sqlite3.IntegrityError as exc:
                raise HistoryError(f"unknown task {task_id!r}") from exc
        return sequence

    def get_task(self, task_id: str) -> HistoryRecord | None:
        self.prune()
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
        self.prune()
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
        self.prune()
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
    "assert_persistence_safe",
    "default_history_path",
    "project_history_request",
    "sanitize_exception",
    "sanitize_persisted_text",
]
