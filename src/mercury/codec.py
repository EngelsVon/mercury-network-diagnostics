"""Strict JSON codec for Mercury's public result contract."""

from __future__ import annotations

import json
import math
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable, Mapping, TypeVar

from . import MODEL_SCHEMA_VERSION, is_compatible_model_schema
from .models import (
    Capability,
    CapabilityState,
    Conclusion,
    Confidence,
    Direction,
    Disposition,
    EffectiveConfig,
    EvidenceKind,
    Health,
    ModelError,
    Observation,
    Progress,
    TaskResult,
    TaskState,
)

MAX_DOCUMENT_BYTES = 64 * 1024 * 1024
MAX_JSON_INTEGER_DIGITS = 1_000


class CodecError(ValueError):
    """The wire document is malformed or unsupported."""


TEnum = TypeVar("TEnum", bound=Enum)


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    if isinstance(value, list):
        return [_thaw(item) for item in value]
    return value


def _time_to_wire(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _time_from_wire(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise CodecError(f"{field} must be an ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError as exc:
        raise CodecError(f"{field} is not a valid ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise CodecError(f"{field} must include a UTC offset")
    return parsed


def _enum(enum_type: type[TEnum], value: Any, field: str) -> TEnum:
    if not isinstance(value, str):
        raise CodecError(f"{field} must be a string")
    try:
        return enum_type(value)
    except ValueError as exc:
        raise CodecError(f"{field} has unsupported value {value!r}") from exc


def _object(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CodecError(f"{field} must be an object")
    return value


def _array(value: Any, field: str, *, maximum: int = 100_000) -> list[Any]:
    if not isinstance(value, list):
        raise CodecError(f"{field} must be an array")
    if len(value) > maximum:
        raise CodecError(f"{field} exceeds {maximum} items")
    return value


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise CodecError(f"{field} must be a string")
    return value


def _integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CodecError(f"{field} must be an integer")
    return value


def _number(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CodecError(f"{field} must be a number")
    try:
        number = float(value)
    except OverflowError as exc:
        raise CodecError(f"{field} is outside the supported numeric range") from exc
    if not math.isfinite(number):
        raise CodecError(f"{field} must be finite")
    return number


def _expect_fields(
    value: dict[str, Any],
    *,
    required: Iterable[str],
    optional: Iterable[str] = (),
    field: str,
) -> None:
    required_set = set(required)
    allowed = required_set | set(optional)
    missing = required_set - value.keys()
    unknown = value.keys() - allowed
    if missing:
        raise CodecError(f"{field} is missing fields: {', '.join(sorted(missing))}")
    if unknown:
        raise CodecError(f"{field} has unknown fields: {', '.join(sorted(unknown))}")


def capability_to_wire(value: Capability) -> dict[str, Any]:
    return {
        "name": value.name,
        "state": value.state.value,
        "source": value.source,
        "detail": value.detail,
    }


def capability_from_wire(value: Any) -> Capability:
    item = _object(value, "capability")
    _expect_fields(
        item,
        required=("name", "state", "source", "detail"),
        field="capability",
    )
    return Capability(
        name=_text(item["name"], "capability.name"),
        state=_enum(CapabilityState, item["state"], "capability.state"),
        source=_text(item["source"], "capability.source"),
        detail=_text(item["detail"], "capability.detail"),
    )


def observation_to_wire(value: Observation) -> dict[str, Any]:
    return {
        "id": value.id,
        "probe": value.probe,
        "disposition": value.disposition.value,
        "evidence_kind": value.evidence_kind.value,
        "direction": value.direction.value,
        "target": value.target,
        "started_at": _time_to_wire(value.started_at),
        "ended_at": _time_to_wire(value.ended_at),
        "duration_ms": value.duration_ms,
        "attempt": value.attempt,
        "source": value.source,
        "detail": _thaw(value.detail),
    }


def observation_from_wire(value: Any) -> Observation:
    item = _object(value, "observation")
    _expect_fields(
        item,
        required=(
            "id",
            "probe",
            "disposition",
            "evidence_kind",
            "direction",
            "target",
            "started_at",
            "ended_at",
            "duration_ms",
            "attempt",
            "source",
            "detail",
        ),
        field="observation",
    )
    return Observation(
        id=_text(item["id"], "observation.id"),
        probe=_text(item["probe"], "observation.probe"),
        disposition=_enum(
            Disposition, item["disposition"], "observation.disposition"
        ),
        evidence_kind=_enum(
            EvidenceKind, item["evidence_kind"], "observation.evidence_kind"
        ),
        direction=_enum(Direction, item["direction"], "observation.direction"),
        target=_text(item["target"], "observation.target"),
        started_at=_time_from_wire(item["started_at"], "observation.started_at"),
        ended_at=_time_from_wire(item["ended_at"], "observation.ended_at"),
        duration_ms=_number(item["duration_ms"], "observation.duration_ms"),
        attempt=_integer(item["attempt"], "observation.attempt"),
        source=_text(item["source"], "observation.source"),
        detail=_object(item["detail"], "observation.detail"),
    )


def conclusion_to_wire(value: Conclusion) -> dict[str, Any]:
    return {
        "id": value.id,
        "title": value.title,
        "summary": value.summary,
        "health": value.health.value,
        "confidence": value.confidence.value,
        "observation_ids": list(value.observation_ids),
        "alternatives": list(value.alternatives),
        "limitations": list(value.limitations),
    }


def conclusion_from_wire(value: Any) -> Conclusion:
    item = _object(value, "conclusion")
    _expect_fields(
        item,
        required=(
            "id",
            "title",
            "summary",
            "health",
            "confidence",
            "observation_ids",
            "alternatives",
            "limitations",
        ),
        field="conclusion",
    )
    return Conclusion(
        id=_text(item["id"], "conclusion.id"),
        title=_text(item["title"], "conclusion.title"),
        summary=_text(item["summary"], "conclusion.summary"),
        health=_enum(Health, item["health"], "conclusion.health"),
        confidence=_enum(Confidence, item["confidence"], "conclusion.confidence"),
        observation_ids=tuple(
            _text(entry, "conclusion.observation_ids[]")
            for entry in _array(
                item["observation_ids"], "conclusion.observation_ids", maximum=100_000
            )
        ),
        alternatives=tuple(
            _text(entry, "conclusion.alternatives[]")
            for entry in _array(
                item["alternatives"], "conclusion.alternatives", maximum=256
            )
        ),
        limitations=tuple(
            _text(entry, "conclusion.limitations[]")
            for entry in _array(
                item["limitations"], "conclusion.limitations", maximum=256
            )
        ),
    )


def progress_to_wire(value: Progress) -> dict[str, int]:
    return {
        "admitted": value.admitted,
        "completed": value.completed,
        "total": value.total,
    }


def progress_from_wire(value: Any) -> Progress:
    item = _object(value, "progress")
    _expect_fields(
        item, required=("admitted", "completed", "total"), field="progress"
    )
    return Progress(
        admitted=_integer(item["admitted"], "progress.admitted"),
        completed=_integer(item["completed"], "progress.completed"),
        total=_integer(item["total"], "progress.total"),
    )


def effective_config_to_wire(value: EffectiveConfig) -> dict[str, Any]:
    return {
        "profile": value.profile,
        "targets": list(value.targets),
        "authorized": value.authorized,
        "policy_digest": value.policy_digest,
        "budget": _thaw(value.budget),
        "warnings": list(value.warnings),
    }


def effective_config_from_wire(value: Any) -> EffectiveConfig:
    item = _object(value, "effective_config")
    _expect_fields(
        item,
        required=(
            "profile",
            "targets",
            "authorized",
            "policy_digest",
            "budget",
            "warnings",
        ),
        field="effective_config",
    )
    if not isinstance(item["authorized"], bool):
        raise CodecError("effective_config.authorized must be a boolean")
    return EffectiveConfig(
        profile=_text(item["profile"], "effective_config.profile"),
        targets=tuple(
            _text(entry, "effective_config.targets[]")
            for entry in _array(
                item["targets"], "effective_config.targets", maximum=4096
            )
        ),
        authorized=item["authorized"],
        policy_digest=_text(
            item["policy_digest"], "effective_config.policy_digest"
        ),
        budget=_object(item["budget"], "effective_config.budget"),
        warnings=tuple(
            _text(entry, "effective_config.warnings[]")
            for entry in _array(
                item["warnings"], "effective_config.warnings", maximum=256
            )
        ),
    )


def result_to_wire(value: TaskResult) -> dict[str, Any]:
    return {
        "schema_version": value.schema_version,
        "task_id": value.task_id,
        "task_kind": value.task_kind,
        "direction": value.direction.value,
        "target": value.target,
        "state": value.state.value,
        "started_at": _time_to_wire(value.started_at),
        "ended_at": _time_to_wire(value.ended_at),
        "requested_config": _thaw(value.requested_config),
        "effective_config": effective_config_to_wire(value.effective_config),
        "progress": progress_to_wire(value.progress),
        "observations": [observation_to_wire(item) for item in value.observations],
        "conclusions": [conclusion_to_wire(item) for item in value.conclusions],
        "capabilities": [capability_to_wire(item) for item in value.capabilities],
        "errors": list(value.errors),
    }


def result_from_wire(value: Any) -> TaskResult:
    item = _object(value, "result")
    _expect_fields(
        item,
        required=(
            "schema_version",
            "task_id",
            "task_kind",
            "direction",
            "target",
            "state",
            "started_at",
            "ended_at",
            "requested_config",
            "effective_config",
            "progress",
            "observations",
            "conclusions",
            "capabilities",
            "errors",
        ),
        field="result",
    )
    version = _text(item["schema_version"], "schema_version")
    if not is_compatible_model_schema(version):
        raise CodecError(
            f"unsupported schema version {version!r}; supported major is "
            f"{MODEL_SCHEMA_VERSION.partition('.')[0]!r}"
        )
    try:
        return TaskResult(
            schema_version=version,
            task_id=_text(item["task_id"], "task_id"),
            task_kind=_text(item["task_kind"], "task_kind"),
            direction=_enum(Direction, item["direction"], "direction"),
            target=_text(item["target"], "target"),
            state=_enum(TaskState, item["state"], "state"),
            started_at=_time_from_wire(item["started_at"], "started_at"),
            ended_at=_time_from_wire(item["ended_at"], "ended_at"),
            requested_config=_object(item["requested_config"], "requested_config"),
            effective_config=effective_config_from_wire(item["effective_config"]),
            progress=progress_from_wire(item["progress"]),
            observations=tuple(
                observation_from_wire(entry)
                for entry in _array(
                    item["observations"], "observations", maximum=100_000
                )
            ),
            conclusions=tuple(
                conclusion_from_wire(entry)
                for entry in _array(
                    item["conclusions"], "conclusions", maximum=100_000
                )
            ),
            capabilities=tuple(
                capability_from_wire(entry)
                for entry in _array(
                    item["capabilities"], "capabilities", maximum=4096
                )
            ),
            errors=tuple(
                _text(entry, "errors[]")
                for entry in _array(item["errors"], "errors", maximum=256)
            ),
        )
    except ModelError as exc:
        raise CodecError(str(exc)) from exc


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CodecError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise CodecError(f"non-finite JSON number is not allowed: {value}")


def _parse_integer(value: str) -> int:
    digits = value[1:] if value.startswith("-") else value
    if len(digits) > MAX_JSON_INTEGER_DIGITS:
        raise CodecError(
            f"JSON integer exceeds {MAX_JSON_INTEGER_DIGITS} decimal digits"
        )
    try:
        return int(value)
    except ValueError as exc:
        raise CodecError("JSON integer is outside the supported range") from exc


def loads_document(
    value: str | bytes,
    *,
    maximum_bytes: int = MAX_DOCUMENT_BYTES,
) -> Any:
    if isinstance(value, str):
        encoded_length = len(value.encode("utf-8"))
        text = value
    elif isinstance(value, bytes):
        encoded_length = len(value)
        try:
            text = value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CodecError("JSON document is not UTF-8") from exc
    else:
        raise CodecError("JSON document must be str or bytes")
    if encoded_length > maximum_bytes:
        raise CodecError(f"JSON document exceeds {maximum_bytes} bytes")
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
            parse_int=_parse_integer,
        )
    except CodecError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise CodecError(f"invalid JSON: {exc}") from exc


def dumps_document(value: Any, *, pretty: bool = False) -> str:
    separators = None if pretty else (",", ":")
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            indent=2 if pretty else None,
            separators=separators,
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise CodecError(f"value cannot be encoded as JSON: {exc}") from exc


def result_to_json(value: TaskResult, *, pretty: bool = False) -> str:
    return dumps_document(result_to_wire(value), pretty=pretty)


def result_from_json(value: str | bytes) -> TaskResult:
    return result_from_wire(loads_document(value))


__all__ = [
    "CodecError",
    "MAX_DOCUMENT_BYTES",
    "MAX_JSON_INTEGER_DIGITS",
    "dumps_document",
    "loads_document",
    "result_from_json",
    "result_from_wire",
    "result_to_json",
    "result_to_wire",
]
