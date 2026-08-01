"""Deterministic, default-redacted history comparisons and exports."""

from __future__ import annotations

import html
import ipaddress
import re
from collections.abc import Mapping
from typing import Any

from .codec import dumps_document, result_to_wire
from .history import HistoryRecord


class ReportError(ValueError):
    """A history/report request cannot safely be fulfilled."""


_SECRET = re.compile(r"(?:token|secret|password|credential|private.?key|authorization)", re.I)
_IDENTIFIER = re.compile(r"(?:host|hostname|address|target|mac|bssid|ssid|chassis|port_id)", re.I)
_PAYLOAD = re.compile(r"(?:payload|body|content)", re.I)
_MAC = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$", re.I)
_HOSTNAME = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)


def _is_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return False
    return True


def redact(value: object, *, retain_sensitive: bool = False, key: str = "") -> object:
    """Return a recursively safe projection; credentials never survive."""
    if _SECRET.search(key):
        return "[redacted secret]"
    if isinstance(value, Mapping):
        return {str(name): redact(item, retain_sensitive=retain_sensitive, key=str(name)) for name, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(item, retain_sensitive=retain_sensitive, key=key) for item in value]
    if not isinstance(value, str):
        return value
    if _PAYLOAD.search(key):
        return value if retain_sensitive else "[redacted payload]"
    identifier = _IDENTIFIER.search(key) or _is_address(value) or bool(_MAC.fullmatch(value)) or bool(_HOSTNAME.fullmatch(value))
    return value if retain_sensitive or not identifier else "[redacted identifier]"


def report_wire(record: HistoryRecord, *, retain_sensitive: bool = False) -> dict[str, object]:
    if record.result is None:
        raise ReportError("only completed history tasks can be exported")
    return {
        "task_id": record.task_id,
        "task_kind": record.task_kind,
        "state": record.state.value,
        "created_at": record.created_at.isoformat(),
        "updated_at": record.updated_at.isoformat(),
        "result": redact(result_to_wire(record.result), retain_sensitive=retain_sensitive),
    }


def json_report(record: HistoryRecord, *, retain_sensitive: bool = False) -> str:
    return dumps_document(report_wire(record, retain_sensitive=retain_sensitive), pretty=True)


def html_report(record: HistoryRecord, *, retain_sensitive: bool = False) -> str:
    document = html.escape(json_report(record, retain_sensitive=retain_sensitive), quote=True)
    title = html.escape(f"Mercury report {record.task_id}", quote=True)
    return f"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>{title}</title></head><body><main><h1>{title}</h1><pre>{document}</pre></main></body></html>"


def _observation_key(value: Mapping[str, Any]) -> tuple[object, ...]:
    return (value["probe"], value["target"], value["attempt"], value["direction"])


def compare_records(left: HistoryRecord, right: HistoryRecord) -> dict[str, object]:
    if left.result is None or right.result is None:
        raise ReportError("only completed history tasks can be compared")
    if left.task_kind != right.task_kind or left.result.schema_version != right.result.schema_version:
        raise ReportError("history tasks are not compatible for comparison")
    left_wire, right_wire = result_to_wire(left.result), result_to_wire(right.result)
    left_items = {_observation_key(item): item for item in left_wire["observations"]}
    right_items = {_observation_key(item): item for item in right_wire["observations"]}
    evidence: list[dict[str, object]] = []
    for key in sorted(set(left_items) | set(right_items), key=repr):
        previous, current = left_items.get(key), right_items.get(key)
        if previous is None:
            status = "missing_left"
        elif current is None:
            status = "missing_right"
        elif previous == current:
            status = "unchanged"
        else:
            status = "changed"
        evidence.append({
            "status": status,
            "probe": key[0], "target": key[1], "attempt": key[2], "direction": key[3],
            "left_observation_id": previous["id"] if previous else None,
            "right_observation_id": current["id"] if current else None,
        })
    return {
        "schema_version": left.result.schema_version,
        "task_kind": left.task_kind,
        "left_task_id": left.task_id,
        "right_task_id": right.task_id,
        "evidence": evidence,
        "limitation": "Missing evidence is reported as absent from one run, not as a reachability conclusion.",
    }


__all__ = ["ReportError", "compare_records", "html_report", "json_report", "redact", "report_wire"]
