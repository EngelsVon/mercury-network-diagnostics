"""Small human-readable projections of canonical Mercury values."""

from __future__ import annotations

from typing import Iterable

from .history import HistoryRecord
from .models import TaskResult
from .planner import PlanPreview, confirmation_phrase


def render_result(result: TaskResult) -> str:
    lines = [
        f"Task {result.task_id} [{result.state.value}]",
        f"Kind: {result.task_kind}",
        f"Target: {result.target}",
        (
            f"Progress: {result.progress.completed}/{result.progress.total} "
            f"(admitted {result.progress.admitted})"
        ),
    ]
    if result.conclusions:
        lines.append("Conclusions:")
        for conclusion in result.conclusions:
            lines.append(
                f"  - [{conclusion.health.value}/{conclusion.confidence.value}] "
                f"{conclusion.title}: {conclusion.summary}"
            )
    if result.observations:
        lines.append("Observations:")
        for observation in result.observations:
            lines.append(
                f"  - {observation.evidence_kind.value}: "
                f"{observation.disposition.value} "
                f"({observation.duration_ms:.1f} ms)"
            )
    if result.errors:
        lines.append("Errors:")
        lines.extend(f"  - {error}" for error in result.errors)
    return "\n".join(lines)


def render_preview(preview: PlanPreview) -> str:
    estimate = preview.estimate
    lines = [
        f"Plan preview {preview.digest[:12]}",
        "Targets: " + ", ".join(target.canonical for target in preview.targets),
        f"Ports: {estimate.ports}",
        "Transports: " + ", ".join(preview.transports),
        f"Hosts: {estimate.hosts}",
        f"Logical attempts: {estimate.logical_attempts}",
        f"Generated UDP datagrams: {estimate.generated_datagrams}",
        f"Application bytes: {estimate.application_bytes}",
        (
            "Attempt-start rates: "
            f"{estimate.global_attempt_start_rate}/s global, "
            f"{estimate.target_attempt_start_rate}/s per target"
        ),
        f"Concurrency: {estimate.concurrency}",
        f"Worst-case duration: {estimate.worst_case_duration_s}s",
        f"Output ceiling estimate: {estimate.output_bytes} bytes",
        (
            "Accounting note: kernel retransmissions and on-wire framing are "
            "not counted."
        ),
    ]
    if preview.required_confirmations:
        lines.append("Required confirmations:")
        lines.extend(
            f"  - {confirmation_phrase(kind, preview.digest)}"
            for kind in preview.required_confirmations
        )
    return "\n".join(lines)


def render_history(records: Iterable[HistoryRecord]) -> str:
    rows = list(records)
    if not rows:
        return "No history."
    lines = ["TASK ID                              STATE       KIND       UPDATED"]
    for record in rows:
        lines.append(
            f"{record.task_id:<36} {record.state.value:<11} "
            f"{record.task_kind:<10} {record.updated_at.isoformat()}"
        )
    return "\n".join(lines)


__all__ = ["render_history", "render_preview", "render_result"]

