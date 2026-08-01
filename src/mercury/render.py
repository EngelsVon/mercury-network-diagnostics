"""Small human-readable projections of canonical Mercury values."""

from __future__ import annotations

from typing import Iterable

from .history import HistoryRecord
from .models import TaskResult
from .paired import paired_matrix
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


def render_status(result: TaskResult) -> str:
    """Project only canonical passive inventory evidence for an operator."""
    observations = result.observations
    host = [item for item in observations if item.probe == "host_fact"]
    interfaces = [item for item in observations if item.probe in {"interface", "interface_address"}]
    routes = [item for item in observations if item.probe == "route"]
    dns = [item for item in observations if item.probe == "dns_server"]
    lines = ["Host"]
    lines.extend(f"  {item.detail.get('field')}: {item.detail.get('value')}" for item in host)
    lines.append("Interfaces")
    lines.extend(f"  {item.detail}" for item in interfaces)
    lines.append("Routes and default gateways")
    lines.extend(f"  {item.detail}" for item in routes)
    lines.append("DNS servers")
    lines.extend(f"  {item.detail}" for item in dns)
    lines.append("Capabilities and limitations")
    lines.extend(f"  {item.name}: {item.state.value} ({item.source})" for item in result.capabilities)
    lines.append("  Access switch: not observable (no_direct_lldp_or_managed_evidence)")
    return "\n".join(lines)


def render_diagnosis(result: TaskResult) -> str:
    """Project the already-derived endpoint health without changing it."""
    health = next((item for item in result.conclusions if item.id == "diagnosis-health"), None)
    if health is None:
        raise RuntimeError("diagnosis-health conclusion contract violated")
    lines = [f"Diagnosis: {health.health.value}", f"Profile: {result.effective_config.profile}"]
    lines.extend(f"Limitation: {item}" for item in health.limitations)
    lines.append("Selected endpoint layers")
    for item in result.observations:
        if item.probe == "local_snapshot":
            label = "local prerequisite"
        else:
            label = item.probe
        detail = item.detail.get("category") or item.detail.get("status") or ""
        lines.append(
            f"  {item.target} | {label} | {item.disposition.value} | "
            f"{item.duration_ms:.1f} ms | attempt {item.attempt} | {item.source} {detail}".rstrip()
        )
    lines.append("Supporting observations: " + ", ".join(health.observation_ids))
    return "\n".join(lines)


def render_paired(result: TaskResult) -> str:
    """Project the fixed paired matrix; it performs no network work."""
    health = [item for item in result.conclusions if item.id == "paired-health"]
    if len(health) != 1:
        raise RuntimeError("paired-health conclusion contract violated")
    lines = ["Directional matrix"]
    for row in paired_matrix(result):
        citations = ", ".join(row.observation_ids)
        lines.append(
            f"  {row.direction} | {row.layer} | {row.outcome} | "
            f"{row.confidence.value} | evidence: {citations}"
        )
        lines.extend(f"    Limitation: {item}" for item in row.limitations)
    lines.append(f"Paired diagnosis: {health[0].health.value}")
    lines.extend(f"Limitation: {item}" for item in health[0].limitations)
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


__all__ = ["render_diagnosis", "render_history", "render_paired", "render_preview", "render_result", "render_status"]
