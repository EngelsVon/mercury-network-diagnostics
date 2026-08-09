"""Small human-readable projections of canonical Mercury values."""

from __future__ import annotations

from typing import Iterable

from .history import HistoryRecord
from .models import CoverageProfile, EvidenceKind, TaskResult
from .paired import coverage_matrix, paired_matrix
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


def render_discovery(result: TaskResult) -> str:
    """Project candidates without promoting routes or neighbors into switches."""
    if result.task_kind == "discover_passive":
        lines = ["Passive discovery (no active packets)"]
        for item in result.observations:
            if item.probe == "connected_ipv4_network":
                lines.append(f"  IPv4 network: {item.detail.get('network')} on {item.detail.get('interface_name')}")
            elif item.probe == "neighbor_cache":
                lines.append(f"  Neighbor cache: {item.detail.get('address')} on {item.detail.get('interface_name')}")
            elif item.probe == "wifi_access_point":
                lines.append(f"  Wi-Fi AP: SSID={item.detail.get('ssid')} BSSID={item.detail.get('bssid')}")
            elif item.probe == "direct_lldp_neighbor":
                lines.append(f"  Direct LLDP: chassis={item.detail.get('chassis_id')} port={item.detail.get('port_id')}")
        lines.extend(f"Capability: {item.name} = {item.state.value}" for item in result.capabilities)
        if not any(item.probe == "direct_lldp_neighbor" for item in result.observations):
            lines.append("Topology limitation: access switch is not observable without direct LLDP evidence.")
        return "\n".join(lines)
    return render_result(result)


def render_trace(result: TaskResult) -> str:
    """Show each observed repeat without collapsing it into one asserted route."""
    lines = ["Native route trace (observed responses; not a certain route)"]
    for item in result.observations:
        if item.evidence_kind is EvidenceKind.PATH_HOP:
            lines.append(f"  repeat {item.attempt} hop {item.detail.get('hop')}: {', '.join(item.detail.get('addresses', ())) or 'response without parsed address'}")
        elif item.evidence_kind is EvidenceKind.PATH_HOP_UNANSWERED:
            lines.append(f"  repeat {item.attempt} hop {item.detail.get('hop')}: unanswered")
        elif item.evidence_kind in {EvidenceKind.PATH_COMPLETE, EvidenceKind.PATH_INCOMPLETE, EvidenceKind.TIMEOUT, EvidenceKind.UNSUPPORTED, EvidenceKind.PERMISSION_DENIED, EvidenceKind.EXECUTION_ERROR}:
            lines.append(f"  repeat {item.attempt}: {item.evidence_kind.value}")
    lines.append("Limitation: gateway, first hop and neighbor cache do not identify an access switch.")
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


def render_coverage(
    result: TaskResult, *, requested: tuple[CoverageProfile, ...],
) -> str:
    """Render the finite directional coverage matrix as terminal text."""
    conclusions = [item for item in result.conclusions if item.id == "coverage-assessment"]
    if len(conclusions) != 1:
        return render_result(result)
    lines = ["Coverage matrix"]
    for row in coverage_matrix(result, requested=requested):
        citations = ", ".join(row.observation_ids) or "none"
        lines.append(
            f"  {row.direction} | {row.profile.value} | {row.outcome.value} | "
            f"evidence: {citations}"
        )
    lines.append(f"Coverage assessment: {conclusions[0].health.value}")
    lines.append(conclusions[0].summary)
    lines.extend(f"Limitation: {item}" for item in conclusions[0].limitations)
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


__all__ = ["render_diagnosis", "render_discovery", "render_history", "render_paired", "render_preview", "render_result", "render_status", "render_trace"]
