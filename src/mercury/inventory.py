"""Passive, bounded local host and network inventory.

This module deliberately collects local facts only.  It neither resolves names
nor opens a socket: route and DNS information comes from the concrete platform
collector and interface information comes from :mod:`psutil`.
"""

from __future__ import annotations

import ipaddress
import platform
import socket
from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import Any

import psutil

from . import __version__
from .history import sanitize_persisted_text
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
    Observation,
    Progress,
    TaskResult,
    TaskState,
    utc_now,
)
from .platform import PlatformRecords, collect_platform


MAX_INTERFACES = 256
MAX_INTERFACE_ADDRESSES = 4_096
MAX_ROUTES = 4_096
MAX_DNS_SERVERS = 256


def _text(value: object, *, maximum: int = 1_024) -> str:
    """Return persistence-safe text suitable for an allowlisted fact."""

    return sanitize_persisted_text(value, maximum=maximum).strip()


def _exception_detail(exc: BaseException) -> str:
    return type(exc).__name__


def _address_and_scope(value: object) -> tuple[str | None, str | None]:
    """Canonicalize an address and retain only a safe IPv6 scope identifier."""

    if not isinstance(value, str) or not value:
        return None, None
    address, separator, scope = value.partition("%")
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return None, None
    if separator:
        if (
            parsed.version != 6
            or not scope
            or len(scope) > 256
            or any(character in "/\\[]\x00" for character in scope)
        ):
            return None, None
    return parsed.compressed, scope or None


def _prefix_length(address: str, netmask: object) -> int | None:
    if not isinstance(netmask, str) or not netmask:
        return None
    try:
        return ipaddress.ip_interface(f"{address}/{netmask}").network.prefixlen
    except ValueError:
        # psutil commonly exposes IPv6 netmasks in expanded hexadecimal form,
        # while ip_interface only accepts a prefix length in this spelling.
        try:
            mask = int(ipaddress.IPv6Address(netmask))
            host_mask = ((1 << 128) - 1) ^ mask
            if host_mask & (host_mask + 1):
                return None
            return mask.bit_count()
        except ValueError:
            return None


def _route_key(record: Any) -> tuple[object, ...]:
    return (
        record.family,
        record.destination,
        record.gateway or "",
        record.interface_name or "",
        record.interface_index if record.interface_index is not None else -1,
        record.route_metric if record.route_metric is not None else -1,
        record.interface_metric if record.interface_metric is not None else -1,
        record.source,
        record.source_record_index if record.source_record_index is not None else -1,
    )


def _dns_key(record: Any) -> tuple[object, ...]:
    return (
        record.family,
        record.address,
        record.scope_id or "",
        record.interface_name or "",
        record.interface_index if record.interface_index is not None else -1,
        record.resolver_order if record.resolver_order is not None else -1,
        record.source,
    )


async def collect_status(
    *,
    clock: Callable[[], datetime] = utc_now,
    hostname: Callable[[], str] = socket.gethostname,
    system: Callable[[], str] = platform.system,
    release: Callable[[], str] = platform.release,
    machine: Callable[[], str] = platform.machine,
    python_version: Callable[[], str] = platform.python_version,
    mercury_version: Callable[[], str] | None = None,
    psutil_module: Any = psutil,
    platform_collector: Callable[[], Awaitable[PlatformRecords]] = collect_platform,
    task_id: str = "status-local",
) -> TaskResult:
    """Collect a canonical passive local snapshot without authorization or I/O probes."""

    collected_at = clock()
    observations: list[Observation] = []
    capabilities: list[Capability] = []

    def observation(
        probe: str,
        source: str,
        detail: dict[str, object],
        *,
        evidence_kind: EvidenceKind = EvidenceKind.LOCAL_FACT,
        disposition: Disposition = Disposition.POSITIVE,
    ) -> str:
        identifier = f"status-{len(observations) + 1:05d}"
        observations.append(
            Observation(
                id=identifier,
                probe=probe,
                disposition=disposition,
                evidence_kind=evidence_kind,
                direction=Direction.LOCAL,
                target="local",
                started_at=collected_at,
                ended_at=collected_at,
                duration_ms=0,
                source=source,
                detail=detail,
            )
        )
        return identifier

    host_sources: tuple[tuple[str, str, Callable[[], str]], ...] = (
        ("hostname", "socket.gethostname", hostname),
        ("system", "platform.system", system),
        ("release", "platform.release", release),
        ("machine", "platform.machine", machine),
        ("python_version", "platform.python_version", python_version),
        (
            "mercury_version",
            "mercury.__version__",
            mercury_version if mercury_version is not None else lambda: __version__,
        ),
        ("collection_time", "mercury.clock", lambda: collected_at.isoformat()),
    )
    for field, source, provider in host_sources:
        try:
            value = _text(provider())
            if not value:
                raise ValueError("empty host fact")
        except Exception as exc:  # A local fact must not suppress the others.
            capabilities.append(
                Capability(field, CapabilityState.ERROR, source, _exception_detail(exc))
            )
        else:
            capabilities.append(Capability(field, CapabilityState.AVAILABLE, source))
            observation("host_fact", source, {"field": field, "value": value})

    try:
        raw_addresses = psutil_module.net_if_addrs()
    except Exception as exc:
        raw_addresses: dict[str, object] = {}
        capabilities.append(
            Capability(
                "interface_addresses",
                CapabilityState.ERROR,
                "psutil.net_if_addrs",
                _exception_detail(exc),
            )
        )
    else:
        capabilities.append(
            Capability("interface_addresses", CapabilityState.AVAILABLE, "psutil.net_if_addrs")
        )

    try:
        raw_stats = psutil_module.net_if_stats()
    except Exception as exc:
        raw_stats: dict[str, object] = {}
        capabilities.append(
            Capability(
                "interface_stats",
                CapabilityState.ERROR,
                "psutil.net_if_stats",
                _exception_detail(exc),
            )
        )
    else:
        capabilities.append(
            Capability("interface_stats", CapabilityState.AVAILABLE, "psutil.net_if_stats")
        )

    interface_names = sorted({str(item) for item in raw_addresses} | {str(item) for item in raw_stats})
    if len(interface_names) > MAX_INTERFACES:
        interface_names = interface_names[:MAX_INTERFACES]
        capabilities.append(
            Capability(
                "interfaces",
                CapabilityState.ERROR,
                "mercury.inventory",
                f"limit={MAX_INTERFACES}",
            )
        )
        observation(
            "inventory_limit",
            "mercury.inventory",
            {"source": "interfaces", "limit": MAX_INTERFACES},
            evidence_kind=EvidenceKind.EXECUTION_ERROR,
            disposition=Disposition.ERROR,
        )

    address_count = 0
    link_family = getattr(psutil_module, "AF_LINK", object())
    for interface_name in interface_names:
        entries = raw_addresses.get(interface_name, ())
        stats = raw_stats.get(interface_name)
        mac: str | None = None
        for entry in entries:
            if getattr(entry, "family", None) == link_family:
                candidate = _text(getattr(entry, "address", ""), maximum=256)
                if candidate:
                    mac = candidate
                    break
        mtu = getattr(stats, "mtu", None)
        speed = getattr(stats, "speed", None)
        interface_detail: dict[str, object] = {
            "name": _text(interface_name, maximum=256),
            "is_up": getattr(stats, "isup", None) if stats is not None else None,
            "mac": mac,
            "mtu": mtu if type(mtu) is int and mtu > 0 else None,
            "speed_mbps": speed if type(speed) is int and speed > 0 else None,
        }
        unavailable = [
            field
            for field in ("mac", "mtu", "speed_mbps")
            if interface_detail[field] is None
        ]
        if stats is None:
            unavailable.append("is_up")
        if unavailable:
            interface_detail["unavailable"] = unavailable
        observation("interface", "psutil", interface_detail)

        for entry in entries:
            family = getattr(entry, "family", None)
            if family not in (socket.AF_INET, socket.AF_INET6):
                continue
            address, scope_id = _address_and_scope(getattr(entry, "address", None))
            if address is None:
                continue
            if address_count >= MAX_INTERFACE_ADDRESSES:
                continue
            prefix = _prefix_length(address, getattr(entry, "netmask", None))
            detail: dict[str, object] = {
                "interface_name": _text(interface_name, maximum=256),
                "family": 4 if family == socket.AF_INET else 6,
                "address": address,
                "prefix_length": prefix,
                "scope_id": scope_id,
            }
            missing = []
            if prefix is None:
                missing.append("prefix_length")
            if family == socket.AF_INET6 and "%" in str(getattr(entry, "address", "")) and scope_id is None:
                missing.append("scope_id")
            if missing:
                detail["unavailable"] = missing
            observation("interface_address", "psutil.net_if_addrs", detail)
            address_count += 1

    available_addresses = sum(
        1
        for interface_name in interface_names
        for entry in raw_addresses.get(interface_name, ())
        if getattr(entry, "family", None) in (socket.AF_INET, socket.AF_INET6)
        and _address_and_scope(getattr(entry, "address", None))[0] is not None
    )
    if available_addresses > MAX_INTERFACE_ADDRESSES:
        capabilities.append(
            Capability(
                "interface_addresses",
                CapabilityState.ERROR,
                "mercury.inventory",
                f"limit={MAX_INTERFACE_ADDRESSES}",
            )
        )
        observation(
            "inventory_limit",
            "mercury.inventory",
            {"source": "interface_addresses", "limit": MAX_INTERFACE_ADDRESSES},
            evidence_kind=EvidenceKind.EXECUTION_ERROR,
            disposition=Disposition.ERROR,
        )

    try:
        platform_records = await platform_collector()
    except Exception as exc:
        platform_records = PlatformRecords()
        capabilities.append(
            Capability(
                "platform_inventory",
                CapabilityState.ERROR,
                "mercury.platform",
                _exception_detail(exc),
            )
        )
    else:
        capabilities.append(
            Capability("platform_inventory", CapabilityState.AVAILABLE, "mercury.platform")
        )
    capabilities.extend(platform_records.capabilities)

    routes = sorted(platform_records.routes, key=_route_key)
    if len(routes) > MAX_ROUTES:
        routes = routes[:MAX_ROUTES]
        capabilities.append(
            Capability("routes", CapabilityState.ERROR, "mercury.inventory", f"limit={MAX_ROUTES}")
        )
        observation(
            "inventory_limit",
            "mercury.inventory",
            {"source": "routes", "limit": MAX_ROUTES},
            evidence_kind=EvidenceKind.EXECUTION_ERROR,
            disposition=Disposition.ERROR,
        )
    for record in routes:
        observation(
            "route",
            record.source,
            {
                "family": record.family,
                "destination": record.destination,
                "gateway": record.gateway,
                "interface_name": record.interface_name,
                "interface_index": record.interface_index,
                "route_metric": record.route_metric,
                "interface_metric": record.interface_metric,
                "effective_metric": record.effective_metric,
                "is_default": record.is_default,
                "protocol": record.protocol,
                "scope": record.scope,
                "route_type": record.route_type,
                "state": record.state,
                "flags": list(record.flags),
                "on_link": record.on_link,
            },
        )

    dns_servers = sorted(platform_records.dns_servers, key=_dns_key)
    if len(dns_servers) > MAX_DNS_SERVERS:
        dns_servers = dns_servers[:MAX_DNS_SERVERS]
        capabilities.append(
            Capability("dns_servers", CapabilityState.ERROR, "mercury.inventory", f"limit={MAX_DNS_SERVERS}")
        )
        observation(
            "inventory_limit",
            "mercury.inventory",
            {"source": "dns_servers", "limit": MAX_DNS_SERVERS},
            evidence_kind=EvidenceKind.EXECUTION_ERROR,
            disposition=Disposition.ERROR,
        )
    for record in dns_servers:
        observation(
            "dns_server",
            record.source,
            {
                "family": record.family,
                "address": record.address,
                "scope_id": record.scope_id,
                "interface_name": record.interface_name,
                "interface_index": record.interface_index,
                "resolver_order": record.resolver_order,
                "scoped_domain": record.scoped_domain,
                "configuration_state": record.configuration_state,
            },
        )

    switch_observation = observation(
        "topology_limit",
        "mercury.inventory",
        {
            "component": "access_switch",
            "reason": "no_direct_lldp_or_managed_evidence",
        },
        evidence_kind=EvidenceKind.UNSUPPORTED,
        disposition=Disposition.UNAVAILABLE,
    )
    conclusion = Conclusion(
        id="status-access-switch-unavailable",
        title="Access switch not observable",
        summary=(
            "The access switch is not observable without direct LLDP or managed evidence."
        ),
        health=Health.UNKNOWN,
        confidence=Confidence.HIGH,
        observation_ids=(switch_observation,),
        limitations=("No direct LLDP or managed topology evidence was collected.",),
    )
    return TaskResult(
        task_id=task_id,
        task_kind="status",
        direction=Direction.LOCAL,
        target="local",
        state=TaskState.COMPLETED,
        started_at=collected_at,
        ended_at=collected_at,
        requested_config={"profile": "status-v1", "passive": True},
        effective_config=EffectiveConfig(
            profile="status-v1",
            targets=("local",),
            authorized=False,
            policy_digest="status-v1",
            budget={},
        ),
        progress=Progress(admitted=0, completed=0, total=0),
        observations=tuple(observations),
        conclusions=(conclusion,),
        capabilities=tuple(capabilities),
    )


__all__ = [
    "MAX_DNS_SERVERS",
    "MAX_INTERFACE_ADDRESSES",
    "MAX_INTERFACES",
    "MAX_ROUTES",
    "collect_status",
]
