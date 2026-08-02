"""Passive-first topology context and bounded authorized TCP discovery.

This module intentionally has no packet crafting, ARP emission, IPv6 host
enumeration, or generic protocol controls.  Passive sources are read through
fixed, bounded platform commands; active work is compiled into the same
immutable TCP plan used by every other Mercury service.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import platform
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import psutil

from .history import HistoryStore
from .models import (
    Capability, CapabilityState, Conclusion, Confidence, Direction,
    Disposition, EffectiveConfig, EvidenceKind, Health, Observation,
    Progress, TaskResult, TaskState, utc_now,
)
from .planner import (
    ABSOLUTE_CEILINGS, DEFAULT_LIMITS, BudgetLimits, PlanPreview, ProbePlan,
    confirmation_phrase, authorize_plan, preview_plan,
)
from .policy import PolicyError, ScopeGrant, TargetKind, parse_target
from .probes import run_protocol_probe
from .tasks import TaskContext, TaskService
from .platform.common import CommandOutcome, CommandResult, run_passive_command
from .platform import PlatformRecords, collect_platform


COMMON_TCP_PORTS = (22, 53, 80, 443, 445, 3389, 8080)
MAX_PASSIVE_RECORDS = 1_024
LINUX_NEIGHBORS_ARGV = ("ip", "-j", "neigh", "show")
LINUX_LLDP_ARGV = ("lldpctl", "-f", "json")
WINDOWS_NEIGHBORS_ARGV = (
    "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
    "@(Get-NetNeighbor | Select-Object IPAddress,InterfaceAlias,LinkLayerAddress,State) | ConvertTo-Json -Compress -Depth 3",
)
WINDOWS_WIFI_ARGV = ("netsh.exe", "wlan", "show", "interfaces")


@dataclass(frozen=True, slots=True)
class VisibleNetwork:
    interface_name: str
    network: str

    def __post_init__(self) -> None:
        if not isinstance(self.interface_name, str) or not self.interface_name or len(self.interface_name) > 256:
            raise ValueError("interface name is invalid")
        parsed = ipaddress.ip_network(self.network, strict=False)
        if parsed.version != 4:
            raise ValueError("visible discovery networks must be IPv4")
        object.__setattr__(self, "network", parsed.with_prefixlen)


@dataclass(frozen=True, slots=True)
class NeighborRecord:
    address: str
    interface_name: str
    state: str | None
    link_layer_address: str | None
    source: str

    def __post_init__(self) -> None:
        address = ipaddress.ip_address(self.address)
        if not isinstance(self.interface_name, str) or not self.interface_name or len(self.interface_name) > 256:
            raise ValueError("neighbor interface is invalid")
        if not isinstance(self.source, str) or not self.source or len(self.source) > 256:
            raise ValueError("neighbor source is invalid")
        object.__setattr__(self, "address", address.compressed)
        for name in ("state", "link_layer_address"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or len(value) > 256):
                raise ValueError(f"neighbor {name} is invalid")


@dataclass(frozen=True, slots=True)
class WifiAccessPoint:
    ssid: str | None
    bssid: str | None
    source: str

    def __post_init__(self) -> None:
        if not isinstance(self.source, str) or not self.source or len(self.source) > 256:
            raise ValueError("Wi-Fi source is invalid")
        if self.ssid is None and self.bssid is None:
            raise ValueError("Wi-Fi record needs an SSID or BSSID")
        for name in ("ssid", "bssid"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or not value or len(value) > 256):
                raise ValueError(f"Wi-Fi {name} is invalid")


@dataclass(frozen=True, slots=True)
class LldpNeighbor:
    chassis_id: str | None
    port_id: str | None
    interface_name: str | None
    source: str

    def __post_init__(self) -> None:
        if self.chassis_id is None and self.port_id is None:
            raise ValueError("direct LLDP record needs a chassis or port identifier")
        if not isinstance(self.source, str) or not self.source or len(self.source) > 256:
            raise ValueError("LLDP source is invalid")
        for name in ("chassis_id", "port_id", "interface_name"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or not value or len(value) > 256):
                raise ValueError(f"LLDP {name} is invalid")


def derive_ipv4_networks(*, psutil_module: Any = psutil) -> tuple[VisibleNetwork, ...]:
    """Derive local connected IPv4 prefixes without sending any packet."""
    rows: set[VisibleNetwork] = set()
    for interface_name, addresses in psutil_module.net_if_addrs().items():
        for item in addresses:
            if getattr(item, "family", None) != socket.AF_INET:
                continue
            address, netmask = getattr(item, "address", None), getattr(item, "netmask", None)
            if not isinstance(address, str) or not isinstance(netmask, str):
                continue
            try:
                network = ipaddress.ip_interface(f"{address}/{netmask}").network
            except ValueError:
                continue
            rows.add(VisibleNetwork(str(interface_name), network.with_prefixlen))
    return tuple(sorted(rows, key=lambda item: (int(ipaddress.ip_network(item.network).network_address), item.network, item.interface_name)))


def _rows(document: str, source: str) -> tuple[dict[str, Any], ...]:
    try:
        value = json.loads(document)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{source} returned malformed JSON") from exc
    if isinstance(value, dict):
        value = [value]
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError(f"{source} must return JSON records")
    return tuple(value[:MAX_PASSIVE_RECORDS])


def parse_linux_neighbors(document: str) -> tuple[NeighborRecord, ...]:
    parsed: list[NeighborRecord] = []
    for row in _rows(document, "ip neigh"):
        address, interface = row.get("dst"), row.get("dev")
        if not isinstance(address, str) or not isinstance(interface, str) or not interface:
            raise ValueError("ip neigh record has no address or interface")
        parsed.append(NeighborRecord(address, interface, row.get("state") if isinstance(row.get("state"), str) else None, row.get("lladdr") if isinstance(row.get("lladdr"), str) else None, "linux.iproute2"))
    return tuple(parsed)


def parse_windows_neighbors(document: str) -> tuple[NeighborRecord, ...]:
    parsed: list[NeighborRecord] = []
    for row in _rows(document, "Get-NetNeighbor"):
        address, interface = row.get("IPAddress"), row.get("InterfaceAlias")
        if not isinstance(address, str) or not isinstance(interface, str) or not interface:
            raise ValueError("Get-NetNeighbor record has no address or interface")
        parsed.append(NeighborRecord(address, interface, row.get("State") if isinstance(row.get("State"), str) else None, row.get("LinkLayerAddress") if isinstance(row.get("LinkLayerAddress"), str) else None, "windows.Get-NetNeighbor"))
    return tuple(parsed)


def parse_windows_wifi(document: str) -> tuple[WifiAccessPoint, ...]:
    ssid = bssid = None
    for line in document.splitlines():
        key, separator, value = line.partition(":")
        if not separator:
            continue
        key, value = key.strip().casefold(), value.strip()
        if key == "ssid" and value:
            ssid = value
        elif key == "bssid" and value:
            bssid = value
    return () if ssid is None and bssid is None else (WifiAccessPoint(ssid, bssid, "windows.netsh"),)


def _text_from(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    if isinstance(value, dict):
        for key in ("value", "id", "name"):
            found = _text_from(value.get(key))
            if found:
                return found
    return None


def parse_lldpctl(document: str) -> tuple[LldpNeighbor, ...]:
    """Extract only explicit chassis/port values from lldpctl JSON.

    The lldpctl layout differs between releases, so unknown shapes deliberately
    yield no topology claim instead of guessing from gateways or route hops.
    """
    try:
        root = json.loads(document)
    except json.JSONDecodeError as exc:
        raise ValueError("lldpctl returned malformed JSON") from exc
    found: list[LldpNeighbor] = []
    seen: set[tuple[str | None, str | None, str | None]] = set()

    def visit(value: Any, interface: str | None = None) -> None:
        if isinstance(value, dict):
            local_interface = _text_from(value.get("interface")) or interface
            chassis = _text_from(value.get("chassis")) or _text_from(value.get("chassis_id"))
            port = _text_from(value.get("port")) or _text_from(value.get("port_id"))
            if chassis or port:
                key = (chassis, port, local_interface)
                if key not in seen:
                    seen.add(key)
                    found.append(LldpNeighbor(chassis, port, local_interface, "linux.lldpctl"))
            for child in value.values():
                visit(child, local_interface)
        elif isinstance(value, list):
            for child in value:
                visit(child, interface)
    visit(root)
    return tuple(found[:MAX_PASSIVE_RECORDS])


async def _passive_command(argv: tuple[str, ...], *, runner=None) -> CommandResult:
    return await run_passive_command(argv, runner=runner)


async def collect_passive_discovery(
    *,
    clock: Callable[[], datetime] = utc_now,
    psutil_module: Any = psutil,
    system: Callable[[], str] = platform.system,
    command_runner=None,
    platform_collector: Callable[[], Awaitable[PlatformRecords]] = collect_platform,
    task_id: str = "discover-passive-local",
) -> TaskResult:
    """Collect passive context only; it never calls a probe or opens a socket."""
    instant = clock()
    observations: list[Observation] = []
    capabilities: list[Capability] = []

    def observe(probe: str, source: str, detail: dict[str, object], *, kind=EvidenceKind.LOCAL_FACT, disposition=Disposition.POSITIVE) -> str:
        identifier = f"discover-passive-{len(observations) + 1:05d}"
        observations.append(Observation(identifier, probe, disposition, kind, Direction.LOCAL, "local", instant, instant, 0, source=source, detail=detail))
        return identifier

    try:
        networks = derive_ipv4_networks(psutil_module=psutil_module)
        capabilities.append(Capability("connected_ipv4_networks", CapabilityState.AVAILABLE, "psutil.net_if_addrs"))
    except Exception as exc:
        networks = ()
        capabilities.append(Capability("connected_ipv4_networks", CapabilityState.ERROR, "psutil.net_if_addrs", type(exc).__name__))
    for record in networks:
        observe("connected_ipv4_network", "psutil.net_if_addrs", {"interface_name": record.interface_name, "network": record.network, "passive": True})
    try:
        platform_records = await platform_collector()
    except Exception as exc:
        capabilities.append(Capability("passive_routes", CapabilityState.ERROR, "mercury.platform", type(exc).__name__))
    else:
        capabilities.append(Capability("passive_routes", CapabilityState.AVAILABLE, "mercury.platform"))
        capabilities.extend(platform_records.capabilities)
        for route in platform_records.routes:
            if route.family == 4 and route.on_link:
                observe("connected_ipv4_route", route.source, {"network": route.destination, "interface_name": route.interface_name, "interface_index": route.interface_index, "gateway": route.gateway, "on_link": True, "passive": True})
    ipv6_limit = observe("discovery_limit", "mercury.discovery", {"feature": "ipv6_host_enumeration", "reason": "unsupported_in_v1"}, kind=EvidenceKind.UNSUPPORTED, disposition=Disposition.UNAVAILABLE)
    capabilities.append(Capability("ipv6_host_enumeration", CapabilityState.UNSUPPORTED, "mercury.discovery", "v1_ipv4_only"))

    platform_name = system().casefold()
    candidates: list[tuple[str, tuple[str, ...], Callable[[str], tuple[Any, ...]]]] = []
    if platform_name == "windows":
        candidates = [("neighbor_cache", WINDOWS_NEIGHBORS_ARGV, parse_windows_neighbors), ("wifi_access_point", WINDOWS_WIFI_ARGV, parse_windows_wifi)]
    elif platform_name == "linux":
        candidates = [("neighbor_cache", LINUX_NEIGHBORS_ARGV, parse_linux_neighbors), ("direct_lldp_neighbors", LINUX_LLDP_ARGV, parse_lldpctl)]
    else:
        capabilities.append(Capability("passive_topology", CapabilityState.UNSUPPORTED, "mercury.discovery", "windows_or_ubuntu_only"))

    lldp_ids: list[str] = []
    for name, argv, parser in candidates:
        result = await _passive_command(argv, runner=command_runner)
        states = {
            CommandOutcome.SUCCESS: CapabilityState.AVAILABLE,
            CommandOutcome.MISSING_TOOL: CapabilityState.MISSING_TOOL,
            CommandOutcome.PERMISSION_DENIED: CapabilityState.PERMISSION_DENIED,
        }
        state = states.get(result.outcome, CapabilityState.ERROR)
        capabilities.append(Capability(name, state, " ".join(argv[:2]), result.outcome.value))
        if result.outcome is not CommandOutcome.SUCCESS:
            continue
        try:
            records = parser(result.stdout)
        except Exception as exc:
            capabilities.append(Capability(name, CapabilityState.ERROR, "mercury.discovery", type(exc).__name__))
            continue
        for record in records:
            if isinstance(record, NeighborRecord):
                observe("neighbor_cache", record.source, {"address": record.address, "family": ipaddress.ip_address(record.address).version, "interface_name": record.interface_name, "state": record.state, "link_layer_address": record.link_layer_address, "passive": True})
            elif isinstance(record, WifiAccessPoint):
                observe("wifi_access_point", record.source, {"ssid": record.ssid, "bssid": record.bssid, "passive": True})
            elif isinstance(record, LldpNeighbor):
                lldp_ids.append(observe("direct_lldp_neighbor", record.source, {"chassis_id": record.chassis_id, "port_id": record.port_id, "interface_name": record.interface_name, "direct_evidence": True}))
    if lldp_ids:
        conclusion = Conclusion("passive-topology", "Direct LLDP neighbor observed", "Only direct LLDP evidence is used to identify an infrastructure neighbor.", Health.HEALTHY, Confidence.HIGH, tuple(lldp_ids))
    else:
        conclusion = Conclusion("passive-topology", "Access switch not observable", "Gateway, neighbor cache, Wi-Fi AP and route data do not identify an access switch.", Health.UNKNOWN, Confidence.HIGH, (ipv6_limit,), limitations=("No direct LLDP neighbor evidence was collected.",))
    return TaskResult(task_id, "discover_passive", Direction.LOCAL, "local", TaskState.COMPLETED, instant, instant, {"profile": "passive-discovery-v1", "passive": True}, EffectiveConfig("passive-discovery-v1", ("local",), False, "passive-discovery-v1", {}), Progress(0, 0, 0), tuple(observations), (conclusion,), tuple(capabilities))


@dataclass(frozen=True, slots=True)
class DiscoveryRequest:
    network: str
    scope: str
    profile: str = "common"
    ports: tuple[int, ...] = ()
    timeout_s: float = 1.0
    authorized: bool = False
    confirmations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        target_value = parse_target(self.network)
        scope_value = parse_target(self.scope)
        if target_value.kind is not TargetKind.NETWORK or scope_value.kind is not TargetKind.NETWORK:
            raise PolicyError("active discovery requires IPv4 CIDR targets")
        assert target_value.network is not None and scope_value.network is not None
        target, scope = target_value.network, scope_value.network
        if target.version != 4 or scope.version != 4:
            raise PolicyError("active discovery supports IPv4 CIDR only")
        if not target.subnet_of(scope):
            raise PolicyError("discovery CIDR must be contained in the authorized scope")
        if self.profile not in {"common", "custom", "full"}:
            raise ValueError("discovery profile must be common, custom, or full")
        if not isinstance(self.authorized, bool):
            raise ValueError("authorized must be boolean")
        if not isinstance(self.timeout_s, (int, float)) or not 0.1 <= float(self.timeout_s) <= 30:
            raise ValueError("discovery timeout must be within 0.1..30 seconds")
        if self.profile == "custom":
            if not self.ports or any(type(port) is not int or not 1 <= port <= 65_535 for port in self.ports):
                raise ValueError("custom discovery requires bounded valid TCP ports")
        elif self.ports:
            raise ValueError("only the custom profile accepts explicit ports")
        if not isinstance(self.confirmations, (tuple, list)) or any(not isinstance(item, str) for item in self.confirmations):
            raise ValueError("confirmations must be text")
        object.__setattr__(self, "network", target.with_prefixlen)
        object.__setattr__(self, "scope", scope.with_prefixlen)
        object.__setattr__(self, "ports", tuple(sorted(set(self.ports))))
        object.__setattr__(self, "confirmations", tuple(self.confirmations))
        object.__setattr__(self, "timeout_s", float(self.timeout_s))

    @property
    def selected_ports(self) -> tuple[int, ...]:
        if self.profile == "common":
            return COMMON_TCP_PORTS
        if self.profile == "full":
            return tuple(range(1, 65_536))
        return self.ports


def default_discovery_grant(request: DiscoveryRequest) -> ScopeGrant:
    return ScopeGrant(networks=(ipaddress.ip_network(request.scope),), ports=request.selected_ports, transports=("tcp",), probe_kinds=(), attested=request.authorized, purpose="authorized bounded TCP discovery", expires_at=datetime.now(timezone.utc) + timedelta(minutes=15))


def compile_discovery(request: DiscoveryRequest, *, grant: ScopeGrant) -> PlanPreview:
    if type(request) is not DiscoveryRequest or type(grant) is not ScopeGrant:
        raise TypeError("discovery request and grant must be canonical")
    if not request.authorized or not grant.attested:
        raise PolicyError("active discovery requires explicit authorization attestation")
    # The grant carries TCP permission and is rechecked by preview_plan for every address.
    limits: BudgetLimits = ABSOLUTE_CEILINGS if request.profile == "full" else DEFAULT_LIMITS
    return preview_plan(target_values=(request.network,), ports=request.selected_ports, transports=("tcp",), grant=grant, profile=f"discovery-{request.profile}-tcp-v1", limits=limits, repeats=1, timeout_s=request.timeout_s)


class DiscoveryRunner:
    """Execute only the immutable plan steps, retaining TCP outcome semantics."""
    def __init__(self, *, protocol_dispatcher=run_protocol_probe) -> None:
        self.protocol_dispatcher = protocol_dispatcher

    async def __call__(self, context: TaskContext) -> None:
        for step in context.plan.preview.steps:
            await self.protocol_dispatcher(context, step.id)


async def run_discovery(
    request: DiscoveryRequest,
    *,
    history: HistoryStore,
    grant: ScopeGrant | None = None,
    service_factory=TaskService,
) -> TaskResult:
    effective_grant = default_discovery_grant(request) if grant is None else grant
    preview = compile_discovery(request, grant=effective_grant)
    plan: ProbePlan = authorize_plan(preview, confirmations=request.confirmations)
    service = service_factory(history)
    task_id = service.submit(
        plan, DiscoveryRunner(), task_kind="discover",
        requested_config={
            "profile": f"discovery-{request.profile}-tcp-v1",
            "targets": [request.network], "ports": list(request.selected_ports),
            "transports": ["tcp"], "timeout_s": request.timeout_s,
            "purpose": "authorized bounded TCP discovery", "network_io": True,
        },
    )
    try:
        result = await service.wait(task_id)
    except asyncio.CancelledError:
        service.cancel(task_id)
        result = await asyncio.shield(service.wait(task_id))
    if type(result) is not TaskResult:
        raise RuntimeError("discovery task returned an invalid result")
    return result


def full_confirmation_example(request: DiscoveryRequest, *, grant: ScopeGrant | None = None) -> str:
    """Return the digest-bound full-TCP phrase without opening a socket."""
    preview = compile_discovery(request, grant=default_discovery_grant(request) if grant is None else grant)
    if "full_tcp" not in preview.required_confirmations:
        raise ValueError("confirmation is only used by the full TCP profile")
    return confirmation_phrase("full_tcp", preview.digest)


__all__ = [
    "COMMON_TCP_PORTS", "DiscoveryRequest", "DiscoveryRunner", "LldpNeighbor",
    "NeighborRecord", "VisibleNetwork", "WifiAccessPoint", "collect_passive_discovery",
    "compile_discovery", "default_discovery_grant", "derive_ipv4_networks",
    "full_confirmation_example", "parse_linux_neighbors", "parse_lldpctl",
    "parse_windows_neighbors", "parse_windows_wifi", "run_discovery",
]
