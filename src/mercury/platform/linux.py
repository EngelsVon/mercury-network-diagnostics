"""Linux iproute2 and resolver configuration inventory adapter."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from mercury.models import Capability, CapabilityState

from .common import (
    CommandOutcome,
    CommandRunner,
    DnsServerRecord,
    MAX_COMMAND_OUTPUT_BYTES,
    PlatformRecords,
    RouteRecord,
    capability_for_command,
    run_passive_command,
)

LINUX_IPV4_ROUTES_ARGV = ("ip", "-j", "-4", "route", "show", "table", "all")
LINUX_IPV6_ROUTES_ARGV = ("ip", "-j", "-6", "route", "show", "table", "all")
LINUX_RESOLVECTL_ARGV = ("resolvectl", "status", "--json=short", "--no-pager")
RESOLV_CONF_PATH = Path("/etc/resolv.conf")


def _json_rows(document: str, source: str) -> list[dict[str, Any]]:
    try:
        value = json.loads(document)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{source} returned malformed JSON") from exc
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError(f"{source} must return a JSON array")
    return value


def _nonnegative_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    if type(value) is bool:
        raise ValueError("route metric cannot be boolean")
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("route metric must be an integer") from exc
    if number < 0:
        raise ValueError("route metric cannot be negative")
    return number


def parse_routes(document: str, family: int) -> tuple[RouteRecord, ...]:
    """Parse one ``ip -j`` family without guessing missing route fields."""

    parsed: list[RouteRecord] = []
    for position, row in enumerate(_json_rows(document, "ip")):
        destination = row.get("dst", "default")
        if destination == "default":
            destination = "0.0.0.0/0" if family == 4 else "::/0"
        if not isinstance(destination, str):
            raise ValueError("route destination must be text")
        interface = row.get("dev")
        if not isinstance(interface, str) or not interface.strip():
            raise ValueError("ip route has no device")
        gateway = row.get("gateway")
        if gateway is not None and not isinstance(gateway, str):
            raise ValueError("ip route gateway must be text")
        preferred = row.get("prefsrc")
        if preferred is not None and not isinstance(preferred, str):
            raise ValueError("ip route preferred source must be text")
        flags = row.get("flags", ())
        if isinstance(flags, str):
            flags = (flags,)
        if not isinstance(flags, list | tuple) or not all(isinstance(item, str) for item in flags):
            raise ValueError("ip route flags must be text")
        parsed.append(
            RouteRecord(
                family=family,
                destination=destination,
                gateway=gateway,
                interface_name=interface,
                route_metric=_nonnegative_int(row.get("metric")),
                preferred_source=preferred,
                protocol=row.get("protocol") if isinstance(row.get("protocol"), str) else None,
                scope=row.get("scope") if isinstance(row.get("scope"), str) else None,
                route_type=row.get("type") if isinstance(row.get("type"), str) else None,
                flags=tuple(flags),
                on_link=gateway is None,
                source="linux.iproute2",
                source_record_index=position,
            )
        )
    return tuple(parsed)


def _split_scoped_address(value: str) -> tuple[str, str | None]:
    address, separator, scope = value.partition("%")
    if not separator:
        return value, None
    if not scope:
        raise ValueError("DNS scope is empty")
    return address, scope


def parse_resolv_conf(document: str) -> tuple[DnsServerRecord, ...]:
    """Parse only direct ``nameserver`` directives; includes stay untouched."""

    if len(document.encode("utf-8", "replace")) > MAX_COMMAND_OUTPUT_BYTES:
        raise ValueError("resolv.conf exceeds the byte ceiling")
    parsed: list[DnsServerRecord] = []
    for order, line in enumerate(document.splitlines()):
        content = line.split("#", 1)[0].split(";", 1)[0].strip()
        if not content:
            continue
        fields = content.split()
        if fields[0] != "nameserver":
            continue
        if len(fields) != 2:
            raise ValueError("resolv.conf nameserver line is malformed")
        address, scope = _split_scoped_address(fields[1])
        family = 6 if ":" in address else 4
        state = "local_stub" if address == "127.0.0.53" else "resolver_visible"
        parsed.append(
            DnsServerRecord(
                family=family,
                address=address,
                scope_id=scope,
                interface_name="global",
                resolver_order=len(parsed),
                source="linux.resolv.conf",
                configuration_state=state,
            )
        )
    return tuple(parsed)


def _walk_resolvectl(value: Any, interface: str = "global", index: int | None = None) -> list[DnsServerRecord]:
    """Tolerate the small documented JSON shape variations across systemd releases."""

    records: list[DnsServerRecord] = []
    if isinstance(value, dict):
        name = value.get("name") or value.get("ifname") or value.get("interface") or interface
        current_interface = name if isinstance(name, str) and name else interface
        raw_index = value.get("ifindex", value.get("index", index))
        try:
            current_index = _nonnegative_int(raw_index)
        except ValueError:
            current_index = index
        for key, item in value.items():
            if key.casefold().replace(" ", "_") in {"dns", "dns_servers", "dns_server", "servers"}:
                values = item if isinstance(item, list) else [item]
                for server in values:
                    if not isinstance(server, str):
                        continue
                    address, scope = _split_scoped_address(server)
                    family = 6 if ":" in address else 4
                    records.append(
                        DnsServerRecord(
                            family=family,
                            address=address,
                            scope_id=scope,
                            interface_name=current_interface,
                            interface_index=current_index,
                            resolver_order=len(records),
                            source="linux.resolvectl",
                            configuration_state="per_link_configured",
                        )
                    )
            else:
                records.extend(_walk_resolvectl(item, current_interface, current_index))
    elif isinstance(value, list):
        for item in value:
            records.extend(_walk_resolvectl(item, interface, index))
    return records


def parse_resolvectl(document: str) -> tuple[DnsServerRecord, ...]:
    try:
        value = json.loads(document)
    except json.JSONDecodeError as exc:
        raise ValueError("resolvectl returned malformed JSON") from exc
    records = tuple(_walk_resolvectl(value))
    if not records:
        raise ValueError("resolvectl JSON has no DNS records")
    return records


def read_resolv_conf(path: Path = RESOLV_CONF_PATH) -> str:
    """Read only one bounded resolver file; no include expansion is performed."""

    with path.open("rb") as handle:
        content = handle.read(MAX_COMMAND_OUTPUT_BYTES + 1)
    if len(content) > MAX_COMMAND_OUTPUT_BYTES:
        raise ValueError("resolv.conf exceeds the byte ceiling")
    return content.decode("utf-8", "replace")


def _error_capability(name: str, source: str, detail: str) -> Capability:
    return Capability(name=name, state=CapabilityState.ERROR, source=source, detail=detail)


def _file_capability(name: str, source: str, exc: BaseException) -> Capability:
    if isinstance(exc, FileNotFoundError):
        state = CapabilityState.MISSING_TOOL
    elif isinstance(exc, PermissionError):
        state = CapabilityState.PERMISSION_DENIED
    else:
        state = CapabilityState.ERROR
    return Capability(name=name, state=state, source=source, detail=type(exc).__name__)


async def collect_platform(
    *,
    runner: CommandRunner = run_passive_command,
    timeout_s: float = 5.0,
    resolv_conf_reader: Callable[[], str] = read_resolv_conf,
) -> PlatformRecords:
    """Collect routes and resolver-visible DNS while keeping sources independent."""

    v4_result = await runner(LINUX_IPV4_ROUTES_ARGV, timeout_s, MAX_COMMAND_OUTPUT_BYTES)
    v6_result = await runner(LINUX_IPV6_ROUTES_ARGV, timeout_s, MAX_COMMAND_OUTPUT_BYTES)
    resolvectl_result = await runner(LINUX_RESOLVECTL_ARGV, timeout_s, MAX_COMMAND_OUTPUT_BYTES)
    routes: list[RouteRecord] = []
    dns_servers: list[DnsServerRecord] = []
    capabilities: list[Capability] = []

    for family, name, result in ((4, "linux_routes_ipv4", v4_result), (6, "linux_routes_ipv6", v6_result)):
        if result.outcome is CommandOutcome.SUCCESS:
            try:
                routes.extend(parse_routes(result.stdout, family))
            except ValueError:
                capabilities.append(_error_capability(name, "linux.iproute2", "parse_error"))
            else:
                capabilities.append(capability_for_command(name, "linux.iproute2", result))
        else:
            capabilities.append(capability_for_command(name, "linux.iproute2", result))

    try:
        baseline = parse_resolv_conf(resolv_conf_reader())
    except (OSError, ValueError) as exc:
        capabilities.append(_file_capability("linux_dns_resolv_conf", "linux.resolv.conf", exc))
    else:
        dns_servers.extend(baseline)
        stub = any(record.configuration_state == "local_stub" for record in baseline)
        detail = "local_stub_upstream_not_observable" if stub else "configured_nameservers"
        capabilities.append(Capability("linux_dns_resolv_conf", CapabilityState.AVAILABLE, "linux.resolv.conf", detail))

    if resolvectl_result.outcome is CommandOutcome.SUCCESS:
        try:
            dns_servers.extend(parse_resolvectl(resolvectl_result.stdout))
        except ValueError:
            capabilities.append(_error_capability("linux_dns_resolvectl", "linux.resolvectl", "parse_error"))
        else:
            capabilities.append(capability_for_command("linux_dns_resolvectl", "linux.resolvectl", resolvectl_result))
    else:
        capabilities.append(capability_for_command("linux_dns_resolvectl", "linux.resolvectl", resolvectl_result))

    return PlatformRecords(routes=tuple(routes), dns_servers=tuple(dns_servers), capabilities=tuple(capabilities))


__all__ = [
    "LINUX_IPV4_ROUTES_ARGV",
    "LINUX_IPV6_ROUTES_ARGV",
    "LINUX_RESOLVECTL_ARGV",
    "RESOLV_CONF_PATH",
    "collect_platform",
    "parse_resolv_conf",
    "parse_resolvectl",
    "parse_routes",
    "read_resolv_conf",
]
