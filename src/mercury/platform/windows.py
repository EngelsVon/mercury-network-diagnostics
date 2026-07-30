"""Windows PowerShell route and DNS inventory adapter."""

from __future__ import annotations

import json
from typing import Any

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

_POWERSHELL_PREFIX = (
    "$OutputEncoding = [System.Text.UTF8Encoding]::new($false); "
    "[Console]::OutputEncoding = $OutputEncoding; "
)
WINDOWS_ROUTES_SCRIPT = _POWERSHELL_PREFIX + (
    "$interfaces = @(Get-NetIPInterface | Select-Object AddressFamily,"
    "InterfaceIndex,InterfaceAlias,InterfaceMetric,ConnectionState); "
    "$routes = @(Get-NetRoute -PolicyStore ActiveStore | Select-Object "
    "AddressFamily,DestinationPrefix,NextHop,InterfaceIndex,InterfaceAlias,"
    "RouteMetric,Protocol,State); "
    "[PSCustomObject]@{interfaces=$interfaces;routes=$routes} | "
    "ConvertTo-Json -Compress -Depth 4"
)
WINDOWS_DNS_SCRIPT = _POWERSHELL_PREFIX + (
    "@(Get-DnsClientServerAddress | Select-Object InterfaceAlias,"
    "InterfaceIndex,AddressFamily,ServerAddresses) | "
    "ConvertTo-Json -Compress -Depth 4"
)
WINDOWS_ROUTES_ARGV = (
    "powershell.exe",
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-Command",
    WINDOWS_ROUTES_SCRIPT,
)
WINDOWS_DNS_ARGV = (
    "powershell.exe",
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-Command",
    WINDOWS_DNS_SCRIPT,
)


def _json_document(text: str, source: str) -> Any:
    if not text.strip():
        raise ValueError(f"{source} returned empty JSON")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{source} returned malformed JSON") from exc


def _records(value: Any, name: str) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list) and all(isinstance(item, dict) for item in value):
        return value
    raise ValueError(f"{name} must be a JSON object or array of objects")


def _family(value: Any) -> int:
    if value in ("IPv4", "ipv4", 2, "2"):
        return 4
    if value in ("IPv6", "ipv6", 23, "23"):
        return 6
    raise ValueError("Windows record has an unsupported address family")


def _nonnegative_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    if type(value) is bool:
        raise ValueError("metric/index cannot be boolean")
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("metric/index must be an integer") from exc
    if number < 0:
        raise ValueError("metric/index cannot be negative")
    return number


def _interface_name(value: Any, index: int | None) -> str:
    if isinstance(value, str) and value.strip():
        return value
    if index is not None:
        return f"ifindex-{index}"
    raise ValueError("Windows record has no interface identity")


def _gateway(value: Any, family: int) -> tuple[str | None, bool | None]:
    if value in (None, "", "0.0.0.0", "::"):
        return None, True
    if not isinstance(value, str):
        raise ValueError("Windows next hop must be text")
    return value, False


def parse_routes(document: str) -> tuple[RouteRecord, ...]:
    """Parse the fixed PowerShell route/interface document."""

    root = _json_document(document, "Windows route source")
    if not isinstance(root, dict):
        raise ValueError("Windows route document must be an object")
    routes = _records(root.get("routes", []), "routes")
    interfaces = _records(root.get("interfaces", []), "interfaces")
    metrics: dict[tuple[int, int], tuple[int | None, str | None]] = {}
    for entry in interfaces:
        family = _family(entry.get("AddressFamily"))
        index = _nonnegative_int(entry.get("InterfaceIndex"))
        if index is None:
            continue
        metrics[(family, index)] = (
            _nonnegative_int(entry.get("InterfaceMetric")),
            entry.get("InterfaceAlias"),
        )

    parsed: list[RouteRecord] = []
    for position, entry in enumerate(routes):
        family = _family(entry.get("AddressFamily"))
        index = _nonnegative_int(entry.get("InterfaceIndex"))
        if index is None:
            raise ValueError("Windows route has no interface index")
        interface_metric, joined_alias = metrics.get((family, index), (None, None))
        alias = entry.get("InterfaceAlias") or joined_alias
        gateway, on_link = _gateway(entry.get("NextHop"), family)
        destination = entry.get("DestinationPrefix")
        if not isinstance(destination, str):
            raise ValueError("Windows route has no destination prefix")
        parsed.append(
            RouteRecord(
                family=family,
                destination=destination,
                gateway=gateway,
                interface_name=_interface_name(alias, index),
                interface_index=index,
                route_metric=_nonnegative_int(entry.get("RouteMetric")),
                interface_metric=interface_metric,
                protocol=entry.get("Protocol") if isinstance(entry.get("Protocol"), str) else None,
                state=entry.get("State") if isinstance(entry.get("State"), str) else None,
                source="windows.Get-NetRoute",
                on_link=on_link,
                source_record_index=position,
            )
        )
    return tuple(parsed)


def _split_scoped_address(value: str) -> tuple[str, str | None]:
    address, separator, scope = value.partition("%")
    if not separator:
        return value, None
    if not scope:
        raise ValueError("Windows DNS scope is empty")
    return address, scope


def parse_dns(document: str) -> tuple[DnsServerRecord, ...]:
    """Parse configured DNS rows; placeholder values are not IP evidence."""

    rows = _records(_json_document(document, "Windows DNS source"), "DNS rows")
    parsed: list[DnsServerRecord] = []
    order = 0
    for row in rows:
        family = _family(row.get("AddressFamily"))
        index = _nonnegative_int(row.get("InterfaceIndex"))
        name = _interface_name(row.get("InterfaceAlias"), index)
        servers = row.get("ServerAddresses")
        if servers is None:
            continue
        if not isinstance(servers, list):
            raise ValueError("Windows DNS server addresses must be an array")
        for server in servers:
            if not isinstance(server, str):
                raise ValueError("Windows DNS server address must be text")
            if server in ("", "0.0.0.0", "::"):
                continue
            address, scope = _split_scoped_address(server)
            parsed.append(
                DnsServerRecord(
                    family=family,
                    address=address,
                    scope_id=scope,
                    interface_name=name,
                    interface_index=index,
                    resolver_order=order,
                    source="windows.Get-DnsClientServerAddress",
                    configuration_state="configured",
                )
            )
            order += 1
    return tuple(parsed)


def _parse_capability(name: str, source: str) -> Capability:
    return Capability(
        name=name,
        state=CapabilityState.ERROR,
        source=source,
        detail="parse_error",
    )


async def collect_platform(
    *,
    runner: CommandRunner = run_passive_command,
    timeout_s: float = 5.0,
) -> PlatformRecords:
    """Collect independent Windows route and configured-DNS evidence."""

    routes_result = await runner(WINDOWS_ROUTES_ARGV, timeout_s, MAX_COMMAND_OUTPUT_BYTES)
    dns_result = await runner(WINDOWS_DNS_ARGV, timeout_s, MAX_COMMAND_OUTPUT_BYTES)
    routes: tuple[RouteRecord, ...] = ()
    dns_servers: tuple[DnsServerRecord, ...] = ()
    capabilities: list[Capability] = []

    if routes_result.outcome is CommandOutcome.SUCCESS:
        try:
            routes = parse_routes(routes_result.stdout)
        except ValueError:
            capabilities.append(_parse_capability("windows_routes", "windows.Get-NetRoute"))
        else:
            capabilities.append(capability_for_command("windows_routes", "windows.Get-NetRoute", routes_result))
    else:
        capabilities.append(capability_for_command("windows_routes", "windows.Get-NetRoute", routes_result))

    if dns_result.outcome is CommandOutcome.SUCCESS:
        try:
            dns_servers = parse_dns(dns_result.stdout)
        except ValueError:
            capabilities.append(_parse_capability("windows_dns", "windows.Get-DnsClientServerAddress"))
        else:
            capabilities.append(capability_for_command("windows_dns", "windows.Get-DnsClientServerAddress", dns_result))
    else:
        capabilities.append(capability_for_command("windows_dns", "windows.Get-DnsClientServerAddress", dns_result))

    return PlatformRecords(routes=routes, dns_servers=dns_servers, capabilities=tuple(capabilities))


__all__ = [
    "WINDOWS_DNS_ARGV",
    "WINDOWS_DNS_SCRIPT",
    "WINDOWS_ROUTES_ARGV",
    "WINDOWS_ROUTES_SCRIPT",
    "collect_platform",
    "parse_dns",
    "parse_routes",
]
