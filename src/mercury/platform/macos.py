"""macOS route/netstat/scutil passive inventory adapter."""

from __future__ import annotations

import re
from typing import Iterable

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

MACOS_ROUTE_V4_ARGV = ("/sbin/route", "-n", "get", "default")
MACOS_ROUTE_V6_ARGV = ("/sbin/route", "-n", "get", "-inet6", "default")
MACOS_NETSTAT_V4_ARGV = ("/usr/sbin/netstat", "-rn", "-f", "inet")
MACOS_NETSTAT_V6_ARGV = ("/usr/sbin/netstat", "-rn", "-f", "inet6")
MACOS_SCUTIL_DNS_ARGV = ("/usr/sbin/scutil", "--dns")


def _destination(value: str, family: int) -> str:
    value = value.split("%", 1)[0]
    if value in ("default", "0.0.0.0"):
        return "0.0.0.0/0" if family == 4 else "::/0"
    if family == 6 and value == "::":
        return "::/0"
    if family == 4 and "/" in value:
        address, prefix = value.rsplit("/", 1)
        if address.count(".") == 2:
            value = f"{address}.0/{prefix}"
    return value


def _parse_index(value: str | None) -> int | None:
    if value is None:
        return None
    match = re.search(r"\d+", value)
    return None if match is None else int(match.group())


def parse_route_get(document: str, family: int) -> RouteRecord:
    """Parse the labelled ``route -n get`` form rather than fixed columns."""

    values: dict[str, str] = {}
    for line in document.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        values[key.strip().casefold()] = value.strip()
    destination = values.get("destination") or values.get("route to")
    interface = values.get("interface")
    if not destination or not interface:
        raise ValueError("route get output lacks destination or interface")
    gateway = values.get("gateway")
    if gateway in (None, "", "#"):
        gateway = None
    elif gateway is not None:
        gateway = gateway.split("%", 1)[0]
    return RouteRecord(
        family=family,
        destination=_destination(destination, family),
        gateway=gateway,
        interface_name=interface,
        interface_index=_parse_index(values.get("interface index")),
        flags=tuple(values.get("flags", "").split()),
        on_link=gateway is None,
        source="macos.route_get",
    )


def _header_positions(lines: list[str]) -> tuple[int, dict[str, int]]:
    for position, line in enumerate(lines):
        headings = line.split()
        normalized = {name.casefold(): index for index, name in enumerate(headings)}
        if {"destination", "gateway", "flags"} <= set(normalized):
            return position, normalized
    raise ValueError("netstat output has no route header")


def parse_netstat(document: str, family: int) -> tuple[RouteRecord, ...]:
    """Parse table rows by their observed header names, not fixed offsets."""

    lines = [line.strip() for line in document.splitlines() if line.strip()]
    header_line, positions = _header_positions(lines)
    interface_position = positions.get("netif", positions.get("interface"))
    if interface_position is None:
        raise ValueError("netstat output has no interface column")
    required = max(positions["destination"], positions["gateway"], positions["flags"], interface_position)
    parsed: list[RouteRecord] = []
    for source_index, line in enumerate(lines[header_line + 1 :]):
        fields = line.split()
        if len(fields) <= required:
            continue
        destination = fields[positions["destination"]]
        gateway = fields[positions["gateway"]]
        interface = fields[interface_position]
        if gateway in ("link#", "#", "-") or gateway.startswith("link#"):
            gateway = None
        else:
            gateway = gateway.split("%", 1)[0]
        parsed.append(
            RouteRecord(
                family=family,
                destination=_destination(destination, family),
                gateway=gateway,
                interface_name=interface,
                flags=(fields[positions["flags"]],),
                on_link=gateway is None,
                source="macos.netstat",
                source_record_index=source_index,
            )
        )
    return tuple(parsed)


def _resolver_blocks(document: str) -> Iterable[list[str]]:
    block: list[str] = []
    for line in document.splitlines():
        if re.match(r"^resolver\s+#\d+", line.strip(), re.IGNORECASE):
            if block:
                yield block
            block = [line]
        elif block:
            block.append(line)
    if block:
        yield block


def _block_value(block: list[str], prefix: str) -> str | None:
    for line in block:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key.strip().casefold().startswith(prefix):
            return value.strip()
    return None


def parse_scutil_dns(document: str) -> tuple[DnsServerRecord, ...]:
    """Parse default and supplemental resolver blocks with scoped DNS intact."""

    parsed: list[DnsServerRecord] = []
    for block_number, block in enumerate(_resolver_blocks(document)):
        interface_field = _block_value(block, "if_index")
        interface_index = _parse_index(interface_field)
        interface_match = re.search(r"\(([^)]+)\)", interface_field or "")
        interface = interface_match.group(1) if interface_match else "global"
        domain = _block_value(block, "search domain") or _block_value(block, "domain")
        state = "supplemental" if domain else "default"
        found = False
        for line in block:
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            if not key.strip().casefold().startswith("nameserver"):
                continue
            server = value.strip()
            address, separator, scope = server.partition("%")
            if separator and not scope:
                raise ValueError("scutil resolver has an empty scope")
            family = 6 if ":" in address else 4
            parsed.append(
                DnsServerRecord(
                    family=family,
                    address=address,
                    scope_id=scope or None,
                    interface_name=interface,
                    interface_index=interface_index,
                    resolver_order=len(parsed),
                    scoped_domain=domain,
                    source="macos.scutil",
                    configuration_state=state,
                )
            )
            found = True
        if not found and len(block) > 1:
            raise ValueError(f"resolver block {block_number} has no nameserver")
    if not parsed:
        raise ValueError("scutil output has no resolver records")
    return tuple(parsed)


def _parse_capability(name: str, source: str) -> Capability:
    return Capability(name, CapabilityState.ERROR, source, "parse_error")


async def collect_platform(
    *,
    runner: CommandRunner = run_passive_command,
    timeout_s: float = 5.0,
) -> PlatformRecords:
    """Collect each macOS route/DNS source independently."""

    results = (
        ("macos_default_route_ipv4", "macos.route_get", 4, MACOS_ROUTE_V4_ARGV),
        ("macos_default_route_ipv6", "macos.route_get", 6, MACOS_ROUTE_V6_ARGV),
        ("macos_routes_ipv4", "macos.netstat", 4, MACOS_NETSTAT_V4_ARGV),
        ("macos_routes_ipv6", "macos.netstat", 6, MACOS_NETSTAT_V6_ARGV),
    )
    command_results = {
        argv: await runner(argv, timeout_s, MAX_COMMAND_OUTPUT_BYTES)
        for _, _, _, argv in results
    }
    dns_result = await runner(MACOS_SCUTIL_DNS_ARGV, timeout_s, MAX_COMMAND_OUTPUT_BYTES)
    routes: list[RouteRecord] = []
    dns_servers: tuple[DnsServerRecord, ...] = ()
    capabilities: list[Capability] = []

    for name, source, family, argv in results:
        result = command_results[argv]
        if result.outcome is not CommandOutcome.SUCCESS:
            capabilities.append(capability_for_command(name, source, result))
            continue
        try:
            parsed = parse_route_get(result.stdout, family) if "default_route" in name else parse_netstat(result.stdout, family)
        except ValueError:
            capabilities.append(_parse_capability(name, source))
        else:
            routes.extend((parsed,) if isinstance(parsed, RouteRecord) else parsed)
            capabilities.append(capability_for_command(name, source, result))

    if dns_result.outcome is CommandOutcome.SUCCESS:
        try:
            dns_servers = parse_scutil_dns(dns_result.stdout)
        except ValueError:
            capabilities.append(_parse_capability("macos_dns", "macos.scutil"))
        else:
            capabilities.append(capability_for_command("macos_dns", "macos.scutil", dns_result))
    else:
        capabilities.append(capability_for_command("macos_dns", "macos.scutil", dns_result))
    return PlatformRecords(routes=tuple(routes), dns_servers=dns_servers, capabilities=tuple(capabilities))


__all__ = [
    "MACOS_NETSTAT_V4_ARGV",
    "MACOS_NETSTAT_V6_ARGV",
    "MACOS_ROUTE_V4_ARGV",
    "MACOS_ROUTE_V6_ARGV",
    "MACOS_SCUTIL_DNS_ARGV",
    "collect_platform",
    "parse_netstat",
    "parse_route_get",
    "parse_scutil_dns",
]
