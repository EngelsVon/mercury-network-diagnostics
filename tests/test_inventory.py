"""Fixture-only tests for the passive local inventory service."""

from __future__ import annotations

import asyncio
from collections import namedtuple
from datetime import datetime, timezone
import socket
import unittest

from mercury.codec import result_from_json, result_to_json
from mercury.inventory import (
    MAX_DNS_SERVERS,
    MAX_INTERFACE_ADDRESSES,
    MAX_INTERFACES,
    MAX_ROUTES,
    collect_status,
)
from mercury.models import CapabilityState, Direction, EvidenceKind
from mercury.platform.common import DnsServerRecord, PlatformRecords, RouteRecord


Snicaddr = namedtuple("Snicaddr", "family address netmask broadcast ptp")
Snicstats = namedtuple("Snicstats", "isup duplex speed mtu")
FIXED_TIME = datetime(2026, 7, 31, 12, 0, tzinfo=timezone.utc)


class FakePsutil:
    AF_LINK = 17

    def __init__(self, addresses, stats, *, address_error=None, stats_error=None):
        self.addresses = addresses
        self.stats = stats
        self.address_error = address_error
        self.stats_error = stats_error

    def net_if_addrs(self):
        if self.address_error:
            raise self.address_error
        return self.addresses

    def net_if_stats(self):
        if self.stats_error:
            raise self.stats_error
        return self.stats


def fixture_records(*, routes=(), dns_servers=(), capabilities=()):
    async def collector():
        return PlatformRecords(routes=routes, dns_servers=dns_servers, capabilities=capabilities)

    return collector


class InventoryTests(unittest.TestCase):
    def collect(self, *, psutil_module, collector=None, **kwargs):
        return asyncio.run(
            collect_status(
                clock=lambda: FIXED_TIME,
                hostname=lambda: "mercury-host",
                system=lambda: "Windows",
                release=lambda: "11",
                machine=lambda: "AMD64",
                python_version=lambda: "3.13.0",
                mercury_version=lambda: "0.1.0",
                psutil_module=psutil_module,
                platform_collector=collector or fixture_records(),
                **kwargs,
            )
        )

    def test_facts_interfaces_routes_dns_and_switch_limitation(self):
        addresses = {
            "以太网": [
                Snicaddr(socket.AF_INET, "192.0.2.9", "255.255.255.0", None, None),
                Snicaddr(socket.AF_INET6, "fe80::1%以太网", "ffff:ffff:ffff:ffff::", None, None),
                Snicaddr(17, "00-11-22-33-44-55", None, None, None),
            ],
            "VPN tunnel": [Snicaddr(socket.AF_INET, "198.51.100.8", None, None, None)],
        }
        stats = {
            "以太网": Snicstats(True, 0, 1_000, 1_500),
            "VPN tunnel": Snicstats(False, 0, 0, 0),
        }
        route = RouteRecord(
            family=4,
            destination="0.0.0.0/0",
            gateway="192.0.2.1",
            interface_name="以太网",
            route_metric=5,
            interface_metric=10,
            source="windows.Get-NetRoute",
        )
        dns = DnsServerRecord(
            family=6,
            address="fe80::53",
            scope_id="以太网",
            interface_name="以太网",
            source="windows.Get-DnsClientServerAddress",
        )
        result = self.collect(
            psutil_module=FakePsutil(addresses, stats),
            collector=fixture_records(routes=(route,), dns_servers=(dns,)),
        )

        self.assertEqual(result.task_kind, "status")
        self.assertEqual(result.direction, Direction.LOCAL)
        self.assertEqual((result.progress.admitted, result.progress.completed, result.progress.total), (0, 0, 0))
        host_fields = {item.detail["field"] for item in result.observations if item.probe == "host_fact"}
        self.assertEqual(host_fields, {"hostname", "system", "release", "machine", "python_version", "mercury_version", "collection_time"})
        ipv6 = next(item for item in result.observations if item.probe == "interface_address" and item.detail["family"] == 6)
        self.assertEqual(ipv6.detail["address"], "fe80::1")
        self.assertEqual(ipv6.detail["prefix_length"], 64)
        self.assertEqual(ipv6.detail["scope_id"], "以太网")
        tunnel = next(item for item in result.observations if item.probe == "interface" and item.detail["name"] == "VPN tunnel")
        self.assertIsNone(tunnel.detail["mtu"])
        self.assertIn("speed_mbps", tunnel.detail["unavailable"])
        route_observation = next(item for item in result.observations if item.probe == "route")
        self.assertEqual(route_observation.source, "windows.Get-NetRoute")
        self.assertEqual(route_observation.detail["effective_metric"], 15)
        self.assertTrue(route_observation.detail["is_default"])
        self.assertEqual(next(item for item in result.observations if item.probe == "dns_server").source, "windows.Get-DnsClientServerAddress")
        switch = next(item for item in result.observations if item.probe == "topology_limit")
        self.assertEqual(switch.evidence_kind, EvidenceKind.UNSUPPORTED)
        self.assertEqual(switch.detail["reason"], "no_direct_lldp_or_managed_evidence")
        self.assertIn("access switch is not observable", result.conclusions[0].summary.lower())
        self.assertNotIn("gateway", result.conclusions[0].summary.lower())

    def test_source_failures_are_independent_and_json_is_deterministic(self):
        addresses = {"eth0": [Snicaddr(socket.AF_INET, "192.0.2.3", "255.255.255.0", None, None)]}
        psutil_module = FakePsutil(addresses, {}, stats_error=RuntimeError("no stats"))

        async def failing_platform():
            raise PermissionError("denied")

        result = self.collect(psutil_module=psutil_module, collector=failing_platform)
        self.assertTrue(any(item.probe == "interface_address" for item in result.observations))
        states = {(item.name, item.state) for item in result.capabilities}
        self.assertIn(("interface_stats", CapabilityState.ERROR), states)
        self.assertIn(("platform_inventory", CapabilityState.ERROR), states)
        encoded = result_to_json(result)
        self.assertEqual(encoded, result_to_json(result))
        self.assertEqual(result_from_json(encoded), result)

    def test_all_psutil_sources_can_fail_without_invalidating_status(self):
        result = self.collect(
            psutil_module=FakePsutil({}, {}, address_error=RuntimeError(), stats_error=RuntimeError())
        )
        self.assertEqual(result.task_kind, "status")
        self.assertTrue(any(item.probe == "host_fact" for item in result.observations))
        self.assertEqual(
            {item.name for item in result.capabilities if item.state is CapabilityState.ERROR},
            {"interface_addresses", "interface_stats"},
        )

    def test_boundaries_retain_sorted_prefix_and_expose_limits(self):
        addresses = {
            f"if-{index:03d}": [
                Snicaddr(socket.AF_INET, f"192.0.2.{index % 250 + 1}", "255.255.255.0", None, None)
            ]
            for index in range(MAX_INTERFACES + 3)
        }
        stats = {name: Snicstats(True, 0, 100, 1_500) for name in addresses}
        routes = tuple(
            RouteRecord(4, f"198.18.{index // 256}.{index % 256}/32", "native", interface_name="if-000")
            for index in range(MAX_ROUTES + 2)
        )
        dns_servers = tuple(
            DnsServerRecord(4, f"203.0.113.{index % 250 + 1}", "native", interface_name="if-000", resolver_order=index)
            for index in range(MAX_DNS_SERVERS + 2)
        )
        result = self.collect(
            psutil_module=FakePsutil(addresses, stats),
            collector=fixture_records(routes=routes, dns_servers=dns_servers),
        )
        self.assertEqual(len([item for item in result.observations if item.probe == "interface"]), MAX_INTERFACES)
        self.assertEqual(len([item for item in result.observations if item.probe == "route"]), MAX_ROUTES)
        self.assertEqual(len([item for item in result.observations if item.probe == "dns_server"]), MAX_DNS_SERVERS)
        limits = {item.detail["source"]: item.detail["limit"] for item in result.observations if item.probe == "inventory_limit"}
        self.assertEqual(limits["interfaces"], MAX_INTERFACES)
        self.assertEqual(limits["routes"], MAX_ROUTES)
        self.assertEqual(limits["dns_servers"], MAX_DNS_SERVERS)

    def test_address_ceiling_is_reported(self):
        addresses = {
            "eth0": [
                Snicaddr(socket.AF_INET, f"10.{index // 65536}.{(index // 256) % 256}.{index % 256}", "255.255.255.0", None, None)
                for index in range(MAX_INTERFACE_ADDRESSES + 1)
            ]
        }
        result = self.collect(psutil_module=FakePsutil(addresses, {"eth0": Snicstats(True, 0, 1, 1)}))
        self.assertEqual(len([item for item in result.observations if item.probe == "interface_address"]), MAX_INTERFACE_ADDRESSES)
        self.assertTrue(any(item.detail.get("source") == "interface_addresses" for item in result.observations if item.probe == "inventory_limit"))


if __name__ == "__main__":
    unittest.main()
