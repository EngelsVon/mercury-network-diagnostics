from __future__ import annotations

import asyncio
from collections import namedtuple
from datetime import datetime, timezone
import errno
import socket
import unittest

from mercury.discovery import (
    DiscoveryRequest, DiscoveryRunner, collect_passive_discovery, compile_discovery,
    default_discovery_grant, derive_ipv4_networks, parse_linux_neighbors,
    parse_windows_neighbors, parse_windows_wifi, run_discovery,
)
from mercury.history import HistoryStore
from mercury.models import CapabilityState, EvidenceKind, TaskState
from mercury.platform.common import CommandOutcome, CommandResult
from mercury.planner import authorize_plan
from mercury.policy import PolicyError
from mercury.tasks import TaskService


Snicaddr = namedtuple("Snicaddr", "family address netmask broadcast ptp")


class FakePsutil:
    def net_if_addrs(self):
        return {
            "eth0": [
                Snicaddr(socket.AF_INET, "192.0.2.7", "255.255.255.0", None, None),
                Snicaddr(socket.AF_INET6, "2001:db8::7", "ffff:ffff:ffff:ffff::", None, None),
            ],
        }


async def missing_command(argv, _timeout, _maximum):
    return CommandResult(argv, None, "", "", CommandOutcome.MISSING_TOOL, error_type="FileNotFoundError")


class PassiveDiscoveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_ipv4_only_networks_and_missing_tools_are_explicit(self):
        self.assertEqual(
            derive_ipv4_networks(psutil_module=FakePsutil())[0].network,
            "192.0.2.0/24",
        )
        result = await collect_passive_discovery(
            clock=lambda: datetime(2026, 8, 2, tzinfo=timezone.utc),
            psutil_module=FakePsutil(), system=lambda: "Linux",
            command_runner=missing_command,
        )
        networks = [item for item in result.observations if item.probe == "connected_ipv4_network"]
        self.assertEqual([item.detail["network"] for item in networks], ["192.0.2.0/24"])
        self.assertTrue(any(item.evidence_kind is EvidenceKind.UNSUPPORTED for item in result.observations))
        capabilities = {item.name: item.state for item in result.capabilities}
        self.assertIs(capabilities["neighbor_cache"], CapabilityState.MISSING_TOOL)
        self.assertIs(capabilities["ipv6_host_enumeration"], CapabilityState.UNSUPPORTED)
        self.assertIn("do not identify", result.conclusions[0].summary)

    async def test_parsers_do_not_turn_neighbors_or_wifi_into_lldp(self):
        linux = parse_linux_neighbors('[{"dst":"192.0.2.1","dev":"eth0","lladdr":"00:11:22:33:44:55","state":"REACHABLE"}]')
        windows = parse_windows_neighbors('{"IPAddress":"192.0.2.2","InterfaceAlias":"Ethernet","LinkLayerAddress":"00-11-22-33-44-56","State":"Reachable"}')
        wifi = parse_windows_wifi("    SSID                   : Campus\n    BSSID                  : 00:11:22:33:44:57\n")
        self.assertEqual(linux[0].address, "192.0.2.1")
        self.assertEqual(windows[0].interface_name, "Ethernet")
        self.assertEqual(wifi[0].ssid, "Campus")


class ActiveDiscoveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_scope_and_authorization_reject_before_connects(self):
        with self.assertRaises(PolicyError):
            DiscoveryRequest("192.0.2.0/30", "198.51.100.0/24", authorized=True)
        request = DiscoveryRequest("192.0.2.0/30", "192.0.2.0/24", authorized=False)
        with self.assertRaises(PolicyError):
            compile_discovery(request, grant=default_discovery_grant(request))
        with self.assertRaises(PolicyError):
            DiscoveryRequest("2001:db8::/64", "2001:db8::/64", authorized=True)

    async def test_loopback_success_and_refusal_retain_distinct_evidence(self):
        server = await asyncio.start_server(lambda _reader, writer: writer.close(), "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            request = DiscoveryRequest("127.0.0.1/32", "127.0.0.0/8", profile="custom", ports=(port,), timeout_s=0.5, authorized=True)
            with HistoryStore(":memory:") as history:
                result = await run_discovery(request, history=history)
            self.assertEqual(result.progress.completed, 1)
            self.assertEqual(result.observations[0].evidence_kind, EvidenceKind.TCP_CONNECTED)
        finally:
            server.close()
            await server.wait_closed()

        refusal = DiscoveryRequest("127.0.0.1/32", "127.0.0.0/8", profile="custom", ports=(port,), timeout_s=0.5, authorized=True)
        plan = authorize_plan(compile_discovery(refusal, grant=default_discovery_grant(refusal)))

        async def refused_connector(*_args, **_kwargs):
            raise ConnectionRefusedError(errno.ECONNREFUSED, "controlled refusal")

        class RefusalRunner:
            async def __call__(self, context):
                from mercury.probes import run_protocol_probe
                await run_protocol_probe(context, context.plan.preview.steps[0].id, connector=refused_connector)

        with HistoryStore(":memory:") as history:
            service = TaskService(history)
            task_id = service.submit(plan, RefusalRunner(), task_kind="discover", requested_config={"profile": "discovery-custom-tcp-v1", "targets": ["127.0.0.1/32"], "ports": [port], "transports": ["tcp"], "timeout_s": 0.5, "purpose": "controlled test", "network_io": True})
            result = await service.wait(task_id)
        self.assertEqual(result.progress.completed, 1)
        self.assertEqual(result.observations[0].evidence_kind, EvidenceKind.TCP_REFUSED)

    async def test_custom_profile_and_timeout_are_digest_bound(self):
        request = DiscoveryRequest("127.0.0.1/32", "127.0.0.0/8", profile="custom", ports=(443, 22), timeout_s=0.25, authorized=True)
        preview = compile_discovery(request, grant=default_discovery_grant(request))
        self.assertEqual(preview.ports, (22, 443))
        self.assertTrue(all(step.timeout_s == 0.25 for step in preview.steps))
        with self.assertRaises(ValueError):
            DiscoveryRequest("127.0.0.1/32", "127.0.0.0/8", profile="custom", authorized=True)

    async def test_full_profile_needs_digest_confirmation_before_task_submission(self):
        request = DiscoveryRequest("127.0.0.1/32", "127.0.0.0/8", profile="full", authorized=True)
        preview = compile_discovery(request, grant=default_discovery_grant(request))
        self.assertEqual(preview.required_confirmations, ("full_tcp",))
        with self.assertRaises(PermissionError):
            authorize_plan(preview)

    async def test_cancellation_preserves_partial_discovery_progress(self):
        request = DiscoveryRequest("127.0.0.0/30", "127.0.0.0/8", profile="custom", ports=(443,), authorized=True)
        plan = authorize_plan(compile_discovery(request, grant=default_discovery_grant(request)))

        async def delayed_probe(context, step_id):
            await context.admit(step_id)
            await context.cancellation.wait_or_timeout(60)

        with HistoryStore(":memory:") as history:
            service = TaskService(history)
            task_id = service.submit(plan, DiscoveryRunner(protocol_dispatcher=delayed_probe), task_kind="discover", requested_config={"profile": "discovery-custom-tcp-v1", "targets": ["127.0.0.0/30"], "ports": [443], "transports": ["tcp"], "timeout_s": 1.0, "purpose": "controlled cancellation", "network_io": True})
            await asyncio.sleep(0)
            service.cancel(task_id)
            result = await service.wait(task_id)
        self.assertEqual(result.state, TaskState.CANCELLED)
        self.assertEqual(result.progress.admitted, 1)
        self.assertEqual(result.progress.completed, 0)


if __name__ == "__main__":
    unittest.main()
