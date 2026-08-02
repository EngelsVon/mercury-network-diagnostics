from __future__ import annotations

import asyncio
import unittest

from mercury.app import MercuryApplication
from mercury.history import HistoryStore
from mercury.models import CapabilityState, CoverageProfile, Disposition, EvidenceKind
from mercury.nmap_adapter import NativeNmapResult, NativePortState
from mercury.platform.common import CommandOutcome
from mercury.planner import BudgetError, InternalMappingRequest, authorize_internal_mapping, compile_internal_mapping
from mercury.policy import PolicyError


class InternalMappingRequestTests(unittest.TestCase):
    def test_private_overlapping_ranges_are_canonical_and_bounded(self) -> None:
        request = InternalMappingRequest(
            cidrs=("10.0.0.0/24", "10.0.0.0/25", "172.16.0.0/16"),
            profiles=(CoverageProfile.UDP_TAGGED, CoverageProfile.TCP_TAGGED),
            ports=(443, 53, 443), rate=10, concurrency=2, duration_s=0, authorized=True,
        )
        self.assertEqual(request.cidrs, ("10.0.0.0/24", "172.16.0.0/16"))
        self.assertEqual(request.ports, (53, 443))
        self.assertEqual(request.profiles, (CoverageProfile.TCP_TAGGED, CoverageProfile.UDP_TAGGED))

    def test_public_range_fails_before_planning(self) -> None:
        with self.assertRaisesRegex(PolicyError, "private scope"):
            InternalMappingRequest(
                cidrs=("198.51.100.0/24",), profiles=(CoverageProfile.TCP_TAGGED,),
                ports=(443,), rate=1, concurrency=1, duration_s=0, authorized=True,
            )

    def test_compilation_binds_cross_product_to_one_preview(self) -> None:
        request = InternalMappingRequest(
            cidrs=("127.0.0.1/32",), profiles=(CoverageProfile.TCP_TAGGED, CoverageProfile.UDP_TAGGED),
            ports=(53000,), rate=5, concurrency=2, duration_s=0, authorized=True,
        )
        preview = compile_internal_mapping(request)
        self.assertEqual(len(preview.steps), 2)
        self.assertEqual(preview.limits.max_global_rate, 5)
        self.assertEqual(preview.profile, "internal-mapping-v1")
        self.assertEqual(authorize_internal_mapping(request).preview.digest, preview.digest)

    def test_large_range_is_rejected_before_host_expansion(self) -> None:
        request = InternalMappingRequest(
            cidrs=("10.0.0.0/8",), profiles=(CoverageProfile.TCP_TAGGED,),
            ports=(443,), rate=1, concurrency=1, duration_s=0, authorized=True,
        )
        with self.assertRaisesRegex(BudgetError, "host estimate"):
            compile_internal_mapping(request)

    def test_application_routes_mapping_to_shared_authorization_service(self) -> None:
        with HistoryStore(":memory:") as history:
            application = MercuryApplication(history=history)
            plan = application.authorize_mapping(InternalMappingRequest(
                cidrs=("127.0.0.1/32",), profiles=(CoverageProfile.TCP_TAGGED,),
                ports=(443,), rate=1, concurrency=1, duration_s=0, authorized=True,
            ))
        self.assertEqual(plan.preview.profile, "internal-mapping-v1")

    def test_native_profile_is_a_closed_single_profile_plan(self) -> None:
        request = InternalMappingRequest(
            cidrs=("127.0.0.1/32",), profiles=(CoverageProfile.NMAP_SCTP_INIT,),
            ports=(53,), rate=2, concurrency=1, duration_s=0, authorized=True,
        )
        step = compile_internal_mapping(request).steps[0]
        self.assertEqual((step.probe_kind.value, step.transport.value), ("native_port_scan", "sctp"))
        with self.assertRaisesRegex(BudgetError, "exactly one"):
            compile_internal_mapping(InternalMappingRequest(
                cidrs=("127.0.0.1/32",),
                profiles=(CoverageProfile.NMAP_UDP, CoverageProfile.UDP_TAGGED),
                ports=(53,), rate=2, concurrency=1, duration_s=0, authorized=True,
            ))


class InternalMappingExecutionTests(unittest.IsolatedAsyncioTestCase):
    async def test_application_executes_loopback_mapping_through_task_service(self) -> None:
        with HistoryStore(":memory:") as history:
            application = MercuryApplication(history=history)
            result = await application.map_internal(InternalMappingRequest(
                cidrs=("127.0.0.1/32",), profiles=(CoverageProfile.TCP_CONNECT,),
                ports=(9,), rate=1, concurrency=1, duration_s=0, authorized=True,
            ))
            stored = history.get_task(result.task_id)
        self.assertEqual(result.task_kind, "internal_mapping")
        self.assertIsNotNone(stored)
        self.assertEqual(result.effective_config.profile, "internal-mapping-v1")
        self.assertEqual(result.effective_config.budget["limits"]["max_global_rate"], 1)
        self.assertEqual(stored.request["duration_s"], 0)
        self.assertEqual(stored.request["duration_semantics"], "zero means no operator early cutoff within immutable ceilings")
        self.assertEqual(stored.request["coverage_profiles"], [CoverageProfile.TCP_CONNECT.value])
        self.assertEqual(stored.request["directions"], ["outbound"])

    async def test_application_mapping_uses_its_shared_service_factory(self) -> None:
        created: list[HistoryStore] = []

        def service_factory(history: HistoryStore):
            created.append(history)
            from mercury.tasks import TaskService
            return TaskService(history)

        with HistoryStore(":memory:") as history:
            await MercuryApplication(history=history, service_factory=service_factory).map_internal(
                InternalMappingRequest(
                    cidrs=("127.0.0.1/32",), profiles=(CoverageProfile.TCP_CONNECT,),
                    ports=(9,), rate=1, concurrency=1, duration_s=0, authorized=True,
                )
            )
        self.assertEqual(created, [history])

    async def test_udp_mapping_preserves_reply_evidence_without_an_arbitrary_payload(self) -> None:
        class Echo(asyncio.DatagramProtocol):
            def connection_made(self, transport: asyncio.BaseTransport) -> None:
                self.transport = transport

            def datagram_received(self, _data: bytes, address: tuple[str, int]) -> None:
                self.transport.sendto(b"ok", address)

        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            Echo, local_addr=("127.0.0.1", 0),
        )
        try:
            port = transport.get_extra_info("sockname")[1]
            with HistoryStore(":memory:") as history:
                result = await MercuryApplication(history=history).map_internal(InternalMappingRequest(
                    cidrs=("127.0.0.1/32",), profiles=(CoverageProfile.UDP_TAGGED,),
                    ports=(port,), rate=10, concurrency=1, duration_s=0, authorized=True,
                ))
            self.assertEqual(result.observations[0].evidence_kind.value, "udp_application_reply")
            self.assertEqual(result.observations[0].detail["payload_metadata"]["length"], 1)
            self.assertNotIn("payload", result.observations[0].detail)
        finally:
            transport.close()

    async def test_native_mapping_persists_native_provenance_without_command_or_xml(self) -> None:
        async def native(plan, profile):
            self.assertEqual(profile, CoverageProfile.NMAP_UDP)
            return NativeNmapResult(
                profile, CommandOutcome.SUCCESS,
                (NativePortState("127.0.0.1", 53, "udp", "open|filtered", "no-response"),),
            )

        with HistoryStore(":memory:") as history:
            result = await MercuryApplication(history=history, nmap_executor=native).map_internal(
                InternalMappingRequest(
                    cidrs=("127.0.0.1/32",), profiles=(CoverageProfile.NMAP_UDP,),
                    ports=(53,), rate=10, concurrency=1, duration_s=0, authorized=True,
                )
            )
            stored = history.get_task(result.task_id)
        observation = result.observations[0]
        self.assertEqual(
            (observation.evidence_kind, observation.disposition, observation.source),
            (EvidenceKind.NATIVE_PORT_STATE, Disposition.INCONCLUSIVE, "mercury.nmap"),
        )
        self.assertEqual(observation.detail["native_state"], "open|filtered")
        self.assertNotIn("argv", observation.detail)
        self.assertNotIn("xml", observation.detail)
        self.assertIsNotNone(stored)

    async def test_native_mapping_handles_multiple_ports_with_one_native_invocation(self) -> None:
        calls = 0

        async def native(plan, profile):
            nonlocal calls
            calls += 1
            self.assertEqual((profile, plan.preview.ports), (CoverageProfile.NMAP_TCP_CONNECT, (53, 443)))
            return NativeNmapResult(profile, CommandOutcome.SUCCESS, (
                NativePortState("127.0.0.1", 53, "tcp", "open", "syn-ack"),
                NativePortState("127.0.0.1", 443, "tcp", "closed", "reset"),
            ))

        with HistoryStore(":memory:") as history:
            result = await MercuryApplication(history=history, nmap_executor=native).map_internal(
                InternalMappingRequest(
                    cidrs=("127.0.0.1/32",), profiles=(CoverageProfile.NMAP_TCP_CONNECT,),
                    ports=(53, 443), rate=100, concurrency=1, duration_s=0, authorized=True,
                )
            )
        self.assertEqual(calls, 1)
        self.assertEqual(result.progress.completed, 2)
        self.assertEqual(
            [(item.detail["port"], item.detail["native_state"]) for item in result.observations],
            [(53, "open"), (443, "closed")],
        )

    async def test_native_mapping_preserves_missing_nmap_as_a_capability_gap(self) -> None:
        async def missing(_plan, profile):
            return NativeNmapResult(profile, CommandOutcome.MISSING_TOOL, (), "nmap executable unavailable")

        with HistoryStore(":memory:") as history:
            result = await MercuryApplication(history=history, nmap_executor=missing).map_internal(
                InternalMappingRequest(
                    cidrs=("127.0.0.1/32",), profiles=(CoverageProfile.NMAP_TCP_SYN,),
                    ports=(443,), rate=10, concurrency=1, duration_s=0, authorized=True,
                )
            )
        self.assertEqual(
            (result.observations[0].evidence_kind, result.observations[0].disposition),
            (EvidenceKind.UNSUPPORTED, Disposition.UNAVAILABLE),
        )
        self.assertEqual([(item.name, item.state) for item in result.capabilities], [("nmap", CapabilityState.MISSING_TOOL)])
