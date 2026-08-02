from __future__ import annotations

import asyncio
import json
import socket
import ssl
import tempfile
import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

from mercury.codec import result_from_json, result_to_json
from mercury.app import MercuryApplication
from mercury.history import HistoryStore
from mercury.models import (
    CoverageOutcome, CoverageProfile, Direction, Disposition, EffectiveConfig, EvidenceKind,
    Health, Observation, Progress, TaskResult, TaskState, utc_now,
)
from mercury.paired import (
    AuthenticatedPairedRunner,
    ConfiguredPairedExecutor,
    CoverageReceiverLease,
    CoverageReceiverService,
    CoverageLeaseRegistry,
    PairedEndpoint,
    PairedError,
    PairedLease,
    PairedListenerService,
    PairedPeerService,
    PairedRequest,
    PairedRunner,
    encode_tcp_tag,
    encode_udp_tag,
    encode_coverage_tag,
    local_link_applicability,
    icmp_coverage_evidence,
    run_icmp_coverage,
    coverage_matrix,
    is_valid_udp_tag,
    paired_matrix,
)
from mercury.peer import PeerClient, PeerConfig, PeerConfigurationError, PeerFrame, ReceiverProfileConfig
from mercury.planner import (
    PayloadMetadata,
    ProbeKind,
    ProbeSpec,
    StepCost,
    Transport,
    authorize_plan,
    preview_probe_plan,
)
from mercury.policy import ScopeGrant
from mercury.tasks import TaskContext, TaskError, TaskService
from mercury.platform.common import CommandOutcome, CommandResult
from mercury.reports import coverage_html_table


def _port(kind: int) -> int:
    with socket.socket(socket.AF_INET, kind) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def _plan(tcp_port: int, udp_port: int, *, nonce: str, tag: bytes):
    # The fixed profile length is independent of the digest value itself.
    udp_bytes = 4 + 16 + 1 + len(nonce) + len(tag)
    tcp_bytes = 5 + 16 + 1 + len("pair-correlation") + 5
    preview = preview_probe_plan(
        specs=(
            ProbeSpec(
                probe_kind=ProbeKind.TCP_CONNECT,
                target="127.0.0.1",
                address="127.0.0.1",
                port=tcp_port,
                transport=Transport.TCP,
                cost=StepCost(1, 0, tcp_bytes, logical_packets=1),
            ),
            ProbeSpec(
                probe_kind=ProbeKind.UDP_EXCHANGE,
                target="127.0.0.1",
                address="127.0.0.1",
                port=udp_port,
                transport=Transport.UDP,
                payload_metadata=PayloadMetadata("paired-v1", udp_bytes),
                cost=StepCost(1, 1, udp_bytes, logical_packets=1),
            ),
        ),
        grant=ScopeGrant(networks=()),
        profile="paired-v1",
    )
    return authorize_plan(preview)


def _lease(*, tcp_port: int | None = None, udp_port: int | None = None) -> PairedLease:
    tcp_port = tcp_port or _port(socket.SOCK_STREAM)
    udp_port = udp_port or _port(socket.SOCK_DGRAM)
    nonce, tag = "nonce-123", b"opaque-test-tag"
    plan = _plan(tcp_port, udp_port, nonce=nonce, tag=tag)
    return PairedLease(
        plan=plan,
        correlation_id="pair-correlation",
        endpoint=PairedEndpoint("owned-loopback", "127.0.0.1", tcp_port, udp_port),
        authenticated_source="127.0.0.1",
        expires_at=utc_now() + timedelta(seconds=30),
        udp_nonce=nonce,
        udp_tag=tag,
    )


def _role_result(endpoint: str, disposition: Disposition, kind: EvidenceKind) -> TaskResult:
    now = utc_now()
    observation = Observation(
        id=f"{endpoint}-observation", probe="tcp_connect", disposition=disposition,
        evidence_kind=kind, direction=Direction.OUTBOUND, target="127.0.0.1",
        started_at=now, ended_at=now, duration_ms=0.0, source="tests.paired",
    )
    return TaskResult(
        task_id=f"{endpoint}-task", task_kind="paired", direction=Direction.OUTBOUND,
        target="127.0.0.1", state=TaskState.COMPLETED, started_at=now, ended_at=now,
        requested_config={"paired_manifest": "paired-v1"},
        effective_config=EffectiveConfig("paired-v1", ("127.0.0.1",), True, "test", {}),
        progress=Progress(1, 1, 1), observations=(observation,),
    )


class _UdpClient(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.reply: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()

    def datagram_received(self, data: bytes, _address: tuple[str, int]) -> None:
        if not self.reply.done():
            self.reply.set_result(data)


class PlanAdmissionTests(unittest.IsolatedAsyncioTestCase):
    def test_paired_runtime_requires_one_fixed_configured_peer_address(self) -> None:
        with self.assertRaisesRegex(PeerConfigurationError, "one fixed peer address"):
            PeerConfig(
                identity="owned-pair", bind_host="127.0.0.1", control_port=0,
                certificate_path=None, key_path=None, ca_path=None, token_path=None,
                peer_pins=(), peer_addresses=("127.0.0.1", "127.0.0.2"),
                unsafe_development=True, paired_tcp_port=46001,
                paired_udp_port=46002, paired_timeout_s=1.0,
            )

    def test_lease_accepts_only_exact_plan_endpoint_and_reservations(self) -> None:
        lease = _lease()
        self.assertEqual(lease.endpoint.address, lease.authenticated_source)
        self.assertEqual(lease.plan.preview.steps[0].port, lease.endpoint.tcp_port)

        with self.assertRaisesRegex(PairedError, "authenticated source"):
            PairedLease(
                plan=lease.plan,
                correlation_id=lease.correlation_id,
                endpoint=lease.endpoint,
                authenticated_source="127.0.0.2",
                expires_at=lease.expires_at,
                udp_nonce=lease.udp_nonce,
                udp_tag=lease.udp_tag,
            )
        changed = PairedEndpoint(
            "owned-loopback", "127.0.0.2", lease.endpoint.tcp_port, lease.endpoint.udp_port,
        )
        with self.assertRaisesRegex(PairedError, "outside immutable plan"):
            PairedLease(
                plan=lease.plan,
                correlation_id=lease.correlation_id,
                endpoint=changed,
                authenticated_source="127.0.0.2",
                expires_at=lease.expires_at,
                udp_nonce=lease.udp_nonce,
                udp_tag=lease.udp_tag,
            )

    async def test_paired_evidence_requires_admission_and_round_trips(self) -> None:
        lease = _lease()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        history = HistoryStore(Path(temporary.name) / "history.sqlite3")
        self.addCleanup(history.close)
        service = TaskService(history)

        async def runner(context: TaskContext) -> None:
            step = context.plan.preview.steps[0]
            instant = context.wall_clock()
            evidence = Observation(
                id="paired-evidence",
                probe=step.probe_kind.value,
                disposition=Disposition.POSITIVE,
                evidence_kind=EvidenceKind.PEER_OBSERVED_ARRIVAL,
                direction=Direction.INBOUND,
                target=step.address,
                started_at=instant,
                ended_at=instant,
                duration_ms=0,
                source="tests",
            )
            with self.assertRaisesRegex(TaskError, "before admitting"):
                context.record_paired(
                    evidence, step_id=step.id, endpoint="owned-loopback",
                    correlation_id=lease.correlation_id, phase="arrived",
                )
            await context.admit(step.id)
            context.record_paired(
                evidence, step_id=step.id, endpoint="owned-loopback",
                correlation_id=lease.correlation_id, phase="arrived",
            )
            context.complete_attempt(step.id)
            udp = context.plan.preview.steps[1]
            await context.admit(udp.id)
            instant = context.wall_clock()
            context.record_paired(
                Observation(
                    id="paired-silent", probe=udp.probe_kind.value,
                    disposition=Disposition.INCONCLUSIVE, evidence_kind=EvidenceKind.SILENT,
                    direction=Direction.OUTBOUND, target=udp.address,
                    started_at=instant, ended_at=instant, duration_ms=0, source="tests",
                ),
                step_id=udp.id, endpoint="owned-loopback",
                correlation_id=lease.correlation_id, phase="received",
            )
            context.complete_attempt(udp.id)

        result = await service.run(lease.plan, runner, task_kind="paired")
        self.assertEqual(result.state, TaskState.COMPLETED)
        self.assertEqual(result_from_json(result_to_json(result)), result)
        self.assertEqual(result.observations[0].detail["paired_phase"], "arrived")


class SourceBindingTests(unittest.IsolatedAsyncioTestCase):
    async def test_listener_rejects_post_expiry_before_binding(self) -> None:
        lease = _lease()
        expired = replace(
            lease,
            expires_at=lease.plan.authorized_at + timedelta(milliseconds=1),
        )
        await asyncio.sleep(0.01)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        history = HistoryStore(Path(temporary.name) / "history.sqlite3")
        self.addCleanup(history.close)
        context = TaskContext(
            task_id="expired-pair", task_kind="paired", plan=lease.plan,
            requested_config={}, started_at=utc_now(), history=history,
            cancellation=service_token(), wall_clock=utc_now, monotonic=lambda: 0.0,
            resolver=None,
        )
        listener = PairedListenerService(expired, context=context)
        with self.assertRaisesRegex(PairedError, "expired"):
            await listener.start()
        self.assertEqual(listener.outcome, "pending")


class ListenerLeaseTests(unittest.IsolatedAsyncioTestCase):
    async def test_owned_loopback_tcp_udp_lease_records_only_fixed_profile(self) -> None:
        lease = _lease()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        history = HistoryStore(Path(temporary.name) / "history.sqlite3")
        self.addCleanup(history.close)
        service = TaskService(history)

        async def runner(context: TaskContext) -> None:
            listener = PairedListenerService(lease, context=context)
            await listener.start()
            reader, writer = await asyncio.open_connection("127.0.0.1", lease.endpoint.tcp_port)
            writer.write(encode_tcp_tag(lease))
            await writer.drain()
            self.assertEqual(await reader.readexactly(5), b"MRP1A")
            writer.close()
            await writer.wait_closed()
            protocol = _UdpClient()
            transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: protocol, local_addr=("127.0.0.1", 0),
            )
            try:
                transport.sendto(encode_udp_tag(lease), ("127.0.0.1", lease.endpoint.udp_port))
                self.assertEqual(await asyncio.wait_for(protocol.reply, 1), encode_udp_tag(lease))
            finally:
                transport.close()
            await listener.stop()

        result = await service.run(lease.plan, runner, task_kind="paired")
        self.assertEqual(result.state, TaskState.COMPLETED)
        self.assertEqual({item.detail["paired_phase"] for item in result.observations}, {"arrived", "replied"})
        self.assertTrue(all(item.detail["paired_endpoint"] == "owned-loopback" for item in result.observations))


class UdpProfileTests(unittest.TestCase):
    def test_fixed_udp_profile_rejects_tampering_and_never_accepts_payloads(self) -> None:
        lease = _lease()
        payload = encode_udp_tag(lease)
        self.assertLessEqual(len(payload), 1_400)
        self.assertTrue(is_valid_udp_tag(lease, payload))
        self.assertFalse(is_valid_udp_tag(lease, payload + b"x"))
        self.assertFalse(is_valid_udp_tag(lease, b"MRP1"))
        self.assertFalse(is_valid_udp_tag(lease, b"x" * 1_401))


class CoverageReceiverTests(unittest.IsolatedAsyncioTestCase):
    async def test_authenticated_coverage_manifest_provisions_only_local_receiver_table(self) -> None:
        port = _port(socket.SOCK_STREAM)
        config = PeerConfig(
            identity="coverage-peer", bind_host="127.0.0.1", control_port=0,
            certificate_path=None, key_path=None, ca_path=None, token_path=None,
            peer_pins=(), peer_addresses=("127.0.0.1",), unsafe_development=True,
            receiver_profiles=(ReceiverProfileConfig(CoverageProfile.TCP_TAGGED, "127.0.0.1", port, 1.0),),
        )
        registry = CoverageLeaseRegistry(config)
        service = PairedPeerService(lambda _role, _correlation: _role_result("unused", Disposition.POSITIVE, EvidenceKind.TCP_CONNECTED), coverage_registry=registry)
        self.assertIn(f"coverage-v2:tcp_tagged:{port}", (await service.capabilities(PeerFrame(
            1, "capabilities", "coverage-correlation", "coverage-peer", utc_now(), utc_now() + timedelta(seconds=1), "nonce-capability", {},
        )))["capabilities"])
        now = utc_now()
        frame = PeerFrame(
            1, "submit", "coverage-correlation", "coverage-peer", now, now + timedelta(seconds=1), "nonce-coverage", {"manifest": "coverage-v2", "role": "B-to-A"},
        )
        self.assertEqual(await service.submit(frame), {"status": "accepted"})
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"MRC2:tcp_tagged:coverage-correlation")
        await writer.drain()
        self.assertEqual(await reader.readexactly(5), b"MRC2A")
        writer.close()
        await writer.wait_closed()
        receipts = await service.read_result(replace(frame, operation="read-result", body={}, nonce="nonce-coverage2"))
        self.assertEqual(receipts["receipts"][0]["correlation_id"], "coverage-correlation")
        await service.cancel(frame)

    async def test_tls_receiver_requires_a_configured_certificate_and_records_handshake(self) -> None:
        port = _port(socket.SOCK_STREAM)
        receiver = ReceiverProfileConfig(CoverageProfile.TLS_HANDSHAKE, "127.0.0.1", port, 1.0)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        fixture = Path(__file__).parent / "fixtures" / "tls"
        context.load_cert_chain(fixture / "localhost-cert.pem", fixture / "localhost-key.pem")
        service = CoverageReceiverService(CoverageReceiverLease(
            receiver, "coverage-correlation", "127.0.0.1", utc_now() + timedelta(seconds=2),
        ), ssl_context=context)
        await service.start()
        try:
            client = ssl.create_default_context(cafile=str(fixture / "test-ca.pem"))
            reader, writer = await asyncio.open_connection("127.0.0.1", port, ssl=client, server_hostname="localhost")
            writer.close()
            await writer.wait_closed()
            await asyncio.sleep(0)
            self.assertEqual(service.receipts[0].profile, CoverageProfile.TLS_HANDSHAKE)
        finally:
            await service.stop()

    async def test_dns_tcp_receiver_answers_the_same_fixed_query(self) -> None:
        port = _port(socket.SOCK_STREAM)
        receiver = ReceiverProfileConfig(CoverageProfile.DNS_TCP, "127.0.0.1", port, 1.0)
        service = CoverageReceiverService(CoverageReceiverLease(
            receiver, "coverage-correlation", "127.0.0.1", utc_now() + timedelta(seconds=2),
        ))
        await service.start()
        try:
            name = b"\x14coverage-correlation\x07mercury\x04test\x00"
            query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + name + b"\x00\x01\x00\x01"
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(len(query).to_bytes(2, "big") + query)
            await writer.drain()
            reply = await reader.readexactly(int.from_bytes(await reader.readexactly(2), "big"))
            self.assertEqual(reply[2:4], b"\x81\x80")
            writer.close()
            await writer.wait_closed()
            await asyncio.sleep(0)
            self.assertEqual(service.receipts[0].reply_result, "acknowledged")
        finally:
            await service.stop()

    async def test_dns_udp_receiver_answers_only_its_correlation_test_zone(self) -> None:
        port = _port(socket.SOCK_DGRAM)
        receiver = ReceiverProfileConfig(CoverageProfile.DNS_UDP, "127.0.0.1", port, 1.0)
        service = CoverageReceiverService(CoverageReceiverLease(
            receiver, "coverage-correlation", "127.0.0.1", utc_now() + timedelta(seconds=2),
        ))
        await service.start()
        try:
            name = b"\x14coverage-correlation\x07mercury\x04test\x00"
            query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + name + b"\x00\x01\x00\x01"
            protocol = _UdpClient()
            transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: protocol, remote_addr=("127.0.0.1", port),
            )
            try:
                transport.sendto(query)
                self.assertEqual((await asyncio.wait_for(protocol.reply, 1))[2:4], b"\x81\x80")
            finally:
                transport.close()
            self.assertEqual(service.receipts[0].reply_result, "dns_answered")
        finally:
            await service.stop()

    async def test_http_and_ssh_receivers_require_the_fixed_correlation(self) -> None:
        for profile in (CoverageProfile.HTTP_EXCHANGE, CoverageProfile.SSH_BANNER):
            with self.subTest(profile=profile):
                port = _port(socket.SOCK_STREAM)
                receiver = ReceiverProfileConfig(profile, "127.0.0.1", port, 1.0)
                service = CoverageReceiverService(CoverageReceiverLease(
                    receiver, "coverage-correlation", "127.0.0.1", utc_now() + timedelta(seconds=2),
                ))
                await service.start()
                try:
                    reader, writer = await asyncio.open_connection("127.0.0.1", port)
                    if profile is CoverageProfile.HTTP_EXCHANGE:
                        writer.write(b"GET /mercury/coverage-correlation HTTP/1.1\r\nHost: test\r\nX-Mercury-Correlation: coverage-correlation\r\n\r\n")
                        await writer.drain()
                        self.assertTrue((await reader.readuntil(b"\r\n\r\n")).startswith(b"HTTP/1.1 204"))
                    else:
                        self.assertEqual(await reader.readline(), b"SSH-2.0-MercuryCoverage\r\n")
                        writer.write(b"SSH-2.0-Mercury-coverage-correlation\r\n")
                        await writer.drain()
                    writer.close()
                    await writer.wait_closed()
                    await asyncio.sleep(0)
                    self.assertEqual(len(service.receipts), 1)
                finally:
                    await service.stop()

    async def test_tcp_and_udp_receivers_accept_only_the_fixed_lease_tag(self) -> None:
        for profile, kind in ((CoverageProfile.TCP_TAGGED, socket.SOCK_STREAM), (CoverageProfile.UDP_TAGGED, socket.SOCK_DGRAM)):
            with self.subTest(profile=profile):
                port = _port(kind)
                receiver = ReceiverProfileConfig(profile, "127.0.0.1", port, 1.0)
                service = CoverageReceiverService(CoverageReceiverLease(
                    receiver, "coverage-correlation", "127.0.0.1", utc_now() + timedelta(seconds=2),
                ))
                await service.start()
                try:
                    tag = encode_coverage_tag(service.lease)
                    if profile is CoverageProfile.TCP_TAGGED:
                        reader, writer = await asyncio.open_connection("127.0.0.1", port)
                        writer.write(tag)
                        await writer.drain()
                        self.assertEqual(await reader.readexactly(5), b"MRC2A")
                        writer.close()
                        await writer.wait_closed()
                    else:
                        protocol = _UdpClient()
                        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                            lambda: protocol, remote_addr=("127.0.0.1", port),
                        )
                        try:
                            transport.sendto(tag)
                            self.assertEqual(await asyncio.wait_for(protocol.reply, 1), b"MRC2A")
                        finally:
                            transport.close()
                    self.assertEqual(len(service.receipts), 1)
                    self.assertEqual(service.receipts[0].payload_length, len(tag))
                finally:
                    await service.stop()


class MatrixTests(unittest.IsolatedAsyncioTestCase):
    async def test_icmp_coverage_uses_only_a_fixed_native_echo_argv(self) -> None:
        calls: list[tuple[tuple[str, ...], float, int]] = []

        async def runner(argv: tuple[str, ...], timeout_s: float, maximum: int) -> CommandResult:
            calls.append((argv, timeout_s, maximum))
            return CommandResult(argv, 0, "", "", CommandOutcome.SUCCESS)

        result = await run_icmp_coverage("127.0.0.1", 0.25, system=lambda: "Windows", command_runner=runner)
        self.assertEqual(result.outcome, CommandOutcome.SUCCESS)
        self.assertEqual(calls, [(('ping', '-n', '1', '-w', '250', '127.0.0.1'), 1.25, 8_192)])

    async def test_configured_icmp_profile_persists_native_capability_evidence(self) -> None:
        async def runner(_address: str, _timeout: float) -> CommandResult:
            return CommandResult(("ping",), None, "", "", CommandOutcome.PERMISSION_DENIED)

        config = PeerConfig(
            identity="icmp-pair", bind_host="127.0.0.2", control_port=0,
            certificate_path=None, key_path=None, ca_path=None, token_path=None,
            peer_pins=(), peer_addresses=("127.0.0.1",), unsafe_development=True,
            coverage_profiles=(CoverageProfile.ICMP_ECHO,),
        )
        history = HistoryStore(":memory:")
        self.addCleanup(history.close)
        from mercury.paired import ConfiguredCoverageExecutor
        result = await ConfiguredCoverageExecutor(config, history, icmp_runner=runner)("A-to-B", "icmp-correlation")
        self.assertEqual(result.observations[0].evidence_kind, EvidenceKind.PERMISSION_DENIED)
        self.assertEqual(result.observations[0].disposition, Disposition.UNAVAILABLE)
        self.assertEqual(result.observations[0].detail["coverage_profile"], CoverageProfile.ICMP_ECHO.value)

    async def test_icmp_capability_gaps_do_not_become_peer_arrival_claims(self) -> None:
        cases = (
            (CommandOutcome.SUCCESS, EvidenceKind.NATIVE_PING_REPLY, Disposition.POSITIVE),
            (CommandOutcome.TIMEOUT, EvidenceKind.TIMEOUT, Disposition.INCONCLUSIVE),
            (CommandOutcome.PERMISSION_DENIED, EvidenceKind.PERMISSION_DENIED, Disposition.UNAVAILABLE),
            (CommandOutcome.MISSING_TOOL, EvidenceKind.UNSUPPORTED, Disposition.UNAVAILABLE),
        )
        for outcome, kind, disposition in cases:
            with self.subTest(outcome=outcome):
                result = CommandResult(("ping",), 0 if outcome is CommandOutcome.SUCCESS else None, "", "", outcome)
                self.assertEqual(icmp_coverage_evidence(result)[:2], (kind, disposition))

    async def test_cross_subnet_arp_nd_is_not_applicable_to_remote_pair(self) -> None:
        self.assertEqual(local_link_applicability("172.26.0.0/16", "172.27.0.0/16"), CoverageOutcome.NOT_APPLICABLE)
        self.assertEqual(local_link_applicability("10.20.30.0/24", "10.20.30.0/24"), CoverageOutcome.SKIPPED)

    async def test_cross_subnet_arp_nd_rows_are_not_applicable_not_negative(self) -> None:
        from mercury.paired import CoverageAssessmentRequest, _local_link_scope_observations
        request = CoverageAssessmentRequest(
            identity="coverage-pair", address="172.27.20.2", config_path="peer.json",
            timeout_s=1.0, authorized=True, profiles=(CoverageProfile.ARP, CoverageProfile.IPV6_ND),
            local_network="172.26.0.0/16", peer_network="172.27.0.0/16",
        )
        result = _role_result("local", Disposition.POSITIVE, EvidenceKind.TCP_CONNECTED)
        result = replace(result, observations=_local_link_scope_observations(request), conclusions=())
        rows = coverage_matrix(result, requested=request.profiles)
        self.assertEqual({row.outcome for row in rows}, {CoverageOutcome.NOT_APPLICABLE})

    async def test_coverage_matrix_requires_arrival_or_response_for_candidate_carrier(self) -> None:
        result = _role_result("local", Disposition.POSITIVE, EvidenceKind.PEER_OBSERVED_ARRIVAL)
        observation = replace(
            result.observations[0],
            detail={"coverage_profile": CoverageProfile.TCP_TAGGED.value, "paired_phase": "A-to-B"},
        )
        rows = coverage_matrix(
            replace(result, observations=(observation,)),
            requested=(CoverageProfile.TCP_TAGGED,),
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].outcome, CoverageOutcome.CANDIDATE_CARRIER)
        self.assertEqual(rows[0].direction, "A-to-B")
        self.assertIn("profile, port/packet shape", rows[0].limitations[0])

    async def test_matrix_is_cited_and_preserves_directional_phases(self) -> None:
        lease = _lease()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        history = HistoryStore(Path(temporary.name) / "history.sqlite3")
        self.addCleanup(history.close)
        service = TaskService(history)

        async def runner(context: TaskContext) -> None:
            async def role(inner: TaskContext) -> None:
                listener = PairedListenerService(lease, context=inner)
                await listener.start()
                await listener.stop()

            await PairedRunner(role)(context)

        result = await service.run(lease.plan, runner, task_kind="paired")
        rows = paired_matrix(result)
        self.assertEqual([row.layer for row in rows], ["tcp_connect", "udp_exchange"])
        self.assertEqual({row.direction for row in rows}, {"A→B"})
        self.assertTrue(all(row.observation_ids for row in rows))
        self.assertTrue(any("silence is inconclusive" in row.limitations[0] for row in rows))
        self.assertEqual(result.conclusions[-2].id, "paired-health")


class AuthenticatedCompositionTests(unittest.IsolatedAsyncioTestCase):
    async def test_coverage_runner_keeps_icmp_receiver_gap_distinct_in_both_directions(self) -> None:
        """ICMP replies are sender-side facts when no privileged peer observer exists."""
        from mercury.paired import AuthenticatedCoverageRunner, CoverageAssessmentRequest, ConfiguredCoverageExecutor

        async def echo_runner(_address: str, _timeout: float) -> CommandResult:
            return CommandResult(("ping",), 0, "", "", CommandOutcome.SUCCESS)

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        token_path = Path(temporary.name) / "token"
        token_path.write_text("controlled-loopback-token", encoding="utf-8")
        remote_config = PeerConfig(
            identity="icmp-pair", bind_host="127.0.0.1", control_port=0,
            certificate_path=None, key_path=None, ca_path=None, token_path=token_path,
            peer_pins=(), peer_addresses=("127.0.0.2",), unsafe_development=True,
            coverage_profiles=(CoverageProfile.ICMP_ECHO,),
        )
        remote_history = HistoryStore(":memory:")
        self.addCleanup(remote_history.close)
        remote_app = MercuryApplication(
            history=remote_history,
            paired_peer_service=PairedPeerService(
                lambda _role, _correlation: _role_result("unused", Disposition.POSITIVE, EvidenceKind.TCP_CONNECTED),
                coverage_registry=CoverageLeaseRegistry(remote_config),
                coverage_sender_executor=ConfiguredCoverageExecutor(remote_config, remote_history, icmp_runner=echo_runner),
            ),
        )
        agent = await remote_app.start_agent(remote_config)
        try:
            server = agent.server
            assert server is not None
            local_config = PeerConfig(
                identity="icmp-pair", bind_host="127.0.0.2", control_port=server.sockets[0].getsockname()[1],
                certificate_path=None, key_path=None, ca_path=None, token_path=token_path,
                peer_pins=(), peer_addresses=("127.0.0.1",), unsafe_development=True,
                coverage_profiles=(CoverageProfile.ICMP_ECHO,),
            )
            local_history = HistoryStore(":memory:")
            self.addCleanup(local_history.close)
            runner = AuthenticatedCoverageRunner(
                PeerClient(local_config), local_config, local_history,
                coverage_sender=ConfiguredCoverageExecutor(local_config, local_history, icmp_runner=echo_runner),
            )
            result = await runner.run(CoverageAssessmentRequest(
                identity="icmp-pair", address="127.0.0.1", config_path="peer.json",
                timeout_s=1.0, authorized=True, profiles=(CoverageProfile.ICMP_ECHO,), unsafe_development=True,
            ))
        finally:
            await remote_app.stop_agent()
        rows = coverage_matrix(result, requested=(CoverageProfile.ICMP_ECHO,))
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row.outcome is CoverageOutcome.CANDIDATE_CARRIER for row in rows))
        self.assertFalse(any(item.evidence_kind is EvidenceKind.PEER_OBSERVED_ARRIVAL for item in result.observations))

    async def test_coverage_runner_correlates_configured_tcp_udp_receivers_in_both_directions(self) -> None:
        """Each direction needs a sender fact *and* the peer receiver receipt."""
        from mercury.paired import AuthenticatedCoverageRunner, CoverageAssessmentRequest, ConfiguredCoverageExecutor

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        token_path = Path(temporary.name) / "token"
        token_path.write_text("controlled-loopback-token", encoding="utf-8")
        tcp_port, udp_port = _port(socket.SOCK_STREAM), _port(socket.SOCK_DGRAM)
        tls_fixture = Path(__file__).parent / "fixtures" / "tls"
        receivers = (
            ReceiverProfileConfig(CoverageProfile.TCP_TAGGED, "127.0.0.1", tcp_port, 1.0),
            ReceiverProfileConfig(CoverageProfile.UDP_TAGGED, "127.0.0.1", udp_port, 1.0),
            ReceiverProfileConfig(CoverageProfile.DNS_UDP, "127.0.0.1", _port(socket.SOCK_DGRAM), 1.0),
            ReceiverProfileConfig(CoverageProfile.DNS_TCP, "127.0.0.1", _port(socket.SOCK_STREAM), 1.0),
            ReceiverProfileConfig(CoverageProfile.HTTP_EXCHANGE, "127.0.0.1", _port(socket.SOCK_STREAM), 1.0),
            ReceiverProfileConfig(CoverageProfile.SSH_BANNER, "127.0.0.1", _port(socket.SOCK_STREAM), 1.0),
            ReceiverProfileConfig(
                CoverageProfile.TLS_HANDSHAKE, "127.0.0.1", _port(socket.SOCK_STREAM), 1.0,
                tls_certificate_path=tls_fixture / "localhost-cert.pem",
                tls_key_path=tls_fixture / "localhost-key.pem", tls_ca_path=tls_fixture / "test-ca.pem",
                tls_server_name="localhost",
            ),
        )
        remote_config = PeerConfig(
            identity="coverage-pair", bind_host="127.0.0.1", control_port=0,
            certificate_path=None, key_path=None, ca_path=None, token_path=token_path,
            peer_pins=(), peer_addresses=("127.0.0.2",), unsafe_development=True,
            receiver_profiles=receivers,
        )
        remote_history = HistoryStore(":memory:")
        self.addCleanup(remote_history.close)
        remote_app = MercuryApplication(
            history=remote_history,
            paired_peer_service=PairedPeerService(
                lambda _role, _correlation: _role_result("unused", Disposition.POSITIVE, EvidenceKind.TCP_CONNECTED),
                coverage_registry=CoverageLeaseRegistry(remote_config),
                coverage_sender_executor=ConfiguredCoverageExecutor(remote_config, remote_history),
            ),
        )
        agent = await remote_app.start_agent(remote_config)
        try:
            server = agent.server
            assert server is not None
            control_port = server.sockets[0].getsockname()[1]
            local_receivers = tuple(
                replace(receiver, bind_host="127.0.0.2") for receiver in receivers
            )
            local_config = PeerConfig(
                identity="coverage-pair", bind_host="127.0.0.2", control_port=control_port,
                certificate_path=None, key_path=None, ca_path=None, token_path=token_path,
                peer_pins=(), peer_addresses=("127.0.0.1",), unsafe_development=True,
                receiver_profiles=local_receivers,
            )
            local_history = HistoryStore(":memory:")
            self.addCleanup(local_history.close)
            runner = AuthenticatedCoverageRunner(PeerClient(local_config), local_config, local_history)
            result = await runner.run(CoverageAssessmentRequest(
                identity="coverage-pair", address="127.0.0.1", config_path="peer.json",
                timeout_s=1.0, authorized=True,
                profiles=(
                    CoverageProfile.TCP_CONNECT, CoverageProfile.TCP_TAGGED, CoverageProfile.UDP_TAGGED,
                    CoverageProfile.DNS_UDP, CoverageProfile.DNS_TCP,
                    CoverageProfile.HTTP_EXCHANGE, CoverageProfile.SSH_BANNER, CoverageProfile.TLS_HANDSHAKE,
                ),
                unsafe_development=True,
            ))
        finally:
            await remote_app.stop_agent()
        rows = coverage_matrix(result, requested=(
            CoverageProfile.TCP_CONNECT, CoverageProfile.TCP_TAGGED, CoverageProfile.UDP_TAGGED,
            CoverageProfile.DNS_UDP, CoverageProfile.DNS_TCP,
            CoverageProfile.HTTP_EXCHANGE, CoverageProfile.SSH_BANNER, CoverageProfile.TLS_HANDSHAKE,
        ))
        self.assertEqual({row.direction for row in rows}, {"A-to-B", "B-to-A"})
        self.assertTrue(all(row.outcome is CoverageOutcome.CANDIDATE_CARRIER for row in rows))
        self.assertTrue(any(item.evidence_kind is EvidenceKind.PEER_OBSERVED_ARRIVAL for item in result.observations))
        self.assertTrue({
            CoverageProfile.DNS_UDP.value, CoverageProfile.DNS_TCP.value,
            CoverageProfile.HTTP_EXCHANGE.value, CoverageProfile.SSH_BANNER.value, CoverageProfile.TLS_HANDSHAKE.value,
        }.issubset({str(item.detail.get("coverage_profile")) for item in result.observations}))
        self.assertTrue({EvidenceKind.DNS_QUERY, EvidenceKind.HTTP_RESPONSE, EvidenceKind.SSH_BANNER, EvidenceKind.TLS_HANDSHAKE}.issubset(
            {item.evidence_kind for item in result.observations}
        ))
        table = coverage_html_table(result, requested=(
            CoverageProfile.TCP_CONNECT, CoverageProfile.TCP_TAGGED, CoverageProfile.UDP_TAGGED,
            CoverageProfile.DNS_UDP, CoverageProfile.DNS_TCP, CoverageProfile.HTTP_EXCHANGE,
            CoverageProfile.SSH_BANNER, CoverageProfile.TLS_HANDSHAKE,
        ))
        self.assertIn('<th scope="col">Port</th>', table)
        self.assertIn('<th scope="col">Timing</th>', table)
        self.assertIn("mercury.coverage_receiver", table)

    async def test_configured_runtime_performs_fixed_loopback_tcp_udp_profile(self) -> None:
        """The bare runtime composes only configured data-plane endpoints."""
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        token_path = Path(temporary.name) / "token"
        token_path.write_text("controlled-loopback-token", encoding="utf-8")
        tcp_port, udp_port = _port(socket.SOCK_STREAM), _port(socket.SOCK_DGRAM)
        remote_config = PeerConfig(
            identity="loopback-pair", bind_host="127.0.0.1", control_port=0,
            certificate_path=None, key_path=None, ca_path=None, token_path=token_path,
            peer_pins=(), peer_addresses=("127.0.0.1",), unsafe_development=True,
            paired_tcp_port=tcp_port, paired_udp_port=udp_port, paired_timeout_s=1.0,
        )
        remote_history = HistoryStore(":memory:")
        self.addCleanup(remote_history.close)
        remote_app = MercuryApplication(
            history=remote_history,
            paired_peer_service=PairedPeerService(
                ConfiguredPairedExecutor(remote_config, remote_history)
            ),
        )
        agent = await remote_app.start_agent(remote_config)
        try:
            server = agent.server
            assert server is not None
            control_port = server.sockets[0].getsockname()[1]
            local_history = HistoryStore(":memory:")
            self.addCleanup(local_history.close)
            config_path = Path(temporary.name) / "peer.json"
            config_path.write_text(json.dumps({
                "identity": "loopback-pair", "bind_host": "127.0.0.1",
                "control_port": control_port, "peer_pins": [],
                "peer_addresses": ["127.0.0.1"], "token_path": "token",
                "paired": {"tcp_port": tcp_port, "udp_port": udp_port, "timeout_s": 1.0},
            }), encoding="utf-8")
            result = await MercuryApplication(history=local_history).run_paired(PairedRequest(
                identity="loopback-pair", address="127.0.0.1", config_path=str(config_path),
                timeout_s=1.0, authorized=True, unsafe_development=True,
            ))
        finally:
            await remote_app.stop_agent()
        kinds = {item.evidence_kind for item in result.observations}
        self.assertIn(EvidenceKind.TCP_CONNECTED, kinds)
        self.assertIn(EvidenceKind.UDP_APPLICATION_REPLY, kinds)
        self.assertIn(EvidenceKind.PEER_OBSERVED_ARRIVAL, kinds)

    async def test_authenticated_control_runs_independently_admitted_role_swap(self) -> None:
        """D-12 local proof.

        An opt-in two-machine smoke may use only the user-authorized Ubuntu
        peer at its configured address, temporary restrictive-permission
        certificate/token files, and this fixed manifest.  Copy only sanitized
        evidence, then remove the temporary remote files; never automate SSH.
        """
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        token_path = Path(temporary.name) / "token"
        token_path.write_text("controlled-loopback-token", encoding="utf-8")
        base = PeerConfig(
            identity="loopback-peer", bind_host="127.0.0.1", control_port=0,
            certificate_path=None, key_path=None, ca_path=None, token_path=token_path,
            peer_pins=(), peer_addresses=("127.0.0.1",), unsafe_development=True,
        )
        remote_roles: list[str] = []
        remote_started = asyncio.Event()
        allow_remote_result = asyncio.Event()

        async def remote_role(role: str, _correlation: str) -> TaskResult:
            remote_roles.append(role)
            remote_started.set()
            await allow_remote_result.wait()
            return _role_result("remote", Disposition.INCONCLUSIVE, EvidenceKind.SILENT)

        remote_history = HistoryStore(":memory:")
        self.addCleanup(remote_history.close)
        remote_app = MercuryApplication(
            history=remote_history, paired_peer_service=PairedPeerService(remote_role),
        )
        agent = await remote_app.start_agent(base)
        try:
            server = agent.server
            assert server is not None
            port = server.sockets[0].getsockname()[1]
            local_roles: list[str] = []

            async def local_role(role: str, _correlation: str) -> TaskResult:
                local_roles.append(role)
                # A real remote B-to-A role must bind before local A-to-B
                # starts.  This catches a sequential submit implementation.
                await asyncio.wait_for(remote_started.wait(), 1)
                allow_remote_result.set()
                return _role_result("local", Disposition.POSITIVE, EvidenceKind.TCP_CONNECTED)

            runner = AuthenticatedPairedRunner(
                PeerClient(replace(base, control_port=port)), local_role,
            )
            local_history = HistoryStore(":memory:")
            self.addCleanup(local_history.close)
            result = await MercuryApplication(history=local_history, paired_runner=runner).run_paired(PairedRequest(
                identity="loopback-peer", address="127.0.0.1", config_path="peer.json",
                timeout_s=3.0, authorized=True, unsafe_development=True,
            ))
        finally:
            await remote_app.stop_agent()
        self.assertEqual(local_roles, ["A-to-B"])
        self.assertEqual(remote_roles, ["B-to-A"])
        self.assertEqual(result.conclusions[0].health, Health.PARTIAL)
        rows = paired_matrix(result)
        self.assertEqual([row.direction for row in rows], ["A→B", "B→A"])
        self.assertTrue(all(row.observation_ids for row in rows))

    async def test_control_grace_collects_a_role_result_at_lease_expiry(self) -> None:
        """The data lease can expire before its terminal result is collected."""
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        token_path = Path(temporary.name) / "token"
        token_path.write_text("controlled-loopback-token", encoding="utf-8")
        base = PeerConfig(
            identity="loopback-peer", bind_host="127.0.0.1", control_port=0,
            certificate_path=None, key_path=None, ca_path=None, token_path=token_path,
            peer_pins=(), peer_addresses=("127.0.0.1",), unsafe_development=True,
        )

        async def remote_role(_role: str, _correlation: str) -> TaskResult:
            await asyncio.sleep(0.15)
            return _role_result("remote", Disposition.INCONCLUSIVE, EvidenceKind.SILENT)

        remote_history = HistoryStore(":memory:")
        self.addCleanup(remote_history.close)
        remote_app = MercuryApplication(
            history=remote_history, paired_peer_service=PairedPeerService(remote_role),
        )
        agent = await remote_app.start_agent(base)
        try:
            server = agent.server
            assert server is not None
            port = server.sockets[0].getsockname()[1]

            async def local_role(_role: str, _correlation: str) -> TaskResult:
                return _role_result("local", Disposition.POSITIVE, EvidenceKind.TCP_CONNECTED)

            runner = AuthenticatedPairedRunner(PeerClient(replace(base, control_port=port)), local_role)
            local_history = HistoryStore(":memory:")
            self.addCleanup(local_history.close)
            result = await MercuryApplication(history=local_history, paired_runner=runner).run_paired(PairedRequest(
                identity="loopback-peer", address="127.0.0.1", config_path="peer.json",
                timeout_s=0.1, authorized=True, unsafe_development=True,
            ))
        finally:
            await remote_app.stop_agent()
        self.assertEqual(result.state, TaskState.COMPLETED)
        self.assertEqual(result.conclusions[0].health, Health.PARTIAL)

    async def test_peer_submit_cannot_carry_scan_selectors(self) -> None:
        # The frame validation is the peer boundary: submission has no target,
        # CIDR, port, payload, scope, resolver, or runner fields to admit.
        with self.assertRaisesRegex(Exception, "submit body"):
            from mercury.peer import PeerFrame
            PeerFrame(
                version=1, operation="submit", correlation_id="pair-control-1",
                identity="loopback-peer", issued_at=utc_now(),
                expires_at=utc_now() + timedelta(seconds=10), nonce="nonce-12345678",
                body={"manifest": "paired-v1", "role": "B-to-A", "port": 443},
            )


def service_token():
    """Use the production cancellation primitive without a second task service."""
    from mercury.tasks import CancellationToken

    return CancellationToken(asyncio.Event())


if __name__ == "__main__":
    unittest.main()
