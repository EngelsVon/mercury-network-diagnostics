from __future__ import annotations

import asyncio
import json
import socket
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
    PairedEndpoint,
    PairedError,
    PairedLease,
    PairedListenerService,
    PairedPeerService,
    PairedRequest,
    PairedRunner,
    encode_tcp_tag,
    encode_udp_tag,
    coverage_matrix,
    is_valid_udp_tag,
    paired_matrix,
)
from mercury.peer import PeerClient, PeerConfig, PeerConfigurationError
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


class MatrixTests(unittest.IsolatedAsyncioTestCase):
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
