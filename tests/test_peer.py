"""Controlled-loopback tests for the peer-control trust boundary."""

from __future__ import annotations

import asyncio
import hashlib
import json
import ssl
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from mercury.app import MercuryApplication
from mercury.history import HistoryStore
from mercury.models import CoverageProfile
from mercury.peer import (
    PeerAgent,
    PeerClient,
    PeerConfig,
    PeerConfigurationError,
    PeerFrame,
    ReceiverProfileConfig,
    load_peer_config,
)


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "tls"


class _FakeServer:
    def close(self) -> None:
        return None

    async def wait_closed(self) -> None:
        return None


class PeerStartupTests(unittest.IsolatedAsyncioTestCase):
    async def test_coverage_submit_frame_cannot_carry_receiver_selectors(self) -> None:
        now = datetime.now(timezone.utc)
        with self.assertRaisesRegex(Exception, "submit body"):
            PeerFrame(
                1, "submit", "coverage-correlation", "loopback-peer", now, now + timedelta(seconds=1), "nonce-coverage",
                {"manifest": "coverage-v2", "role": "A-to-B", "port": 53},
            )

    async def test_receiver_profiles_are_local_fixed_private_bindings(self) -> None:
        receiver = ReceiverProfileConfig(
            profile=CoverageProfile.DNS_UDP,
            bind_host="127.0.0.1", port=53053, timeout_s=1.0,
        )
        with tempfile.TemporaryDirectory() as temporary:
            token = Path(temporary) / "token"
            token.write_text("controlled-token", encoding="utf-8")
            config = PeerConfig(
                identity="loopback-peer", bind_host="127.0.0.1", control_port=0,
                certificate_path=None, key_path=None, ca_path=None, token_path=token,
                peer_pins=(), peer_addresses=("127.0.0.1",), unsafe_development=True,
                receiver_profiles=(receiver,),
            )
        self.assertTrue(config.coverage_enabled)
        with self.assertRaisesRegex(PeerConfigurationError, "receiver bind host"):
            ReceiverProfileConfig(profile=receiver.profile, bind_host="8.8.8.8", port=53054, timeout_s=1.0)
        with self.assertRaisesRegex(PeerConfigurationError, "receiver profile table"):
            replace(config, receiver_profiles=(receiver, receiver))

    async def test_strict_file_config_keeps_only_secret_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config_path = Path(temporary) / "peer.json"
            config_path.write_text(json.dumps({
                "identity": "loopback-peer", "bind_host": "127.0.0.1",
                "control_port": 0, "peer_pins": [], "peer_addresses": ["127.0.0.1"],
                "token_path": "token.txt",
            }), encoding="utf-8")
            config = load_peer_config(config_path, unsafe_development=True)
            self.assertEqual(config.token_path, (Path(temporary) / "token.txt").resolve())
            self.assertTrue(config.unsafe_development)
            config_path.write_text('{"identity":"x"}', encoding="utf-8")
            with self.assertRaisesRegex(PeerConfigurationError, "fields"):
                load_peer_config(config_path)

    async def test_tls_receiver_file_configuration_requires_fixed_data_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config_path = Path(temporary) / "peer.json"
            config_path.write_text(json.dumps({
                "identity": "loopback-peer", "bind_host": "127.0.0.1", "control_port": 0,
                "peer_pins": [], "peer_addresses": ["127.0.0.1"], "token_path": "token.txt",
                "receivers": [{
                    "profile": "tls_handshake", "bind_host": "127.0.0.1", "port": 4443, "timeout_s": 1.0,
                    "tls": {
                        "certificate_path": str(FIXTURE_DIR / "localhost-cert.pem"),
                        "key_path": str(FIXTURE_DIR / "localhost-key.pem"),
                        "ca_path": str(FIXTURE_DIR / "test-ca.pem"), "server_name": "localhost",
                    },
                }],
            }), encoding="utf-8")
            config = load_peer_config(config_path, unsafe_development=True)
            receiver = config.receiver_profiles[0]
            self.assertEqual(receiver.tls_server_name, "localhost")
            self.assertEqual(receiver.tls_ca_path, FIXTURE_DIR / "test-ca.pem")
            config_path.write_text(json.dumps({
                "identity": "loopback-peer", "bind_host": "127.0.0.1", "control_port": 0,
                "peer_pins": [], "peer_addresses": ["127.0.0.1"],
                "receivers": [{"profile": "tls_handshake", "bind_host": "127.0.0.1", "port": 4443, "timeout_s": 1.0}],
            }), encoding="utf-8")
            with self.assertRaisesRegex(PeerConfigurationError, "TLS receiver"):
                load_peer_config(config_path, unsafe_development=True)

    def _config(self, default_token_path: Path, **changes: object) -> PeerConfig:
        values: dict[str, object] = {
            "identity": "loopback-peer",
            "bind_host": "127.0.0.1",
            "control_port": 0,
            "certificate_path": FIXTURE_DIR / "localhost-cert.pem",
            "key_path": FIXTURE_DIR / "localhost-key.pem",
            "ca_path": FIXTURE_DIR / "test-ca.pem",
            "token_path": default_token_path,
            "peer_pins": (self._pin(FIXTURE_DIR / "peer-client-cert.pem"),),
            "peer_addresses": ("127.0.0.1",),
        }
        values.update(changes)
        return PeerConfig(**values)  # type: ignore[arg-type]

    @staticmethod
    def _pin(path: Path) -> str:
        der = ssl.PEM_cert_to_DER_cert(path.read_text(encoding="ascii"))
        return "sha256:" + hashlib.sha256(der).hexdigest()

    async def test_non_loopback_missing_trust_is_rejected_before_listener_start(self) -> None:
        starts = 0

        async def server_factory(*_args: object, **_kwargs: object) -> _FakeServer:
            nonlocal starts
            starts += 1
            return _FakeServer()

        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(PeerConfigurationError, "certificate"):
                config = self._config(
                    Path(temporary) / "token",
                    bind_host="10.20.30.10",
                    certificate_path=None,
                    key_path=None,
                    ca_path=None,
                    token_path=None,
                    peer_pins=(),
                )
                await PeerAgent(config, server_factory=server_factory).start()
        self.assertEqual(starts, 0)

    async def test_public_peer_bind_or_destination_is_rejected_at_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            token_path = Path(temporary) / "token"
            with self.assertRaisesRegex(PeerConfigurationError, "private"):
                self._config(token_path, bind_host="203.0.113.10")
            with self.assertRaisesRegex(PeerConfigurationError, "private"):
                self._config(token_path, peer_addresses=("8.8.8.8",))

    async def test_unsafe_development_is_loopback_only_and_audited(self) -> None:
        starts = 0

        async def server_factory(*_args: object, **_kwargs: object) -> _FakeServer:
            nonlocal starts
            starts += 1
            return _FakeServer()

        with tempfile.TemporaryDirectory() as temporary:
            config = self._config(
                Path(temporary) / "token",
                unsafe_development=True,
                certificate_path=None,
                key_path=None,
                ca_path=None,
                token_path=None,
                peer_pins=(),
            )
            agent = PeerAgent(config, server_factory=server_factory)
            await agent.start()
            self.assertEqual(starts, 1)
            self.assertEqual(agent.audit[-1].outcome, "unsafe-development-loopback")
            await agent.stop()
            with self.assertRaisesRegex(PeerConfigurationError, "loopback"):
                self._config(
                    Path(temporary) / "token",
                    bind_host="10.20.30.10",
                    unsafe_development=True,
                    certificate_path=None,
                    key_path=None,
                    ca_path=None,
                    token_path=None,
                    peer_pins=(),
                )

    async def test_committed_client_certificate_completes_mutual_tls(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            token_path = Path(temporary) / "token"
            token_path.write_text("test-token", encoding="utf-8")
            agent = PeerAgent(self._config(token_path))
            await agent.start()
            try:
                server = agent.server
                self.assertIsNotNone(server)
                assert server is not None
                port = server.sockets[0].getsockname()[1]
                context = ssl.create_default_context(
                    ssl.Purpose.SERVER_AUTH,
                    cafile=str(FIXTURE_DIR / "test-ca.pem"),
                )
                context.load_cert_chain(
                    str(FIXTURE_DIR / "peer-client-cert.pem"),
                    str(FIXTURE_DIR / "peer-client-key.pem"),
                )
                reader, writer = await asyncio.open_connection(
                    "localhost", port, ssl=context, server_hostname="localhost"
                )
                del reader
                writer.close()
                await writer.wait_closed()
            finally:
                await agent.stop()


class PeerControlTests(PeerStartupTests):
    def _frame(self, **changes: object) -> PeerFrame:
        values: dict[str, object] = {
            "version": 1,
            "operation": "capabilities",
            "correlation_id": "correlation-1",
            "identity": "loopback-peer",
            "issued_at": datetime.now(timezone.utc),
            "expires_at": datetime.now(timezone.utc) + timedelta(minutes=1),
            "nonce": "nonce-00000001",
            "body": {},
        }
        values.update(changes)
        return PeerFrame(**values)  # type: ignore[arg-type]

    async def _agent(self, token_path: Path, calls: list[str]) -> PeerAgent:
        async def capabilities(frame: PeerFrame) -> dict[str, object]:
            calls.append(frame.operation)
            return {"capabilities": ["paired-control"]}

        agent = PeerAgent(
            self._config(token_path, unsafe_development=True),
            handlers={"capabilities": capabilities},
        )
        await agent.start()
        return agent

    async def _send_raw(
        self, agent: PeerAgent, document: bytes, *, token: str = "test-token"
    ) -> bytes:
        server = agent.server
        assert server is not None
        port = server.sockets[0].getsockname()[1]
        if agent.config.unsafe_development:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
        else:
            context = ssl.create_default_context(
                ssl.Purpose.SERVER_AUTH, cafile=str(FIXTURE_DIR / "test-ca.pem")
            )
            context.load_cert_chain(
                str(FIXTURE_DIR / "peer-client-cert.pem"),
                str(FIXTURE_DIR / "peer-client-key.pem"),
            )
            reader, writer = await asyncio.open_connection(
                "localhost", port, ssl=context, server_hostname="localhost"
            )
        try:
            envelope = json.loads(document.decode("utf-8"))
            envelope["token"] = token
            payload = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
            writer.write(len(payload).to_bytes(4, "big") + payload)
            await writer.drain()
            header = await asyncio.wait_for(reader.readexactly(4), timeout=1)
            return await asyncio.wait_for(reader.readexactly(int.from_bytes(header, "big")), timeout=1)
        finally:
            writer.close()
            await writer.wait_closed()

    async def test_authenticated_capability_frame_reaches_only_closed_handler(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            token_path = Path(temporary) / "token"
            token_path.write_text("test-token", encoding="utf-8")
            calls: list[str] = []
            agent = await self._agent(token_path, calls)
            try:
                response = await self._send_raw(agent, self._frame().to_json())
                self.assertIn(b"capabilities", response)
                self.assertEqual(calls, ["capabilities"])
            finally:
                await agent.stop()

    async def test_peer_client_completes_strict_mutual_tls_control(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            token_path = Path(temporary) / "token"
            token_path.write_text("test-token", encoding="utf-8")
            agent = PeerAgent(
                self._config(token_path),
                handlers={"capabilities": lambda _frame: {"capabilities": ["paired-v1"]}},
            )
            await agent.start()
            try:
                server = agent.server
                assert server is not None
                client_config = self._config(
                    token_path,
                    control_port=server.sockets[0].getsockname()[1],
                    certificate_path=FIXTURE_DIR / "peer-client-cert.pem",
                    key_path=FIXTURE_DIR / "peer-client-key.pem",
                    peer_pins=(self._pin(FIXTURE_DIR / "localhost-cert.pem"),),
                    server_hostname="localhost",
                )
                frame = await PeerClient(client_config).request(self._frame())
                self.assertEqual(dict(frame.body), {"capabilities": ["paired-v1"]})
            finally:
                await agent.stop()

    async def test_malformed_frames_and_bad_token_fail_before_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            token_path = Path(temporary) / "token"
            token_path.write_text("test-token", encoding="utf-8")
            calls: list[str] = []
            agent = await self._agent(token_path, calls)
            try:
                for document, token in ((b'{"token":"bad"}', "test-token"),
                                        (self._frame().to_json(), "wrong-token")):
                    with self.subTest(document=document, token=token):
                        with self.assertRaises((asyncio.IncompleteReadError, TimeoutError)):
                            await self._send_raw(agent, document, token=token)
                self.assertEqual(calls, [])
            finally:
                await agent.stop()

    async def test_replay_and_live_cache_full_never_dispatch_again(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            token_path = Path(temporary) / "token"
            token_path.write_text("test-token", encoding="utf-8")
            calls: list[str] = []
            agent = await self._agent(token_path, calls)
            try:
                encoded = self._frame().to_json()
                await self._send_raw(agent, encoded)
                with self.assertRaises((asyncio.IncompleteReadError, TimeoutError)):
                    await self._send_raw(agent, encoded)
                self.assertEqual(calls, ["capabilities"])
                agent._nonces._capacity = 1  # type: ignore[attr-defined]
                with self.assertRaises((asyncio.IncompleteReadError, TimeoutError)):
                    await self._send_raw(
                        agent, self._frame(nonce="nonce-00000002").to_json()
                    )
                self.assertEqual(calls, ["capabilities"])
            finally:
                await agent.stop()

    async def test_client_pin_and_facade_lifecycle_are_application_owned(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, HistoryStore(":memory:") as history:
            token_path = Path(temporary) / "token"
            token_path.write_text("test-token", encoding="utf-8")
            calls: list[str] = []
            agent = await self._agent(token_path, calls)
            try:
                server = agent.server
                assert server is not None
                port = server.sockets[0].getsockname()[1]
                client_config = replace(
                    self._config(token_path, unsafe_development=True),
                    control_port=port,
                    peer_pins=(),
                )
                client = PeerClient(
                    client_config,
                    certificate_path=FIXTURE_DIR / "peer-client-cert.pem",
                    key_path=FIXTURE_DIR / "peer-client-key.pem",
                )
                self.assertEqual((await client.request(self._frame())).operation, "capabilities")
            finally:
                await agent.stop()

            created: list[PeerAgent] = []

            def factory(config: PeerConfig) -> PeerAgent:
                instance = PeerAgent(config, server_factory=lambda *_args, **_kwargs: asyncio.sleep(0, result=_FakeServer()))
                created.append(instance)
                return instance

            app = MercuryApplication(history=history, peer_agent_factory=factory)
            managed = await app.start_agent(self._config(token_path, unsafe_development=True,
                certificate_path=None, key_path=None, ca_path=None, token_path=None, peer_pins=()))
            self.assertIs(managed, created[0])
            await app.stop_agent()

    async def test_audit_and_errors_do_not_disclose_token_or_private_key_values(self) -> None:
        token = "super-secret-token-value"
        key_value = (FIXTURE_DIR / "localhost-key.pem").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as temporary:
            token_path = Path(temporary) / "token"
            token_path.write_text(token, encoding="utf-8")
            agent = PeerAgent(self._config(token_path, unsafe_development=True))
            await agent.start()
            try:
                rendered = repr(agent.audit)
                self.assertNotIn(token, rendered)
                self.assertNotIn(key_value, rendered)
            finally:
                await agent.stop()
