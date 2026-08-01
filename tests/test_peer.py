"""Controlled-loopback tests for the peer-control trust boundary."""

from __future__ import annotations

import asyncio
import hashlib
import ssl
import tempfile
import unittest
from pathlib import Path

from mercury.peer import PeerAgent, PeerConfig, PeerConfigurationError


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "tls"


class _FakeServer:
    def close(self) -> None:
        return None

    async def wait_closed(self) -> None:
        return None


class PeerStartupTests(unittest.IsolatedAsyncioTestCase):
    def _config(self, token_path: Path, **changes: object) -> PeerConfig:
        values: dict[str, object] = {
            "identity": "loopback-peer",
            "bind_host": "127.0.0.1",
            "control_port": 0,
            "certificate_path": FIXTURE_DIR / "localhost-cert.pem",
            "key_path": FIXTURE_DIR / "localhost-key.pem",
            "ca_path": FIXTURE_DIR / "test-ca.pem",
            "token_path": token_path,
            "peer_pins": ("sha256:" + hashlib.sha256(
                (FIXTURE_DIR / "peer-client-cert.pem").read_bytes()
            ).hexdigest(),),
            "peer_addresses": ("127.0.0.1",),
        }
        values.update(changes)
        return PeerConfig(**values)  # type: ignore[arg-type]

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
                    bind_host="192.0.2.10",
                    certificate_path=None,
                    key_path=None,
                    ca_path=None,
                    token_path=None,
                    peer_pins=(),
                )
                await PeerAgent(config, server_factory=server_factory).start()
        self.assertEqual(starts, 0)

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
                    bind_host="192.0.2.10",
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

