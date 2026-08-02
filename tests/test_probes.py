from __future__ import annotations

import asyncio
import errno
import ipaddress
import inspect
import json
from pathlib import Path
import ssl
import unittest

from mercury.models import Disposition, EvidenceKind, ProbeKind
from mercury.platform.common import CommandOutcome
from mercury.platform.common import CommandResult
from mercury.planner import PreparedStep, ProbeSpec, StepCost, Transport, preview_probe_plan
from mercury.policy import ScopeGrant
from mercury.probes import dns_probe, http_probe, tcp_probe, tls_probe
from mercury.profiles import DiagnosisRequest, compile_diagnosis
from mercury.resolver import MAX_RESOLUTION_ADDRESSES, MAX_RESOLUTION_ROWS, ResolutionResult
from mercury.resolver import resolve_addresses


async def _loopback_resolver(hostname: str, **_: object) -> ResolutionResult:
    return ResolutionResult(hostname, ("127.0.0.1",), CommandOutcome.SUCCESS)


async def _compiled_steps() -> tuple[PreparedStep, ...]:
    compiled = await compile_diagnosis(
        DiagnosisRequest(profile="custom", targets=("example.test:443",), authorized=True),
        grant=ScopeGrant(
            networks=(), hostnames=("example.test",), ports=(443,),
            transports=("tcp",), attested=True,
        ), resolver=_loopback_resolver,
    )
    return tuple(PreparedStep(step, step.address) for step in compiled.plan.preview.steps)


class _Writer:
    def __init__(self) -> None:
        self.closed = False
        self.sent = b""

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None

    def write(self, data: bytes) -> None:
        self.sent += data

    async def drain(self) -> None:
        return None

    def get_extra_info(self, name: str) -> None:
        return None


class _Reader:
    def __init__(self, header: bytes) -> None:
        self.header = header

    async def readuntil(self, separator: bytes) -> bytes:
        self.asserted_separator = separator
        return self.header


class DnsProbeTests(unittest.IsolatedAsyncioTestCase):
    async def test_dns_answer_and_failure_categories(self) -> None:
        dns = next(step for step in await _compiled_steps() if step.step.probe_kind is ProbeKind.SYSTEM_DNS)

        async def answer(*_: object, **__: object) -> ResolutionResult:
            return ResolutionResult("example.test", ("127.0.0.1",), CommandOutcome.SUCCESS)

        observation = await dns_probe(dns, resolver=answer)
        self.assertEqual(observation.evidence_kind, EvidenceKind.DNS_ANSWER)
        self.assertEqual(observation.disposition, Disposition.POSITIVE)
        self.assertEqual(observation.detail["addresses"], ("127.0.0.1",))

        async def missing(*_: object, **__: object) -> ResolutionResult:
            return ResolutionResult("example.test", (), CommandOutcome.NONZERO, "NoAddress")

        observation = await dns_probe(dns, resolver=missing)
        self.assertEqual(observation.evidence_kind, EvidenceKind.DNS_FAILURE)
        self.assertEqual(observation.disposition, Disposition.NEGATIVE)

    async def test_dns_timeout_and_error_stay_distinct(self) -> None:
        dns = next(step for step in await _compiled_steps() if step.step.probe_kind is ProbeKind.SYSTEM_DNS)

        async def timeout(*_: object, **__: object) -> ResolutionResult:
            return ResolutionResult("example.test", (), CommandOutcome.TIMEOUT, "Timeout")

        async def broken(*_: object, **__: object) -> ResolutionResult:
            return ResolutionResult("example.test", (), CommandOutcome.ERROR, "MalformedResolverOutput")

        self.assertEqual((await dns_probe(dns, resolver=timeout)).disposition, Disposition.INCONCLUSIVE)
        self.assertEqual((await dns_probe(dns, resolver=broken)).disposition, Disposition.ERROR)


class ResolverIsolationTests(unittest.IsolatedAsyncioTestCase):
    async def test_fixed_isolated_helper_and_timeout_validation(self) -> None:
        calls = []
        async def command(argv, *, timeout_s, max_output_bytes):
            calls.append((argv, timeout_s, max_output_bytes))
            return CommandResult(argv, 0, '["127.0.0.1"]', "", CommandOutcome.SUCCESS)
        resolved = await resolve_addresses("example.test", operation_timeout=5.001, hard_deadline=30.0, command_runner=command)
        self.assertEqual(resolved.addresses, ("127.0.0.1",))
        self.assertEqual(calls[0][0][0:2], (__import__("sys").executable, "-I"))
        self.assertEqual(calls[0][1], 5.001)
        with self.assertRaises(ValueError):
            await resolve_addresses("example.test", operation_timeout=30.001, hard_deadline=30.0, command_runner=command)

    async def test_name_not_found_is_explicit_but_other_helper_failure_is_error(self) -> None:
        async def missing(argv, *, timeout_s, max_output_bytes):
            return CommandResult(argv, 1, '{"error":"NameNotFound"}', "", CommandOutcome.NONZERO)
        async def failed(argv, *, timeout_s, max_output_bytes):
            return CommandResult(argv, 1, '{"error":"ResolverFailure"}', "", CommandOutcome.NONZERO)
        self.assertEqual((await resolve_addresses("example.test", operation_timeout=3, hard_deadline=3, command_runner=missing)).outcome, CommandOutcome.NONZERO)
        self.assertEqual((await resolve_addresses("example.test", operation_timeout=3, hard_deadline=3, command_runner=failed)).outcome, CommandOutcome.ERROR)

    async def test_resolution_row_and_address_boundaries_fail_closed(self) -> None:
        async def helper_rows(rows: list[str]):
            async def command(argv, *, timeout_s, max_output_bytes):
                return CommandResult(argv, 0, json.dumps(rows), "", CommandOutcome.SUCCESS)
            return await resolve_addresses("example.test", operation_timeout=3, hard_deadline=3, command_runner=command)

        accepted = ["127.0.0.1"] * MAX_RESOLUTION_ROWS
        # Duplicate rows are legitimate resolver output; the canonical set stays bounded.
        self.assertEqual((await helper_rows(accepted)).outcome, CommandOutcome.SUCCESS)
        self.assertEqual((await helper_rows(accepted + ["192.0.2.1"])).error, "ResolutionRowOverflow")

        addresses = [f"fd00::{index}" for index in range(MAX_RESOLUTION_ADDRESSES)]
        self.assertEqual((await helper_rows(addresses)).outcome, CommandOutcome.SUCCESS)
        overflow = await helper_rows(addresses + ["fd00::100"])
        self.assertEqual((overflow.outcome, overflow.addresses, overflow.error), (CommandOutcome.ERROR, (), "ResolutionAddressOverflow"))

    async def test_cancellation_propagates_without_a_late_result(self) -> None:
        started = asyncio.Event()
        released = asyncio.Event()

        async def command(argv, *, timeout_s, max_output_bytes):
            started.set()
            await released.wait()
            return CommandResult(argv, 0, '["127.0.0.1"]', "", CommandOutcome.SUCCESS)

        task = asyncio.create_task(resolve_addresses("example.test", operation_timeout=3, hard_deadline=3, command_runner=command))
        await started.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        released.set()
        await asyncio.sleep(0)
        self.assertTrue(task.cancelled())


class TcpProbeTests(unittest.IsolatedAsyncioTestCase):
    async def test_connect_success_and_refusal_have_distinct_evidence(self) -> None:
        prepared = next(step for step in await _compiled_steps() if step.step.probe_kind is ProbeKind.TCP_CONNECT)
        writer = _Writer()
        calls: list[tuple[object, ...]] = []

        async def connected(*args: object, **kwargs: object) -> tuple[_Reader, _Writer]:
            calls.append(args)
            self.assertEqual(kwargs, {})
            return _Reader(b""), writer

        observation = await tcp_probe(prepared, connector=connected)
        self.assertEqual(observation.evidence_kind, EvidenceKind.TCP_CONNECTED)
        self.assertEqual(calls, [("127.0.0.1", 443)])
        self.assertTrue(writer.closed)

        async def refused(*_: object, **__: object) -> tuple[_Reader, _Writer]:
            raise ConnectionRefusedError(errno.ECONNREFUSED, "refused")

        observation = await tcp_probe(prepared, connector=refused)
        self.assertEqual(observation.evidence_kind, EvidenceKind.TCP_REFUSED)
        self.assertEqual(observation.disposition, Disposition.NEGATIVE)

    async def test_reset_unreachable_and_timeout_remain_distinct(self) -> None:
        prepared = next(step for step in await _compiled_steps() if step.step.probe_kind is ProbeKind.TCP_CONNECT)
        cases = (
            (ConnectionResetError(errno.ECONNRESET, "reset"), EvidenceKind.TCP_RESET, Disposition.NEGATIVE),
            (OSError(errno.ENETUNREACH, "unreachable"), EvidenceKind.NETWORK_UNREACHABLE, Disposition.NEGATIVE),
            (TimeoutError(), EvidenceKind.TIMEOUT, Disposition.INCONCLUSIVE),
        )
        for failure, kind, disposition in cases:
            with self.subTest(kind=kind):
                async def connector(*_: object, failure=failure, **__: object):
                    raise failure
                observation = await tcp_probe(prepared, connector=connector)
                self.assertEqual((observation.evidence_kind, observation.disposition), (kind, disposition))


class ConnectorBindingTests(unittest.IsolatedAsyncioTestCase):
    async def test_tls_and_http_use_numeric_address_not_logical_hostname(self) -> None:
        steps = await _compiled_steps()
        for kind, function in ((ProbeKind.TLS_HANDSHAKE, tls_probe), (ProbeKind.HTTP_EXCHANGE, http_probe)):
            prepared = next(step for step in steps if step.step.probe_kind is kind)
            writer = _Writer()
            calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

            async def connector(*args: object, **kwargs: object) -> tuple[_Reader, _Writer]:
                calls.append((args, kwargs))
                header = b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"
                return _Reader(header), writer

            if kind is ProbeKind.TLS_HANDSHAKE:
                await function(prepared, connector=connector)
            else:
                await function(prepared, connector=connector)
                self.assertEqual(writer.sent.split(b"\r\n")[0], b"HEAD / HTTP/1.1")
                self.assertIn(b"Host: example.test", writer.sent)
            self.assertEqual(calls[0][0], ("127.0.0.1", 443))
            self.assertNotEqual(calls[0][0][0], "example.test")


class TlsLoopbackTests(unittest.IsolatedAsyncioTestCase):
    async def test_controlled_loopback_tls_succeeds_only_with_its_explicit_ca(self) -> None:
        cert_data = Path(__file__).with_name("fixtures") / "tls"
        certificate = cert_data / "test-ca.pem"
        server_certificate, server_key = cert_data / "localhost-cert.pem", cert_data / "localhost-key.pem"
        self.assertTrue(certificate.is_file() and server_certificate.is_file() and server_key.is_file())
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(server_certificate, server_key)
        async def handler(reader, writer):
            writer.close()
            await writer.wait_closed()
        server = await asyncio.start_server(
            handler, "127.0.0.1", 0, ssl=server_context, ssl_handshake_timeout=1.0,
        )
        try:
            port = server.sockets[0].getsockname()[1]
            grant = ScopeGrant(networks=(ipaddress.ip_network("127.0.0.0/8"),), hostnames=("localhost",), ports=(port,), transports=("tcp",), attested=True)
            preview = preview_probe_plan(
                specs=(ProbeSpec(ProbeKind.TLS_HANDSHAKE, "localhost", address="127.0.0.1", port=port,
                                 transport=Transport.TCP, source_hostname="localhost", resolution_slot=0,
                                 server_name="localhost", timeout_s=3.0, cost=StepCost(1, 0, 0, logical_packets=1)),),
                grant=grant, profile="loopback-test-v1",
            )
            prepared = PreparedStep(preview.steps[0], "127.0.0.1")
            trusted = await tls_probe(prepared, ssl_context_factory=lambda: ssl.create_default_context(cafile=str(certificate)))
            untrusted = await tls_probe(prepared)
            self.assertEqual(trusted.evidence_kind, EvidenceKind.TLS_HANDSHAKE)
            self.assertEqual(untrusted.evidence_kind, EvidenceKind.TLS_VERIFICATION_FAILED)
        finally:
            server.close()
            await server.wait_closed()

    async def test_default_tls_context_keeps_hostname_and_certificate_checks(self) -> None:
        prepared = next(step for step in await _compiled_steps() if step.step.probe_kind is ProbeKind.TLS_HANDSHAKE)
        seen = []
        async def connector(*args, **kwargs):
            seen.append(kwargs["ssl"])
            return _Reader(b""), _Writer()
        observation = await tls_probe(prepared, connector=connector)
        self.assertEqual(observation.evidence_kind, EvidenceKind.TLS_HANDSHAKE)
        self.assertTrue(seen[0].check_hostname)
        self.assertEqual(seen[0].verify_mode, ssl.CERT_REQUIRED)

    async def test_certificate_verification_failure_is_specific_negative_evidence(self) -> None:
        prepared = next(step for step in await _compiled_steps() if step.step.probe_kind is ProbeKind.TLS_HANDSHAKE)
        async def rejected(*args, **kwargs):
            raise ssl.SSLCertVerificationError(1, "test certificate rejected")
        observation = await tls_probe(prepared, connector=rejected)
        self.assertEqual(observation.evidence_kind, EvidenceKind.TLS_VERIFICATION_FAILED)
        self.assertEqual(observation.disposition, Disposition.NEGATIVE)


class HttpLoopbackTests(unittest.IsolatedAsyncioTestCase):
    async def test_all_valid_statuses_are_positive_without_following_redirects(self) -> None:
        prepared = next(step for step in await _compiled_steps() if step.step.probe_kind is ProbeKind.HTTP_EXCHANGE)
        for status in (200, 204, 301, 404, 500):
            with self.subTest(status=status):
                writer = _Writer()

                async def connector(*_: object, **__: object) -> tuple[_Reader, _Writer]:
                    return _Reader(f"HTTP/1.1 {status} status\r\nLocation: /next\r\n\r\n".encode()), writer

                observation = await http_probe(prepared, connector=connector)
                self.assertEqual(observation.evidence_kind, EvidenceKind.HTTP_RESPONSE)
                self.assertEqual(observation.disposition, Disposition.POSITIVE)
                self.assertEqual(observation.detail["status"], status)


class CleanupTests(unittest.IsolatedAsyncioTestCase):
    async def test_malformed_http_still_closes_its_writer(self) -> None:
        prepared = next(step for step in await _compiled_steps() if step.step.probe_kind is ProbeKind.HTTP_EXCHANGE)
        writer = _Writer()
        async def connector(*args, **kwargs):
            return _Reader(b"not-http\r\n\r\n"), writer
        observation = await http_probe(prepared, connector=connector)
        self.assertEqual(observation.evidence_kind, EvidenceKind.EXECUTION_ERROR)
        self.assertTrue(writer.closed)


class SourceBoundaryTests(unittest.TestCase):
    def test_protocol_and_diagnosis_layers_have_no_unsafe_resolution_or_tls_bypass(self) -> None:
        import mercury.diagnosis as diagnosis
        import mercury.probes as probes
        import mercury.profiles as profiles
        import mercury.tasks as tasks

        source = "\n".join(inspect.getsource(module) for module in (profiles, probes, diagnosis, tasks))
        for forbidden in ("socket.getaddrinfo", "loop.getaddrinfo", "run_in_executor", "shell=True", "CERT_NONE", "_create_unverified_context"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
