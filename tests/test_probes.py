from __future__ import annotations

import errno
import unittest

from mercury.models import Disposition, EvidenceKind, ProbeKind
from mercury.platform.common import CommandOutcome
from mercury.platform.common import CommandResult
from mercury.planner import PreparedStep
from mercury.policy import ScopeGrant
from mercury.probes import dns_probe, http_probe, tcp_probe, tls_probe
from mercury.profiles import DiagnosisRequest, compile_diagnosis
from mercury.resolver import ResolutionResult
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


if __name__ == "__main__":
    unittest.main()
