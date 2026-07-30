from __future__ import annotations

import asyncio
import math
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from mercury.models import CapabilityState
from mercury.platform import collect_platform
from mercury.platform.common import (
    CommandOutcome,
    CommandResult,
    DnsServerRecord,
    MAX_COMMAND_OUTPUT_BYTES,
    PlatformRecords,
    RouteRecord,
    run_command,
    run_passive_command,
)
from mercury.platform.linux import (
    LINUX_IPV4_ROUTES_ARGV,
    LINUX_IPV6_ROUTES_ARGV,
    LINUX_RESOLVECTL_ARGV,
    collect_platform as collect_linux,
    parse_resolv_conf,
    parse_routes as parse_linux_routes,
)
from mercury.platform.macos import (
    MACOS_NETSTAT_V4_ARGV,
    MACOS_NETSTAT_V6_ARGV,
    MACOS_ROUTE_V4_ARGV,
    MACOS_ROUTE_V6_ARGV,
    MACOS_SCUTIL_DNS_ARGV,
    collect_platform as collect_macos,
    parse_netstat,
    parse_route_get,
    parse_scutil_dns,
)
from mercury.platform.windows import (
    WINDOWS_DNS_ARGV,
    WINDOWS_ROUTES_ARGV,
    collect_platform as collect_windows,
    parse_dns as parse_windows_dns,
    parse_routes as parse_windows_routes,
)


FIXTURES = Path(__file__).with_name("fixtures") / "platform"


def fixture(platform: str, name: str) -> str:
    return (FIXTURES / platform / name).read_text(encoding="utf-8")


def command_result(
    argv: tuple[str, ...],
    *,
    stdout: str = "",
    outcome: CommandOutcome = CommandOutcome.SUCCESS,
    returncode: int | None = None,
) -> CommandResult:
    if outcome is CommandOutcome.SUCCESS:
        returncode = 0
    elif outcome is CommandOutcome.NONZERO:
        returncode = 1
    return CommandResult(
        argv=argv,
        returncode=returncode,
        stdout=stdout,
        stderr="",
        outcome=outcome,
        stdout_bytes=len(stdout.encode("utf-8")),
    )


class FixtureRunner:
    def __init__(self, results: dict[tuple[str, ...], CommandResult]) -> None:
        self.results = results
        self.calls: list[tuple[tuple[str, ...], float, int]] = []

    async def __call__(
        self,
        argv: tuple[str, ...],
        timeout_s: float,
        max_output_bytes: int,
    ) -> CommandResult:
        self.calls.append((argv, timeout_s, max_output_bytes))
        return self.results[argv]


class RecordTests(unittest.TestCase):
    def test_command_result_requires_canonical_typed_state(self) -> None:
        valid = CommandResult(
            argv=("tool", "--json"),
            returncode=0,
            stdout="数据",
            stderr="",
            outcome=CommandOutcome.SUCCESS,
            stdout_bytes=len("数据".encode()),
        )
        self.assertEqual(valid.argv, ("tool", "--json"))
        self.assertFalse(valid.timed_out)

        cases = (
            {"argv": [], "returncode": 0, "outcome": CommandOutcome.SUCCESS},
            {"argv": ("",), "returncode": 0, "outcome": CommandOutcome.SUCCESS},
            {"argv": ("tool",), "returncode": None, "outcome": CommandOutcome.SUCCESS},
            {"argv": ("tool",), "returncode": 0, "outcome": CommandOutcome.NONZERO},
            {"argv": ("tool",), "returncode": 1, "outcome": CommandOutcome.TIMEOUT},
            {"argv": ("tool",), "returncode": 0, "outcome": "success"},
        )
        for values in cases:
            with self.subTest(values=values), self.assertRaises(ValueError):
                CommandResult(
                    stdout="",
                    stderr="",
                    **values,  # type: ignore[arg-type]
                )

    def test_diagnostic_is_sanitized_and_bounded(self) -> None:
        result = CommandResult(
            argv=("tool",),
            returncode=1,
            stdout="",
            stderr="token=secret-value\x00" + ("x" * 2_000),
            outcome=CommandOutcome.NONZERO,
            stderr_bytes=2_020,
        )
        self.assertEqual(result.diagnostic, "[sensitive detail redacted]")
        controls = CommandResult(
            argv=("tool",),
            returncode=1,
            stdout="",
            stderr="alpha\x00beta\n",
            outcome=CommandOutcome.NONZERO,
            stderr_bytes=11,
        )
        self.assertEqual(controls.diagnostic, "alpha beta ")

    def test_route_record_normalizes_prefixes_and_keeps_metrics_separate(self) -> None:
        route = RouteRecord(
            family=4,
            destination="192.0.2.99/24",
            gateway="192.0.2.1",
            interface_name="以太网",
            route_metric=10,
            interface_metric=25,
            source="fixture",
        )
        self.assertEqual(route.destination, "192.0.2.0/24")
        self.assertEqual(route.effective_metric, 35)
        self.assertFalse(route.is_default)
        default = RouteRecord(
            family=6,
            destination="::/0",
            interface_index=4,
            source="fixture",
            on_link=True,
        )
        self.assertTrue(default.is_default)
        self.assertIsNone(default.gateway)

    def test_route_record_rejects_family_interface_and_metric_errors(self) -> None:
        cases = (
            {"family": 5, "destination": "0.0.0.0/0", "interface_index": 1},
            {"family": 4, "destination": "::/0", "interface_index": 1},
            {"family": 4, "destination": "0.0.0.0/0"},
            {
                "family": 4,
                "destination": "0.0.0.0/0",
                "interface_index": 1,
                "route_metric": True,
            },
        )
        for values in cases:
            with self.subTest(values=values), self.assertRaises(ValueError):
                RouteRecord(source="fixture", **values)  # type: ignore[arg-type]

    def test_dns_record_separates_and_validates_ipv6_scope(self) -> None:
        record = DnsServerRecord(
            family=6,
            address="fe80::1",
            scope_id="Ethernet 2",
            interface_name="Ethernet 2",
            source="fixture",
        )
        self.assertEqual(record.address, "fe80::1")
        self.assertEqual(record.scope_id, "Ethernet 2")
        cases = (
            {"family": 6, "address": "fe80::1%Ethernet", "scope_id": None},
            {"family": 4, "address": "192.0.2.53", "scope_id": "1"},
            {"family": 6, "address": "2001:db8::53", "scope_id": "1"},
            {"family": 4, "address": "192.0.2.53"},
        )
        for values in cases:
            with self.subTest(values=values), self.assertRaises(ValueError):
                DnsServerRecord(source="fixture", **values)  # type: ignore[arg-type]


class CommandBoundaryTests(unittest.IsolatedAsyncioTestCase):
    async def test_success_nonzero_unicode_and_missing_executable(self) -> None:
        success = await run_command(
            (
                sys.executable,
                "-c",
                "import sys; sys.stdout.buffer.write('Mercury-网络'.encode())",
            ),
            timeout_s=5.0,
        )
        self.assertEqual(success.outcome, CommandOutcome.SUCCESS)
        self.assertEqual(success.stdout.strip(), "Mercury-网络")

        nonzero = await run_command(
            (sys.executable, "-c", "raise SystemExit(7)"),
            timeout_s=5.001,
        )
        self.assertEqual(nonzero.outcome, CommandOutcome.NONZERO)
        self.assertEqual(nonzero.returncode, 7)

        missing = await run_command(
            ("mercury-definitely-missing-executable-02-01",),
        )
        self.assertEqual(missing.outcome, CommandOutcome.MISSING_TOOL)
        self.assertEqual(missing.error_type, "FileNotFoundError")

    async def test_permission_error_is_typed_without_localized_text(self) -> None:
        with patch(
            "mercury.platform.common.asyncio.create_subprocess_exec",
            new=AsyncMock(side_effect=PermissionError("本地化路径")),
        ):
            result = await run_command(("blocked",))
        self.assertEqual(result.outcome, CommandOutcome.PERMISSION_DENIED)
        self.assertEqual(result.stderr, "")
        self.assertEqual(result.error_type, "PermissionError")

    async def test_timeout_and_output_boundaries_are_validated_before_creation(
        self,
    ) -> None:
        valid_timeouts = (0.1, 5.0, 5.001, 30.0)
        for timeout in valid_timeouts:
            with self.subTest(timeout=timeout):
                result = await run_command(
                    (sys.executable, "-c", "pass"),
                    timeout_s=timeout,
                    max_output_bytes=1,
                )
                self.assertIn(
                    result.outcome,
                    (CommandOutcome.SUCCESS, CommandOutcome.TIMEOUT),
                )
        for limit in (1, MAX_COMMAND_OUTPUT_BYTES):
            with self.subTest(limit=limit):
                result = await run_command(
                    (sys.executable, "-c", "pass"),
                    max_output_bytes=limit,
                )
                self.assertEqual(result.outcome, CommandOutcome.SUCCESS)

        invalid_timeouts = (
            0,
            -1,
            0.099,
            30.001,
            math.nan,
            math.inf,
            -math.inf,
            True,
            "5",
        )
        invalid_limits = (0, -1, True, 1.0, MAX_COMMAND_OUTPUT_BYTES + 1)
        create = AsyncMock()
        with patch(
            "mercury.platform.common.asyncio.create_subprocess_exec",
            new=create,
        ):
            for timeout in invalid_timeouts:
                with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                    await run_command(("tool",), timeout_s=timeout)  # type: ignore[arg-type]
            for limit in invalid_limits:
                with self.subTest(limit=limit), self.assertRaises(ValueError):
                    await run_command(
                        ("tool",),
                        max_output_bytes=limit,  # type: ignore[arg-type]
                    )
        create.assert_not_awaited()

    async def test_output_overflow_retains_only_the_bounded_prefix(self) -> None:
        result = await run_command(
            (
                sys.executable,
                "-c",
                "import sys; sys.stdout.buffer.write(b'x' * 4096); sys.stdout.flush()",
            ),
            max_output_bytes=31,
        )
        self.assertEqual(result.outcome, CommandOutcome.OUTPUT_OVERFLOW)
        self.assertEqual(result.stdout_bytes, 31)
        self.assertEqual(result.stdout, "x" * 31)

    async def test_passive_timeout_rejects_above_five_before_runner(self) -> None:
        runner = AsyncMock(
            return_value=CommandResult(
                argv=("tool",),
                returncode=0,
                stdout="",
                stderr="",
                outcome=CommandOutcome.SUCCESS,
            )
        )
        result = await run_passive_command(
            ("tool",),
            timeout_s=5.0,
            runner=runner,
        )
        self.assertEqual(result.outcome, CommandOutcome.SUCCESS)
        runner.assert_awaited_once_with(("tool",), 5.0, MAX_COMMAND_OUTPUT_BYTES)
        runner.reset_mock()
        with self.assertRaises(ValueError):
            await run_passive_command(
                ("tool",),
                timeout_s=5.001,
                runner=runner,
            )
        runner.assert_not_awaited()

    async def test_timeout_and_cancellation_kill_reap_and_close_both_pipes(
        self,
    ) -> None:
        for mode in ("timeout", "cancel"):
            with self.subTest(mode=mode):
                process = _HangingProcess()
                create = AsyncMock(return_value=process)
                with patch(
                    "mercury.platform.common.asyncio.create_subprocess_exec",
                    new=create,
                ):
                    task = asyncio.create_task(
                        run_command(("fixture",), timeout_s=0.1)
                    )
                    await process.both_readers_started.wait()
                    if mode == "cancel":
                        task.cancel()
                        with self.assertRaises(asyncio.CancelledError):
                            await task
                    else:
                        result = await task
                        self.assertEqual(result.outcome, CommandOutcome.TIMEOUT)
                self.assertEqual(process.kill_count, 1)
                self.assertGreaterEqual(process.wait_count, 1)
                self.assertTrue(process.stdout.transport.closed)
                self.assertTrue(process.stderr.transport.closed)
                self.assertTrue(all(reader.cancelled for reader in process.streams))


class WindowsAdapterTests(unittest.IsolatedAsyncioTestCase):
    async def test_windows_fixtures_preserve_defaults_unicode_and_metrics(self) -> None:
        routes = parse_windows_routes(fixture("windows", "routes.json"))
        defaults = [route for route in routes if route.is_default]
        self.assertEqual(len(defaults), 3)
        self.assertEqual(defaults[0].interface_name, "以太网")
        self.assertEqual(defaults[0].route_metric, 15)
        self.assertEqual(defaults[0].interface_metric, 25)
        self.assertEqual(defaults[0].effective_metric, 40)
        self.assertTrue(routes[-1].on_link)

        dns = parse_windows_dns(fixture("windows", "dns.json"))
        self.assertEqual(len(dns), 3)
        self.assertEqual(dns[1].address, "fe80::53")
        self.assertEqual(dns[1].scope_id, "12")

        runner = FixtureRunner(
            {
                WINDOWS_ROUTES_ARGV: command_result(
                    WINDOWS_ROUTES_ARGV,
                    stdout=fixture("windows", "routes.json"),
                ),
                WINDOWS_DNS_ARGV: command_result(
                    WINDOWS_DNS_ARGV,
                    stdout=fixture("windows", "dns.json"),
                ),
            }
        )
        result = await collect_windows(runner=runner)
        self.assertEqual(result.routes, routes)
        self.assertEqual(result.dns_servers, dns)
        self.assertTrue(all(cap.state is CapabilityState.AVAILABLE for cap in result.capabilities))
        self.assertTrue(all(call[1] == 5.0 for call in runner.calls))

    async def test_windows_command_failures_keep_dns_source(self) -> None:
        dns = command_result(WINDOWS_DNS_ARGV, stdout=fixture("windows", "dns.json"))
        outcomes = (
            CommandOutcome.MISSING_TOOL,
            CommandOutcome.PERMISSION_DENIED,
            CommandOutcome.NONZERO,
            CommandOutcome.TIMEOUT,
            CommandOutcome.OUTPUT_OVERFLOW,
        )
        for outcome in outcomes:
            with self.subTest(outcome=outcome):
                runner = FixtureRunner(
                    {
                        WINDOWS_ROUTES_ARGV: command_result(
                            WINDOWS_ROUTES_ARGV,
                            outcome=outcome,
                        ),
                        WINDOWS_DNS_ARGV: dns,
                    }
                )
                result = await collect_windows(runner=runner)
                self.assertEqual(len(result.routes), 0)
                self.assertEqual(len(result.dns_servers), 3)
                self.assertEqual(result.capabilities[0].detail, outcome.value)

    async def test_windows_parse_failure_keeps_successful_dns(self) -> None:
        runner = FixtureRunner(
            {
                WINDOWS_ROUTES_ARGV: command_result(
                    WINDOWS_ROUTES_ARGV,
                    stdout="{truncated",
                ),
                WINDOWS_DNS_ARGV: command_result(
                    WINDOWS_DNS_ARGV,
                    stdout=fixture("windows", "dns.json"),
                ),
            }
        )
        result = await collect_windows(runner=runner)
        self.assertEqual(result.capabilities[0].detail, "parse_error")
        self.assertEqual(len(result.dns_servers), 3)


class LinuxAdapterTests(unittest.IsolatedAsyncioTestCase):
    async def test_linux_fixture_routes_and_stub_dns_are_explicit(self) -> None:
        v4 = parse_linux_routes(fixture("linux", "routes-v4.json"), 4)
        v6 = parse_linux_routes(fixture("linux", "routes-v6.json"), 6)
        self.assertTrue(v4[0].is_default)
        self.assertTrue(v4[1].on_link)
        self.assertEqual(v6[0].gateway, "fe80::1")
        baseline = parse_resolv_conf(fixture("linux", "resolv.conf"))
        self.assertEqual(baseline[0].address, "127.0.0.53")
        self.assertEqual(baseline[0].configuration_state, "local_stub")

        runner = FixtureRunner(
            {
                LINUX_IPV4_ROUTES_ARGV: command_result(
                    LINUX_IPV4_ROUTES_ARGV,
                    stdout=fixture("linux", "routes-v4.json"),
                ),
                LINUX_IPV6_ROUTES_ARGV: command_result(
                    LINUX_IPV6_ROUTES_ARGV,
                    stdout=fixture("linux", "routes-v6.json"),
                ),
                LINUX_RESOLVECTL_ARGV: command_result(
                    LINUX_RESOLVECTL_ARGV,
                    outcome=CommandOutcome.MISSING_TOOL,
                ),
            }
        )
        result = await collect_linux(
            runner=runner,
            resolv_conf_reader=lambda: fixture("linux", "resolv.conf"),
        )
        self.assertEqual(result.routes, v4 + v6)
        self.assertEqual(result.dns_servers, baseline)
        self.assertEqual(result.capabilities[2].detail, "local_stub_upstream_not_observable")
        self.assertEqual(result.capabilities[3].state, CapabilityState.MISSING_TOOL)

    async def test_linux_malformed_enrichment_keeps_resolv_conf(self) -> None:
        runner = FixtureRunner(
            {
                LINUX_IPV4_ROUTES_ARGV: command_result(LINUX_IPV4_ROUTES_ARGV, stdout="[]"),
                LINUX_IPV6_ROUTES_ARGV: command_result(LINUX_IPV6_ROUTES_ARGV, stdout="[]"),
                LINUX_RESOLVECTL_ARGV: command_result(LINUX_RESOLVECTL_ARGV, stdout="{bad"),
            }
        )
        result = await collect_linux(
            runner=runner,
            resolv_conf_reader=lambda: "nameserver 192.0.2.53\n",
        )
        self.assertEqual(result.dns_servers[0].address, "192.0.2.53")
        self.assertEqual(result.capabilities[-1].detail, "parse_error")


class MacosAdapterTests(unittest.IsolatedAsyncioTestCase):
    async def test_macos_fixtures_cover_defaults_and_scoped_supplemental_dns(self) -> None:
        default = parse_route_get(fixture("macos", "route-v4.txt"), 4)
        routes_v4 = parse_netstat(fixture("macos", "netstat-v4.txt"), 4)
        routes_v6 = parse_netstat(fixture("macos", "netstat-v6.txt"), 6)
        dns = parse_scutil_dns(fixture("macos", "scutil-dns.txt"))
        self.assertTrue(default.is_default)
        self.assertEqual(len(routes_v4), 2)
        self.assertEqual(len(routes_v6), 2)
        self.assertEqual(dns[1].scope_id, "en0")
        self.assertEqual(dns[1].scoped_domain, "corp.example.test")
        self.assertEqual(dns[1].configuration_state, "supplemental")

        runner = FixtureRunner(
            {
                MACOS_ROUTE_V4_ARGV: command_result(MACOS_ROUTE_V4_ARGV, stdout=fixture("macos", "route-v4.txt")),
                MACOS_ROUTE_V6_ARGV: command_result(MACOS_ROUTE_V6_ARGV, outcome=CommandOutcome.NONZERO),
                MACOS_NETSTAT_V4_ARGV: command_result(MACOS_NETSTAT_V4_ARGV, stdout=fixture("macos", "netstat-v4.txt")),
                MACOS_NETSTAT_V6_ARGV: command_result(MACOS_NETSTAT_V6_ARGV, stdout=fixture("macos", "netstat-v6.txt")),
                MACOS_SCUTIL_DNS_ARGV: command_result(MACOS_SCUTIL_DNS_ARGV, stdout=fixture("macos", "scutil-dns.txt")),
            }
        )
        result = await collect_macos(runner=runner)
        self.assertIn(default, result.routes)
        self.assertNotEqual(result.capabilities[1].state, CapabilityState.AVAILABLE)
        self.assertEqual(result.dns_servers, dns)

    async def test_macos_malformed_dns_does_not_erase_routes(self) -> None:
        runner = FixtureRunner(
            {
                MACOS_ROUTE_V4_ARGV: command_result(MACOS_ROUTE_V4_ARGV, stdout=fixture("macos", "route-v4.txt")),
                MACOS_ROUTE_V6_ARGV: command_result(MACOS_ROUTE_V6_ARGV, outcome=CommandOutcome.MISSING_TOOL),
                MACOS_NETSTAT_V4_ARGV: command_result(MACOS_NETSTAT_V4_ARGV, stdout=fixture("macos", "netstat-v4.txt")),
                MACOS_NETSTAT_V6_ARGV: command_result(MACOS_NETSTAT_V6_ARGV, stdout=fixture("macos", "netstat-v6.txt")),
                MACOS_SCUTIL_DNS_ARGV: command_result(MACOS_SCUTIL_DNS_ARGV, stdout="resolver #1\n  if_index : 1 (lo0)\n"),
            }
        )
        result = await collect_macos(runner=runner)
        self.assertGreater(len(result.routes), 0)
        self.assertEqual(result.dns_servers, ())
        self.assertEqual(result.capabilities[-1].detail, "parse_error")


class DispatchTests(unittest.IsolatedAsyncioTestCase):
    async def test_direct_dispatch_selects_only_the_matching_collector(self) -> None:
        for platform_name, selected in (
            ("win32", "windows"),
            ("linux", "linux"),
            ("darwin", "macos"),
        ):
            calls: list[str] = []

            async def windows(**kwargs: object) -> PlatformRecords:
                calls.append("windows")
                return PlatformRecords()

            async def linux(**kwargs: object) -> PlatformRecords:
                calls.append("linux")
                return PlatformRecords()

            async def macos(**kwargs: object) -> PlatformRecords:
                calls.append("macos")
                return PlatformRecords()

            with self.subTest(platform_name=platform_name):
                result = await collect_platform(
                    platform_name=platform_name,
                    windows_collector=windows,
                    linux_collector=linux,
                    macos_collector=macos,
                )
                self.assertEqual(result, PlatformRecords())
                self.assertEqual(calls, [selected])

    async def test_unsupported_platform_is_an_explicit_capability(self) -> None:
        result = await collect_platform(platform_name="plan9")
        self.assertEqual(len(result.capabilities), 1)
        self.assertEqual(
            result.capabilities[0].state,
            CapabilityState.UNSUPPORTED,
        )
        self.assertIn("plan9", result.capabilities[0].source)


class _Transport:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _HangingStream:
    def __init__(self, owner: "_HangingProcess") -> None:
        self.owner = owner
        self.transport = _Transport()
        self._transport = self.transport
        self.cancelled = False

    async def read(self, maximum: int) -> bytes:
        self.owner.started_count += 1
        if self.owner.started_count == 2:
            self.owner.both_readers_started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        return b""


class _HangingProcess:
    def __init__(self) -> None:
        self.returncode: int | None = None
        self.kill_count = 0
        self.wait_count = 0
        self.started_count = 0
        self.both_readers_started = asyncio.Event()
        self.stdout = _HangingStream(self)
        self.stderr = _HangingStream(self)
        self.streams = (self.stdout, self.stderr)

    def kill(self) -> None:
        self.kill_count += 1
        self.returncode = -9

    async def wait(self) -> int:
        self.wait_count += 1
        return -9


if __name__ == "__main__":
    unittest.main()
