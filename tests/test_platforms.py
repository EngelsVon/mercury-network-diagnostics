from __future__ import annotations

import asyncio
import math
import sys
import unittest
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
