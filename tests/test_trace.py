from __future__ import annotations

import unittest

from mercury.history import HistoryStore
from mercury.models import EvidenceKind, TaskState
from mercury.platform.common import CommandOutcome, CommandResult
from mercury.policy import PolicyError
from mercury.trace import (
    TraceRequest, TraceRunner, compile_trace, default_trace_grant,
    linux_trace_argv, parse_linux_trace, parse_windows_trace, windows_trace_argv,
)
from mercury.planner import authorize_plan
from mercury.tasks import TaskService


WINDOWS_COMPLETE = """\
Tracing route to 203.0.113.7 over a maximum of 3 hops:
  1     1 ms     1 ms     1 ms  192.0.2.1
  2     *        *        *     Request timed out.
  3     4 ms     4 ms     4 ms  203.0.113.7
"""
LINUX_ALTERNATE = """\
traceroute to 203.0.113.7 (203.0.113.7), 3 hops max
 1  192.0.2.1  1.0 ms  1.1 ms
 2  192.0.2.2  2.0 ms  192.0.2.3  2.1 ms
 3  203.0.113.7  4.0 ms
"""


class TraceParserTests(unittest.TestCase):
    def test_complete_unanswered_and_alternate_hops_remain_raw_evidence(self):
        windows = parse_windows_trace(WINDOWS_COMPLETE)
        self.assertEqual(len(windows), 3)
        self.assertFalse(windows[1].answered)
        self.assertEqual(windows[-1].addresses, ("203.0.113.7",))
        linux = parse_linux_trace(LINUX_ALTERNATE)
        self.assertEqual(linux[1].addresses, ("192.0.2.2", "192.0.2.3"))
        self.assertIn("192.0.2.3", linux[1].raw)

    def test_fixed_argv_uses_only_normalized_addresses_and_bounds(self):
        self.assertEqual(windows_trace_argv("203.0.113.7", max_hops=3, timeout_s=0.2), ("tracert.exe", "-d", "-h", "3", "-w", "200", "203.0.113.7"))
        self.assertEqual(linux_trace_argv("203.0.113.7", max_hops=3, timeout_s=0.2), ("traceroute", "-n", "-m", "3", "-w", "0.2", "203.0.113.7"))
        with self.assertRaises(ValueError):
            linux_trace_argv("203.0.113.7;whoami", max_hops=3, timeout_s=0.2)


class TraceServiceTests(unittest.IsolatedAsyncioTestCase):
    async def test_scope_and_authorization_fail_before_native_command(self):
        with self.assertRaises(PolicyError):
            TraceRequest("203.0.113.7", "198.51.100.0/24", authorized=True)
        request = TraceRequest("203.0.113.7", "203.0.113.0/24", authorized=False)
        with self.assertRaises(PolicyError):
            compile_trace(request, grant=default_trace_grant(request))

    async def test_repeats_keep_alternate_paths_without_a_route_claim(self):
        request = TraceRequest("203.0.113.7", "203.0.113.0/24", max_hops=3, repeats=2, timeout_s=0.2, authorized=True)
        plan = authorize_plan(compile_trace(request, grant=default_trace_grant(request)))
        calls = []

        async def command(argv, timeout, maximum):
            calls.append((argv, timeout, maximum))
            return CommandResult(argv, 0, LINUX_ALTERNATE, "", CommandOutcome.SUCCESS)

        with HistoryStore(":memory:") as history:
            service = TaskService(history)
            task_id = service.submit(plan, TraceRunner(request, system=lambda: "Linux", command_runner=command), task_kind="trace", requested_config={"profile": "native-trace-v1", "targets": [request.target], "repeats": 2, "timeout_s": 0.2, "purpose": "controlled trace", "network_io": True})
            result = await service.wait(task_id)
        self.assertEqual(result.state, TaskState.COMPLETED)
        self.assertEqual((result.progress.completed, result.progress.total), (2, 2))
        alternates = [item for item in result.observations if item.evidence_kind is EvidenceKind.PATH_HOP and len(item.detail["addresses"]) == 2]
        self.assertEqual({item.attempt for item in alternates}, {1, 2})
        self.assertEqual(len(calls), 2)
        self.assertNotIn("switch", " ".join(item.summary for item in result.conclusions).lower())

    async def test_missing_native_tool_is_explicit_not_an_empty_path(self):
        request = TraceRequest("127.0.0.1", "127.0.0.0/8", max_hops=1, repeats=1, authorized=True)
        plan = authorize_plan(compile_trace(request, grant=default_trace_grant(request)))

        async def command(argv, _timeout, _maximum):
            return CommandResult(argv, None, "", "", CommandOutcome.MISSING_TOOL, error_type="FileNotFoundError")

        with HistoryStore(":memory:") as history:
            service = TaskService(history)
            task_id = service.submit(plan, TraceRunner(request, system=lambda: "Linux", command_runner=command), task_kind="trace", requested_config={"profile": "native-trace-v1", "targets": [request.target], "repeats": 1, "timeout_s": 1.0, "purpose": "controlled trace", "network_io": True})
            result = await service.wait(task_id)
        self.assertEqual(result.observations[0].evidence_kind, EvidenceKind.UNSUPPORTED)
        self.assertEqual(result.observations[0].disposition.value, "unavailable")


if __name__ == "__main__":
    unittest.main()
