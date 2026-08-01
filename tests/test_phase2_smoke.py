"""Controlled Phase 2 facade smoke tests; no public destinations are allowed."""

from __future__ import annotations

import ipaddress
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from mercury.app import MercuryApplication
from mercury.history import HistoryStore
from mercury.models import (
    Confidence, Conclusion, Direction, Disposition, EffectiveConfig,
    EvidenceKind, Health, Observation, Progress, TaskResult, TaskState,
)
from mercury.policy import ScopeGrant
from mercury.profiles import DiagnosisRequest, compile_diagnosis
from mercury.render import render_diagnosis, render_status
from mercury.tasks import SyntheticRunner


LOOPBACK_ALLOWLIST = (ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128"))


def _status_result() -> TaskResult:
    now = datetime(2026, 8, 1, tzinfo=timezone.utc)
    switch = Observation("switch-limit", "topology_limit", Disposition.UNAVAILABLE,
        EvidenceKind.UNSUPPORTED, Direction.LOCAL, "local", now, now, 0, source="test",
        detail={"reason": "no_direct_lldp_or_managed_evidence"})
    return TaskResult("status-test", "status", Direction.LOCAL, "local", TaskState.COMPLETED,
        now, now, {"passive": True}, EffectiveConfig("status-v1", ("local",), False, "test", {}),
        Progress(0, 0, 0), observations=(switch,), conclusions=(Conclusion(
            "status-access-switch-unavailable", "Access switch not observable", "No direct evidence.",
            Health.UNKNOWN, Confidence.HIGH, (switch.id,)),))


class Phase2SmokeTests(unittest.IsolatedAsyncioTestCase):
    async def test_status_facade_and_projection_stay_passive(self) -> None:
        expected = _status_result()

        async def collector() -> TaskResult:
            return expected

        with HistoryStore(":memory:") as history:
            result = await MercuryApplication(history=history, status_collector=collector).status()
        self.assertIs(result, expected)
        text = render_status(result)
        self.assertIn("Access switch: not observable", text)
        self.assertIn("no_direct_lldp_or_managed_evidence", text)

    async def test_loopback_diagnosis_round_trips_terminal_result(self) -> None:
        request = DiagnosisRequest(profile="custom", targets=("127.0.0.1:443",), authorized=True)
        compiled = await compile_diagnosis(request, grant=ScopeGrant(networks=()))

        async def compiler(received, *, grant):
            self.assertEqual(received, request)
            self.assertTrue(all(any(ipaddress.ip_address(step.address) in network for network in LOOPBACK_ALLOWLIST)
                                for step in compiled.plan.preview.steps if step.address))
            return compiled

        with tempfile.TemporaryDirectory() as temporary:
            with HistoryStore(Path(temporary) / "history.sqlite3") as history:
                app = MercuryApplication(history=history, compiler=compiler,
                    runner_factory=lambda _: SyntheticRunner())
                result = await app.diagnose(request)
                record = history.list_tasks(limit=1)[0]
                self.assertEqual(record.result, result)
        self.assertEqual(len([item for item in result.conclusions if item.id == "diagnosis-health"]), 1)
        self.assertIn("Diagnosis: partial", render_diagnosis(result))


if __name__ == "__main__":
    unittest.main()
