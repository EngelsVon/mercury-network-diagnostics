from __future__ import annotations

import unittest
from datetime import datetime, timezone

from mercury.history import HistoryRecord
from mercury.models import CoverageProfile, TaskState
from mercury.reports import ReportError, compare_records, coverage_html_table, html_report, redact, report_wire
from tests.test_web import result


def record(identifier: str, *, kind: str = "web") -> HistoryRecord:
    now = datetime(2026, 8, 2, tzinfo=timezone.utc)
    task = result()
    object.__setattr__(task, "task_id", identifier)
    object.__setattr__(task, "task_kind", kind)
    return HistoryRecord(identifier, kind, TaskState.COMPLETED, now, now, {}, {}, task)


class ReportTests(unittest.TestCase):
    def test_coverage_table_is_accessible_and_scopes_negative_claims(self) -> None:
        document = coverage_html_table(result(), requested=(CoverageProfile.TCP_TAGGED,))
        self.assertIn('<th scope="col">Profile</th>', document)
        self.assertIn("untested tunnel mechanisms remain outside", document)
        self.assertIn("skipped", document)

    def test_default_redaction_is_recursive_but_never_retains_secrets(self) -> None:
        value = {"token": "abc", "target": "203.0.113.2", "nested": {"mac": "aa:bb:cc:dd:ee:ff", "payload": "hello", "value": "private.example"}}
        self.assertEqual(redact(value), {"token": "[redacted secret]", "target": "[redacted identifier]", "nested": {"mac": "[redacted identifier]", "payload": "[redacted payload]", "value": "[redacted identifier]"}})
        retained = redact(value, retain_sensitive=True)
        self.assertEqual(retained["token"], "[redacted secret]")
        self.assertEqual(retained["target"], "203.0.113.2")

    def test_report_is_deterministic_and_html_escaped(self) -> None:
        item = record("report-one")
        first, second = report_wire(item), report_wire(item)
        self.assertEqual(first, second)
        object.__setattr__(item.result, "task_id", "<unsafe>")
        self.assertIn("&lt;unsafe&gt;", html_report(item))

    def test_comparison_cites_changed_and_missing_evidence_without_conclusion(self) -> None:
        left, right = record("left"), record("right")
        object.__setattr__(right.result.observations[0], "detail", {"status": "changed"})
        delta = compare_records(left, right)
        self.assertEqual(delta["evidence"][0]["status"], "changed")
        self.assertIn("not as a reachability conclusion", delta["limitation"])
        with self.assertRaisesRegex(ReportError, "not compatible"):
            compare_records(left, record("other", kind="trace"))


if __name__ == "__main__":
    unittest.main()
