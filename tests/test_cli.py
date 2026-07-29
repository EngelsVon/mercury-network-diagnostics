from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from mercury.cli import EXIT_OK, EXIT_PARTIAL, EXIT_POLICY, main


def invoke(*arguments: str) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = main(list(arguments))
    return code, stdout.getvalue(), stderr.getvalue()


class CliTests(unittest.TestCase):
    def test_version_and_model_json(self) -> None:
        code, output, error = invoke("version", "--json")
        self.assertEqual((code, error), (EXIT_OK, ""))
        payload = json.loads(output)
        self.assertEqual(payload["model_schema"], "1.0")
        self.assertIn("python", payload)

        code, output, _ = invoke("model", "--json")
        self.assertEqual(code, EXIT_OK)
        payload = json.loads(output)
        self.assertEqual(payload["semantic_rules"]["silence"], "inconclusive")
        self.assertIn("max_application_bytes", payload["absolute_ceilings"])

    def test_loopback_plan_preview_is_stable_json(self) -> None:
        code, output, error = invoke(
            "plan",
            "127.0.0.1",
            "--ports",
            "53,443",
            "--transport",
            "tcp",
            "--json",
        )
        self.assertEqual((code, error), (EXIT_OK, ""))
        payload = json.loads(output)
        self.assertEqual(payload["targets"], ["127.0.0.1"])
        self.assertEqual(payload["estimate"]["logical_attempts"], 2)

    def test_nonloopback_plan_requires_attestation(self) -> None:
        code, output, error = invoke(
            "plan", "192.0.2.10", "--ports", "443", "--json"
        )
        self.assertEqual(code, EXIT_POLICY)
        self.assertEqual(output, "")
        payload = json.loads(error)
        self.assertEqual(payload["error"]["category"], "policy")
        self.assertIn("attestation", payload["error"]["message"])

    def test_synthetic_task_and_history_share_result(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data_path = str(Path(temporary) / "history.sqlite3")
            code, output, error = invoke(
                "--data-path",
                data_path,
                "task",
                "synthetic",
                "--steps",
                "2",
                "--json",
            )
            self.assertEqual((code, error), (EXIT_OK, ""))
            result = json.loads(output)
            task_id = result["task_id"]
            code, history_output, error = invoke(
                "--data-path",
                data_path,
                "history",
                "show",
                task_id,
                "--json",
            )
            self.assertEqual((code, error), (EXIT_OK, ""))
            stored = json.loads(history_output)
            self.assertEqual(stored["result"], result)

    def test_synthetic_cancellation_uses_partial_exit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            code, output, error = invoke(
                "--data-path",
                str(Path(temporary) / "history.sqlite3"),
                "task",
                "synthetic",
                "--steps",
                "10",
                "--delay",
                "0.03",
                "--cancel-after",
                "0.05",
                "--json",
            )
            self.assertEqual((code, error), (EXIT_PARTIAL, ""))
            result = json.loads(output)
            self.assertEqual(result["state"], "cancelled")
            self.assertLess(
                result["progress"]["completed"], result["progress"]["total"]
            )

    def test_human_projection_mentions_semantics(self) -> None:
        code, output, _ = invoke("model")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("Silence remains inconclusive", output)


if __name__ == "__main__":
    unittest.main()

