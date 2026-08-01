from __future__ import annotations

import asyncio
import contextlib
import io
import json
import tempfile
import unittest
from argparse import Namespace
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from mercury.cli import (
    EXIT_OK,
    EXIT_PARTIAL,
    EXIT_POLICY,
    EXIT_FAILED,
    EXIT_USAGE,
    CliError,
    _run_synthetic,
    build_parser,
    diagnosis_exit_code,
    paired_exit_code,
    main,
)
from mercury.history import HistoryStore
from mercury.models import (
    Confidence, Conclusion, Direction, Disposition, EffectiveConfig, EvidenceKind, Health, Observation, Progress,
    TaskResult, TaskState,
)
from mercury.codec import result_to_wire


def invoke(*arguments: str) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = main(list(arguments))
    return code, stdout.getvalue(), stderr.getvalue()


def diagnosis_result(health: Health | None = Health.PARTIAL, *, duplicate: bool = False) -> TaskResult:
    now = datetime(2026, 8, 1, tzinfo=timezone.utc)
    observation = Observation(
        "diagnosis-observation", "tcp_connect", Disposition.POSITIVE,
        EvidenceKind.TCP_CONNECTED, Direction.OUTBOUND, "127.0.0.1", now, now, 0,
    )
    conclusions = () if health is None else (Conclusion(
        "diagnosis-health", "Selected endpoint diagnosis health", "Endpoint-scoped.",
        health, Confidence.LOW, (observation.id,),
    ),)
    result = TaskResult(
        "diagnosis-test", "diagnose", Direction.LOCAL, "127.0.0.1", TaskState.COMPLETED,
        now, now, {}, EffectiveConfig("custom-v1", ("127.0.0.1",), True, "test", {}),
        Progress(0, 0, 0), observations=(observation,), conclusions=conclusions,
    )
    if duplicate:
        object.__setattr__(result, "conclusions", conclusions * 2)
    return result


def paired_result(health: Health = Health.PARTIAL) -> TaskResult:
    result = diagnosis_result(None)
    observation = result.observations[0]
    paired = Observation(
        "paired-observation", observation.probe, observation.disposition,
        observation.evidence_kind, observation.direction, observation.target,
        observation.started_at, observation.ended_at, observation.duration_ms,
        detail={"paired_endpoint": "owned", "paired_correlation": "pair", "paired_phase": "received"},
    )
    return TaskResult(
        result.task_id, "paired", result.direction, result.target, result.state,
        result.started_at, result.ended_at, result.requested_config, result.effective_config,
        result.progress, observations=(paired,), conclusions=(Conclusion(
            "paired-health", "Paired health", "Typed paired evidence.", health,
            Confidence.LOW, (paired.id,),
        ),),
    )


class CliTests(unittest.TestCase):
    def test_agent_and_paired_accept_only_closed_configuration_inputs(self) -> None:
        parser = build_parser()
        agent = parser.parse_args(("agent", "--config", "peer.json", "--unsafe-development"))
        self.assertEqual((agent.command, agent.config.name, agent.unsafe_development), ("agent", "peer.json", True))
        paired = parser.parse_args(("paired", "--config", "peer.json", "--identity", "peer", "--address", "127.0.0.1", "--authorized"))
        self.assertEqual((paired.command, paired.timeout, paired.authorized), ("paired", 3.0, True))
        with self.assertRaises(CliError):
            parser.parse_args(("paired", "--config", "peer.json", "--identity", "peer", "--address", "127.0.0.1", "--port", "1"))

    def test_web_parser_exposes_only_lifecycle_and_transport_security_options(self) -> None:
        parser = build_parser()
        web = parser.parse_args(("web", "--bind", "127.0.0.1", "--port", "0", "--cert", "cert.pem", "--key", "key.pem", "--token-file", "token.txt"))
        self.assertEqual((web.command, web.bind, web.port, web.cert.name, web.key.name, web.token_file.name), ("web", "127.0.0.1", 0, "cert.pem", "key.pem", "token.txt"))
        with self.assertRaises(CliError):
            parser.parse_args(("web", "--target", "192.0.2.1"))

    def test_history_compare_and_export_are_closed_commands(self) -> None:
        parser = build_parser()
        compared = parser.parse_args(("history", "compare", "left", "right", "--json"))
        exported = parser.parse_args(("history", "export", "task", "--format", "html", "--retain-sensitive"))
        self.assertEqual((compared.history_command, compared.left_task_id, compared.right_task_id), ("compare", "left", "right"))
        self.assertEqual((exported.history_command, exported.format, exported.retain_sensitive), ("export", "html", True))
        with self.assertRaises(CliError):
            parser.parse_args(("history", "export", "task", "--output", "report.html"))

    def test_discovery_parser_exposes_only_passive_or_fixed_tcp_controls(self) -> None:
        parser = build_parser()
        active = parser.parse_args(("discover", "--network", "127.0.0.1/32", "--scope", "127.0.0.0/8", "--profile", "custom", "--ports", "443", "--authorized"))
        self.assertEqual((active.command, active.profile, active.ports, active.authorized), ("discover", "custom", "443", True))
        passive = parser.parse_args(("discover", "--passive"))
        self.assertTrue(passive.passive)
        with self.assertRaises(CliError):
            parser.parse_args(("discover", "--network", "127.0.0.1/32", "--scope", "127.0.0.0/8", "--payload-bytes", "1"))

    def test_passive_discovery_rejects_active_flags_before_facade_work(self) -> None:
        code, output, error = invoke("discover", "--passive", "--authorized", "--json")
        self.assertEqual((code, output), (EXIT_USAGE, ""))
        self.assertEqual(json.loads(error)["error"]["category"], "input")

    def test_trace_cli_requires_authorization_and_has_no_protocol_knobs(self) -> None:
        parser = build_parser()
        trace = parser.parse_args(("trace", "127.0.0.1", "--scope", "127.0.0.0/8", "--hops", "2", "--repeat", "1", "--authorized"))
        self.assertEqual((trace.command, trace.hops, trace.repeat, trace.authorized), ("trace", 2, 1, True))
        with self.assertRaises(CliError):
            parser.parse_args(("trace", "127.0.0.1", "--scope", "127.0.0.0/8", "--protocol", "icmp"))
        code, output, error = invoke("trace", "127.0.0.1", "--scope", "127.0.0.0/8", "--json")
        self.assertEqual((code, output), (EXIT_POLICY, ""))
        self.assertEqual(json.loads(error)["error"]["category"], "policy")

    def test_paired_exit_requires_one_canonical_health_conclusion(self) -> None:
        self.assertEqual(paired_exit_code(paired_result(Health.HEALTHY)), EXIT_OK)
        self.assertEqual(paired_exit_code(paired_result(Health.PARTIAL)), EXIT_PARTIAL)
        self.assertEqual(paired_exit_code(paired_result(Health.FAILED)), EXIT_FAILED)
        with self.assertRaisesRegex(RuntimeError, "paired-health"):
            paired_exit_code(diagnosis_result())

    def test_paired_cli_projects_the_exact_facade_result(self) -> None:
        result = paired_result(Health.PARTIAL)

        class FakeApplication:
            def __init__(self, *, history):
                self.history = history

            async def run_paired(self, request):
                self.request = request
                return result

        with patch("mercury.cli.MercuryApplication", FakeApplication):
            code, output, error = invoke(
                "paired", "--config", "peer.json", "--identity", "peer",
                "--address", "127.0.0.1", "--authorized", "--json",
            )
        self.assertEqual((code, error), (EXIT_PARTIAL, ""))
        self.assertEqual(json.loads(output), result_to_wire(result))

        with patch("mercury.cli.MercuryApplication", FakeApplication):
            code, output, error = invoke(
                "paired", "--config", "peer.json", "--identity", "peer",
                "--address", "127.0.0.1", "--authorized",
            )
        self.assertEqual((code, error), (EXIT_PARTIAL, ""))
        self.assertTrue(output.startswith("Directional matrix\n"))
        self.assertIn("evidence: paired-observation", output)
    def test_version_and_model_json(self) -> None:
        code, output, error = invoke("version", "--json")
        self.assertEqual((code, error), (EXIT_OK, ""))
        payload = json.loads(output)
        self.assertEqual(payload["model_schema"], "1.1")
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

    def test_argparse_error_returns_structured_json_without_system_exit(self) -> None:
        code, output, error = invoke("--json", "plan")
        self.assertEqual((code, output), (EXIT_USAGE, ""))
        payload = json.loads(error)
        self.assertEqual(payload["error"]["category"], "input")
        self.assertIn("required", payload["error"]["message"])

        code, output, error = invoke("plan")
        self.assertEqual((code, output), (EXIT_USAGE, ""))
        self.assertTrue(error.startswith("mercury: input:"))

    def test_diagnose_requires_authorization_before_any_runner_work(self) -> None:
        code, output, error = invoke("diagnose", "--target", "127.0.0.1:443", "--json")
        self.assertEqual((code, output), (EXIT_POLICY, ""))
        self.assertEqual(json.loads(error)["error"]["category"], "policy")

    def test_diagnose_timeout_boundaries_are_input_errors_without_network(self) -> None:
        received = []

        class FakeApplication:
            def __init__(self, *, history):
                self.history = history
            async def diagnose(self, request):
                received.append(request)
                return diagnosis_result(Health.PARTIAL)

        for value, expected in (("0.1", EXIT_PARTIAL), ("30.0", EXIT_PARTIAL), ("0.099", EXIT_USAGE),
                                ("30.001", EXIT_USAGE), ("nan", EXIT_USAGE), ("inf", EXIT_USAGE), ("-inf", EXIT_USAGE)):
            with self.subTest(value=value):
                with patch("mercury.cli.MercuryApplication", FakeApplication):
                    code, _, _ = invoke("diagnose", "--target", "127.0.0.1:443", "--authorized", "--timeout", value)
                self.assertEqual(code, expected)
        self.assertEqual([item.timeout_s for item in received], [0.1, 30.0])

    def test_diagnosis_exit_contract_maps_only_health_conclusion(self) -> None:
        self.assertEqual(diagnosis_exit_code(diagnosis_result(Health.HEALTHY)), EXIT_OK)
        self.assertEqual(diagnosis_exit_code(diagnosis_result(Health.FAILED)), EXIT_FAILED)
        self.assertEqual(diagnosis_exit_code(diagnosis_result(Health.PARTIAL)), EXIT_PARTIAL)
        for result in (diagnosis_result(None), diagnosis_result(Health.PARTIAL, duplicate=True)):
            with self.subTest(result=result.conclusions):
                with self.assertRaisesRegex(RuntimeError, "diagnosis-health conclusion contract violated"):
                    diagnosis_exit_code(result)

    def test_status_json_projects_the_exact_facade_result(self) -> None:
        result = diagnosis_result(Health.PARTIAL)

        class FakeApplication:
            def __init__(self, *, history):
                self.history = history
            async def status(self):
                return result

        with patch("mercury.cli.MercuryApplication", FakeApplication):
            code, output, error = invoke("status", "--json")
        self.assertEqual((code, error), (EXIT_OK, ""))
        self.assertEqual(json.loads(output), result_to_wire(result))


class CliCancellationTests(unittest.IsolatedAsyncioTestCase):
    async def test_operator_cancellation_returns_persisted_partial_result(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "history.sqlite3"
            with HistoryStore(path) as history:
                operation = asyncio.create_task(
                    _run_synthetic(
                        Namespace(
                            steps=10,
                            delay=0.05,
                            cancel_after=None,
                        ),
                        history,
                    )
                )
                while not history.list_tasks(limit=1):
                    await asyncio.sleep(0)
                operation.cancel()
                payload, _, exit_code = await operation

                self.assertEqual(exit_code, EXIT_PARTIAL)
                self.assertEqual(payload["state"], "cancelled")
                record = history.get_task(payload["task_id"])
                assert record is not None and record.result is not None
                self.assertEqual(record.result.state.value, "cancelled")


if __name__ == "__main__":
    unittest.main()

