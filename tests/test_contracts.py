from __future__ import annotations

import json
import tempfile
import tomllib
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from mercury import MODEL_SCHEMA_VERSION, __version__
from mercury.codec import result_from_json, result_to_json
from mercury.history import HistoryError, HistoryStore
from mercury.models import (
    Capability,
    CapabilityState,
    Confidence,
    Direction,
    Disposition,
    EvidenceKind,
    Health,
    ModelError,
    TaskState,
)
from mercury.planner import ABSOLUTE_CEILINGS

from tests.helpers import sample_observation, sample_result


class FoundationContractTests(unittest.TestCase):
    def test_absolute_budget_contract_has_every_required_dimension(self) -> None:
        self.assertEqual(
            set(ABSOLUTE_CEILINGS.to_wire()),
            {
                "max_hosts",
                "max_ports",
                "max_attempts",
                "max_datagrams",
                "max_application_bytes",
                "max_global_rate",
                "max_target_rate",
                "max_concurrency",
                "max_duration_s",
                "max_events",
                "max_output_bytes",
            },
        )
        self.assertEqual(ABSOLUTE_CEILINGS.max_ports, 65_535)
        self.assertGreaterEqual(ABSOLUTE_CEILINGS.max_attempts, 65_535)

    def test_protocol_truth_table_round_trips(self) -> None:
        cases = (
            (EvidenceKind.DNS_ANSWER, Disposition.POSITIVE),
            (EvidenceKind.DNS_FAILURE, Disposition.NEGATIVE),
            (EvidenceKind.DNS_FAILURE, Disposition.INCONCLUSIVE),
            (EvidenceKind.DNS_FAILURE, Disposition.ERROR),
            (EvidenceKind.TCP_CONNECTED, Disposition.POSITIVE),
            (EvidenceKind.TCP_REFUSED, Disposition.NEGATIVE),
            (EvidenceKind.TCP_RESET, Disposition.NEGATIVE),
            (EvidenceKind.NETWORK_UNREACHABLE, Disposition.NEGATIVE),
            (EvidenceKind.HOST_UNREACHABLE, Disposition.NEGATIVE),
            (EvidenceKind.ICMP_UNREACHABLE, Disposition.NEGATIVE),
            (EvidenceKind.ADMIN_PROHIBITED, Disposition.NEGATIVE),
            (EvidenceKind.UDP_APPLICATION_REPLY, Disposition.POSITIVE),
            (EvidenceKind.PEER_OBSERVED_ARRIVAL, Disposition.POSITIVE),
            (EvidenceKind.TLS_HANDSHAKE, Disposition.POSITIVE),
            (EvidenceKind.HTTP_RESPONSE, Disposition.POSITIVE),
            (EvidenceKind.HTTP_RESPONSE, Disposition.NEGATIVE),
            (EvidenceKind.LOCAL_FACT, Disposition.POSITIVE),
            (EvidenceKind.TIMEOUT, Disposition.INCONCLUSIVE),
            (EvidenceKind.SILENT, Disposition.INCONCLUSIVE),
            (EvidenceKind.UNSUPPORTED, Disposition.UNAVAILABLE),
            (EvidenceKind.PERMISSION_DENIED, Disposition.UNAVAILABLE),
            (EvidenceKind.EXECUTION_ERROR, Disposition.ERROR),
            (EvidenceKind.CANCELLED, Disposition.CANCELLED),
        )
        self.assertEqual({kind for kind, _ in cases}, set(EvidenceKind))
        self.assertEqual({disposition for _, disposition in cases}, set(Disposition))
        for index, (kind, disposition) in enumerate(cases, 1):
            with self.subTest(kind=kind):
                observation = sample_observation(
                    observation_id=f"obs-{index}",
                    kind=kind,
                    disposition=disposition,
                )
                result = sample_result(
                    task_id=f"task-{index}", observation=observation
                )
                restored = result_from_json(result_to_json(result))
                self.assertEqual(restored.observations[0].evidence_kind, kind)
                self.assertEqual(restored.observations[0].disposition, disposition)

    def test_every_confidence_and_health_value_round_trips(self) -> None:
        for enum_type, field in (
            (Confidence, "confidence"),
            (Health, "health"),
        ):
            for value in enum_type:
                with self.subTest(field=field, value=value):
                    result = sample_result()
                    conclusion = replace(
                        result.conclusions[0],
                        **{field: value},
                    )
                    restored = result_from_json(
                        result_to_json(
                            replace(result, conclusions=(conclusion,))
                        )
                    )
                    self.assertEqual(
                        getattr(restored.conclusions[0], field),
                        value,
                    )

    def test_every_direction_and_terminal_task_state_round_trips(self) -> None:
        for direction in Direction:
            with self.subTest(direction=direction):
                result = sample_result()
                observation = replace(
                    result.observations[0],
                    direction=direction,
                )
                restored = result_from_json(
                    result_to_json(
                        replace(
                            result,
                            direction=direction,
                            observations=(observation,),
                        )
                    )
                )
                self.assertEqual(restored.direction, direction)
                self.assertEqual(restored.observations[0].direction, direction)

        terminal = {
            TaskState.COMPLETED,
            TaskState.FAILED,
            TaskState.CANCELLED,
        }
        for state in terminal:
            with self.subTest(state=state):
                restored = result_from_json(
                    result_to_json(replace(sample_result(), state=state))
                )
                self.assertEqual(restored.state, state)
        for state in set(TaskState) - terminal:
            with self.subTest(nonterminal=state), self.assertRaises(ModelError):
                replace(sample_result(), state=state)

    def test_every_capability_state_round_trips(self) -> None:
        for state in CapabilityState:
            with self.subTest(state=state):
                capability = Capability(
                    name=f"fixture-{state.value}",
                    state=state,
                    source="tests",
                )
                restored = result_from_json(
                    result_to_json(
                        replace(
                            sample_result(),
                            capabilities=(capability,),
                        )
                    )
                )
                self.assertEqual(restored.capabilities[0].state, state)

    def test_silent_result_remains_inconclusive_through_history_json(self) -> None:
        observation = sample_observation(
            kind=EvidenceKind.SILENT,
            disposition=Disposition.INCONCLUSIVE,
        )
        result = sample_result(task_id="silent", observation=observation)
        created_at = datetime(2026, 7, 30, tzinfo=timezone.utc)
        lease_expires_at = created_at + timedelta(hours=1)
        with tempfile.TemporaryDirectory() as temporary:
            with HistoryStore(Path(temporary) / "history.sqlite3") as history:
                history.create_task(
                    task_id="silent",
                    task_kind="synthetic",
                    request={"profile": "udp-silence-fixture"},
                    plan={"digest": result.effective_config.policy_digest},
                    owner_id="contract-test-owner",
                    lease_expires_at=lease_expires_at,
                    created_at=created_at,
                )
                history.mark_running(
                    "silent",
                    owner_id="contract-test-owner",
                    lease_expires_at=lease_expires_at,
                    at=created_at,
                )
                history.finish_task(
                    result,
                    owner_id="contract-test-owner",
                )
                stored = history.get_task("silent")
                assert stored is not None and stored.result is not None
                wire = json.loads(result_to_json(stored.result))
        self.assertEqual(
            wire["observations"][0]["disposition"], Disposition.INCONCLUSIVE.value
        )
        self.assertNotIn("open", wire["observations"][0])
        self.assertNotIn("reachable", wire["observations"][0])

    def test_credential_key_variants_are_rejected_recursively(self) -> None:
        with HistoryStore(":memory:") as history:
            created_at = datetime(2026, 7, 30, tzinfo=timezone.utc)
            for index, key in enumerate(
                ("access_token", "bearer-token", "private.key", "pairingSecret"),
                1,
            ):
                with self.subTest(key=key), self.assertRaises(HistoryError):
                    history.create_task(
                        task_id=f"secret-{index}",
                        task_kind="fixture",
                        request={"outer": [{"inner": {key: "value"}}]},
                        plan={"digest": f"secret-{index}"},
                        owner_id="contract-test-owner",
                        lease_expires_at=created_at + timedelta(hours=1),
                        created_at=created_at,
                    )

    def test_pyproject_has_one_runtime_dependency(self) -> None:
        with Path("pyproject.toml").open("rb") as handle:
            document = tomllib.load(handle)
        dependencies = document["project"]["dependencies"]
        self.assertEqual(len(dependencies), 1)
        self.assertTrue(dependencies[0].startswith("psutil"))

    def test_package_and_document_versions_have_single_sources(self) -> None:
        with Path("pyproject.toml").open("rb") as handle:
            document = tomllib.load(handle)
        self.assertNotIn("version", document["project"])
        self.assertIn("version", document["project"]["dynamic"])
        self.assertEqual(
            document["tool"]["setuptools"]["dynamic"]["version"]["attr"],
            "mercury.__version__",
        )
        self.assertRegex(__version__, r"^\d+\.\d+\.\d+$")
        self.assertEqual(MODEL_SCHEMA_VERSION, "1.0")


if __name__ == "__main__":
    unittest.main()
