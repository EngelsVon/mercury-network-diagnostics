from __future__ import annotations

import json
import tempfile
import tomllib
import unittest
from pathlib import Path

from mercury import MODEL_SCHEMA_VERSION, __version__
from mercury.codec import result_from_json, result_to_json
from mercury.history import HistoryError, HistoryStore
from mercury.models import Disposition, EvidenceKind
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
            (EvidenceKind.TCP_CONNECTED, Disposition.POSITIVE),
            (EvidenceKind.TCP_REFUSED, Disposition.NEGATIVE),
            (EvidenceKind.TCP_RESET, Disposition.NEGATIVE),
            (EvidenceKind.NETWORK_UNREACHABLE, Disposition.NEGATIVE),
            (EvidenceKind.HOST_UNREACHABLE, Disposition.NEGATIVE),
            (EvidenceKind.ICMP_UNREACHABLE, Disposition.NEGATIVE),
            (EvidenceKind.UDP_APPLICATION_REPLY, Disposition.POSITIVE),
            (EvidenceKind.PEER_OBSERVED_ARRIVAL, Disposition.POSITIVE),
            (EvidenceKind.TIMEOUT, Disposition.INCONCLUSIVE),
            (EvidenceKind.SILENT, Disposition.INCONCLUSIVE),
            (EvidenceKind.UNSUPPORTED, Disposition.UNAVAILABLE),
            (EvidenceKind.PERMISSION_DENIED, Disposition.UNAVAILABLE),
            (EvidenceKind.EXECUTION_ERROR, Disposition.ERROR),
            (EvidenceKind.CANCELLED, Disposition.CANCELLED),
        )
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

    def test_silent_result_remains_inconclusive_through_history_json(self) -> None:
        observation = sample_observation(
            kind=EvidenceKind.SILENT,
            disposition=Disposition.INCONCLUSIVE,
        )
        result = sample_result(task_id="silent", observation=observation)
        with tempfile.TemporaryDirectory() as temporary:
            with HistoryStore(Path(temporary) / "history.sqlite3") as history:
                history.create_task(
                    task_id="silent",
                    task_kind="synthetic",
                    request={"profile": "udp-silence-fixture"},
                    plan={"digest": "fixture"},
                )
                history.mark_running("silent")
                history.finish_task(result)
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
            for index, key in enumerate(
                ("access_token", "bearer-token", "private.key", "pairingSecret"),
                1,
            ):
                with self.subTest(key=key), self.assertRaises(HistoryError):
                    history.create_task(
                        task_id=f"secret-{index}",
                        task_kind="fixture",
                        request={"outer": [{"inner": {key: "value"}}]},
                        plan={},
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
