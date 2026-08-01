from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError, replace
from datetime import datetime

from mercury.codec import (
    CodecError,
    loads_document,
    result_from_json,
    result_from_wire,
    result_to_json,
    result_to_wire,
)
from mercury.models import (
    Capability,
    CapabilityState,
    Conclusion,
    Confidence,
    Direction,
    Disposition,
    EffectiveConfig,
    EvidenceKind,
    Health,
    ModelError,
    Observation,
    Progress,
    TaskResult,
    TaskState,
)

from tests.helpers import sample_observation, sample_result


class ModelTests(unittest.TestCase):
    def test_round_trip_is_stable(self) -> None:
        original = sample_result()
        encoded = result_to_json(original)
        decoded = result_from_json(encoded)
        self.assertEqual(result_to_json(decoded), encoded)
        self.assertEqual(decoded, original)
        self.assertIn('"schema_version":"1.1"', encoded)

    def test_models_are_deeply_immutable(self) -> None:
        source_observations = [sample_observation()]
        source_targets = ["offline"]
        source_errors = ["fixture"]
        baseline = sample_result()
        result = TaskResult(
            task_id=baseline.task_id,
            task_kind=baseline.task_kind,
            direction=baseline.direction,
            target=baseline.target,
            state=baseline.state,
            started_at=baseline.started_at,
            ended_at=baseline.ended_at,
            requested_config=baseline.requested_config,
            effective_config=EffectiveConfig(
                profile="synthetic-v1",
                targets=source_targets,
                authorized=False,
                policy_digest="sha256:test",
                budget={"max_attempts": 1},
            ),
            progress=baseline.progress,
            observations=source_observations,
            conclusions=baseline.conclusions,
            errors=source_errors,
        )
        source_observations.clear()
        source_targets.clear()
        source_errors.clear()
        self.assertEqual(len(result.observations), 1)
        self.assertEqual(result.effective_config.targets, ("offline",))
        self.assertEqual(result.errors, ("fixture",))
        with self.assertRaises(FrozenInstanceError):
            result.task_id = "changed"  # type: ignore[misc]
        with self.assertRaises(TypeError):
            result.requested_config["steps"] = 2  # type: ignore[index]
        with self.assertRaises(TypeError):
            result.observations[0].detail["fixture"] = False  # type: ignore[index]

    def test_protocol_kind_and_disposition_must_agree(self) -> None:
        invalid = (
            (EvidenceKind.TCP_REFUSED, Disposition.POSITIVE),
            (EvidenceKind.SILENT, Disposition.POSITIVE),
            (EvidenceKind.UDP_APPLICATION_REPLY, Disposition.INCONCLUSIVE),
            (EvidenceKind.PERMISSION_DENIED, Disposition.ERROR),
        )
        for kind, disposition in invalid:
            with self.subTest(kind=kind, disposition=disposition):
                with self.assertRaises(ModelError):
                    sample_observation(kind=kind, disposition=disposition)

    def test_silence_survives_round_trip_as_inconclusive(self) -> None:
        observation = sample_observation(
            kind=EvidenceKind.SILENT,
            disposition=Disposition.INCONCLUSIVE,
        )
        result = sample_result(observation=observation)
        decoded = result_from_json(result_to_json(result))
        self.assertEqual(
            decoded.observations[0].disposition, Disposition.INCONCLUSIVE
        )
        self.assertEqual(decoded.observations[0].evidence_kind, EvidenceKind.SILENT)

    def test_conclusion_cannot_cite_unknown_observation(self) -> None:
        result = sample_result()
        bad = Conclusion(
            id="bad",
            title="Bad",
            summary="Bad reference",
            health=result.conclusions[0].health,
            confidence=Confidence.UNKNOWN,
            observation_ids=("missing",),
        )
        with self.assertRaises(ModelError):
            type(result)(
                task_id=result.task_id,
                task_kind=result.task_kind,
                direction=result.direction,
                target=result.target,
                state=result.state,
                started_at=result.started_at,
                ended_at=result.ended_at,
                requested_config=result.requested_config,
                effective_config=result.effective_config,
                progress=result.progress,
                observations=result.observations,
                conclusions=(bad,),
            )

    def test_progress_invariants(self) -> None:
        for values in (
            (2, 1, 1),
            (1, 2, 2),
            (-1, 0, 0),
            (True, 1, 1),
            (1.0, 1, 1),
        ):
            with self.subTest(values=values), self.assertRaises(ModelError):
                Progress(admitted=values[0], completed=values[1], total=values[2])

    def test_direct_constructors_reject_string_enums_and_wrong_nested_types(self) -> None:
        observation = sample_observation()
        invalid_observation_fields = {
            "disposition": "positive",
            "evidence_kind": "local_fact",
            "direction": "local",
        }
        for field, invalid in invalid_observation_fields.items():
            values = {
                "id": observation.id,
                "probe": observation.probe,
                "disposition": observation.disposition,
                "evidence_kind": observation.evidence_kind,
                "direction": observation.direction,
                "target": observation.target,
                "started_at": observation.started_at,
                "ended_at": observation.ended_at,
                "duration_ms": observation.duration_ms,
            }
            values[field] = invalid
            with self.subTest(field=field), self.assertRaises(ModelError):
                Observation(**values)

        with self.assertRaises(ModelError):
            Capability(
                name="fixture",
                state="available",  # type: ignore[arg-type]
                source="tests",
            )
        with self.assertRaises(ModelError):
            EffectiveConfig(
                profile="fixture",
                targets=("offline",),
                authorized=1,  # type: ignore[arg-type]
                policy_digest="digest",
                budget={},
            )
        with self.assertRaises(ModelError):
            Conclusion(
                id="fixture",
                title="Fixture",
                summary="Fixture",
                health="healthy",  # type: ignore[arg-type]
                confidence=Confidence.HIGH,
                observation_ids=("obs",),
            )
        with self.assertRaises(ModelError):
            Conclusion(
                id="fixture",
                title="Fixture",
                summary="Fixture",
                health=Health.HEALTHY,
                confidence="high",  # type: ignore[arg-type]
                observation_ids=("obs",),
            )

    def test_direct_result_constructor_rejects_mutable_or_wrong_members(self) -> None:
        result = sample_result()
        with self.assertRaises(ModelError):
            TaskResult(
                task_id=result.task_id,
                task_kind=result.task_kind,
                direction="local",  # type: ignore[arg-type]
                target=result.target,
                state=TaskState.COMPLETED,
                started_at=result.started_at,
                ended_at=result.ended_at,
                requested_config=result.requested_config,
                effective_config=result.effective_config,
                progress=result.progress,
            )
        with self.assertRaises(ModelError):
            TaskResult(
                task_id=result.task_id,
                task_kind=result.task_kind,
                direction=Direction.LOCAL,
                target=result.target,
                state=TaskState.COMPLETED,
                started_at=result.started_at,
                ended_at=result.ended_at,
                requested_config=result.requested_config,
                effective_config=result.effective_config,
                progress=result.progress,
                observations=("not-an-observation",),  # type: ignore[arg-type]
            )
        invalid_members = (
            ("state", "completed"),
            ("effective_config", {}),
            ("progress", {}),
            ("conclusions", ("not-a-conclusion",)),
            ("capabilities", ("not-a-capability",)),
            ("errors", "not-an-error-sequence"),
        )
        for field, invalid in invalid_members:
            with self.subTest(field=field), self.assertRaises(ModelError):
                replace(result, **{field: invalid})

    def test_naive_timestamp_is_rejected(self) -> None:
        observation = sample_observation()
        with self.assertRaises(ModelError):
            type(observation)(
                id=observation.id,
                probe=observation.probe,
                disposition=observation.disposition,
                evidence_kind=observation.evidence_kind,
                direction=observation.direction,
                target=observation.target,
                started_at=datetime.now(),
                ended_at=observation.ended_at,
                duration_ms=observation.duration_ms,
            )

    def test_one_attempt_may_produce_multiple_correlated_observations(self) -> None:
        result = sample_result()
        second = sample_observation(observation_id="obs-2")
        expanded = type(result)(
            task_id=result.task_id,
            task_kind=result.task_kind,
            direction=result.direction,
            target=result.target,
            state=result.state,
            started_at=result.started_at,
            ended_at=result.ended_at,
            requested_config=result.requested_config,
            effective_config=result.effective_config,
            progress=Progress(admitted=1, completed=1, total=1),
            observations=(result.observations[0], second),
            conclusions=result.conclusions,
        )
        self.assertEqual(len(expanded.observations), 2)
        self.assertEqual(expanded.progress.completed, 1)

    def test_result_collection_count_limits_reject_one_past_boundary(self) -> None:
        result = sample_result()
        cases = (
            ("observations", result.observations[0], 100_000),
            ("conclusions", result.conclusions[0], 100_000),
            (
                "capabilities",
                Capability(
                    name="fixture",
                    state=CapabilityState.AVAILABLE,
                    source="tests",
                ),
                4_096,
            ),
            ("errors", "fixture", 256),
        )
        for field, item, maximum in cases:
            with self.subTest(field=field), self.assertRaisesRegex(
                ModelError,
                "too many",
            ):
                replace(result, **{field: (item,) * (maximum + 1)})


class CodecTests(unittest.TestCase):
    def test_duplicate_key_is_rejected(self) -> None:
        with self.assertRaisesRegex(CodecError, "duplicate"):
            result_from_json('{"schema_version":"1.0","schema_version":"1.0"}')

    def test_unknown_top_level_field_is_rejected(self) -> None:
        encoded = result_to_json(sample_result())
        document = encoded[:-1] + ',"surprise":true}'
        with self.assertRaisesRegex(CodecError, "unknown"):
            result_from_json(document)

    def test_nonfinite_number_is_rejected(self) -> None:
        encoded = result_to_json(sample_result())
        document = encoded.replace('"duration_ms":12', '"duration_ms":NaN')
        with self.assertRaisesRegex(CodecError, "non-finite"):
                result_from_json(document)

    def test_overflowing_number_is_rejected_as_codec_error(self) -> None:
        wire = result_to_wire(sample_result())
        wire["observations"][0]["duration_ms"] = 10**1000
        with self.assertRaisesRegex(CodecError, "numeric range"):
            result_from_wire(wire)

    def test_oversized_json_integer_is_rejected_as_codec_error(self) -> None:
        with self.assertRaisesRegex(CodecError, "decimal digits"):
            loads_document('{"value":' + ("9" * 1_001) + "}")

    def test_unsupported_schema_is_rejected(self) -> None:
        encoded = result_to_json(sample_result()).replace(
            '"schema_version":"1.1"', '"schema_version":"2.0"'
        )
        with self.assertRaisesRegex(CodecError, "unsupported schema"):
            result_from_json(encoded)

    def test_schema_10_and_11_round_trip(self) -> None:
        for version in ("1.0", "1.1"):
            with self.subTest(version=version):
                original = replace(sample_result(), schema_version=version)
                encoded = result_to_json(original)
                restored = result_from_json(encoded)
                self.assertEqual(restored.schema_version, version)
                self.assertEqual(result_to_json(restored), encoded)

    def test_unknown_schema_minor_is_rejected(self) -> None:
        for version in ("1.2", "1.7", "2.0"):
            with self.subTest(version=version), self.assertRaisesRegex(
                CodecError, "unsupported schema"
            ):
                result_from_json(
                    result_to_json(sample_result()).replace(
                        '"schema_version":"1.1"', f'"schema_version":"{version}"'
                    )
                )

    def test_schema_10_rejects_schema_11_evidence(self) -> None:
        observation = sample_observation(
            kind=EvidenceKind.NATIVE_PING_REPLY,
            disposition=Disposition.POSITIVE,
        )
        with self.assertRaisesRegex(ModelError, "not valid for schema 1.0"):
            replace(sample_result(observation=observation), schema_version="1.0")


if __name__ == "__main__":
    unittest.main()
