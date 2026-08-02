from __future__ import annotations

import asyncio
import ast
from collections import namedtuple
from datetime import datetime, timezone
import inspect
import ipaddress
import socket
import textwrap
import unittest

from mercury.history import HistoryStore
from mercury.inventory import collect_status
from mercury.models import Confidence, Direction, Disposition, EvidenceKind, Health, Observation, ProbeKind, utc_now
from mercury.policy import ScopeGrant
from mercury.profiles import BASIC_V1, DiagnosisRequest, compile_diagnosis
from mercury.diagnosis import DiagnosisRunner, classify_diagnosis
from mercury.tasks import SyntheticRunner, TaskError, TaskService


async def _compiled():
    return await compile_diagnosis(
        DiagnosisRequest(profile="custom", targets=("127.0.0.1:443",), authorized=True),
        grant=ScopeGrant(networks=()),
    )


def _observation(identifier: str, kind: EvidenceKind, disposition: Disposition, probe: ProbeKind, *, target: str = "127.0.0.1", detail=None) -> Observation:
    now = utc_now()
    return Observation(
        id=identifier, probe=probe.value, disposition=disposition, evidence_kind=kind,
        direction=Direction.OUTBOUND, target=target, started_at=now, ended_at=now,
        duration_ms=0, detail=detail or {},
    )


class HealthClassifierTests(unittest.TestCase):
    def test_explicit_failure_and_lifecycle_partial_are_distinct(self) -> None:
        compiled = asyncio.run(_compiled())
        failures = {
            ProbeKind.TCP_CONNECT: EvidenceKind.TCP_REFUSED,
            ProbeKind.TLS_HANDSHAKE: EvidenceKind.TLS_VERIFICATION_FAILED,
            ProbeKind.HTTP_EXCHANGE: EvidenceKind.EXECUTION_ERROR,
        }
        observations = tuple(_observation(
            f"failure-{index}", failures[group.probe_kind], Disposition.NEGATIVE if group.probe_kind is not ProbeKind.HTTP_EXCHANGE else Disposition.ERROR,
            group.probe_kind, detail={"planned_target": group.target, "port": group.port, "server_name": group.server_name, "http_scheme": group.http_scheme},
        ) for index, group in enumerate(compiled.required_groups))
        result = classify_diagnosis(compiled.plan, compiled.required_groups, observations)
        self.assertEqual(result.health, Health.FAILED)
        self.assertEqual(result.confidence, Confidence.HIGH)
        lifecycle = Observation(
            id="task-cancelled", probe="task_cancellation", disposition=Disposition.CANCELLED,
            evidence_kind=EvidenceKind.CANCELLED, direction=Direction.LOCAL, target="task",
            started_at=utc_now(), ended_at=utc_now(), duration_ms=0,
        )
        result = classify_diagnosis(compiled.plan, compiled.required_groups, (*observations, lifecycle))
        self.assertEqual(result.health, Health.PARTIAL)
        self.assertNotIn("Internet", result.summary)

    def test_missing_or_mixed_required_groups_are_partial(self) -> None:
        compiled = asyncio.run(_compiled())
        positive = _observation("tcp-connected", EvidenceKind.TCP_CONNECTED, Disposition.POSITIVE, ProbeKind.TCP_CONNECT,
                                detail={"planned_target": "127.0.0.1", "port": 443, "server_name": None, "http_scheme": None})
        result = classify_diagnosis(compiled.plan, compiled.required_groups, (positive,))
        self.assertEqual(result.health, Health.PARTIAL)
        self.assertEqual(result.id, "diagnosis-health")
        self.assertLessEqual(len(result.observation_ids), 16)

    def test_planning_dns_failure_with_intended_missing_layers_is_partial(self) -> None:
        async def missing(hostname, **_):
            from mercury.platform.common import CommandOutcome
            from mercury.resolver import ResolutionResult
            return ResolutionResult(hostname, (), CommandOutcome.NONZERO, "NameNotFound")
        compiled = asyncio.run(compile_diagnosis(
            DiagnosisRequest(profile="custom", targets=("missing.test:443",), authorized=True),
            grant=ScopeGrant(hostnames=("missing.test",), ports=(443,), transports=("tcp",), attested=True, networks=()), resolver=missing,
        ))
        dns = _observation("dns", EvidenceKind.DNS_FAILURE, Disposition.NEGATIVE, ProbeKind.SYSTEM_DNS,
                           target="missing.test", detail={"planned_target": "missing.test", "port": None, "server_name": None, "http_scheme": None})
        self.assertEqual(classify_diagnosis(compiled.plan, compiled.required_groups, (dns,)).health, Health.PARTIAL)

    def test_local_interface_address_and_matching_route_enable_healthy(self) -> None:
        compiled = asyncio.run(_compiled())
        now = utc_now()
        local = (
            Observation("interface", "local_snapshot", Disposition.POSITIVE, EvidenceKind.LOCAL_FACT, Direction.LOCAL, "local", now, now, 0, detail={"name": "eth0", "is_up": True}),
            Observation("address", "local_snapshot", Disposition.POSITIVE, EvidenceKind.LOCAL_FACT, Direction.LOCAL, "local", now, now, 0, detail={"interface_name": "eth0", "family": 4, "address": "192.0.2.8"}),
            Observation("route", "local_snapshot", Disposition.POSITIVE, EvidenceKind.LOCAL_FACT, Direction.LOCAL, "local", now, now, 0, detail={"interface_name": "eth0", "family": 4, "is_default": True}),
        )
        kinds = {
            ProbeKind.TCP_CONNECT: EvidenceKind.TCP_CONNECTED,
            ProbeKind.TLS_HANDSHAKE: EvidenceKind.TLS_HANDSHAKE,
            ProbeKind.HTTP_EXCHANGE: EvidenceKind.HTTP_RESPONSE,
        }
        protocol = tuple(
            _observation(
                f"group-{index}", kinds[group.probe_kind], Disposition.POSITIVE, group.probe_kind,
                detail={"planned_target": group.target, "port": group.port, "server_name": group.server_name, "http_scheme": group.http_scheme},
            ) for index, group in enumerate(compiled.required_groups)
        )
        result = classify_diagnosis(compiled.plan, compiled.required_groups, (*local, *protocol))
        self.assertEqual(result.health, Health.HEALTHY)


Snicaddr = namedtuple("Snicaddr", "family address netmask broadcast ptp")
Snicstats = namedtuple("Snicstats", "isup duplex speed mtu")


class _Psutil:
    AF_LINK = 17
    def net_if_addrs(self):
        return {"eth0": [Snicaddr(socket.AF_INET, "192.0.2.8", "255.255.255.0", None, None)]}
    def net_if_stats(self):
        return {"eth0": Snicstats(True, 0, 100, 1500)}


class DiagnosisRunnerTests(unittest.IsolatedAsyncioTestCase):
    async def test_runner_rebinds_snapshot_and_completes_optional_native_steps(self) -> None:
        async def resolve(hostname, **_):
            from mercury.platform.common import CommandOutcome
            from mercury.resolver import ResolutionResult
            return ResolutionResult(hostname, ("127.0.0.1",), CommandOutcome.SUCCESS)

        compiled = await compile_diagnosis(
            DiagnosisRequest(profile="basic", authorized=True),
            grant=ScopeGrant(
                networks=(ipaddress.ip_network("127.0.0.0/8"),), hostnames=BASIC_V1.https_hosts,
                ports=(53, 443), transports=("tcp",), attested=True,
            ), resolver=resolve,
        )
        async def snapshot():
            async def platform():
                from mercury.platform.common import PlatformRecords, RouteRecord
                return PlatformRecords(routes=(RouteRecord(4, "0.0.0.0/0", "test", interface_name="eth0"),))
            return await collect_status(
                clock=lambda: datetime(2026, 8, 1, tzinfo=timezone.utc), hostname=lambda: "host",
                system=lambda: "test", release=lambda: "test", machine=lambda: "test",
                python_version=lambda: "3.13", mercury_version=lambda: "test", psutil_module=_Psutil(),
                platform_collector=platform,
            )
        async def protocol(context, step_id):
            prepared = await context.admit(step_id)
            now = context.wall_clock()
            kind = {ProbeKind.SYSTEM_DNS: EvidenceKind.DNS_ANSWER, ProbeKind.TCP_CONNECT: EvidenceKind.TCP_CONNECTED,
                    ProbeKind.TLS_HANDSHAKE: EvidenceKind.TLS_HANDSHAKE, ProbeKind.HTTP_EXCHANGE: EvidenceKind.HTTP_RESPONSE}[prepared.step.probe_kind]
            context.record(Observation(f"{step_id}-obs", prepared.step.probe_kind.value, Disposition.POSITIVE, kind,
                Direction.OUTBOUND, prepared.address or prepared.step.target, now, now, 0, attempt=prepared.step.attempt), step_id=step_id)
            context.complete_attempt(step_id)
        native_steps = []
        async def native(context, step_id):
            native_steps.append(step_id)
            prepared = await context.admit(step_id)
            now = context.wall_clock()
            context.record(Observation(f"{step_id}-native", prepared.step.probe_kind.value, Disposition.UNAVAILABLE,
                EvidenceKind.UNSUPPORTED, Direction.OUTBOUND, prepared.address or prepared.step.target, now, now, 0,
                attempt=prepared.step.attempt), step_id=step_id)
            context.complete_attempt(step_id)
        runner = DiagnosisRunner(compiled, snapshot_collector=snapshot, protocol_dispatcher=protocol, native_dispatcher=native)
        with HistoryStore(":memory:") as history:
            service = TaskService(history, resolver=lambda _: ("127.0.0.1",))
            task_id = service.submit_diagnosis(compiled, runner)
            result = await service.wait(task_id)
        self.assertEqual(result.errors, ())
        self.assertEqual(result.progress.completed, result.progress.total)
        self.assertEqual(len(native_steps), 2)
        self.assertEqual(len([item for item in result.conclusions if item.id == "diagnosis-health"]), 1)


class LocalPrerequisiteTests(unittest.TestCase):
    def test_wrong_family_default_route_stays_partial(self) -> None:
        compiled = asyncio.run(_compiled())
        now = utc_now()
        observations = (
            Observation("interface", "local_snapshot", Disposition.POSITIVE, EvidenceKind.LOCAL_FACT, Direction.LOCAL, "local", now, now, 0, detail={"name": "eth0", "is_up": True}),
            Observation("address", "local_snapshot", Disposition.POSITIVE, EvidenceKind.LOCAL_FACT, Direction.LOCAL, "local", now, now, 0, detail={"interface_name": "eth0", "family": 4, "address": "192.0.2.8"}),
            Observation("route", "local_snapshot", Disposition.POSITIVE, EvidenceKind.LOCAL_FACT, Direction.LOCAL, "local", now, now, 0, detail={"interface_name": "eth0", "family": 6, "is_default": True}),
        )
        result = classify_diagnosis(compiled.plan, (), observations)
        self.assertEqual(result.health, Health.PARTIAL)


class LocalSnapshotBudgetTests(unittest.TestCase):
    def test_compilation_reserves_bounded_snapshot_and_diagnosis_envelope(self) -> None:
        compiled = asyncio.run(_compiled())
        local = next(step for step in compiled.plan.preview.steps if step.probe_kind is ProbeKind.LOCAL_SNAPSHOT)
        self.assertEqual(local.cost.max_observations, 8_720)
        self.assertEqual(local.cost.max_output_bytes, 12 * 1024 * 1024)
        self.assertEqual(compiled.plan.preview.limits.max_output_bytes, 24 * 1024 * 1024)
        self.assertLessEqual(compiled.plan.preview.estimate.output_bytes, compiled.plan.preview.limits.max_output_bytes)


class ClassifierPurityTests(unittest.TestCase):
    def test_classifier_has_no_io_or_provider_access(self) -> None:
        source = textwrap.dedent(inspect.getsource(classify_diagnosis))
        tree = ast.parse(source)
        names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
        self.assertTrue({"open", "socket", "ssl", "http", "subprocess", "asyncio", "sleep"}.isdisjoint(names))
        self.assertFalse(any(isinstance(node, ast.AsyncFunctionDef) for node in ast.walk(tree)))


class DiagnosisLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_only_closed_service_submission_can_create_diagnosis(self) -> None:
        compiled = await _compiled()
        with HistoryStore(":memory:") as history:
            service = TaskService(history)
            with self.assertRaises(TaskError):
                service.submit(compiled.plan, SyntheticRunner(), task_kind="diagnose")
            identifier = service.submit_diagnosis(compiled, SyntheticRunner(), task_id="diagnosis-closed")
            result = await service.wait(identifier)
        conclusions = [item for item in result.conclusions if item.id == "diagnosis-health"]
        self.assertEqual(len(conclusions), 1)
        self.assertEqual(result.task_kind, "diagnose")


if __name__ == "__main__":
    unittest.main()
