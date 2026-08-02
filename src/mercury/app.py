"""The small shared status/diagnosis application boundary."""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .diagnosis import DiagnosisRunner
from .discovery import (
    DiscoveryRequest, collect_passive_discovery, default_discovery_grant,
    run_discovery, run_internal_mapping,
)
from .history import HistoryStore
from .inventory import collect_status
from .models import TaskResult
from .peer import PeerAgent, PeerClient, PeerConfig, load_peer_config
from .planner import InternalMappingRequest, ProbePlan, authorize_internal_mapping
from .paired import (
    AuthenticatedCoverageRunner, AuthenticatedPairedRunner, ConfiguredCoverageExecutor, ConfiguredPairedExecutor,
    CoverageAssessmentRequest, CoverageLeaseRegistry, PairedError, PairedPeerService, PairedRequest,
)
from .policy import PolicyError, ScopeGrant, parse_target
from .profiles import BASIC_V1, DiagnosisRequest, compile_diagnosis
from .tasks import TaskService
from .trace import TraceRequest, default_trace_grant, run_trace
from .reports import compare_records, report_wire


def _default_grant(request: DiagnosisRequest) -> ScopeGrant:
    """Build the narrow declared scope represented by one CLI request."""
    if request.profile == "custom":
        endpoints = tuple(item.rsplit(":", 1)[0].strip("[]") for item in request.targets)
        ports = tuple(int(item.rsplit(":", 1)[1]) for item in request.targets)
    else:
        profile = BASIC_V1
        endpoints = (profile.raw_tcp_target.host, *profile.https_hosts)
        ports = (profile.raw_tcp_target.port, 443)
    networks = []
    names = []
    for value in endpoints:
        target = parse_target(value)
        if target.address is not None:
            networks.append(ipaddress.ip_network(
                f"{target.address}/{32 if target.address.version == 4 else 128}"
            ))
        elif target.hostname is not None:
            names.append(target.hostname)
    return ScopeGrant(
        networks=tuple(networks), hostnames=tuple(names), ports=ports,
        transports=("tcp",), attested=request.authorized,
        purpose="authorized local diagnosis",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=15),
    )


class MercuryApplication:
    """One facade reused by CLI and future presentation adapters."""

    def __init__(
        self,
        *,
        history: HistoryStore,
        status_collector: Callable[..., object] = collect_status,
        grant_factory: Callable[[DiagnosisRequest], ScopeGrant] = _default_grant,
        compiler=compile_diagnosis,
        runner_factory=DiagnosisRunner,
        service_factory=TaskService,
        peer_agent_factory=PeerAgent,
        paired_executor: Callable[[PairedRequest], Awaitable[TaskResult]] | None = None,
        paired_runner: AuthenticatedPairedRunner | None = None,
        coverage_runner: AuthenticatedCoverageRunner | None = None,
        paired_peer_service: PairedPeerService | None = None,
        passive_discovery_collector=collect_passive_discovery,
        discovery_executor=run_discovery,
        discovery_grant_factory=default_discovery_grant,
        trace_executor=run_trace,
        trace_grant_factory=default_trace_grant,
    ) -> None:
        self.history = history
        self.status_collector = status_collector
        self.grant_factory = grant_factory
        self.compiler = compiler
        self.runner_factory = runner_factory
        self.service_factory = service_factory
        self.peer_agent_factory = peer_agent_factory
        self.paired_executor = paired_executor
        self.paired_runner = paired_runner
        self.coverage_runner = coverage_runner
        self.paired_peer_service = paired_peer_service
        self.passive_discovery_collector = passive_discovery_collector
        self.discovery_executor = discovery_executor
        self.discovery_grant_factory = discovery_grant_factory
        self.trace_executor = trace_executor
        self.trace_grant_factory = trace_grant_factory
        self._peer_agent: PeerAgent | None = None

    async def status(self) -> TaskResult:
        result = await self.status_collector()
        if not isinstance(result, TaskResult):
            raise RuntimeError("status collector returned an invalid result")
        return result

    async def diagnose(self, request: DiagnosisRequest) -> TaskResult:
        if not request.authorized:
            raise PolicyError("active diagnosis requires explicit authorization attestation")
        compiled = await self.compiler(request, grant=self.grant_factory(request))
        service = self.service_factory(self.history)
        task_id = service.submit_diagnosis(
            compiled,
            self.runner_factory(compiled),
            requested_config={
                "profile": compiled.effective_profile,
                "targets": compiled.request.targets,
                "timeout_s": compiled.request.timeout_s,
                "network_io": True,
                "purpose": "authorized local diagnosis",
            },
        )
        try:
            result = await service.wait(task_id)
        except asyncio.CancelledError:
            service.cancel(task_id)
            result = await asyncio.shield(service.wait(task_id))
        if not isinstance(result, TaskResult):
            raise RuntimeError("diagnosis service returned an invalid result")
        return result

    async def discover_passive(self) -> TaskResult:
        """Collect local candidates without transmitting a network probe."""
        result = await self.passive_discovery_collector()
        if type(result) is not TaskResult:
            raise RuntimeError("passive discovery collector returned an invalid result")
        return result

    def authorize_mapping(self, request: InternalMappingRequest) -> ProbePlan:
        """Compile the operator's private ranges through the shared service boundary."""
        if type(request) is not InternalMappingRequest or not request.authorized:
            raise PolicyError("internal mapping requires explicit authorization attestation")
        return authorize_internal_mapping(request)

    async def map_internal(self, request: InternalMappingRequest) -> TaskResult:
        if type(request) is not InternalMappingRequest or not request.authorized:
            raise PolicyError("internal mapping requires explicit authorization attestation")
        return await run_internal_mapping(
            request, history=self.history, service_factory=self.service_factory,
        )

    async def discover(self, request: DiscoveryRequest) -> TaskResult:
        """Run the fixed TCP-only discovery service through this shared facade."""
        if type(request) is not DiscoveryRequest or not request.authorized:
            raise PolicyError("active discovery requires explicit authorization attestation")
        result = await self.discovery_executor(
            request, history=self.history, grant=self.discovery_grant_factory(request),
        )
        if type(result) is not TaskResult:
            raise RuntimeError("discovery executor returned an invalid result")
        return result

    async def trace(self, request: TraceRequest) -> TaskResult:
        """Run an authorized, finite native route trace through the facade."""
        if type(request) is not TraceRequest or not request.authorized:
            raise PolicyError("native trace requires explicit authorization attestation")
        result = await self.trace_executor(
            request, history=self.history, grant=self.trace_grant_factory(request),
        )
        if type(result) is not TaskResult:
            raise RuntimeError("trace executor returned an invalid result")
        return result

    def history_list(self, *, limit: int = 50):
        return self.history.list_tasks(limit=limit)

    def history_show(self, task_id: str):
        return self.history.get_task(task_id)

    def compare_history(self, left_task_id: str, right_task_id: str) -> dict[str, object]:
        left, right = self.history.get_task(left_task_id), self.history.get_task(right_task_id)
        if left is None or right is None:
            raise PolicyError("history task was not found")
        return compare_records(left, right)

    def report_history(self, task_id: str, *, retain_sensitive: bool = False) -> dict[str, object]:
        record = self.history.get_task(task_id)
        if record is None:
            raise PolicyError("history task was not found")
        return report_wire(record, retain_sensitive=retain_sensitive)

    async def start_agent(self, config: PeerConfig) -> PeerAgent:
        """Start the application-owned peer-control listener once."""
        if self._peer_agent is not None:
            raise RuntimeError("peer agent is already running")
        if self.paired_peer_service is None:
            agent = self.peer_agent_factory(config)
        else:
            agent = self.peer_agent_factory(config, handlers=self.paired_peer_service.handlers)
        if not isinstance(agent, PeerAgent):
            raise RuntimeError("peer agent factory returned an invalid agent")
        await agent.start()
        self._peer_agent = agent
        return agent

    async def start_agent_from_file(
        self, path: Path, *, unsafe_development: bool = False,
    ) -> PeerAgent:
        """Load operator-provisioned paths and start the shared control agent."""
        config = load_peer_config(path, unsafe_development=unsafe_development)
        if self.paired_peer_service is None and (config.paired_enabled or config.coverage_enabled):
            async def unavailable_role(_role: str, _correlation: str) -> TaskResult:
                raise PairedError("paired-v1 is not configured on this coverage receiver")
            self.paired_peer_service = PairedPeerService(
                ConfiguredPairedExecutor(config, self.history) if config.paired_enabled else unavailable_role,
                coverage_registry=CoverageLeaseRegistry(config) if config.coverage_enabled else None,
                coverage_sender_executor=ConfiguredCoverageExecutor(config, self.history) if config.coverage_enabled else None,
            )
        return await self.start_agent(config)

    async def stop_agent(self) -> None:
        """Stop the application-owned listener without exposing transport to the CLI."""
        if self._peer_agent is None:
            return
        agent, self._peer_agent = self._peer_agent, None
        await agent.stop()

    async def run_paired(self, request: PairedRequest) -> TaskResult:
        """Dispatch the closed paired profile through the application boundary."""
        if type(request) is not PairedRequest or not request.authorized:
            raise PolicyError("paired diagnostics require explicit authorization attestation")
        if self.paired_runner is not None:
            result = await self.paired_runner.run(request)
        elif self.paired_executor is not None:
            result = await self.paired_executor(request)
        else:
            config = load_peer_config(
                Path(request.config_path), unsafe_development=request.unsafe_development,
            )
            if not config.paired_enabled:
                raise PolicyError("paired configuration does not define the fixed pair profile")
            if request.identity != config.identity or request.address != config.peer_addresses[0]:
                raise PolicyError("paired request does not match its operator-provisioned peer configuration")
            assert config.paired_timeout_s is not None
            if request.timeout_s > config.paired_timeout_s:
                raise PolicyError("paired request timeout exceeds configured finite profile")
            runner = AuthenticatedPairedRunner(
                PeerClient(config),
                ConfiguredPairedExecutor(config, self.history),
            )
            result = await runner.run(request)
        if type(result) is not TaskResult:
            raise RuntimeError("paired executor returned an invalid result")
        return result

    async def run_coverage(self, request: CoverageAssessmentRequest) -> TaskResult:
        """Dispatch the fixed two-endpoint coverage matrix through the facade."""
        if type(request) is not CoverageAssessmentRequest or not request.authorized:
            raise PolicyError("coverage assessment requires explicit authorization attestation")
        if self.coverage_runner is not None:
            result = await self.coverage_runner.run(request)
        else:
            config = load_peer_config(Path(request.config_path), unsafe_development=request.unsafe_development)
            if not config.coverage_enabled:
                raise PolicyError("peer configuration does not define coverage receivers")
            if request.identity != config.identity or request.address != config.peer_addresses[0]:
                raise PolicyError("coverage request does not match its operator-provisioned peer configuration")
            result = await AuthenticatedCoverageRunner(PeerClient(config), config, self.history).run(request)
        if type(result) is not TaskResult:
            raise RuntimeError("coverage runner returned an invalid result")
        return result


__all__ = ["MercuryApplication"]
