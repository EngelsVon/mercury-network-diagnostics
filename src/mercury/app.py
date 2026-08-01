"""The small shared status/diagnosis application boundary."""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Callable
from datetime import datetime, timedelta, timezone

from .diagnosis import DiagnosisRunner
from .history import HistoryStore
from .inventory import collect_status
from .models import TaskResult
from .peer import PeerAgent, PeerConfig
from .policy import PolicyError, ScopeGrant, parse_target
from .profiles import BASIC_V1, CHINA_V1, DiagnosisRequest, compile_diagnosis
from .tasks import TaskService


def _default_grant(request: DiagnosisRequest) -> ScopeGrant:
    """Build the narrow declared scope represented by one CLI request."""
    if request.profile == "custom":
        endpoints = tuple(item.rsplit(":", 1)[0].strip("[]") for item in request.targets)
        ports = tuple(int(item.rsplit(":", 1)[1]) for item in request.targets)
    else:
        profile = BASIC_V1 if request.profile == "basic" else CHINA_V1
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
    ) -> None:
        self.history = history
        self.status_collector = status_collector
        self.grant_factory = grant_factory
        self.compiler = compiler
        self.runner_factory = runner_factory
        self.service_factory = service_factory
        self.peer_agent_factory = peer_agent_factory
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

    async def start_agent(self, config: PeerConfig) -> PeerAgent:
        """Start the application-owned peer-control listener once."""
        if self._peer_agent is not None:
            raise RuntimeError("peer agent is already running")
        agent = self.peer_agent_factory(config)
        if not isinstance(agent, PeerAgent):
            raise RuntimeError("peer agent factory returned an invalid agent")
        await agent.start()
        self._peer_agent = agent
        return agent

    async def stop_agent(self) -> None:
        """Stop the application-owned listener without exposing transport to the CLI."""
        if self._peer_agent is None:
            return
        agent, self._peer_agent = self._peer_agent, None
        await agent.stop()


__all__ = ["MercuryApplication"]
