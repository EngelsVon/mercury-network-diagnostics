"""Immutable diagnosis profile data and strict custom endpoint parsing.

Profiles are finite recommendations, not a remote catalogue or an implicit
authorization grant.  Compilation into executable sparse steps happens only
after the caller supplies the corresponding attested scope.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, replace

from .models import ProbeKind
from .planner import (
    ProbePlan,
    ProbeSpec,
    StepCost,
    Transport,
    DEFAULT_LIMITS,
    authorize_plan,
    preview_probe_plan,
)
from .policy import PolicyError, TargetKind, parse_target
from .policy import ScopeGrant
from .resolver import ResolutionResult, resolve_addresses


class ProfileError(ValueError):
    """A diagnosis request or custom endpoint is malformed."""


@dataclass(frozen=True, slots=True)
class DiagnosisRequest:
    profile: str = "basic"
    targets: tuple[str, ...] = ()
    timeout_s: float = 3.0
    authorized: bool = False

    def __post_init__(self) -> None:
        if type(self.profile) is not str or self.profile not in {"basic", "china", "custom"}:
            raise ProfileError("profile must be basic, china, or custom")
        if not isinstance(self.targets, (tuple, list)) or len(self.targets) > 256:
            raise ProfileError("targets must contain at most 256 values")
        targets = tuple(self.targets)
        if any(type(value) is not str for value in targets):
            raise ProfileError("targets must contain only text")
        if type(self.authorized) is not bool:
            raise ProfileError("authorized must be a boolean")
        if type(self.timeout_s) not in (int, float) or not math.isfinite(float(self.timeout_s)):
            raise ProfileError("timeout_s must be finite")
        timeout = float(self.timeout_s)
        if not 0.1 <= timeout <= 30.0:
            raise ProfileError("timeout_s must be within 0.1..30")
        if self.profile == "custom" and not targets:
            raise ProfileError("custom profile requires at least one target")
        if self.profile != "custom" and targets:
            raise ProfileError("built-in profiles do not accept custom targets")
        object.__setattr__(self, "targets", targets)
        object.__setattr__(self, "timeout_s", timeout)


@dataclass(frozen=True, slots=True)
class CustomTarget:
    host: str
    port: int

    def __post_init__(self) -> None:
        target = parse_target(self.host)
        if target.kind is TargetKind.NETWORK:
            raise ProfileError("custom target host cannot be a network")
        if type(self.port) is not int or not 1 <= self.port <= 65_535:
            raise ProfileError("custom target port must be within 1..65535")
        object.__setattr__(self, "host", target.canonical)

    @property
    def canonical(self) -> str:
        return f"[{self.host}]:{self.port}" if ":" in self.host else f"{self.host}:{self.port}"


@dataclass(frozen=True, slots=True)
class ProfileDefinition:
    name: str
    raw_tcp_target: CustomTarget
    https_hosts: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.name) is not str or not self.name.endswith("-v1"):
            raise ProfileError("profile definition must have a versioned name")
        if type(self.raw_tcp_target) is not CustomTarget:
            raise ProfileError("profile raw TCP target is invalid")
        if not isinstance(self.https_hosts, tuple) or len(self.https_hosts) != 3:
            raise ProfileError("profile must contain exactly three HTTPS hosts")
        canonical = tuple(parse_target(host).canonical for host in self.https_hosts)
        if any(parse_target(host).kind is not TargetKind.HOSTNAME for host in canonical):
            raise ProfileError("profile HTTPS targets must be hostnames")
        object.__setattr__(self, "https_hosts", canonical)


BASIC_V1 = ProfileDefinition(
    "basic-v1", CustomTarget("1.1.1.1", 53),
    ("www.cloudflare.com", "www.microsoft.com", "www.apple.com"),
)
CHINA_V1 = ProfileDefinition(
    "china-v1", CustomTarget("223.5.5.5", 53),
    ("www.baidu.com", "www.qq.com", "www.aliyun.com"),
)
_PROFILES = {"basic": BASIC_V1, "china": CHINA_V1}
_PORT_RE = re.compile(r"^[1-9][0-9]{0,4}$")


@dataclass(frozen=True, slots=True)
class ProbeGroupKey:
    probe_kind: ProbeKind
    target: str
    port: int | None = None
    server_name: str | None = None
    http_scheme: str | None = None


@dataclass(frozen=True, slots=True)
class CompiledDiagnosis:
    request: DiagnosisRequest
    effective_profile: str
    canonical_targets: tuple[str, ...]
    plan: ProbePlan
    required_groups: tuple[ProbeGroupKey, ...]

    def __post_init__(self) -> None:
        if type(self.request) is not DiagnosisRequest or type(self.plan) is not ProbePlan:
            raise ProfileError("compiled diagnosis has invalid request or plan")
        if any(type(item) is not ProbeGroupKey for item in self.required_groups):
            raise ProfileError("compiled diagnosis groups must be ProbeGroupKey values")
        if self.request.profile == "custom":
            expected = tuple(item.canonical for item in canonical_custom_targets(self.request.targets))
            if self.canonical_targets != expected:
                raise ProfileError("compiled diagnosis targets do not match request")


def _cost(*, packets: int = 1, observations: int = 1) -> StepCost:
    return StepCost(1, 0, 0, logical_packets=packets, max_observations=observations, max_output_bytes=8_192)


def _local_snapshot_cost() -> StepCost:
    """Reserve the bounded 02-01 snapshot before passive collection begins."""
    return StepCost(
        1, 0, 0, logical_packets=0, max_observations=8_720,
        max_capabilities=32, max_conclusions=16, max_errors=16,
        max_output_bytes=12 * 1024 * 1024,
    )


async def compile_diagnosis(
    request: DiagnosisRequest,
    *,
    grant: ScopeGrant,
    hard_deadline: float = 30.0,
    resolver=resolve_addresses,
) -> CompiledDiagnosis:
    """Compile only finite, already-authorized layered operations.

    The returned ``ProbePlan`` remains the sole executable authority.  This
    companion preserves the stable profile/endpoint group manifest used later
    by the closed health classifier.
    """
    if type(request) is not DiagnosisRequest or type(grant) is not ScopeGrant:
        raise ProfileError("request and grant must be canonical values")
    if not request.authorized:
        raise ProfileError("active diagnosis requires explicit authorization")
    endpoints: tuple[CustomTarget, ...]
    definition = profile_definition(request)
    if definition is None:
        endpoints = canonical_custom_targets(request.targets)
        profile = "custom-v1"
    else:
        endpoints = (definition.raw_tcp_target,) + tuple(CustomTarget(host, 443) for host in definition.https_hosts)
        profile = definition.name
    specs: list[ProbeSpec] = [ProbeSpec(
        ProbeKind.LOCAL_SNAPSHOT, "local", cost=_local_snapshot_cost(),
    )]
    groups: list[ProbeGroupKey] = []
    for endpoint in endpoints:
        target = parse_target(endpoint.host)
        addresses: tuple[str, ...]
        if target.address is not None:
            addresses = (target.canonical,)
        else:
            resolution: ResolutionResult = await resolver(
                target.canonical, operation_timeout=request.timeout_s, hard_deadline=hard_deadline
            )
            if not resolution.addresses:
                specs.append(ProbeSpec(ProbeKind.SYSTEM_DNS, target.canonical, timeout_s=request.timeout_s, cost=_cost()))
                groups.append(ProbeGroupKey(ProbeKind.SYSTEM_DNS, target.canonical))
                continue
            addresses = resolution.addresses
            specs.append(ProbeSpec(ProbeKind.SYSTEM_DNS, target.canonical, timeout_s=request.timeout_s, cost=_cost()))
            groups.append(ProbeGroupKey(ProbeKind.SYSTEM_DNS, target.canonical))
        for slot, address in enumerate(addresses):
            resolution = (
                {"source_hostname": target.canonical, "resolution_slot": slot}
                if target.hostname is not None else {}
            )
            kwargs = {"target": target.canonical, "address": address, "port": endpoint.port, "transport": Transport.TCP, "timeout_s": request.timeout_s, "cost": _cost(), **resolution}
            specs.append(ProbeSpec(ProbeKind.TCP_CONNECT, **kwargs))
        groups.append(ProbeGroupKey(ProbeKind.TCP_CONNECT, target.canonical, endpoint.port))
        if endpoint.port == 443:
            for slot, address in enumerate(addresses):
                resolution = (
                    {"source_hostname": target.canonical, "resolution_slot": slot}
                    if target.hostname is not None else {}
                )
                common = {"target": target.canonical, "address": address, "port": 443, "transport": Transport.TCP, "server_name": target.canonical, "timeout_s": request.timeout_s, "cost": _cost(), **resolution}
                specs.append(ProbeSpec(ProbeKind.TLS_HANDSHAKE, **common))
                specs.append(ProbeSpec(ProbeKind.HTTP_EXCHANGE, http_scheme="https", **common))
            groups.extend((ProbeGroupKey(ProbeKind.TLS_HANDSHAKE, target.canonical, 443, target.canonical), ProbeGroupKey(ProbeKind.HTTP_EXCHANGE, target.canonical, 443, target.canonical, "https")))
        elif endpoint.port == 80:
            for slot, address in enumerate(addresses):
                resolution = (
                    {"source_hostname": target.canonical, "resolution_slot": slot}
                    if target.hostname is not None else {}
                )
                specs.append(ProbeSpec(ProbeKind.HTTP_EXCHANGE, target=target.canonical, address=address, port=80, transport=Transport.TCP, server_name=target.canonical, http_scheme="http", timeout_s=request.timeout_s, cost=_cost(), **resolution))
            groups.append(ProbeGroupKey(ProbeKind.HTTP_EXCHANGE, target.canonical, 80, target.canonical, "http"))
    if definition is not None:
        raw = parse_target(definition.raw_tcp_target.host)
        specs.extend((
            ProbeSpec(ProbeKind.NATIVE_PING, raw.canonical, address=raw.canonical,
                      timeout_s=request.timeout_s, required=False, cost=_cost()),
            ProbeSpec(ProbeKind.NATIVE_PATH, raw.canonical, address=raw.canonical,
                      max_hops=8, timeout_s=request.timeout_s, required=False,
                      cost=_cost(packets=24, observations=9)),
        ))
    diagnosis_limits = replace(DEFAULT_LIMITS, max_output_bytes=24 * 1024 * 1024)
    preview = preview_probe_plan(
        specs=tuple(specs), grant=grant, profile=profile, limits=diagnosis_limits,
    )
    return CompiledDiagnosis(request, profile, tuple(item.canonical for item in endpoints), authorize_plan(preview), tuple(groups))


def parse_custom_target(value: str) -> CustomTarget:
    """Parse only ``HOST:PORT`` or bracketed IPv6 endpoint syntax."""
    if type(value) is not str or not value or len(value) > 1_024:
        raise ProfileError("custom target must be bounded non-empty text")
    if value != value.strip() or any(character.isspace() for character in value):
        raise ProfileError("custom target cannot contain whitespace")
    if any(token in value for token in ("://", "/", ",", "*")):
        raise ProfileError("custom target must be one host and decimal port")
    host: str
    port_text: str
    if value.startswith("["):
        close = value.find("]")
        if close < 2 or close + 1 >= len(value) or value[close + 1] != ":":
            raise ProfileError("bracketed IPv6 target requires :port")
        host, port_text = value[1:close], value[close + 2:]
    else:
        if value.count(":") != 1:
            raise ProfileError("IPv6 targets must use brackets")
        host, port_text = value.split(":", 1)
    if not host or not _PORT_RE.fullmatch(port_text):
        raise ProfileError("custom target port must be decimal within 1..65535")
    try:
        return CustomTarget(host, int(port_text))
    except (PolicyError, ValueError) as exc:
        raise ProfileError("custom target host is invalid") from exc


def canonical_custom_targets(values: tuple[str, ...] | list[str]) -> tuple[CustomTarget, ...]:
    if not isinstance(values, (tuple, list)) or not values or len(values) > 256:
        raise ProfileError("custom targets must contain 1..256 values")
    targets = {parse_custom_target(value).canonical: parse_custom_target(value) for value in values}
    return tuple(targets[key] for key in sorted(targets))


def profile_definition(request: DiagnosisRequest) -> ProfileDefinition | None:
    """Return the immutable built-in profile selected by a valid request."""
    if type(request) is not DiagnosisRequest:
        raise ProfileError("request must be DiagnosisRequest")
    return _PROFILES.get(request.profile)


__all__ = [
    "BASIC_V1", "CHINA_V1", "CompiledDiagnosis", "CustomTarget", "DiagnosisRequest",
    "ProfileDefinition", "ProfileError", "canonical_custom_targets",
    "parse_custom_target", "profile_definition", "ProbeGroupKey", "compile_diagnosis",
]
