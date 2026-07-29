"""Strict target parsing and explicit scope authorization."""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import Callable, Iterable, Sequence


class PolicyError(ValueError):
    """A target or authorization decision failed closed."""


class TargetKind(StrEnum):
    ADDRESS = "address"
    NETWORK = "network"
    HOSTNAME = "hostname"


_SCOPE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_NUMERICISH_RE = re.compile(r"^[0-9A-Fa-f:.%]+$")
_HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


@dataclass(frozen=True, slots=True)
class Target:
    kind: TargetKind
    canonical: str
    address: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    network: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
    hostname: str | None = None
    scope_id: str | None = None

    @property
    def is_loopback(self) -> bool:
        if self.address is not None:
            return self.address.is_loopback
        if self.network is not None:
            return self.network.subnet_of(
                ipaddress.ip_network(
                    "127.0.0.0/8" if self.network.version == 4 else "::1/128"
                )
            )
        return self.hostname == "localhost"

    @property
    def host_count(self) -> int:
        if self.network is None:
            return 1
        if self.network.version == 6 and self.network.prefixlen < 128:
            raise PolicyError("IPv6 network enumeration is not supported")
        if self.network.version == 4 and self.network.prefixlen < 31:
            return max(0, self.network.num_addresses - 2)
        return self.network.num_addresses


@dataclass(frozen=True, slots=True)
class ResolutionSnapshot:
    hostname: str
    addresses: tuple[str, ...]
    resolved_at: datetime

    def __post_init__(self) -> None:
        if not self.addresses:
            raise PolicyError("resolution snapshot cannot be empty")
        if self.resolved_at.tzinfo is None:
            raise PolicyError("resolution timestamp must be timezone-aware")


@dataclass(frozen=True, slots=True)
class ScopeGrant:
    """The exact names and networks an operator attested they may test."""

    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    hostnames: tuple[str, ...] = ()
    attested: bool = False
    purpose: str = ""
    expires_at: datetime | None = None

    def __post_init__(self) -> None:
        canonical_networks = tuple(
            sorted(
                {
                    ipaddress.ip_network(value, strict=False)
                    for value in self.networks
                },
                key=lambda item: (item.version, int(item.network_address), item.prefixlen),
            )
        )
        canonical_names = tuple(
            sorted({_canonical_hostname(value) for value in self.hostnames})
        )
        object.__setattr__(self, "networks", canonical_networks)
        object.__setattr__(self, "hostnames", canonical_names)
        if self.expires_at is not None and self.expires_at.tzinfo is None:
            raise PolicyError("scope expiry must be timezone-aware")
        if len(self.purpose) > 1024:
            raise PolicyError("scope purpose is too long")

    def assert_current(self, now: datetime | None = None) -> None:
        instant = now or datetime.now(timezone.utc)
        if self.expires_at is not None and instant >= self.expires_at:
            raise PolicyError("authorization scope has expired")

    def permits_address(
        self, address: ipaddress.IPv4Address | ipaddress.IPv6Address
    ) -> bool:
        return any(
            address.version == network.version and address in network
            for network in self.networks
        )

    def permits_name(self, hostname: str) -> bool:
        return _canonical_hostname(hostname) in self.hostnames

    def to_wire(self) -> dict[str, object]:
        return {
            "networks": [str(item) for item in self.networks],
            "hostnames": list(self.hostnames),
            "attested": self.attested,
            "purpose": self.purpose,
            "expires_at": (
                self.expires_at.astimezone(timezone.utc)
                .isoformat(timespec="seconds")
                .replace("+00:00", "Z")
                if self.expires_at
                else None
            ),
        }


Resolver = Callable[[str], Sequence[object]]


def _canonical_hostname(value: str) -> str:
    candidate = value.strip().rstrip(".")
    if not candidate or len(candidate) > 253:
        raise PolicyError("hostname length is invalid")
    try:
        ascii_name = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise PolicyError("hostname is not valid IDNA") from exc
    labels = ascii_name.split(".")
    if any(not _HOST_LABEL_RE.fullmatch(label) for label in labels):
        raise PolicyError("hostname contains an invalid label")
    return ascii_name


def parse_target(value: str) -> Target:
    if not isinstance(value, str):
        raise PolicyError("target must be text")
    candidate = value.strip()
    if not candidate or len(candidate) > 1024:
        raise PolicyError("target length is invalid")
    if candidate != value or any(character.isspace() for character in candidate):
        raise PolicyError("target must not contain surrounding or embedded whitespace")
    if "://" in candidate or "@" in candidate or "?" in candidate or "#" in candidate:
        raise PolicyError("target must be an IP, CIDR, or hostname, not a URL")

    if "/" in candidate:
        if "%" in candidate:
            raise PolicyError("CIDR targets cannot contain an IPv6 scope ID")
        try:
            network = ipaddress.ip_network(candidate, strict=False)
        except ValueError as exc:
            raise PolicyError(f"invalid CIDR target: {candidate!r}") from exc
        return Target(
            kind=TargetKind.NETWORK,
            canonical=str(network),
            network=network,
        )

    scope_id: str | None = None
    address_candidate = candidate
    if "%" in candidate:
        address_candidate, separator, scope_id = candidate.rpartition("%")
        if not separator or not address_candidate or not scope_id:
            raise PolicyError("invalid IPv6 scope ID syntax")
        if not _SCOPE_RE.fullmatch(scope_id):
            raise PolicyError("IPv6 scope ID contains invalid characters")
    try:
        address = ipaddress.ip_address(address_candidate)
    except ValueError:
        if scope_id is not None:
            raise PolicyError("scope IDs are valid only on IPv6 literals")
        if _NUMERICISH_RE.fullmatch(candidate):
            raise PolicyError("ambiguous or malformed numeric address")
        hostname = _canonical_hostname(candidate)
        return Target(
            kind=TargetKind.HOSTNAME,
            canonical=hostname,
            hostname=hostname,
        )
    if scope_id is not None:
        if not isinstance(address, ipaddress.IPv6Address) or not address.is_link_local:
            raise PolicyError("scope ID is allowed only on IPv6 link-local literals")
    canonical = f"{address}%{scope_id}" if scope_id else str(address)
    return Target(
        kind=TargetKind.ADDRESS,
        canonical=canonical,
        address=address,
        scope_id=scope_id,
    )


def normalize_targets(values: Iterable[str]) -> tuple[Target, ...]:
    targets: dict[str, Target] = {}
    for value in values:
        target = parse_target(value)
        targets[target.canonical] = target
    if not targets:
        raise PolicyError("at least one target is required")
    return tuple(targets[key] for key in sorted(targets))


def authorize_targets(
    targets: Iterable[Target],
    grant: ScopeGrant,
    *,
    now: datetime | None = None,
) -> None:
    grant.assert_current(now)
    for target in targets:
        if target.is_loopback:
            continue
        if not grant.attested:
            raise PolicyError(
                f"non-loopback target {target.canonical!r} requires "
                "explicit authorization attestation"
            )
        if target.address is not None and not grant.permits_address(target.address):
            raise PolicyError(f"address {target.canonical!r} is outside scope")
        if target.network is not None:
            if not any(
                target.network.version == network.version
                and target.network.subnet_of(network)
                for network in grant.networks
            ):
                raise PolicyError(f"network {target.canonical!r} is outside scope")
        if target.hostname is not None and not grant.permits_name(target.hostname):
            raise PolicyError(f"hostname {target.hostname!r} is outside scope")


def _default_resolver(hostname: str) -> Sequence[object]:
    return socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)


def _addresses_from_resolution(values: Sequence[object]) -> tuple[str, ...]:
    addresses: set[str] = set()
    for value in values:
        raw: object
        if isinstance(value, str):
            raw = value
        elif (
            isinstance(value, tuple)
            and len(value) == 5
            and isinstance(value[4], tuple)
            and value[4]
        ):
            raw = value[4][0]
        else:
            raise PolicyError("resolver returned an unsupported address shape")
        try:
            address = ipaddress.ip_address(str(raw).split("%", 1)[0])
        except ValueError as exc:
            raise PolicyError(f"resolver returned invalid address {raw!r}") from exc
        addresses.add(str(address))
    if not addresses:
        raise PolicyError("hostname resolved to no addresses")
    return tuple(
        sorted(
            addresses,
            key=lambda item: (
                ipaddress.ip_address(item).version,
                int(ipaddress.ip_address(item)),
            ),
        )
    )


def resolve_for_plan(
    target: Target,
    grant: ScopeGrant,
    *,
    resolver: Resolver = _default_resolver,
    now: datetime | None = None,
) -> ResolutionSnapshot:
    if target.hostname is None:
        raise PolicyError("only a hostname can be resolved")
    authorize_targets((target,), grant, now=now)
    addresses = _addresses_from_resolution(resolver(target.hostname))
    for value in addresses:
        address = ipaddress.ip_address(value)
        if not (target.is_loopback and address.is_loopback) and not grant.permits_address(address):
            raise PolicyError(
                f"resolved address {value} for {target.hostname!r} is outside scope"
            )
    return ResolutionSnapshot(
        hostname=target.hostname,
        addresses=addresses,
        resolved_at=now or datetime.now(timezone.utc),
    )


def recheck_resolution(
    snapshot: ResolutionSnapshot,
    grant: ScopeGrant,
    *,
    resolver: Resolver = _default_resolver,
    now: datetime | None = None,
) -> tuple[str, ...]:
    grant.assert_current(now)
    loopback_name = snapshot.hostname == "localhost"
    if not loopback_name and not grant.permits_name(snapshot.hostname):
        raise PolicyError(f"hostname {snapshot.hostname!r} is no longer in scope")
    addresses = _addresses_from_resolution(resolver(snapshot.hostname))
    if addresses != snapshot.addresses:
        raise PolicyError(
            f"DNS answers for {snapshot.hostname!r} changed after authorization"
        )
    for value in addresses:
        address = ipaddress.ip_address(value)
        if not (loopback_name and address.is_loopback) and not grant.permits_address(address):
            raise PolicyError(
                f"resolved address {value} for {snapshot.hostname!r} escaped scope"
            )
    return addresses


__all__ = [
    "PolicyError",
    "ResolutionSnapshot",
    "Resolver",
    "ScopeGrant",
    "Target",
    "TargetKind",
    "authorize_targets",
    "normalize_targets",
    "parse_target",
    "recheck_resolution",
    "resolve_for_plan",
]
