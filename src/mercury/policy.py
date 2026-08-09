"""Strict target parsing and explicit scope authorization."""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import Callable, Iterable, Sequence

from .models import ProbeKind


class PolicyError(ValueError):
    """A target or authorization decision failed closed."""


class TargetKind(StrEnum):
    ADDRESS = "address"
    NETWORK = "network"
    HOSTNAME = "hostname"


_SCOPE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_NUMERICISH_RE = re.compile(r"^[0-9A-Fa-f:.%]+$")
_HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_IPV4_MULTICAST = ipaddress.ip_network("224.0.0.0/4")
_IPV6_MULTICAST = ipaddress.ip_network("ff00::/8")
_LIMITED_BROADCAST = ipaddress.ip_address("255.255.255.255")
_IPV4_INTERNAL_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    # RFC 6598 shared address space is used by private tailnets such as
    # Tailscale; it is not globally routable Internet address space.
    ipaddress.ip_network("100.64.0.0/10"),
)
_IPV4_LOOPBACK_NETWORK = ipaddress.ip_network("127.0.0.0/8")
_IPV6_LOOPBACK_NETWORK = ipaddress.ip_network("::1/128")
_IPV6_ULA_NETWORK = ipaddress.ip_network("fc00::/7")
_IPV6_LINK_LOCAL_NETWORK = ipaddress.ip_network("fe80::/10")


@dataclass(frozen=True, slots=True)
class Target:
    kind: TargetKind
    canonical: str
    address: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    network: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
    hostname: str | None = None
    scope_id: str | None = None

    def __post_init__(self) -> None:
        if type(self.kind) is not TargetKind:
            raise PolicyError("target kind must be TargetKind")
        if type(self.canonical) is not str or not self.canonical:
            raise PolicyError("target canonical value must be non-empty text")
        present = sum(
            item is not None for item in (self.address, self.network, self.hostname)
        )
        if present != 1:
            raise PolicyError("target must contain exactly one typed destination")
        if self.kind is TargetKind.ADDRESS:
            if type(self.address) not in (
                ipaddress.IPv4Address,
                ipaddress.IPv6Address,
            ):
                raise PolicyError("address target must contain an IP address")
            _assert_destination_address(self.address, scope_id=self.scope_id)
            if self.scope_id is not None:
                if (
                    type(self.scope_id) is not str
                    or not _SCOPE_RE.fullmatch(self.scope_id)
                    or type(self.address) is not ipaddress.IPv6Address
                    or not self.address.is_link_local
                ):
                    raise PolicyError(
                        "scope ID is allowed only on IPv6 link-local literals"
                    )
            expected = (
                f"{self.address}%{self.scope_id}"
                if self.scope_id is not None
                else str(self.address)
            )
            if self.canonical != expected:
                raise PolicyError("address target is not canonical")
        elif self.kind is TargetKind.NETWORK:
            if type(self.network) not in (
                ipaddress.IPv4Network,
                ipaddress.IPv6Network,
            ):
                raise PolicyError("network target must contain an IP network")
            if self.scope_id is not None:
                raise PolicyError("network target cannot contain a scope ID")
            _assert_destination_network(self.network)
            if self.canonical != str(self.network):
                raise PolicyError("network target is not canonical")
        else:
            if type(self.hostname) is not str or self.scope_id is not None:
                raise PolicyError("hostname target fields are invalid")
            if self.canonical != _canonical_hostname(self.hostname):
                raise PolicyError("hostname target is not canonical")

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
        hostname = _canonical_hostname(self.hostname)
        if not isinstance(self.addresses, (list, tuple)):
            raise PolicyError("resolution addresses must be a sequence")
        addresses = tuple(self.addresses)
        if not addresses:
            raise PolicyError("resolution snapshot cannot be empty")
        for value in addresses:
            target = parse_target(value)
            if target.kind is not TargetKind.ADDRESS:
                raise PolicyError("resolution snapshot must contain addresses")
        if (
            type(self.resolved_at) is not datetime
            or self.resolved_at.tzinfo is None
            or self.resolved_at.utcoffset() is None
        ):
            raise PolicyError("resolution timestamp must be timezone-aware")
        object.__setattr__(self, "hostname", hostname)
        object.__setattr__(self, "addresses", addresses)


@dataclass(frozen=True, slots=True)
class ScopeGrant:
    """The exact names and networks an operator attested they may test."""

    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    hostnames: tuple[str, ...] = ()
    ports: tuple[int, ...] = ()
    transports: tuple[str, ...] = ()
    probe_kinds: tuple[ProbeKind, ...] = tuple(ProbeKind)
    attested: bool = False
    purpose: str = ""
    expires_at: datetime | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.networks, (list, tuple)):
            raise PolicyError("scope networks must be a sequence")
        if not isinstance(self.hostnames, (list, tuple)):
            raise PolicyError("scope hostnames must be a sequence")
        if not isinstance(self.ports, (list, tuple)):
            raise PolicyError("scope ports must be a sequence")
        if not isinstance(self.transports, (list, tuple)):
            raise PolicyError("scope transports must be a sequence")
        if not isinstance(self.probe_kinds, (list, tuple)):
            raise PolicyError("scope probe_kinds must be a sequence")
        network_set: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
        for value in self.networks:
            if type(value) not in (
                ipaddress.IPv4Network,
                ipaddress.IPv6Network,
            ):
                raise PolicyError("scope networks must contain IP network objects")
            _assert_destination_network(value)
            network_set.add(value)
        canonical_networks = tuple(
            sorted(
                network_set,
                key=lambda item: (
                    item.version,
                    int(item.network_address),
                    item.prefixlen,
                ),
            )
        )
        canonical_names = tuple(
            sorted({_canonical_hostname(value) for value in self.hostnames})
        )
        canonical_ports: set[int] = set()
        for value in self.ports:
            if type(value) is not int or not 1 <= value <= 65_535:
                raise PolicyError(f"invalid scope port {value!r}")
            canonical_ports.add(value)
        canonical_transports: set[str] = set()
        for value in self.transports:
            if type(value) is not str or value.casefold() not in {"tcp", "udp", "sctp"}:
                raise PolicyError(f"invalid scope transport {value!r}")
            canonical_transports.add(value.casefold())
        canonical_kinds: set[ProbeKind] = set()
        for value in self.probe_kinds:
            if type(value) is not ProbeKind:
                raise PolicyError("scope probe_kinds must contain ProbeKind values")
            canonical_kinds.add(value)
        if type(self.attested) is not bool:
            raise PolicyError("scope attested must be a boolean")
        if type(self.purpose) is not str or "\x00" in self.purpose:
            raise PolicyError("scope purpose must be text without NUL")
        object.__setattr__(self, "networks", canonical_networks)
        object.__setattr__(self, "hostnames", canonical_names)
        object.__setattr__(self, "ports", tuple(sorted(canonical_ports)))
        object.__setattr__(
            self, "transports", tuple(sorted(canonical_transports))
        )
        object.__setattr__(
            self, "probe_kinds", tuple(sorted(canonical_kinds, key=lambda item: item.value))
        )
        if self.expires_at is not None and (
            type(self.expires_at) is not datetime
            or self.expires_at.tzinfo is None
            or self.expires_at.utcoffset() is None
        ):
            raise PolicyError("scope expiry must be a timezone-aware datetime")
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

    def permits_step(self, port: int, transport: str) -> bool:
        return port in self.ports and transport.casefold() in self.transports

    def permits_probe(
        self,
        kind: ProbeKind,
        port: int | None,
        transport: str | None,
    ) -> bool:
        """Check the exact finite probe authority without dummy port values."""
        if type(kind) is not ProbeKind or kind not in self.probe_kinds:
            return False
        ported = {
            ProbeKind.TCP_CONNECT,
            ProbeKind.UDP_EXCHANGE,
            ProbeKind.TLS_HANDSHAKE,
            ProbeKind.HTTP_EXCHANGE,
            ProbeKind.NATIVE_PORT_SCAN,
        }
        if kind not in ported:
            return port is None and transport is None
        return (
            type(port) is int
            and type(transport) is str
            and self.permits_step(port, transport)
        )

    def to_wire(self) -> dict[str, object]:
        return {
            "networks": [str(item) for item in self.networks],
            "hostnames": list(self.hostnames),
            "ports": list(self.ports),
            "transports": list(self.transports),
            "probe_kinds": [item.value for item in self.probe_kinds],
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


def _assert_destination_address(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    *,
    scope_id: str | None = None,
) -> None:
    if address.is_unspecified:
        raise PolicyError("unspecified destinations are not allowed")
    if address.is_multicast:
        raise PolicyError("multicast destinations are not allowed")
    if address == _LIMITED_BROADCAST:
        raise PolicyError("limited-broadcast destinations are not allowed")
    if address.version == 4:
        if any(address in network for network in (*_IPV4_INTERNAL_NETWORKS, _IPV4_LOOPBACK_NETWORK)):
            return
    elif address in _IPV6_LOOPBACK_NETWORK or address in _IPV6_ULA_NETWORK:
        return
    elif address in _IPV6_LINK_LOCAL_NETWORK and scope_id is not None:
        return
    raise PolicyError("active destinations must use an explicit private address range")


def _assert_destination_network(
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
) -> None:
    multicast = _IPV4_MULTICAST if network.version == 4 else _IPV6_MULTICAST
    unspecified = ipaddress.ip_address("0.0.0.0" if network.version == 4 else "::")
    if network.overlaps(multicast):
        raise PolicyError("multicast destination networks are not allowed")
    if unspecified in network:
        raise PolicyError("networks containing an unspecified destination are not allowed")
    if network.version == 4 and _LIMITED_BROADCAST in network:
        raise PolicyError(
            "networks containing the limited-broadcast destination are not allowed"
        )
    allowed = (
        (*_IPV4_INTERNAL_NETWORKS, _IPV4_LOOPBACK_NETWORK)
        if network.version == 4
        else (_IPV6_LOOPBACK_NETWORK, _IPV6_ULA_NETWORK, _IPV6_LINK_LOCAL_NETWORK)
    )
    if not any(network.subnet_of(candidate) for candidate in allowed):
        raise PolicyError("active destination networks must use an explicit private address range")


def _canonical_hostname(value: str) -> str:
    if type(value) is not str:
        raise PolicyError("hostname must be text")
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
        _assert_destination_network(network)
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
    _assert_destination_address(address, scope_id=scope_id)
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
    if type(grant) is not ScopeGrant:
        raise PolicyError("grant must be ScopeGrant")
    grant.assert_current(now)
    for target in targets:
        if type(target) is not Target:
            raise PolicyError("targets must contain Target values")
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
        sockaddr: tuple[object, ...] | None = None
        if isinstance(value, str):
            raw = value
        elif (
            isinstance(value, tuple)
            and len(value) == 5
            and isinstance(value[4], tuple)
            and value[4]
        ):
            sockaddr = value[4]
            raw = sockaddr[0]
        else:
            raise PolicyError("resolver returned an unsupported address shape")
        candidate = str(raw)
        if (
            sockaddr is not None
            and len(sockaddr) >= 4
            and "%" not in candidate
            and type(sockaddr[3]) is int
            and sockaddr[3] > 0
        ):
            candidate = f"{candidate}%{sockaddr[3]}"
        try:
            target = parse_target(candidate)
        except PolicyError as exc:
            raise PolicyError(
                f"resolver returned invalid or non-private address {raw!r}"
            ) from exc
        if target.kind is not TargetKind.ADDRESS or target.address is None:
            raise PolicyError(f"resolver returned non-address {raw!r}")
        addresses.add(target.canonical)
    if not addresses:
        raise PolicyError("hostname resolved to no addresses")
    return tuple(
        sorted(
            addresses,
            key=lambda item: (
                ipaddress.ip_address(item.split("%", 1)[0]).version,
                int(ipaddress.ip_address(item.split("%", 1)[0])),
                item.partition("%")[2],
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
        address = ipaddress.ip_address(value.split("%", 1)[0])
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
    for value in addresses:
        address = ipaddress.ip_address(value.split("%", 1)[0])
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
