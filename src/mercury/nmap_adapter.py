"""Closed, plan-derived adapter for an operator-local Nmap executable.

It intentionally has no public argv, target, script, payload, proxy or decoy
interface.  Nmap is a native evidence source, never a generic shell feature.
"""

from __future__ import annotations

import ipaddress
import shutil
import tempfile
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass
from pathlib import Path

from .models import CoverageProfile
from .planner import ProbePlan, validate_plan
from .platform.common import CommandOutcome, CommandResult, run_command

MAX_NMAP_XML_BYTES = 1_048_576
MAX_NMAP_PORTS = 65_535
_NATIVE_PROFILES = {
    CoverageProfile.NMAP_TCP_CONNECT: "-sT",
    CoverageProfile.NMAP_TCP_SYN: "-sS",
    CoverageProfile.NMAP_UDP: "-sU",
    CoverageProfile.NMAP_SCTP_INIT: "-sY",
}
_PORT_STATES = frozenset({"open", "closed", "filtered", "open|filtered"})


class NmapError(RuntimeError):
    """A native profile could not be derived or parsed safely."""


@dataclass(frozen=True, slots=True)
class NativePortState:
    """One bounded Nmap port state, preserving native rather than wire provenance."""

    address: str
    port: int
    protocol: str
    state: str
    reason: str | None

    def __post_init__(self) -> None:
        try:
            address = ipaddress.ip_address(self.address)
        except ValueError as exc:
            raise NmapError("Nmap XML has an invalid numeric address") from exc
        if not (address.is_private or address.is_loopback):
            raise NmapError("Nmap XML escaped the private target scope")
        object.__setattr__(self, "address", str(address))
        if type(self.port) is not int or not 1 <= self.port <= 65_535:
            raise NmapError("Nmap XML has an invalid port")
        if self.protocol not in {"tcp", "udp", "sctp"}:
            raise NmapError("Nmap XML has an unsupported protocol")
        if self.state not in _PORT_STATES:
            raise NmapError("Nmap XML has an unsupported port state")
        if self.reason is not None and (not isinstance(self.reason, str) or len(self.reason) > 128):
            raise NmapError("Nmap XML has an invalid state reason")


@dataclass(frozen=True, slots=True)
class NativeNmapResult:
    """Bounded native result without retaining argv, XML, or command output."""

    profile: CoverageProfile
    outcome: CommandOutcome
    ports: tuple[NativePortState, ...]
    diagnostic: str = ""

    def __post_init__(self) -> None:
        if self.profile not in _NATIVE_PROFILES or type(self.outcome) is not CommandOutcome:
            raise NmapError("native Nmap result is invalid")
        if not isinstance(self.ports, (tuple, list)) or any(type(item) is not NativePortState for item in self.ports):
            raise NmapError("native Nmap port evidence is invalid")
        object.__setattr__(self, "ports", tuple(self.ports))
        if not isinstance(self.diagnostic, str) or len(self.diagnostic) > 1_024:
            raise NmapError("native Nmap diagnostic is invalid")


def find_nmap(executable: str | Path | None = None) -> Path | None:
    """Return an operator-local executable path, without executing it."""
    if executable is not None:
        path = Path(executable)
        if not path.is_file():
            return None
        return path.resolve()
    found = shutil.which("nmap")
    return None if found is None else Path(found).resolve()


def build_nmap_argv(
    plan: ProbePlan,
    profile: CoverageProfile,
    *,
    executable: str | Path,
    xml_path: str | Path,
) -> tuple[str, ...]:
    """Construct the sole accepted Nmap argv from a validated private plan."""
    if type(plan) is not ProbePlan:
        raise NmapError("Nmap requires an admitted immutable plan")
    validate_plan(plan)
    if type(profile) is not CoverageProfile or profile not in _NATIVE_PROFILES:
        raise NmapError("Nmap profile is not part of the closed native matrix")
    binary = Path(executable)
    if not binary.is_file():
        raise NmapError("Nmap executable is unavailable")
    output = Path(xml_path)
    if not output.is_absolute() or output.suffix.casefold() != ".xml":
        raise NmapError("Nmap XML output path must be an absolute .xml file")
    targets = tuple(dict.fromkeys(step.address for step in plan.preview.steps if step.address is not None))
    ports = plan.preview.ports
    if not targets or not ports or len(ports) > MAX_NMAP_PORTS:
        raise NmapError("Nmap needs bounded numeric plan targets and ports")
    for target in targets:
        assert target is not None
        try:
            address = ipaddress.ip_address(target)
        except ValueError as exc:
            raise NmapError("Nmap plan target is not numeric") from exc
        if not (address.is_private or address.is_loopback):
            raise NmapError("Nmap plan target escaped the private scope")
    timeout = plan.preview.limits.max_duration_s
    return (
        str(binary), "-n", "-Pn", "--reason", _NATIVE_PROFILES[profile],
        "--max-rate", str(plan.preview.limits.max_global_rate),
        "--host-timeout", f"{timeout}s", "-p", ",".join(str(port) for port in ports),
        "-oX", str(output), *targets,
    )


def parse_nmap_xml(document: bytes | str) -> tuple[NativePortState, ...]:
    """Parse only bounded host/port/state facts from Nmap XML."""
    raw = document.encode("utf-8") if isinstance(document, str) else document
    if type(raw) is not bytes or not raw or len(raw) > MAX_NMAP_XML_BYTES:
        raise NmapError("Nmap XML is empty or exceeds its byte ceiling")
    try:
        root = ElementTree.fromstring(raw)
    except ElementTree.ParseError as exc:
        raise NmapError("Nmap XML is malformed") from exc
    if root.tag != "nmaprun":
        raise NmapError("Nmap XML root is invalid")
    observations: list[NativePortState] = []
    for host in root.findall("host"):
        address = next((item.get("addr") for item in host.findall("address") if item.get("addrtype") in {"ipv4", "ipv6"}), None)
        if address is None:
            continue
        for port in host.findall("ports/port"):
            if len(observations) >= MAX_NMAP_PORTS:
                raise NmapError("Nmap XML port count exceeds its ceiling")
            state = port.find("state")
            if state is None:
                raise NmapError("Nmap XML port has no state")
            try:
                number = int(port.get("portid", ""))
            except ValueError as exc:
                raise NmapError("Nmap XML port number is invalid") from exc
            observations.append(NativePortState(
                address, number, port.get("protocol", ""), state.get("state", ""), state.get("reason"),
            ))
    return tuple(observations)


async def run_nmap(
    plan: ProbePlan,
    profile: CoverageProfile,
    *,
    executable: str | Path | None = None,
    command_runner=run_command,
    temporary_directory: str | Path | None = None,
) -> NativeNmapResult:
    """Run one fixed native profile and return only bounded parsed evidence."""
    binary = find_nmap(executable)
    if binary is None:
        return NativeNmapResult(profile, CommandOutcome.MISSING_TOOL, (), "nmap executable unavailable")
    root_argument = None if temporary_directory is None else str(Path(temporary_directory).resolve())
    with tempfile.TemporaryDirectory(prefix="mercury-nmap-", dir=root_argument) as directory:
        root = Path(directory).resolve()
        xml_path = root / "result.xml"
        argv = build_nmap_argv(plan, profile, executable=binary, xml_path=xml_path)
        result: CommandResult = await command_runner(argv, min(30.0, float(plan.preview.limits.max_duration_s)), MAX_NMAP_XML_BYTES)
        if type(result) is not CommandResult:
            raise NmapError("native command runner returned an invalid result")
        if result.outcome not in {CommandOutcome.SUCCESS, CommandOutcome.NONZERO}:
            return NativeNmapResult(profile, result.outcome, (), result.diagnostic)
        resolved = xml_path.resolve()
        if resolved.parent != root or not resolved.is_file():
            return NativeNmapResult(profile, CommandOutcome.ERROR, (), "nmap did not produce bounded XML output")
        try:
            document = resolved.read_bytes()
            ports = parse_nmap_xml(document)
        except (OSError, NmapError) as exc:
            return NativeNmapResult(profile, CommandOutcome.ERROR, (), type(exc).__name__)
        return NativeNmapResult(profile, result.outcome, ports, "")


__all__ = [
    "MAX_NMAP_XML_BYTES", "NativeNmapResult", "NativePortState", "NmapError",
    "build_nmap_argv", "find_nmap", "parse_nmap_xml", "run_nmap",
]
