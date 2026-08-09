from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mercury.models import CoverageProfile
from mercury.nmap_adapter import MAX_NMAP_XML_BYTES, NmapError, build_nmap_argv, parse_nmap_xml, run_nmap
from mercury.platform.common import MAX_COMMAND_OUTPUT_BYTES
from mercury.planner import InternalMappingRequest, authorize_internal_mapping
from mercury.platform.common import CommandOutcome, CommandResult


def plan():
    return authorize_internal_mapping(InternalMappingRequest(
        cidrs=("127.0.0.1/32",), profiles=(CoverageProfile.TCP_CONNECT,),
        ports=(53, 443), rate=17, concurrency=1, duration_s=0, authorized=True,
    ))


class NmapAdapterTests(unittest.IsolatedAsyncioTestCase):
    def test_argv_is_fixed_and_plan_derived_for_each_native_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "nmap.exe"
            output = Path(temporary) / "result.xml"
            binary.write_bytes(b"fixture")
            expected = {
                CoverageProfile.NMAP_TCP_CONNECT: "-sT",
                CoverageProfile.NMAP_TCP_SYN: "-sS",
                CoverageProfile.NMAP_UDP: "-sU",
                CoverageProfile.NMAP_SCTP_INIT: "-sY",
            }
            for profile, switch in expected.items():
                with self.subTest(profile=profile):
                    argv = build_nmap_argv(plan(), profile, executable=binary, xml_path=output)
                    self.assertEqual(argv, (
                        str(binary), "-n", "-Pn", "--reason", switch, "--max-rate", "17",
                        "--host-timeout", "300s", "-p", "53,443", "-oX", str(output), "127.0.0.1",
                    ))
                    self.assertFalse(any(item.startswith("--script") or item.startswith("--proxy") for item in argv))

    def test_unavailable_binary_non_native_profile_and_relative_output_fail_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "nmap"
            with self.assertRaisesRegex(NmapError, "unavailable"):
                build_nmap_argv(plan(), CoverageProfile.NMAP_TCP_CONNECT, executable=binary, xml_path=Path(temporary) / "result.xml")
            binary.write_bytes(b"fixture")
            with self.assertRaisesRegex(NmapError, "closed native"):
                build_nmap_argv(plan(), CoverageProfile.TCP_CONNECT, executable=binary, xml_path=Path(temporary) / "result.xml")
            with self.assertRaisesRegex(NmapError, "absolute"):
                build_nmap_argv(plan(), CoverageProfile.NMAP_TCP_CONNECT, executable=binary, xml_path="result.xml")

    def test_xml_parser_preserves_native_states_and_rejects_scope_or_size_escape(self) -> None:
        states = parse_nmap_xml(b"""<nmaprun><host><address addr='127.0.0.1' addrtype='ipv4'/><ports>
            <port protocol='tcp' portid='53'><state state='open' reason='syn-ack'/></port>
            <port protocol='tcp' portid='443'><state state='closed' reason='reset'/></port>
            <port protocol='udp' portid='161'><state state='open|filtered' reason='no-response'/></port>
        </ports></host></nmaprun>""")
        self.assertEqual([(item.port, item.state) for item in states], [(53, "open"), (443, "closed"), (161, "open|filtered")])
        with self.assertRaisesRegex(NmapError, "private target"):
            parse_nmap_xml(b"<nmaprun><host><address addr='8.8.8.8' addrtype='ipv4'/><ports><port protocol='tcp' portid='53'><state state='open'/></port></ports></host></nmaprun>")
        with self.assertRaisesRegex(NmapError, "byte ceiling"):
            parse_nmap_xml(b"x" * (MAX_NMAP_XML_BYTES + 1))

    async def test_execution_reads_only_owned_temporary_xml_and_cleans_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "nmap.exe"
            binary.write_bytes(b"fixture")
            seen: list[Path] = []

            async def runner(argv: tuple[str, ...], _timeout: float, maximum: int) -> CommandResult:
                self.assertEqual(maximum, MAX_COMMAND_OUTPUT_BYTES)
                output = Path(argv[argv.index("-oX") + 1])
                seen.append(output)
                output.write_text("<nmaprun><host><address addr='127.0.0.1' addrtype='ipv4'/><ports><port protocol='tcp' portid='53'><state state='open' reason='syn-ack'/></port></ports></host></nmaprun>", encoding="utf-8")
                return CommandResult(argv, 0, "", "", CommandOutcome.SUCCESS)

            result = await run_nmap(
                plan(), CoverageProfile.NMAP_TCP_CONNECT, executable=binary,
                command_runner=runner, temporary_directory=temporary,
            )
            self.assertEqual(result.outcome, CommandOutcome.SUCCESS)
            self.assertEqual([(item.port, item.state) for item in result.ports], [(53, "open")])
            self.assertEqual(len(seen), 1)
            self.assertFalse(seen[0].exists())

    async def test_execution_reports_missing_tool_without_subprocess(self) -> None:
        async def runner(*_args: object) -> CommandResult:
            self.fail("runner must not execute when Nmap is absent")

        result = await run_nmap(plan(), CoverageProfile.NMAP_UDP, executable="missing-nmap", command_runner=runner)
        self.assertEqual((result.outcome, result.ports), (CommandOutcome.MISSING_TOOL, ()))
