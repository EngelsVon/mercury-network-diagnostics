from __future__ import annotations

import ipaddress
import unittest

from mercury.profiles import (
    BASIC_V1,
    DiagnosisRequest,
    ProfileError,
    canonical_custom_targets,
    parse_custom_target,
    compile_diagnosis,
)
from mercury.policy import ScopeGrant


class ProfileRequestTests(unittest.TestCase):
    def test_builtin_profile_is_private_and_versioned(self) -> None:
        self.assertEqual(BASIC_V1.name, "basic-v1")
        self.assertEqual(len(BASIC_V1.https_hosts), 1)
        self.assertEqual(BASIC_V1.raw_tcp_target.host, "127.0.0.1")
        self.assertEqual(BASIC_V1.https_hosts, ("localhost",))

    def test_builtin_profile_keeps_optional_native_context_out_of_required_groups(self) -> None:
        async def loopback(hostname, **_):
            from mercury.platform.common import CommandOutcome
            from mercury.resolver import ResolutionResult
            return ResolutionResult(hostname, ("127.0.0.1",), CommandOutcome.SUCCESS)

        compiled = __import__("asyncio").run(compile_diagnosis(
            DiagnosisRequest(profile="basic", authorized=True),
            grant=ScopeGrant(
                networks=(),
                hostnames=BASIC_V1.https_hosts, ports=(53, 443), transports=("tcp",),
                attested=True,
            ), resolver=loopback,
        ))
        kinds = {step.probe_kind for step in compiled.plan.preview.steps}
        self.assertIn(__import__("mercury.models", fromlist=["ProbeKind"]).ProbeKind.NATIVE_PING, kinds)
        self.assertIn(__import__("mercury.models", fromlist=["ProbeKind"]).ProbeKind.NATIVE_PATH, kinds)
        self.assertNotIn(__import__("mercury.models", fromlist=["ProbeKind"]).ProbeKind.NATIVE_PATH, {item.probe_kind for item in compiled.required_groups})

    def test_request_rejects_invalid_timeout_and_scope_shapes(self) -> None:
        for timeout in (0, 30.1, float("inf"), True):
            with self.subTest(timeout=timeout), self.assertRaises(ProfileError):
                DiagnosisRequest(timeout_s=timeout)
        with self.assertRaises(ProfileError):
            DiagnosisRequest(profile="custom")
        with self.assertRaises(ProfileError):
            DiagnosisRequest(profile="china")


class CustomTargetTests(unittest.TestCase):
    def test_canonicalizes_and_deduplicates_custom_targets(self) -> None:
        values = canonical_custom_targets(
            ("Example.COM:443", "example.com:443", "[::1]:80")
        )
        self.assertEqual(
            tuple(item.canonical for item in values),
            ("[::1]:80", "example.com:443"),
        )

    def test_rejects_urls_networks_ranges_and_ambiguous_ipv6(self) -> None:
        for value in (
            "https://example.com:443", "192.0.2.0/24:443",
            "example.com:*", "::1:443", "example.com:080", "example.com:0",
        ):
            with self.subTest(value=value), self.assertRaises(ProfileError):
                parse_custom_target(value)

    def test_custom_loopback_compiles_only_sparse_required_layers(self) -> None:
        compiled = __import__("asyncio").run(
            compile_diagnosis(
                DiagnosisRequest(profile="custom", targets=("127.0.0.1:443",), authorized=True),
                grant=ScopeGrant(networks=()),
            )
        )
        self.assertEqual(compiled.canonical_targets, ("127.0.0.1:443",))
        self.assertEqual({step.probe_kind.value for step in compiled.plan.preview.steps}, {"local_snapshot", "tcp_connect", "tls_handshake", "http_exchange"})

    def test_planning_dns_failure_retains_intended_missing_layer_groups(self) -> None:
        async def missing(hostname, **_):
            from mercury.platform.common import CommandOutcome
            from mercury.resolver import ResolutionResult
            return ResolutionResult(hostname, (), CommandOutcome.NONZERO, "NameNotFound")
        compiled = __import__("asyncio").run(compile_diagnosis(
            DiagnosisRequest(profile="custom", targets=("missing.test:443",), authorized=True),
            grant=ScopeGrant(hostnames=("missing.test",), ports=(443,), transports=("tcp",), attested=True, networks=()),
            resolver=missing,
        ))
        self.assertEqual({step.probe_kind.value for step in compiled.plan.preview.steps}, {"local_snapshot", "system_dns"})
        self.assertEqual({group.probe_kind.value for group in compiled.required_groups}, {"system_dns", "tcp_connect", "tls_handshake", "http_exchange"})


if __name__ == "__main__":
    unittest.main()
