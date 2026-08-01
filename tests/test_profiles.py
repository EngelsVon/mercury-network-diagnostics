from __future__ import annotations

import unittest

from mercury.profiles import (
    BASIC_V1,
    CHINA_V1,
    DiagnosisRequest,
    ProfileError,
    canonical_custom_targets,
    parse_custom_target,
    compile_diagnosis,
)
from mercury.policy import ScopeGrant


class ProfileRequestTests(unittest.TestCase):
    def test_builtin_profiles_are_finite_and_versioned(self) -> None:
        self.assertEqual(BASIC_V1.name, "basic-v1")
        self.assertEqual(CHINA_V1.name, "china-v1")
        self.assertEqual(len(BASIC_V1.https_hosts), 3)
        self.assertEqual(len(CHINA_V1.https_hosts), 3)

    def test_request_rejects_invalid_timeout_and_scope_shapes(self) -> None:
        for timeout in (0, 30.1, float("inf"), True):
            with self.subTest(timeout=timeout), self.assertRaises(ProfileError):
                DiagnosisRequest(timeout_s=timeout)
        with self.assertRaises(ProfileError):
            DiagnosisRequest(profile="custom")


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


if __name__ == "__main__":
    unittest.main()
