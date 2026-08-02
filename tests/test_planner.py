from __future__ import annotations

import unittest

from mercury.models import CoverageProfile
from mercury.planner import BudgetError, InternalMappingRequest, authorize_internal_mapping, compile_internal_mapping
from mercury.policy import PolicyError


class InternalMappingRequestTests(unittest.TestCase):
    def test_private_overlapping_ranges_are_canonical_and_bounded(self) -> None:
        request = InternalMappingRequest(
            cidrs=("10.0.0.0/24", "10.0.0.0/25", "172.16.0.0/16"),
            profiles=(CoverageProfile.UDP_TAGGED, CoverageProfile.TCP_TAGGED),
            ports=(443, 53, 443), rate=10, concurrency=2, duration_s=0, authorized=True,
        )
        self.assertEqual(request.cidrs, ("10.0.0.0/24", "172.16.0.0/16"))
        self.assertEqual(request.ports, (53, 443))
        self.assertEqual(request.profiles, (CoverageProfile.TCP_TAGGED, CoverageProfile.UDP_TAGGED))

    def test_public_range_fails_before_planning(self) -> None:
        with self.assertRaisesRegex(PolicyError, "private scope"):
            InternalMappingRequest(
                cidrs=("198.51.100.0/24",), profiles=(CoverageProfile.TCP_TAGGED,),
                ports=(443,), rate=1, concurrency=1, duration_s=0, authorized=True,
            )

    def test_compilation_binds_cross_product_to_one_preview(self) -> None:
        request = InternalMappingRequest(
            cidrs=("127.0.0.1/32",), profiles=(CoverageProfile.TCP_TAGGED, CoverageProfile.UDP_TAGGED),
            ports=(53000,), rate=5, concurrency=2, duration_s=0, authorized=True,
        )
        preview = compile_internal_mapping(request)
        self.assertEqual(len(preview.steps), 2)
        self.assertEqual(preview.limits.max_global_rate, 5)
        self.assertEqual(preview.profile, "internal-mapping-v1")
        self.assertEqual(authorize_internal_mapping(request).preview.digest, preview.digest)

    def test_large_range_is_rejected_before_host_expansion(self) -> None:
        request = InternalMappingRequest(
            cidrs=("10.0.0.0/8",), profiles=(CoverageProfile.TCP_TAGGED,),
            ports=(443,), rate=1, concurrency=1, duration_s=0, authorized=True,
        )
        with self.assertRaisesRegex(BudgetError, "host estimate"):
            compile_internal_mapping(request)
