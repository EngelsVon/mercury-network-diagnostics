from __future__ import annotations

import unittest

from mercury.models import CoverageProfile
from mercury.planner import InternalMappingRequest
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
