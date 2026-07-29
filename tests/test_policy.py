from __future__ import annotations

import ipaddress
import unittest
from datetime import datetime, timedelta, timezone

from mercury.planner import (
    ABSOLUTE_CEILINGS,
    DEFAULT_LIMITS,
    BudgetError,
    BudgetLimits,
    ConfirmationError,
    authorize_plan,
    confirmation_phrase,
    preview_plan,
)
from mercury.policy import (
    PolicyError,
    ScopeGrant,
    authorize_targets,
    normalize_targets,
    parse_target,
    recheck_resolution,
    resolve_for_plan,
)


NOW = datetime(2026, 7, 30, tzinfo=timezone.utc)


class TargetPolicyTests(unittest.TestCase):
    def test_targets_are_canonical_and_deduplicated(self) -> None:
        targets = normalize_targets(
            ("192.168.1.4", "192.168.1.4", "192.168.1.99/24", "EXAMPLE.COM.")
        )
        self.assertEqual(
            [target.canonical for target in targets],
            ["192.168.1.0/24", "192.168.1.4", "example.com"],
        )

    def test_urls_and_ambiguous_numeric_addresses_are_rejected(self) -> None:
        for value in (
            "https://example.com",
            "user@example.com",
            "127.1",
            "2130706433",
            " 127.0.0.1",
            "example..com",
        ):
            with self.subTest(value=value), self.assertRaises(PolicyError):
                parse_target(value)

    def test_ipv6_link_local_scope_is_preserved(self) -> None:
        target = parse_target("fe80::1%Ethernet_2")
        self.assertEqual(target.canonical, "fe80::1%Ethernet_2")
        self.assertEqual(target.scope_id, "Ethernet_2")
        for value in ("2001:db8::1%eth0", "127.0.0.1%3", "fe80::1%bad scope"):
            with self.subTest(value=value), self.assertRaises(PolicyError):
                parse_target(value)

    def test_nonloopback_requires_attestation_and_containment(self) -> None:
        target = parse_target("192.0.2.10")
        without_attestation = ScopeGrant(
            networks=(ipaddress.ip_network("192.0.2.0/24"),),
            attested=False,
        )
        with self.assertRaisesRegex(PolicyError, "attestation"):
            authorize_targets((target,), without_attestation, now=NOW)
        outside = ScopeGrant(
            networks=(ipaddress.ip_network("198.51.100.0/24"),),
            attested=True,
        )
        with self.assertRaisesRegex(PolicyError, "outside"):
            authorize_targets((target,), outside, now=NOW)
        inside = ScopeGrant(
            networks=(ipaddress.ip_network("192.0.2.0/24"),),
            attested=True,
        )
        authorize_targets((target,), inside, now=NOW)

    def test_loopback_needs_no_attestation(self) -> None:
        authorize_targets(
            normalize_targets(("127.0.0.1", "::1")),
            ScopeGrant(networks=()),
            now=NOW,
        )

    def test_expired_scope_fails_closed(self) -> None:
        grant = ScopeGrant(
            networks=(ipaddress.ip_network("192.0.2.0/24"),),
            attested=True,
            expires_at=NOW - timedelta(seconds=1),
        )
        with self.assertRaisesRegex(PolicyError, "expired"):
            authorize_targets((parse_target("192.0.2.1"),), grant, now=NOW)

    def test_dns_answer_must_be_in_scope_and_stable(self) -> None:
        grant = ScopeGrant(
            networks=(ipaddress.ip_network("192.0.2.10/32"),),
            hostnames=("example.test",),
            attested=True,
        )
        target = parse_target("example.test")
        snapshot = resolve_for_plan(
            target,
            grant,
            resolver=lambda _: ("192.0.2.10",),
            now=NOW,
        )
        self.assertEqual(snapshot.addresses, ("192.0.2.10",))
        self.assertEqual(
            recheck_resolution(
                snapshot,
                grant,
                resolver=lambda _: ("192.0.2.10",),
                now=NOW,
            ),
            ("192.0.2.10",),
        )
        with self.assertRaisesRegex(PolicyError, "changed"):
            recheck_resolution(
                snapshot,
                grant,
                resolver=lambda _: ("192.0.2.11",),
                now=NOW,
            )

    def test_authorized_plan_rechecks_dns_at_socket_boundary(self) -> None:
        grant = ScopeGrant(
            networks=(ipaddress.ip_network("192.0.2.10/32"),),
            hostnames=("example.test",),
            attested=True,
        )
        preview = preview_plan(
            target_values=("example.test",),
            ports=(443,),
            transports=("tcp",),
            grant=grant,
            resolver=lambda _: ("192.0.2.10",),
            now=NOW,
        )
        plan = authorize_plan(preview, now=NOW)
        target = preview.targets[0]
        self.assertEqual(
            plan.preflight_addresses(
                target,
                resolver=lambda _: ("192.0.2.10",),
                now=NOW,
            ),
            ("192.0.2.10",),
        )
        with self.assertRaisesRegex(PolicyError, "changed"):
            plan.preflight_addresses(
                target,
                resolver=lambda _: ("192.0.2.11",),
                now=NOW,
            )

    def test_dns_out_of_scope_is_rejected_before_plan(self) -> None:
        grant = ScopeGrant(
            networks=(ipaddress.ip_network("192.0.2.0/24"),),
            hostnames=("example.test",),
            attested=True,
        )
        with self.assertRaisesRegex(PolicyError, "outside"):
            resolve_for_plan(
                parse_target("example.test"),
                grant,
                resolver=lambda _: ("203.0.113.8",),
                now=NOW,
            )


class BudgetTests(unittest.TestCase):
    def test_preview_reports_all_budget_dimensions(self) -> None:
        preview = preview_plan(
            target_values=("127.0.0.1",),
            ports=(53, 443),
            transports=("tcp", "udp"),
            grant=ScopeGrant(networks=()),
            repeats=2,
            payload_bytes_per_attempt=16,
            datagrams_per_udp_attempt=2,
            now=NOW,
        )
        estimate = preview.estimate
        self.assertEqual(estimate.logical_attempts, 8)
        self.assertEqual(estimate.generated_datagrams, 8)
        self.assertEqual(estimate.application_bytes, 192)
        wire = preview.to_wire()
        self.assertIn("max_global_rate", wire["limits"])
        self.assertIn("max_output_bytes", wire["limits"])

    def test_config_cannot_raise_absolute_ceiling(self) -> None:
        unsafe = BudgetLimits(
            **{
                **ABSOLUTE_CEILINGS.to_wire(),
                "max_hosts": ABSOLUTE_CEILINGS.max_hosts + 1,
            }
        )
        with self.assertRaisesRegex(BudgetError, "absolute"):
            unsafe.assert_within(ABSOLUTE_CEILINGS)

    def test_cross_product_is_rejected_cheaply(self) -> None:
        grant = ScopeGrant(
            networks=(ipaddress.ip_network("10.0.0.0/8"),),
            attested=True,
        )
        with self.assertRaises(BudgetError):
            preview_plan(
                target_values=("10.0.0.0/8",),
                ports=range(1, 65_536),
                transports=("tcp",),
                grant=grant,
                limits=ABSOLUTE_CEILINGS,
                now=NOW,
            )

    def test_full_port_confirmation_is_digest_bound(self) -> None:
        preview = preview_plan(
            target_values=("127.0.0.1",),
            ports=range(1, 65_536),
            transports=("tcp",),
            grant=ScopeGrant(networks=()),
            limits=ABSOLUTE_CEILINGS,
            now=NOW,
        )
        expected = confirmation_phrase("full_tcp", preview.digest)
        with self.assertRaisesRegex(ConfirmationError, "missing"):
            authorize_plan(preview, now=NOW)
        with self.assertRaises(ConfirmationError):
            authorize_plan(
                preview,
                confirmations=("AUTHORIZE FULL TCP deadbeefdead",),
                now=NOW,
            )
        plan = authorize_plan(preview, confirmations=(expected,), now=NOW)
        self.assertEqual(plan.digest, preview.digest)

    def test_custom_udp_requires_separate_confirmation(self) -> None:
        preview = preview_plan(
            target_values=("127.0.0.1",),
            ports=(9,),
            transports=("udp",),
            grant=ScopeGrant(networks=()),
            payload_bytes_per_attempt=32,
            custom_udp_payload=True,
            now=NOW,
        )
        self.assertEqual(preview.required_confirmations, ("custom_udp",))
        phrase = confirmation_phrase("custom_udp", preview.digest)
        authorize_plan(preview, confirmations=(phrase,), now=NOW)

    def test_defaults_are_strictly_below_absolutes(self) -> None:
        DEFAULT_LIMITS.assert_within(ABSOLUTE_CEILINGS)
        for name, maximum in ABSOLUTE_CEILINGS.to_wire().items():
            self.assertLessEqual(DEFAULT_LIMITS.to_wire()[name], maximum)


if __name__ == "__main__":
    unittest.main()
