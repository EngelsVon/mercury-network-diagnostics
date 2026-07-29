from __future__ import annotations

import ipaddress
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from mercury.planner import (
    ABSOLUTE_CEILINGS,
    DEFAULT_LIMITS,
    BudgetError,
    BudgetLimits,
    ConfirmationError,
    Transport,
    authorize_plan,
    confirmation_phrase,
    preview_plan,
    validate_plan,
)
from mercury.policy import (
    PolicyError,
    ScopeGrant,
    TargetKind,
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

    def test_fanout_and_unspecified_destinations_are_rejected_everywhere(self) -> None:
        unsafe = (
            "0.0.0.0",
            "::",
            "224.0.0.1",
            "ff02::1",
            "255.255.255.255",
            "224.0.0.0/24",
            "ff00::/8",
            "0.0.0.0/0",
            "::/0",
        )
        for value in unsafe:
            with self.subTest(value=value), self.assertRaises(PolicyError):
                parse_target(value)

        grant = ScopeGrant(
            networks=(ipaddress.ip_network("192.0.2.0/24"),),
            hostnames=("unsafe.test",),
            attested=True,
        )
        for answer in ("0.0.0.0", "224.0.0.1", "255.255.255.255", "ff02::1"):
            with self.subTest(answer=answer), self.assertRaises(PolicyError):
                resolve_for_plan(
                    parse_target("unsafe.test"),
                    grant,
                    resolver=lambda _, answer=answer: (answer,),
                    now=NOW,
                )

    def test_ipv6_link_local_scope_is_preserved(self) -> None:
        target = parse_target("fe80::1%Ethernet_2")
        self.assertEqual(target.canonical, "fe80::1%Ethernet_2")
        self.assertEqual(target.scope_id, "Ethernet_2")
        for value in ("2001:db8::1%eth0", "127.0.0.1%3", "fe80::1%bad scope"):
            with self.subTest(value=value), self.assertRaises(PolicyError):
                parse_target(value)

        grant = ScopeGrant(
            networks=(ipaddress.ip_network("fe80::/64"),),
            hostnames=("link.test",),
            attested=True,
        )
        snapshot = resolve_for_plan(
            parse_target("link.test"),
            grant,
            resolver=lambda _: (
                (10, 1, 6, "", ("fe80::1", 0, 0, 7)),
            ),
            now=NOW,
        )
        self.assertEqual(snapshot.addresses, ("fe80::1%7",))

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

    def test_dns_answer_must_remain_in_scope(self) -> None:
        grant = ScopeGrant(
            networks=(ipaddress.ip_network("192.0.2.10/32"),),
            hostnames=("example.test",),
            ports=(443,),
            transports=("tcp",),
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
        with self.assertRaisesRegex(PolicyError, "escaped scope"):
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
            ports=(443,),
            transports=("tcp",),
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
        with self.assertRaisesRegex(PolicyError, "escaped scope"):
            plan.preflight_addresses(
                target,
                resolver=lambda _: ("192.0.2.11",),
                now=NOW,
            )

    def test_dns_rotation_is_allowed_inside_the_granted_network(self) -> None:
        grant = ScopeGrant(
            networks=(ipaddress.ip_network("192.0.2.0/24"),),
            hostnames=("rotate.test",),
            attested=True,
        )
        snapshot = resolve_for_plan(
            parse_target("rotate.test"),
            grant,
            resolver=lambda _: ("192.0.2.10",),
            now=NOW,
        )
        self.assertEqual(
            recheck_resolution(
                snapshot,
                grant,
                resolver=lambda _: ("192.0.2.11",),
                now=NOW,
            ),
            ("192.0.2.11",),
        )

    def test_dns_rotation_cannot_increase_reserved_step_slots(self) -> None:
        grant = ScopeGrant(
            networks=(ipaddress.ip_network("192.0.2.0/24"),),
            hostnames=("rotate.test",),
            ports=(443,),
            transports=("tcp",),
            attested=True,
        )
        preview = preview_plan(
            target_values=("rotate.test",),
            ports=(443,),
            transports=("tcp",),
            grant=grant,
            resolver=lambda _: ("192.0.2.10",),
            now=NOW,
        )
        plan = authorize_plan(preview, now=NOW)
        with self.assertRaisesRegex(ConfirmationError, "cardinality"):
            plan.preflight_step(
                preview.steps[0].id,
                resolver=lambda _: ("192.0.2.11", "192.0.2.12"),
                now=NOW,
            )
        prepared = plan.preflight_step(
            preview.steps[0].id,
            resolver=lambda _: ("192.0.2.11",),
            now=NOW,
        )
        self.assertEqual(prepared.address, "192.0.2.11")
        self.assertTrue(prepared.dns_changed)

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
        self.assertEqual(len(preview.steps), 8)
        self.assertEqual(len({step.id for step in preview.steps}), 8)
        first = preview.steps[0]
        self.assertEqual(first.address, "127.0.0.1")
        self.assertEqual(first.transport, Transport.TCP)
        self.assertEqual(first.attempt, 1)
        self.assertEqual(first.cost.logical_attempts, 1)
        wire = preview.to_wire()
        self.assertEqual(len(wire["steps"]), 8)
        self.assertIn("max_global_rate", wire["limits"])
        self.assertIn("max_output_bytes", wire["limits"])

    def test_networks_compile_to_concrete_finite_steps(self) -> None:
        grant = ScopeGrant(
            networks=(ipaddress.ip_network("192.0.2.0/30"),),
            ports=(443,),
            transports=("tcp",),
            attested=True,
        )
        preview = preview_plan(
            target_values=("192.0.2.0/30",),
            ports=(443,),
            transports=("tcp",),
            grant=grant,
            repeats=2,
            now=NOW,
        )
        self.assertEqual(
            {step.address for step in preview.steps},
            {"192.0.2.1", "192.0.2.2"},
        )
        self.assertEqual(len(preview.steps), 4)
        self.assertTrue(
            all(step.target == "192.0.2.0/30" for step in preview.steps)
        )

    def test_every_budget_dimension_enforces_absolute_boundary(self) -> None:
        for name, maximum in ABSOLUTE_CEILINGS.to_wire().items():
            with self.subTest(name=name, boundary=maximum):
                replace(
                    ABSOLUTE_CEILINGS,
                    **{name: maximum},
                ).assert_within(ABSOLUTE_CEILINGS)
            with self.subTest(name=name, one_past=maximum + 1):
                unsafe = replace(
                    ABSOLUTE_CEILINGS,
                    **{name: maximum + 1},
                )
                with self.assertRaisesRegex(BudgetError, name):
                    unsafe.assert_within(ABSOLUTE_CEILINGS)

    def test_every_budget_dimension_requires_positive_exact_integer(self) -> None:
        minimum = {name: 1 for name in ABSOLUTE_CEILINGS.to_wire()}
        BudgetLimits(**minimum).assert_within(ABSOLUTE_CEILINGS)
        for name in minimum:
            for invalid in (0, True):
                with self.subTest(name=name, invalid=invalid):
                    values = {**minimum, name: invalid}
                    with self.assertRaisesRegex(BudgetError, name):
                        BudgetLimits(**values)

    def test_plan_scalar_boundaries_are_table_driven(self) -> None:
        common = {
            "target_values": ("127.0.0.1",),
            "ports": (53,),
            "transports": ("udp",),
            "grant": ScopeGrant(networks=()),
            "now": NOW,
        }
        cases = (
            ("repeats", 1, 0),
            ("repeats", 100, 101),
            ("payload_bytes_per_attempt", 0, -1),
            ("payload_bytes_per_attempt", 1_400, 1_401),
            ("datagrams_per_udp_attempt", 1, 0),
            ("datagrams_per_udp_attempt", 100, 101),
        )
        for name, boundary, invalid in cases:
            with self.subTest(name=name, boundary=boundary):
                preview_plan(**common, **{name: boundary})
            with self.subTest(name=name, invalid=invalid), self.assertRaises(
                BudgetError
            ):
                preview_plan(**common, **{name: invalid})

        for port in (1, 65_535):
            with self.subTest(valid_port=port):
                preview_plan(**{**common, "ports": (port,)})
        for port in (0, 65_536):
            with self.subTest(invalid_port=port), self.assertRaises(BudgetError):
                preview_plan(**{**common, "ports": (port,)})

    def test_estimated_work_dimensions_enforce_configured_limits(self) -> None:
        loopback = {
            "target_values": ("127.0.0.1",),
            "ports": (53,),
            "transports": ("tcp",),
            "grant": ScopeGrant(networks=()),
            "now": NOW,
        }
        network = ipaddress.ip_network("192.0.2.0/30")
        cases = (
            (
                "max_hosts",
                2,
                {
                    **loopback,
                    "target_values": (str(network),),
                    "grant": ScopeGrant(
                        networks=(network,),
                        ports=(53,),
                        transports=("tcp",),
                        attested=True,
                    ),
                },
            ),
            ("max_ports", 2, {**loopback, "ports": (53, 54)}),
            ("max_attempts", 2, {**loopback, "ports": (53, 54)}),
            (
                "max_datagrams",
                2,
                {
                    **loopback,
                    "transports": ("udp",),
                    "datagrams_per_udp_attempt": 2,
                },
            ),
            (
                "max_application_bytes",
                2,
                {
                    **loopback,
                    "transports": ("udp",),
                    "payload_bytes_per_attempt": 2,
                },
            ),
            ("max_events", 6, loopback),
            ("max_output_bytes", 4_608, loopback),
        )

        def limits_for(name: str, value: int) -> BudgetLimits:
            changes = {name: value}
            if name == "max_attempts":
                changes["max_concurrency"] = value
            return replace(DEFAULT_LIMITS, **changes)

        for name, boundary, arguments in cases:
            with self.subTest(name=name, boundary=boundary):
                preview_plan(
                    **arguments,
                    limits=limits_for(name, boundary),
                )
            with self.subTest(name=name, one_below=boundary - 1):
                with self.assertRaises(BudgetError):
                    preview_plan(
                        **arguments,
                        limits=limits_for(name, boundary - 1),
                    )

    def test_target_and_transport_enums_have_public_examples(self) -> None:
        targets = (
            parse_target("127.0.0.1"),
            parse_target("192.0.2.0/24"),
            parse_target("example.test"),
        )
        self.assertEqual({target.kind for target in targets}, set(TargetKind))
        preview = preview_plan(
            target_values=("127.0.0.1",),
            ports=(53,),
            transports=("tcp", "udp"),
            grant=ScopeGrant(networks=()),
            now=NOW,
        )
        self.assertEqual({step.transport for step in preview.steps}, set(Transport))

    def test_cross_product_is_rejected_cheaply(self) -> None:
        grant = ScopeGrant(
            networks=(ipaddress.ip_network("10.0.0.0/8"),),
            ports=tuple(range(1, 65_536)),
            transports=("tcp",),
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
        payload = b"A" * 32
        preview = preview_plan(
            target_values=("127.0.0.1",),
            ports=(9,),
            transports=("udp",),
            grant=ScopeGrant(networks=()),
            udp_payload=payload,
            now=NOW,
        )
        self.assertEqual(preview.required_confirmations, ("custom_udp",))
        self.assertEqual(preview.steps[0].payload.length, len(payload))
        self.assertEqual(
            preview.steps[0].payload.sha256,
            "22a48051594c1949deed7040850c1f0f8764537f5191be56732d16a54c1d8153",
        )
        self.assertNotIn("AAAAAAAA", repr(preview.to_wire()))
        phrase = confirmation_phrase("custom_udp", preview.digest)
        plan = authorize_plan(preview, confirmations=(phrase,), now=NOW)
        with self.assertRaisesRegex(ConfirmationError, "hash"):
            plan.preflight_step(
                preview.steps[0].id,
                payload=b"B" * 32,
                now=NOW,
            )
        prepared = plan.preflight_step(
            preview.steps[0].id,
            payload=payload,
            now=NOW,
        )
        self.assertEqual(prepared.step.payload.length, 32)

        other = preview_plan(
            target_values=("127.0.0.1",),
            ports=(9,),
            transports=("udp",),
            grant=ScopeGrant(networks=()),
            udp_payload=b"B" * 32,
            now=NOW,
        )
        self.assertNotEqual(preview.digest, other.digest)

    def test_custom_udp_metadata_is_required_and_never_raw(self) -> None:
        with self.assertRaisesRegex(BudgetError, "bytes or a SHA-256"):
            preview_plan(
                target_values=("127.0.0.1",),
                ports=(9,),
                transports=("udp",),
                grant=ScopeGrant(networks=()),
                payload_bytes_per_attempt=16,
                custom_udp_payload=True,
                now=NOW,
            )
        preview = preview_plan(
            target_values=("127.0.0.1",),
            ports=(9,),
            transports=("udp",),
            grant=ScopeGrant(networks=()),
            payload_bytes_per_attempt=16,
            payload_sha256="ab" * 32,
            now=NOW,
        )
        self.assertEqual(preview.steps[0].payload.sha256, "ab" * 32)

    def test_defaults_are_strictly_below_absolutes(self) -> None:
        DEFAULT_LIMITS.assert_within(ABSOLUTE_CEILINGS)
        for name, maximum in ABSOLUTE_CEILINGS.to_wire().items():
            self.assertLessEqual(DEFAULT_LIMITS.to_wire()[name], maximum)

    def test_scope_grant_has_exact_types_and_port_transport_envelope(self) -> None:
        with self.assertRaises(PolicyError):
            ScopeGrant(networks=(), attested="false")  # type: ignore[arg-type]
        with self.assertRaises(PolicyError):
            ScopeGrant(networks=("192.0.2.0/24",))  # type: ignore[arg-type]
        with self.assertRaises(PolicyError):
            ScopeGrant(networks=(ipaddress.ip_network("0.0.0.0/0"),))

        grant = ScopeGrant(
            networks=(ipaddress.ip_network("192.0.2.10/32"),),
            ports=(443,),
            transports=("tcp",),
            attested=True,
        )
        preview_plan(
            target_values=("192.0.2.10",),
            ports=(443,),
            transports=("tcp",),
            grant=grant,
            now=NOW,
        )
        for port, transport in ((80, "tcp"), (443, "udp")):
            with self.subTest(port=port, transport=transport), self.assertRaises(
                ConfirmationError
            ):
                preview_plan(
                    target_values=("192.0.2.10",),
                    ports=(port,),
                    transports=(transport,),
                    grant=grant,
                    now=NOW,
                )

    def test_authorization_recompiles_public_plan_objects(self) -> None:
        preview = preview_plan(
            target_values=("127.0.0.1",),
            ports=(443,),
            transports=("tcp",),
            grant=ScopeGrant(networks=()),
            now=NOW,
        )
        with self.assertRaisesRegex(ConfirmationError, "canonical"):
            authorize_plan(replace(preview, digest="0" * 64), now=NOW)
        forged_estimate = replace(
            preview.estimate,
            logical_attempts=preview.estimate.logical_attempts + 1,
        )
        with self.assertRaisesRegex(ConfirmationError, "canonical"):
            authorize_plan(replace(preview, estimate=forged_estimate), now=NOW)
        forged_scope = replace(
            preview,
            targets=(parse_target("203.0.113.9"),),
            scope=ScopeGrant(networks=()),
        )
        with self.assertRaises((PolicyError, ConfirmationError)):
            authorize_plan(forged_scope, now=NOW)

        plan = authorize_plan(preview, now=NOW)
        self.assertIs(validate_plan(plan, now=NOW), plan)
        with self.assertRaises(ConfirmationError):
            validate_plan(
                replace(plan, confirmations=("AUTHORIZE FULL TCP 000000000000",)),
                now=NOW,
            )


if __name__ == "__main__":
    unittest.main()
