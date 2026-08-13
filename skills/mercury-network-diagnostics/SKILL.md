---
name: mercury-network-diagnostics
description: Operate and interpret the Mercury private-network diagnostics CLI, agent, and WebUI. Use when an intelligent agent needs to install Mercury, collect passive network facts, plan or run authorized RFC1918/ULA reachability checks, map selected ports, coordinate two configured Mercury peers, use Mercury's fixed Nmap profiles, inspect history, or explain evidence without treating silence as proof.
---

# Mercury network diagnostics

Use Mercury only on private networks the operator owns or is authorized to assess. Keep every command inside the operator-declared scope. Never transform Mercury into a public scanner, credential tester, arbitrary Nmap wrapper, packet-crafting interface, or third-party relay.

## Establish facts first

1. Run `mercury version` and `mercury --help`.
2. Read the relevant subcommand help before composing arguments.
3. Run `mercury model` when exact evidence states or current ceilings matter.
4. Prefer human-readable output for operators. Add `--json` only when structured output is required.
5. Read [references/commands.md](references/commands.md) for command patterns and [references/evidence.md](references/evidence.md) before interpreting results.

Do not assume a repository checkout. If operating in one, prefer its documented environment command, such as `uv run --no-sync python -m mercury`. Otherwise use the installed `mercury` entry point.

## Choose the smallest fitting workflow

- Use `status` for passive local interfaces, routes, DNS, neighbors, Wi-Fi, LLDP capability, and limitations.
- Use `discover --passive` before active discovery.
- Use `diagnose` for one or more selected private endpoints.
- Use `trace` for bounded route evidence to one numeric private address.
- Use `mapping` for one immutable plan spanning selected private IPv4 CIDRs, profiles, and ports.
- Use `coverage` only when reciprocal administrator-provisioned Mercury peers are already configured and their agents are running.
- Use `history` to inspect, compare, or export completed local tasks.
- Use `web` for the local dashboard; a non-loopback bind requires TLS and a token file.

## Active-work procedure

1. Restate the target CIDRs or endpoints, direction, profiles, ports, rate, concurrency, and duration.
2. Verify every destination is loopback, RFC1918 IPv4, IPv6 ULA, or a correctly scoped IPv6 link-local address.
3. Obtain the operator's explicit authorization statement before adding `--authorized`. Do not infer authorization merely from private addressing.
4. Preview unusual custom work with `mercury plan` or the relevant command's documented confirmation flow.
5. Execute through Mercury, never by reconstructing an unrestricted native command.
6. Report the terminal reason, attempted/finished counts, positive carrier evidence, negative observations, silent outcomes, unsupported capabilities, and coverage gaps separately.

`--duration 0` means no operator-selected early cutoff; immutable ceilings still apply. Never describe it as unlimited.

## Paired coverage procedure

1. Confirm reciprocal configuration files exist on both endpoints and contain the same identity, trusted peer control addresses, certificate pins, CA trust, token references, and matching receiver profile/port tables.
2. Keep secret values in referenced files. Never print tokens, private keys, passwords, or full certificates.
3. Start `mercury agent --config <peer.json>` on both endpoints.
4. Run `coverage` using only the configured identity, peer address, and configured finite profile list.
5. Treat a peer-correlated arrival or reply as a candidate communication carrier for that tested direction and packet shape.
6. Treat timeout, UDP silence, missing privilege, unavailable capture, and non-applicable ARP/ND as explicit gaps or scoped outcomes—not proof of isolation.

ARP and IPv6 ND are same-link evidence. Mark them not applicable across subnets. Optional Nmap profiles are local native evidence, not Mercury peer-receipt evidence.

## Native Nmap

Use only Mercury's fixed profiles: `nmap_tcp_connect`, `nmap_tcp_syn`, `nmap_udp`, and `nmap_sctp_init`. Let Mercury derive the arguments from the admitted plan. Never add arbitrary flags, NSE scripts, decoys, proxies, target files, custom payloads, or alternate destinations.

If Nmap is absent or privilege is insufficient, report the capability state and remediation. Do not silently replace the profile with a different scan.

## Result language

Lead with what Mercury observed in the recorded window. Use statements such as:

- "The peer recorded the tagged UDP payload in direction A to B; this tested profile is a candidate carrier."
- "TCP connection attempts timed out on the selected ports; no response was observed."
- "No candidate carrier was observed among the completed finite profiles; listed gaps remain."

Never say that all ports, all protocols, all packet forms, or all tunnels are impossible unless those exact finite items were completed—and even then limit the statement to the recorded directions, packet shapes, and time window. A finite test cannot prove a universal negative.

## Protect evidence

- Redact credentials unconditionally.
- Redact hostnames, IP addresses, MAC addresses, and payload details unless the operator explicitly needs a local sensitive export.
- Do not paste raw JSON when an operator asked for a clear result; summarize the decision-relevant fields and retain task IDs for traceability.
- Do not label a gateway, route hop, or neighbor as a switch without direct LLDP or managed evidence.
