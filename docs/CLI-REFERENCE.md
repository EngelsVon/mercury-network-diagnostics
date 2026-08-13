<!-- generated-by: gsd-doc-writer -->
# CLI reference

Mercury's console entry point is `mercury`; `python -m mercury` is equivalent. Run active commands only for explicitly authorized private scope.

## Global syntax

```text
mercury [--version] [--json] [--data-path PATH] COMMAND ...
```

Global options must precede the command. Most subcommands also accept their own `--json` flag.

| Option | Meaning |
| --- | --- |
| `--version` | Print the package version and exit. |
| `--json` | Emit stable JSON. |
| `--data-path PATH` | Override the SQLite history path. |

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Successful passive/task result or healthy conclusion. |
| `1` | Explicit failed task/diagnosis conclusion. |
| `2` | Invalid input. |
| `3` | Authorization, scope, budget, or confirmation policy rejection. |
| `4` | Partial, mixed, cancelled, silent, unavailable, or inconclusive result. |
| `70` | Internal/result-contract error. |

## Informational and passive commands

### `version`

```bash
mercury version [--json]
```

Print component versions.

### `model`

```bash
mercury model [--json]
```

Print evidence semantics and immutable absolute ceilings. Silence remains inconclusive.

### `status`

```bash
mercury status [--json]
```

Collect passive local host, interface, route, DNS, neighbor, Wi-Fi, LLDP, and capability evidence as available on the platform.

## Diagnosis, discovery, mapping, and trace

### `diagnose`

```text
mercury diagnose [--profile basic] [--target HOST:PORT ...] [--timeout SECONDS] [--authorized] [--json]
```

`--target` is repeatable and switches to a custom exact endpoint set. Timeout defaults to `3.0` and must be within `0.1..30`. Non-loopback targets require `--authorized`; resolved addresses are rechecked against private scope.

```bash
mercury diagnose --profile basic --authorized
mercury diagnose --target <PRIVATE-HOST>:443 --target [::1]:443 --timeout 3 --authorized --json
```

### `discover`

```text
mercury discover --passive [--json]
mercury discover --network CIDR --scope CIDR [--profile common|custom|full] [--ports PORTS] [--timeout SECONDS] [--authorized] [--confirm PHRASE ...] [--json]
```

Passive discovery cannot be combined with active options. Active discovery is bounded IPv4 TCP discovery. `custom` requires `--ports`; `full` is the finite `1..65535` profile and requires the digest-bound confirmation shown by its preview—not an unbounded or all-protocol scan.

```bash
mercury discover --passive
mercury discover --network <PRIVATE-CIDR> --scope <AUTHORIZED-PRIVATE-CIDR> --profile common --authorized
```

### `mapping`

```text
mercury mapping --cidr CIDR [--cidr CIDR ...] --profiles LIST --ports PORTS [--rate N] [--concurrency N] [--duration SECONDS] [--authorized] [--json]
```

Defaults: rate `10` logical attempt starts/second, concurrency `1`, duration `0`. CIDRs are repeatable private IPv4 ranges. Direct profiles are `tcp_connect`, `tcp_tagged`, `udp_tagged`, `dns_udp`, `dns_tcp`, `tls_handshake`, `http_exchange`, and `ssh_banner`. Native profiles are `nmap_tcp_connect`, `nmap_tcp_syn`, `nmap_udp`, and `nmap_sctp_init`; select exactly one native profile in a task.

```bash
mercury mapping --cidr <PRIVATE-CIDR-A> --cidr <PRIVATE-CIDR-B> --profiles tcp_connect,udp_tagged --ports 53,80,443 --rate 20 --concurrency 4 --duration 60 --authorized
```

Duration `0` means no additional operator cutoff within normal immutable ceilings, not unlimited work.

### `trace`

```text
mercury trace TARGET --scope CIDR [--hops N] [--repeat N] [--timeout SECONDS] [--authorized] [--json]
```

`TARGET` is one numeric admitted private IP. Defaults are 8 hops, 3 repeats, and 1-second per-hop wait. Unanswered and alternate hops remain evidence; a route hop is not labeled a switch.

```bash
mercury trace <PRIVATE-IP> --scope <AUTHORIZED-PRIVATE-CIDR> --authorized
```

## Plan preview

```text
mercury plan TARGET [TARGET ...] [--ports PORTS] [--transport tcp|udp ...]
  [--repeat N] [--payload-bytes N] [--payload-sha256 HEX]
  [--payload-profile NAME] [--datagrams N] [--authorized]
  [--scope CIDR ...] [--name HOSTNAME ...] [--purpose TEXT]
  [--custom-udp] [--absolute-limits] [--json]
```

Defaults are ports `80,443`, TCP, one repeat, no payload, one UDP datagram, and purpose `interactive diagnosis`. The command canonicalizes and costs work without executing it. `--payload-sha256` records approved custom UDP payload metadata; raw payload is never persisted. `--absolute-limits` previews against hard ceilings and does not remove them.

## Authenticated peers

### `agent`

```text
mercury agent --config FILE [--unsafe-development] [--json]
```

Start the closed peer-control listener and configured short-lived receivers. Non-loopback configuration requires mTLS, token, and certificate pinning. `--unsafe-development` is loopback-only.

### `paired`

```text
mercury paired --config FILE --identity ID --address PEER-DATA-IP [--timeout SECONDS] [--authorized] [--unsafe-development] [--json]
```

Run the fixed paired profile. The identity and address must equal the configuration; there is no CLI target/port/payload control. Timeout defaults to `3.0` and is bounded to `0.1..30`.

### `coverage`

```text
mercury coverage --config FILE --identity ID --address PEER-DATA-IP --profiles LIST
  [--timeout SECONDS] [--local-network CIDR] [--peer-network CIDR]
  [--authorized] [--unsafe-development] [--json]
```

Profiles must exactly equal the configured set. The receiver-capable matrix is TCP tagged/connect, UDP tagged, DNS over UDP/TCP, TLS handshake, HTTP exchange, and SSH banner. ICMP echo is native with peer arrival only where supported. ARP/IPv6 ND are passive same-link evidence; use both network options to establish applicability.

```bash
mercury coverage --config <LOCAL-PEER.json> --identity <PAIR-ID> --address <CONFIGURED-PEER-DATA-IP> --profiles <EXACT-CONFIGURED-PROFILE-LIST> --local-network <LOCAL-PRIVATE-CIDR> --peer-network <PEER-PRIVATE-CIDR> --timeout 3 --authorized
```

Results keep both directions and explicit candidate-carrier, direct-negative, inconclusive, unsupported, permission-denied, skipped, and not-applicable outcomes. They do not prove every possible packet kind or tunnel absent.

## WebUI

```text
mercury web [--bind NUMERIC-IP] [--port N] [--cert FILE] [--key FILE] [--token-file FILE]
```

Defaults to `127.0.0.1:8765`; port `0` selects a free port. A non-loopback bind requires certificate, key, and token file:

```bash
mercury web --bind <LOCAL-PRIVATE-IP> --port 8765 --cert <WEB-CERT.pem> --key <WEB-KEY.pem> --token-file <WEB-TOKEN.txt>
```

## History

### `history list`

```bash
mercury history list [--limit N] [--json]
```

List recent tasks; default limit is 50.

### `history show`

```bash
mercury history show TASK_ID [--json]
```

### `history compare`

```bash
mercury history compare LEFT_TASK_ID RIGHT_TASK_ID [--json]
```

Only compatible completed task kinds/model schemas can be compared. Missing evidence is not a failed observation.

### `history export`

```bash
mercury history export TASK_ID [--format json|html] [--retain-sensitive] [--json]
```

Format defaults to JSON. Default output redacts identifiers and payloads. `--retain-sensitive` retains those fields but credentials, tokens, and private keys remain redacted.

## Offline developer command

`mercury task synthetic [--steps N] [--delay SECONDS] [--cancel-after SECONDS] [--json]` exercises the bounded lifecycle without network I/O. It is intentionally hidden from the top-level help and is not an operator scanning command.

## Safety interpretation

- Public, documentation, multicast, unspecified, broadcast, and scope-escaping resolved destinations fail before active I/O.
- `--authorized` is an explicit attestation, not a bypass of destination or budget policy.
- TCP refusal/reset, timeout, UDP response/silence, ICMP unreachable, unsupported, permission denied, and execution error remain distinct.
- Nmap states have native provenance and are not rewritten as direct Mercury socket observations.
- A positive correlated result identifies a tested candidate carrier. A silent or negative finite matrix cannot establish a universal absence of tunnels or arbitrary packet sequences.
