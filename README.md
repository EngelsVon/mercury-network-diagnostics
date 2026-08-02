# Mercury

Mercury is a local-first, evidence-first internal-network diagnostics tool. It
reports what was observed for selected private endpoints and layers; it is not a
topology oracle or a replacement for MTR, iperf3, or LLDP tooling.

## Installation

Mercury supports CPython 3.11+ and has one runtime dependency, `psutil`.

```powershell
uv tool install mercury-netdiag
mercury --help
```

For a checkout, use `uv run --no-sync python -m mercury --help`. Linux users
can use the identical command in an Ubuntu shell. Mercury v1 supports Windows
and Ubuntu; macOS and other platforms explicitly report unsupported capability
evidence and are not release targets.

## Quick start

`status` is passive and collects local host, interface, route, DNS, capability,
and limitation evidence:

```powershell
uv run --no-sync python -m mercury status
uv run --no-sync python -m mercury status --json
```

Run diagnosis only for private endpoints you own or are authorized to test.
The immutable `basic-v1` profile uses loopback; custom endpoints are exact
repeatable private `HOST:PORT` values, including `[::1]:443`.

```powershell
uv run --no-sync python -m mercury diagnose --profile basic --authorized
uv run --no-sync python -m mercury diagnose --target example.internal:443 --target [::1]:443 --timeout 3 --authorized --json
```

Timeouts are finite and inclusive: `0.1..30` seconds. DNS results can change
between planning and connection; Mercury rechecks the admitted numeric address
and reports a scoped rejection rather than silently switching destinations.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Passive status completed, or diagnosis health is `healthy` |
| 1 | Diagnosis has explicit selected-endpoint failure evidence |
| 2 | Invalid command input |
| 3 | Authorization or scope policy rejected the operation |
| 4 | Diagnosis is partial, mixed, silent, unavailable, or inconclusive |
| 70 | Internal result-contract error |

## Platform capabilities

Windows and Ubuntu are Mercury's supported platforms. Ordinary-user status
collection reports each native adapter's available, unavailable, permission, or
error state. Optional native ping/path tools degrade explicitly. A gateway,
ARP/NDP neighbor, or first route hop is not an observed access switch: status
states `Access switch: not observable` until direct LLDP or managed evidence
exists. Other platforms, including macOS, return explicit unsupported capability
evidence and are not supported release targets.

| Capability | Windows | Ubuntu | macOS / other |
| --- | --- | --- | --- |
| Passive status, interfaces, routes and DNS | Supported with typed adapter evidence | Supported with typed adapter evidence | Explicitly unsupported |
| Passive neighbor / Wi-Fi / direct LLDP enrichment | Best-effort capability evidence | Best-effort capability evidence | Explicitly unsupported |
| Native ping and route trace | Uses bounded native commands when present | Uses bounded native commands when present | Explicitly unsupported |
| Paired and Web modes | Supported subject to configured trust | Supported subject to configured trust | Not a v1 release target |

### Operator release smoke (Windows and Ubuntu)

Run this procedure only on a device and network you administer. It makes no
public or third-party scan.

1. From a clean checkout, run `uv run --no-sync python -m unittest discover -s tests -v`.
2. Run `uv run --no-sync python -m mercury status --json` and confirm that the
   platform, route/DNS and capability/degradation observations are explicit.
3. Run `uv run --no-sync python -m mercury discover --passive` and confirm it
   does not call an active profile.
4. On an owned loopback or lab CIDR, preview and run one authorized common TCP
   discovery, then one authorized bounded trace. Confirm refusal, timeout and
   unanswered-hop evidence are not relabeled as success.
5. Start `uv run --no-sync python -m mercury web`, open the shown loopback URL,
   submit passive status and verify task polling/cancellation. Do not bind it
   remotely without certificate, key and token file.
6. If two lab endpoints are configured, run the operator-provisioned paired
   profile in both directions and retain its directional matrix. Never use an
   unconfigured address.

## Authenticated paired diagnostics

Paired diagnostics use two reciprocal, operator-provisioned configurations. The
CLI never accepts a data-plane target, CIDR, port, or payload. Each file fixes
one peer address, a TCP port, a UDP port, and a finite profile timeout; the two
endpoints use the same pair identity and ports, with their own local bind and
peer address reversed.

```json
{
  "identity": "campus-pair-01",
  "bind_host": "10.20.30.10",
  "control_port": 9443,
  "peer_addresses": ["10.20.30.20"],
  "peer_pins": ["sha256:<configured-peer-certificate-fingerprint>"],
  "certificate_path": "server-cert.pem",
  "key_path": "server-key.pem",
  "ca_path": "trusted-client-ca.pem",
  "token_path": "pair-token",
  "paired": {"tcp_port": 45001, "udp_port": 45002, "timeout_s": 3.0}
}
```

Secret values stay in the referenced files, never in the configuration or CLI.
Start the agent on both endpoints, then invoke `mercury paired --config ...
--identity campus-pair-01 --address <configured-peer-IP> --timeout 3
--authorized`. Non-loopback operation requires mTLS, a configured certificate
pin, and a token. `--unsafe-development` is loopback-only.

### Coverage receiver configuration

For two-endpoint coverage, each reciprocal peer file adds a local `receivers`
table and an explicit `coverage_profiles` list. Receiver ports are fixed by the
administrator; the coverage command cannot provide a listener address, port,
payload, or receiver profile to the other peer.

```json
{
  "receivers": [
    {"profile": "tcp_tagged", "bind_host": "172.26.4.10", "port": 45101, "timeout_s": 3},
    {"profile": "udp_tagged", "bind_host": "172.26.4.10", "port": 45102, "timeout_s": 3},
    {"profile": "dns_udp", "bind_host": "172.26.4.10", "port": 45103, "timeout_s": 3},
    {"profile": "dns_tcp", "bind_host": "172.26.4.10", "port": 45104, "timeout_s": 3},
    {"profile": "http_exchange", "bind_host": "172.26.4.10", "port": 45105, "timeout_s": 3},
    {"profile": "ssh_banner", "bind_host": "172.26.4.10", "port": 45106, "timeout_s": 3}
  ],
  "coverage_profiles": ["tcp_connect", "tcp_tagged", "udp_tagged", "dns_udp", "dns_tcp", "http_exchange", "ssh_banner", "icmp_echo", "arp", "ipv6_nd"]
}
```

Add `tls_handshake` only with its own receiver entry and a fixed `tls` object
containing certificate, key, CA, and server-name paths. The normal peer-control
fields—local certificate/key/CA paths, token path, one fixed peer address, and
the peer certificate pin—remain required for a non-loopback agent. Start each
endpoint with `mercury agent --config peer.json`; then invoke `coverage` from
one endpoint using that same configured identity and peer address.

## Discovery and routes

Start with passive discovery; it reads local IPv4 interface, route, neighbor,
Wi-Fi and optional direct-LLDP evidence without sending probes. It does not
identify a switch from a gateway, ARP/NDP entry or route hop.

```powershell
uv run --no-sync python -m mercury discover --passive
uv run --no-sync python -m mercury discover --network 10.20.30.0/30 --scope 10.20.30.0/24 --profile common --authorized
uv run --no-sync python -m mercury trace 10.20.30.10 --scope 10.20.30.0/24 --authorized
```

Active discovery is TCP-only and requires an authorized CIDR. `common` is the
normal bounded profile; `custom` requires an explicit port list. `full` is a
finite 1–65535 TCP plan and requires the digest-bound confirmation printed by
the preview. Native route tracing is repeated and retains unanswered or
alternate hops; it does not claim one certain path.

## Internal mapping and two-endpoint coverage

`mapping` expands one or more RFC1918/loopback IPv4 CIDRs into a single
immutable, outbound plan. Select only named profiles and ports; its rate is
logical attempt starts per second, and `--duration 0` means "finish the
selected plan where possible" within compiled hard ceilings, not an unlimited
scan.

```powershell
uv run --no-sync python -m mercury mapping --cidr 172.26.4.0/24 --cidr 172.27.20.0/24 --profiles tcp_connect,udp_tagged --ports 53,80,443 --rate 20 --concurrency 4 --duration 0 --authorized
uv run --no-sync python -m mercury mapping --cidr 172.26.4.0/24 --profiles nmap_tcp_connect --ports 1-1024 --rate 20 --concurrency 4 --duration 0 --authorized
```

Nmap selection is optional and closed: `nmap_tcp_connect`, `nmap_tcp_syn`,
`nmap_udp`, and `nmap_sctp_init` are the only native profiles. Mercury derives
their arguments from the approved plan; there is no `--nmap-args`, script,
proxy, decoy, target-file, payload, or arbitrary destination option. Native
results retain Nmap `open`, `closed`, `filtered`, and `open|filtered` as native
provenance, rather than claiming that Mercury observed an equivalent direct
socket response. Missing Nmap or native privilege is capability evidence.

For a directed isolation-boundary assessment, provision reciprocal Mercury
peers with fixed receiver profile ports, start an agent on both, then run the
configured matrix from the initiating endpoint:

```powershell
uv run --no-sync python -m mercury coverage --config peer.json --identity campus-pair-01 --address 172.27.20.20 --profiles tcp_tagged,udp_tagged,dns_udp,dns_tcp,icmp_echo,tls_handshake,http_exchange,ssh_banner,arp,ipv6_nd --local-network 172.26.4.0/24 --peer-network 172.27.20.0/24 --authorized
```

Receivers record only configured short-lived leases and correlate a fixed
Mercury test record in both directions. TCP, UDP, DNS-over-UDP/TCP, ICMP echo,
TLS, HTTP, and SSH-banner tests are available when configured; no login or
credentials are attempted. ARP and IPv6 ND are passive same-link evidence:
between different subnets they are explicitly `not_applicable`, never evidence
that the remote peer was reached.

An assessment can identify a tested candidate carrier, for example a tagged
UDP/DNS message whose peer receipt matches. It cannot establish that every
untested custom packet sequence or tunnel is impossible. Each result records
the profile, port, direction, packet shape, time window, evidence, and gaps.

## Web dashboard and history reports

The dashboard uses the same `MercuryApplication` service boundary as the CLI;
browser code never probes a network directly.

```powershell
uv run --no-sync python -m mercury web
```

Open the printed loopback address in a browser. The default listener accepts
only loopback requests. It validates Host, same-origin mutations, a SameSite
session cookie, CSRF header and bounded JSON bodies; responses include a CSP.
For an intentional non-loopback listener, provide a numeric bind address,
certificate, key and token file:

```powershell
uv run --no-sync python -m mercury web --bind 10.20.30.10 --cert web-cert.pem --key web-key.pem --token-file web-token.txt
```

The token stays in its local file and is never printed or persisted. Web mode
does not expose peer-agent control.

Completed local tasks can be compared only when their kind and model schema are
compatible. Missing evidence means it was absent from one run, not that the
network failed. Exports redact credentials unconditionally and redact
hostnames, addresses, MACs and payloads by default.

```powershell
uv run --no-sync python -m mercury history list
uv run --no-sync python -m mercury history compare <older-task-id> <newer-task-id>
uv run --no-sync python -m mercury history export <task-id> --format html
```

`--retain-sensitive` is an explicit local export choice for identifiers and
payloads. It never retains credentials, tokens or private keys.

## Safety and limitations

- Active work is normalized, authorized, admitted, rate-limited, and bounded
  before it starts. Public, documentation, multicast, unspecified, and
  broadcast destinations are rejected before I/O.
- DNS, TCP, TLS, HTTP, native ping, and path observations retain separate
  outcomes; silence and timeout are inconclusive, not success or failure.
- Diagnosis conclusions cover only the selected endpoints and observed layers;
  Mercury never makes a universal Internet or root-cause claim.
- Tests use fakes and loopback only. They never resolve or connect to real
  non-loopback targets.
- SQLite history rejects credentials and secret material; reports repeat that
  protection by default.
- If a native command is absent or permission is insufficient, inspect the
  capability evidence instead of treating the result as a connectivity claim.
- A finite matrix can prove that one emitted carrier worked, or show a direct
  profile-specific negative; it cannot prove that no arbitrary tunnel, packet
  mutation, or unknown protocol can ever cross the boundary.
- For a refused TCP connection, inspect the TCP observation; for timeouts or
  UDP silence, treat the result as inconclusive and compare a controlled second
  endpoint or route trace where authorized.

## Verification and non-goals

Run the controlled suite from a checkout:

```powershell
uv run --no-sync python -m unittest discover -s tests -v
uv run --no-sync python -m compileall -q src tests
uv run --no-sync ruff check src tests
uv build
```

Tests use fakes, fixtures and loopback only. Mercury does not scan unowned
networks, evade network controls, enumerate all packet kinds, identify an L2
switch without direct evidence, provide a remote Web/peer control plane, or
replace Nmap, iperf3, MTR, packet capture or centralized fleet management.
