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
