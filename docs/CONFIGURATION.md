<!-- generated-by: gsd-doc-writer -->
# Configuration

Mercury has no application `.env` file. Configuration comes from CLI options, two standard OS environment variables used only to choose the default history path, WebUI certificate/token files, and strict peer JSON files.

## Environment variables

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `LOCALAPPDATA` | No | `~/AppData/Local` on Windows | Base directory for `Mercury/history.sqlite3`. |
| `XDG_DATA_HOME` | No | `~/.local/share` on non-Windows systems | Base directory for `mercury/history.sqlite3`. |

No environment variable supplies Mercury peer tokens, certificates, destinations, scan profiles, or WebUI credentials. Use file paths and CLI arguments described below.

## History configuration

The default database paths are:

- Windows: `%LOCALAPPDATA%\Mercury\history.sqlite3`
- Ubuntu: `${XDG_DATA_HOME:-~/.local/share}/mercury/history.sqlite3`

Override the path with the global option before the subcommand:

```bash
mercury --data-path <HISTORY.sqlite3> status
mercury --data-path <HISTORY.sqlite3> history list
```

History and reports reject credential, token, and private-key material. Exports redact identifiers and payloads by default; `history export --retain-sensitive` may retain those identifiers and payloads, but never credentials.

## WebUI configuration

| Option | Required | Default | Description |
| --- | --- | --- | --- |
| `--bind` | No | `127.0.0.1` | Numeric admitted private address. |
| `--port` | No | `8765` | Listener port; `0` selects a free port. |
| `--cert` | For non-loopback | None | TLS certificate path. Must be paired with `--key`. |
| `--key` | For non-loopback | None | TLS private-key path. Must be paired with `--cert`. |
| `--token-file` | For non-loopback | None | Readable file containing a non-empty token of at most 512 characters. |

Loopback example:

```bash
mercury web --bind 127.0.0.1 --port 8765
```

Non-loopback example:

```bash
mercury web --bind <LOCAL-PRIVATE-IP> --port 8765 --cert <WEB-CERT.pem> --key <WEB-KEY.pem> --token-file <WEB-TOKEN.txt>
```

The WebUI uses server TLS plus its token. This is distinct from the peer agent, which requires mTLS, a token, and certificate pinning for non-loopback operation.

## Peer JSON format

All paths may be absolute or relative to the JSON file. Secret values belong in the referenced files, not in JSON. The following is a template, not a ready-to-run configuration:

```json
{
  "identity": "<PAIR-ID>",
  "bind_host": "<LOCAL-DATA-IP>",
  "control_bind_host": "<LOCAL-CONTROL-IP>",
  "control_port": 9443,
  "peer_addresses": ["<PEER-DATA-IP>"],
  "control_peer_addresses": ["<PEER-CONTROL-IP>"],
  "peer_pins": ["sha256:<64-lowercase-hex-digits>"],
  "certificate_path": "<LOCAL-PEER-CERT.pem>",
  "key_path": "<LOCAL-PEER-KEY.pem>",
  "ca_path": "<TRUSTED-CLIENT-CA.pem>",
  "token_path": "<PAIR-TOKEN.txt>",
  "server_hostname": "<PEER-CERTIFICATE-NAME>",
  "paired": {
    "tcp_port": 45001,
    "udp_port": 45002,
    "timeout_s": 3.0
  },
  "receivers": [
    {"profile": "tcp_tagged", "bind_host": "<LOCAL-DATA-IP>", "port": 45101, "timeout_s": 3.0},
    {"profile": "udp_tagged", "bind_host": "<LOCAL-DATA-IP>", "port": 45102, "timeout_s": 3.0},
    {"profile": "dns_udp", "bind_host": "<LOCAL-DATA-IP>", "port": 45103, "timeout_s": 3.0},
    {"profile": "dns_tcp", "bind_host": "<LOCAL-DATA-IP>", "port": 45104, "timeout_s": 3.0},
    {
      "profile": "tls_handshake",
      "bind_host": "<LOCAL-DATA-IP>",
      "port": 45105,
      "timeout_s": 3.0,
      "tls": {
        "certificate_path": "<RECEIVER-CERT.pem>",
        "key_path": "<RECEIVER-KEY.pem>",
        "ca_path": "<RECEIVER-TRUST-CA.pem>",
        "server_name": "<RECEIVER-CERTIFICATE-NAME>"
      }
    },
    {"profile": "http_exchange", "bind_host": "<LOCAL-DATA-IP>", "port": 45106, "timeout_s": 3.0},
    {"profile": "ssh_banner", "bind_host": "<LOCAL-DATA-IP>", "port": 45107, "timeout_s": 3.0}
  ],
  "coverage_profiles": [
    "tcp_connect", "tcp_tagged", "udp_tagged", "dns_udp", "dns_tcp",
    "icmp_echo", "tls_handshake", "http_exchange", "ssh_banner", "arp", "ipv6_nd"
  ]
}
```

### Required peer fields

| Field | Rules |
| --- | --- |
| `identity` | 1–64 characters: letters, digits, `.`, `_`, and `-`; first character is alphanumeric. Must match the CLI identity. |
| `bind_host` | Local numeric data-plane private address. |
| `control_port` | `0..65535`; use a fixed nonzero port for reciprocal machines. |
| `peer_addresses` | Fixed numeric data-plane peer addresses. Paired operation requires exactly one; coverage addresses the first configured fixed peer. |
| `peer_pins` | For non-loopback, at least one `sha256:` pin followed by 64 lowercase hexadecimal digits. |

### Non-loopback trust fields

`certificate_path`, `key_path`, `ca_path`, and `token_path` are mandatory when `bind_host` is non-loopback. The server requires a client certificate trusted by `ca_path`; both sides also validate the configured certificate pin and token. `server_hostname` controls TLS name verification when set.

Generate a Mercury-formatted pin from an administrator-verified PEM certificate without storing any secret value in the command:

```bash
python -c "import hashlib,ssl,sys; print('sha256:'+hashlib.sha256(ssl.PEM_cert_to_DER_cert(open(sys.argv[1], encoding='ascii').read())).hexdigest())" <PEER-CERT.pem>
```

Provision the same non-empty token through a protected local file on each peer. Do not place it in JSON, shell history, source control, reports, or screenshots.

### Receiver and profile rules

- Each receiver uses one of `tcp_tagged`, `udp_tagged`, `dns_udp`, `dns_tcp`, `tls_handshake`, `http_exchange`, or `ssh_banner`.
- Receiver ports are `1..65535`, unique by bind-address/port pair, and timeouts are `0.1..30` seconds.
- `tls_handshake` requires all four nested TLS fields. Non-TLS receivers cannot contain `tls`.
- `tcp_connect` needs a configured `tcp_tagged` receiver.
- `icmp_echo`, `arp`, and `ipv6_nd` do not use receiver rows. ICMP peer arrival exists only where the platform exposes the required observer capability; otherwise Mercury reports the gap.
- `coverage_profiles` must exactly match the set passed to `mercury coverage`.
- ARP and IPv6 ND are applicable only to same-link evidence. Supply `--local-network` and `--peer-network` for an explicit applicability decision.

## Control and data addresses, including Tailscale

By default, peer control uses the same addresses as data testing. The optional split is:

| Purpose | Local field | Remote field |
| --- | --- | --- |
| Control channel | `control_bind_host` | `control_peer_addresses` |
| Tested data path | `bind_host` and receiver `bind_host` | `peer_addresses` |

Mercury accepts RFC 6598 shared addresses (`100.64.0.0/10`), which allows an administrator to use Tailscale addresses for the authenticated control channel. For example, put the local Tailscale address in `control_bind_host` and the remote Tailscale address in `control_peer_addresses`, while keeping physical/VLAN lab addresses in the data fields.

Mercury does not discover Tailscale peers, configure ACLs, issue certificates, or treat the overlay as trusted automatically. mTLS, token, pinning, fixed addresses, and authorization still apply. If Tailscale addresses are placed in the data fields, the assessment tests the overlay path itself—not the underlay isolation boundary.

## Mapping limits and defaults

The `mapping` defaults are rate `10`, concurrency `1`, and duration `0`. Normal compiled ceilings are 256 hosts, 64 ports, 4,096 attempts, 10,000 datagrams/logical packets/events, 8 MiB application data/output, rate 100 globally and 10 per target, concurrency 64, and 300 seconds. Absolute code ceilings are larger but immutable; `duration 0` never disables them.

Use `mercury model --json` to inspect the current model semantics and absolute limits. Use `mercury plan ...` to preview cost and any required confirmation before active work.

## Start and validate

```bash
mercury agent --config <LOCAL-PEER.json>
mercury paired --config <LOCAL-PEER.json> --identity <PAIR-ID> --address <CONFIGURED-PEER-DATA-IP> --timeout 3 --authorized
mercury coverage --config <LOCAL-PEER.json> --identity <PAIR-ID> --address <CONFIGURED-PEER-DATA-IP> --profiles <EXACT-CONFIGURED-PROFILE-LIST> --timeout 3 --authorized
```

`--unsafe-development` is an explicit loopback-only override. It is rejected for a non-loopback `bind_host` and must not be used for deployment.

## Per-environment overrides

Mercury has no development/staging/production config merger. Maintain separate administrator-owned peer JSON and trust files per environment, with restrictive filesystem permissions. Select a file explicitly with `--config`; select a separate history database with the global `--data-path` option.
