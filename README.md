<!-- generated-by: gsd-doc-writer -->
# Mercury

[简体中文](README.zh-CN.md)

Mercury is a local-first network diagnostics tool for administrators who need reproducible evidence about reachability inside an explicitly authorized private network.

Mercury's CLI, peer agent, and WebUI use the same Python engine and versioned evidence model. It preserves protocol-specific outcomes instead of turning silence into success or failure, and it reports the limits of every conclusion.

> Mercury is private-network-only. Active work admits loopback, RFC1918 IPv4, RFC6598 shared IPv4, IPv6 ULA, and scoped IPv6 link-local destinations as supported by the selected operation. Public, documentation, multicast, unspecified, and broadcast destinations are rejected before network or native-tool I/O. Non-loopback work requires an explicit authorization attestation. Multi-range `mapping` is narrower: it accepts loopback and RFC1918 IPv4 CIDRs only.

## Feature matrix

| Capability | What Mercury provides | Important boundary |
| --- | --- | --- |
| Passive status and discovery | Interfaces, routes, DNS, neighbors, Wi-Fi, capabilities, and direct LLDP evidence when the platform exposes them | A gateway, route hop, or ARP/ND neighbor is not labeled as a switch |
| Layered diagnosis | Bounded DNS, TCP, TLS, HTTP, native ping, and route evidence for selected private endpoints | A result applies only to the selected endpoint and observed layer |
| Internal mapping | One immutable plan over multiple private IPv4 CIDRs, fixed profiles, selected ports, rate, concurrency, and duration | Active work is subject to host, port, attempt, logical-packet, application-byte, rate, concurrency, duration, event, and output ceilings |
| Paired coverage | Directional TCP, UDP, DNS over UDP/TCP, ICMP, TLS, HTTP, SSH-banner, and same-link ARP/IPv6-ND evidence | Receiver-capable profiles require reciprocal, administrator-provisioned Mercury peers |
| Optional Nmap evidence | Fixed TCP connect, TCP SYN, UDP, and SCTP INIT profiles parsed from bounded XML | No arbitrary flags, scripts, target files, proxies, decoys, payloads, or destinations |
| WebUI | Accessible task creation, progress, cancellation, coverage matrices, gaps, and local history | Browser code performs no network probes; non-loopback listeners require TLS and a token |
| History and reports | Local SQLite task history, comparison, JSON, and HTML reports | Credentials are always rejected or redacted; identifiers and payloads are redacted by default |

Mercury v1 targets Windows and Ubuntu. Unsupported native capabilities are reported as evidence rather than silently ignored. macOS and other platforms are not release targets.

## Installation

Mercury requires CPython 3.11 or newer and has one runtime dependency, `psutil`. From a checkout, install it with either `uv` or `pip`:

```bash
uv tool install .
mercury --help
```

```bash
python -m venv .venv
# PowerShell: .venv\Scripts\Activate.ps1
# Ubuntu: source .venv/bin/activate
python -m pip install .
python -m mercury --help
```

For development from the checkout, `uv sync` followed by `uv run python -m mercury --help` uses the locked environment. See [Getting Started](docs/GETTING-STARTED.md) for the full setup.

## Quick start

The safest first run is passive and sends no probes:

1. Inspect the CLI and evidence contract.

   ```bash
   mercury --help
   mercury model
   ```

2. Collect local status evidence.

   ```bash
   mercury status
   mercury status --json
   ```

3. Collect passive discovery evidence.

   ```bash
   mercury discover --passive
   ```

Use `mercury plan --help` to preview and cost authorized active work before executing it. Never substitute a public, third-party, or unapproved destination.

## Internal mapping

`mapping` canonicalizes overlapping private IPv4 CIDRs, selected fixed profiles, and ports into one immutable outbound plan. `--rate` counts logical attempt starts per second. `--duration 0` removes only the operator-selected early cutoff; compiled hard ceilings still terminate the task.

```bash
mercury mapping \
  --cidr <owned-private-cidr> \
  --profiles tcp_connect,udp_tagged \
  --ports 53,80,443 \
  --rate 20 \
  --concurrency 4 \
  --duration 0 \
  --authorized
```

The angle-bracket value is a placeholder. Replace it only with a private IPv4 CIDR that you administer and are authorized to test.

## Internal mapping and two-endpoint coverage

### Coverage receiver configuration

A paired assessment uses reciprocal peer configuration files created by an administrator. Each file fixes the peer identity and addresses, control channel, certificate and token paths, certificate pins, allowed coverage profiles, and receiver ports. The CLI cannot turn a peer into an arbitrary third-party scan relay.

The peer JSON binds the finite `coverage_profiles` list and receiver table. See [Configuration](docs/CONFIGURATION.md) for the full schema and reciprocal examples.

Receiver-capable profiles are `tcp_tagged`, `udp_tagged`, `dns_udp`, `dns_tcp`, `tls_handshake`, `http_exchange`, and `ssh_banner`. `tcp_connect` uses the configured TCP receiver. `icmp_echo` uses native platform evidence and records an observer capability gap when peer arrival cannot be observed. `arp` and `ipv6_nd` are same-link evidence and become `not_applicable` for a cross-subnet pair.

On each configured endpoint, start its local agent:

```bash
mercury agent --config <local-peer-config.json>
```

Then start the assessment from one endpoint with values that exactly match its configuration:

```bash
mercury coverage \
  --config <local-peer-config.json> \
  --identity <configured-identity> \
  --address <configured-private-peer-address> \
  --profiles tcp_tagged,udp_tagged,dns_udp,dns_tcp,icmp_echo,tls_handshake,http_exchange,ssh_banner,arp,ipv6_nd \
  --local-network <owned-local-private-cidr> \
  --peer-network <owned-peer-private-cidr> \
  --authorized
```

The assessment runs eligible profiles in both directions and correlates sender evidence with peer receipts. No DNS profile performs general name resolution, and no SSH profile attempts credentials or login.

## Optional Nmap

If an `nmap` executable is installed locally, mapping can select exactly one of these closed native profiles per task:

- `nmap_tcp_connect`
- `nmap_tcp_syn`
- `nmap_udp`
- `nmap_sctp_init`

Mercury validates the private plan first and derives the complete Nmap argument vector itself. Results retain native `open`, `closed`, `filtered`, and `open|filtered` states with native provenance. A missing executable, insufficient privilege, timeout, malformed output, or unsupported profile remains distinct capability or error evidence. Mercury does not expose an arbitrary Nmap command line.

## WebUI

Start the local dashboard:

```bash
uv run --no-sync python -m mercury web
```

Open the printed loopback URL. The WebUI submits the same typed requests to `MercuryApplication` as the CLI and supports passive status, diagnosis, discovery, trace, mapping, paired coverage, progress, cancellation, history comparison, and redacted reports.

For an intentional non-loopback listener, provide a private numeric bind address, a certificate/key pair, and a token file:

```bash
mercury web \
  --bind <private-listener-address> \
  --cert <certificate.pem> \
  --key <private-key.pem> \
  --token-file <token-file>
```

These are placeholders, not bundled credentials. The listener also validates the Host header, same-origin mutations, its session cookie and CSRF header, and bounded JSON request bodies. Web mode does not expose the peer-agent control surface.

## Evidence semantics

Every observation records an evidence kind, semantic disposition, direction, target, start/end time, duration, attempt number, provenance source, and bounded details. Conclusions reference their supporting observation IDs and add confidence, alternatives, and limitations.

- Positive evidence means the selected exchange produced a defined response or a correlated peer arrival; it does not prove a broader topology or deployed tunnel.
- Direct negative evidence, such as TCP refusal or ICMP unreachable, is kept separate from timeout and silence.
- Timeout and silence are inconclusive. They are never rendered as a closed port, successful isolation, or failed network.
- Unsupported, permission-denied, skipped, and not-applicable rows are coverage gaps or applicability statements, not negative reachability evidence.
- A finite paired matrix can identify a tested candidate carrier. It cannot prove that every untested payload, state sequence, protocol, or tunnel is absent.

See [Evidence Semantics](docs/EVIDENCE-SEMANTICS.md) for the normative interpretation guide and [Architecture](docs/ARCHITECTURE.md) for the shared execution path.

## History and reports

```bash
mercury history list
mercury history show <task-id>
mercury history compare <older-task-id> <newer-task-id>
mercury history export <task-id> --format html
```

Only compatible completed task kinds and model schemas can be compared. Missing evidence in one run means it was not recorded in that run, not that a network condition was proven. `--retain-sensitive` can retain identifiers and payloads in a local export, but never credentials, tokens, or private keys.

## Documentation

| English | 简体中文 |
| --- | --- |
| [Getting Started](docs/GETTING-STARTED.md) | [入门指南](docs/zh-CN/GETTING-STARTED.md) |
| [Architecture](docs/ARCHITECTURE.md) | [架构](docs/zh-CN/ARCHITECTURE.md) |
| [Evidence Semantics](docs/EVIDENCE-SEMANTICS.md) | [证据语义](docs/zh-CN/EVIDENCE-SEMANTICS.md) |
| [CLI Reference](docs/CLI-REFERENCE.md) | [CLI 参考](docs/zh-CN/CLI-REFERENCE.md) |
| [Configuration](docs/CONFIGURATION.md) | [配置](docs/zh-CN/CONFIGURATION.md) |
| [Deployment](docs/DEPLOYMENT.md) | [部署](docs/zh-CN/DEPLOYMENT.md) |
| [Development](docs/DEVELOPMENT.md) | [开发](docs/zh-CN/DEVELOPMENT.md) |
| [Testing](docs/TESTING.md) | [测试](docs/zh-CN/TESTING.md) |
| [Contributing](CONTRIBUTING.md) | [贡献指南](CONTRIBUTING.zh-CN.md) |
| [Security](SECURITY.md) | [安全](SECURITY.zh-CN.md) |
| [Code of Conduct](CODE_OF_CONDUCT.md) | [行为准则](CODE_OF_CONDUCT.zh-CN.md) |
| [Mercury network-diagnostics skill](skills/mercury-network-diagnostics/SKILL.md) | 同一技能文档 |

## Development and verification

### Operator release smoke

The controlled test suite uses fakes, fixtures, and loopback; it does not contact real non-loopback targets and does not scan unowned networks.

```bash
python -m unittest discover -s tests -v
python -m compileall -q src tests
python -m build
```

## License

See [LICENSE](LICENSE).
