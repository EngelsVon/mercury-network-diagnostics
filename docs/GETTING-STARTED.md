<!-- generated-by: gsd-doc-writer -->
# Getting started

Mercury is a local-first network diagnostics tool for evidence-based testing of explicitly authorized private networks. Windows and Ubuntu are the v1 release targets.

## Prerequisites

- CPython 3.11 or newer (`python --version`). Development and CI use Python 3.13.
- `psutil>=7.0,<8`; the package installer installs it automatically.
- `uv` is recommended for the commands below. A standard virtual environment and `pip` also work.
- Optional: a local `nmap` executable on `PATH` for the four fixed native profiles. SYN, UDP, and SCTP scans may require elevated OS privileges; missing tools or privileges are reported as capability evidence.
- For two-endpoint coverage: Mercury installed on both endpoints, administrator-provisioned reciprocal peer JSON files, a token file, and certificates for mutual TLS (mTLS).

Mercury actively admits only loopback, RFC1918 IPv4, RFC 6598 shared space (`100.64.0.0/10`), IPv6 ULA, and scoped IPv6 link-local destinations. Authorization is still required for non-loopback work.

## Install Mercury

### From a checkout

The repository has no configured public remote URL. Replace `<repository-url>` with the authorized source location.

```powershell
git clone <repository-url> mercury
cd mercury
uv sync
uv run python -m mercury --help
```

On Ubuntu, the same commands work in a shell:

```bash
git clone <repository-url> mercury
cd mercury
uv sync
uv run python -m mercury --help
```

To use `pip` instead:

```bash
python -m venv .venv
# Ubuntu: source .venv/bin/activate
# PowerShell: .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install .
mercury --help
```

### Install as a local CLI tool

From the repository root:

```bash
uv tool install .
mercury --help
```

## First run

Start with passive status collection. It does not initiate an active scan:

```bash
mercury status
mercury status --json
```

The result distinguishes available, unavailable, permission-denied, and error states. A gateway, route hop, or neighbor is not reported as a switch without direct LLDP or managed evidence.

For a safe active loopback check:

```bash
mercury diagnose --profile basic --authorized
```

For an owned private lab network, preview the bounded work before execution:

```bash
mercury plan <PRIVATE-IP-OR-CIDR> --ports 80,443 --scope <AUTHORIZED-PRIVATE-CIDR> --authorized
mercury mapping --cidr <AUTHORIZED-PRIVATE-IPv4-CIDR> --profiles tcp_connect --ports 80,443 --rate 10 --concurrency 1 --duration 30 --authorized
```

`--duration 0` removes only the operator-selected early cutoff. The compiled immutable ceilings still apply.

## Start the WebUI

The default is a loopback-only HTTP listener:

```bash
mercury web
```

Open `http://127.0.0.1:8765`. Use `--port 0` to select a free port. Browser code submits to the same application service as the CLI and does not probe the network directly.

A non-loopback listener requires a numeric private bind address, a TLS certificate and key, and a non-empty token file:

```bash
mercury web --bind <LOCAL-PRIVATE-IP> --port 8765 --cert <WEB-CERT.pem> --key <WEB-KEY.pem> --token-file <WEB-TOKEN.txt>
```

Do not put the token value on the command line or in peer JSON.

## Optional Nmap profiles

Install Nmap through your operating-system package source, then verify that `nmap --version` works in the same environment as Mercury. Mercury finds only the local executable on `PATH` and derives a fixed command from an admitted plan.

Run exactly one native profile per mapping task:

```bash
mercury mapping --cidr <AUTHORIZED-PRIVATE-IPv4-CIDR> --profiles nmap_tcp_connect --ports 22,80,443 --rate 10 --concurrency 1 --duration 30 --authorized
```

Supported names are `nmap_tcp_connect`, `nmap_tcp_syn`, `nmap_udp`, and `nmap_sctp_init`. Mercury exposes no arbitrary Nmap arguments, scripts, target files, proxies, decoys, or payload option. Native `open`, `closed`, `filtered`, and `open|filtered` states retain Nmap provenance.

## Two-endpoint coverage

1. Create reciprocal peer configurations as described in [Configuration](CONFIGURATION.md). Use placeholders until the administrator supplies addresses, ports, certificate paths, pins, and token files.
2. Start the configured agent on both endpoints:

   ```bash
   mercury agent --config <LOCAL-PEER.json>
   ```

3. From one endpoint, run exactly the profiles listed in its configuration:

   ```bash
   mercury coverage --config <LOCAL-PEER.json> --identity <PAIR-ID> --address <CONFIGURED-PEER-DATA-IP> --profiles tcp_connect,tcp_tagged,udp_tagged,dns_udp,dns_tcp,icmp_echo,tls_handshake,http_exchange,ssh_banner,arp,ipv6_nd --local-network <LOCAL-PRIVATE-CIDR> --peer-network <PEER-PRIVATE-CIDR> --timeout 3 --authorized
   ```

The peer command cannot select a third-party destination. Receiver-capable profiles use fixed local receiver entries. ARP and IPv6 ND are same-link evidence and become `not_applicable` across subnets. A candidate carrier proves only that the recorded finite profile worked in that direction and time window; silence and uncovered packet shapes do not prove that every possible tunnel is absent.

## Common setup issues

### `nmap executable unavailable`

Confirm `nmap --version` works in the same terminal and that the executable directory is on `PATH`. Otherwise use a non-native Mercury profile. Do not add an arbitrary executable or argument field to the request.

### Permission denied for native or ICMP work

Some native Nmap modes and ICMP observation need OS privileges. Run the least-privileged supported profile or arrange approved elevation. Treat the result as a capability gap, not a network verdict.

### Non-loopback WebUI is rejected

Supply all three of `--cert`, `--key`, and `--token-file`, bind a numeric admitted private address, and verify the files are readable. Loopback does not require them.

### Peer configuration is rejected

Check that both files use the same identity and reciprocal fixed addresses, that the requested `--address` equals the configured data peer address, and that every selected receiver profile has a unique fixed port. Non-loopback peers require certificate, private key, trusted-client CA, token file, and a lowercase `sha256:` certificate pin with 64 hexadecimal digits.

### History is in an unexpected location

Use the global option before the command: `mercury --data-path <PATH> status`. Defaults are `%LOCALAPPDATA%\Mercury\history.sqlite3` on Windows and `${XDG_DATA_HOME:-~/.local/share}/mercury/history.sqlite3` on Ubuntu.

## Next steps

- [Configuration](CONFIGURATION.md) covers every file and runtime setting.
- [Deployment](DEPLOYMENT.md) covers controlled Windows/Ubuntu rollout and peer trust.
- [CLI reference](CLI-REFERENCE.md) lists the complete command surface.
