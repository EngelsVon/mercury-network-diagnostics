# Command patterns

Replace every placeholder with operator-owned private values. Run `mercury <subcommand> --help` because installed versions may differ.

## Passive collection

```text
mercury status
mercury discover --passive
```

## Selected endpoint diagnosis

```text
mercury diagnose --target 10.0.0.10:443 --timeout 3 --authorized
```

## Bounded private mapping

```text
mercury mapping \
  --cidr 10.10.0.0/24 \
  --cidr 10.20.0.0/24 \
  --profiles tcp_connect,udp_tagged \
  --ports 53,80,443 \
  --rate 20 \
  --concurrency 4 \
  --duration 0 \
  --authorized
```

Valid profile names must come from the installed CLI/model. Native Nmap profiles are `nmap_tcp_connect`, `nmap_tcp_syn`, `nmap_udp`, and `nmap_sctp_init` when Nmap and required privileges are available.

## Two-endpoint coverage

Start the reciprocal agents:

```text
mercury agent --config peer.json
```

Then initiate the configured finite matrix:

```text
mercury coverage \
  --config peer.json \
  --identity <configured-identity> \
  --address <configured-private-peer-address> \
  --profiles tcp_connect,tcp_tagged,udp_tagged,dns_udp,dns_tcp,tls_handshake,http_exchange,ssh_banner,icmp_echo,arp,ipv6_nd \
  --local-network <local-private-cidr> \
  --peer-network <peer-private-cidr> \
  --authorized
```

The selected profile set must match the configuration. Do not supply a third-party target or change receiver ports from the command line.

## WebUI

```text
mercury web
```

The default is loopback-only. A non-loopback bind requires a numeric address, TLS certificate/key, and token file:

```text
mercury web --bind <private-address> --cert <cert.pem> --key <key.pem> --token-file <token-file>
```

## History

```text
mercury history list
mercury history show <task-id>
mercury history compare <older-task-id> <newer-task-id>
mercury history export <task-id> --format html
```

Inspect each nested history command's help for output-path and redaction switches.
