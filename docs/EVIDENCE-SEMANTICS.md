<!-- generated-by: gsd-doc-writer -->
# Evidence Semantics

[简体中文](zh-CN/EVIDENCE-SEMANTICS.md) · [README](../README.md) · [Architecture](ARCHITECTURE.md)

## Overview

Mercury reports observations, capabilities, conclusions, and task state; it does not reduce network behavior to a single reachable/unreachable Boolean. The model schema is versioned (`1.1` in this release), and compatible historical documents retain the meanings defined by their schema.

This guide is the interpretation contract for CLI output, WebUI rows, JSON, history comparisons, and reports.

## Observation contract

An `Observation` contains:

| Field | Meaning |
| --- | --- |
| `evidence_kind` | The protocol or execution fact that was observed |
| `disposition` | Its semantic class: positive, negative, inconclusive, unavailable, error, or cancelled |
| `direction` | Local, outbound, inbound, or reverse |
| `target` | The selected endpoint or local subject of the observation |
| `started_at`, `ended_at`, `duration_ms` | Time-bounded measurement context |
| `attempt` | Logical attempt number |
| `source` | Provenance, such as a Mercury adapter, peer receipt, or native tool |
| `detail` | Bounded, evidence-specific structured metadata |

An evidence kind permits only compatible dispositions. For example, `tcp_connected` is positive, `tcp_refused` is negative, `timeout` is inconclusive, and `permission_denied` is unavailable. This validation prevents a renderer from relabeling silence as a successful or failed connection.

## Core dispositions

| Disposition | Interpretation | Examples | What it does not establish |
| --- | --- | --- | --- |
| `positive` | A defined response, local fact, peer arrival, or acknowledgement was observed | TCP connected, DNS answer, HTTP response, native ping reply, peer receipt | General reachability beyond the exact profile, direction, endpoint, and time window |
| `negative` | A direct selected-protocol negative response or verified protocol failure was observed | TCP refusal/reset, network/host/ICMP unreachable, administrative prohibition, TLS verification failure | The absence of all other carriers or routes |
| `inconclusive` | The attempt ended without evidence that distinguishes reachability from filtering, loss, delay, or silence | Timeout, UDP silence, unanswered route hop | Success, failure, a closed port, or effective isolation |
| `unavailable` | The capability could not be exercised | Unsupported platform/tool, missing privilege | Negative reachability |
| `error` | Mercury or a bounded adapter could not produce valid protocol evidence | Execution error, parser failure, unclassified native failure | A network conclusion |
| `cancelled` | The operator or lifecycle stopped admitted work | Cancelled task/attempt | Any unexecuted attempt's outcome |

## Protocol-specific interpretation

### DNS

`dns_answer` is positive evidence for the recorded answer and lookup context. `dns_failure` can be negative, inconclusive, or error depending on the concrete resolver result. Active hostname work is planned from a private resolution snapshot and rechecked before connection; an answer that becomes public or escapes the declared scope causes policy rejection rather than a connection to the new address.

The paired `dns_udp` and `dns_tcp` profiles exchange a fixed correlation-bound DNS message with a configured Mercury receiver. They do not provide arbitrary recursive resolution.

### TCP

- `tcp_connected`: the selected TCP connection completed.
- `tcp_refused`: the destination returned a refusal for that endpoint and attempt.
- `tcp_reset`: a reset was observed.
- `network_unreachable` or `host_unreachable`: a direct unreachable condition was reported.
- `timeout`: no definitive TCP result arrived within the recorded window.

A refusal is direct negative evidence for the tested TCP endpoint. A timeout is not equivalent to refusal and is not proof that a firewall blocked the connection.

### UDP

`udp_application_reply` or a correlation-bound peer receipt is positive evidence for the exact fixed exchange. `icmp_unreachable` is direct negative evidence associated with the attempted datagram. `silent` and `timeout` remain inconclusive because UDP need not reply and return-path evidence may be filtered or lost.

### TLS, HTTP, and SSH banner

`tls_handshake` records a completed verified configured handshake. `tls_verification_failed` and `tls_handshake_failed` retain their specific failure semantics instead of being rewritten as generic TCP failure. An `http_response` records a response at the HTTP layer; its disposition depends on the concrete protocol evidence. `ssh_banner` records only the configured banner exchange. Mercury does not attempt passwords, credentials, or login.

### ICMP and route evidence

`native_ping_reply` is positive native echo evidence. Timeout remains inconclusive, permission denial is unavailable, and an unclassified nonzero native exit remains failure/error evidence rather than being guessed into an ICMP meaning.

`path_hop` reports a native route observation. `path_hop_unanswered` and `path_incomplete` remain inconclusive. A route hop, gateway, or neighbor record is not direct evidence of an access switch.

### ARP, IPv6 ND, and LLDP

ARP and IPv6 Neighbor Discovery are same-link facts. In a paired assessment, different local and peer subnets make these profiles `not_applicable`; that row says nothing about cross-subnet reachability. A same-link neighbor fact is not a proof of application reachability.

Mercury identifies infrastructure as a direct neighbor only when direct LLDP evidence exists. It does not infer a switch identity from route, gateway, Wi-Fi, ARP, or ND observations.

### Native Nmap

Nmap-derived port states use `native_port_state` and native provenance. Mercury preserves:

| Native state | Mercury disposition | Interpretation |
| --- | --- | --- |
| `open` | Positive | Nmap reported the port open for its selected fixed profile |
| `closed` | Negative | Nmap reported the port closed |
| `filtered` | Inconclusive | Nmap reported filtering without a definitive open/closed state |
| `open|filtered` | Inconclusive | Nmap could not distinguish open from filtered |

These are native-tool reports, not claims that Mercury observed an identical direct socket exchange. Missing Nmap, permission denial, timeout, malformed XML, and adapter error remain separate outcomes.

## Coverage matrix semantics

Each requested paired coverage profile produces rows by direction. A row carries the profile, direction, configured port where applicable, outcome, supporting evidence kinds, provenance, timing, and limitations.

| Coverage outcome | Meaning |
| --- | --- |
| `candidate_carrier` | Positive evidence exists for the exact selected exchange; it may carry data across the tested boundary |
| `direct_negative` | The selected profile produced direct negative evidence |
| `inconclusive_silence_or_timeout` | Silence or timeout prevented a conclusion |
| `unsupported` | Required capability is not supported |
| `permission_denied` | Required capability exists but was not permitted |
| `skipped` | The profile/direction did not produce an applicable executed result |
| `not_applicable` | The profile does not apply to the topology, such as cross-subnet ARP/ND |

`candidate_carrier` is intentionally narrower than “tunnel found.” It means that the tested carrier conveyed the defined exchange or produced another accepted positive signal. Whether an actual tunnel is deployed requires separate evidence.

All non-candidate rows remain visible as gaps or scoped negatives. Even a matrix with no empty rows covers only the emitted profiles, ports, packet shapes, directions, and time window. Mercury never converts it into a universal statement that all tunnels are absent.

## Direction and peer correlation

Direction is part of the evidence, not presentation metadata:

- `local`: a fact about the executing endpoint.
- `outbound`: the initiating endpoint sent toward its configured peer or target.
- `inbound`: the executing receiver observed arrival.
- `reverse`: the configured peer executed the reciprocal direction.

A `CoverageReceipt` records correlation ID, profile, source/destination tuple, arrival time, SHA-256 payload digest, payload length, direction, provenance, and reply result. It does not retain the raw test tag. The assessment correlates sender observations and receipts using the short-lived correlation identifier; an unrelated packet is not accepted as proof of the exchange.

## Conclusions, confidence, and health

A `Conclusion` contains a title and summary, health, confidence, supporting observation IDs, alternative explanations, and limitations. Confidence describes how strongly the cited observations support that scoped conclusion; it is not a probability that the entire network is healthy.

Task health is also scoped. A healthy or completed task means its defined lifecycle completed according to its evidence rules. It does not mean every endpoint was reachable. A partial, failed, unknown, or cancelled task must be interpreted with its observations, capabilities, errors, and terminal reason.

## Capability evidence

Capabilities use these states:

- `available`
- `unsupported`
- `permission_denied`
- `missing_tool`
- `error`

Capability evidence answers whether Mercury could perform or enrich a measurement. It is not connectivity evidence. For example, a missing native ping tool does not mean the target failed to respond to ICMP; it means that Mercury could not run that measurement through the selected adapter.

## Timing, provenance, and accounting

Every observation has timezone-aware start and end timestamps and a non-negative duration. Provenance identifies the adapter or peer evidence source. Compare evidence only when its task kind and model schema are compatible, and account for different plans, time windows, capability states, and directions.

Budget fields are logical accounting units:

- Attempt rates count logical attempt starts.
- Datagram and logical-packet counts describe work generated by Mercury's plan.
- Application-byte counts describe bounded payload data.
- Event and output limits bound recorded lifecycle data.

They are not packet-capture measurements and do not count exact link-layer overhead, kernel retransmissions, or every on-wire byte.

## History, comparison, and redaction

History records the requested and effective configuration, immutable limits, evidence, terminal state, and safe lifecycle data. Secret material is rejected before persistence. Reports redact hostnames, IP addresses, MAC addresses, and payloads by default; credential material remains excluded even when an operator explicitly retains other sensitive identifiers.

A history comparison describes additions, removals, and changes between compatible recorded evidence. An observation missing from one run means “not recorded in that run.” It is not automatically a direct negative and must not be displayed as a proven regression or fix without matching protocol evidence.

## Safe wording guide

Prefer statements tied to the evidence:

| Use | Avoid |
| --- | --- |
| “TCP connection to the selected endpoint was refused at the recorded time.” | “The host is down.” |
| “No UDP reply or correlated receipt arrived within the timeout.” | “UDP is blocked.” |
| “The peer recorded the tagged DNS/UDP exchange in the outbound direction.” | “A DNS tunnel exists.” |
| “ARP is not applicable to this cross-subnet pair.” | “The peer is unreachable at layer 2.” |
| “Nmap reported `filtered` with native provenance.” | “Mercury proved the firewall dropped the packet.” |
| “No candidate carrier was recorded in this finite matrix; listed gaps remain.” | “No tunnel can cross the boundary.” |

## Reporting checklist

Before acting on a result, confirm:

1. The target and authorization scope match the intended private environment.
2. The profile, port, packet shape, direction, and time window match the question.
3. The evidence kind and disposition support the wording used.
4. Capability gaps, timeout, silence, cancellation, and non-applicability remain visible.
5. Provenance distinguishes Mercury direct evidence, peer receipts, local facts, and native-tool reports.
6. The conclusion includes plausible alternatives and limitations.
7. No finite result is presented as proof about every route, packet sequence, protocol, or tunnel.
