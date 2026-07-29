# Feature Research

**Domain:** Cross-platform, distributed network reachability diagnosis for authorized LAN/campus/enterprise networks  
**Researched:** 2026-07-30  
**Confidence:** HIGH for the existing-tool capability map; MEDIUM for the product-value verdict because user demand has not yet been validated

## Verdict

**NARROW-GO — build only a paired differential network debugger, not an all-in-one network toolbox.**

Research judgment: Mercury has defensible value only as this tightly scoped product:

> Two explicitly paired endpoints execute the same bounded diagnostic plan in both directions, preserve what each side actually observed, compare direction/protocol/path/environment differences, and produce a local, redacted, replayable evidence report that says “observed”, “inferred”, or “unknown”.

Integration alone is not a moat: Netshoot already packages a broad troubleshooting toolbox, Windows `Test-NetConnection` already combines several common checks, and ThousandEyes already integrates endpoint history, local-network context, and path visualization ([S05 · HIGH](https://learn.microsoft.com/en-us/powershell/module/nettcpip/test-netconnection), [S21 · HIGH](https://github.com/nicolaka/netshoot), [S28 · HIGH](https://docs.thousandeyes.com/product-documentation/end-user-monitoring/viewing-data/endpoint-agent-scheduled-tests-view), [S29 · HIGH](https://docs.thousandeyes.com/product-documentation/end-user-monitoring/viewing-data/endpoint-agent-local-networks-view)). Pairing alone is not a moat either: Nping Echo Mode distinguishes an outbound probe being dropped from its response being lost, `iperf3` supports reverse and simultaneous bidirectional tests, and perfSONAR coordinates measurements among participants ([S12 · HIGH](https://nmap.org/book/nping-man-echo-mode.html), [S19 · HIGH](https://software.es.net/iperf/invoking.html), [S32 · HIGH](https://docs.perfsonar.net/pscheduler_intro.html)).

The narrow combination remains plausible because the documented tools split into four different jobs:

1. raw probes and scanners;
2. performance measurement;
3. overlay-specific peer troubleshooting;
4. fleet/Internet monitoring.

Research judgment: none of the reviewed primary documentation establishes a lightweight, local-first product contract that combines arbitrary authorized underlay networks, role-swapped multi-protocol tests, explicit evidence provenance and uncertainty, run-to-run comparison, safe progressive discovery, and one portable CLI/WebUI artifact. This is an **absence-of-evidence conclusion**, so confidence is MEDIUM and it must be validated with users rather than treated as proven whitespace.

### Immediate NO-GO Triggers

Cancel or radically rescope Mercury if any of these becomes true:

- The paired, role-swapped test protocol is removed; what remains is a thin wrapper over built-ins, Nmap, MTR, and Netshoot.
- The headline becomes “discover every host/port”, “draw the whole topology”, “run a speed test”, or “monitor the fleet”; those categories are already served.
- A lab MVP cannot identify the failing **layer + direction + protocol/port** more reliably than a competent operator using existing commands.
- Normal-user Windows, Linux, and macOS builds cannot deliver a useful common baseline without silently changing semantics between platforms.
- Authentication, scope budgets, cancellation, redaction, and audit are deferred until after active probing ships.

## Evidence Convention

Every external factual claim is followed by an inline source token of the form `[S## · CONFIDENCE]`. All linked sources were accessed **2026-07-30**. “Research judgment”, “Recommendation”, “Estimate”, and proposed acceptance thresholds are synthesis, not externally sourced facts.

## Competitive Reality: What Is Already Commoditized

| Tool / class | Verified current capability | Consequence for Mercury |
|---|---|---|
| `ping` | Sends ICMP Echo Request and reports round-trip and packet-loss statistics ([S01 · HIGH](https://man7.org/linux/man-pages/man8/ping.8.html)). | **Commoditized:** basic reachability, RTT, and loss earn no differentiation credit. |
| `traceroute` / MTR | Linux traceroute supports UDP, ICMP, and TCP methods; MTR combines traceroute and ping and exposes report, JSON, XML, and CSV modes ([S02 · HIGH](https://traceroute.sourceforge.net/), [S03 · HIGH](https://www.bitwizard.nl/mtr/), [S04 · HIGH](https://raw.githubusercontent.com/traviscross/mtr/master/man/mtr.8.in)). | **Commoditized:** hop discovery, repeated latency/loss, and machine-readable path results. |
| OS diagnostics | Windows `Test-NetConnection` combines DNS lookup context, ping, TCP connection tests, route tracing, and route-selection diagnostics; NetworkManager’s `nmcli` reports device/network status and can re-check configured connectivity ([S05 · HIGH](https://learn.microsoft.com/en-us/powershell/module/nettcpip/test-netconnection), [S06 · HIGH](https://networkmanager.dev/docs/api/latest/nmcli.html)). | **Commoditized:** a local snapshot plus several one-host tests. Mercury must normalize and compare, not merely expose commands. |
| Nmap | Nmap performs host discovery, port scanning, service/version and OS detection, scripting, and traceroute; local Ethernet discovery can use ARP, and XML output is intended for programmatic parsing ([S07 · HIGH](https://nmap.org/book/man.html), [S08 · HIGH](https://nmap.org/book/man-host-discovery.html), [S11 · HIGH](https://nmap.org/book/man-output.html)). | **Commoditized:** host/service discovery and broad scan mechanics. Do not rebuild Nmap. |
| Nping / Ncat | Nping generates and analyzes TCP, UDP, ICMP, ARP, and other packets. Its authenticated/encrypted Echo Mode can determine whether probes fail outbound or replies fail on return. Ncat provides TCP/UDP/SCTP/SSL client, server, relay, proxy, and broker modes ([S12 · HIGH](https://nmap.org/book/nping-man-echo-mode.html), [S13 · HIGH](https://nmap.org/ncat/guide/index.html)). | **Strong prior art:** packet customization, client/server listeners, and directionality already exist. Mercury must add orchestration, evidence comparison, safety, and usability. |
| ARP and neighbor tools | `arp-scan` discovers/fingerprints IPv4 hosts on the local network; Netdiscover sends ARP requests and sniffs replies; OS neighbor tables expose on-link IP-to-link-layer mappings ([S14 · HIGH](https://github.com/royhills/arp-scan), [S15 · HIGH](https://github.com/netdiscover-scanner/netdiscover), [S34 · HIGH](https://man7.org/linux/man-pages/man8/ip-neighbour.8.html)). | **Commoditized and bounded:** same-link discovery. It cannot justify a general topology claim. |
| LLDP clients | `lldpd` sends/receives LLDP advertisements, supports a receive-only mode, and `lldpcli` shows immediate neighbors; LLDP is described as a Layer-2 protocol for advertising identity/capability on the local network ([S16 · HIGH](https://lldpd.github.io/usage.html)). | **Optional evidence source:** useful when available, never a mandatory dependency or proof of unseen topology. |
| Tailscale / NetBird diagnostics | `tailscale netcheck` reports physical-network conditions relevant to Tailscale, and `tailscale ping` diagnoses another device exclusively over Tailscale with TSMP, ICMP, PeerAPI, and direct-path modes. NetBird reports peer P2P/relayed state, ICE endpoints, handshakes, latency, routes, control-service reachability, and can collect logs/status/routes/config into a debug bundle ([S18 · HIGH](https://tailscale.com/kb/1080/cli), [S17 · HIGH](https://docs.netbird.io/how-to/troubleshooting-client)). | **Strong workflow prior art, limited scope:** Mercury should not manage an overlay. Its wedge is arbitrary authorized underlay/LAN paths and non-overlay services. |
| `iperf3` / Ethr / OpenNetLab P2P | `iperf3` is a client/server TCP/UDP/SCTP throughput tool with reverse and simultaneous bidirectional modes. Microsoft Ethr documents cross-platform client/server measurements for bandwidth, connections, packets, latency, loss, and jitter across TCP/UDP/HTTP/HTTPS. OpenNetLab’s P2P project wraps `iperf3` for bandwidth, latency, jitter, and loss and writes JSON ([S19 · HIGH](https://software.es.net/iperf/invoking.html), [S20 · HIGH](https://github.com/microsoft/ethr), [S33 · MEDIUM](https://github.com/OpenNetLab/OpenNetLab-P2P-Measurment)). | **Pairing is commoditized:** Mercury must diagnose reachability semantics, not compete as another throughput generator. |
| OpenSpeedTest | OpenSpeedTest is a self-hosted HTML5 network-performance estimator with download, upload, and ping modes, including local-network use ([S25 · HIGH](https://github.com/openspeedtest/Speed-Test)). | **Orthogonal:** throughput is supporting context at most, not Mercury’s product. |
| Netshoot | Netshoot is a Docker/Kubernetes troubleshooting container that brings tools such as MTR, Nmap, `iperf3`, DNS utilities, and packet capture into a target network namespace and documents scenario-oriented workflows ([S21 · HIGH](https://github.com/nicolaka/netshoot)). | **Integration is commoditized:** a bag of tools and recipes is insufficient differentiation. |
| Prometheus Blackbox Exporter | Blackbox Exporter probes HTTP, HTTPS, DNS, TCP, ICMP, and gRPC endpoints and exposes success, timing, debug data, and Prometheus metrics ([S22 · HIGH](https://github.com/prometheus/blackbox_exporter)). | **Commoditized for continuous synthetic checks:** Mercury should focus on interactive incident evidence and paired comparison, not metrics scraping. |
| NetBox Discovery / Orb Agent | NetBox Labs’ Orb Agent provides network discovery and observability; its network backend uses Nmap, accepts target scopes and schedules, supports OS detection, and offers TCP-connect fallback when raw sockets are unavailable ([S23 · HIGH](https://github.com/netboxlabs/orb-agent), [S24 · HIGH](https://raw.githubusercontent.com/netboxlabs/orb-agent/develop/docs/backends/network_discovery.md)). | **Discovery/CMDB integration is occupied:** Mercury should export evidence to inventory systems later, not become one. |
| RIPE Atlas | RIPE Atlas is a global probe/anchor network for active Internet-connectivity measurements, public data, visualizations, APIs, and customized measurements ([S31 · HIGH](https://www.ripe.net/analyse/internet-measurements/ripe-atlas/)). | **External-vantage measurement is occupied:** do not build a public global probe network. |
| perfSONAR | perfSONAR is a distributed end-to-end measurement toolkit with coordinated participants, scheduling, access limits, result archiving, dashboards, and widely deployed measurement points ([S30 · HIGH](https://www.perfsonar.net/), [S32 · HIGH](https://docs.perfsonar.net/pscheduler_intro.html)). | **Closest campus/R&E counterexample:** Mercury must stay lightweight, incident-driven, endpoint-friendly, and reachability-focused. |
| PingPlotter | PingPlotter documents visual traceroute, local-device discovery, historical latency/loss, ICMP/UDP/TCP tests, shareable snapshots, alerts, route-change tracking, and Web UI workflows ([S26 · MEDIUM](https://www.pingplotter.com/products/standard/), [S27 · MEDIUM](https://www.pingplotter.com/manual/)). | **UI/history/sharing are commoditized:** these are table stakes, not differentiators. Vendor claims are MEDIUM confidence because they are product marketing/manual content rather than independent evaluation. |
| ThousandEyes Endpoint Agents | Endpoint Agents run scheduled agent-to-server and HTTP tests, retain a timeline, expose local-network views connecting agents to gateways/proxies/DNS/VPN terminators, and visualize layer-3 hop-by-hop paths from an endpoint to a target ([S28 · HIGH](https://docs.thousandeyes.com/product-documentation/end-user-monitoring/viewing-data/endpoint-agent-scheduled-tests-view), [S29 · HIGH](https://docs.thousandeyes.com/product-documentation/end-user-monitoring/viewing-data/endpoint-agent-local-networks-view)). Agent performance/network data is sent to ThousandEyes over HTTPS ([S35 · HIGH](https://docs.thousandeyes.com/product-documentation/global-vantage-points/endpoint-agents/how-endpoint-agents-work/how-does-the-endpoint-agent-work)). | **Strongest NO-GO evidence:** “agent + history + path + local context + Web UI” already exists. Mercury can defend only a local/self-hosted, open workflow and deeper paired differential semantics. |

### Maintenance and Reuse Signal

The closest open-source alternatives cannot be dismissed as dead. Official GitHub metadata/commit feeds showed the following state on 2026-07-30:

| Project | Verified repository state | Product implication |
|---|---|---|
| MTR | Not archived; repository metadata reports GPL-2.0; commit feed updated 2026-06-16 ([S36 · HIGH](https://github.com/traviscross/mtr), [S37 · HIGH](https://github.com/traviscross/mtr/commits/master.atom)). | Mature path probing remains an active dependency/competitor. |
| Netshoot | Not archived; repository metadata reports Apache-2.0; commit feed updated 2026-07-01 ([S21 · HIGH](https://github.com/nicolaka/netshoot), [S38 · HIGH](https://github.com/nicolaka/netshoot/commits/master.atom)). | Scenario-oriented tool aggregation is active. |
| Prometheus Blackbox Exporter | Not archived; repository metadata reports Apache-2.0; commit feed updated 2026-07-24 ([S22 · HIGH](https://github.com/prometheus/blackbox_exporter), [S39 · HIGH](https://github.com/prometheus/blackbox_exporter/commits/master.atom)). | Multi-protocol synthetic checks are active and well occupied. |
| NetBox Orb Agent | Not archived; repository metadata reports Apache-2.0; commit feed updated 2026-07-28 ([S23 · HIGH](https://github.com/netboxlabs/orb-agent), [S40 · HIGH](https://github.com/netboxlabs/orb-agent/commits/develop.atom)). | Discovery/observability overlap is current, not historical. |
| Microsoft Ethr | Not archived; repository metadata reports MIT; commit feed updated 2025-12-10 ([S20 · HIGH](https://github.com/microsoft/ethr), [S41 · HIGH](https://github.com/microsoft/ethr/commits/master.atom)). | A close multi-protocol paired measurement tool remains available, though its visible commit cadence is lower than the projects above. |
| OpenSpeedTest | Not archived; repository metadata reports MIT; commit feed updated 2026-04-22 ([S25 · HIGH](https://github.com/openspeedtest/Speed-Test), [S42 · HIGH](https://github.com/openspeedtest/Speed-Test/commits/main.atom)). | There is no reason to duplicate its speed-test scope. |
| OpenNetLab P2P Measurement | Repository is visible and not marked archived, but its commit feed’s latest visible update was 2023-04-10 ([S33 · MEDIUM](https://github.com/OpenNetLab/OpenNetLab-P2P-Measurment), [S43 · HIGH](https://github.com/OpenNetLab/OpenNetLab-P2P-Measurment/commits/main.atom)). | Relevant prior art, but weaker evidence of a currently maintained direct competitor. |

Reuse warning: Nmap/Nping/Ncat are distributed under the Nmap Public Source License, which adds terms beyond GPLv2 and restricts proprietary embedding/redistribution; bundling or deriving code requires a dedicated license review ([S44 · HIGH](https://nmap.org/npsl/)). Repository-level SPDX labels above are not a substitute for file-level dependency and redistribution review.

## Feature Landscape

### Table Stakes (Users Expect These)

These are non-negotiable for a Mercury launch. Complexity is a research estimate.

| Feature | Why Expected | Complexity | MVP acceptance boundary |
|---|---|---:|---|
| Truthful local network snapshot | OS tools already expose interfaces, routes, DNS context, source-address selection, and connection state ([S05 · HIGH](https://learn.microsoft.com/en-us/powershell/module/nettcpip/test-netconnection), [S06 · HIGH](https://networkmanager.dev/docs/api/latest/nmcli.html)). | MEDIUM | Versioned snapshot of interfaces, addresses, DNS, routes, default gateway, MTU, OS, privileges, and collector errors; missing data stays explicit. |
| Multi-layer guided baseline | A useful diagnosis must separate local configuration, gateway/link, name resolution, routed reachability, and service reachability; existing tools already cover the individual checks ([S01 · HIGH](https://man7.org/linux/man-pages/man8/ping.8.html), [S05 · HIGH](https://learn.microsoft.com/en-us/powershell/module/nettcpip/test-netconnection), [S22 · HIGH](https://github.com/prometheus/blackbox_exporter)). | HIGH | One bounded plan tests loopback/local state, gateway, DNS through configured and explicit resolvers, IP reachability, and selected TCP/application targets without declaring a single failed probe “offline”. |
| Exact TCP/UDP outcome semantics | Nmap distinguishes `open`, `closed`, `filtered`, `unfiltered`, `open-or-filtered`, and `closed-or-filtered`; no UDP response is `open-or-filtered`, not proof of an open port ([S09 · HIGH](https://nmap.org/book/man-port-scanning-basics.html), [S10 · HIGH](https://nmap.org/book/scan-methods-udp-scan.html)). | HIGH | Preserve connect success, refusal/reset, timeout, ICMP unreachable, application response, malformed response, and silence as separate observations. Never render UDP silence as “open”. |
| Authenticated explicit pairing | Nping already demonstrates an authenticated/encrypted client/server control channel for directional troubleshooting ([S12 · HIGH](https://nmap.org/book/nping-man-echo-mode.html)). | HIGH | Short-lived pairing code/key, peer identity display, explicit consent on both sides, loopback-only UI by default, narrow listener lifetime, and no anonymous remote execution. |
| Role-swapped paired probe plan | `iperf3`, Nping, Ethr, and perfSONAR prove that coordinated endpoints and reverse-direction measurements are established expectations ([S12 · HIGH](https://nmap.org/book/nping-man-echo-mode.html), [S19 · HIGH](https://software.es.net/iperf/invoking.html), [S20 · HIGH](https://github.com/microsoft/ethr), [S32 · HIGH](https://docs.perfsonar.net/pscheduler_intro.html)). | HIGH | A and B run the same TCP/UDP/application probes with roles reversed; results retain source, destination, direction, interface, address family, port, payload profile, and timestamps. |
| Path evidence with uncertainty | Traceroute supports several probe methods, while path systems document missing/unresponsive hops and alternate routes ([S02 · HIGH](https://traceroute.sourceforge.net/), [S45 · HIGH](https://docs.thousandeyes.com/product-documentation/internet-and-wan-monitoring/path-visualization/path-trace)). | HIGH | TCP/UDP/ICMP path attempts where supported; timeouts are “no response”, not invented hops; repeated runs retain alternate paths and probe method. |
| Structured, replayable evidence artifact | Nmap provides parseable XML; MTR offers structured modes; PingPlotter and ThousandEyes expose saved snapshots/timelines ([S11 · HIGH](https://nmap.org/book/man-output.html), [S04 · HIGH](https://raw.githubusercontent.com/traviscross/mtr/master/man/mtr.8.in), [S27 · MEDIUM](https://www.pingplotter.com/manual/), [S28 · HIGH](https://docs.thousandeyes.com/product-documentation/end-user-monitoring/viewing-data/endpoint-agent-scheduled-tests-view)). | HIGH | Versioned JSON schema containing plan, authorization scope, raw observations, normalized outcomes, collector/probe versions, environment, inference links, confidence, errors, and redaction manifest. |
| Run history and diff | Historical latency/loss, route changes, snapshots, and timelines are established product behavior ([S26 · MEDIUM](https://www.pingplotter.com/products/standard/), [S27 · MEDIUM](https://www.pingplotter.com/manual/), [S28 · HIGH](https://docs.thousandeyes.com/product-documentation/end-user-monitoring/viewing-data/endpoint-agent-scheduled-tests-view)). | MEDIUM | Compare two local artifacts by config, path, DNS answer, direction, protocol, outcome, and latency; no fleet-monitoring backend required. |
| Safe bounded executor | Nmap exposes parallelism, rate, and host-timeout controls; perfSONAR applies scheduling/access limits to measurements ([S46 · HIGH](https://nmap.org/book/man-performance.html), [S32 · HIGH](https://docs.perfsonar.net/pscheduler_intro.html)). | HIGH | Preflight count/cost, hard target/port/rate/concurrency/duration/output ceilings, active cancellation, explicit dangerous-mode confirmation, and audit entry before any probe. |
| CLI and minimal local WebUI over one engine | PingPlotter and ThousandEyes establish visual/history expectations, while CLI tools establish scriptability ([S27 · MEDIUM](https://www.pingplotter.com/manual/), [S28 · HIGH](https://docs.thousandeyes.com/product-documentation/end-user-monitoring/viewing-data/endpoint-agent-scheduled-tests-view), [S11 · HIGH](https://nmap.org/book/man-output.html)). | HIGH | CLI emits the canonical artifact; WebUI invokes the same API and renders progress, conclusion/evidence, A/B direction matrix, path, and run diff. No duplicate probe logic. |
| Privacy-preserving sharing | NetBird debug bundles may include routes, firewall rules, resolver state, network maps, configuration, and logs; diagnostic artifacts therefore contain operationally sensitive data ([S17 · HIGH](https://docs.netbird.io/how-to/troubleshooting-client)). | MEDIUM | Redact/public-IP, MAC, hostname, payload, and token fields by default; preview exact exported fields; secrets never enter reports. |
| Cross-platform capability degradation | Orb documents that raw-socket scanning needs privilege while TCP-connect fallback can run rootless; `lldpd` uses a privileged daemon with separation ([S24 · HIGH](https://raw.githubusercontent.com/netboxlabs/orb-agent/develop/docs/backends/network_discovery.md), [S16 · HIGH](https://lldpd.github.io/usage.html)). | HIGH | Each probe reports required/granted capability and fallback used. The UI never implies equal fidelity when platforms or privileges differ. |

### Differentiators (Competitive Advantage)

No single row is a durable moat. The **combination of the first five rows** is the defensible product contract.

| Feature | Value proposition | Complexity | Why it is genuinely different enough |
|---|---|---:|---|
| Paired differential incident plan | Converts “works from A but not B” and “outbound works but return traffic fails” into a controlled A↔B experiment. | HIGH | Nping solves packet reflection/directionality, and `iperf3` solves bidirectional performance, but Mercury’s proposed plan compares local state, DNS, path, TCP/UDP/application outcomes, and permissions in one role-swapped artifact ([S12 · HIGH](https://nmap.org/book/nping-man-echo-mode.html), [S19 · HIGH](https://software.es.net/iperf/invoking.html)). Research judgment: the cross-layer comparison, not pairing itself, is the wedge. |
| Evidence graph with provenance and uncertainty | Lets an operator inspect why a conclusion was reached and distinguish observation from inference or ignorance. | HIGH | Nmap’s state model proves ambiguity must be represented, especially for filtered paths and UDP silence ([S09 · HIGH](https://nmap.org/book/man-port-scanning-basics.html), [S10 · HIGH](https://nmap.org/book/scan-methods-udp-scan.html)). Mercury turns that discipline into the product-wide data contract. |
| Direction × protocol × endpoint matrix | Surfaces selective ACL/NAT/firewall behavior without a 65,535-port Cartesian explosion. | HIGH | Existing tools expose the underlying probes, while Mercury organizes a small hypothesis-driven matrix and explains mismatches. Research judgment: this is more useful than another scan table only if recipes stay bounded and incident-specific. |
| Reproducible run diff | Answers “what changed?” across network, device, location, or time using the same versioned plan. | MEDIUM | PingPlotter/ThousandEyes already provide history ([S27 · MEDIUM](https://www.pingplotter.com/manual/), [S28 · HIGH](https://docs.thousandeyes.com/product-documentation/end-user-monitoring/viewing-data/endpoint-agent-scheduled-tests-view)). Mercury differentiates by diffing both endpoints’ environment and evidence locally, not by inventing another time-series UI. |
| Safe progressive discovery as UX | Starts passive/low-impact, shows the next probe’s cost and diagnostic hypothesis, and escalates only with consent. | HIGH | Nmap already offers powerful rate/timeout/scan controls ([S46 · HIGH](https://nmap.org/book/man-performance.html)). Research judgment: Mercury’s value is making the safe boundary the default guided workflow rather than exposing expert flags. |
| Local-first, portable incident case | Gives teams without an overlay or monitoring SaaS one redacted case file that can be handed to another administrator. | MEDIUM | Tailscale’s detailed ping is explicitly tailnet-only, NetBird diagnoses NetBird peers/control services, and ThousandEyes agents transmit data to the vendor service ([S18 · HIGH](https://tailscale.com/kb/1080/cli), [S17 · HIGH](https://docs.netbird.io/how-to/troubleshooting-client), [S35 · HIGH](https://docs.thousandeyes.com/product-documentation/global-vantage-points/endpoint-agents/how-endpoint-agents-work/how-does-the-endpoint-agent-work)). Research judgment: arbitrary authorized networks plus local custody is a credible niche. |
| Guided partial-connectivity recipes | Makes common hidden failures—DNS substitution, ICMP blocked while TCP works, one-way ACLs, MTU/path issues, and device-specific route choice—repeatable. | HIGH | Netshoot documents scenario workflows but leaves operators to run and interpret separate commands ([S21 · HIGH](https://github.com/nicolaka/netshoot)). Mercury can differentiate by compiling a recipe into a bounded plan and linking every conclusion to evidence. |

### Anti-Features (Commonly Requested, Often Problematic)

| Feature | Why requested | Why problematic | Alternative |
|---|---|---|---|
| Full Nmap replacement | “One binary should discover everything.” | Nmap already owns host discovery, ports, services, OS detection, scripting, timing, and machine output ([S07 · HIGH](https://nmap.org/book/man.html), [S08 · HIGH](https://nmap.org/book/man-host-discovery.html), [S11 · HIGH](https://nmap.org/book/man-output.html)). Reimplementation expands dual-use risk and delays the paired debugger. | Implement a small safe native probe set; optionally import externally produced Nmap XML after a license/security review. |
| Default full-port/full-protocol matrix | Appears exhaustive. | UDP silence is ambiguous, state space explodes, and brute-force coverage does not establish causality ([S10 · HIGH](https://nmap.org/book/scan-methods-udp-scan.html)). | Curated service profiles, operator-selected ports, sampled escalation, hard budgets, and an estimate before execution. |
| Packet-crafting laboratory / arbitrary payload editor | Advanced users want maximum control. | Nping already provides extensive packet generation and header/payload control ([S12 · HIGH](https://nmap.org/book/nping-man-echo-mode.html)). It turns Mercury into a dual-use generator rather than a diagnosis product. | Fixed, reviewed probe profiles with a narrow versioned extension interface later. |
| Throughput/speed-test centerpiece | Speed is easy to demo. | `iperf3`, Ethr, OpenSpeedTest, and perfSONAR already cover paired or self-hosted performance measurement ([S19 · HIGH](https://software.es.net/iperf/invoking.html), [S20 · HIGH](https://github.com/microsoft/ethr), [S25 · HIGH](https://github.com/openspeedtest/Speed-Test), [S30 · HIGH](https://www.perfsonar.net/)). High-rate tests can also disturb the network under diagnosis. | Import/launch an optional capped `iperf3` test only after reachability evidence indicates performance is the actual question. |
| “Automatic full topology” without management-plane data | A graph looks authoritative. | ARP/neighbor tools see on-link bindings, and LLDP reports advertised immediate Layer-2 neighbors; neither proves an unseen switched topology ([S14 · HIGH](https://github.com/royhills/arp-scan), [S16 · HIGH](https://lldpd.github.io/usage.html), [S34 · HIGH](https://man7.org/linux/man-pages/man8/ip-neighbour.8.html)). | Evidence-labeled local neighbor and routed-path views; mark inferred/unknown nodes explicitly. |
| NetBox/CMDB replacement | Discovery seems adjacent to inventory. | Orb Agent already combines scoped/scheduled Nmap and device discovery for the NetBox ecosystem ([S23 · HIGH](https://github.com/netboxlabs/orb-agent), [S24 · HIGH](https://raw.githubusercontent.com/netboxlabs/orb-agent/develop/docs/backends/network_discovery.md)). | Export a stable, redacted observation format or optional NetBox adapter after MVP. |
| Overlay VPN/control plane | Pairing suggests tunneling. | Tailscale and NetBird already provide peer connectivity, relays, routes, identity, and overlay-specific diagnostics ([S18 · HIGH](https://tailscale.com/kb/1080/cli), [S17 · HIGH](https://docs.netbird.io/how-to/troubleshooting-client)). | Pair over an existing reachable path; report NAT/firewall limitations; never bypass policy. |
| Continuous global/fleet monitoring in v1 | Teams want dashboards and alerts. | Blackbox Exporter, RIPE Atlas, perfSONAR, PingPlotter, and ThousandEyes occupy synthetic monitoring, global vantage points, scheduling, archives, and alerts ([S22 · HIGH](https://github.com/prometheus/blackbox_exporter), [S31 · HIGH](https://www.ripe.net/analyse/internet-measurements/ripe-atlas/), [S30 · HIGH](https://www.perfsonar.net/), [S26 · MEDIUM](https://www.pingplotter.com/products/standard/), [S28 · HIGH](https://docs.thousandeyes.com/product-documentation/end-user-monitoring/viewing-data/endpoint-agent-scheduled-tests-view)). | On-demand local cases and explicit run comparison; add scheduling only after users prove repeated incidents need it. |
| AI root-cause oracle | A definitive answer sounds valuable. | Filtered paths, UDP silence, missing LLDP, NAT, and privilege limits produce genuine ambiguity ([S10 · HIGH](https://nmap.org/book/scan-methods-udp-scan.html), [S16 · HIGH](https://lldpd.github.io/usage.html), [S24 · HIGH](https://raw.githubusercontent.com/netboxlabs/orb-agent/develop/docs/backends/network_discovery.md)). | Deterministic evidence rules with confidence, alternatives, and recommended next probes. Natural-language summaries may come later but cannot upgrade confidence. |
| Packet capture/content inspection by default | More data appears to mean better diagnosis. | Netshoot’s packet-capture workflows show the operational power and sensitivity of captures, while NetBird bundles already expose sensitive routing/firewall/resolver state ([S21 · HIGH](https://github.com/nicolaka/netshoot), [S17 · HIGH](https://docs.netbird.io/how-to/troubleshooting-client)). | Metadata-only probes by default; narrowly scoped capture as an explicit privileged export in a later phase, with retention/redaction controls. |
| Central multi-tenant SaaS in v1 | Makes collaboration and history easy. | ThousandEyes already provides the mature endpoint/fleet model ([S28 · HIGH](https://docs.thousandeyes.com/product-documentation/end-user-monitoring/viewing-data/endpoint-agent-scheduled-tests-view), [S29 · HIGH](https://docs.thousandeyes.com/product-documentation/end-user-monitoring/viewing-data/endpoint-agent-local-networks-view)). | Local WebUI plus encrypted/exportable case files; validate the incident workflow before building tenancy, billing, and fleet security. |

## Feature Dependencies

```text
[Versioned evidence schema + network outcome semantics]
    ├──requires──> [Cross-platform collectors]
    ├──requires──> [Bounded cancellable probe executor]
    │                   └──guarded-by──> [Scope, budget, consent, audit]
    └──enables──> [CLI canonical JSON artifact]
                        ├──enables──> [Minimal local WebUI]
                        ├──enables──> [Redacted report]
                        └──enables──> [Run-to-run diff]

[Authenticated short-lived pairing]
    └──requires──> [Bounded probe executor]
    └──enables──> [Role-swapped A↔B probe plan]
                        └──requires──> [Clock/timestamp + endpoint identity metadata]
                        └──enables──> [Direction × protocol × endpoint matrix]
                                                └──enables──> [Evidence-linked diagnosis rules]

[Local snapshot] ──enhances──> [Evidence-linked diagnosis rules]
[Path probes] ─────enhances──> [Evidence-linked diagnosis rules]
[Optional LLDP/neighbor evidence] ──enhances──> [Local context]

[Unbounded scanner] ──conflicts──> [Safe incident debugger]
[SaaS fleet control plane] ──conflicts──> [Local-first MVP focus]
[Independent WebUI probe code] ──conflicts──> [One canonical engine]
```

### Dependency Notes

- **Outcome semantics and evidence schema come first.** Probe/UI work built before these contracts will encode false binaries such as “open/closed” or “online/offline” and require a rewrite.
- **The bounded executor precedes pairing and discovery.** Both features create remote traffic and must inherit cancellation, cost estimation, audit, and hard ceilings.
- **Pairing precedes the main differentiator.** The direction matrix is impossible to trust if endpoints cannot authenticate each other, agree on the exact plan/version, and retain their roles.
- **CLI artifact precedes WebUI.** The WebUI must render canonical events/results rather than create a second diagnostic implementation.
- **Report and history depend on redaction/schema versioning.** Storing ad hoc terminal text first will make safe comparison and migration expensive.
- **Discovery and LLDP are downstream context.** They can enrich a diagnosis but do not validate the core paired-value hypothesis.

## MVP Definition

### Launch With (v1)

Minimum product needed to validate the narrow hypothesis:

- [ ] **Versioned evidence/outcome model** — tasks, probes, observations, inferences, unknowns, confidence, errors, authorization, endpoint/direction, and redaction are first-class.
- [ ] **Cross-platform normal-user snapshot** — Windows, Linux, and macOS collectors produce the same logical model and explicitly record gaps/fallbacks.
- [ ] **Safe plan executor** — strict host/port/rate/concurrency/time/output budgets, preflight estimate, cancellation, audit, and no arbitrary payloads.
- [ ] **Authenticated ephemeral pairing** — two endpoints consent to one bounded plan and close listeners automatically.
- [ ] **Role-swapped core probes** — DNS, TCP connect/listen, UDP with exact silence semantics, ICMP where available, and minimal HTTP/TLS application confirmation.
- [ ] **Differential result matrix and deterministic explanations** — identify which endpoint, direction, protocol/port, or layer differs; link every conclusion to observations.
- [ ] **Minimal path evidence** — at least one unprivileged-capable method plus explicit degradation; never treat silent hops as proof.
- [ ] **Canonical CLI JSON plus minimal local WebUI** — live progress, A↔B matrix, conclusion/evidence drawer, path, run diff, and report export over the same engine.
- [ ] **Redacted portable case file** — previewable, versioned, and usable without a central service.

Do **not** require broad subnet discovery, LLDP, speed tests, continuous monitoring, plugins, or a topology canvas to validate v1.

### Add After Validation (v1.x)

- [ ] **Passive-first local discovery and a small active host/service set** — add only if paired-incident users repeatedly need local context; reuse/import mature scanners rather than expanding probe breadth.
- [ ] **LLDP/OS-neighbor adapters** — add when managed-network users can supply representative fixtures and accept capability-dependent results.
- [ ] **Additional application probes** — add DNS-over-TCP, SMTP banner, SSH banner, QUIC, or custom enterprise protocols only from observed incident demand.
- [ ] **MTU/PMTUD recipe** — add after the core direction matrix is stable; platform and middlebox behavior make this a separate research phase.
- [ ] **Optional capped `iperf3` handoff/import** — add if users show that reachability incidents routinely become performance investigations.
- [ ] **Signed/encrypted case exchange** — add when teams use reports across trust boundaries.

### Future Consideration (v2+)

- [ ] **Scheduled repeated cases** — only if users need intermittent-incident capture and existing Prometheus/perfSONAR/PingPlotter integrations are insufficient.
- [ ] **Inventory/NetBox export adapters** — integrate rather than build a CMDB.
- [ ] **Organization-managed probe policy bundles** — only after the local authorization model survives security review.
- [ ] **Privileged packet capture helper** — separate process, explicit consent, narrow filters, and retention controls.
- [ ] **More than two cooperating endpoints** — only after two-endpoint differential value is proven; multi-party coordination approaches perfSONAR/ThousandEyes complexity.

## Feature Prioritization Matrix

| Feature | User value | Implementation cost | Priority |
|---|---:|---:|---:|
| Evidence/outcome semantics | HIGH | HIGH | P1 |
| Safe bounded executor | HIGH | HIGH | P1 |
| Cross-platform local snapshot | HIGH | HIGH | P1 |
| Authenticated ephemeral pairing | HIGH | HIGH | P1 |
| Role-swapped multi-protocol plan | HIGH | HIGH | P1 |
| Differential matrix + evidence rules | HIGH | HIGH | P1 |
| Canonical CLI artifact | HIGH | MEDIUM | P1 |
| Redacted report + run diff | HIGH | MEDIUM | P1 |
| Minimal local WebUI | MEDIUM | HIGH | P1, narrowly scoped |
| Minimal path probes | MEDIUM | HIGH | P1 |
| Local subnet/service discovery | MEDIUM | HIGH | P2 |
| LLDP/neighbor enrichment | MEDIUM | HIGH | P2 |
| MTU/PMTUD diagnosis | MEDIUM | HIGH | P2 |
| Optional performance-test import | LOW | MEDIUM | P2/P3 |
| Continuous monitoring/alerts | LOW for the validated wedge | HIGH | P3 |
| Multi-node fleet/SaaS control plane | LOW for the validated wedge | VERY HIGH | Do not schedule |
| Full scanner/topology engine | LOW; harms focus | VERY HIGH | Anti-feature |

**Priority key:**

- **P1:** required to validate the product thesis.
- **P2:** add only after evidence from real incidents.
- **P3:** likely better served by integration.

## Competitor Feature Analysis

| Capability | Best existing evidence | Mercury approach |
|---|---|---|
| Single-host reachability/path | ping, traceroute, MTR, `Test-NetConnection` ([S01 · HIGH](https://man7.org/linux/man-pages/man8/ping.8.html), [S02 · HIGH](https://traceroute.sourceforge.net/), [S03 · HIGH](https://www.bitwizard.nl/mtr/), [S05 · HIGH](https://learn.microsoft.com/en-us/powershell/module/nettcpip/test-netconnection)). | Normalize results, retain method/privilege, compare both endpoints; do not clone their probing breadth. |
| Host/service discovery | Nmap, arp-scan, Orb Agent ([S07 · HIGH](https://nmap.org/book/man.html), [S14 · HIGH](https://github.com/royhills/arp-scan), [S23 · HIGH](https://github.com/netboxlabs/orb-agent)). | Small, bounded context phase after core validation; import mature output where practical. |
| Packet-level directional test | Nping Echo Mode ([S12 · HIGH](https://nmap.org/book/nping-man-echo-mode.html)). | Use a safer fixed-profile protocol and combine its directional evidence with DNS/path/local-state/service evidence. |
| Bidirectional performance | `iperf3`, Ethr, perfSONAR ([S19 · HIGH](https://software.es.net/iperf/invoking.html), [S20 · HIGH](https://github.com/microsoft/ethr), [S30 · HIGH](https://www.perfsonar.net/)). | Do not compete; optionally hand off/import after reachability diagnosis. |
| Overlay peer diagnosis | Tailscale, NetBird ([S18 · HIGH](https://tailscale.com/kb/1080/cli), [S17 · HIGH](https://docs.netbird.io/how-to/troubleshooting-client)). | Diagnose arbitrary authorized underlay/service paths without becoming an overlay. |
| Integrated toolbox | Netshoot ([S21 · HIGH](https://github.com/nicolaka/netshoot)). | Compile a bounded hypothesis into a plan and evidence graph; avoid a shell full of disconnected tools. |
| Synthetic monitoring | Blackbox Exporter, RIPE Atlas, perfSONAR ([S22 · HIGH](https://github.com/prometheus/blackbox_exporter), [S31 · HIGH](https://www.ripe.net/analyse/internet-measurements/ripe-atlas/), [S30 · HIGH](https://www.perfsonar.net/)). | On-demand incident case, local custody, explicit pairing; provide export/integration later. |
| Visual history/share | PingPlotter, ThousandEyes ([S26 · MEDIUM](https://www.pingplotter.com/products/standard/), [S28 · HIGH](https://docs.thousandeyes.com/product-documentation/end-user-monitoring/viewing-data/endpoint-agent-scheduled-tests-view)). | Minimal evidence-first UI and local run diff; no fleet dashboard in v1. |
| Evidence/uncertainty semantics | Nmap’s six-state model is the strongest reviewed precedent for refusing false certainty ([S09 · HIGH](https://nmap.org/book/man-port-scanning-basics.html), [S10 · HIGH](https://nmap.org/book/scan-methods-udp-scan.html)). | Apply provenance/confidence/unknown semantics across every collector, probe, inference, report, and UI view. |

## Explicit Counterarguments for NOT Building Mercury

1. **Most raw capability already exists for free.** A skilled operator can combine OS state, ping/MTR, Nmap/Nping/Ncat, DNS tools, and `iperf3`; Netshoot even packages many of them with scenario recipes ([S05 · HIGH](https://learn.microsoft.com/en-us/powershell/module/nettcpip/test-netconnection), [S07 · HIGH](https://nmap.org/book/man.html), [S12 · HIGH](https://nmap.org/book/nping-man-echo-mode.html), [S13 · HIGH](https://nmap.org/ncat/guide/index.html), [S19 · HIGH](https://software.es.net/iperf/invoking.html), [S21 · HIGH](https://github.com/nicolaka/netshoot)). **Cancellation implication:** a command wrapper is not a product.

2. **The apparent differentiators are individually occupied.** Nping provides directional echo evidence; `iperf3` provides bidirectional client/server testing; PingPlotter provides history/sharing; perfSONAR provides coordinated scheduling/archives; ThousandEyes provides endpoint/local-network/path views ([S12 · HIGH](https://nmap.org/book/nping-man-echo-mode.html), [S19 · HIGH](https://software.es.net/iperf/invoking.html), [S26 · MEDIUM](https://www.pingplotter.com/products/standard/), [S30 · HIGH](https://www.perfsonar.net/), [S28 · HIGH](https://docs.thousandeyes.com/product-documentation/end-user-monitoring/viewing-data/endpoint-agent-scheduled-tests-view)). **Cancellation implication:** Mercury wins only if the combined workflow is materially faster and clearer.

3. **Campus/research networks already have a purpose-built distributed option.** perfSONAR coordinates end-to-end measurements, access controls, scheduling, archives, and dashboards across deployed instances ([S30 · HIGH](https://www.perfsonar.net/), [S32 · HIGH](https://docs.perfsonar.net/pscheduler_intro.html)). **Cancellation implication:** do not target permanent R&E measurement infrastructure; target ad hoc endpoint incidents or stop.

4. **Truth has hard limits.** UDP silence is ambiguous, traceroute hops can be unresponsive or alternate, ARP is local-link only, and LLDP depends on advertisements from immediate neighbors ([S10 · HIGH](https://nmap.org/book/scan-methods-udp-scan.html), [S45 · HIGH](https://docs.thousandeyes.com/product-documentation/internet-and-wan-monitoring/path-visualization/path-trace), [S14 · HIGH](https://github.com/royhills/arp-scan), [S16 · HIGH](https://lldpd.github.io/usage.html)). **Cancellation implication:** if product messaging requires definitive automated root cause, it will overpromise.

5. **The second endpoint may be unavailable precisely when needed.** Research judgment: installation, pairing, NAT/firewall reachability, ownership boundaries, and outage timing can make a two-ended workflow impossible. **Cancellation implication:** Mercury still needs a useful one-ended artifact, while reserving its strongest claims for paired mode.

6. **Cross-platform parity is expensive and may be illusory.** Raw-socket and LLDP capabilities depend on privilege/daemon support, while rootless fallbacks change probe fidelity ([S24 · HIGH](https://raw.githubusercontent.com/netboxlabs/orb-agent/develop/docs/backends/network_discovery.md), [S16 · HIGH](https://lldpd.github.io/usage.html)). **Cancellation implication:** if ordinary-user mode cannot answer enough useful questions on all three OSes, the distribution promise is not defensible.

7. **An authenticated listener and active scanner create security liability.** Nping’s echo mode requires an authenticated/encrypted channel, while perfSONAR applies explicit limits over who may run which tests ([S12 · HIGH](https://nmap.org/book/nping-man-echo-mode.html), [S32 · HIGH](https://docs.perfsonar.net/pscheduler_intro.html)). **Cancellation implication:** pairing, least privilege, budgets, audit, and protocol threat modeling are launch features, not polish.

8. **The mature enterprise version already exists.** ThousandEyes provides endpoint scheduled tests, local network context, historical views, and path visualization ([S28 · HIGH](https://docs.thousandeyes.com/product-documentation/end-user-monitoring/viewing-data/endpoint-agent-scheduled-tests-view), [S29 · HIGH](https://docs.thousandeyes.com/product-documentation/end-user-monitoring/viewing-data/endpoint-agent-local-networks-view)). **Cancellation implication:** Mercury should not chase enterprise fleet breadth; its niche is open/local/on-demand paired evidence.

9. **The addressable niche may be too small.** Research judgment: users capable of installing two diagnostic agents may already know the component tools, while less-technical users may not control both endpoints. **Cancellation implication:** user testing must prove that reduced interpretation/coordination cost is worth installing Mercury.

10. **Maintenance breadth can erase the value.** Research judgment: three OS adapters, privileged helpers, a secure protocol, probe semantics, packaging, WebUI, schemas, and controlled-network tests form a large surface before broad discovery begins. **Cancellation implication:** if the project will not enforce the anti-features above, do not start.

## Falsifiable Product-Value Gate

Before roadmap expansion, run a time-boxed prototype evaluation. These are proposed thresholds, not industry facts.

### Lab Gate

Construct at least 12 blinded incidents across Windows/Linux/macOS endpoint pairs, covering:

- DNS answer/resolver-path mismatch;
- ICMP blocked while target TCP/application works;
- TCP allowed in one direction and refused/filtered in the other;
- UDP response, ICMP-unreachable, and silent/unknown outcomes;
- route/source-interface change;
- MTU/path issue only if the MVP claims to diagnose it.

Pass only if:

- at least 10/12 reports identify the correct layer + direction + protocol/port;
- the other cases are reported as evidence-backed “unknown”, not an incorrect diagnosis;
- there are **zero** false claims that UDP silence means open/reachable;
- a shareable redacted artifact is produced within five minutes of pairing;
- the normal-user baseline runs on all three OSes and visibly explains every degraded probe.

### Operator Gate

Give at least five target users the same incidents using (a) existing tools/documented recipes and (b) Mercury. Continue only if:

- at least four of five prefer Mercury for handing evidence to another administrator;
- median time to a correct, shareable conclusion improves by at least 50%;
- users can point to the evidence behind a conclusion without reading raw logs;
- no participant accidentally exceeds the authorized scope or probe budget.

**If Mercury fails either gate, the recommendation becomes NO-GO.** Improve integrations/documentation for existing tools instead of building a broad product.

## Sources

All sources accessed 2026-07-30.

| ID | Primary source | Confidence and use |
|---|---|---|
| S01 | [iputils `ping(8)` manual](https://man7.org/linux/man-pages/man8/ping.8.html) | HIGH for documented ping semantics; man7 is a maintained manual mirror. |
| S02 | [Traceroute for Linux project](https://traceroute.sourceforge.net/) | HIGH for supported probe methods. |
| S03 | [MTR project site](https://www.bitwizard.nl/mtr/) | HIGH for MTR’s ping/traceroute role. |
| S04 | [MTR official man-page source](https://raw.githubusercontent.com/traviscross/mtr/master/man/mtr.8.in) | HIGH for output modes. |
| S05 | [Microsoft `Test-NetConnection`](https://learn.microsoft.com/en-us/powershell/module/nettcpip/test-netconnection) | HIGH; official Microsoft documentation. |
| S06 | [NetworkManager `nmcli`](https://networkmanager.dev/docs/api/latest/nmcli.html) | HIGH; official project documentation. |
| S07 | [Nmap Reference Guide](https://nmap.org/book/man.html) | HIGH; official Nmap documentation. |
| S08 | [Nmap Host Discovery](https://nmap.org/book/man-host-discovery.html) | HIGH; official Nmap documentation. |
| S09 | [Nmap Port Scanning Basics](https://nmap.org/book/man-port-scanning-basics.html) | HIGH for state semantics. |
| S10 | [Nmap UDP Scan](https://nmap.org/book/scan-methods-udp-scan.html) | HIGH for UDP response/silence semantics. |
| S11 | [Nmap Output](https://nmap.org/book/man-output.html) | HIGH for structured output. |
| S12 | [Nping Echo Mode](https://nmap.org/book/nping-man-echo-mode.html) | HIGH for paired directional prior art and channel behavior. |
| S13 | [Ncat Users’ Guide](https://nmap.org/ncat/guide/index.html) | HIGH for client/server/relay capabilities. |
| S14 | [`arp-scan` official repository](https://github.com/royhills/arp-scan) | HIGH for local IPv4 ARP discovery. |
| S15 | [Netdiscover official repository](https://github.com/netdiscover-scanner/netdiscover) | HIGH for ARP request/reply discovery. |
| S16 | [`lldpd` Usage](https://lldpd.github.io/usage.html) | HIGH for LLDP daemon/client, neighbor, receive-only, and privilege behavior. |
| S17 | [NetBird client troubleshooting](https://docs.netbird.io/how-to/troubleshooting-client) | HIGH; official current product documentation. |
| S18 | [Tailscale CLI](https://tailscale.com/kb/1080/cli) | HIGH for `netcheck`, `ping`, status, and bug-report behavior. |
| S19 | [`iperf3` invocation manual](https://software.es.net/iperf/invoking.html) | HIGH for client/server, protocol, reverse, and bidirectional modes. |
| S20 | [Microsoft Ethr official repository](https://github.com/microsoft/ethr) | HIGH for documented feature scope and repository metadata. |
| S21 | [Netshoot official repository](https://github.com/nicolaka/netshoot) | HIGH for packaged tools and documented troubleshooting scenarios. |
| S22 | [Prometheus Blackbox Exporter official repository](https://github.com/prometheus/blackbox_exporter) | HIGH for prober types and metrics/debug behavior. |
| S23 | [NetBox Labs Orb Agent official repository](https://github.com/netboxlabs/orb-agent) | HIGH for current NetBox Discovery scope and repository metadata. |
| S24 | [Orb network-discovery backend documentation](https://raw.githubusercontent.com/netboxlabs/orb-agent/develop/docs/backends/network_discovery.md) | HIGH for Nmap, scopes, schedules, privilege, and fallback claims. |
| S25 | [OpenSpeedTest official repository](https://github.com/openspeedtest/Speed-Test) | HIGH for self-hosted performance-test scope and repository metadata. |
| S26 | [PingPlotter Standard](https://www.pingplotter.com/products/standard/) | MEDIUM; first-party product claims. |
| S27 | [PingPlotter Manual](https://www.pingplotter.com/manual/) | MEDIUM-HIGH for documented product workflows. |
| S28 | [ThousandEyes Endpoint Agent Scheduled Tests View](https://docs.thousandeyes.com/product-documentation/end-user-monitoring/viewing-data/endpoint-agent-scheduled-tests-view) | HIGH; official Cisco/ThousandEyes documentation. |
| S29 | [ThousandEyes Endpoint Agent Local Networks View](https://docs.thousandeyes.com/product-documentation/end-user-monitoring/viewing-data/endpoint-agent-local-networks-view) | HIGH; official Cisco/ThousandEyes documentation. |
| S30 | [perfSONAR project site](https://www.perfsonar.net/) | HIGH for project scope, deployment model, scheduling/storage claims. |
| S31 | [RIPE Atlas overview](https://www.ripe.net/analyse/internet-measurements/ripe-atlas/) | HIGH; official RIPE NCC source. |
| S32 | [perfSONAR pScheduler introduction](https://docs.perfsonar.net/pscheduler_intro.html) | HIGH for participant coordination, limits, scheduling, and archiving. |
| S33 | [OpenNetLab P2P Measurement repository](https://github.com/OpenNetLab/OpenNetLab-P2P-Measurment) | MEDIUM for prototype scope; README is primary but project maturity is unclear. |
| S34 | [`ip-neighbour(8)` manual](https://man7.org/linux/man-pages/man8/ip-neighbour.8.html) | HIGH for neighbor/ARP table scope; man7 is a maintained manual mirror. |
| S35 | [How ThousandEyes Endpoint Agent works](https://docs.thousandeyes.com/product-documentation/global-vantage-points/endpoint-agents/how-endpoint-agents-work/how-does-the-endpoint-agent-work) | HIGH for service/data-flow claims. |
| S36 | [MTR official repository](https://github.com/traviscross/mtr) | HIGH for repository archive/license metadata. |
| S37 | [MTR commit feed](https://github.com/traviscross/mtr/commits/master.atom) | HIGH for visible latest-feed timestamp. |
| S38 | [Netshoot commit feed](https://github.com/nicolaka/netshoot/commits/master.atom) | HIGH for visible latest-feed timestamp. |
| S39 | [Blackbox Exporter commit feed](https://github.com/prometheus/blackbox_exporter/commits/master.atom) | HIGH for visible latest-feed timestamp. |
| S40 | [Orb Agent commit feed](https://github.com/netboxlabs/orb-agent/commits/develop.atom) | HIGH for visible latest-feed timestamp. |
| S41 | [Ethr commit feed](https://github.com/microsoft/ethr/commits/master.atom) | HIGH for visible latest-feed timestamp. |
| S42 | [OpenSpeedTest commit feed](https://github.com/openspeedtest/Speed-Test/commits/main.atom) | HIGH for visible latest-feed timestamp. |
| S43 | [OpenNetLab P2P commit feed](https://github.com/OpenNetLab/OpenNetLab-P2P-Measurment/commits/main.atom) | HIGH for visible latest-feed timestamp. |
| S44 | [Nmap Public Source License](https://nmap.org/npsl/) | HIGH; official licensing source. |
| S45 | [ThousandEyes Path Trace](https://docs.thousandeyes.com/product-documentation/internet-and-wan-monitoring/path-visualization/path-trace) | HIGH for documented path behavior. |
| S46 | [Nmap Timing and Performance](https://nmap.org/book/man-performance.html) | HIGH for scan rate, parallelism, and timeout controls. |

## Gaps and Confidence Limits

- No primary source can prove that a competitor **does not** implement Mercury’s proposed full combination. The whitespace conclusion is therefore MEDIUM confidence.
- Vendor documentation establishes offered features, not real-world usability, diagnostic accuracy, or total cost.
- No user interviews, incident corpus, willingness-to-install evidence, or willingness-to-pay evidence exists yet; the operator gate is mandatory.
- The closest comparison changes by segment: perfSONAR is strongest in research/education infrastructure, ThousandEyes in managed enterprise fleets, Tailscale/NetBird inside overlays, and Nping/Netshoot for expert operators.
- Phase-specific research is still required for protocol threat modeling, OS privilege parity, UDP/application probe semantics, report privacy, and licensing of any bundled third-party executable.

---
*Feature research for: Mercury distributed network diagnosis*  
*Researched: 2026-07-30*
