# Tunnel-Exposure Coverage Matrix

**Defined:** 2026-08-02
**Status:** Planned contract for phases 2–4

## Assessment Contract

This matrix answers one operational question: does at least one tested carrier permit a tagged Mercury message from one configured endpoint to reach the other endpoint and, where the carrier supports it, return an acknowledgement?

A matching send/receive correlation is direct positive evidence that the tested carrier is usable for communication in that direction. A negative result is limited to the exact profile, packet shape, ports, source/destination pair, and time window recorded in the result. Mercury must never emit an “all tunnel possibilities eliminated” conclusion.

## Receiver Model

- Peer control remains mutually authenticated and is used only to provision a short-lived, correlation-bound test lease.
- Each endpoint binds only the preconfigured receiver ports/profiles in its local peer configuration.
- A receiver records correlation ID, source address/port, destination port, protocol profile, arrival timestamp, payload digest/length, and reply result.
- The peer controller never accepts a third-party destination or raw arbitrary payload from a caller.
- A receiver can report unsupported or permission_denied; lack of that capability is a coverage gap, not a negative reachability result.

## Coverage Profiles

| Profile | Sender behavior | Receiver/observer evidence | Directional result |
|---------|-----------------|----------------------------|--------------------|
| TCP connect | Complete a TCP handshake to each selected port | Configured receiver accepts a tagged connection, or connection outcome is recorded for an existing service | Connected, refused, reset, unreachable, timeout |
| TCP tagged exchange | Send a fixed correlation record after connection | Peer receiver validates the tag and returns a fixed acknowledgement | Arrival-confirmed, reply-confirmed, one-way, or no evidence |
| UDP tagged exchange | Send a fixed-size, digest-bound UDP datagram to each selected port | Peer receiver validates and optionally echoes a fixed acknowledgement | Arrival-confirmed, reply-confirmed, ICMP unreachable, silent, or error |
| DNS over UDP/TCP | Issue a standard query with a correlation label to a configured test resolver endpoint | DNS receiver records query and returns an approved fixed answer | Query-arrived, answer-returned, refusal, timeout, or unsupported |
| ICMP echo | Use a native echo request with a correlation identifier/payload where the platform permits it | OS reply is recorded; privileged peer capture may add an arrival receipt | Echo-reply, unreachable, timeout, permission-denied, or unsupported |
| TLS handshake | Perform a TLS handshake to a configured receiver with a certificate/pin identity | TLS listener records handshake metadata; client records verification/handshake outcome | Handshake-confirmed, verification-failed, refused, timeout, or error |
| HTTP exchange | Send a fixed request to a configured HTTP test endpoint after TCP/TLS admission | Receiver records request correlation and returns a fixed response | Request-arrived, response-returned, or lower-layer outcome |
| SSH banner | Read only the initial SSH server banner on selected ports; never authenticate | Client records banner/lower-layer evidence | Banner-observed, refused, timeout, or error |
| ARP / IPv6 ND | Inspect and, where platform capability exists, test neighbour resolution only on the local L2 link | Local neighbour/cache/native capability evidence | Local-link evidence or not-applicable |
| Native Nmap TCP/UDP/SCTP profile | Optional native scanner runs a fixed profile created from the admitted plan | Bounded XML parser records Nmap provenance | Native-open/closed/filtered/open-or-filtered plus parser/capability state |

## Layer-2 Boundary

ARP and IPv6 Neighbour Discovery are link-local. For endpoints on different IPv4 subnets, an ARP reply pertains to the local next hop rather than the remote endpoint. The matrix must report ARP/ND as not_applicable_for_remote_pair for cross-subnet reachability rather than use it as evidence that the peer can communicate.

## Coverage Output

Every assessment produces:

1. A normalized list of requested and actually attempted profiles.
2. A profile-by-direction coverage table with sender and peer-receiver evidence IDs.
3. A list of positive candidate carriers: any profile with confirmed arrival or an application/transport response.
4. A list of unavailable, permission-denied, skipped, and non-applicable profiles.
5. A conclusion whose scope is the exact coverage matrix, never an assertion about untested packets or tunnel implementations.

## Excluded Behaviors

- No credential attempts, authentication guessing, or login brute force.
- No arbitrary payload forwarding, arbitrary raw-packet crafting, or generic Nmap argument forwarding.
- No claim that the finite matrix proves an absence of all possible communication or tunnelling mechanisms.

---

*Last updated: 2026-08-02 after peer-receiver and tunnel-exposure planning*
