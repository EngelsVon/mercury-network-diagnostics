# Mercury（墨丘利）

Mercury is an evidence-first network reachability diagnostic tool under active
development. Its narrow purpose is to explain which endpoint, direction,
layer, protocol, or port differs—not to replace Nmap, MTR, iperf3, or an LLDP
daemon.

The current foundation release provides:

- a versioned JSON evidence model with separate protocol evidence and semantic
  disposition;
- strict target/scope parsing, DNS answer revalidation, cost previews, and
  non-bypassable work ceilings;
- cancellable offline lifecycle verification with partial SQLite history;
- one CLI entry point for schema, plan, lifecycle, and history inspection.

Real network inventory and probes arrive in the next phases. The synthetic task
never opens a network socket.

## Development quick start

```powershell
python -m pip install -e .
python -m mercury --help
python -m mercury model --json
python -m mercury plan 127.0.0.1 --ports 53,443 --json
python -m mercury task synthetic --steps 5 --delay 0.01
python -m unittest discover -s tests -v
```

For any non-loopback active plan, pass `--authorized` and an exact `--scope`.
This is an attestation that you own the target or have permission to test it;
Mercury cannot grant legal or organizational authority.

Full-port and custom UDP plans require digest-bound second confirmations before
execution. “All packet kinds” is not finite and is intentionally unsupported.
Budgets count logical attempt starts, Mercury-generated UDP datagrams, and
application payload bytes. They do not claim to measure kernel retransmissions
or exact on-wire framing.

## Evidence semantics

Silence, timeout, refusal, reset, unreachable, unsupported, permission denied,
and execution error are different observations. In particular, UDP or ICMP
silence is inconclusive—not proof that a port is open, closed, or reachable.

Mercury does not label a gateway, ARP neighbor, or traceroute hop as a switch.
Only direct evidence such as LLDP can identify adjacent infrastructure; when
that evidence is unavailable, the correct answer is “not observable.”

## Safety and privacy

- Active work is normalized, authorized, costed, and bounded before execution.
- Local SQLite history is count/age bounded and uses a current-user data
  directory; tokens, private keys, pairing secrets, and credential fields are
  rejected from persistence.
- Export redaction, mTLS peer mode, discovery, route analysis, and the WebUI are
  scheduled work and are not claimed by this foundation release.
- Tests use loopback and deterministic fakes; they do not scan public networks.

See `.planning/REQUIREMENTS.md` and `.planning/ROADMAP.md` for the verified
scope and delivery plan.
