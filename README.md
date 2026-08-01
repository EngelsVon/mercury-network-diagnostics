# Mercury

Mercury is a local-first, evidence-first network diagnostics tool. It reports
what was observed for selected endpoints and layers; it is not a scanner,
topology oracle, or a replacement for Nmap, MTR, iperf3, or LLDP tooling.

## Installation

Mercury supports CPython 3.11+ and has one runtime dependency, `psutil`.

```powershell
python -m pip install mercury-netdiag
mercury --help
```

For a checkout, use `python -m pip install -e .`.

## Quick start

`status` is passive and collects local host, interface, route, DNS, capability,
and limitation evidence:

```powershell
mercury status
mercury status --json
```

Run diagnosis only for endpoints you own or are authorized to test. Built-in
profiles are immutable (`basic-v1` and `china-v1`); custom endpoints are exact
repeatable `HOST:PORT` values, including `[::1]:443`.

```powershell
mercury diagnose --profile basic --authorized
mercury diagnose --target example.internal:443 --target [::1]:443 --timeout 3 --authorized --json
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

## Safety and limitations

- Active work is normalized, authorized, admitted, rate-limited, and bounded
  before it starts. Public profile use requires explicit authorization.
- DNS, TCP, TLS, HTTP, native ping, and path observations retain separate
  outcomes; silence and timeout are inconclusive, not success or failure.
- Diagnosis conclusions cover only the selected endpoints and observed layers;
  Mercury never makes a universal Internet or root-cause claim.
- Tests use fakes and loopback only. They never resolve or connect to built-in
  public profile targets.
- SQLite history rejects credentials and secret material. Peer mode, discovery,
  WebUI, reports, and release hardening remain future work.
