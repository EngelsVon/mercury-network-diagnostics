# Phase 4 Research: Safe Discovery, Topology Evidence, and Routes

## Recommended Approach

Use the existing planner, task service, evidence model and fixed-argv platform
command runner. Add no runtime dependencies.

1. Passive collection derives IPv4 connected prefixes from `psutil.net_if_addrs`
   and consumes fixed platform neighbor/Wi-Fi/LLDP commands only when present.
2. Active discovery compiles one TCP-connect `ProbeSpec` per selected address
   and port through `preview_probe_plan` / `authorize_plan`; the runner calls
   `TaskContext.admit`, uses bounded `asyncio.open_connection`, records a
   typed observation, then completes the same step.
3. Route tracing uses fixed native argv (`tracert` on Windows, `traceroute` on
   Ubuntu), bounded output/time, and typed parsed observations. Missing hops
   are `PATH_HOP_UNANSWERED`; a response is not a switch claim.

## Platform Commands

| Purpose | Windows | Ubuntu | Degradation |
|---|---|---|---|
| Neighbor cache | `Get-NetNeighbor` JSON | `ip -j neigh show` | capability unavailable/error |
| Wi-Fi | `netsh wlan show interfaces` | `iw dev` | missing tool / no Wi-Fi |
| LLDP | `Get-NetLldpAgent` where available | `lldpctl -f json` | missing tool / no direct evidence |
| Trace | `tracert -d -h <n> -w <ms> <ip>` | `traceroute -n -m <n> -w <s> <ip>` | missing/permission/timeout |

All argv values are locally generated from normalized numeric addresses and
bounded integers; no shell string is built.

## Security Notes

- Reject non-IPv4 active discovery before any network I/O.
- Require explicit authorization and scope containment before plan generation.
- Full port mode uses the existing dangerous confirmation. It must never become
  the default and its final plan is still subject to immutable absolute limits.
- Neighbor cache and route hops are observations only. Infer neither ownership
  nor a Layer-2 switch from them.
- Record source, timing, direction, tool capability and raw bounded fields so
  a conclusion can stay provisional.

## Validation Map

| Requirement | Automated proof |
|---|---|
| INVT-04/05 | fixture parser tests distinguish gateway/neighbor/Wi-Fi/LLDP and missing LLDP limitation |
| DISC-01 | passive IPv4 prefix derivation and IPv6 refusal tests |
| DISC-02/03 | scope/authorization/full-confirmation and controlled loopback TCP refusal/connect/timeout tests |
| DISC-04 | missing/available native trace parser tests retain unanswered/alternate hops |
| DISC-05 | direct LLDP only topology tests; no gateway/ARP/route hop becomes switch |

## Pitfalls

- Never treat an empty neighbor cache as a scan result.
- Never parse localized diagnostic text into a root-cause claim.
- Keep native trace command execution out of render/CLI modules.
- Do not create a second budget or an unplanned socket loop; reuse TaskContext.
