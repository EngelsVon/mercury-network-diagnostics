# Phase 4: Safe Discovery, Topology Evidence, and Routes - Context

**Gathered:** 2026-08-02  
**Status:** Ready for planning

<domain>
## Phase Boundary

Provide passive-first local IPv4 network context, explicitly authorized bounded
TCP discovery, repeated native route evidence, and honest neighbor/Wi-Fi/LLDP
projections for Windows and Ubuntu. This phase does not add a general scanner,
raw packet capture, IPv6 enumeration, SNMP, or a topology oracle.

</domain>

<decisions>
## Implementation Decisions

### Discovery safety
- Passive discovery derives only IPv4 connected networks and locally available
  neighbor records; it transmits no packets and explicitly refuses IPv6
  enumeration.
- Active discovery accepts one operator-supplied IPv4 CIDR only when it is
  contained in the canonical authorized scope and `--authorized` is present.
- Port plans are fixed `common`, explicit bounded `custom`, or `full`; full
  mode requires the existing independent dangerous-work confirmation and all
  work goes through the immutable planner and TaskContext.
- Connect/refusal/timeout stay separate evidence. Progress reflects admitted
  and completed canonical attempts; no process claims kernel retransmission or
  wire-byte accounting.

### Topology evidence
- Gateway, ARP/NDP neighbor, first trace hop, Wi-Fi access point, and direct
  LLDP neighbor are distinct observation types.
- Only parsed direct LLDP evidence may identify an infrastructure neighbor;
  absent or missing LLDP must retain the existing “access switch not
  observable” limitation.
- Platform commands use fixed argv, bounded output and bounded time through
  `mercury.platform.common`; missing tools and permissions become capabilities,
  never silent success.

### Route evidence
- Trace supports one already-authorized numeric target, a finite per-hop wait,
  and a fixed small repeat count. It retains each raw hop response, unanswered
  hop and alternate hop instead of declaring a single certain route.
- Native tool text is parsed only as evidence with source/mode metadata;
  localized/unparseable output remains an explicit error or partial result.

### the agent's Discretion
- Exact common port set, fixed repeat count and concise CLI table shape should
  follow existing hard ceilings and evidence conventions.

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `src/mercury/planner.py` supplies immutable ProbePlan, scopes, cost previews
  and dangerous-work confirmations.
- `src/mercury/tasks.py` supplies admission, cancellation, rate/concurrency
  ceilings, canonical persistence and terminal result construction.
- `src/mercury/platform/common.py` supplies fixed-argv bounded subprocess
  execution; Windows and Linux adapters already parse passive routes/DNS.
- `src/mercury/models.py` already contains typed path evidence semantics and
  explicitly separates silent, timeout, unsupported and permission outcomes.

### Integration Points
- `MercuryApplication` is the shared service façade.
- `mercury.cli` parses/projects only; future WebUI must invoke the same facade.
- `render.py` owns human projections, while JSON uses canonical codec output.

</code_context>

<specifics>
## Specific Ideas

- Release support remains Windows and Ubuntu only; macOS reports unsupported.
- The existing Phase 2 status result remains honest unless direct Phase 4 LLDP
  evidence is available.

</specifics>

<deferred>
## Deferred Ideas

- IPv6 host enumeration, raw ARP/NDP emission, custom packet crafting, SNMP,
  centralized topology maps and exhaustive “all packets” are out of scope.

</deferred>
