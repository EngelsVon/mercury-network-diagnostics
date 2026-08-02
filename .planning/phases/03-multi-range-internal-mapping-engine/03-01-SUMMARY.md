# Phase 3 Summary: Multi-Range Internal Mapping

Completed 2026-08-02.

- `InternalMappingRequest` canonicalizes overlapping private IPv4 CIDRs and
  compiles one immutable cross-product plan.
- Mapping records selected profiles, ports, rate, concurrency, duration-zero
  semantics, payload metadata, outbound direction, and effective ceilings.
- UDP mapping uses one fixed byte only; no caller payload is accepted.
- `MercuryApplication.map_internal()` uses the normal TaskService/history path.

Focused verification: planner, discovery, tasks, models, policy, and probes
tests pass using loopback/fakes only.
