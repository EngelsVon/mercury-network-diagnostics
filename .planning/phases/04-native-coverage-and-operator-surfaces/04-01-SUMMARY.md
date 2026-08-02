# Phase 4 Summary: Native Profiles and Operator Surfaces

Completed 2026-08-02.

- Fixed Nmap TCP-connect/SYN, UDP, and SCTP-init argv are derived exclusively
  from an admitted private plan; bounded XML is parsed and removed from an
  owned temporary directory.
- Native results persist `native_port_state` evidence with Nmap provenance,
  never as fabricated direct Mercury packet evidence.
- CLI and Web route typed mapping and configured paired coverage requests only
  through `MercuryApplication`; neither surface has raw Nmap arguments.
- Existing peer mTLS/token/pin/replay and history redaction tests remain green.

Focused verification: Nmap adapter, CLI, Web, planner, policy, models, tasks,
peer, paired, history, and reports tests use loopback/fakes only.
