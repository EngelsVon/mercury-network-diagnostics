---
phase: 2
plan: 01
status: complete
completed: 2026-08-02
requirements:
  - COVER-02
  - COVER-03
  - COVER-04
  - COVER-05
  - COVER-06
  - COVER-07
  - COVER-08
---

# Phase 2 Summary: Peer Receivers and Coverage Matrix

Implemented the non-native closed `coverage-v2` paired assessment.  Configured peers now
provision only fixed, short-lived TCP, UDP, DNS/UDP, DNS/TCP, TLS, HTTP and SSH
receivers; each direction retains distinct sender and correlation-bound
receiver evidence.  ICMP uses a fixed native echo invocation and reports an
observer-capability gap rather than fabricating a peer receipt.

The final bidirectional assessment is persisted as one immutable coverage task
with the selected profiles, both directions, scope, limits and joined evidence.
Its HTML matrix shows profile, port, direction, outcome, timing, provenance and
evidence IDs.  Correlation tags, tokens and key paths are not persisted.

ARP and IPv6 ND do not emit packets.  Cross-subnet pairs are `not_applicable`;
for same-link pairs Mercury can project a matching passive local neighbor-cache
entry as local-only evidence and leaves the unobserved reverse direction as a
coverage gap.

## Verification

- `PYTHONPATH=src python -m unittest tests.test_models tests.test_paired tests.test_peer tests.test_platforms tests.test_reports -v` — 92 passed.
- `PYTHONPATH=src python -m compileall -q src tests` — passed.
- `PYTHONPATH=src python -m unittest tests.test_cli -v` — 21 passed.
- The installation-suite wheel/venv test exceeds the desktop command's 60-second execution window; it is deferred to Phase 5 release verification.

## Commits

- `959a280`, `1b11125`, `06dab66`, `8d79112`, `6415297` — receiver, TLS, ICMP and coverage foundations.
- `ab22c01` — persisted immutable assessment aggregate and safe request history fields.
- `4149043` — passive local-link ARP/ND evidence and directional gap preservation.
