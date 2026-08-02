---
phase: 1
plan: 01
subsystem: private-scope-policy
tags: [policy, private-network, verification]
key-files:
  - src/mercury/policy.py
  - src/mercury/profiles.py
  - src/mercury/peer.py
  - tests/test_policy.py
  - tests/test_diagnosis.py
  - tests/test_probes.py
metrics:
  tests: 247
  skipped: 3
---

## Summary

Completed the private-only admission migration. Active literals, CIDRs, resolved
addresses, active-service inputs, peer endpoints, CLI/Web entry points, and built-in
profiles now share the explicit internal-address policy. Public and documentation
addresses fail before probe runners, socket activity, or native commands.

## Commits

| Commit | Description |
|---|---|
| `990635d` | Enforce private active targets in canonical policy. |
| `fc4a767` | Restrict active service entry points and peer configuration. |
| `a8a1f03` | Document private-only active work. |
| `6a779f6` | Keep successful diagnosis/resolver test fixtures private. |

## Verification

- `PYTHONPATH=src python -m unittest discover -s tests -v` — passed: 247 tests, 3 Windows permission-model skips.
- `PYTHONPATH=src python -m compileall -q src tests` — passed.
- `python -m build` — passed; built sdist and wheel.

## Deviations

Updated two unrelated success fixtures exposed by the intended policy change: a
public diagnosis scope became loopback-only, and public IPv6 resolver rows became
IPv6 ULA rows. Dedicated public-address rejection tests remain unchanged.

## Self-Check: PASSED

SCOPE-01, SCOPE-02, and SCOPE-03 are complete. Phase 2 remains pending.
