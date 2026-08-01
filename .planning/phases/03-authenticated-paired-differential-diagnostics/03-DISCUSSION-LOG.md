# Phase 3: Authenticated Paired Differential Diagnostics - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md.

**Date:** 2026-08-01
**Phase:** 03-authenticated-paired-differential-diagnostics
**Areas discussed:** Pair trust boundary, peer data plane, directional result, verification

---

## Pair trust boundary

| Option | Description | Selected |
|---|---|---|
| Operator-provisioned mTLS + pin + token | Fixed peer configuration with independent certificate identity and authorization secret. | Yes |
| Token-only control | Does not meet the peer trust boundary. | |

**Choice:** Autonomous project-continuation default: operator-provisioned mTLS, pins, and a separate token.

## Peer data plane

| Option | Description | Selected |
|---|---|---|
| Fixed paired TCP/UDP profile | Finite listeners and nonce-tagged UDP evidence, restricted to configured peers. | Yes |
| Arbitrary remote target/payload | Would create a scan oracle and is outside scope. | |

**Choice:** Autonomous default: finite pair-only data plane.

## Directional result

| Option | Description | Selected |
|---|---|---|
| A→B/B→A evidence matrix | Source-linked layers reveal differences without unsupported causes. | Yes |
| Flattened probe list | Loses the product-defining directionality. | |

**Choice:** Autonomous default: a canonical directional matrix.

## Verification

| Option | Description | Selected |
|---|---|---|
| Loopback security suite, then opt-in Ubuntu smoke | Deterministic coverage before a user-authorized two-machine confirmation. | Yes |
| Remote-only validation | Is not reproducible and would leave security regressions uncovered. | |

**Choice:** Autonomous default: controlled tests followed by a sanitized Ubuntu smoke.

## the agent's Discretion

- Concrete protocol framing, bounded size/TTL values, module layout and wording remain constrained implementation choices.

## Deferred Ideas

- Pairing short-code enrollment, central control, arbitrary payloads and fleet features remain out of scope.
