# Mercury repository instructions

## Product

Mercury is a local-first, cross-platform network diagnostics tool. The CLI,
agent and WebUI share one Python engine and one versioned evidence model.

Core value: within an explicitly authorized scope, explain where and why
node-to-node reachability fails with safe, reproducible evidence.

## Required workflow

- Read `.planning/PROJECT.md`, `.planning/REQUIREMENTS.md`,
  `.planning/ROADMAP.md` and `.planning/STATE.md` before planned work.
- Execute roadmap phases in order. Keep requirements, roadmap and state in sync.
- Use small atomic commits when the worktree is safe; never revert unrelated
  edits made by the user or another agent.
- Verification is part of each plan. A requirement is complete only after its
  behavior and tests pass.

## Ponytail full mode

Apply DietrichGebert/ponytail v4.8.4, inspected at commit
`16f29800fd2681bdf24f3eb4ccffe38be3baec6b`.

Stop at the first sufficient rung:

1. Does the feature need to exist?
2. Is it already in this repository?
3. Can the standard library do it?
4. Can a native platform capability do it?
5. Can an installed dependency do it?
6. Can the correct implementation be smaller?
7. Only then write the minimum custom code that works.

Do not add speculative abstractions, factories with one implementation,
frameworks, frontend build systems, ORMs, brokers, plugin SDKs or custom crypto.
Never simplify away trust-boundary validation, authorization, hard scan budgets,
error/data-loss handling, accessibility, or runnable checks. Use a `ponytail:`
comment only for a deliberate simplification with a named ceiling and upgrade
trigger.

## Stack

- CPython 3.11+; develop/test on the available 3.13 interpreter. v1 support
  targets Windows and Ubuntu; other platforms may report unsupported capability
  evidence but are not release targets.
- One runtime dependency: `psutil`.
- Prefer `argparse`, `asyncio`, `socket`, `ssl`, `http.server`, `sqlite3`,
  `ipaddress`, `subprocess`, `dataclasses`, `json` and `importlib.resources`.
- Semantic HTML/CSS/native JavaScript; no Node or frontend framework.
- `unittest` plus controlled network tests; no public/unowned scan in tests.

## Network and security semantics

- Silence is not success or failure. Keep TCP refusal, timeout, UDP response,
  ICMP unreachable, silent, unsupported, permission denied and error distinct.
- Every conclusion carries evidence, direction, timing, provenance and
  confidence. Do not present inference as fact.
- Never label a gateway, route hop or ARP neighbor as a switch. Identify
  infrastructure only from direct evidence such as LLDP; otherwise report that
  it is not observable.
- All active work passes through canonical scope policy and immutable aggregate
  host/port/attempt, logical packet/application-byte, attempt-start rate,
  concurrency, duration, event and output ceilings. Do not claim to count
  kernel retransmissions or exact on-wire bytes.
- Non-loopback Web listeners require TLS and a token. Peer agents additionally
  require a trusted client certificate (mTLS); only an explicit, audited
  unsafe-development override may relax these defaults.
- Peer control must not accept arbitrary third-party scan destinations.
- “All packet kinds” is impossible and out of scope. Advanced mode is a bounded
  finite port/payload profile with explicit authorization and confirmation.
- WebUI and CLI must call the same service functions; presentation code performs
  no network probes directly.

## Useful commands

```powershell
python -m unittest discover -s tests -v
python -m mercury --help
python -m build
```

Update this file only when established repository patterns change.
