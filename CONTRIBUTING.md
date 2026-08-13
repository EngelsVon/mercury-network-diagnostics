<!-- generated-by: gsd-doc-writer -->
# Contributing to Mercury

[简体中文](CONTRIBUTING.zh-CN.md)

Thank you for helping improve Mercury. Contributions should preserve its core promise: within an explicitly authorized private-network scope, report safe, reproducible reachability evidence without presenting inference or silence as fact.

## Development setup

See [Getting Started](README.md#installation) for prerequisites and first-run instructions, [Development](docs/DEVELOPMENT.md) for local setup and project commands, and [Testing](docs/TESTING.md) for controlled test guidance.

## Coding standards

- Support CPython 3.11+ and the Windows and Ubuntu release targets.
- Prefer the standard library and the existing `psutil` dependency. Mercury intentionally has no frontend framework or additional runtime framework.
- Run `uv run --no-sync ruff check src tests`, `uv run --no-sync python -m compileall -q src tests`, and the full `unittest` suite.
- Keep evidence semantics, authorization, private-scope checks, immutable budgets, secret filtering, peer/Web trust controls, and accessibility explicit and tested.

## Pull request guidelines

- Branch from `master`. No fixed branch-name scheme is enforced; use a short descriptive name.
- Use a short imperative Conventional Commit-style subject such as `feat: add ...`, `fix: preserve ...`, or `docs: clarify ...`.
- Keep each pull request focused and explain the behavior, evidence, security, and compatibility impact.
- Add or update tests. They must use fakes, fixtures, or loopback only and must not contact public or unowned non-loopback targets.
- Complete the pull request template and run the checks in [Testing](docs/TESTING.md). CI covers the full suite and compilation across Python 3.11/3.13 on Windows/Ubuntu, distribution building, and installed-package passive smoke; run Ruff locally.
- Update user documentation, CLI help, and Web copy when their shared behavior changes. Do not introduce a presentation-only probing path.

## Reporting issues

Before filing an issue, search [existing issues](https://github.com/EngelsVon/mercury-network-diagnostics/issues) and use the repository's bug or feature template. For a bug, include:

- a minimal reproduction using only an owned or explicitly authorized private network;
- expected behavior and actual typed evidence;
- Mercury version, Python version, operating system, command, and sanitized output;
- whether the result is reproducible and whether an optional native tool was available.

Remove addresses, hostnames, tokens, certificates, private keys, payloads, and other sensitive network details. Feature requests should explain the operator problem, the bounded authorized scope, and why existing behavior is insufficient.

Do not report security vulnerabilities in a public issue. Follow [SECURITY.md](SECURITY.md) instead.

## Conduct

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
