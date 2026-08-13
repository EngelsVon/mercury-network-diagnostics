<!-- generated-by: gsd-doc-writer -->
# Development

[简体中文](zh-CN/DEVELOPMENT.md)

Mercury is a CPython 3.11+ project with a `src/` layout. Windows and Ubuntu are the v1 release targets; development is performed on the available Python 3.13 interpreter. The runtime dependency is `psutil`; the CLI, agent, and Web UI all use the same Python service layer, and the Web UI uses semantic HTML, CSS, and native JavaScript without a frontend build system.

## Local setup

Install [uv](https://docs.astral.sh/uv/) and Python 3.11 or newer, then work from a fork or checkout:

```powershell
git clone <your-fork-url>
cd Mercury-dev
uv sync
uv run --no-sync python -m mercury --help
```

No environment file or configuration-generation step is required for ordinary development and tests. Nmap is optional and is exercised through fakes unless an operator explicitly selects a fixed native profile on an authorized private network.

## Commands

`pyproject.toml` defines the `mercury` console entry point but no project task aliases. Run these repository commands directly:

| Command | Description |
| --- | --- |
| `uv run --no-sync python -m mercury --help` | Verify the source checkout and CLI entry point. |
| `uv run --no-sync python -m unittest discover -s tests -v` | Run the complete controlled test suite. |
| `uv run --no-sync python -m compileall -q src tests` | Compile all source and test modules. |
| `uv run --no-sync ruff check src tests` | Run the documented Ruff source check. Ruff is a developer tool, not a locked project dependency. |
| `uv build` | Build source and wheel distributions. |
| `uv run --no-sync python -m mercury status --json` | Exercise the passive status path without active probing. |

## Code style

- Follow the existing typed, standard-library-first Python style and keep changes compatible with Python 3.11+.
- Run `uv run --no-sync ruff check src tests`. The repository currently has no dedicated Ruff configuration file, so its standard rules apply.
- Preserve the evidence vocabulary: refusal, timeout, UDP response, ICMP unreachable, silence, unsupported capability, permission denial, and execution error are not interchangeable.
- Keep network and trust-boundary validation, immutable work ceilings, cancellation, secret filtering, and accessibility intact. Add no framework or abstraction unless a smaller standard-library or existing-dependency solution is insufficient.
- Presentation code must call `MercuryApplication`; it must not open probe sockets or native scanner subprocesses itself.

## Branch and commit conventions

The current default development branch in this checkout is `master`. No branch-naming rule is documented; choose a short descriptive name such as `fix/timeout-evidence` or `docs/testing-guide`.

Recent history uses short imperative Conventional Commit-style subjects, including `feat:`, `fix:`, and `docs:` with optional scopes. Follow that pattern and keep commits small and independently verifiable.

## Pull request process

- Open a focused pull request against `master` and explain the operator-visible behavior and safety impact.
- Link the relevant issue when one exists; never put undisclosed vulnerability details in a public issue or pull request.
- Add or update controlled tests for every behavior change. Tests must use fakes, fixtures, or loopback and must never scan a public or unowned non-loopback target.
- Run the full suite, compilation, Ruff, and build commands above; report any platform-specific skip or failure accurately.
- Keep documentation, CLI help, Web copy, and the shared evidence model consistent when changing user-visible behavior.
- Complete the repository pull request template, including its verification, safety, compatibility, secret-handling, and bilingual-documentation checks.
- Expect reviewers to check private-scope admission, authorization, hard budgets, evidence semantics, secret handling, peer/Web trust controls, and Windows/Ubuntu compatibility.

The GitHub CI workflow runs the complete suite and compilation on Windows and Ubuntu with Python 3.11 and 3.13, builds distributions on Ubuntu/Python 3.13, and also runs an installed-wheel passive-status smoke job on both platforms.
