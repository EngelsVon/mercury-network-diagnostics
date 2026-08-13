<!-- generated-by: gsd-doc-writer -->
# Testing

[简体中文](zh-CN/TESTING.md)

## Framework and setup

Mercury uses Python's standard-library `unittest` framework, including `IsolatedAsyncioTestCase` for asynchronous behavior and `unittest.mock` for controlled boundaries. Tests require Python 3.11+ and the project's `psutil` runtime dependency.

From the repository root:

```powershell
uv sync
```

The suite requires no public service or test account. TLS material under `tests/fixtures/tls/` is test-only and must never be used for production listeners, client credentials, or trust stores.

## Running tests

Run the full suite:

```powershell
uv run --no-sync python -m unittest discover -s tests -v
```

Run one module, class, or method with a dotted name:

```powershell
uv run --no-sync python -m unittest tests.test_policy -v
uv run --no-sync python -m unittest tests.test_policy.TargetPolicyTests -v
uv run --no-sync python -m unittest tests.test_policy.TargetPolicyTests.test_only_explicit_internal_address_spaces_are_admitted -v
```

Run the release checks used by the project documentation:

```powershell
uv run --no-sync python -m compileall -q src tests
uv run --no-sync ruff check src tests
uv build
```

No watch-mode test command is configured.

## Writing tests

- Put tests in `tests/test_<area>.py`, using `unittest.TestCase` or `unittest.IsolatedAsyncioTestCase` and methods named `test_<behavior>`.
- Reuse `tests/helpers.py` for representative versioned observations and results. Keep platform data under `tests/fixtures/platform/` and loopback-only TLS material under `tests/fixtures/tls/`.
- Use fakes, mocks, temporary directories, and loopback (`127.0.0.0/8` or `::1`) for controlled I/O. Never resolve or connect to a real public, supplied peer, or other unowned non-loopback target.
- Assert typed outcomes and provenance. Silence and timeout remain inconclusive; refusal, reset, reply, ICMP unreachable, unsupported, permission-denied, and error states remain distinct.
- For a new active path, prove that authorization, private-scope policy, DNS rechecks, immutable budgets, and cancellation are enforced before or during I/O as applicable.
- Keep cross-platform expectations explicit. POSIX permission-bit tests are skipped on Windows because Windows ACLs have different semantics.

Useful focused areas include `test_policy.py` for admission and budgets, `test_tasks.py` for lifecycle and persistence, `test_paired.py` and `test_peer.py` for correlated peer trust, `test_nmap_adapter.py` for fixed native command boundaries, and `test_web.py`/`test_cli.py` for shared-service routing.

## Coverage requirements

No line, branch, function, or statement coverage threshold is configured. Behavioral requirement coverage is enforced through focused regression tests, but the repository does not currently publish a numeric coverage target or coverage command.

## CI integration

`.github/workflows/ci.yml` defines `CI`. It runs on pushes, pull requests, and manual dispatch.

The `tests` job uses Python 3.11 and 3.13 on `windows-latest` and `ubuntu-latest`. It installs the project and `build`, runs the full suite and compilation, and builds distributions on Ubuntu with Python 3.13.

The `installed-passive-status` job:

1. Builds a wheel with `python -m pip wheel . --no-deps`.
2. Creates a clean virtual environment and installs `psutil` plus the wheel.
3. Runs `python -m mercury status --json`.
4. Verifies completed passive evidence and the explicit `no_direct_lldp_or_managed_evidence` access-switch limitation.
5. Uploads a sanitized status artifact.

CI does not run Ruff, so contributors should still run the documented Ruff check locally before opening a pull request.
