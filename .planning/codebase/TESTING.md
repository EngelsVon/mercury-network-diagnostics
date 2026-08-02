# Testing Patterns

**Analysis Date:** 2026-08-02

## Test Framework

- Runner: Python standard-library `unittest`.
- Async runner: `unittest.IsolatedAsyncioTestCase` for asynchronous task, peer, and discovery behavior.
- Assertions: built-in `unittest.TestCase` methods, including `assertRaisesRegex`, `assertEqual`, and `subTest`.

## Run Commands

```powershell
python -m unittest discover -s tests -v
python -m compileall -q src tests
python -m build
```

- `README.md` also documents `ruff check src tests` where Ruff is available.
- Individual modules can be run with `python -m unittest tests.test_discovery -v`.

## Test File Organization

- Tests live in a separate top-level `tests/` tree.
- Domain tests mirror source modules: `src/mercury/policy.py` maps to `tests/test_policy.py`.
- Shared constructors live in `tests/helpers.py`.
- Reusable file fixtures live under `tests/fixtures/platform/` and `tests/fixtures/tls/`.

## Test Structure

- Test modules import production classes directly and build explicit value objects.
- A module-level fixed timezone-aware `NOW` is used where plan digests and expiry need deterministic time.
- Complex boundaries use fakes injected through constructor arguments, such as fake `psutil`, command runners, resolvers, application facades, and clocks.
- Table-driven boundary coverage uses `subTest` rather than dynamically generated test classes.

## Mocking and Network Control

- No third-party mocking library is used.
- Async command runners and resolvers are passed as callables, preserving deterministic error and capability behavior.
- Socket-level tests use loopback and test TLS certificates in `tests/fixtures/tls/`.
- The test policy explicitly prohibits public or unowned scan traffic; fake addresses are used for validation-only tests.

## Existing Test Categories

- `test_models.py` and `test_contracts.py`: model, codec, and compatibility invariants.
- `test_policy.py` and `test_probes.py`: target admission, plan budget, and protocol outcome semantics.
- `test_tasks.py`: cancellation, execution, persistence, and lifecycle behavior.
- `test_discovery.py`, `test_trace.py`, and `test_diagnosis.py`: service-level active/passive behavior.
- `test_peer.py` and `test_paired.py`: peer mTLS and paired diagnostics.
- `test_cli.py`, `test_web.py`, `test_history.py`, and `test_reports.py`: user-facing boundaries.

## Coverage Guidance for the New Direction

- Add rejection tests for public, multicast, unspecified, and DNS-escaped targets before implementing a scan runner.
- Use fake subprocess output to exercise any Nmap XML parser and argv construction; do not invoke the installed Nmap binary in normal tests.
- Add cancellation, rate, duration, and output-cap tests for scan tasks, including the allowed zero-duration request semantics.
- Exercise CLI and Web input parsing against the same service request object.

---

*Testing analysis: 2026-08-02*
*Update when test tools or safety controls change*
