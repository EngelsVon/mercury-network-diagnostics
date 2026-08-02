# Technology Stack

**Analysis Date:** 2026-08-02

## Languages and Runtime

- Python is the only implementation language. The project requires CPython 3.11 or newer and is developed here with CPython 3.13.5.
- The package is installed from `src/` with setuptools, configured in `pyproject.toml`.
- The public console entry point is `mercury = "mercury.cli:main"`.
- The supported operating systems are Windows and Ubuntu. Other platforms return explicit capability evidence rather than an implicit fallback.

## Runtime Dependencies

- `psutil>=7.0,<8` is the sole declared runtime dependency and supplies interface/process-adjacent local inventory.
- The rest of the implementation uses the standard library: `argparse`, `asyncio`, `socket`, `ssl`, `ipaddress`, `sqlite3`, `http.server`, `subprocess`, `dataclasses`, and `json`.
- `uv.lock` is present for reproducible local development; no Node runtime, frontend framework, ORM, or broker is used.

## Application Technologies

- The core evidence schema uses frozen slot dataclasses and `StrEnum` values in `src/mercury/models.py`.
- Active work is compiled into immutable plan steps in `src/mercury/planner.py` and executed through `src/mercury/tasks.py`.
- Local history is SQLite via `src/mercury/history.py`; exports and persistence apply secret filtering.
- The Web UI is server-rendered semantic HTML, CSS, and native JavaScript under `src/mercury/web/static/`.

## Native Platform Capabilities

- Windows adapters use PowerShell and `netsh.exe`; Linux adapters use `ip`, `resolvectl`, and optional `lldpctl`.
- Native ping and trace tools are invoked through bounded adapters and return typed missing-tool or permission evidence.
- `D:\\Nmap\\nmap.exe` is installed on this development host, but the product has no Nmap integration today and Nmap is not a Python dependency.

## Build and Verification

- The normal test runner is `python -m unittest discover -s tests -v`.
- Packaging is exercised with `python -m build`; `ruff check src tests` is documented as an optional style check.
- No CI dependency manifest or test-runner configuration file is present beyond `pyproject.toml`.

## Constraints for Future Work

- Prefer the existing standard-library engine over a new framework or package.
- If Nmap support is added, detect the local executable and treat it as an optional native capability; do not make it a required dependency.
- Preserve the versioned evidence schema and the shared application boundary used by both CLI and Web UI.

---

*Stack analysis: 2026-08-02*
*Update when dependencies or supported platforms change*
