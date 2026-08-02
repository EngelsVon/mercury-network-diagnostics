# Codebase Structure

**Analysis Date:** 2026-08-02

## Directory Layout

```text
Mercury-dev/
├── src/
│   └── mercury/             # application package and Web assets
│       ├── platform/        # Windows/Linux command adapters
│       └── web/             # standard-library HTTP server and static UI
├── tests/                   # unittest suites, helpers, and static fixtures
│   └── fixtures/            # TLS and platform-output fixtures
├── .github/workflows/       # existing release smoke workflow
├── pyproject.toml           # packaging, metadata, runtime dependency
├── README.md                # operator documentation
└── AGENTS.md                # repository execution and safety rules
```

## Directory Purposes

**`src/mercury/`:**

- Purpose: product implementation.
- Contains: one Python module per domain rather than nested framework packages.
- Key files: `app.py`, `cli.py`, `planner.py`, `tasks.py`, `policy.py`, and `models.py`.
- Subdirectories: `platform/` holds OS-specific adapters; `web/` holds server and browser assets.

**`tests/`:**

- Purpose: unit and controlled integration coverage.
- Contains: `test_<domain>.py` modules and `helpers.py`.
- Key files: `test_policy.py`, `test_discovery.py`, `test_tasks.py`, `test_peer.py`, and `test_web.py`.
- Subdirectories: `fixtures/tls/` has test certificates; `fixtures/platform/` has captured command output.

**`.planning/`:**

- Purpose: project planning and codebase-map documents recreated after the prior plan was intentionally removed.
- Contains: product context, requirements, roadmap, state, and codebase mapping.
- Generated output: no source code is generated from it.

## Key File Locations

**Entry points:**

- `src/mercury/__main__.py`: supports `python -m mercury`.
- `src/mercury/cli.py`: registered console command and argument definitions.
- `src/mercury/app.py`: shared application service facade.

**Configuration:**

- `pyproject.toml`: build backend, package metadata, Python requirement, dependency list, console script.
- `.gitignore`: excludes environments, builds, caches, and SQLite task history.

**Core logic:**

- `src/mercury/policy.py`: target parsing, containment, and resolver rechecks.
- `src/mercury/planner.py`: limits, step compilation, and canonical plans.
- `src/mercury/tasks.py`: task lifecycle and per-step admission.
- `src/mercury/probes.py`: socket-level protocol evidence.
- `src/mercury/discovery.py`: passive context and TCP discovery service.

**Documentation:**

- `README.md`: operator usage and product boundaries.
- `AGENTS.md`: mandatory implementation rules.

## Naming Conventions

- Source modules use lowercase snake_case names: `history.py`, `paired.py`, `test_history.py`.
- Tests use `test_<domain>.py` and classes ending in `Tests`.
- Static assets use simple lower-case names under `src/mercury/web/static/`.
- Package exports are kept explicit with `__all__` lists in many modules.

## Where to Add New Code

**Internal scan feature:**

- Request/service: a focused module beside `src/mercury/discovery.py` or a clearly named new module in `src/mercury/`.
- Shared facade: `src/mercury/app.py`.
- CLI: `src/mercury/cli.py`.
- Web broker/UI: `src/mercury/web/__init__.py` and static assets only after the facade is implemented.
- Tests: new `tests/test_<feature>.py` plus targeted changes to `tests/test_cli.py` and `tests/test_web.py`.

**Native adapter:**

- Implementation: a narrowly scoped module under `src/mercury/`.
- Native-command fixture/parser tests: `tests/fixtures/` and the corresponding `tests/test_<feature>.py`.

## Special Directories

- `build/` and `dist/` are packaging outputs ignored by Git.
- `.venv/` is a local virtual environment ignored by Git.
- `.tmp-phase3-smoke/` is a local smoke-test artifact and should not be treated as product source.

---

*Structure analysis: 2026-08-02*
*Update when the layout changes*
