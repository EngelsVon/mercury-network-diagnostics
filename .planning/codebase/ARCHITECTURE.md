# Architecture

**Analysis Date:** 2026-08-02

## Pattern Overview

**Overall:** a layered, local-first Python CLI and Web application with one immutable evidence model and one task-execution boundary.

**Key Characteristics:**

- `src/mercury/cli.py` parses commands and projects results; it does not perform probe I/O directly.
- `src/mercury/app.py` exposes `MercuryApplication` as the shared facade for CLI and Web UI.
- `src/mercury/planner.py` turns a typed scope and request into a digest-bearing immutable plan before `src/mercury/tasks.py` admits individual steps.
- Observations, conclusions, capability states, and result wires are all versioned in `src/mercury/models.py` and `src/mercury/codec.py`.

## Layers

**Presentation layer:**

- Purpose: parse CLI arguments, serve the dashboard, render human and JSON output.
- Contains: `cli.py`, `render.py`, `web/__init__.py`, and `web/static/`.
- Depends on: `MercuryApplication` and presentation-safe history/report methods.
- Used by: operators running the executable or loopback dashboard.

**Application layer:**

- Purpose: expose status, diagnosis, discovery, trace, paired operation, history, and agent lifecycle through one facade.
- Contains: `app.py`.
- Depends on: request compilers, runners, `TaskService`, and `HistoryStore`.
- Used by: CLI dispatch and Web task broker.

**Policy and planning layer:**

- Purpose: canonicalize targets, bind their declared scope, cost work, and issue immutable plans.
- Contains: `policy.py`, `planner.py`, `profiles.py`, `discovery.py`, and `trace.py`.
- Depends on: `ipaddress`, resolver snapshots, and the evidence model.
- Used by: every active service before it can enqueue I/O.

**Execution and evidence layer:**

- Purpose: enforce lifecycle admission and collect typed socket/native observations.
- Contains: `tasks.py`, `probes.py`, `resolver.py`, `diagnosis.py`, and `paired.py`.
- Depends on: immutable plans and platform adapters.
- Used by: application service requests.

**Persistence and reporting layer:**

- Purpose: retain local task records, redact exports, and compare compatible runs.
- Contains: `history.py`, `reports.py`, and `codec.py`.
- Depends on: the frozen model types and SQLite.
- Used by: task lifecycle, CLI history, and the dashboard.

## Data Flow

**Active CLI discovery flow:**

1. The operator supplies CLI arguments to `mercury discover`.
2. `cli.py` creates `DiscoveryRequest` and calls `MercuryApplication.discover`.
3. `discovery.py` creates a `ScopeGrant`, compiles a `PlanPreview`, and authorizes it.
4. `TaskService` validates the plan, admits frozen steps, rechecks names where needed, and calls the protocol dispatcher.
5. `probes.py` records TCP/UDP evidence into the task context.
6. `TaskResult` is persisted locally and rendered through the selected presentation boundary.

**State management:**

- A task's network permissions and work estimate are immutable once planned.
- Task state is persisted locally in SQLite; running work remains in-process and is cancelable.
- Web requests are transient and dispatch only through the same facade.

## Key Abstractions

**ScopeGrant and Target:**

- Purpose: describe a typed target envelope and permitted finite operations.
- Examples: `src/mercury/policy.py`.
- Pattern: immutable validation objects with canonical wire form.

**PlanPreview and ProbePlan:**

- Purpose: bind exact steps, costs, resolution snapshot, and confirmations to a digest.
- Examples: `src/mercury/planner.py`.
- Pattern: immutable compile-then-authorize value objects.

**TaskContext and TaskService:**

- Purpose: manage cancellation, admission, progress, and result assembly.
- Examples: `src/mercury/tasks.py`.
- Pattern: service-owned capability boundary around runner callbacks.

**TaskResult evidence graph:**

- Purpose: retain observations and conclusions without conflating silence, refusal, error, or unavailable capability.
- Examples: `src/mercury/models.py` and `src/mercury/codec.py`.
- Pattern: frozen versioned dataclasses with references from conclusions to observation IDs.

## Entry Points

- `src/mercury/__main__.py`: module execution entry point.
- `src/mercury/cli.py`: console-script parser and stable exit-code boundary.
- `src/mercury/web/__init__.py`: local HTTP server and task broker.
- `src/mercury/app.py`: central application facade for presentation callers.

## Error Handling and Cross-Cutting Concerns

- Input, policy, planner, history, and report errors are caught in `cli.main()` and mapped to stable exits.
- Capability absence and permission failure are evidence, not successful empty results.
- Trust-boundary validation is intentionally duplicated at request, plan, and admission points.
- History redacts secrets and generated reports redact identifiers by default.

---

*Architecture analysis: 2026-08-02*
*Update when service boundaries or plan lifecycle change*
