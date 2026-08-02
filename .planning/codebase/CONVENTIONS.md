# Coding Conventions

**Analysis Date:** 2026-08-02

## Naming Patterns

- Modules, functions, variables, and keyword arguments use `snake_case`.
- Classes, dataclasses, and enums use `PascalCase`.
- Constants use `UPPER_SNAKE_CASE`, for example `ABSOLUTE_CEILINGS`.
- Test classes end in `Tests`; test methods begin with `test_`.
- Private helpers use a leading underscore and live near the public functions they support.

## Code Style

- Source is type-annotated Python with `from __future__ import annotations`.
- Domain values commonly use `@dataclass(frozen=True, slots=True)` to prevent accidental mutation.
- Public data is normalized and validated in `__post_init__` rather than trusted from the caller.
- String enums represent stable wire values; `models.py` is the source of truth for evidence semantics.
- Standard-library facilities are preferred, consistent with `AGENTS.md` and the one-runtime-dependency limit.

## Validation and Error Handling

- Boundary failures use domain-specific `ValueError` subclasses such as `PolicyError`, `BudgetError`, `HistoryError`, and `WebError`.
- Inputs fail closed and error messages describe the rejected invariant without exposing a secret.
- Active paths validate more than once: request construction, plan compilation, plan validation, and task admission.
- Native command absence or permission denial is converted to typed evidence rather than hidden or treated as successful output.

## Architecture Conventions

- Presentation modules call `MercuryApplication`; they must not perform a probe directly.
- Active runners receive only a task context and request a predeclared step by ID.
- New evidence kinds require matching updates to `models.py`, `tasks.py`, codec conversion, renderers, and tests.
- Conclusions cite concrete observation IDs and must distinguish observed fact from inference.

## Persistence and Sensitive Data

- `history.py` validates content before persistence and strips sensitive error material.
- Reports redact identifiers and payloads by default; credentials, tokens, and private keys remain excluded even when sensitive retention is requested.
- Tests use fixtures and fakes rather than source-controlled production credentials.

## Web Conventions

- The dashboard uses semantic HTML and accessible labels in `index.html`.
- Browser JavaScript uses `fetch` to call the local service; no inline event handlers or network probes are permitted.
- The HTTP server checks host, session, same-origin mutation, and CSRF boundaries.

## Verification Conventions

- Add focused `unittest` coverage at the domain boundary plus CLI and Web routing coverage when an operator-visible feature changes.
- Controlled test addresses are loopback or synthetic; no test may scan a public or unowned address.
- Run the full unittest suite and packaging check before marking a requirement complete.

---

*Convention analysis: 2026-08-02*
*Update when established implementation patterns change*
