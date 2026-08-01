# Phase 5: WebUI, Reports, and Release Hardening - Context

**Gathered:** 2026-08-02
**Status:** Ready for planning

## Phase Boundary

Ship the existing shared Mercury engine through an accessible local WebUI,
safe history/report views, documentation, packaging checks and controlled
Windows/Ubuntu release verification. No Web framework, Node build, ORM,
remote control plane, scanner profile, or second probe implementation is in
scope.

## Decisions

- The stdlib `http.server` implementation must only adapt HTTP requests to
  `MercuryApplication` and `HistoryStore`; it may never probe a network itself.
- Loopback is the default bind. A non-loopback bind needs TLS plus a token;
  peer control still requires mTLS and must not be exposed through the WebUI.
- Every mutating Web request requires same-origin validation, a SameSite
  session cookie and a CSRF request header. Responses use CSP and strict body
  limits.
- The UI is semantic HTML/CSS/vanilla JavaScript, keyboard usable, with
  visible task state/progress, outcome distinctions and cited evidence.
- Reports default to redacting tokens, credentials, hostnames, MAC addresses,
  public IPs and raw payloads. Retaining sensitive fields requires an explicit
  export switch and must still reject secret values.
- Release verification stays controlled: loopback, fixtures or the already
  authorized Windows/Ubuntu peer only. No public/unowned scan is allowed.

## Reusable Assets

- `MercuryApplication`, `TaskService` and all existing service requests are
  the sole execution boundary.
- `HistoryStore` retains canonical task results and contains persistence-safe
  request projection.
- `codec.result_to_wire`, `render.py`, static package data and the `uv` lock
  give the UI/report/packaging implementation its existing primitives.

## Deferred

- Browser-based peer-agent administration, remote SaaS, WebSockets, user
  accounts, centralized fleet history, a charting dependency, PDF rendering,
  standalone signed binaries and arbitrary report templating remain out of
  scope.
