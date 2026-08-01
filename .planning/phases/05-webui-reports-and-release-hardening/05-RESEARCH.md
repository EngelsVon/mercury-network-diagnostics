# Phase 5 Research: WebUI, Reports, and Release Hardening

## Chosen Architecture

Use `http.server.ThreadingHTTPServer` with a small request handler and a
single application-owned task registry. The handler performs bounded parsing,
host/origin/session/CSRF checks and then delegates to the existing facade.
Static files are packaged resources, not a frontend build artifact.

The browser polls task snapshots over a same-origin JSON API. This is simpler
than a WebSocket broker, keeps cancellation explicit and maps directly to the
already persisted canonical result model.

## Security Contract

| Boundary | Required behavior |
|---|---|
| Bind | `127.0.0.1`/`::1` by default; non-loopback requires supplied TLS cert/key and token. |
| Host/Origin | Exact permitted loopback host or configured host; mutations require exact same Origin. |
| Session | Random HttpOnly, SameSite=Strict cookie; never store peer token in UI state. |
| CSRF | Per-server random token exposed only in page bootstrap and required in `X-Mercury-CSRF`. |
| Request bodies | Fixed JSON only, content type checked, maximum bytes before decoding. |
| Headers/content | CSP without remote sources, `nosniff`, `frame-ancestors 'none'`, no inline event handlers. |
| HTTP APIs | Validate closed request shapes, then call facade; no URL-driven target/port/protocol escape. |

## Report Contract

- JSON reports use canonical result wire data followed by deterministic
  redaction; HTML reports are self-contained, escape all data, and link no
  external resource.
- Comparisons require compatible model schema and task types. They produce a
  cited delta view instead of pretending that missing evidence is a failure.
- Export always removes recognized credential material and raw payloads.

## Validation

- Standard-library HTTP client tests cover loopback routes, Host/Origin/CSRF
  rejection, body limits, token/TLS startup policy, polling and cancellation.
- History/report tests cover persistence round trips, compatible/incompatible
  comparison and default redaction.
- Build `uv build`, install into a temporary isolated environment, invoke
  `mercury --help`, and verify package static assets are present.
