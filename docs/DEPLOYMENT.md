<!-- generated-by: gsd-doc-writer -->
# Deployment

Mercury is deployed as a local Python CLI/WebUI and, for paired assessments, as an administrator-operated process on two Windows or Ubuntu endpoints. The repository contains no Docker, Compose, Vercel, Netlify, Fly.io, Railway, Serverless, or automated production deployment configuration.

## Deployment targets

| Target | Supported role | Installation |
| --- | --- | --- |
| Windows with CPython 3.11+ | CLI, WebUI, peer agent | Wheel/virtual environment or `uv tool install .` |
| Ubuntu with CPython 3.11+ | CLI, WebUI, peer agent | Wheel/virtual environment or `uv tool install .` |
| Other platforms | Not a v1 release target | Platform-specific capabilities report unsupported evidence where implemented. |

Mercury is local-first. It is not a centralized remote scanning service, and the peer agent exposes only closed configured operations.

## Build pipeline

Build a wheel from a controlled checkout:

```bash
python -m unittest discover -s tests -v
python -m compileall -q src tests
python -m build
```

Install the resulting wheel in the target environment:

```bash
python -m venv .venv
# Ubuntu: source .venv/bin/activate
# PowerShell: .venv\Scripts\Activate.ps1
python -m pip install psutil
python -m pip install --no-index --no-deps <MERCURY-WHEEL.whl>
python -m mercury --help
python -m mercury status --json
```

The repository CI workflow `.github/workflows/phase2-passive-status.yml` runs on pushes, pull requests, and manual dispatch. It builds and installs a wheel on Windows and Ubuntu with Python 3.13, then records sanitized passive status evidence. It does not publish or deploy Mercury. No CI/CD deployment pipeline is present.

## Windows rollout

1. Install CPython 3.11+ and create a dedicated virtual environment or `uv` tool installation.
2. Install the reviewed wheel and `psutil`.
3. Run `python -m mercury status --json` as the intended service user.
4. If native profiles are required, install Nmap through the administrator-approved Windows package source and confirm `nmap --version` works for that user.
5. Store history, tokens, private keys, peer JSON, and certificates in administrator-controlled local directories. Use OS ACLs so only the Mercury account and administrators can read secrets.
6. Start WebUI or peer-agent commands with an OS service wrapper approved for the environment. This repository does not ship a Windows service definition.

## Ubuntu rollout

1. Install CPython 3.11+ and create a dedicated virtual environment or `uv` tool installation.
2. Install the reviewed wheel and `psutil`.
3. Run `python -m mercury status --json` as the intended service user.
4. If native profiles are required, install the distribution Nmap package and confirm `nmap --version`. Grant only the OS capabilities needed for the selected profile; do not run all Mercury operations as root by default.
5. Keep token, key, certificate, configuration, and history paths readable only by the Mercury account. Set `XDG_DATA_HOME` or use `--data-path` if the service account needs a non-default history location.
6. Use an administrator-reviewed service unit if automatic startup is required. This repository does not ship a `systemd` unit.

## Production environment setup

See [Configuration](CONFIGURATION.md) for the full peer schema and defaults. For each two-endpoint deployment:

1. Allocate one fixed peer-control port and unique fixed receiver ports.
2. Decide which addresses are control-plane and which are the data path under test.
3. Issue endpoint certificates from an administrator-controlled CA with the correct names/usages.
4. Provision reciprocal trust: client CA, server/client certificate and key, exact peer certificate pin, and a shared token file.
5. Create reciprocal JSON files. Each side's peer data/control addresses must point to the other side; the identity and configured profile set must match.
6. Open only the selected control and receiver ports in host/network policy for the planned time window.
7. Start `mercury agent --config <LOCAL-PEER.json>` on both endpoints.
8. Run a bounded authorized assessment from one endpoint and retain the evidence/history according to local policy.

Never deploy `--unsafe-development` off loopback. Peer non-loopback operation requires mTLS, a token, and certificate pinning. A non-loopback WebUI separately requires TLS and a token.

## WebUI deployment

Loopback is the recommended default:

```bash
mercury web --bind 127.0.0.1 --port 8765
```

For an intentional private non-loopback listener:

```bash
mercury web --bind <LOCAL-PRIVATE-IP> --port 8765 --cert <WEB-CERT.pem> --key <WEB-KEY.pem> --token-file <WEB-TOKEN.txt>
```

The built-in server validates host/origin state, uses a SameSite session cookie and CSRF header, bounds request bodies, and emits a content security policy. It is still an operator surface: restrict network access, protect the token file, and use a certificate trusted by intended browsers. Web mode does not expose peer-agent control.

## Tailscale control-channel option

When an administrator already operates Tailscale, Mercury can bind peer control to admitted `100.64.0.0/10` addresses using `control_bind_host` and `control_peer_addresses`, while `bind_host`, `peer_addresses`, and receiver addresses remain on the private network under test.

This split prevents the control path from being mistaken for data-path evidence. Tailscale is neither installed nor managed by Mercury; its ACLs, device enrollment, DNS, and availability are external deployment responsibilities. Mercury mTLS/token/pin requirements remain mandatory. Do not use Tailscale data addresses if the goal is to test a different underlay path.

## Nmap deployment

Nmap is optional and must be present on the same machine and `PATH` as Mercury. Mercury supports only one of `nmap_tcp_connect`, `nmap_tcp_syn`, `nmap_udp`, or `nmap_sctp_init` per mapping task. It constructs `-n -Pn --reason`, the fixed scan selector, bounded rate/timeout/ports, XML output, and admitted numeric targets internally.

Privilege requirements depend on the selected Nmap profile and operating system. Missing executable, permission denial, nonzero exit, timeout, malformed XML, and native port states are kept distinct. Do not treat a capability failure or `filtered`/`open|filtered` state as equivalent to a direct Mercury socket observation.

## Release smoke test

Run only on systems and networks you administer:

```bash
python -m mercury version --json
python -m mercury model --json
python -m mercury status --json
python -m mercury discover --passive --json
python -m mercury diagnose --profile basic --authorized --json
```

Then verify the WebUI on loopback. If peer deployment is in scope, first start both configured agents, then run a small configured profile set with a short timeout. Never substitute a public, documentation, or unowned address.

## Rollback procedure

No automatic rollback mechanism is present.

1. Stop the WebUI/agent process and preserve its local history if required.
2. Reinstall the previously reviewed wheel in the virtual environment, or switch the service command back to the previous immutable environment.
3. Restore the matching peer JSON and trust files from protected configuration backup; certificates, pins, and addresses must remain mutually consistent.
4. Run `python -m mercury --help`, `status --json`, and the loopback smoke test before restarting non-loopback listeners.
5. If trust material may have been exposed, rotate the token and certificates instead of restoring them.

## Monitoring and operations

No Sentry, Datadog, New Relic, OpenTelemetry, or external monitoring integration is present. Monitor the OS process and collect sanitized CLI JSON/history exports under local retention policy. The SQLite history defaults to the user data directory and can be moved with global `--data-path`.

Alert separately on process exit and on typed capability/terminal states. Silence, timeout, and missing observations are not a successful health check. Coverage is finite: a positive correlated arrival identifies a candidate carrier, while a negative assessment is limited to the recorded profiles, directions, ports, packet shapes, and time window.
