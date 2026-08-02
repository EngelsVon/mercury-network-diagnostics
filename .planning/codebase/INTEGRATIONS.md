# External Integrations

**Analysis Date:** 2026-08-02

## Overview

Mercury has no SaaS API, cloud account, telemetry backend, or remote database integration. Its integrations are local operating-system capabilities and an optional mutually authenticated peer transport.

## Operating-System Integrations

**Local inventory:**

- Location: `src/mercury/inventory.py` and `src/mercury/discovery.py`.
- Uses: `psutil` plus Windows and Linux platform adapters.
- Purpose: collect interfaces, routes, DNS, neighbour-cache, Wi-Fi, and direct LLDP evidence without sending probes.
- Failure behavior: unavailable commands and permissions become `Capability` records.

**Native diagnostic commands:**

- Location: `src/mercury/platform/common.py` and `src/mercury/trace.py`.
- Uses: platform-native command binaries through bounded subprocess calls.
- Purpose: optional native ping/path observations.
- Boundary: command absence, permission denial, and unresponsive hops remain distinct evidence outcomes.

**SQLite history:**

- Location: `src/mercury/history.py`.
- Uses: a per-user SQLite database selected by `default_history_path()`.
- Purpose: durable local task lifecycle, comparison, and report source.
- Boundary: request/result data is validated and secret-like values are rejected before persistence.

## Local Web Integration

- Location: `src/mercury/web/__init__.py` and `src/mercury/web/static/`.
- Uses: the Python standard-library HTTP server, loopback by default.
- Purpose: submit and poll work through `MercuryApplication`; browser code does not open network probes.
- Boundary: non-loopback listeners require TLS and a token, while all mutations enforce origin and CSRF checks.

## Peer-Agent Integration

- Location: `src/mercury/peer.py` and `src/mercury/paired.py`.
- Uses: TLS client/server contexts, configured certificate pinning, a token file, and a closed operation set.
- Purpose: run the fixed paired diagnostic profile in both directions.
- Boundary: the peer transport does not accept an arbitrary third-party destination.

## Nmap Status

- The development machine has `D:\\Nmap\\nmap.exe`, discovered as a local executable.
- Current source code neither invokes Nmap nor parses Nmap output.
- Any future adapter must create its argv from an internally validated request, write fixed XML to stdout, and record Nmap provenance. It must never forward arbitrary operator flags, scripts, target files, proxies, decoys, or destinations.

## Operational Implications

- No external credentials need to be configured for the normal product.
- Tests must fake command execution or use loopback; they must not invoke a real scan of an unowned host.
- Capability discovery is the correct fallback when a native tool is absent.

---

*Integration analysis: 2026-08-02*
*Update when an external or native integration changes*
