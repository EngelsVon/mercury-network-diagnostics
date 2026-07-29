# Stack Research

**Domain:** Cross-platform local-first network diagnostics  
**Researched:** 2026-07-30  
**Recommendation:** Python 3.11+ with one runtime dependency (`psutil`)  
**Confidence:** MEDIUM-HIGH; validate packaging and route adapters in Phase 1

## Decision

Build the first useful Mercury release in Python, using the standard library for
the CLI, concurrent probes, TLS/HTTP, WebUI server, JSON, IP policy, SQLite,
process adapters, and tests. Add `psutil==7.2.2` as the only runtime dependency
because Python’s standard library cannot portably enumerate interface
addresses, link state, MTU, MAC, and speed.

This is the Ponytail answer for this repository: it is an empty project under a
Python workspace with Python 3.13.5 already installed; the required UI is small;
and the product risk lies in network semantics, not framework scale. Go has a
stronger single-binary story and is the fallback if deployment evidence—not
preference—shows Python packaging is the limiting problem.

## Language comparison

| Criterion | Python 3.11+ | Go | Rust |
|-----------|--------------|----|------|
| Time to validate diagnostic semantics | **Best**: concise stdlib and interactive platform testing | Good | Slowest |
| Interface enumeration | `psutil` needed | `net.Interfaces` baseline; routes still OS-specific | crates/platform APIs |
| Async TCP/DNS/subprocess | `asyncio` stdlib | goroutines/net stdlib | Tokio dependency |
| UDP/raw ICMP portability | OS-specific limits; same fundamental issue | OS-specific limits; `x/net` often needed | crates/unsafe/platform work |
| Embedded local WebUI | `http.server` + package resources | `net/http` + `embed` | framework/crates |
| Secure transport | `ssl` stdlib; user/managed certs | `crypto/tls` stdlib | Rustls/native TLS crate |
| Local persistence | `sqlite3` stdlib | driver dependency | driver dependency |
| Distribution | pipx/venv; optional frozen builds | **Best** single binary | Excellent single binary |
| Developer/test environment here | **Already present** (3.11–3.13) | Not established | Not established |
| Maintenance surface for lean v1 | **Lowest** | Low | Highest |

### Why not Go now

Go would remove the Python runtime requirement, but it does not eliminate the
hard parts: route/neighbor/LLDP capability differences, raw-socket privileges,
UDP uncertainty, peer policy, and controlled failure tests. Rewriting those
semantics to gain one-binary deployment before validating the workflow is
speculation.

**Migration trigger:** reconsider Go only if clean-machine testing shows pipx/
installer support causes material adoption failures or frozen Python releases
are repeatedly unstable. Preserve a versioned JSON schema so a later engine
can interoperate, but do not add an abstraction layer for a hypothetical
rewrite.

### Why not Rust now

Rust is attractive for privileged packet handling and tightly controlled
binaries. Mercury v1 deliberately avoids a custom capture/raw-packet engine.
Rust would add async, web, TLS, serialization, platform, and SQLite crates
before the product hypothesis is proven.

## Recommended stack

### Runtime

| Layer | Choice | Version/policy | Rationale | Confidence |
|------|--------|----------------|-----------|------------|
| Python | CPython | `>=3.11` (develop/test on 3.13.5) | `TaskGroup`, `tomllib`, modern typing; broad supported installs | HIGH |
| Interface data | `psutil` | `7.2.2` | Mature cross-platform NIC addresses/stats; only real stdlib gap | HIGH |
| CLI | `argparse` | stdlib | Subcommands/options/epilog are sufficient | HIGH |
| Probe concurrency | `asyncio` | stdlib | Bounded TCP tasks, DNS offload, timeouts, cancellation | HIGH |
| IP/scope policy | `ipaddress` | stdlib | Canonical IPv4/IPv6 networks and containment | HIGH |
| HTTP/WebUI | `http.server.ThreadingHTTPServer` | stdlib | Small local API/static dashboard; no framework need | MEDIUM-HIGH |
| TLS | `ssl` | stdlib | Wrap remote WebUI/agent listeners with configured certs | HIGH |
| Auth primitives | `ssl` client certificates, `secrets`, `hmac.compare_digest` | stdlib | mTLS identifies peers; bearer token independently authorizes; no custom cipher | HIGH |
| History | `sqlite3` | stdlib | Local task/result history, transactions, no ORM | HIGH |
| Serialization | `dataclasses`, `enum`, `json` | stdlib | Explicit versioned observations without Pydantic | HIGH |
| Native commands | `asyncio.create_subprocess_exec` / `subprocess.run` | stdlib | Safe argument arrays, timeouts, captured raw evidence | HIGH |
| Assets | `importlib.resources` | stdlib | Ship the native HTML/CSS/JS inside the same package | HIGH |
| Tests | `unittest`, fakes, subprocess fixtures | stdlib | No test-framework dependency needed | HIGH |
| Packaging | `setuptools` | build requirement `>=77`; current PyPI 83.0.0 | Standard wheel/editable install and entry point | HIGH |

### Optional external capabilities

These are detected and consumed; they are not installed or reimplemented by
Mercury:

| Tool | Use |
|------|-----|
| `ping` | Privilege-compatible ICMP status; retain exit code/raw output |
| `traceroute` / `tracepath` / `tracert` | Route evidence using platform-native behavior |
| `lldpctl -f json` | Adjacent LLDP evidence when an administrator has deployed lldpd |
| `nmap -oX` | Future opt-in deep scan import, only after user demand |
| `iperf3 --json` | Future opt-in performance profile, not a Mercury implementation |

## Architecture implications

```text
mercury CLI / local HTTP API
             |
        shared service functions
             |
 policy + budget + evidence schema + task events
       |             |              |
 platform facts   stdlib probes   framed peer TLS protocol
       |                            |
 psutil + optional native tools   SQLite history
```

Use functions and small modules until a second implementation genuinely
requires an interface. The one justified boundary is the platform adapter:
Windows/Linux/macOS commands and capabilities differ and need isolated fixtures.
Do not create factories, dependency injection containers, repositories, or a
plugin SDK.

## Peer/Web security choice

- Local WebUI binds `127.0.0.1` by default with an unguessable session token.
- A non-loopback WebUI requires TLS certificate/key plus a bearer token.
- A peer agent also requires a trusted client certificate (mTLS); the bearer
  token is an independent authorization factor, not the peer identity. Plain
  or server-auth-only peer binding is refused unless the operator supplies an
  explicit unsafe-development override that is visibly audited.
- Mercury does not generate or manage a private CA in v1. Users may use an
  organizational certificate or `openssl`-generated test certificate.
- Do not design a custom encryption or pairing handshake. Human-friendly
  pairing can be added only when a reviewed protocol/library is selected.

This makes secure remote deployment slightly less automatic, but avoids
shipping bespoke crypto. A guided certificate helper is a future usability
feature, not a reason to weaken the boundary.

## What not to add

| Avoid | Why |
|-------|-----|
| FastAPI/Flask/aiohttp | The API has a few local endpoints; framework cost and supply chain exceed saved code |
| React/Vue/Svelte/Node build | Native HTML, CSS, fetch, and accessible tables/forms suffice |
| Pydantic | Dataclasses and explicit validators cover internal versioned JSON |
| SQLAlchemy | A bounded local SQLite table needs a handful of SQL statements |
| Celery/Redis/message broker | Tasks are local, bounded, cancellable in-process operations |
| Scapy | Pulls Mercury toward privileged packet crafting and scanner scope |
| Raw libpcap/Npcap integration | Optional LLDP/capture does not justify privileged cross-platform machinery |
| Custom crypto/Noise-like protocol | Use TLS; cryptographic protocol design is not the product |
| Generic plugin system | One internal probe registry is enough until third-party extensions exist |
| Kubernetes/Docker as primary distribution | Tool must diagnose the host network, including desktops |

## Build and compatibility policy

- `pyproject.toml` defines one `mercury` console script; the same wheel contains
  WebUI assets and agent commands.
- CI tests CPython 3.11–3.13 on Windows, Linux, and macOS. The current local
  interpreter is 3.13.5.
- Normal tests are unprivileged. Optional privileged integration tests are
  marked/skipped with a clear reason.
- Linux controlled-network tests use namespaces/netem when available; portable
  classifier/adapter fixtures cover other platforms.
- A future release workflow may build PyInstaller/Nuitka artifacts only after
  the installed wheel works. Neither is a runtime dependency or Phase 1 need.

## Version verification

Queried official package metadata on 2026-07-30:

- `psutil` latest: 7.2.2 — https://pypi.org/project/psutil/
- `setuptools` latest: 83.0.0 — https://pypi.org/project/setuptools/
- local CPython: 3.13.5; Python downloads/support information:
  https://www.python.org/downloads/

The minimum Python version is a compatibility floor, not a claim that 3.11 is
the latest release.

## Risks and validation spikes

1. **Windows route/neighbor commands:** implement one adapter with recorded
   English and non-English fixtures; prefer structured PowerShell CIM data only
   if it is stable and available.
2. **Remote TLS ergonomics:** prove two-machine setup with supplied certificates
   before claiming peer mode is easy.
3. **Threaded WebUI + async probes:** keep API operations job-based; do not
   share event loops across handler threads.
4. **Frozen distribution:** test only after wheel behavior is stable; migrate
   language only on evidence.
5. **psutil free-threaded Python:** CI includes regular CPython first; free-
   threaded 3.13 support is not a v1 requirement.

## Sources

- Python standard library documentation:
  https://docs.python.org/3/library/
- `asyncio`:
  https://docs.python.org/3/library/asyncio.html
- `http.server` security note and API:
  https://docs.python.org/3/library/http.server.html
- `ssl`:
  https://docs.python.org/3/library/ssl.html
- `sqlite3`:
  https://docs.python.org/3/library/sqlite3.html
- psutil documentation/releases:
  https://psutil.readthedocs.io/ and https://pypi.org/project/psutil/
- Go standard library networking:
  https://pkg.go.dev/net and https://pkg.go.dev/net/http
- Rust standard library networking:
  https://doc.rust-lang.org/std/net/
- setuptools:
  https://setuptools.pypa.io/

All sources accessed 2026-07-30.

---
*Stack research for Mercury*
