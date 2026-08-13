<!-- generated-by: gsd-doc-writer -->
# Security Policy

[简体中文](SECURITY.zh-CN.md)

## Supported versions

Mercury is currently in alpha development. Security fixes are applied to the latest revision on `master`; no older release line is currently maintained. Windows and Ubuntu are the v1 security-support targets on CPython 3.11+.

## Reporting a vulnerability

Do not open a public issue, discussion, or pull request for a suspected vulnerability.

Use the repository's private [GitHub Security Advisory reporting form](https://github.com/EngelsVon/mercury-network-diagnostics/security/advisories/new), or open **Security** → **Advisories** → **Report a vulnerability**. If private vulnerability reporting is unavailable, retain the report privately until maintainers publish another official private channel. This repository does not publish a security email address; do not guess one or send secrets to unrelated contacts.

Include only the information needed to reproduce and assess the problem:

- affected revision or version, platform, and Python version;
- vulnerability class and affected trust boundary;
- minimal steps using loopback or a private network you own or are explicitly authorized to test;
- expected and actual behavior, impact, and suggested mitigation if known;
- sanitized logs or evidence with tokens, private keys, certificates, addresses, hostnames, payloads, and credentials removed.

Do not attach live credentials or production private keys. Do not test against public Internet targets, third-party systems, the project maintainers' infrastructure, or any network you do not own or have explicit permission to assess. Do not expand a proof of concept beyond the minimum needed to demonstrate the issue, disrupt service, retain private data, or attempt credential brute force.

Maintainers should acknowledge a private report, reproduce it in a controlled environment, coordinate a fix and disclosure timeline, and credit the reporter if requested. A response-time service level is not currently published.

## Security boundaries

Security-sensitive contributions must preserve these repository guarantees:

- Active targets are limited to loopback, RFC1918 IPv4, IPv6 ULA, or scoped IPv6 link-local addresses/CIDRs and require explicit authorization where applicable. Public, documentation, multicast, unspecified, broadcast, and scope-escaping DNS answers fail before I/O.
- All active work passes through canonical policy and immutable host, port, attempt, logical-byte, rate, concurrency, duration, event, and output ceilings.
- Non-loopback Web listeners require TLS and a token. Peer control also requires mutual TLS, configured certificate trust/pinning, token and replay checks, and fixed configured destinations.
- Peer control cannot become a third-party scan relay, and the optional Nmap adapter accepts only fixed plan-derived profiles—not arbitrary arguments, scripts, target files, proxies, decoys, or payloads.
- History and reports reject credentials, tokens, and private keys; identifier and payload output is redacted by default.
- Silence or timeout is inconclusive evidence. A finite test matrix cannot prove that every tunnel or packet sequence is blocked.

The certificates and keys under `tests/fixtures/tls/` are committed test fixtures only and must never be trusted or deployed in production.

## Safe research scope

Mercury is intended only for controlled diagnostics on private networks owned by the operator or covered by explicit authorization. A private IP address alone does not establish permission. Coordinated security research must remain within the exact systems, ports, profiles, rate, duration, and data-handling limits granted by the owner.
