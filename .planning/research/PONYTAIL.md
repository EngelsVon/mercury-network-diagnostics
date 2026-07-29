# Ponytail Applicability Review

**Project reviewed:** [DietrichGebert/ponytail](https://github.com/DietrichGebert/ponytail)  
**Inspected branch/commit:** `main` at
[`16f29800fd2681bdf24f3eb4ccffe38be3baec6b`](https://github.com/DietrichGebert/ponytail/commit/16f29800fd2681bdf24f3eb4ccffe38be3baec6b)  
**Commit authored:** 2026-07-15 23:32:15 +02:00  
**Latest release found:** `v4.8.4`, published 2026-06-29  
**Package version at inspected commit:** `@dietrichgebert/ponytail` 4.8.4  
**Inspected:** 2026-07-30  
**Overall confidence:** HIGH for repository purpose, code, tests, and license;
MEDIUM for maintenance durability because the project is only weeks old

## Verdict

**Ponytail is not a network diagnostics project and is not a Mercury codebase
starter.** It is an AI coding-agent instruction package: a canonical
minimalism ruleset plus thin adapters that inject that ruleset into many agent
hosts. It has no network inventory engine, scanner, route model, WebUI, peer
agent, TCP/UDP reachability protocol, persistence model, or privilege boundary
that Mercury can reuse.

Mercury should therefore:

- **adopt** Ponytail's engineering discipline and its canonical-core/thin-
  adapter/conformance-test pattern;
- **adapt** that pattern to typed diagnostic models and three operating-system
  capability adapters;
- **reject** Ponytail's runtime, state format, hook protocol, security
  assumptions, and UI/command code as unrelated;
- **copy no code by default.** Independent reimplementation is smaller and
  avoids carrying an unnecessary JavaScript/agent-plugin subsystem.

This is a firm **conceptual fit / implementation non-fit** verdict.

## What Ponytail Actually Is

Ponytail describes itself as “lazy senior dev mode for AI agents.” Its
canonical skill instructs an agent to understand the affected code first, then
stop at the earliest sufficient implementation rung:

1. do not build what does not need to exist;
2. reuse what the codebase already has;
3. use the standard library;
4. use a native platform feature;
5. use an installed dependency;
6. use the smallest correct implementation;
7. only then write new machinery.

The skill explicitly excludes trust-boundary validation, data-loss protection,
security, accessibility, requested behavior, and a runnable check for
non-trivial logic from its simplification pressure. That qualification is
important for Mercury: authorization, authentication, budgets, cancellation,
and honest UDP/L2 semantics are necessary product behavior, not optional
“complexity.”

### Actual repository architecture

| Layer | Upstream implementation | What it does |
|------|--------------------------|--------------|
| Canonical behavior | `skills/ponytail/SKILL.md` and related skills | Holds the agent instructions and mode-specific behavior |
| Shared core | `hooks/ponytail-config.js`, `hooks/ponytail-instructions.js` | Resolves modes/config and builds one filtered instruction body |
| Host runtime | `hooks/ponytail-runtime.js` | Maps shared state/output to Claude, Codex, Copilot, and Qoder hook shapes |
| Lifecycle adapters | hook manifests and small Node scripts | Activate a mode, track commands, and inject instructions into parent/subagents |
| Native host adapters | OpenCode module, Pi extension, Hermes Python plugin | Registers commands/status and injects the same rules at each host's extension point |
| Instruction-only adapters | `AGENTS.md`, editor rule files, Gemini manifest | Copies or points hosts at the canonical instructions |
| Optional MCP adapter | private `ponytail-mcp` package | Exposes instructions as a prompt/read-only tool over MCP stdio |
| Verification | Node/Python tests and synchronization scripts | Checks host shapes, Windows behavior, copied rules, versions, packaging, and benchmark evaluators |

This is a useful ports-and-adapters example at a very small scale: canonical
behavior is centralized, while host-specific mechanics stay at the edge.
Ponytail's own portability document says adapters should remain thin and point
at existing skills/hooks where possible.

### Its data, protocol, CLI, and UI are deliberately tiny

- **Persistent data:** an optional JSON config and a plaintext
  `.ponytail-active` mode flag. This is configuration state, not an application
  data model.
- **Runtime states:** `off`, `lite`, `full`, and `ultra`; `review` is handled as
  a special session mode.
- **Protocols:** host-specific lifecycle-hook stdin/stdout JSON (or raw text)
  and an optional MCP stdio prompt/tool. There is no network wire protocol.
- **Commands/UI:** agent slash commands plus a status-line badge. There is no
  standalone CLI application or browser UI.
- **Network behavior:** the installed agent runtime does not implement a
  network service. Some benchmark/development scripts call model APIs or local
  tools, but those are not a Mercury-like diagnostic engine.

## What Is Reusable

### Strengths worth adopting

1. **One source of behavior.** The shared instruction builder is reused by
   several adapters instead of reimplementing the rule semantics per host.
   Mercury should similarly have one task/policy/probe/classification engine
   called by both CLI and WebUI.
2. **Thin, explicit adapters.** Platform quirks are visible in small boundary
   modules. Mercury should isolate Windows/Linux/macOS inventory and command
   differences behind typed capability results.
3. **Cross-adapter contract tests.** Ponytail tests real host output shapes,
   CRLF behavior, PowerShell environment syntax, stalled stdin, manifest
   consistency, and generated-copy drift. Mercury needs the same style of
   platform fixtures and contract tests around its OS and presentation edges.
4. **Configuration precedence is documented and tested.** Environment,
   platform config path, and default behavior have a deterministic order.
5. **Failure containment.** Lifecycle hooks time out and avoid freezing their
   host. Mercury must take the stronger form of this rule: deadlines and
   cancellation propagate through every scheduled socket and subprocess.
6. **Minimal dependency stance with escape hatches.** The root npm package has
   no runtime dependency list; the private MCP adapter declares dependencies
   only where its protocol warrants them. Mercury's one-dependency Python stack
   follows the same discipline.
7. **Benchmark criticism is recorded.** The README no longer presents its old
   single-shot percentage as a flat universal result; it links the criticism
   and a newer agentic benchmark. That transparency is a good reporting
   precedent, though it is not independent validation.

### Patterns to adapt, not copy literally

| Ponytail pattern | Mercury adaptation |
|------------------|--------------------|
| Canonical Markdown rules plus host injectors | Canonical versioned dataclasses/enums plus CLI, HTTP, peer, storage, and report projections |
| Mode flag and config resolver | Explicit capability report, immutable task policy snapshot, and protected peer records |
| Host-specific hook output | OS-specific facts/probe adapters returning the same normalized observation types |
| Rule-copy synchronization tests | JSON round-trip, schema migration, platform fixture, and frontend equivalence tests |
| Best-effort nonblocking hooks | Bounded tasks that persist a visible timeout/cancel/error observation |
| “Fewest files” | Few cohesive modules; preserve trust, I/O, and presentation boundaries needed for testing |
| One small check as a floor | Table-driven classifier/policy tests plus controlled network integration scenarios |

## What Must Not Be Reused

### No useful product code

Ponytail has no implementation for any Mercury requirement. Reusing its
JavaScript hooks would add a Node runtime, host-agent concepts, and global mode
files without reducing Mercury work. The visual assets, brand, instruction
copy, benchmark harness, and agent commands also have no product role.

### No useful security model

Ponytail's state and failure rules are appropriate for a non-security-critical
persona plugin, not for a dual-use network tool:

- mode/config files are ordinary plaintext and unauthenticated;
- several adapters intentionally catch errors silently or “fail open” by
  injecting instructions;
- lifecycle hooks execute local Node/PowerShell commands after host trust;
- an invalid subagent matcher falls back to injection;
- there is no remote identity, target authorization, replay protection,
  per-peer scope, or scan budget.

Mercury policy must fail closed on invalid scope/authentication and fail
visible—not silent—on unavailable diagnostic capabilities.

### No protocol or state-machine template

MCP stdio and agent hook events do not model peer identity, directional data
plane observations, TCP refusal/timeout, UDP silence, task replay, listener
readiness, or cancellation. Building Mercury's peer protocol by “generalizing”
these files would be a category error.

## Security-Sensitive Upstream Behavior Reviewed

| Surface | Evidence at inspected commit | Mercury implication |
|---------|------------------------------|---------------------|
| Host command execution | Claude/Codex/Copilot/Qoder manifests run local Node hooks; the README tells users to review/trust them | Never treat an installed plugin as inert; Mercury's privileged helper, if ever added, needs a much narrower audited command surface |
| Shell path handling | `isShellSafe()` allowlists install-path characters before suggesting a status-line shell command | Positive defensive pattern, but unrelated code should not be copied |
| PowerShell execution | Status-line setup may use `powershell -ExecutionPolicy Bypass -File ...` after path validation | Do not use execution-policy bypass as a Mercury service/privilege mechanism |
| State writes | Hooks write mode flags and config; uninstall conditionally edits host settings only when the entry points at Ponytail | Preserve the “only remove what we own” principle for Mercury configuration and credentials |
| Silent catches | Many plugin-boundary failures are swallowed so the host keeps working | Acceptable for optional persona injection; unacceptable for authorization, persistence, or diagnostic conclusions |
| MCP server | Serves instructions over stdio and marks its tool read-only/open-world false | No listening network port or peer authentication pattern to reuse |
| Dependency audit | Local tests succeeded, but automated npm audit could not run because the configured registry mirror lacked the audit endpoint | Do not infer a clean vulnerability result from the absence of a report |

## Maintenance Evidence

Repository activity is strong but too young to establish durability.

| Signal observed on 2026-07-30 | Result | Interpretation | Confidence |
|-------------------------------|--------|----------------|------------|
| First commit in cloned history | 2026-06-12 | Project age is roughly one month | HIGH |
| Inspected head | 2026-07-15, commit `16f2980…` | Recent activity | HIGH |
| Commits reachable from head | 206 | Rapid iteration | HIGH |
| Author identity lines from `git shortlog` | 69 | Broad contribution activity, but identities are not guaranteed unique humans | HIGH |
| Tags | 14 (`v1.0.0`, then `v4.0.0`–`v4.8.4`) | Frequent release/version churn | HIGH |
| Latest GitHub release | `v4.8.4`, 2026-06-29 | Release trails head by 53 commits | HIGH |
| Live repository page | about 91.6k stars and 5.0k forks | Exceptional visibility; volatile popularity is not maintenance proof | MEDIUM |
| Live Issues tab | 42 open issues | Active queue; count is volatile | MEDIUM |
| Representative open portability issues | #645 Node missing on POSIX PATH; #646 WSL/backslash module resolution; #631 OpenCode loader failure | Many-host adapter churn remains real | HIGH |
| Test run at exact commit | 82 root + 23 Pi + 3 MCP tests passed locally | Good regression coverage for current adapter contracts | HIGH |

The head commit contains a GPG signature packet, but local verification could
not establish trust because the public key was unavailable. This review does
not claim an independently verified commit signature.

### Maintenance conclusion

Ponytail is actively maintained and unusually well tested for its age.
However, recent open issues show that adding every host multiplies shell,
manifest, loader, and state edge cases. Mercury should learn from that cost:
support exactly three OS adapters and two presentation adapters, and add
extension points only after a demonstrated need.

## License and Attribution

The inspected repository contains the MIT License with:

> Copyright (c) 2026 DietrichGebert

The license permits use, copying, modification, distribution, sublicensing,
and sale, but requires the copyright and permission notice to be included in
all copies or substantial portions. It also disclaims warranty and liability.

### Practical Mercury decision

- **No upstream code is needed**, so the preferred plan creates no Ponytail
  runtime dependency and no copied source.
- The engineering idea is credited in this research document and may be
  independently implemented.
- If a future change copies Ponytail source or substantial instruction text,
  Mercury must retain the MIT notice with that distribution, record the exact
  upstream commit and modifications in third-party attribution, and confirm
  compatibility with Mercury's then-selected license.
- Do not assume the software license grants rights to Ponytail's name, logos,
  or other branding; Mercury has no reason to redistribute them.
- The MIT text contains no express patent grant. This is not presently material
  because no code reuse is recommended, but legal review should decide any
  future substantial reuse.

This is an engineering license assessment, not legal advice.

## Adopt / Adapt / Reject Matrix

| Decision | Item | Rationale |
|----------|------|-----------|
| **Adopt** | Understand first; standard library/native platform before new dependency | Directly reduces greenfield speculation |
| **Adopt** | One canonical core used by all adapters | Prevents CLI/WebUI semantic drift |
| **Adopt** | Adapter contract tests and build-time drift checks | Cross-platform boundaries are Mercury's highest implementation risk |
| **Adopt** | Root-cause fixes in shared code | One policy/classifier fix protects all entry points |
| **Adopt** | Deliberate shortcut comments with a measured upgrade trigger | Makes scoped v1 compromises explicit |
| **Adapt** | Thin host adapters | Use typed capability/evidence adapters; never silent empty results |
| **Adapt** | Minimal files/tests | Keep cohesive security boundaries and test all state combinations that matter |
| **Adapt** | Textual canonical source | Mercury needs typed, versioned models with explicit validation and migrations |
| **Reject** | Ponytail runtime/hooks/MCP server | Solves agent prompt injection, not diagnostics |
| **Reject** | Plain mode-file state model | Cannot protect peer identity, authorization, or audit evidence |
| **Reject** | Silent fail-open boundary handling | Security decisions must reject; optional capabilities must report degradation |
| **Reject** | Benchmark percentages as Mercury goals | Different domain and maintainer-authored evaluation |
| **Reject** | Generic plugin system in v1 | Built-in probe registry is enough; arbitrary plugins expand code-execution risk |

## Mercury-Specific Application of the Ladder

1. **Does it need to exist?** Mercury only earns existence through layered,
   evidence-backed explanation and paired directional tests—not by wrapping
   every existing scanner.
2. **Already present?** CLI and WebUI call the same application engine; no
   duplicate probe or classifier implementation.
3. **Standard library?** Follow `STACK.md`: Python networking, concurrency,
   TLS, HTTP, JSON, IP policy, SQLite, resources, and tests are standard-library
   first.
4. **Native platform?** Use platform facts/commands behind capability adapters
   where stable; preserve their provenance and limitations.
5. **Existing dependency?** `psutil` earns its place for portable interface
   facts. Do not add frameworks, ORM, task broker, crypto protocol, or UI build
   chain without evidence.
6. **Smallest correct implementation?** Start with hypothesis-oriented,
   bounded profiles—not a packet DSL or port × protocol × payload Cartesian
   product.
7. **Never cut safety.** Scope grants, hard budgets, peer identity, replay
   checks, cancellation, redaction, audit, UDP uncertainty, and “L2 switch
   unknown” semantics remain mandatory.

## Gaps and Confidence Limits

- GitHub REST API access was rate-limited during this review; volatile
  popularity/issue counts were read from the public HTML interface and are
  marked MEDIUM confidence.
- Local tests verify the cloned commit under this machine, not every supported
  host integration.
- Long-term maintainer responsiveness cannot be inferred from one month of
  intense activity.
- This review did not independently reproduce Ponytail's model benchmark; it is
  irrelevant to the Mercury architecture decision.

## Sources

All sources accessed 2026-07-30.

### Commit-pinned upstream evidence (HIGH confidence)

- [Repository tree at inspected commit](https://github.com/DietrichGebert/ponytail/tree/16f29800fd2681bdf24f3eb4ccffe38be3baec6b)
- [README](https://github.com/DietrichGebert/ponytail/blob/16f29800fd2681bdf24f3eb4ccffe38be3baec6b/README.md)
- [Canonical Ponytail skill](https://github.com/DietrichGebert/ponytail/blob/16f29800fd2681bdf24f3eb4ccffe38be3baec6b/skills/ponytail/SKILL.md)
- [Agent portability/adapters](https://github.com/DietrichGebert/ponytail/blob/16f29800fd2681bdf24f3eb4ccffe38be3baec6b/docs/agent-portability.md)
- [Package metadata](https://github.com/DietrichGebert/ponytail/blob/16f29800fd2681bdf24f3eb4ccffe38be3baec6b/package.json)
- [Shared instruction builder](https://github.com/DietrichGebert/ponytail/blob/16f29800fd2681bdf24f3eb4ccffe38be3baec6b/hooks/ponytail-instructions.js)
- [Shared runtime/state adapter](https://github.com/DietrichGebert/ponytail/blob/16f29800fd2681bdf24f3eb4ccffe38be3baec6b/hooks/ponytail-runtime.js)
- [Cross-platform hook manifest](https://github.com/DietrichGebert/ponytail/blob/16f29800fd2681bdf24f3eb4ccffe38be3baec6b/hooks/claude-codex-hooks.json)
- [OpenCode adapter](https://github.com/DietrichGebert/ponytail/blob/16f29800fd2681bdf24f3eb4ccffe38be3baec6b/.opencode/plugins/ponytail.mjs)
- [MCP stdio server](https://github.com/DietrichGebert/ponytail/blob/16f29800fd2681bdf24f3eb4ccffe38be3baec6b/ponytail-mcp/index.js)
- [Windows hook contract tests](https://github.com/DietrichGebert/ponytail/blob/16f29800fd2681bdf24f3eb4ccffe38be3baec6b/tests/hooks-windows.test.js)
- [MIT License](https://github.com/DietrichGebert/ponytail/blob/16f29800fd2681bdf24f3eb4ccffe38be3baec6b/LICENSE)

### Live maintenance evidence (MEDIUM/HIGH as noted)

- [Release v4.8.4](https://github.com/DietrichGebert/ponytail/releases/tag/v4.8.4)
- [Open issues](https://github.com/DietrichGebert/ponytail/issues?q=is%3Aissue%20state%3Aopen)
- [Issue #645: Node absent on POSIX PATH](https://github.com/DietrichGebert/ponytail/issues/645)
- [Issue #646: WSL/backslashed plugin root](https://github.com/DietrichGebert/ponytail/issues/646)
- [Issue #631: OpenCode plugin loader failure](https://github.com/DietrichGebert/ponytail/issues/631)
- [Issue #126: benchmark baseline criticism](https://github.com/DietrichGebert/ponytail/issues/126)

---
*Ponytail applicability research for Mercury*  
*Researched: 2026-07-30*
