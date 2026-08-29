# Changelog

All notable release changes are documented here.

## 3.1.12 - 2026-08-28

### Security

- Git batch-object hashing now handles raw-pipe short writes with a bounded complete
  request loop and closes stdin on every outcome.
- Unbound Skill/Agent labels no longer share or mutate a generic capability breaker;
  breaker state is updated only for inventory-verified identities or native tool kinds.
- Installation now documents a two-pass Codex activation sequence so executable trust
  is configured before user-level lifecycle hooks are enabled.
- User-defined Codex hook groups without a `hooks` field are preserved unchanged
  while structurally recognized Supervisor handlers are replaced.
- User-level Codex hook commands now bind the installer-selected absolute Python
  executable and absolute adapter path before any workspace-controlled lookup can run.
- The Claude adapter derives its active pointer and allowed release roots from its
  canonical installed location and ignores ambient home/release overrides in production.
- Hook upgrades remove only structurally exact Supervisor handlers; unrelated commands
  that merely mention the adapter filename are preserved.
- Caller-supplied Skill/Agent labels contribute to the signed timeline only when the
  observed tool kind and current capability inventory correlate the exact identity.
- The first exact Stop-hook summary is now bound by a signed hash so later
  finalization timestamps cannot make an already supplied summary appear forged.
- Existing Codex `hooks.json` files with duplicate JSON keys are rejected instead of
  being ambiguously merged during global activation.
- The legacy prompt-content archive switch is permanently disabled; only bounded
  metadata and digests remain eligible for persistence.
- Release builds require `--version` to equal repository `VERSION` and reject any
  runtime member outside Git's publishable source set.
- Release builds resolve Git only through the machine-local trusted executable
  registry and run it with a credential-minimal environment, ignoring poisoned PATHs.
- Immutable review artifacts now validate their declared baseline context against
  the workspace delta instead of incorrectly requiring a context-free base tree.
- Immutable review trees are hashed through bounded `git cat-file --batch`
  sessions, avoiding one child process per tracked file.
- Generic event ingestion rejects caller-supplied attestations; only core-built
  invocation events can be signed after transactional fields are added.
- Caller-supplied `kind` and `capability_kind` markers are discarded and then
  re-derived from trusted inventory/command metadata before invocation signing,
  so native commands cannot be relabeled as Skills or Agents.
- Caller-supplied `tool_kind` is also discarded before invocation signing, closing
  the remaining path for forged plugin attribution in signed timeline details.
- Git batch-object hashing now uses a bounded timeout scaled to the accepted object
  and byte budget instead of applying the single-command timeout to the whole batch.
- Codex Stop-summary continuation now blocks only in `enforce` mode; `observe`
  and `warn` emit the signed summary as an advisory and preserve the documented
  host limitation instead of acting like a hard lifecycle gate.

### Fixed

- Global Codex hook activation now gives the lifecycle bridge enough outer time for
  interpreter identity, process startup, the event-specific core deadline, and bounded
  cleanup. This prevents Codex from terminating healthy cross-project hooks before
  they can return their structured result or final `RoundProcessSummary/v1`.
- Immutable CodeRabbit review materialization now reads `before` bytes from the bound
  baseline commit when reviewing an already committed delta, while separately binding
  the live workspace to the expected reviewed HEAD.
- The core-owned default registered-gate timeout now matches the existing
  30-minute hard ceiling, allowing the full cross-platform source suite to finish
  without accepting caller-selected timeout overrides.
- Claude installations accept a redirected profile-home ancestor while continuing
  to reject links and reparse points inside the managed `.claude` adapter subtree.

## 3.1.11 - 2026-08-28

### Fixed

- Explicit audited native-command invocations now retain their sanitized kind and
  command category in the signed event pair, so `RoundProcessSummary/v1` cannot
  mislabel tests, installers, or other native commands as Skills.

## 3.1.10 - 2026-08-28

### Fixed

- Transactional explicit Skill results are now re-attested after the core adds its
  transaction identity. Valid invocation pairs therefore remain visible in
  `RoundProcessSummary/v1` instead of being incorrectly discarded as tampered records.

## 3.1.9 - 2026-08-28

### Security

- Release materialization now rejects drive-relative, colon-bearing, NUL,
  backslash, absolute, and traversal member names before any file is written.
- Ambiguous duplicate global `AGENTS.md` managed markers now fail closed.

## 3.1.8 - 2026-08-28

### Fixed

- The installer now materializes and verifies every immutable runtime-bundle member
  before publishing the active pointer. This restores the Stage-0 path contract and
  safely resumes a matching partial installation after interruption.

## 3.1.7 - 2026-08-28

### Added

- Safe, idempotent user-level Codex activation during adapter installation: all 11
  lifecycle hooks plus a replaceable global `AGENTS.md` policy block are merged while
  unrelated user configuration is preserved and changed files are backed up.
- A bounded Codex Stop continuation that supplies the signed
  `RoundProcessSummary/v1` whenever the assistant's final message omits it.

### Changed

- The compact round renderer now uses status icons for a one-glance timeline without
  changing the underlying evidence and quality-gate semantics.
- Installation and Codex adapter documentation now distinguish user-level cross-project
  activation, `/hooks` trust, and the host's bounded Stop limitation.

## 3.1.6 - 2026-08-25

### Added

- Apache-2.0 licensing, public contribution/security documentation, and a dry-run-first
  local installer for side-by-side core releases and thin adapters.
- Exact machine-owned argv approvals for repository-declared external gates.
- Resource budgets for hook input, JSON/schema processing, capability discovery,
  workspace capture, release construction, review sources, and child output.
- Repository-bound release/security tests and v3.1.6 hardening regressions.

### Changed

- Raw prompt persistence is private by default and cannot be enabled by project config.
- External gates run with a credential-minimal environment.
- CodeRabbit receives only bounded release-source files, never user/project settings.
- Release identity is published only after the staged bundle validates.
- Claude and Codex stage-zero adapters bind to verified pointer-v4 runtime bytes.

### Security

- Repository-triggered rollback now records `approval_required`; only a separate explicit
  user action may mutate the global active-version pointer.
- Native commands without an authenticated effect boundary fail closed in enforce mode.
- Adapter input and subprocess output are bounded before parsing or buffering.
