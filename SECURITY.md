# Security policy

## Supported version

Security fixes are maintained on the latest tagged release. The current development
target is `v3.1.12`; verify the latest published tag before reporting a version-specific
issue.

## Reporting a vulnerability

Please use the repository's private GitHub Security Advisory flow. Do not include a
live credential, private key, access token, customer data, or an exploit against a
system you do not own. A minimal synthetic reproducer is preferred.

Include the affected version, operating system/runtime, security invariant, source to
sink, impact, and a safe reproduction. Please allow maintainers time to investigate
before public disclosure.

## Boundary and secret handling

- Local HMAC attestations provide integrity and correlation; they are not resistant to
  another process running as the same OS user.
- Project configuration cannot opt in to raw prompt persistence.
- The legacy process-level prompt archive switch is disabled; prompt content is never
  written by the shipped logger.
- Machine-local executable hashes and exact argv approvals live in
  `~/.agent-supervisor/trusted-executables.json`; that file is ignored and is never a
  release artifact.
- The installer never creates a trust registry or modifies Claude settings. A normal
  adapter install safely merges a marked Agent Supervisor block into user-level Codex
  `AGENTS.md` and replaces only its own handlers in Codex `hooks.json`; use
  `--no-codex-global-activation` to opt out.
- Generated Codex hook commands use the installer-selected absolute Python executable
  and absolute installed adapter path. The Claude adapter anchors its production home,
  pointer, and release roots to its canonical path under `~/.claude/skills/`.
- Repository-triggered failures can mark rollback as required, but cannot change the
  user-wide active-version pointer automatically.

Before publishing a fork, scan both the current tree and full Git history for secrets.
Rotate any real credential that was ever committed; deleting it from the latest tree is
not sufficient.
