# Changelog

All notable release changes are documented here.

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

