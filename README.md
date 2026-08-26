# Agent Supervisor v3.1.6

Runtime-neutral goal and quality supervision for Claude Code and Codex. The shared core owns contracts, isolated state, evidence validation, capability discovery/routing, lifecycle finalization, and migration. Host integrations are deliberately thin adapters.

Licensed under Apache-2.0. This release is designed to be installed side by side,
fail closed at security-sensitive boundaries, and keep prompts, machine trust policy,
state, and credentials out of the repository and external review inputs.

## Quick start

```powershell
git clone https://github.com/SevenTeenBoy17/agent-supervisor.git
Set-Location agent-supervisor
git checkout v3.1.6
python -m pip install .
python bin/install-agent-supervisor.py
python bin/install-agent-supervisor.py --apply
python "$HOME/.agent-supervisor/bin/agent-supervisor.py" --version
```

The package install supplies the declared PyYAML and jsonschema runtime dependencies.
The first Supervisor installer call is a read-only plan. `--apply` builds and verifies a
deterministic runtime bundle, installs the core and thin adapters, backs up changed
managed files, and publishes the v4 active pointer last. It never edits Codex
`AGENTS.md`/hooks, Claude settings, or the machine-local executable trust registry.
Complete those explicit activation steps in [the installation guide](docs/INSTALL.md).

## Stable entry points

From this directory:

```powershell
python -m supervisor_core --version
python -m supervisor_core selftest
```

From any directory, use the self-bootstrapping script:

```powershell
$SupervisorRoot = Join-Path $HOME ".agent-supervisor"
python (Join-Path $SupervisorRoot "bin/agent-supervisor.py") --version
```

For source development, an editable install (`python -m pip install -e .`) makes
`python -m supervisor_core` and `agent-supervisor` available from arbitrary working
directories. Production adapters execute only a verified `ActiveVersionPointer/v4`
bundle and do not use mutable `PYTHONPATH` fallback.

The public commands are `discover`, `route`, `start`, `event`, `validate`, `finalize`, `query`, `selftest`, and `migrate`. `hook` is the lifecycle adapter boundary. Exit codes are fixed: `0` success/complete, `2` incomplete, `3` blocked, `4` degraded, `64` invalid state or invocation.

## State and contracts

State is isolated under:

```text
state/<runtime>/<project>/<workspace>/<session>/<round>/
```

Each path segment includes a stable hash. Codex defaults the session to `CODEX_THREAD_ID`; Claude defaults to `CLAUDE_SESSION_ID`. Events use an exclusive lock, a monotonic sequence, atomic file replacement, rotation, and redaction before persistence. Handoffs are rendered from structured state rather than blank templates.

The versioned contracts are in `schemas/`. Completion requires:

- a versioned `GoalContract` and a disposition for every atomic intent;
- correlated invocation attempt/result records (only `result=success` counts);
- structured, current, relevant evidence bound to a criterion and diff;
- a reviewer from a different responsibility group, bound to base/head/diff;
- every binary gate required by the active quality domains;
- resolved/spec-light specification and completed linked tasks.

Free text such as `trust me`, empty evidence, attempts without results, failed commands, stale artifacts, unrelated shell activity, scope violations, reviewer/implementer identity collisions, unreviewed test weakening, and missing domain gates are rejected.

## Goal transitions and Stop behavior

`continue` and `extend` retain the goal identity and increment its version. `replace` creates a new identity and marks the prior active state/tasks as superseded. Terminal states are exactly `complete`, `incomplete`, `blocked`, and `user-waived`. A waiver must bind a criterion, original authorization, authorizer, timestamp, and reason.

The two-Stop cap only releases a host loop. It never changes unresolved state to `complete`. Validator or adapter failures are persisted as degraded health; adapters may fail open for host availability, but finalization exits `4` and records `incomplete`.

## Discovery and routing

Discovery uses real YAML and TOML parsers, preserves full invocation names, distinguishes automatic/manual-only/user-invocable/cache/disabled/broken capabilities, ignores nested `upstream` copies, and chooses one enabled version. `--write-baseline` records a hash inventory; `--baseline` explains missing, added, and changed entries, including a 154-skill baseline.

`start` performs capability discovery and routing automatically for both normal and shadow rounds. The Codex `UserPromptSubmit` entrypoint repeats that scan and route for every newest request, so a continued, extended, or replaced goal is evaluated against the current enabled inventory rather than a stale session list. Codex defaults are derived from explicitly enabled plugins in `~/.codex/config.toml`: only one concrete, non-link installed version is host-callable, while the personal Skill root remains available. Normal rounds atomically persist the full inventory, its hashed discovery summary, and `capability_route`; shadow rounds return only the summary and route. When prompt persistence is disabled, raw prompt text is used only for in-memory intent routing and the ledger stores its digest. The host must execute the ordered route phases and record correlated invocation results—`scheduled`/`deferred` is not success. In Codex, a unique, current-round, locally signed `codex-explicit-audit` attempt/result pair may prove only that a capability contributed to an intent; it never proves implementer, reviewer, or gate-runner identity. Discovery or routing exceptions degrade with exit `4`, and an empty route remains incomplete with exit `2` pending an independently validated zero-Skill review.

Routing accepts host-provided atomic intents. It limits one phase to 2–3 high-signal capabilities but has no total capability, clause, candidate, or name-length limit. A zero-skill start remains incomplete even when every intent has a concrete skipped reason; only a later, independently validated routing review can satisfy the finalization gate.

## Rollout, breaker, and rollback

Projects select `observe`, `warn`, or `enforce` in `.agent-supervisor/project.json`. Recommended promotion:

1. `observe`: replay deterministic fixtures and historical logs.
2. `warn`: run real rounds while measuring critical misses and false blocks.
3. `enforce`: enable per project only after zero critical misses and at most 2% false blocks. Other projects remain in `warn` until 20 non-trivial rounds meet the same bar.

Two consecutive failures open that capability's breaker and retain its configured
`fallback_id`. Two consecutive global-gate failures bound to the same concrete
active-release identity mark rollback as `approval_required`; they never mutate the
user-wide pointer automatically. A separately invoked, explicitly authorized rollback
may compare-and-swap to a validated previous side-by-side release. Unbound failures and
failures observed across different active versions do not combine into a rollback
streak. State and migrated legacy snapshots are append-only and are not deleted.

`ActiveVersionPointer/v4` binds the complete `SupervisorReleaseIdentity/v1`: version, canonical release path, runtime-bundle path, bundle hash, manifest hash, and source-tree hash. The pointer has exactly `contract`, `active`, and `previous`; rollback is compare-and-swap and records audit metadata only in the ledger. A release is built as a deterministic, uncompressed runtime ZIP whose manifest covers every executable core module, schema, launcher, CodeRabbit runner, release scanner, installer, and selftest module. Codex freezes the pointer and bundle once, creates the Windows kill-on-close Job Object, then sends a bounded binary frame over stdin. A deny-disk-fallback importer verifies every member and loads `supervisor_core.*` from those frozen bytes; a pointer or module swap can affect only a later invocation. Bound selftests extract their exact bundled payload under a short OS-temporary session root, bind the child profile to the installation home, execute pytest with the registry-bound Python, derive dependency roots with an isolated fixed probe, mirror only the core's bounded declared runtime package closure into session-local user storage for nested processes, and never write into the immutable release or installation profile. The CodeRabbit runner and complete reviewed core are likewise taken from the bound bundle and executed from a bounded stdin frame instead of reopening mutable core scripts from disk.

Registered command gates must be executed through the core's `gate_run` event (or the Codex `supervisor-gate.ps1` wrapper). A Codex caller supplies only the gate id, criterion id, and optional evidence id; the core mints the one-use execution identity, executes the exact argv from the active `QualityProfile`, captures bounded/redacted output, hashes it, and signs a `GateExecution/v3` attestation. Caller-authored actor/group/invocation/timeout/command fields, exit codes, free-form evidence, or a manually injected `gate_execution` event cannot satisfy completion. The compatibility wrapper still accepts the former identity parameters, but ignores them.

The completion-eligible CodeRabbit runner is shipped inside the immutable active core and included in the Supervisor source snapshot. Its binding covers the exact workspace diff, the full bundled review source, and the selected Codex and Claude adapter manifests. The external review process receives a minimal allowlisted environment and pinned executable registry; product secrets and the ambient process environment are not inherited. A strictly validated `ReviewOutputArtifact/v1` with authenticated context, complete findings, exact source/diff bindings, and no blocking findings lets the core issue an automated external ReviewRecord. Test changes require a second, separately executed `review.coderabbit.test-integrity` record; the general review cannot stand in for it. Manual Codex reviewer/sub-agent claims remain audit-only unless the host supplies an independently verifiable identity primitive.

External commands are resolved only through a machine-local, ignored
`TrustedExecutableRegistry/v1`. Each entry binds a canonical absolute path, streamed
SHA-256, and machine-owner-approved hashes for each exact argument-bearing argv. Ambient
`PATH` discovery, implicit current-directory lookup, symlink/reparse indirection,
registry drift, unknown native-command effects, and oversized/unreadable binaries fail
closed. External gates use a credential-minimal environment with `shell=False`; the
registry is never shipped as a release artifact. See [Installation](docs/INSTALL.md).

Workspace evidence excludes Supervisor runtime state (`.agent-supervisor/handoffs`, state/log/cache/spool files, `.codex-supervisor`) and test caches. Required handoff/timeline maintenance therefore cannot manufacture an implementation diff, while versioned Supervisor contracts, fixtures, adapters, and scripts remain in scope.

### Security boundary (explicit limitation)

The local HMAC is an operational integrity and correlation mechanism, not a security boundary against another process running as the same OS user. Such a process can ultimately read or invoke local code and credentials. Every state therefore declares `AttestationAuthority/v3` with `assurance=local-integrity-only` and `same_user_adversary_resistant=false`. Codex explicit invocation records are locally audited capability claims, not host-signed people identities. Changed rounds instead rely on a core-observed workspace producer, core-executed registered gates, and an immutable-runner external CodeRabbit review bound to the exact diff. Requirements that explicitly demand host-signed liveness or lifecycle identity remain fail-closed and cannot be replaced by this local model.

Codex's supported thin-adapter flow lives under `~/.codex/skills/dev-supervisor/scripts/`: the native lifecycle entrypoint `codex-supervisor-hook.py`, plus `supervisor-bootstrap.ps1`, `supervisor-event.ps1`, `supervisor-record.ps1`, `supervisor-gate.ps1`, `supervisor-validate.ps1`, `supervisor-finalize.ps1`, `supervisor-handoff.ps1`, and `supervisor-turn-ended.ps1`. Deploy or copy that entrypoint set together with `supervisor-core.ps1`, the shared runtime dependency used by PowerShell wrappers, `supervisor-hook.ps1`, and `supervisor-process-job.py`. The native hook opens both bridge files with Windows read-only sharing (denying concurrent write/delete), verifies their exact length and SHA-256, keeps those handles locked until the child exits, and invokes the short `-File supervisor-hook.ps1` path; the hook therefore dot-sources a verified, locked core without exceeding the Windows command-line limit. A real PowerShell end-to-end test exercises the complete deployment set in a Unicode/space workspace on every shared-core selftest.

## Examples

```powershell
python -m supervisor_core start --runtime codex --workspace . --session $env:CODEX_THREAD_ID --round r1 --message "Audit routing" --change-mode replace --execution-mode warn --project-file .agent-supervisor/project.json
python -m supervisor_core event --runtime codex --workspace . --session $env:CODEX_THREAD_ID --round r1 --event-type invocation_result --invocation-id inv-1 --capability code-review --result success --actor reviewer
python -m supervisor_core validate --runtime codex --workspace . --session $env:CODEX_THREAD_ID --round r1 --project-file .agent-supervisor/project.json --json
python -m supervisor_core query --runtime codex --workspace . --session $env:CODEX_THREAD_ID --round r1 --format handoff
```

## Project documentation

- [Installation and activation](docs/INSTALL.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Maintainer release procedure](docs/RELEASING.md)
- [Changelog](CHANGELOG.md)
