# Agent Supervisor v3

Runtime-neutral goal and quality supervision for Claude Code and Codex. The shared core owns contracts, isolated state, evidence validation, capability discovery/routing, lifecycle finalization, and migration. Host integrations are deliberately thin adapters.

## Stable entry points

From this directory:

```powershell
python -m supervisor_core --version
python -m supervisor_core selftest
```

From any directory, use the self-bootstrapping script:

```powershell
python "$env:USERPROFILE\.agent-supervisor\bin\agent-supervisor.py" --version
```

An editable install (`python -m pip install -e "$env:USERPROFILE\.agent-supervisor"`) also makes `python -m supervisor_core` and `agent-supervisor` available from arbitrary working directories. Adapters may instead prepend this directory to `PYTHONPATH` without installation.

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

Routing accepts host-provided atomic intents. It limits one phase to 2–3 high-signal capabilities but has no total capability, clause, candidate, or name-length limit. A zero-skill route is valid only when every intent has a concrete skipped reason and an approving routing review.

## Rollout, breaker, and rollback

Projects select `observe`, `warn`, or `enforce` in `.agent-supervisor/project.json`. Recommended promotion:

1. `observe`: replay deterministic fixtures and historical logs.
2. `warn`: run real rounds while measuring critical misses and false blocks.
3. `enforce`: enable per project only after zero critical misses and at most 2% false blocks. Other projects remain in `warn` until 20 non-trivial rounds meet the same bar.

Two consecutive failures open that capability's breaker and retain its configured `fallback_id`. Two global gate failures atomically swap `active-version.json` to the previous side-by-side release when that release exists; all thin adapters resolve the pointer before loading the core. The first v3 release deliberately has no fabricated rollback target, so it degrades with `previous-version-unavailable` until a later release registers a real predecessor. State and migrated legacy snapshots are append-only and are not deleted.

Registered command gates must be executed through the core's `gate_run` event (or the Codex `supervisor-gate.ps1` wrapper). The core executes the exact argv from the active `QualityProfile`, captures bounded/redacted output, hashes it, and signs a `GateExecution/v3` attestation. Caller-authored exit codes, free-form evidence, or a manually injected `gate_execution` event cannot satisfy completion.

Codex's supported thin-adapter flow lives under `~/.codex/skills/dev-supervisor/scripts/`: `supervisor-bootstrap.ps1`, `supervisor-record.ps1`, `supervisor-gate.ps1`, `supervisor-validate.ps1`, and `supervisor-finalize.ps1`. A real PowerShell end-to-end test exercises those wrappers in a Unicode/space workspace on every shared-core selftest.

## Examples

```powershell
python -m supervisor_core start --runtime codex --workspace . --session $env:CODEX_THREAD_ID --round r1 --message "Audit routing" --change-mode replace --execution-mode warn --project-file .agent-supervisor/project.json
python -m supervisor_core event --runtime codex --workspace . --session $env:CODEX_THREAD_ID --round r1 --event-type invocation_result --invocation-id inv-1 --capability code-review --result success --actor reviewer
python -m supervisor_core validate --runtime codex --workspace . --session $env:CODEX_THREAD_ID --round r1 --project-file .agent-supervisor/project.json --json
python -m supervisor_core query --runtime codex --workspace . --session $env:CODEX_THREAD_ID --round r1 --format handoff --output handoff.md
```
