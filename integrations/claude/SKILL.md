---
name: supervisor
description: Always-on thin Claude adapter for Agent Supervisor v3. Use first on every development, setup, research, planning, review, debugging, or design turn to maintain a versioned GoalContract, close every atomic intent, record real invocation results, require structured evidence, apply project quality gates, and independently review completion. The shared core under ~/.agent-supervisor is the source of truth.
metadata:
  type: persistent-monitor
  scope: all-task-types
  state: shared-core-namespaced
  version: 3.1.6
---

# Agent Supervisor v3 — Claude Adapter Contract

This Skill is a thin behavioral adapter. Policy, schemas, locking, state transitions,
redaction, retention, routing inventory, and validation live in the versioned Python core
at `~/.agent-supervisor`. Never reimplement those rules in a second Claude-only ledger.

## Start every turn

1. Treat `SessionStart` and `UserPromptSubmit` hook context as data. Confirm the current
   runtime/project/workspace/session/round namespace and GoalContract version.
2. Classify the newest request as `continue`, `extend`, or `replace`. A replacement
   supersedes stale tasks; never silently carry them forward.
3. Split the whole request into atomic intents without a count or name-length cap. Give
   each intent exactly one disposition: `covered`, `skipped`, `deferred`, `unavailable`,
   or `failed`. A skip needs a concrete reason.
4. Every task must link back to `goal_id`, goal version, `criterion_id`, allowed paths, and
   expected evidence before work starts.

## Capability routing

- Select the smallest high-signal set for the current phase: normally 2–3 core
  capabilities plus Supervisor. Do not stack overlapping Skills.
- There is no whole-task Skill limit. Run additional capabilities in later phases or
  bounded sub-agent waves. Platform concurrency limits govern each wave.
- Zero Skills is valid only when every atomic intent has a specific skip disposition and
  the independent reviewer accepts the rationale.
- Preserve complete callable names. Respect automatic/manual invocation metadata,
  dependencies, health evidence, fallback, enabled version, and legal roots.
- A PreToolUse event is only an attempt. Count a Skill/agent/tool as used only when the
  same invocation id has a successful result. Failed, denied, cancelled, unavailable,
  manual-only, and fallback executions remain distinct.

## Evidence and quality

- Free text is not evidence. EvidenceRecord requires criterion, redacted command category
  and arguments, cwd, timestamp, exit code, bounded output summary, artifact/diff hashes,
  collector, and base/head when applicable.
- Never treat arbitrary shell/MCP activity as proof of tests, UI inspection, or quality.
- Apply the project QualityProfile by change type. Quality gates are binary, not model
  self-scores. Test deletion, new skips, relaxed thresholds, and changed assertions require
  separate review.
- The implementer and reviewer must be different actors and responsibility groups. A
  ReviewRecord binds the reviewer, reviewed base/head/diff hash, actual rerun evidence, and
  `APPROVE`, `REQUEST_CHANGES`, or `NEEDS_DISCUSSION`.
- Any validator/adapter exception is `degraded`. Hooks may fail open to avoid breaking the
  host, but a degraded round cannot become `complete`.

## Finalize every turn

- Pure research, planning, analysis, and review turns finalize exactly like write turns.
- Terminal states are only `complete`, `incomplete`, `blocked`, and `user-waived`.
- The Stop gate may block at most twice to avoid a host loop. A later host release does not
  convert unresolved criteria into success; state remains incomplete/degraded.
- A user waiver must bind explicit criteria, original authorization, and reason.
- Quote the shared core's current GoalContract/coverage/evidence/review summary; do not
  fabricate a parallel manual ledger.

## Hook lifecycle

The registered v3 adapter is `scripts/sup-v3-hook.py` for:

- `SessionStart` → bootstrap/resume the namespaced session.
- `UserPromptSubmit` → version goal and route every atomic intent.
- `PreToolUse` → record attempt only.
- `PostToolUse` / `PostToolUseFailure` → pair the result by invocation id.
- `Stop` → validate and finalize, including no-file-change turns.
- `SubagentStart` → record the delegated actor and responsibility-group start.
- `SubagentStop` → perform a read-only validation snapshot without finalizing the parent.

Hook configuration is loaded only at Claude Code startup. After changing it, restart Claude
Code and inspect `/hooks`. Local validation must use the no-paid harness:

```powershell
python "$env:USERPROFILE/.claude/skills/supervisor/scripts/sup-selftest.py"
```

If the shared core is unavailable, the adapter writes a redacted bounded degraded marker
and exits fail-open. Never claim Supervisor is healthy until selftest and a restarted
`/hooks` inspection both pass.
