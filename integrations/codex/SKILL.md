---
name: dev-supervisor
description: Always-on Supervisor v3 adapter for goal alignment, capability routing, evidence capture, quality gates, independent review, and auditable finalization across Codex and Claude.
---

# Dev Supervisor v3

This skill is the Codex adapter for the runtime-neutral core at
`%USERPROFILE%/.agent-supervisor/supervisor_core`. The core state is authoritative;
`.codex-supervisor/` is legacy input only after migration.

## Mandatory round protocol

1. Classify domain, size, and action risk in one line.
2. Run `scripts/supervisor-bootstrap.ps1` before task work. Pass the newest request,
   `continue|extend|replace`, and the current `CODEX_THREAD_ID`. In Plan mode use
   `-Shadow`; this records a read-only intent without authorizing implementation.
3. Read the emitted GoalContract, project contract, handoff, active task,
   `discovery`, and `capability_route`. A normal bootstrap must contain a persisted
   inventory hash and a valid route; a shadow bootstrap may return the same data
   without persisting it. Missing or degraded discovery/routing is a gate failure,
   not permission to continue silently. Choose exactly one next task.
4. Register atomic intents and acceptance criteria before non-trivial implementation.
5. Route the smallest high-signal set for the current phase: supervisor plus 2-3
   non-overlapping core capabilities. There is no total skill limit across later
   phases or bounded sub-agent waves. Use as many phases as the atomic intents need,
   while never invoking an irrelevant capability merely to increase the count.
   Manual-only and unavailable capabilities are never auto-dispatched. Every intent
   must end as covered, skipped with a concrete reason, deferred, unavailable, or
   failed. Zero skills is valid only when every intent has a reviewed skip reason.
6. For each selected capability, open and follow its exact canonical `SKILL.md`
   before the phase action. Execute the route in phase/dependency order, give every
   relevant capability its bounded owned contribution, and record attempt/result
   pairs with the same invocation id. Only a correlated `success` is actual use; an
   attempt, failure, cancellation, refusal, fallback, or manual-only capability is
   not a success. A fallback receives its own invocation identity and never counts as
   success for the original capability. In Codex, this is a locally audited capability
   contribution only; it cannot establish implementer, reviewer, or gate-runner
   identity.
7. Before T2 writes, preserve a reversible checkpoint. T3 actions require explicit
   human approval and a rollback. Never broaden authorization from a capability match.
8. Run each registered binary gate through `supervisor-gate.ps1`, supplying only its
   `GateId`, bound `CriterionId`, and optional `EvidenceId`. The shared core owns the
   collector identity, issues a single-use grant, executes the exact QualityProfile
   argv under a fixed timeout, and signs the `GateExecution` and EvidenceRecord.
   Caller-selected actor/group/invocation/timeout/command fields, caller-made evidence,
   free text, unrelated/failed/stale output, and claimed screenshots are not evidence.
9. Apply the project QualityProfile. Changed domains add their specific binary gates;
   generic green tests do not substitute for UI/API/DB/config/research gates.
10. After implementation and focused verification, run code-review-graph when healthy
    (manual impact review if degraded), then the registered immutable-core CodeRabbit
    gate. The core accepts only a strictly validated, exact-diff external artifact and
    issues the signed automated ReviewRecord itself. If tests changed, run the separate
    `review.coderabbit.test-integrity` gate as well; a general review cannot substitute.
    Manual Codex reviewer/sub-agent records remain audit-only without host identity.
    Claude host-observed review finalization remains available where the host supplies
    that identity primitive.
11. Run `supervisor-finalize.ps1` for every round, including research/planning and
    no-file-change rounds. Only `complete`, `incomplete`, `blocked`, and `user-waived`
    are terminal. Retry limits never convert unresolved work into success.

## State and context

State is namespaced by runtime/project/workspace/session/round. The core owns locks,
monotonic event sequence, atomic replacement, redaction, retention, and handoff
rendering. Run `supervisor-handoff.ps1` before a risky edit, phase transition,
sub-agent spawn, or intentional compaction. Do not hand-edit generated state.

## Codex host integration and limits

Codex project hooks are configured through `.codex/hooks.json`. After the user trusts
the workspace and reloads/starts a fresh session, this adapter covers the 11 supported
lifecycle events: SessionStart, UserPromptSubmit, PreToolUse, PermissionRequest,
PostToolUse, PreCompact, PostCompact, SubagentStart, SubagentStop, Stop, and SessionEnd.
PreToolUse can deny an unsafe action and Stop can request continuation, but activation
must not be claimed until `/hooks` shows the project configuration and a fresh-session
probe reaches the adapter. Hosted WebSearch and host-special tools that opt out of
hooks remain coverage limitations; record them as degraded instead of inventing an
event or a hard block.

## Commands

```powershell
scripts/supervisor-bootstrap.ps1 -Workspace $PWD -Message '<request>' -ChangeMode extend -SessionId '<thread-id>'
scripts/supervisor-record.ps1 -Workspace $PWD -RoundId '<id>' -RecordType task -RecordFile .agent-supervisor/task-record.json
scripts/supervisor-event.ps1 -Workspace $PWD -RoundId '<id>' -Event invocation_attempt -InvocationId '<id>' -Skill '<full-name>' -Actor '<actor>' -ResponsibilityGroup '<group>'
scripts/supervisor-event.ps1 -Workspace $PWD -RoundId '<id>' -Event invocation_result -InvocationId '<id>' -Skill '<full-name>' -Actor '<actor>' -ResponsibilityGroup '<same-group>' -Result success
scripts/supervisor-gate.ps1 -Workspace $PWD -RoundId '<id>' -GateId common.lint -CriterionId '<criterion-id>' -EvidenceId '<evidence-id>'
scripts/supervisor-gate.ps1 -Workspace $PWD -RoundId '<id>' -GateId review.coderabbit -CriterionId '<criterion-id>' -EvidenceId '<review-evidence-id>'
scripts/supervisor-gate.ps1 -Workspace $PWD -RoundId '<id>' -GateId review.coderabbit.test-integrity -CriterionId '<criterion-id>' -EvidenceId '<test-review-evidence-id>'
scripts/supervisor-record.ps1 -Workspace $PWD -RoundId '<id>' -RecordType review-finalize -RecordFile .agent-supervisor/review-finalize.json -Actor '<reviewer>'
scripts/supervisor-validate.ps1 -Workspace $PWD -RoundId '<id>' -Json
scripts/supervisor-handoff.ps1 -Workspace $PWD -RoundId '<id>' -Reason phase-transition
scripts/supervisor-finalize.ps1 -Workspace $PWD -RoundId '<id>'
```

Exit codes are stable: `0 complete`, `2 incomplete`, `3 blocked`, `4 degraded`,
`64 invalid-state`.

## Required final report

Report goal/version and intent coverage; spec/contract; capabilities and actual
successful invocations; evidence gates; independent review verdict; unresolved
findings/waivers; context preservation; guardrail tier; degraded fallbacks; exact
verification commands/results; and the final core state. Do not report `complete`
when the core returns another state.
