# Supervisor v3 sub-agent contracts

Delegation is bounded and auditable. The parent remains responsible for integration,
verification, and finalization. Record a handoff before spawning.

Every assignment must include:

- `role`: explorer, worker, or reviewer;
- `actor_id` and `responsibility_group`;
- `goal_id`, `goal_version`, task id, and criterion ids;
- exact `OWNS` paths and `MUST_NOT_TOUCH` paths;
- a non-overlapping path lease for workers;
- expected evidence types and a return cap of 2,000 tokens;
- the warning that other agents share the filesystem and their edits must not be
  reverted.

## Filesystem and shell safety

- Use `apply_patch` for every source, test, documentation, and configuration edit.
  Shell redirection, `Set-Content`, `Out-File`, and ad-hoc script writes are forbidden.
- Never assign to or repurpose `$HOME`, `$home`, `$CODEX_HOME`, or another standard
  system variable. Use a task-specific variable name when a local value is needed.
- Before each write, resolve the exact absolute target and verify that it is inside
  the assigned lease. An empty, unresolved, or out-of-lease target stops the task.
- If any prerequisite, variable assignment, path check, hash check, or initialization
  command fails, stop all dependent commands immediately and report the failure. Do
  not continue with an earlier, default, or partially resolved target.
- Read-only agents must not run any command with a write side effect, including test
  helpers that create fixtures outside a unique task-scoped temporary directory.

## Explorer

Read-only. Return JSON with `answer`, `key_files`, `call_path`, `gotchas`,
`confidence`, and `unknowns`. It must not edit files or claim runtime evidence it did
not collect.

## Worker

Writes only leased paths. Return `status`, `changed_paths`, `acceptance_results`,
`evidence_ids`, `command_summaries`, `failure_summaries`, `blockers`, `risks`, and
`notes`. Every item in `command_summaries` is structured and redacted and includes
`exit_code`, `evidence_record_id`, `artifact_sha256`, `output_sha256`, and a concise
result summary. Failed commands and blocked work must appear in `failure_summaries`
and `blockers`; they are not omitted because a later command passed.

Never return raw stdout/stderr or full command parameters. Full internal evidence
remains in the Supervisor-controlled store and is shared only by
`evidence_record_id` and integrity hashes. The parent compares changed paths to the
lease and records the base/head/diff hash. Out-of-scope changes are an automatic
`REQUEST_CHANGES`.

## Reviewer

Read-only and from a different responsibility group than the implementer. Return a
ReviewRecord containing `review_id`, `actor_id`, `responsibility_group`,
`implementer_group`, `goal_id`, criterion ids, `base`, `head`, `diff_hash`,
`rerun_evidence_ids`, findings, and exactly one verdict:
`APPROVE`, `REQUEST_CHANGES`, or `NEEDS_DISCUSSION`.

Reviewer evidence must be collected by the reviewer. Reviewing prose, reusing only
the implementer's output, or omitting the diff identity cannot approve the task.
The ReviewRecord also returns redacted `command_summaries`, `failure_summaries`, and
`blockers`. Every rerun summary includes `exit_code`, `evidence_record_id`,
`artifact_sha256`, `output_sha256`, and a concise result summary. Never return raw
stdout/stderr or full command parameters. Full internal evidence stays in the
Supervisor-controlled store and is exposed only through its `evidence_record_id`
and integrity hashes.

## Scheduling

Respect the platform concurrency ceiling. If a method describes more parallel agents
than available slots, run non-overlapping waves. An implementer and reviewer must
never be the same responsibility group.
