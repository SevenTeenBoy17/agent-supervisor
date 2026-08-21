from __future__ import annotations

import fnmatch
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .constants import CHANGE_MODES, INTENT_STATES, REVIEW_VERDICTS
from .attestation import verify_record
from .contracts import validate_review_shape
from .util import canonical_sha256, parse_time, sha256_text, utc_now
from .workspace import capture_workspace_snapshot, workspace_delta

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PLACEHOLDER = re.compile(r"(?i)\b(?:tbd|todo|fixme|placeholder|trust\s+me|稍后|待定|未解决)\b")


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _nonempty_string_list(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(_nonempty_string(item) for item in value)


def _valid_hash(value: Any) -> bool:
    return isinstance(value, str) and bool(_SHA256.fullmatch(value))


def _path_allowed(path: str, allowed: list[str]) -> bool:
    normalized = path.replace("\\", "/").lstrip("./")
    for pattern in allowed:
        candidate = pattern.replace("\\", "/").lstrip("./")
        if candidate.endswith("/**") and normalized.startswith(candidate[:-3].rstrip("/") + "/"):
            return True
        if normalized == candidate or fnmatch.fnmatch(normalized, candidate):
            return True
    return False


def _pattern_within(child: str, parent: str) -> bool:
    child_norm = child.replace("\\", "/").lstrip("./")
    parent_norm = parent.replace("\\", "/").lstrip("./")
    if child_norm in {"", "*", "**"} or child_norm.startswith("../"):
        return False
    if parent_norm.endswith("/**"):
        prefix = parent_norm[:-3].rstrip("/")
        return child_norm == prefix or child_norm.startswith(prefix + "/")
    if any(token in parent_norm for token in ("*", "?", "[")):
        return fnmatch.fnmatch(child_norm, parent_norm)
    return child_norm == parent_norm


def successful_invocations(events: list[dict[str, Any]]) -> tuple[set[str], dict[str, dict[str, Any]], list[str]]:
    attempts: dict[str, dict[str, Any]] = {}
    results: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        event_type = event.get("event_type")
        invocation_id = event.get("invocation_id")
        if event_type == "invocation_attempt" and _nonempty_string(invocation_id):
            attempts[str(invocation_id)] = event
        elif event_type == "invocation_result" and _nonempty_string(invocation_id):
            if str(invocation_id) in results:
                errors.append(f"invocation {invocation_id} has duplicate results")
            results[str(invocation_id)] = event
    successful: set[str] = set()
    for invocation_id, result in results.items():
        if invocation_id not in attempts:
            errors.append(f"invocation {invocation_id} has result without correlated attempt")
            continue
        attempt = attempts[invocation_id]
        attempt_capability = str(attempt.get("capability") or "")
        result_capability = str(result.get("capability") or "")
        if not attempt_capability or result_capability != attempt_capability:
            errors.append(f"invocation {invocation_id} capability changed between attempt and result")
            continue
        attempt_actor = str(attempt.get("actor") or "")
        result_actor = str(result.get("actor") or "")
        if not attempt_actor or result_actor != attempt_actor:
            errors.append(f"invocation {invocation_id} actor changed between attempt and result")
            continue
        if result.get("result") == "success":
            successful.add(attempt_capability)
    return successful, results, errors


def _validate_goal(state: dict[str, Any], errors: list[str]) -> None:
    goal = state.get("goal")
    if not isinstance(goal, dict) or not goal:
        errors.append("GoalContract missing or empty")
        return
    required = (
        "goal_id", "version", "original_request_sha256", "change_mode", "objective",
        "acceptance_criteria", "scope", "constraints", "non_goals", "assumptions", "risks",
    )
    if goal.get("contract") != "GoalContract/v3":
        errors.append("GoalContract version invalid")
    for key in required:
        if key not in goal:
            errors.append(f"GoalContract missing {key}")
    if goal.get("change_mode") not in CHANGE_MODES:
        errors.append("GoalContract change_mode invalid")
    if not _nonempty_string(goal.get("goal_id")) or not isinstance(goal.get("version"), int):
        errors.append("GoalContract identity invalid")
    if not _valid_hash(goal.get("original_request_sha256")):
        errors.append("GoalContract original request hash invalid")
    if not _nonempty_string(goal.get("objective")) or _PLACEHOLDER.search(str(goal.get("objective", ""))):
        errors.append("GoalContract objective empty or unresolved")
    for field in ("constraints", "non_goals", "assumptions", "risks"):
        if not isinstance(goal.get(field), list) or not all(_nonempty_string(item) for item in goal.get(field, [])):
            errors.append(f"GoalContract {field} must be a string array")
    criteria = goal.get("acceptance_criteria")
    if not isinstance(criteria, list) or not criteria:
        errors.append("GoalContract acceptance criteria empty")
        return
    seen: set[str] = set()
    for index, criterion in enumerate(criteria):
        if not isinstance(criterion, dict) or not criterion:
            errors.append(f"criterion[{index}] must be a non-empty object")
            continue
        criterion_id = criterion.get("criterion_id")
        if not _nonempty_string(criterion_id) or criterion_id in seen:
            errors.append(f"criterion[{index}] id missing or duplicate")
        seen.add(str(criterion_id))
        if not _nonempty_string(criterion.get("description")) or _PLACEHOLDER.search(str(criterion.get("description", ""))):
            errors.append(f"criterion {criterion_id} description empty or unresolved")
        if not _nonempty_string_list(criterion.get("expected_evidence")):
            errors.append(f"criterion {criterion_id} expected evidence empty")


def _validate_spec(state: dict[str, Any], errors: list[str]) -> None:
    spec = state.get("spec")
    if not isinstance(spec, dict) or not spec:
        errors.append("spec record missing")
        return
    if spec.get("status") not in {"approved", "resolved", "spec-light"}:
        errors.append("spec unresolved")
    content = str(spec.get("content", ""))
    if content and _PLACEHOLDER.search(content):
        errors.append("spec contains unresolved placeholder")
    if spec.get("path") and not _valid_hash(spec.get("hash")):
        errors.append("spec artifact hash invalid")


def _validate_tasks(state: dict[str, Any], criterion_ids: set[str], evidence: dict[str, dict[str, Any]], errors: list[str]) -> None:
    tasks = state.get("tasks")
    if not isinstance(tasks, list):
        errors.append("tasks must be an array")
        return
    goal = state.get("goal", {})
    criterion_expected = {
        str(row.get("criterion_id")): set(_string_values(row.get("expected_evidence")))
        for row in goal.get("acceptance_criteria", [])
        if isinstance(row, dict) and row.get("criterion_id")
    }
    goal_scope = goal.get("scope", {}) if isinstance(goal.get("scope"), dict) else {}
    goal_allowed = _string_values(goal_scope.get("in"))
    policy = state.get("project_policy", {}) if isinstance(state.get("project_policy"), dict) else {}
    project_allowed = _string_values(policy.get("allowed_change_globs"))
    project_denied = _string_values(policy.get("out_of_scope_globs"))
    for index, task in enumerate(tasks):
        if not isinstance(task, dict) or not task:
            errors.append(f"task[{index}] must be a non-empty object")
            continue
        if task.get("goal_id") != goal.get("goal_id") or task.get("goal_version") != goal.get("version"):
            errors.append(f"task {task.get('task_id', index)} not linked to current goal version")
        links = task.get("criterion_ids")
        if not _nonempty_string_list(links) or not set(links).issubset(criterion_ids):
            errors.append(f"task {task.get('task_id', index)} criterion links invalid")
        task_paths = task.get("allowed_paths")
        if not _nonempty_string_list(task_paths):
            errors.append(f"task {task.get('task_id', index)} allowed paths empty")
        else:
            for allowed_path in task_paths:
                if not any(_pattern_within(allowed_path, parent) for parent in goal_allowed):
                    errors.append(f"task {task.get('task_id', index)} path exceeds GoalContract scope: {allowed_path}")
                is_absolute = bool(re.match(r"^[A-Za-z]:[/\\]", allowed_path)) or allowed_path.startswith("/")
                if not is_absolute and project_allowed and not any(_pattern_within(allowed_path, parent) for parent in project_allowed):
                    errors.append(f"task {task.get('task_id', index)} path exceeds project policy: {allowed_path}")
                if any(_pattern_within(allowed_path, denied) or _pattern_within(denied, allowed_path) for denied in project_denied):
                    errors.append(f"task {task.get('task_id', index)} path overlaps project out-of-scope policy: {allowed_path}")
        if not _nonempty_string_list(task.get("expected_evidence")):
            errors.append(f"task {task.get('task_id', index)} expected evidence empty")
        else:
            linked_expected = set().union(*(criterion_expected.get(str(link), set()) for link in links or []))
            if not linked_expected.issubset(set(task.get("expected_evidence", []))):
                errors.append(f"task {task.get('task_id', index)} expected evidence does not cover linked criteria")
        if task.get("status") == "done":
            refs = task.get("evidence_ids")
            if not _nonempty_string_list(refs) or not set(refs).issubset(evidence):
                errors.append(f"done task {task.get('task_id', index)} lacks valid evidence")
            else:
                linked_expected = set().union(*(criterion_expected.get(str(link), set()) for link in links or []))
                referenced_labels = {str(evidence[ref].get("gate_id")) for ref in refs}
                if not linked_expected.issubset(referenced_labels):
                    errors.append(f"done task {task.get('task_id', index)} lacks its declared evidence types")
        elif task.get("status") not in {"superseded", "cancelled"}:
            errors.append(f"task {task.get('task_id', index)} is not done")


def _validate_evidence(state: dict[str, Any], criterion_ids: set[str], events: list[dict[str, Any]], errors: list[str]) -> tuple[set[str], dict[str, dict[str, Any]], dict[str, set[str]]]:
    evidence = state.get("evidence")
    if not isinstance(evidence, list):
        errors.append("evidence must be an array")
        return set(), {}, {}
    goal = state.get("goal", {})
    started = parse_time(state.get("started_at", utc_now()))
    ids: set[str] = set()
    by_id: dict[str, dict[str, Any]] = {}
    satisfied_labels: dict[str, set[str]] = {}
    gate_commands = _registered_gate_commands(state.get("quality_profile", {}))
    executions = {
        str(event.get("execution_id")): event
        for event in events
        if isinstance(event, dict) and event.get("event_type") == "gate_execution" and event.get("execution_id")
    }
    for index, record in enumerate(evidence):
        if not isinstance(record, dict) or not record:
            errors.append(f"evidence[{index}] must be a non-empty structured object; free text is invalid")
            continue
        if record.get("contract") != "EvidenceRecord/v3":
            errors.append(f"evidence[{index}] contract version invalid")
        evidence_id = record.get("evidence_id")
        if not _nonempty_string(evidence_id) or evidence_id in ids:
            errors.append(f"evidence[{index}] id missing or duplicate")
            continue
        evidence_id = str(evidence_id)
        ids.add(evidence_id)
        by_id[evidence_id] = record
        if state.get("runtime") != "test":
            execution = executions.get(str(record.get("execution_id") or ""))
            if not isinstance(execution, dict) or not verify_record(execution):
                errors.append(f"evidence {evidence_id} lacks trusted core execution attestation")
            else:
                bindings = {
                    "evidence_id": evidence_id,
                    "execution_id": record.get("execution_id"),
                    "gate_id": record.get("gate_id"),
                    "criterion_id": record.get("criterion_id"),
                    "goal_id": record.get("goal_id"),
                    "goal_version": record.get("goal_version"),
                    "exit_code": record.get("exit_code"),
                    "cwd": record.get("cwd"),
                    "collected_at": record.get("collected_at"),
                    "base": record.get("base"),
                    "head": record.get("head"),
                    "diff_hash": record.get("diff_hash"),
                    "collector": record.get("collector"),
                    "collector_responsibility_group": record.get("collector_responsibility_group"),
                    "output_sha256": record.get("output_sha256"),
                    "artifact_hash": record.get("artifact_hash"),
                }
                if any(execution.get(key) != value for key, value in bindings.items()):
                    errors.append(f"evidence {evidence_id} does not match trusted core execution")
                if execution.get("artifact_hash") != execution.get("output_sha256"):
                    errors.append(f"evidence {evidence_id} artifact is not bound to the complete gate output")
                if execution.get("output_summary") != record.get("output_summary"):
                    errors.append(f"evidence {evidence_id} output summary was rewritten after execution")
                if execution.get("state_started_at") != state.get("started_at"):
                    errors.append(f"evidence {evidence_id} was signed for a different round start")
                if execution.get("workspace_snapshot_hash") != state.get("workspace_baseline", {}).get("snapshot_hash"):
                    errors.append(f"evidence {evidence_id} was signed for a different workspace baseline")
        criterion_id = record.get("criterion_id")
        if criterion_id not in criterion_ids:
            errors.append(f"evidence {evidence_id} criterion link invalid")
        command = record.get("command")
        if not isinstance(command, dict) or not command or not _nonempty_string(command.get("category")) or not _nonempty_string_list(command.get("args")):
            errors.append(f"evidence {evidence_id} command category/args invalid")
        if not _nonempty_string(record.get("cwd")):
            errors.append(f"evidence {evidence_id} cwd missing")
        try:
            collected = parse_time(str(record.get("collected_at", "")))
            if collected < started:
                errors.append(f"evidence {evidence_id} is stale for this round")
        except (TypeError, ValueError):
            errors.append(f"evidence {evidence_id} timestamp invalid")
        if record.get("exit_code") != 0:
            errors.append(f"evidence {evidence_id} command failed")
        summary = record.get("output_summary")
        if not _nonempty_string(summary) or _PLACEHOLDER.search(str(summary)):
            errors.append(f"evidence {evidence_id} output summary empty/untrusted")
        if not _valid_hash(record.get("artifact_hash")):
            errors.append(f"evidence {evidence_id} artifact hash invalid")
        if not _valid_hash(record.get("output_sha256")):
            errors.append(f"evidence {evidence_id} output hash invalid")
        elif record.get("artifact_hash") != record.get("output_sha256"):
            errors.append(f"evidence {evidence_id} artifact hash does not match complete gate output")
        for binding_hash in ("base", "head", "diff_hash"):
            if not _valid_hash(record.get(binding_hash)):
                errors.append(f"evidence {evidence_id} {binding_hash} invalid")
        if not _nonempty_string(record.get("collector")) or not _nonempty_string(record.get("collector_responsibility_group")):
            errors.append(f"evidence {evidence_id} collector identity/group missing")
        if not _nonempty_string(record.get("gate_id")) or record.get("relevant") is not True:
            errors.append(f"evidence {evidence_id} unrelated to a registered gate")
        elif record.get("gate_id") not in gate_commands:
            errors.append(f"evidence {evidence_id} gate is not registered in QualityProfile")
        elif isinstance(command, dict) and command.get("args") != gate_commands.get(str(record.get("gate_id"))):
            errors.append(f"evidence {evidence_id} command does not match registered gate")
        if record.get("goal_id") != goal.get("goal_id") or record.get("goal_version") != goal.get("version"):
            errors.append(f"evidence {evidence_id} belongs to a different goal version")
        changes = state.get("changes", {})
        if changes.get("diff_hash"):
            if record.get("base") != changes.get("base") or record.get("head") != changes.get("head") or record.get("diff_hash") != changes.get("diff_hash"):
                errors.append(f"evidence {evidence_id} is not bound to the reviewed diff")
        if not any(message.startswith(f"evidence {evidence_id}") for message in errors):
            satisfied_labels.setdefault(str(criterion_id), set()).add(str(record.get("gate_id")))
    return ids, by_id, satisfied_labels


def _validate_intents(
    state: dict[str, Any],
    events: list[dict[str, Any]],
    evidence: dict[str, dict[str, Any]],
    errors: list[str],
) -> None:
    intents = state.get("intents")
    if not isinstance(intents, list) or not intents:
        errors.append("IntentCoverage is empty")
        intents = []
    success_caps, _, invocation_errors = successful_invocations(events)
    errors.extend(invocation_errors)
    manifest = state.get("intent_manifest")
    if not isinstance(manifest, list) or not manifest:
        errors.append("atomic intent manifest missing")
        manifest = []
    expected_manifest = [
        {
            "intent_id": str(intent.get("intent_id") or ""),
            "text_sha256": sha256_text(str(intent.get("text") or "")),
            "domain": str(intent.get("domain") or "general"),
        }
        for intent in intents
        if isinstance(intent, dict)
    ]
    signed_manifest = state.get("request_manifest")
    goal = state.get("goal", {}) if isinstance(state.get("goal"), dict) else {}
    if (
        not isinstance(signed_manifest, dict)
        or signed_manifest.get("contract") != "RequestManifest/v3"
        or not verify_record(signed_manifest)
    ):
        errors.append("atomic request manifest lacks trusted core attestation")
    else:
        bindings = {
            "goal_id": goal.get("goal_id"),
            "goal_version": goal.get("version"),
            "goal_sha256": canonical_sha256(goal),
            "original_request_sha256": goal.get("original_request_sha256"),
            "intents": expected_manifest,
            "runtime": state.get("runtime"),
            "workspace": str(Path(str(state.get("workspace") or "")).resolve()),
            "session": state.get("session"),
            "round": state.get("round"),
        }
        if any(signed_manifest.get(key) != value for key, value in bindings.items()):
            errors.append("GoalContract or atomic intent manifest changed after trusted start")
    if manifest != expected_manifest:
        errors.append("IntentCoverage does not match the immutable atomic request manifest")
    seen_intents: set[str] = set()
    all_skipped = True
    for index, intent in enumerate(intents):
        if not isinstance(intent, dict) or not intent:
            errors.append(f"intent[{index}] must be a non-empty object")
            continue
        if intent.get("contract") != "IntentCoverage/v3":
            errors.append(f"intent {intent.get('intent_id', index)} contract version invalid")
        intent_id = intent.get("intent_id")
        if not _nonempty_string(intent_id) or intent_id in seen_intents:
            errors.append(f"intent[{index}] id missing or duplicate")
        seen_intents.add(str(intent_id))
        if not _nonempty_string(intent.get("text")):
            errors.append(f"intent {intent_id or index} text missing")
        if not _nonempty_string(intent.get("reason")):
            errors.append(f"intent {intent_id or index} reason missing")
        status = intent.get("status")
        if status not in INTENT_STATES:
            errors.append(f"intent {intent.get('intent_id', index)} disposition invalid")
        if status != "skipped":
            all_skipped = False
        if status == "covered":
            capabilities = intent.get("capability_ids")
            if intent.get("method") == "manual-specialized":
                if not _nonempty_string(intent.get("reason")):
                    errors.append(f"intent {intent.get('intent_id', index)} manual result lacks reason")
            elif not _nonempty_string_list(capabilities) or not set(capabilities).intersection(success_caps):
                errors.append(f"intent {intent.get('intent_id', index)} has no successful correlated invocation")
        elif status == "skipped":
            if not _nonempty_string(intent.get("reason")) or intent.get("reason") == "awaiting routing":
                errors.append(f"intent {intent.get('intent_id', index)} skipped without concrete reason")
        else:
            errors.append(f"intent {intent.get('intent_id', index)} unresolved with status {status}")
    if all_skipped:
        approved = False
        for review in state.get("reviews", []):
            if not (
                isinstance(review, dict)
                and review.get("category") == "zero-skill-routing"
                and review.get("verdict") == "APPROVE"
                and validate_review_shape(review)
            ):
                continue
            rerun_ids = review.get("rerun_evidence_ids", [])
            if not set(rerun_ids).issubset(evidence):
                continue
            if all(
                evidence[evidence_id].get("collector") == review.get("reviewer")
                and evidence[evidence_id].get("collector_responsibility_group") == review.get("responsibility_group")
                for evidence_id in rerun_ids
            ):
                approved = True
                break
        if not approved:
            errors.append("zero-skill round lacks approving routing review")


def _observe_workspace(state: dict[str, Any], errors: list[str]) -> dict[str, Any] | None:
    baseline = state.get("workspace_baseline")
    if not isinstance(baseline, dict) or baseline.get("contract") != "WorkspaceSnapshot/v3":
        if state.get("runtime") != "test":
            errors.append("trusted workspace baseline missing")
        return None
    if baseline.get("git") is not True:
        if state.get("runtime") != "test":
            errors.append("git workspace unavailable; manual scope review required")
        return None
    current = capture_workspace_snapshot(str(state.get("workspace") or ""), _string_values(baseline.get("extra_globs")))
    if current.get("git") is not True:
        errors.append("workspace git state unavailable during validation")
        return None
    return workspace_delta(baseline, current)


def _is_test_path(path: str) -> bool:
    normalized = path.replace("\\", "/").casefold()
    name = normalized.rsplit("/", 1)[-1]
    return (
        normalized.startswith("tests/")
        or "/tests/" in normalized
        or "/__tests__/" in normalized
        or any(marker in name for marker in (".test.", ".spec.", "test_"))
    )


def _domains_from_observed(profile: dict[str, Any], files: list[str]) -> set[str]:
    domains: set[str] = set()
    aliases = {"api_db": "api/db", "config_agent": "config/agent"}
    profiles = profile.get("profiles", {}) if isinstance(profile, dict) else {}
    if isinstance(profiles, dict):
        for profile_id, row in profiles.items():
            if not isinstance(row, dict):
                continue
            patterns = _string_values(row.get("applies_to"))
            if patterns and any(_path_allowed(path, patterns) for path in files):
                domains.add(aliases.get(str(profile_id), str(profile_id).replace("_", "/")))
    for path in files:
        normalized = path.replace("\\", "/").casefold()
        if normalized.endswith((".tsx", ".css")) or normalized.startswith("src/components/"):
            domains.add("ui")
        if normalized.startswith(("src/app/api/", "src/lib/db/", "drizzle/")):
            domains.add("api/db")
        if normalized.startswith((".agent-supervisor/", ".claude/", ".codex/")) or normalized in {"agents.md"} or normalized.startswith("skills/dev-supervisor/"):
            domains.add("config/agent")
        if normalized.startswith(("src/", "tests/", "scripts/")):
            domains.add("code")
    return domains


def _validate_changes_and_reviews(
    state: dict[str, Any],
    evidence: dict[str, dict[str, Any]],
    events: list[dict[str, Any]],
    errors: list[str],
    warnings: list[str],
    observed: dict[str, Any] | None,
) -> None:
    changes = state.get("changes")
    if not isinstance(changes, dict):
        errors.append("changes record missing")
        return
    files = changes.get("files", [])
    if not isinstance(files, list):
        errors.append("changes.files must be an array")
        files = []
    if observed is not None:
        observed_files = {str(path) for path in observed.get("files", [])}
        declared_files = {str(path).replace("\\", "/") for path in files}
        for path in sorted(observed_files - declared_files):
            errors.append(f"real workspace diff omitted from changes record: {path}")
        for path in sorted(declared_files - observed_files):
            errors.append(f"changes record claims path absent from observed workspace diff: {path}")
        for field in ("base", "head", "diff_hash"):
            if changes.get(field) != observed.get(field):
                errors.append(f"changes.{field} does not match core-observed workspace delta")
    allowed = []
    for task in state.get("tasks", []):
        if isinstance(task, dict) and task.get("status") == "done":
            allowed.extend([p for p in task.get("allowed_paths", []) if _nonempty_string(p)])
    for path in files:
        if not _nonempty_string(path) or not _path_allowed(str(path), allowed):
            errors.append(f"out-of-scope diff: {path}")
    if files:
        review_policy = state.get("quality_profile", {}).get("review", {})
        required_bindings = set(review_policy.get("record_must_bind", [])) if isinstance(review_policy, dict) else set()
        require_invocations = {"implementer_invocation_id", "reviewer_invocation_id"}.issubset(required_bindings)
        _, invocation_results, invocation_errors = successful_invocations(events)
        errors.extend(invocation_errors)
        for field in ("base", "head", "diff_hash", "implementer", "implementer_responsibility_group"):
            if not _nonempty_string(changes.get(field)):
                errors.append(f"changes.{field} missing")
        implementer_invocation = str(changes.get("implementer_invocation_id") or "")
        if require_invocations:
            result = invocation_results.get(implementer_invocation)
            if not implementer_invocation or not isinstance(result, dict) or result.get("result") != "success" or result.get("actor") != changes.get("implementer"):
                errors.append("changes implementer identity lacks a successful correlated invocation")
        if changes.get("diff") and sha256_text(str(changes["diff"])) != changes.get("diff_hash"):
            errors.append("changes.diff_hash does not match diff content")
        reviews = state.get("reviews")
        if not isinstance(reviews, list) or not reviews:
            errors.append("changed diff lacks independent ReviewRecord")
        else:
            approvals = 0
            for index, review in enumerate(reviews):
                if not validate_review_shape(review):
                    errors.append(f"review[{index}] shape invalid")
                    continue
                if review.get("responsibility_group") == changes.get("implementer_responsibility_group"):
                    errors.append(f"review {review.get('review_id')} is from implementer responsibility group")
                if review.get("goal_id") != state.get("goal", {}).get("goal_id") or review.get("goal_version") != state.get("goal", {}).get("version"):
                    errors.append(f"review {review.get('review_id')} belongs to a different goal version")
                if review.get("reviewer") == changes.get("implementer") or review.get("implementer") != changes.get("implementer"):
                    errors.append(f"review {review.get('review_id')} actor/implementer identity is not independent")
                if require_invocations:
                    reviewer_invocation = str(review.get("reviewer_invocation_id") or "")
                    reviewer_result = invocation_results.get(reviewer_invocation)
                    if (
                        not reviewer_invocation
                        or not isinstance(reviewer_result, dict)
                        or reviewer_result.get("result") != "success"
                        or reviewer_result.get("actor") != review.get("reviewer")
                    ):
                        errors.append(f"review {review.get('review_id')} reviewer identity lacks a successful correlated invocation")
                    if review.get("implementer_invocation_id") != implementer_invocation or reviewer_invocation == implementer_invocation:
                        errors.append(f"review {review.get('review_id')} invocation identities are not independently bound")
                    assurance = review.get("actor_identity_assurance")
                    if assurance not in {"host-hook-observed", "declared-codex"}:
                        errors.append(f"review {review.get('review_id')} actor identity assurance missing")
                    elif assurance == "declared-codex":
                        warnings.append("Codex reviewer independence is auditable but not cryptographically host-enforced")
                if review.get("diff_hash") != changes.get("diff_hash") or review.get("base") != changes.get("base") or review.get("head") != changes.get("head"):
                    errors.append(f"review {review.get('review_id')} not bound to current base/head/diff")
                rerun_ids = review.get("rerun_evidence_ids", [])
                if not set(rerun_ids).issubset(evidence):
                    errors.append(f"review {review.get('review_id')} rerun evidence invalid")
                else:
                    for evidence_id in rerun_ids:
                        record = evidence[evidence_id]
                        if record.get("collector") != review.get("reviewer") or record.get("collector_responsibility_group") != review.get("responsibility_group"):
                            errors.append(f"review {review.get('review_id')} did not collect its rerun evidence")
                if review.get("verdict") == "APPROVE":
                    approvals += 1
                else:
                    errors.append(f"review {review.get('review_id')} verdict {review.get('verdict')}")
            if approvals == 0:
                errors.append("no independent APPROVE review for changed diff")
        test_flags = changes.get("test_changes", {})
        declared_risky = any(bool(test_flags.get(key)) for key in ("deleted", "skips_added", "threshold_loosened", "assertions_changed")) if isinstance(test_flags, dict) else False
        observed_test_change = bool(observed and any(_is_test_path(path) for path in observed.get("files", [])))
        risky = declared_risky or observed_test_change
        if risky:
            integrity = [r for r in state.get("reviews", []) if isinstance(r, dict) and r.get("category") == "test-integrity" and r.get("verdict") == "APPROVE"]
            if not integrity:
                errors.append("test deletion/skip/threshold/assertion change lacks separate test-integrity review")


def _profile_gates(profile: dict[str, Any], domains: set[str]) -> set[str]:
    gates = set(profile.get("global_gates", [])) if isinstance(profile.get("global_gates"), list) else set()
    configured = profile.get("domains", {})
    if isinstance(configured, dict):
        aliases = {"config-agent": "config/agent", "api-db": "api/db"}
        for domain in domains:
            row = configured.get(domain) or configured.get(aliases.get(domain, ""))
            if isinstance(row, dict):
                gates.update(row.get("required_gates", []))
            elif isinstance(row, list):
                gates.update(row)
    return {str(gate) for gate in gates if _nonempty_string(gate)}


def _string_values(value: Any) -> list[str]:
    return [str(item).strip() for item in value] if isinstance(value, list) and all(isinstance(item, str) and item.strip() for item in value) else []


def _registered_gate_definitions(profile: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(profile, dict):
        return {}
    rows: list[Any] = []
    rows.extend(profile.get("common_gates", []) if isinstance(profile.get("common_gates"), list) else [])
    rows.extend(profile.get("gates", []) if isinstance(profile.get("gates"), list) else [])
    profiles = profile.get("profiles", {})
    if isinstance(profiles, dict):
        for profile_row in profiles.values():
            if isinstance(profile_row, dict) and isinstance(profile_row.get("gates"), list):
                rows.extend(profile_row["gates"])
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict) or not _nonempty_string(row.get("id")):
            continue
        if _nonempty_string_list(row.get("command")):
            result[str(row["id"])] = {"command": list(row["command"]), "builtin": None}
        elif row.get("builtin") in {"intent-coverage", "claim-source-map", "goal-finalize"}:
            builtin = str(row["builtin"])
            result[str(row["id"])] = {"command": ["supervisor-builtin", builtin], "builtin": builtin}
    return result


def _registered_gate_commands(profile: Any) -> dict[str, list[str]]:
    return {gate_id: list(row["command"]) for gate_id, row in _registered_gate_definitions(profile).items()}


def _validate_quality(state: dict[str, Any], evidence: dict[str, dict[str, Any]], errors: list[str], observed: dict[str, Any] | None) -> None:
    profile = state.get("quality_profile")
    domains = set(state.get("changes", {}).get("domains", []))
    if isinstance(profile, dict) and observed:
        domains.update(_domains_from_observed(profile, [str(path) for path in observed.get("files", [])]))
    if not domains:
        domains = {str(c.get("domain")) for c in state.get("goal", {}).get("acceptance_criteria", []) if isinstance(c, dict) and c.get("domain")}
    if not isinstance(profile, dict) or not profile:
        errors.append("quality profile missing")
        return
    required = _profile_gates(profile, domains)
    if not required:
        errors.append(f"quality profile has no binary gates for domains: {sorted(domains)}")
        return
    passed = {str(record.get("gate_id")) for record in evidence.values() if record.get("exit_code") == 0 and record.get("relevant") is True}
    for gate in sorted(required - passed):
        errors.append(f"required quality gate missing: {gate}")


def _validate_criteria_and_waivers(state: dict[str, Any], satisfied_labels: dict[str, set[str]], errors: list[str]) -> set[str]:
    required_rows = [
        c for c in state.get("goal", {}).get("acceptance_criteria", [])
        if isinstance(c, dict) and c.get("required", True)
    ]
    required = {str(c.get("criterion_id")) for c in required_rows}
    satisfied = {
        str(c.get("criterion_id"))
        for c in required_rows
        if set(_string_values(c.get("expected_evidence"))).issubset(
            satisfied_labels.get(str(c.get("criterion_id")), set())
        )
    }
    unmet = required - satisfied
    valid_waived: set[str] = set()
    authorizations = {
        (str(row.get("criterion_id")), str(row.get("request_sha256")))
        for row in state.get("goal", {}).get("waiver_authorizations", [])
        if isinstance(row, dict)
    }
    for waiver in state.get("waivers", []):
        if not isinstance(waiver, dict) or not waiver:
            errors.append("waiver must be a structured object")
            continue
        criterion_id = waiver.get("criterion_id")
        if criterion_id not in required:
            errors.append("waiver criterion link invalid")
        elif (
            waiver.get("contract") == "UserWaiver/v3"
            and waiver.get("authorized_by") == "user"
            and all(_nonempty_string(waiver.get(key)) for key in ("waiver_id", "source_authorization", "source_authorization_sha256", "reason", "authorized_at"))
            and waiver.get("source_authorization_sha256") == sha256_text(str(waiver.get("source_authorization")))
            and (str(criterion_id), str(waiver.get("source_authorization_sha256"))) in authorizations
        ):
            try:
                if parse_time(str(waiver["authorized_at"])) < parse_time(str(state.get("started_at"))):
                    raise ValueError("stale waiver")
            except (TypeError, ValueError):
                errors.append(f"waiver for {criterion_id} timestamp invalid or stale")
                continue
            if str(criterion_id) in unmet:
                valid_waived.add(str(criterion_id))
        else:
            errors.append(f"waiver for {criterion_id} lacks original authorization/reason")
    for criterion_id in sorted(unmet - valid_waived):
        errors.append(f"acceptance criterion lacks valid evidence: {criterion_id}")
    return valid_waived


def validate_state(state: Any, events: list[dict[str, Any]]) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(state, dict) or not state:
        return {"valid": False, "health": "invalid", "errors": ["state must be a non-empty object"], "warnings": []}
    _validate_goal(state, errors)
    _validate_spec(state, errors)
    goal = state.get("goal", {}) if isinstance(state.get("goal"), dict) else {}
    criterion_ids = {str(c.get("criterion_id")) for c in goal.get("acceptance_criteria", []) if isinstance(c, dict) and c.get("criterion_id")}
    evidence_ids, evidence_by_id, satisfied_labels = _validate_evidence(state, criterion_ids, events, errors)
    _validate_tasks(state, criterion_ids, evidence_by_id, errors)
    _validate_intents(state, events, evidence_by_id, errors)
    observed = _observe_workspace(state, errors)
    _validate_changes_and_reviews(state, evidence_by_id, events, errors, warnings, observed)
    _validate_quality(state, evidence_by_id, errors, observed)
    valid_waived = _validate_criteria_and_waivers(state, satisfied_labels, errors)
    if state.get("health") == "degraded":
        errors.append("supervisor health degraded")
    return {
        "valid": not errors,
        "health": "healthy" if not errors else ("degraded" if state.get("health") == "degraded" else "incomplete"),
        "errors": errors,
        "warnings": warnings,
        "waived_criteria": sorted(valid_waived),
        "validated_at": utc_now(),
    }
