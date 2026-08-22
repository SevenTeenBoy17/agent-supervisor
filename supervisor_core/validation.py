from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .constants import CHANGE_MODES, EXECUTION_MODES, INTENT_STATES, REVIEW_VERDICTS
from .attestation import verify_record
from .contracts import validate_review_shape
from .util import canonical_sha256, parse_time, sha256_text, utc_now
from .workspace import (
    capture_supervisor_source_snapshot,
    capture_workspace_snapshot,
    segment_glob_match,
    validated_supervisor_source_snapshot_hash,
    workspace_delta,
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PLACEHOLDER = re.compile(r"(?i)\b(?:tbd|todo|fixme|placeholder|trust\s+me|稍后|待定|未解决)\b")


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _nonempty_string_list(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(_nonempty_string(item) for item in value)


def _array_or_empty(value: Any, label: str, errors: list[str]) -> list[Any]:
    """Fail closed at untrusted collection boundaries without aborting validation."""
    if isinstance(value, list):
        return value
    errors.append(f"{label} must be an array")
    return []


def _valid_hash(value: Any) -> bool:
    return isinstance(value, str) and bool(_SHA256.fullmatch(value))


def _canonical_relative_path(value: Any) -> str | None:
    if not isinstance(value, str) or not value or "\x00" in value:
        return None
    raw = value.replace("\\", "/")
    if raw.startswith(("/", "//")) or re.match(r"^[A-Za-z]:", raw):
        return None
    parts: list[str] = []
    for part in raw.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            return None
        parts.append(part)
    return "/".join(parts) or None


def _valid_project_scope_pattern(value: Any, *, bounded: bool) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    if any(marker in value for marker in ("\x00", "\r", "\n", "\\", ":")):
        return False
    raw_path = Path(value)
    if raw_path.is_absolute() or ".." in raw_path.parts:
        return False
    normalized = "/".join(part for part in raw_path.parts if part not in {"", "."})
    if not normalized or normalized == "~" or normalized.startswith("~/"):
        return False
    if bounded and (
        value.startswith("./")
        or normalized in {"*", "**", "**/*"}
        or any(marker in normalized.split("/", 1)[0] for marker in ("*", "?", "["))
    ):
        return False
    return True


def _project_policy_scope(
    state: dict[str, Any],
    errors: list[str] | None = None,
) -> tuple[bool, bool, list[str], list[str]]:
    """Return configured/valid scope without collapsing an explicit bad policy."""
    if "project_policy" not in state:
        return False, True, [], []
    policy = state.get("project_policy")
    if not isinstance(policy, dict):
        if errors is not None:
            errors.append("project policy must be an object when configured")
        return True, False, [], []

    values: dict[str, list[str]] = {}
    valid = True
    for field, bounded, require_nonempty in (
        ("allowed_change_globs", True, True),
        ("out_of_scope_globs", False, False),
    ):
        raw_values = policy.get(field)
        field_valid = (
            isinstance(raw_values, list)
            and (bool(raw_values) or not require_nonempty)
            and all(_valid_project_scope_pattern(value, bounded=bounded) for value in raw_values)
            and len(set(raw_values)) == len(raw_values)
        ) if isinstance(raw_values, list) else False
        if not field_valid:
            valid = False
            if errors is not None:
                errors.append(f"project policy {field} invalid")
            values[field] = []
        else:
            values[field] = list(raw_values)
    return (
        True,
        valid,
        values["allowed_change_globs"] if valid else [],
        values["out_of_scope_globs"] if valid else [],
    )


def _path_allowed(path: str, allowed: list[str]) -> bool:
    normalized = _canonical_relative_path(path)
    if normalized is None:
        return False
    for pattern in allowed:
        candidate = _canonical_relative_path(pattern)
        if candidate is None:
            continue
        if segment_glob_match(normalized, candidate):
            return True
    return False


def _pattern_within(child: str, parent: str) -> bool:
    child_norm = _canonical_relative_path(child)
    parent_norm = _canonical_relative_path(parent)
    if child_norm is None or parent_norm is None or child_norm in {"*", "**"}:
        return False
    if parent_norm.endswith("/**"):
        prefix = parent_norm[:-3].rstrip("/")
        return child_norm == prefix or child_norm.startswith(prefix + "/")
    child_parts = child_norm.split("/")
    parent_parts = parent_norm.split("/")
    child_has_glob = any(
        token in segment for segment in child_parts for token in ("*", "?", "[")
    )
    if child_has_glob:
        if len(child_parts) != len(parent_parts):
            return False
        for child_part, parent_part in zip(child_parts, parent_parts, strict=True):
            if child_part == "**" and parent_part != "**":
                return False
            if any(token in child_part for token in ("*", "?", "[")):
                if child_part != parent_part and parent_part != "*":
                    return False
            elif not segment_glob_match(child_part, parent_part):
                return False
        return True
    if any(token in parent_norm for token in ("*", "?", "[")):
        return segment_glob_match(child_norm, parent_norm)
    return child_norm == parent_norm


def _patterns_overlap(left: str, right: str) -> bool:
    left_norm = _canonical_relative_path(left)
    right_norm = _canonical_relative_path(right)
    if left_norm is None or right_norm is None:
        return False

    def segment_overlap(left_segment: str, right_segment: str) -> bool:
        left_has_glob = any(token in left_segment for token in ("*", "?", "["))
        right_has_glob = any(token in right_segment for token in ("*", "?", "["))
        if not left_has_glob:
            return segment_glob_match(left_segment, right_segment)
        if not right_has_glob:
            return segment_glob_match(right_segment, left_segment)
        if left_segment == right_segment or left_segment == "*" or right_segment == "*":
            return True
        if "[" in left_segment or "[" in right_segment:
            # Character-class intersection is not safely reducible to fixed
            # prefix/suffix checks.  Stay conservative rather than miss a
            # denied-path overlap.
            return True

        def fixed_edges(pattern: str) -> tuple[str, str]:
            first = min(
                (index for index, value in enumerate(pattern) if value in "*?["),
                default=len(pattern),
            )
            wildcard_indexes = [
                index for index, value in enumerate(pattern) if value in "*?["
            ]
            last = max(wildcard_indexes, default=-1)
            return pattern[:first], pattern[last + 1 :] if last >= 0 else pattern

        left_prefix, left_suffix = fixed_edges(left_segment)
        right_prefix, right_suffix = fixed_edges(right_segment)
        prefix_compatible = left_prefix.startswith(right_prefix) or right_prefix.startswith(left_prefix)
        suffix_compatible = left_suffix.endswith(right_suffix) or right_suffix.endswith(left_suffix)
        return prefix_compatible and suffix_compatible

    left_parts = tuple(left_norm.split("/"))
    right_parts = tuple(right_norm.split("/"))
    memo: dict[tuple[int, int], bool] = {}

    def intersects(left_index: int, right_index: int) -> bool:
        key = (left_index, right_index)
        if key in memo:
            return memo[key]
        if left_index == len(left_parts):
            result = all(part == "**" for part in right_parts[right_index:])
        elif right_index == len(right_parts):
            result = all(part == "**" for part in left_parts[left_index:])
        else:
            left_part = left_parts[left_index]
            right_part = right_parts[right_index]
            if left_part == "**" and right_part == "**":
                result = intersects(left_index + 1, right_index) or intersects(
                    left_index, right_index + 1
                )
            elif left_part == "**":
                result = intersects(left_index + 1, right_index) or intersects(
                    left_index, right_index + 1
                )
            elif right_part == "**":
                result = intersects(left_index, right_index + 1) or intersects(
                    left_index + 1, right_index
                )
            else:
                result = segment_overlap(left_part, right_part) and intersects(
                    left_index + 1, right_index + 1
                )
        memo[key] = result
        return result

    return intersects(0, 0)


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
            if str(invocation_id) in attempts:
                errors.append(f"invocation {invocation_id} has duplicate attempts")
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


def _trusted_invocation_for_runtime(
    events: list[dict[str, Any]], invocation_id: str, *, actor: Any, state: dict[str, Any]
) -> bool:
    pair = [
        event for event in events
        if isinstance(event, dict)
        and event.get("invocation_id") == invocation_id
        and event.get("event_type") in {"invocation_attempt", "invocation_result"}
    ]
    if len(pair) != 2:
        return False
    attempts = [event for event in pair if event.get("event_type") == "invocation_attempt"]
    results = [event for event in pair if event.get("event_type") == "invocation_result"]
    if len(attempts) != 1 or len(results) != 1:
        return False
    attempt, result = attempts[0], results[0]
    goal = state.get("goal", {}) if isinstance(state.get("goal"), dict) else {}
    request_manifest = state.get("request_manifest") if isinstance(state.get("request_manifest"), dict) else {}
    expected_binding = {
        "runtime": state.get("runtime"),
        "project": state.get("project"),
        "workspace": str(Path(str(state.get("workspace") or "")).resolve()),
        "session": state.get("session"),
        "round": state.get("round"),
        "goal_id": goal.get("goal_id"),
        "goal_version": goal.get("version"),
        "request_manifest_sha256": canonical_sha256(request_manifest),
    }
    attempt_details = attempt.get("details") if isinstance(attempt.get("details"), dict) else {}
    result_details = result.get("details") if isinstance(result.get("details"), dict) else {}
    attempt_assurance = attempt.get("identity_assurance")
    result_assurance = result.get("identity_assurance")
    accepted_assurances = _accepted_runtime_assurances(state)
    return bool(
        result.get("result") == "success"
        and attempt.get("actor") == actor
        and result.get("actor") == actor
        and attempt.get("capability") == result.get("capability")
        and attempt_assurance == result_assurance
        and attempt_assurance in accepted_assurances
        and verify_record(attempt)
        and verify_record(result)
        and all(attempt_details.get(key) == value for key, value in expected_binding.items())
        and all(result_details.get(key) == value for key, value in expected_binding.items())
    )


def _accepted_runtime_assurances(state: dict[str, Any]) -> set[str]:
    if state.get("runtime") == "codex":
        # Native Codex Hooks are host observations.  Keep explicit audit as a
        # compatibility lane for older Codex adapters and manually finalized
        # rounds; both remain bound to signed attempt/result pairs.
        return {"host-hook-observed", "codex-explicit-audit"}
    return {"host-hook-observed"}


def _runtime_assurance_accepted(state: dict[str, Any], assurance: Any) -> bool:
    return isinstance(assurance, str) and assurance in _accepted_runtime_assurances(state)


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
    raw_t3_authorizations = goal.get("t3_action_authorizations", [])
    if not isinstance(raw_t3_authorizations, list):
        errors.append("GoalContract t3_action_authorizations must be an array")
    else:
        for index, authorization in enumerate(raw_t3_authorizations):
            if not isinstance(authorization, dict) or set(authorization) != {"action_sha256", "request_sha256"}:
                errors.append(f"GoalContract T3 authorization[{index}] structure invalid")
                continue
            if not _valid_hash(authorization.get("action_sha256")):
                errors.append(f"GoalContract T3 authorization[{index}] action hash invalid")
            if not _valid_hash(authorization.get("request_sha256")):
                errors.append(f"GoalContract T3 authorization[{index}] granting request hash invalid")
    criteria = goal.get("acceptance_criteria")
    if not isinstance(criteria, list) or not criteria:
        errors.append("GoalContract acceptance criteria empty")
        return
    seen: set[str] = set()
    for index, criterion in enumerate(criteria):
        if not isinstance(criterion, dict) or not criterion:
            errors.append(f"criterion[{index}] must be a non-empty object")
            continue
        raw_criterion_id = criterion.get("criterion_id")
        criterion_id = raw_criterion_id.strip() if isinstance(raw_criterion_id, str) else ""
        if not criterion_id or criterion_id in seen:
            errors.append(f"criterion[{index}] id missing or duplicate")
        if criterion_id:
            seen.add(criterion_id)
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
    goal = state.get("goal") if isinstance(state.get("goal"), dict) else {}
    criteria = goal.get("acceptance_criteria")
    if not isinstance(criteria, list):
        criteria = []
    criterion_expected = {
        str(row.get("criterion_id")): set(_string_values(row.get("expected_evidence")))
        for row in criteria
        if isinstance(row, dict) and row.get("criterion_id")
    }
    goal_scope = goal.get("scope", {}) if isinstance(goal.get("scope"), dict) else {}
    for field in ("in", "out"):
        value = goal_scope.get(field)
        if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
            errors.append(f"GoalContract scope.{field} invalid")
    goal_allowed = _string_values(goal_scope.get("in"))
    project_policy_configured, project_policy_valid, project_allowed, project_denied = (
        _project_policy_scope(state, errors)
    )
    active_leases: list[tuple[str, str, str, list[str]]] = []
    for index, task in enumerate(tasks):
        if not isinstance(task, dict) or not task:
            errors.append(f"task[{index}] must be a non-empty object")
            continue
        if task.get("goal_id") != goal.get("goal_id") or task.get("goal_version") != goal.get("version"):
            errors.append(f"task {task.get('task_id', index)} not linked to current goal version")
        raw_links = task.get("criterion_ids")
        links: list[str] = list(raw_links) if _nonempty_string_list(raw_links) else []
        if not links or not set(links).issubset(criterion_ids):
            errors.append(f"task {task.get('task_id', index)} criterion links invalid")
        task_paths = task.get("allowed_paths")
        if not _nonempty_string_list(task_paths):
            errors.append(f"task {task.get('task_id', index)} allowed paths empty")
        else:
            for allowed_path in task_paths:
                if not any(_pattern_within(allowed_path, parent) for parent in goal_allowed):
                    errors.append(f"task {task.get('task_id', index)} path exceeds GoalContract scope: {allowed_path}")
                is_absolute = bool(re.match(r"^[A-Za-z]:[/\\]", allowed_path)) or allowed_path.startswith("/")
                if (
                    project_policy_configured
                    and project_policy_valid
                    and not is_absolute
                    and not any(_pattern_within(allowed_path, parent) for parent in project_allowed)
                ):
                    errors.append(f"task {task.get('task_id', index)} path exceeds project policy: {allowed_path}")
                if any(_patterns_overlap(allowed_path, denied) for denied in project_denied):
                    errors.append(f"task {task.get('task_id', index)} path overlaps project out-of-scope policy: {allowed_path}")
        if task.get("lease_status") == "active":
            lease_id = str(task.get("lease_id") or "").strip()
            owner = str(task.get("owner") or "").strip()
            group = str(task.get("responsibility_group") or "").strip()
            if not lease_id or not owner or not group:
                errors.append(f"task {task.get('task_id', index)} active lease identity incomplete")
            elif isinstance(task_paths, list):
                active_leases.append((lease_id, owner, group, [str(path) for path in task_paths if isinstance(path, str)]))
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
    for left_index, left in enumerate(active_leases):
        for right in active_leases[left_index + 1 :]:
            if left[0] == right[0]:
                continue
            if any(_patterns_overlap(left_path, right_path) for left_path in left[3] for right_path in right[3]):
                errors.append(
                    "overlapping active path leases: "
                    f"{left[0]} ({left[1]}/{left[2]}) conflicts with {right[0]} ({right[1]}/{right[2]})"
                )


def _validate_evidence(state: dict[str, Any], criterion_ids: set[str], events: list[dict[str, Any]], errors: list[str]) -> tuple[set[str], dict[str, dict[str, Any]], dict[str, set[str]]]:
    evidence = state.get("evidence")
    if not isinstance(evidence, list):
        errors.append("evidence must be an array")
        return set(), {}, {}
    goal = state.get("goal") if isinstance(state.get("goal"), dict) else {}
    raw_started = state.get("started_at")
    try:
        if not isinstance(raw_started, str):
            raise TypeError("started_at must be a string")
        started = parse_time(raw_started)
    except (TypeError, ValueError):
        errors.append("state started_at invalid")
        started = datetime.max.replace(tzinfo=timezone.utc)
    ids: set[str] = set()
    by_id: dict[str, dict[str, Any]] = {}
    satisfied_labels: dict[str, set[str]] = {}
    gate_definitions = _registered_gate_definitions(state.get("quality_profile", {}))
    gate_commands = {gate_id: list(row.get("command") or []) for gate_id, row in gate_definitions.items()}
    executions = {
        str(event.get("execution_id")): event
        for event in events
        if isinstance(event, dict) and event.get("event_type") == "gate_execution" and event.get("execution_id")
    }
    source_snapshot_hash = (
        validated_supervisor_source_snapshot_hash(state.get("supervisor_source_snapshot"))
        if state.get("runtime") != "test"
        else None
    )
    workspace_baseline = state.get("workspace_baseline")
    workspace_snapshot_hash = (
        workspace_baseline.get("snapshot_hash")
        if isinstance(workspace_baseline, dict)
        else None
    )
    for index, record in enumerate(evidence):
        if not isinstance(record, dict) or not record:
            errors.append(f"evidence[{index}] must be a non-empty structured object; free text is invalid")
            continue
        record_error_count = len(errors)
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
                errors.append(f"evidence {evidence_id} lacks a valid local-core execution attestation")
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
                    "resolved_executable": record.get("resolved_executable"),
                    "resolved_executable_sha256": record.get("resolved_executable_sha256"),
                    "precondition": record.get("precondition"),
                    "command_executed": record.get("command_executed"),
                    "source_snapshot_hash": record.get("source_snapshot_hash"),
                }
                if any(execution.get(key) != value for key, value in bindings.items()):
                    errors.append(f"evidence {evidence_id} does not match the locally attested core execution")
                if execution.get("artifact_hash") != execution.get("output_sha256"):
                    errors.append(f"evidence {evidence_id} artifact is not bound to the complete gate output")
                if execution.get("output_summary") != record.get("output_summary"):
                    errors.append(f"evidence {evidence_id} output summary was rewritten after execution")
                if execution.get("state_started_at") != state.get("started_at"):
                    errors.append(f"evidence {evidence_id} was signed for a different round start")
                if not _valid_hash(workspace_snapshot_hash):
                    errors.append(f"evidence {evidence_id} cannot bind to a valid workspace baseline")
                elif execution.get("workspace_snapshot_hash") != workspace_snapshot_hash:
                    errors.append(f"evidence {evidence_id} was signed for a different workspace baseline")
                if (
                    source_snapshot_hash is None
                    or execution.get("source_snapshot_hash") != source_snapshot_hash
                    or record.get("source_snapshot_hash") != source_snapshot_hash
                ):
                    errors.append(f"evidence {evidence_id} was signed for a different Supervisor source snapshot")
        raw_criterion_id = record.get("criterion_id")
        criterion_id = raw_criterion_id.strip() if isinstance(raw_criterion_id, str) else ""
        if not criterion_id or criterion_id not in criterion_ids:
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
        gate_definition = gate_definitions.get(str(record.get("gate_id")))
        if isinstance(gate_definition, dict):
            expected_precondition = gate_definition.get("precondition")
            observed_precondition = record.get("precondition")
            if expected_precondition:
                if not isinstance(observed_precondition, dict):
                    errors.append(f"evidence {evidence_id} registered precondition was not attested")
                else:
                    precondition_command = observed_precondition.get("command")
                    if not isinstance(precondition_command, dict) or precondition_command.get("args") != expected_precondition:
                        errors.append(f"evidence {evidence_id} precondition command does not match registered gate")
                    if observed_precondition.get("exit_code") != 0 or record.get("command_executed") is not True:
                        errors.append(f"evidence {evidence_id} precondition did not pass before the main command")
                    if not _valid_hash(observed_precondition.get("resolved_executable_sha256")):
                        errors.append(f"evidence {evidence_id} precondition executable hash invalid")
            elif observed_precondition is not None:
                errors.append(f"evidence {evidence_id} contains an unregistered precondition")
        if state.get("runtime") != "test" and isinstance(gate_definition, dict) and not gate_definition.get("builtin"):
            resolved_executable = record.get("resolved_executable")
            is_absolute = _nonempty_string(resolved_executable) and (
                Path(str(resolved_executable)).is_absolute()
                or bool(re.match(r"^[A-Za-z]:[\\/]", str(resolved_executable)))
                or str(resolved_executable).startswith("\\\\")
            )
            if not is_absolute:
                errors.append(f"evidence {evidence_id} resolved executable path is missing or not absolute")
            if not _valid_hash(record.get("resolved_executable_sha256")):
                errors.append(f"evidence {evidence_id} resolved executable hash invalid")
        if record.get("goal_id") != goal.get("goal_id") or record.get("goal_version") != goal.get("version"):
            errors.append(f"evidence {evidence_id} belongs to a different goal version")
        changes = state.get("changes") if isinstance(state.get("changes"), dict) else {}
        if changes.get("diff_hash"):
            if record.get("base") != changes.get("base") or record.get("head") != changes.get("head") or record.get("diff_hash") != changes.get("diff_hash"):
                errors.append(f"evidence {evidence_id} is not bound to the reviewed diff")
        if len(errors) == record_error_count:
            satisfied_labels.setdefault(str(criterion_id), set()).add(str(record.get("gate_id")))
    return ids, by_id, satisfied_labels


def _validate_intents(
    state: dict[str, Any],
    events: list[dict[str, Any]],
    evidence: dict[str, dict[str, Any]],
    errors: list[str],
) -> None:
    intents = state.get("intents")
    if not isinstance(intents, list):
        errors.append("intents must be an array")
        intents = []
    elif not intents:
        errors.append("IntentCoverage is empty")
    success_caps, invocation_results, invocation_errors = successful_invocations(events)
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
        errors.append("atomic request manifest lacks a valid local-core integrity attestation")
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
        raw_intent_id = intent.get("intent_id")
        intent_id = raw_intent_id.strip() if isinstance(raw_intent_id, str) else ""
        if not intent_id or intent_id in seen_intents:
            errors.append(f"intent[{index}] id missing or duplicate")
        if intent_id:
            seen_intents.add(intent_id)
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
            if not _nonempty_string_list(capabilities) or not set(capabilities).intersection(success_caps):
                errors.append(f"intent {intent.get('intent_id', index)} has no successful correlated invocation")
        elif status == "skipped":
            if not _nonempty_string(intent.get("reason")) or intent.get("reason") == "awaiting routing":
                errors.append(f"intent {intent.get('intent_id', index)} skipped without concrete reason")
        else:
            errors.append(f"intent {intent.get('intent_id', index)} unresolved with status {status}")
    if all_skipped:
        approved = False
        request_manifest_sha256 = canonical_sha256(signed_manifest) if isinstance(signed_manifest, dict) else ""
        reviews = state.get("reviews") if isinstance(state.get("reviews"), list) else []
        for review in reviews:
            if not (
                isinstance(review, dict)
                and review.get("category") == "zero-skill-routing"
                and review.get("verdict") == "APPROVE"
                and validate_review_shape(review)
            ):
                continue
            implementer = str(review.get("implementer") or "")
            reviewer = str(review.get("reviewer") or "")
            implementer_group = str(review.get("implementer_responsibility_group") or "")
            reviewer_group = str(review.get("responsibility_group") or "")
            implementer_invocation = str(review.get("implementer_invocation_id") or "")
            reviewer_invocation = str(review.get("reviewer_invocation_id") or "")
            implementer_result = invocation_results.get(implementer_invocation)
            reviewer_result = invocation_results.get(reviewer_invocation)
            independent = bool(
                implementer
                and reviewer
                and implementer != reviewer
                and implementer_group
                and reviewer_group
                and implementer_group != reviewer_group
                and implementer_invocation
                and reviewer_invocation
                and implementer_invocation != reviewer_invocation
                and isinstance(implementer_result, dict)
                and implementer_result.get("result") == "success"
                and implementer_result.get("actor") == implementer
                and isinstance(reviewer_result, dict)
                and reviewer_result.get("result") == "success"
                and reviewer_result.get("actor") == reviewer
                and _trusted_invocation_for_runtime(events, implementer_invocation, actor=implementer, state=state)
                and _trusted_invocation_for_runtime(events, reviewer_invocation, actor=reviewer, state=state)
                and _runtime_assurance_accepted(state, review.get("actor_identity_assurance"))
                and review.get("request_manifest_sha256") == request_manifest_sha256
                and review.get("goal_id") == goal.get("goal_id")
                and review.get("goal_version") == goal.get("version")
            )
            if not independent:
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


def _validate_supervisor_source_snapshot(state: dict[str, Any], errors: list[str]) -> str | None:
    """Bind a real-runtime round to the exact Supervisor core and adapter sources."""
    if state.get("runtime") == "test":
        return None
    expected_hash = validated_supervisor_source_snapshot_hash(state.get("supervisor_source_snapshot"))
    if expected_hash is None:
        errors.append("trusted Supervisor source snapshot missing, degraded, or self-hash invalid")
        return None
    try:
        current = capture_supervisor_source_snapshot()
    except (OSError, RuntimeError, ValueError):
        errors.append("current Supervisor source snapshot unavailable")
        return None
    current_hash = validated_supervisor_source_snapshot_hash(current)
    if current_hash is None:
        errors.append("current Supervisor source snapshot degraded or invalid")
        return None
    if current_hash != expected_hash:
        errors.append("Supervisor source changed after round start")
        return None
    return expected_hash


def _is_test_path(path: str) -> bool:
    normalized = path.replace("\\", "/").casefold()
    name = normalized.rsplit("/", 1)[-1]
    return (
        normalized.startswith("tests/")
        or "/tests/" in normalized
        or "/__tests__/" in normalized
        or ".test." in name
        or ".spec." in name
        or name.startswith("test_")
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
    goal = state.get("goal") if isinstance(state.get("goal"), dict) else {}
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
    tasks = state.get("tasks") if isinstance(state.get("tasks"), list) else []
    for task in tasks:
        if isinstance(task, dict) and task.get("status") == "done":
            allowed.extend([p for p in task.get("allowed_paths", []) if _nonempty_string(p)])
    for path in files:
        if not _nonempty_string(path) or not _path_allowed(str(path), allowed):
            errors.append(f"out-of-scope diff: {path}")
    if files:
        _, invocation_results, invocation_errors = successful_invocations(events)
        errors.extend(invocation_errors)
        for field in ("base", "head", "diff_hash", "implementer", "implementer_responsibility_group"):
            if not _nonempty_string(changes.get(field)):
                errors.append(f"changes.{field} missing")
        implementer_invocation = str(changes.get("implementer_invocation_id") or "")
        result = invocation_results.get(implementer_invocation)
        if not implementer_invocation or not isinstance(result, dict) or result.get("result") != "success" or result.get("actor") != changes.get("implementer"):
            errors.append("changes implementer identity lacks a successful correlated invocation")
        elif not _trusted_invocation_for_runtime(events, implementer_invocation, actor=changes.get("implementer"), state=state):
            errors.append("changes implementer identity is not bound to the active round with accepted runtime assurance")
        if changes.get("diff") and sha256_text(str(changes["diff"])) != changes.get("diff_hash"):
            errors.append("changes.diff_hash does not match diff content")
        reviews = state.get("reviews") if isinstance(state.get("reviews"), list) else []
        if not reviews:
            errors.append("changed diff lacks independent ReviewRecord")
        else:
            approvals = 0
            for index, review in enumerate(reviews):
                if not validate_review_shape(review):
                    errors.append(f"review[{index}] shape invalid")
                    continue
                if review.get("responsibility_group") == changes.get("implementer_responsibility_group"):
                    errors.append(f"review {review.get('review_id')} is from implementer responsibility group")
                if review.get("goal_id") != goal.get("goal_id") or review.get("goal_version") != goal.get("version"):
                    errors.append(f"review {review.get('review_id')} belongs to a different goal version")
                if review.get("reviewer") == changes.get("implementer") or review.get("implementer") != changes.get("implementer"):
                    errors.append(f"review {review.get('review_id')} actor/implementer identity is not independent")
                reviewer_invocation = str(review.get("reviewer_invocation_id") or "")
                reviewer_result = invocation_results.get(reviewer_invocation)
                if (
                    not reviewer_invocation
                    or not isinstance(reviewer_result, dict)
                    or reviewer_result.get("result") != "success"
                    or reviewer_result.get("actor") != review.get("reviewer")
                ):
                    errors.append(f"review {review.get('review_id')} reviewer identity lacks a successful correlated invocation")
                elif not _trusted_invocation_for_runtime(events, reviewer_invocation, actor=review.get("reviewer"), state=state):
                    errors.append(
                        f"review {review.get('review_id')} reviewer identity is not bound to the active round "
                        "with accepted runtime assurance"
                    )
                if review.get("implementer_invocation_id") != implementer_invocation or reviewer_invocation == implementer_invocation:
                    errors.append(f"review {review.get('review_id')} invocation identities are not independently bound")
                assurance = review.get("actor_identity_assurance")
                if not _runtime_assurance_accepted(state, assurance):
                    errors.append(
                        f"review {review.get('review_id')} actor identity assurance is not host-hook-observed or another accepted assurance for {state.get('runtime')}"
                    )
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
            integrity = [r for r in reviews if isinstance(r, dict) and r.get("category") == "test-integrity" and r.get("verdict") == "APPROVE"]
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
            precondition = list(row["precondition"]) if _nonempty_string_list(row.get("precondition")) else None
            result[str(row["id"])] = {
                "command": list(row["command"]),
                "precondition": precondition,
                "builtin": None,
            }
        elif row.get("builtin") in {"intent-coverage", "claim-source-map", "goal-finalize"}:
            builtin = str(row["builtin"])
            result[str(row["id"])] = {
                "command": ["supervisor-builtin", builtin],
                "precondition": None,
                "builtin": builtin,
            }
    return result


def _validate_gate_registry(profile: Any, errors: list[str]) -> None:
    if not isinstance(profile, dict):
        return
    rows: list[Any] = []
    rows.extend(profile.get("common_gates", []) if isinstance(profile.get("common_gates"), list) else [])
    rows.extend(profile.get("gates", []) if isinstance(profile.get("gates"), list) else [])
    profiles = profile.get("profiles", {})
    if isinstance(profiles, dict):
        for profile_row in profiles.values():
            if isinstance(profile_row, dict) and isinstance(profile_row.get("gates"), list):
                rows.extend(profile_row["gates"])
    seen: set[str] = set()
    supported_builtins = {"intent-coverage", "claim-source-map", "goal-finalize"}
    for row in rows:
        if not isinstance(row, dict) or not _nonempty_string(row.get("id")):
            continue
        gate_id = str(row["id"])
        if gate_id in seen:
            errors.append(f"duplicate quality gate id: {gate_id}")
        seen.add(gate_id)
        if "builtin" in row and row.get("builtin") not in supported_builtins:
            errors.append(f"quality gate {gate_id} has unsupported builtin")


def _registered_gate_commands(profile: Any) -> dict[str, list[str]]:
    return {gate_id: list(row.get("command") or []) for gate_id, row in _registered_gate_definitions(profile).items()}


def _validate_quality(state: dict[str, Any], evidence: dict[str, dict[str, Any]], errors: list[str], observed: dict[str, Any] | None) -> None:
    profile = state.get("quality_profile")
    _validate_gate_registry(profile, errors)
    changes = state.get("changes") if isinstance(state.get("changes"), dict) else {}
    raw_domains = changes.get("domains")
    domains = {
        value for value in raw_domains
        if isinstance(value, str) and value.strip()
    } if isinstance(raw_domains, list) else set()
    if isinstance(profile, dict) and observed:
        observed_files = observed.get("files") if isinstance(observed, dict) else []
        domains.update(_domains_from_observed(
            profile,
            [str(path) for path in observed_files] if isinstance(observed_files, list) else [],
        ))
    if not domains:
        goal = state.get("goal") if isinstance(state.get("goal"), dict) else {}
        criteria = goal.get("acceptance_criteria")
        domains = {
            str(c.get("domain"))
            for c in criteria if isinstance(c, dict) and c.get("domain")
        } if isinstance(criteria, list) else set()
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
    goal = state.get("goal") if isinstance(state.get("goal"), dict) else {}
    criteria = goal.get("acceptance_criteria")
    if not isinstance(criteria, list):
        criteria = []
    required_rows = [
        c for c in criteria
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
    raw_authorizations = goal.get("waiver_authorizations")
    if "waiver_authorizations" in goal and not isinstance(raw_authorizations, list):
        errors.append("GoalContract waiver_authorizations must be an array")
    authorizations = {
        (str(row.get("criterion_id")), str(row.get("request_sha256")))
        for row in raw_authorizations
        if isinstance(row, dict)
    } if isinstance(raw_authorizations, list) else set()
    raw_waivers = state.get("waivers")
    if not isinstance(raw_waivers, list):
        errors.append("waivers must be an array")
        raw_waivers = []
    for waiver in raw_waivers:
        if not isinstance(waiver, dict) or not waiver:
            errors.append("waiver must be a structured object")
            continue
        raw_criterion_id = waiver.get("criterion_id")
        criterion_id = raw_criterion_id.strip() if isinstance(raw_criterion_id, str) else ""
        if not criterion_id or criterion_id not in required:
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
    events = _array_or_empty(events, "events", errors)
    if not isinstance(state.get("reviews"), list):
        errors.append("reviews must be an array")
    authority = state.get("attestation_authority")
    if not (
        isinstance(authority, dict)
        and authority.get("contract") == "AttestationAuthority/v3"
        and authority.get("assurance") == "local-integrity-only"
        and authority.get("same_user_adversary_resistant") is False
    ):
        errors.append("attestation authority limitation is missing or overstated")
    else:
        warnings.append("local HMAC provides operational tamper evidence, not a security boundary against same-user processes")
    if state.get("runtime") == "codex":
        warnings.append(
            "Codex native host-hook-observed evidence uses host lifecycle observation; codex-explicit-audit compatibility evidence is auditable local evidence, not host lifecycle observation or a hard host block"
        )
    raw_execution_mode = state.get("execution_mode")
    normalized_execution_mode = (
        raw_execution_mode.strip().casefold()
        if isinstance(raw_execution_mode, str)
        else ""
    )
    if normalized_execution_mode not in EXECUTION_MODES or raw_execution_mode != normalized_execution_mode:
        errors.append("execution mode invalid or non-canonical")
    _validate_supervisor_source_snapshot(state, errors)
    _validate_goal(state, errors)
    _validate_spec(state, errors)
    goal = state.get("goal", {}) if isinstance(state.get("goal"), dict) else {}
    criteria = goal.get("acceptance_criteria")
    criterion_ids = {
        str(c["criterion_id"]).strip()
        for c in criteria
        if isinstance(c, dict) and _nonempty_string(c.get("criterion_id"))
    } if isinstance(criteria, list) else set()
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
