from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from .contracts import build_goal, new_state, normalize_intents
from .routing import split_intents
from .storage import StateContext, atomic_write_json
from .util import json_load, sha256_bytes, utc_now
from .workspace import capture_workspace_snapshot
from .rollout import initial_rollout


def read_project_config(path: str | None, workspace: str) -> dict[str, Any]:
    if not path:
        candidate = Path(workspace) / ".agent-supervisor" / "project.json"
        path = str(candidate) if candidate.exists() else None
    if not path:
        return {}
    value = json_load(Path(path), {})
    if not isinstance(value, dict):
        raise ValueError("project config must be a JSON object")
    return value


def read_quality_profile(project_config: dict[str, Any], project_file: str | None, workspace: str) -> dict[str, Any]:
    configured = project_config.get("quality_profile")
    if configured:
        candidate = Path(configured)
        if not candidate.is_absolute():
            candidate = Path(project_file).parent / candidate if project_file else Path(workspace) / candidate
    else:
        candidate = Path(workspace) / ".agent-supervisor" / "quality-profile.json"
    value = json_load(candidate, {}) if candidate.exists() else {}
    return value if isinstance(value, dict) else {}


def _previous_state(ctx: StateContext) -> tuple[dict[str, Any], Path | None]:
    pointer = ctx.previous_pointer()
    state_path = pointer.get("state_file")
    if not state_path:
        return {}, None
    path = Path(state_path)
    value = json_load(path, {}) if path.exists() else {}
    return (value if isinstance(value, dict) else {}), path


def start_round(
    ctx: StateContext,
    *,
    message: str,
    change_mode: str,
    execution_mode: str,
    project_config: dict[str, Any] | None = None,
    quality_profile: dict[str, Any] | None = None,
    goal_supplied: dict[str, Any] | None = None,
    intents_supplied: Any = None,
    shadow: bool = False,
) -> dict[str, Any]:
    ctx.initialize()
    previous, previous_path = _previous_state(ctx)
    previous_goal = previous.get("goal") if isinstance(previous.get("goal"), dict) else None
    project_config = project_config or {}
    policy_scope = project_config.get("supervisor_scope") if isinstance(project_config.get("supervisor_scope"), dict) else {}
    project_allowed = [str(value) for value in policy_scope.get("allowed_change_globs", []) if isinstance(value, str) and value.strip()]
    project_denied = [str(value) for value in policy_scope.get("out_of_scope_globs", []) if isinstance(value, str) and value.strip()]
    supplied = copy.deepcopy(goal_supplied or {})
    has_explicit_scope = isinstance(supplied.get("scope"), dict) or "scope_in" in supplied or "scope_out" in supplied
    has_previous_scope = bool(
        previous_goal
        and isinstance(previous_goal.get("scope"), dict)
        and previous_goal["scope"].get("in")
    )
    if not has_explicit_scope and not (change_mode in {"continue", "extend"} and has_previous_scope):
        # Thin host adapters do not receive a machine-authored GoalContract. Bound
        # their first goal to the project's declared Supervisor lease; a generic
        # project without a policy remains usable but every concrete task must still
        # name a non-broad child path and pass the workspace-delta gate.
        supplied["scope"] = {
            "in": project_allowed or ["**"],
            "out": project_denied,
        }
    profile = quality_profile or {}
    default_evidence: list[str] = []
    for gate in profile.get("global_gates", []) if isinstance(profile.get("global_gates"), list) else []:
        if isinstance(gate, str) and gate.strip() and gate not in default_evidence:
            default_evidence.append(gate)
    domains = profile.get("domains", {}) if isinstance(profile.get("domains"), dict) else {}
    evidence_by_domain: dict[str, list[str]] = {}
    for domain_id, domain_row in domains.items():
        if not isinstance(domain_row, dict):
            continue
        domain_gates = list(default_evidence)
        for gate in domain_row.get("required_gates", []) if isinstance(domain_row.get("required_gates"), list) else []:
            if isinstance(gate, str) and gate.strip() and gate not in domain_gates:
                domain_gates.append(gate)
        evidence_by_domain[str(domain_id)] = domain_gates
    config_domain = domains.get("config/agent") or domains.get("config-agent")
    if isinstance(config_domain, dict):
        for gate in config_domain.get("required_gates", []) if isinstance(config_domain.get("required_gates"), list) else []:
            if isinstance(gate, str) and gate.strip() and gate not in default_evidence:
                default_evidence.append(gate)
    goal = build_goal(
        message,
        change_mode=change_mode,
        previous_goal=previous_goal,
        supplied=supplied,
        default_evidence=default_evidence,
        default_evidence_by_domain=evidence_by_domain,
    )
    atomic_intents = intents_supplied if intents_supplied is not None else split_intents(message)
    new_intents = normalize_intents(atomic_intents, message)
    carried_intents: list[dict[str, Any]] = []
    if previous and change_mode in {"continue", "extend"}:
        for prior in previous.get("intents", []) if isinstance(previous.get("intents"), list) else []:
            if isinstance(prior, dict) and prior.get("status") not in {"covered", "skipped"}:
                carried = copy.deepcopy(prior)
                carried["carried_from_goal_version"] = previous_goal.get("version") if previous_goal else None
                carried_intents.append(carried)
    intents = carried_intents
    used_intent_ids = {str(row.get("intent_id") or "") for row in intents}
    for incoming in new_intents:
        candidate = str(incoming.get("intent_id") or "")
        if not candidate or candidate in used_intent_ids:
            suffix = len(intents) + 1
            candidate = f"intent-{suffix}"
            while candidate in used_intent_ids:
                suffix += 1
                candidate = f"intent-{suffix}"
            incoming["intent_id"] = candidate
        used_intent_ids.add(candidate)
        intents.append(incoming)
    state = new_state(
        goal,
        intents,
        runtime=ctx.runtime,
        project=str(project_config.get("project_id") or ctx.project),
        workspace=ctx.workspace,
        session=ctx.session,
        round_id=ctx.round,
        execution_mode=execution_mode,
        quality_profile=quality_profile,
    )
    state["quality_profile"] = quality_profile or {}
    state["project_policy"] = {
        "allowed_change_globs": project_allowed,
        "out_of_scope_globs": project_denied,
    }
    fallback_map: dict[str, str] = {}
    for row in project_config.get("agent_roles", []) if isinstance(project_config.get("agent_roles"), list) else []:
        if isinstance(row, dict) and isinstance(row.get("id"), str) and isinstance(row.get("fallback_id"), str):
            fallback_map[row["id"]] = row["fallback_id"]
    for row in project_config.get("capabilities", []) if isinstance(project_config.get("capabilities"), list) else []:
        if isinstance(row, dict) and isinstance(row.get("id"), str) and isinstance(row.get("fallback_id"), str):
            fallback_map[row["id"]] = row["fallback_id"]
    state["capability_fallbacks"] = fallback_map
    session_rollout = previous.get("rollout") if previous else None
    state["rollout"] = ctx.update_project_rollout(
        lambda current: initial_rollout(project_config, execution_mode, current or session_rollout)
    )
    state["execution_mode"] = str(state["rollout"].get("active_mode") or "observe")
    state["workspace_baseline"] = capture_workspace_snapshot(
        ctx.workspace,
        state["project_policy"]["allowed_change_globs"],
    )
    state["shadow"] = bool(shadow)
    if previous and previous_path and change_mode in {"continue", "extend"}:
        prior_rounds = copy.deepcopy(previous.get("prior_rounds", [])) if isinstance(previous.get("prior_rounds"), list) else []
        source_hash = sha256_bytes(previous_path.read_bytes()) if previous_path.exists() else ""
        prior_rounds.append(
            {
                "contract": "PriorRoundRecord/v3",
                "round": previous.get("round"),
                "goal": copy.deepcopy(previous.get("goal")),
                "intents": copy.deepcopy(previous.get("intents", [])),
                "tasks": copy.deepcopy(previous.get("tasks", [])),
                "evidence": copy.deepcopy(previous.get("evidence", [])),
                "reviews": copy.deepcopy(previous.get("reviews", [])),
                "claims": copy.deepcopy(previous.get("claims", [])),
                "waivers": copy.deepcopy(previous.get("waivers", [])),
                "changes": copy.deepcopy(previous.get("changes", {})),
                "spec": copy.deepcopy(previous.get("spec", {})),
                "terminal_state": previous.get("terminal_state"),
                "source_state_file": str(previous_path),
                "source_state_sha256": source_hash,
                "carried_at": utc_now(),
            }
        )
        state["prior_rounds"] = prior_rounds
        state["lineage"] = {
            "previous_round": previous.get("round"),
            "previous_goal_id": previous_goal.get("goal_id") if previous_goal else None,
            "previous_goal_version": previous_goal.get("version") if previous_goal else None,
            "previous_state_sha256": source_hash,
            "relationship": change_mode,
        }
        linked = copy.deepcopy(previous)
        link_name = "continued_by" if change_mode == "continue" else "extended_by"
        linked[link_name] = {
            "goal_id": goal["goal_id"],
            "version": goal["version"],
            "round": ctx.round,
        }
        linked["updated_at"] = utc_now()
        atomic_write_json(previous_path, linked)
    if change_mode == "replace" and previous and previous_path:
        superseded = copy.deepcopy(previous)
        if superseded.get("terminal_state") is None:
            superseded["terminal_state"] = "incomplete"
        superseded["superseded_by"] = {"goal_id": goal["goal_id"], "version": goal["version"], "round": ctx.round}
        for task in superseded.get("tasks", []):
            if isinstance(task, dict) and task.get("status") not in {"done", "cancelled", "superseded"}:
                task["status"] = "superseded"
        superseded["updated_at"] = utc_now()
        atomic_write_json(previous_path, superseded)
    ctx.save(state)
    ctx.update_session_pointer(
        {
            "state_file": str(ctx.state_file),
            "round": ctx.round,
            "goal_id": goal["goal_id"],
            "goal_version": goal["version"],
            "updated_at": utc_now(),
        }
    )
    ctx.append_event(
        {
            "event_type": "round_started",
            "status": "shadow" if shadow else "started",
            "goal_id": goal["goal_id"],
            "goal_version": goal["version"],
            "change_mode": change_mode,
            "execution_mode": execution_mode,
        }
    )
    return state


def merge_state(ctx: StateContext, patch: dict[str, Any]) -> dict[str, Any]:
    state = ctx.load()
    if not state:
        raise ValueError("round state not found")
    for key, value in patch.items():
        if key in {"runtime", "project", "workspace", "session", "round", "goal"}:
            continue
        state[key] = value
    state["updated_at"] = utc_now()
    ctx.save(state)
    return state
