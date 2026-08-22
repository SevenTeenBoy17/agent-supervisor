from __future__ import annotations

import copy
from typing import Any

from .attestation import sign_record
from .constants import EXIT_BLOCKED, EXIT_COMPLETE, EXIT_DEGRADED, EXIT_INCOMPLETE
from .rollout import apply_observation, checkpoint_observation_ids
from .storage import StateContext
from .util import utc_now
from .validation import validate_state


def finalize_round(ctx: StateContext, *, stop_attempt: int | None = None, blocked: bool = False) -> tuple[dict[str, Any], int]:
    state = ctx.load()
    if not state:
        raise ValueError("round state not found")
    increment_stop_attempt = stop_attempt is None
    if stop_attempt is None:
        stop_attempt = int(state.get("stop_attempts", 0)) + 1
    state["stop_attempts"] = max(int(state.get("stop_attempts", 0)), stop_attempt)
    source_snapshot = state.get("supervisor_source_snapshot")
    if isinstance(source_snapshot, dict) and source_snapshot.get("status") not in {"healthy", "available"}:
        state["health"] = "degraded"
    try:
        report = validate_state(state, ctx.events())
    except Exception as exc:  # fail-open at host boundary, never complete in core state
        state["health"] = "degraded"
        report = {"valid": False, "health": "degraded", "errors": [f"validator exception: {type(exc).__name__}"], "warnings": []}
    changes = state.get("changes") if isinstance(state.get("changes"), dict) else {}
    rollout_observation = {
        "contract": "RolloutObservation/v3",
        "observation_id": f"round-{state.get('session')}-{state.get('round')}",
        "kind": "round_outcome",
        "source_contract": "RoundFinalization/v3",
        "source_id": f"{state.get('session')}:{state.get('round')}",
        "nontrivial": bool(state.get("tasks") or changes.get("files")),
        "terminal_candidate": "complete" if report.get("valid") else "incomplete",
        "adjudication_pending": True,
    }
    rollout_observation["attestation"] = sign_record(rollout_observation)
    observation_persisted = False
    rollout_refreshed = False
    try:
        ctx.append_event(rollout_observation)
        observation_persisted = True
    except Exception as exc:
        state["health"] = "degraded"
        report.setdefault("errors", []).append(f"rollout observation event persistence degraded: {type(exc).__name__}")
        report["valid"] = False
        report["health"] = "degraded"
    if observation_persisted:
        try:
            def update_rollout(current: dict[str, Any]) -> dict[str, Any]:
                target = copy.deepcopy(current or state.get("rollout", {}))
                if any(
                    isinstance(row, dict) and row.get("observation_id") == rollout_observation["observation_id"]
                    for row in target.get("observations", [])
                ) or rollout_observation["observation_id"] in checkpoint_observation_ids(target):
                    return target
                return apply_observation(target, rollout_observation)

            state["rollout"] = ctx.update_project_rollout(update_rollout)
            rollout_refreshed = True
        except Exception as exc:
            state["health"] = "degraded"
            report.setdefault("errors", []).append(f"project rollout persistence degraded: {type(exc).__name__}")
            report["valid"] = False
            report["health"] = "degraded"

    final_event: dict[str, Any] = {"event_type": "round_finalized"}
    outcome: dict[str, Any] = {}

    def commit_final_state(current: dict[str, Any]) -> None:
        committed_report = copy.deepcopy(report)
        raw_execution_mode = current.get("execution_mode")
        normalized_execution_mode = (
            raw_execution_mode.strip().casefold()
            if isinstance(raw_execution_mode, str)
            else ""
        )
        host_execution_mode = normalized_execution_mode if normalized_execution_mode in {"observe", "warn", "enforce"} else "enforce"
        if normalized_execution_mode in {"observe", "warn", "enforce"}:
            current["execution_mode"] = normalized_execution_mode
        degraded = (
            current.get("health") == "degraded"
            or state.get("health") == "degraded"
            or committed_report.get("health") == "degraded"
        )
        if degraded:
            committed_report["valid"] = False
            committed_report["health"] = "degraded"
        current_stop_attempt = (
            int(current.get("stop_attempts", 0)) + 1
            if increment_stop_attempt
            else max(int(current.get("stop_attempts", 0)), int(state["stop_attempts"]))
        )
        valid_waived = set(committed_report.get("waived_criteria", []))
        if blocked:
            terminal, exit_code = "blocked", EXIT_BLOCKED
        elif degraded:
            terminal, exit_code = "incomplete", EXIT_DEGRADED
        elif committed_report.get("valid") and valid_waived:
            terminal, exit_code = "user-waived", EXIT_COMPLETE
        elif committed_report.get("valid"):
            terminal, exit_code = "complete", EXIT_COMPLETE
        else:
            terminal, exit_code = "incomplete", EXIT_INCOMPLETE
        if rollout_refreshed and "rollout" in state:
            current["rollout"] = copy.deepcopy(state["rollout"])
        if degraded:
            current["health"] = "degraded"
        current["stop_attempts"] = current_stop_attempt
        current["terminal_state"] = terminal
        current["validation"] = committed_report
        current["updated_at"] = utc_now()
        current["host_gate"] = {
            "should_block": terminal == "incomplete" and current_stop_attempt <= 2 and host_execution_mode == "enforce",
            "stop_cap_reached": current_stop_attempt > 2,
            "note": "stop cap only releases the host loop; it never converts unresolved work to complete",
        }
        final_event.update(
            {
                "status": terminal,
                "exit_code": exit_code,
                "stop_attempt": current_stop_attempt,
                "error_count": len(committed_report.get("errors", [])),
                "rollout_refreshed": rollout_refreshed,
            }
        )
        outcome["exit_code"] = exit_code

    committed, _ = ctx.transact(commit_final_state, final_event)
    return committed, int(outcome["exit_code"])
