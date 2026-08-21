from __future__ import annotations

import copy
from typing import Any

from .attestation import sign_record
from .constants import EXIT_BLOCKED, EXIT_COMPLETE, EXIT_DEGRADED, EXIT_INCOMPLETE
from .rollout import apply_observation
from .storage import StateContext
from .util import utc_now
from .validation import validate_state


def finalize_round(ctx: StateContext, *, stop_attempt: int | None = None, blocked: bool = False) -> tuple[dict[str, Any], int]:
    state = ctx.load()
    if not state:
        raise ValueError("round state not found")
    if stop_attempt is None:
        stop_attempt = int(state.get("stop_attempts", 0)) + 1
    state["stop_attempts"] = max(int(state.get("stop_attempts", 0)), stop_attempt)
    try:
        report = validate_state(state, ctx.events())
    except Exception as exc:  # fail-open at host boundary, never complete in core state
        state["health"] = "degraded"
        report = {"valid": False, "health": "degraded", "errors": [f"validator exception: {type(exc).__name__}"], "warnings": []}
    rollout_observation = {
        "contract": "RolloutObservation/v3",
        "observation_id": f"round-{state.get('session')}-{state.get('round')}",
        "kind": "round_outcome",
        "source_contract": "RoundFinalization/v3",
        "source_id": f"{state.get('session')}:{state.get('round')}",
        "nontrivial": bool(state.get("tasks") or state.get("changes", {}).get("files")),
        "terminal_candidate": "complete" if report.get("valid") else "incomplete",
        "adjudication_pending": True,
    }
    rollout_observation["attestation"] = sign_record(rollout_observation)
    try:
        def update_rollout(current: dict[str, Any]) -> dict[str, Any]:
            target = copy.deepcopy(current or state.get("rollout", {}))
            if any(
                isinstance(row, dict) and row.get("observation_id") == rollout_observation["observation_id"]
                for row in target.get("observations", [])
            ):
                return target
            return apply_observation(target, rollout_observation)

        state["rollout"] = ctx.update_project_rollout(update_rollout)
    except Exception as exc:
        state["health"] = "degraded"
        report.setdefault("errors", []).append(f"project rollout persistence degraded: {type(exc).__name__}")
        report["valid"] = False
        report["health"] = "degraded"
    valid_waived = set(report.get("waived_criteria", []))
    if blocked:
        terminal, exit_code = "blocked", EXIT_BLOCKED
    elif state.get("health") == "degraded" or report.get("health") == "degraded":
        terminal, exit_code = "incomplete", EXIT_DEGRADED
    elif report.get("valid") and valid_waived:
        terminal, exit_code = "user-waived", EXIT_COMPLETE
    elif report.get("valid"):
        terminal, exit_code = "complete", EXIT_COMPLETE
    else:
        terminal, exit_code = "incomplete", EXIT_INCOMPLETE
    state["terminal_state"] = terminal
    state["validation"] = report
    state["updated_at"] = utc_now()
    state["host_gate"] = {
        "should_block": terminal == "incomplete" and state["stop_attempts"] <= 2 and state.get("execution_mode") == "enforce",
        "stop_cap_reached": state["stop_attempts"] > 2,
        "note": "stop cap only releases the host loop; it never converts unresolved work to complete",
    }
    ctx.save(state)
    ctx.append_event(
        {
            "event_type": "round_finalized",
            "status": terminal,
            "exit_code": exit_code,
            "stop_attempt": state["stop_attempts"],
            "error_count": len(report.get("errors", [])),
        }
    )
    ctx.append_event(rollout_observation)
    return state, exit_code
