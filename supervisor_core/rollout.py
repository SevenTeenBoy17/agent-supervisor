from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

from .attestation import verify_record
from .storage import atomic_write_json
from .util import json_load, utc_now


def initial_rollout(project_config: dict[str, Any], execution_mode: str, previous: dict[str, Any] | None = None) -> dict[str, Any]:
    if isinstance(previous, dict) and previous.get("contract") == "RolloutState/v3":
        state = copy.deepcopy(previous)
        state["policy"] = copy.deepcopy(project_config.get("rollout", {}))
        state["requested_mode"] = execution_mode
        state["updated_at"] = utc_now()
        return state
    rollout_policy = project_config.get("rollout", {}) if isinstance(project_config.get("rollout"), dict) else {}
    brown_zone = rollout_policy.get("brown_zone_canary", {}) if isinstance(rollout_policy.get("brown_zone_canary"), dict) else {}
    cross_project = rollout_policy.get("cross_project_default", {}) if isinstance(rollout_policy.get("cross_project_default"), dict) else {}
    initial_mode = str(brown_zone.get("initial_mode") or cross_project.get("mode") or "observe")
    if initial_mode not in {"observe", "warn"}:
        initial_mode = "observe"
    return {
        "contract": "RolloutState/v3",
        "active_mode": initial_mode,
        "requested_mode": execution_mode,
        "policy": copy.deepcopy(project_config.get("rollout", {})),
        "observations": [],
        "metrics": {
            "fixtures_green": False,
            "historical_replay_green": False,
            "nontrivial_rounds": 0,
            "adjudicated_rounds": 0,
            "critical_misses": 0,
            "false_blocks": 0,
            "false_block_rate": 0.0,
            "consecutive_global_gate_failures": 0,
        },
        "promotion": {"eligible_warn": False, "eligible_enforce": False, "recommended_mode": "observe"},
        "rollback": {"required": False, "performed": False, "target": None},
        "updated_at": utc_now(),
    }


def _canary_policy(state: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    policy = state.get("policy", {}) if isinstance(state.get("policy"), dict) else {}
    canary = policy.get("brown_zone_canary", {}) if isinstance(policy.get("brown_zone_canary"), dict) else {}
    other = policy.get("cross_project_default", {}) if isinstance(policy.get("cross_project_default"), dict) else {}
    is_brown_zone = bool(canary)
    return (canary.get("enforce_requires", {}) if is_brown_zone else other), is_brown_zone


def apply_observation(state: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
    if record.get("contract") != "RolloutObservation/v3" or not str(record.get("observation_id") or "").strip():
        raise ValueError("rollout observation contract/id invalid")
    if record.get("source_contract") not in {"GateExecution/v3", "RoundFinalization/v3"} or not verify_record(record):
        raise ValueError("rollout observation must carry a trusted core execution/finalization attestation")
    rows = state.setdefault("observations", [])
    if any(isinstance(row, dict) and row.get("observation_id") == record["observation_id"] for row in rows):
        raise ValueError("duplicate rollout observation")
    kind = record.get("kind")
    metrics = state.setdefault("metrics", {})
    if kind == "fixture_replay":
        metrics["fixtures_green"] = record.get("passed") is True
    elif kind == "historical_replay":
        metrics["historical_replay_green"] = record.get("passed") is True
    elif kind == "round_outcome":
        if record.get("nontrivial") is True:
            metrics["nontrivial_rounds"] = int(metrics.get("nontrivial_rounds", 0)) + 1
        if record.get("critical_miss") is True:
            metrics["critical_misses"] = int(metrics.get("critical_misses", 0)) + 1
        if isinstance(record.get("false_block"), bool):
            metrics["adjudicated_rounds"] = int(metrics.get("adjudicated_rounds", 0)) + 1
            if record.get("false_block") is True:
                metrics["false_blocks"] = int(metrics.get("false_blocks", 0)) + 1
    elif kind == "global_gate":
        if record.get("result") == "failed":
            metrics["consecutive_global_gate_failures"] = int(metrics.get("consecutive_global_gate_failures", 0)) + 1
        elif record.get("result") == "success":
            metrics["consecutive_global_gate_failures"] = 0
        else:
            raise ValueError("global_gate observation result invalid")
    else:
        raise ValueError("rollout observation kind invalid")
    rounds = max(0, int(metrics.get("nontrivial_rounds", 0)))
    false_blocks = max(0, int(metrics.get("false_blocks", 0)))
    adjudicated = max(0, int(metrics.get("adjudicated_rounds", 0)))
    metrics["false_block_rate"] = false_blocks / adjudicated if adjudicated else 0.0
    thresholds, is_brown_zone = _canary_policy(state)
    eligible_warn = bool(metrics.get("fixtures_green") and metrics.get("historical_replay_green"))
    # A rate without a denominator is not canary evidence. Brown Zone may use a
    # shorter canary than other projects, but it still needs at least one real,
    # non-trivial round before enforce can become eligible.
    minimum_rounds = (
        max(1, int(thresholds.get("promotion_requires_nontrivial_rounds", 1)))
        if is_brown_zone
        else int(thresholds.get("promotion_requires_nontrivial_rounds", 20))
    )
    max_false_rate = float(thresholds.get("max_false_block_rate", 0.02))
    required_misses = int(thresholds.get("critical_misses", 0))
    eligible_enforce = (
        eligible_warn
        and rounds >= minimum_rounds
        and adjudicated >= rounds
        and int(metrics.get("critical_misses", 0)) <= required_misses
        and metrics["false_block_rate"] <= max_false_rate
    )
    state["promotion"] = {
        "eligible_warn": eligible_warn,
        "eligible_enforce": eligible_enforce,
        "recommended_mode": "enforce" if eligible_enforce else ("warn" if eligible_warn else "observe"),
        "automatic_cross_project_enforcement": False,
    }
    if int(metrics.get("consecutive_global_gate_failures", 0)) >= 2:
        state["rollback"]["required"] = True
    rows.append(copy.deepcopy(record))
    state["updated_at"] = utc_now()
    return state


def promote(state: dict[str, Any], requested_mode: str) -> None:
    current = str(state.get("active_mode") or "observe")
    recorded = copy.deepcopy(state.get("observations", [])) if isinstance(state.get("observations"), list) else []
    replayed = initial_rollout({"rollout": copy.deepcopy(state.get("policy", {}))}, current)
    replayed["active_mode"] = current
    for observation in recorded:
        apply_observation(replayed, observation)
    state["metrics"] = replayed["metrics"]
    state["promotion"] = replayed["promotion"]
    state["rollback"] = replayed["rollback"]
    order = {"observe": 0, "warn": 1, "enforce": 2}
    if requested_mode not in order or order[requested_mode] < order.get(current, 0):
        raise ValueError("rollout promotion must move forward one stage")
    if requested_mode == "warn" and not state.get("promotion", {}).get("eligible_warn"):
        raise ValueError("warn promotion metrics are not satisfied")
    if requested_mode == "enforce" and not state.get("promotion", {}).get("eligible_enforce"):
        raise ValueError("enforce promotion metrics are not satisfied")
    if order[requested_mode] > order.get(current, 0) + 1:
        raise ValueError("rollout cannot skip a stage")
    state["active_mode"] = requested_mode
    state["promoted_at"] = utc_now()


def active_pointer_path() -> Path:
    configured = os.environ.get("AGENT_SUPERVISOR_ACTIVE_POINTER")
    return Path(configured).expanduser() if configured else Path.home() / ".agent-supervisor" / "active-version.json"


def rollback_active_version() -> dict[str, Any]:
    path = active_pointer_path()
    pointer = json_load(path, {})
    active = pointer.get("active") if isinstance(pointer, dict) else None
    previous = pointer.get("previous") if isinstance(pointer, dict) else None
    previous_path = Path(str(previous.get("path"))) if isinstance(previous, dict) and previous.get("path") else None
    if not isinstance(active, dict) or not previous_path or not previous_path.is_dir():
        return {"performed": False, "reason": "previous-version-unavailable", "target": None}
    updated = {
        "contract": "ActiveVersionPointer/v3",
        "active": previous,
        "previous": active,
        "rolled_back_at": utc_now(),
        "rolled_back_from": active.get("version"),
    }
    atomic_write_json(path, updated)
    return {"performed": True, "reason": "two-consecutive-global-gate-failures", "target": previous.get("version"), "path": str(previous_path)}


def resolve_active_root(default_root: Path) -> Path:
    pointer = json_load(active_pointer_path(), {})
    active = pointer.get("active") if isinstance(pointer, dict) else None
    path = Path(str(active.get("path"))) if isinstance(active, dict) and active.get("path") else default_root
    return path if (path / "supervisor_core").is_dir() else default_root
