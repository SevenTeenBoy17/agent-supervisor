from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

from .attestation import verify_record
from .storage import atomic_write_json, exclusive_lock
from .util import json_load, utc_now


def _empty_rollback() -> dict[str, Any]:
    return {"required": False, "performed": False, "target": None}


def reset_rollback_cycle(state: dict[str, Any], reason: str) -> dict[str, Any]:
    current = state.get("rollback") if isinstance(state.get("rollback"), dict) else {}
    if current.get("required") or current.get("attempted") or current.get("performed"):
        history = state.setdefault("rollback_history", [])
        if isinstance(history, list):
            archived = copy.deepcopy(current)
            archived["reset_reason"] = reason
            archived["reset_at"] = utc_now()
            history.append(archived)
            del history[:-20]
    state["rollback"] = _empty_rollback()
    return state["rollback"]


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
            "global_gate_active_identity": None,
            "unbound_global_gate_failures": 0,
        },
        "promotion": {"eligible_warn": False, "eligible_enforce": False, "recommended_mode": "observe"},
        "rollback": _empty_rollback(),
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
        raise ValueError("rollout observation must carry a valid local-core integrity attestation")
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
        active_identity = record.get("active_version")
        identity_valid = _valid_active_identity(active_identity)
        rollback = state.setdefault("rollback", _empty_rollback())
        if not identity_valid:
            metrics["unbound_global_gate_failures"] = int(metrics.get("unbound_global_gate_failures", 0)) + (
                1 if record.get("result") == "failed" else 0
            )
            metrics["consecutive_global_gate_failures"] = 0
            metrics["global_gate_active_identity"] = None
            if rollback.get("performed") is not True:
                rollback = reset_rollback_cycle(state, "unbound-global-gate-observation")
        else:
            active_identity = copy.deepcopy(active_identity)
            prior_identity = metrics.get("global_gate_active_identity")
            if prior_identity != active_identity:
                metrics["consecutive_global_gate_failures"] = 0
                metrics["global_gate_active_identity"] = active_identity
                if rollback.get("performed") is True:
                    known_identities = [rollback.get("expected_active"), rollback.get("target_active")]
                    if active_identity not in [item for item in known_identities if isinstance(item, dict)]:
                        rollback = reset_rollback_cycle(state, "new-active-version-observed")
                elif rollback.get("attempted") or rollback.get("required"):
                    recoverable_claim = (
                        str(rollback.get("claim_status") or "") in {"in_progress", "retriable"}
                        and _valid_active_identity(rollback.get("expected_active"))
                    )
                    if not recoverable_claim:
                        rollback = reset_rollback_cycle(state, "new-bound-failure-cycle")
            if record.get("result") == "failed":
                metrics["consecutive_global_gate_failures"] = int(metrics.get("consecutive_global_gate_failures", 0)) + 1
            elif record.get("result") == "success":
                metrics["consecutive_global_gate_failures"] = 0
                if rollback.get("performed") is not True:
                    rollback["required"] = False
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
    if _valid_active_identity(metrics.get("global_gate_active_identity")) and int(metrics.get("consecutive_global_gate_failures", 0)) >= 2:
        state["rollback"]["required"] = True
    rows.append(copy.deepcopy(record))
    state["updated_at"] = utc_now()
    return state


def promote(state: dict[str, Any], requested_mode: str) -> None:
    current = str(state.get("active_mode") or "observe")
    rollback_lineage = copy.deepcopy(state.get("rollback", {})) if isinstance(state.get("rollback"), dict) else {}
    recorded = copy.deepcopy(state.get("observations", [])) if isinstance(state.get("observations"), list) else []
    replayed = initial_rollout({"rollout": copy.deepcopy(state.get("policy", {}))}, current)
    replayed["active_mode"] = current
    for observation in recorded:
        apply_observation(replayed, observation)
    state["metrics"] = replayed["metrics"]
    state["promotion"] = replayed["promotion"]
    replayed_rollback = replayed["rollback"]
    if rollback_lineage.get("attempted") is True or rollback_lineage.get("performed") is True:
        replayed_required = replayed_rollback.get("required") is True
        replayed_rollback.update(rollback_lineage)
        replayed_rollback["required"] = replayed_required or rollback_lineage.get("required") is True
    state["rollback"] = replayed_rollback
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


def _pointer_lock_path(path: Path) -> Path:
    return path.with_name(f".{path.name}.lock")


def _valid_active_identity(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and bool(str(value.get("version") or "").strip())
        and bool(str(value.get("path") or "").strip())
    )


def active_version_snapshot() -> dict[str, Any] | None:
    """Read the active release identity under the same lock used for pointer replacement."""
    path = active_pointer_path()
    with exclusive_lock(_pointer_lock_path(path)):
        pointer = json_load(path, {})
        active = pointer.get("active") if isinstance(pointer, dict) else None
        return copy.deepcopy(active) if _valid_active_identity(active) else None


def rollback_active_version(*, expected_active: dict[str, Any] | None) -> dict[str, Any]:
    """CAS the active/previous pointer exactly once under a dedicated pointer lock."""
    if not _valid_active_identity(expected_active):
        return {"performed": False, "reason": "expected-active-identity-required", "target": None}
    path = active_pointer_path()
    with exclusive_lock(_pointer_lock_path(path)):
        pointer = json_load(path, {})
        active = pointer.get("active") if isinstance(pointer, dict) else None
        previous = pointer.get("previous") if isinstance(pointer, dict) else None
        marker = pointer.get("rollback") if isinstance(pointer, dict) and isinstance(pointer.get("rollback"), dict) else {}
        if marker.get("performed") is True:
            marker_expected = marker.get("expected_active")
            marker_target = marker.get("target")
            rollback_lineage_is_active = active == marker_target and previous == marker_expected
            original_claim_replay = marker_expected == expected_active
            rollback_target_observed = expected_active == marker_target and rollback_lineage_is_active
            if original_claim_replay or rollback_target_observed:
                return {
                    "performed": True,
                    "reason": "rollback-lineage-already-active",
                    "target": active.get("version") if isinstance(active, dict) else None,
                    "target_active": copy.deepcopy(active) if isinstance(active, dict) else None,
                    "path": active.get("path") if isinstance(active, dict) else None,
                    "idempotent": True,
                }
        if active != expected_active:
            return {
                "performed": False,
                "reason": "active-version-cas-mismatch",
                "target": active.get("version") if isinstance(active, dict) else None,
            }
        previous_path = Path(str(previous.get("path"))) if isinstance(previous, dict) and previous.get("path") else None
        if not isinstance(active, dict) or not previous_path or not previous_path.is_dir():
            return {"performed": False, "reason": "previous-version-unavailable", "target": None}
        expected = copy.deepcopy(expected_active)
        rolled_back_at = utc_now()
        updated = {
            "contract": "ActiveVersionPointer/v3",
            "active": previous,
            "previous": active,
            "rolled_back_at": rolled_back_at,
            "rolled_back_from": active.get("version"),
            "rollback": {
                "performed": True,
                "expected_active": expected,
                "target": copy.deepcopy(previous),
                "performed_at": rolled_back_at,
            },
        }
        atomic_write_json(path, updated)
        return {
            "performed": True,
            "reason": "two-consecutive-global-gate-failures",
            "target": previous.get("version"),
            "target_active": copy.deepcopy(previous),
            "path": str(previous_path),
            "idempotent": False,
        }


def resolve_active_root(default_root: Path) -> Path:
    pointer = json_load(active_pointer_path(), {})
    active = pointer.get("active") if isinstance(pointer, dict) else None
    path = Path(str(active.get("path"))) if isinstance(active, dict) and active.get("path") else default_root
    return path if (path / "supervisor_core").is_dir() else default_root
