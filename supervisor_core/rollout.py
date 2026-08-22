from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

from .attestation import key_path, sign_record, verify_record
from .storage import atomic_write_json, exclusive_lock
from .util import canonical_sha256, json_load, utc_now


_MIN_OBSERVATION_RETENTION = 64
_RETENTION_OVERHEAD = 8
_MAX_PROMOTION_WINDOW = 10_000
_MAX_COMPACTED_ID_RETENTION = _MAX_PROMOTION_WINDOW + _RETENTION_OVERHEAD
_ZERO_SHA256 = "0" * 64


class RolloutReplayIntegrityError(ValueError):
    """A persisted rollout ledger cannot be safely replayed."""


def _attestation_key_ready() -> bool:
    try:
        return len(key_path().read_bytes()) >= 32
    except (OSError, RuntimeError):
        return False


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
    normalized_requested = str(execution_mode).strip().casefold()
    if normalized_requested not in {"observe", "warn", "enforce"}:
        raise ValueError("rollout requested mode invalid")
    if isinstance(previous, dict) and previous.get("contract") == "RolloutState/v3":
        state = copy.deepcopy(previous)
        normalized_active = str(state.get("active_mode") or "").strip().casefold()
        if normalized_active not in {"observe", "warn", "enforce"}:
            raise ValueError("rollout active mode invalid")
        state["active_mode"] = normalized_active
        state["policy"] = copy.deepcopy(project_config.get("rollout", {}))
        state["requested_mode"] = normalized_requested
        state["updated_at"] = utc_now()
        return state
    rollout_policy = project_config.get("rollout", {}) if isinstance(project_config.get("rollout"), dict) else {}
    brown_zone = rollout_policy.get("brown_zone_canary", {}) if isinstance(rollout_policy.get("brown_zone_canary"), dict) else {}
    cross_project = rollout_policy.get("cross_project_default", {}) if isinstance(rollout_policy.get("cross_project_default"), dict) else {}
    initial_mode = str(brown_zone.get("initial_mode") or cross_project.get("mode") or "observe").strip().casefold()
    if initial_mode not in {"observe", "warn"}:
        initial_mode = "observe"
    return {
        "contract": "RolloutState/v3",
        "active_mode": initial_mode,
        "requested_mode": normalized_requested,
        "policy": copy.deepcopy(project_config.get("rollout", {})),
        "observations": [],
        "observation_checkpoint": None,
        "observation_total_count": 0,
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


def _promotion_minimum_rounds(state: dict[str, Any]) -> int:
    thresholds, is_brown_zone = _canary_policy(state)
    default = 1 if is_brown_zone else 20
    minimum_rounds = max(1, int(thresholds.get("promotion_requires_nontrivial_rounds", default)))
    if minimum_rounds > _MAX_PROMOTION_WINDOW:
        raise ValueError(
            f"promotion_requires_nontrivial_rounds exceeds bounded maximum {_MAX_PROMOTION_WINDOW}"
        )
    return minimum_rounds


def _observation_retention_limit(state: dict[str, Any]) -> int:
    """Keep at least the effective promotion window plus fixed control-event headroom."""
    return max(_MIN_OBSERVATION_RETENTION, _promotion_minimum_rounds(state) + _RETENTION_OVERHEAD)


def _refresh_derived_state(state: dict[str, Any]) -> None:
    metrics = state.get("metrics")
    if not isinstance(metrics, dict):
        raise ValueError("rollout metrics must be an object")
    rounds = max(0, int(metrics.get("nontrivial_rounds", 0)))
    false_blocks = max(0, int(metrics.get("false_blocks", 0)))
    adjudicated = max(0, int(metrics.get("adjudicated_rounds", 0)))
    metrics["false_block_rate"] = false_blocks / adjudicated if adjudicated else 0.0
    thresholds, _ = _canary_policy(state)
    eligible_warn = bool(metrics.get("fixtures_green") and metrics.get("historical_replay_green"))
    minimum_rounds = _promotion_minimum_rounds(state)
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


def _valid_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _validated_checkpoint_ids(state: dict[str, Any], checkpoint: Any) -> list[str]:
    if not (
        isinstance(checkpoint, dict)
        and checkpoint.get("contract") == "RolloutCheckpoint/v3"
        and isinstance(checkpoint.get("covered_observations"), int)
        and not isinstance(checkpoint.get("covered_observations"), bool)
        and checkpoint.get("covered_observations") >= 1
        and _valid_sha256(checkpoint.get("history_sha256"))
        and isinstance(checkpoint.get("metrics"), dict)
        and isinstance(checkpoint.get("rollback"), dict)
        and isinstance(checkpoint.get("rollback_history", []), list)
        and verify_record(checkpoint)
    ):
        raise ValueError("rollout observation checkpoint integrity invalid")
    if "compacted_observation_ids" in checkpoint:
        raw_ids = checkpoint.get("compacted_observation_ids")
        if not isinstance(raw_ids, list):
            raise ValueError("rollout observation checkpoint compacted ids invalid")
        compacted_ids = [item for item in raw_ids if isinstance(item, str) and item.strip()]
        if len(compacted_ids) != len(raw_ids):
            raise ValueError("rollout observation checkpoint compacted ids invalid")
    else:
        # v3 checkpoints written before the bounded replay index carried only
        # the signed newest compacted id. Preserve that protection during the
        # first upgrade compaction instead of invalidating persisted rollout state.
        legacy_last = checkpoint.get("last_observation_id")
        compacted_ids = [legacy_last] if isinstance(legacy_last, str) and legacy_last.strip() else []
    declared_limit = checkpoint.get(
        "compacted_observation_id_limit",
        _observation_retention_limit(state),
    )
    if (
        not compacted_ids
        or not isinstance(declared_limit, int)
        or isinstance(declared_limit, bool)
        or declared_limit < _MIN_OBSERVATION_RETENTION
        or declared_limit > _MAX_COMPACTED_ID_RETENTION
        or len(compacted_ids) > declared_limit
        or len(compacted_ids) > int(checkpoint["covered_observations"])
        or len(set(compacted_ids)) != len(compacted_ids)
        or checkpoint.get("last_observation_id") != compacted_ids[-1]
    ):
        raise ValueError("rollout observation checkpoint compacted ids invalid")
    return compacted_ids


def checkpoint_observation_ids(state: dict[str, Any]) -> frozenset[str]:
    """Return attested compacted observation IDs without mutating rollout state."""
    if not isinstance(state, dict):
        raise ValueError("rollout state must be an object")
    checkpoint = state.get("observation_checkpoint")
    if checkpoint is None:
        return frozenset()
    return frozenset(_validated_checkpoint_ids(state, checkpoint))


def _restore_checkpoint(state: dict[str, Any], checkpoint: Any) -> tuple[int, list[str]]:
    compacted_ids = _validated_checkpoint_ids(state, checkpoint)
    state["metrics"] = copy.deepcopy(checkpoint["metrics"])
    state["rollback"] = copy.deepcopy(checkpoint["rollback"])
    state["rollback_history"] = copy.deepcopy(checkpoint.get("rollback_history", []))
    state["observation_total_count"] = int(checkpoint["covered_observations"])
    _refresh_derived_state(state)
    return int(checkpoint["covered_observations"]), compacted_ids


def _compact_observations(state: dict[str, Any]) -> None:
    rows = state.get("observations")
    if not isinstance(rows, list):
        raise ValueError("rollout observations must be an array")
    limit = _observation_retention_limit(state)
    checkpoint = state.get("observation_checkpoint")
    checkpoint_count = 0
    checkpoint_ids: list[str] = []
    scratch: dict[str, Any] | None = None
    if checkpoint is not None:
        scratch = initial_rollout({"rollout": copy.deepcopy(state.get("policy", {}))}, state.get("active_mode", "observe"))
        checkpoint_count, checkpoint_ids = _restore_checkpoint(scratch, checkpoint)
    if len(rows) <= limit:
        state["observation_total_count"] = checkpoint_count + len(rows)
        return

    compact_count = len(rows) - limit
    compacted = copy.deepcopy(rows[:compact_count])
    scratch = scratch or initial_rollout({"rollout": copy.deepcopy(state.get("policy", {}))}, state.get("active_mode", "observe"))
    prior_history = _ZERO_SHA256
    covered = checkpoint_count
    if checkpoint is not None:
        prior_history = str(checkpoint["history_sha256"])
    for observation in compacted:
        apply_observation(scratch, observation, _compact=False)
    history_sha256 = canonical_sha256({
        "prior_history_sha256": prior_history,
        "observation_sha256": [canonical_sha256(observation) for observation in compacted],
    })
    recent_compacted_ids = (
        checkpoint_ids + [str(observation["observation_id"]) for observation in compacted]
    )[-limit:]
    new_checkpoint: dict[str, Any] = {
        "contract": "RolloutCheckpoint/v3",
        "covered_observations": covered + compact_count,
        "history_sha256": history_sha256,
        "last_observation_id": recent_compacted_ids[-1],
        "compacted_observation_ids": recent_compacted_ids,
        "compacted_observation_id_limit": limit,
        "metrics": copy.deepcopy(scratch["metrics"]),
        "rollback": copy.deepcopy(scratch["rollback"]),
        "rollback_history": copy.deepcopy(scratch.get("rollback_history", [])),
        "compacted_at": utc_now(),
    }
    new_checkpoint["attestation"] = sign_record(new_checkpoint)
    state["observation_checkpoint"] = new_checkpoint
    del rows[:compact_count]
    state["observation_total_count"] = new_checkpoint["covered_observations"] + len(rows)


def apply_observation(
    state: dict[str, Any],
    record: dict[str, Any],
    *,
    _compact: bool = True,
) -> dict[str, Any]:
    if not isinstance(state, dict) or not isinstance(record, dict):
        raise ValueError("rollout state and observation must be objects")
    observation_id = record.get("observation_id")
    if (
        record.get("contract") != "RolloutObservation/v3"
        or not isinstance(observation_id, str)
        or not observation_id.strip()
    ):
        raise ValueError("rollout observation contract/id invalid")
    if record.get("source_contract") not in {"GateExecution/v3", "RoundFinalization/v3"} or not verify_record(record):
        raise ValueError("rollout observation must carry a valid local-core integrity attestation")
    kind = record.get("kind")
    if kind == "global_gate" and record.get("result") not in {"failed", "success"}:
        raise ValueError("global_gate observation result invalid")
    rows = state.get("observations")
    if rows is None and "observations" not in state:
        rows = []
        state["observations"] = rows
    if not isinstance(rows, list):
        raise ValueError("rollout observations must be an array")
    if any(isinstance(row, dict) and row.get("observation_id") == observation_id for row in rows):
        raise ValueError("duplicate rollout observation")
    checkpoint = state.get("observation_checkpoint")
    if checkpoint is not None and observation_id in _validated_checkpoint_ids(state, checkpoint):
        raise ValueError("duplicate compacted rollout observation")
    metrics = state.get("metrics")
    if metrics is None and "metrics" not in state:
        metrics = {}
        state["metrics"] = metrics
    if not isinstance(metrics, dict):
        raise ValueError("rollout metrics must be an object")
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
        rollback = state.get("rollback")
        if rollback is None and "rollback" not in state:
            rollback = _empty_rollback()
            state["rollback"] = rollback
        if not isinstance(rollback, dict):
            raise ValueError("rollout rollback state must be an object")
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
        raise ValueError("rollout observation kind invalid")
    _refresh_derived_state(state)
    rollback_state = state.get("rollback")
    if rollback_state is None and "rollback" not in state:
        rollback_state = _empty_rollback()
        state["rollback"] = rollback_state
    if not isinstance(rollback_state, dict):
        raise ValueError("rollout rollback state must be an object")
    if rollback_state.get("performed") is True:
        rollback_state["required"] = False
    elif (
        _valid_active_identity(metrics.get("global_gate_active_identity"))
        and int(metrics.get("consecutive_global_gate_failures", 0)) >= 2
    ):
        rollback_state["required"] = True
    rows.append(copy.deepcopy(record))
    if _compact:
        _compact_observations(state)
    else:
        state["observation_total_count"] = int(state.get("observation_total_count", 0)) + 1
    state["updated_at"] = utc_now()
    return state


def promote(state: dict[str, Any], requested_mode: str) -> None:
    order = {"observe": 0, "warn": 1, "enforce": 2}
    requested_mode = str(requested_mode).strip().casefold()
    current = str(state.get("active_mode") or "").strip().casefold()
    if current not in order:
        raise ValueError("rollout active mode invalid")
    if requested_mode not in order or order[requested_mode] < order[current]:
        raise ValueError("rollout promotion must move forward one stage")
    if order[requested_mode] > order[current] + 1:
        raise ValueError("rollout cannot skip a stage")
    rollback_lineage = copy.deepcopy(state.get("rollback", {})) if isinstance(state.get("rollback"), dict) else {}
    raw_recorded = state.get("observations")
    if not isinstance(raw_recorded, list):
        raise RolloutReplayIntegrityError("rollout replay observations are not an array")
    recorded = copy.deepcopy(raw_recorded)
    checkpoint = copy.deepcopy(state.get("observation_checkpoint"))
    if (recorded or checkpoint is not None) and not _attestation_key_ready():
        raise RolloutReplayIntegrityError("rollout replay attestation key unavailable or invalid")
    replayed = initial_rollout({"rollout": copy.deepcopy(state.get("policy", {}))}, current)
    replayed["active_mode"] = current
    try:
        if checkpoint is not None:
            covered, compacted_ids = _restore_checkpoint(replayed, checkpoint)
        else:
            covered, compacted_ids = 0, []
        expected_total = covered + len(recorded)
        if "observation_total_count" in state and state.get("observation_total_count") != expected_total:
            raise ValueError("rollout observation count does not match checkpoint lineage")
        for observation in recorded:
            if isinstance(observation, dict) and observation.get("observation_id") in compacted_ids:
                raise ValueError("retained observation duplicates compacted checkpoint lineage")
            apply_observation(replayed, observation, _compact=False)
    except (TypeError, ValueError) as exc:
        raise RolloutReplayIntegrityError("rollout replay observation integrity invalid") from exc
    replayed_rollback = replayed["rollback"]
    if rollback_lineage.get("attempted") is True or rollback_lineage.get("performed") is True:
        replayed_required = replayed_rollback.get("required") is True
        replayed_rollback.update(rollback_lineage)
        replayed_rollback["required"] = (
            False
            if replayed_rollback.get("performed") is True
            else replayed_required or rollback_lineage.get("required") is True
        )
    if requested_mode == "warn" and not replayed.get("promotion", {}).get("eligible_warn"):
        raise ValueError("warn promotion metrics are not satisfied")
    if requested_mode == "enforce" and not replayed.get("promotion", {}).get("eligible_enforce"):
        raise ValueError("enforce promotion metrics are not satisfied")
    state["metrics"] = replayed["metrics"]
    state["promotion"] = replayed["promotion"]
    state["rollback"] = replayed_rollback
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


def _canonical_supervisor_release_root(path: Path) -> Path | None:
    if not path.is_absolute():
        return None
    lexical = Path(os.path.abspath(os.fspath(path.expanduser())))
    try:
        resolved = lexical.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    if os.path.normcase(str(resolved)) != os.path.normcase(str(lexical)):
        return None
    for relative in (
        Path("supervisor_core") / "__init__.py",
        Path("supervisor_core") / "cli.py",
    ):
        marker = lexical / relative
        try:
            resolved_marker = marker.resolve(strict=True)
        except (OSError, RuntimeError):
            return None
        if (
            os.path.normcase(str(resolved_marker)) != os.path.normcase(str(marker))
            or not resolved_marker.is_file()
        ):
            return None
    return resolved


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
        if not _valid_active_identity(previous):
            return {"performed": False, "reason": "previous-version-unavailable", "target": None}
        previous_path = Path(str(previous.get("path"))) if isinstance(previous, dict) and previous.get("path") else None
        canonical_previous_path = (
            _canonical_supervisor_release_root(previous_path)
            if previous_path and previous_path.is_dir()
            else None
        )
        if not isinstance(active, dict) or not previous_path or canonical_previous_path is None:
            return {"performed": False, "reason": "previous-version-unavailable", "target": None}
        previous_path = canonical_previous_path
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
    packaged_root = Path(__file__).resolve().parents[1]
    fallback = (
        _canonical_supervisor_release_root(Path(default_root))
        or _canonical_supervisor_release_root(packaged_root)
        or packaged_root
    )
    pointer_path = active_pointer_path()
    try:
        with exclusive_lock(_pointer_lock_path(pointer_path)):
            pointer = json_load(pointer_path, {})
    except (OSError, RuntimeError, ValueError):
        return fallback
    active = pointer.get("active") if isinstance(pointer, dict) else None
    if not _valid_active_identity(active):
        return fallback
    candidate = _canonical_supervisor_release_root(Path(str(active["path"])))
    return candidate or fallback
