from __future__ import annotations

import json

from supervisor_core.attestation import sign_record
from supervisor_core.rollout import active_version_snapshot, apply_observation, initial_rollout, promote, rollback_active_version


def observation(identifier: str, kind: str, **values):
    if kind == "global_gate" and "active_version" not in values:
        values["active_version"] = {"version": "3.1.0", "path": "C:/agent-supervisor/3.1.0"}
    record = {
        "contract": "RolloutObservation/v3",
        "observation_id": identifier,
        "kind": kind,
        "source_contract": "GateExecution/v3",
        "source_id": f"execution-{identifier}",
        **values,
    }
    record["attestation"] = sign_record(record)
    return record


def test_observe_warn_enforce_metrics_and_cross_project_floor():
    config = {
        "rollout": {
            "cross_project_default": {
                "promotion_requires_nontrivial_rounds": 20,
                "critical_misses": 0,
                "max_false_block_rate": 0.02,
            }
        }
    }
    state = initial_rollout(config, "observe")
    apply_observation(state, observation("fixtures", "fixture_replay", passed=True))
    apply_observation(state, observation("history", "historical_replay", passed=True))
    assert state["promotion"]["eligible_warn"] is True
    assert state["promotion"]["eligible_enforce"] is False
    promote(state, "warn")
    for index in range(20):
        apply_observation(state, observation(f"round-{index}", "round_outcome", nontrivial=True, critical_miss=False, false_block=False))
    assert state["promotion"]["eligible_enforce"] is True
    assert state["promotion"]["automatic_cross_project_enforcement"] is False
    promote(state, "enforce")
    assert state["active_mode"] == "enforce"


def test_brown_zone_canary_needs_a_real_nontrivial_round_before_enforce():
    config = {
        "rollout": {
            "brown_zone_canary": {
                "enforce_requires": {
                    "critical_misses": 0,
                    "max_false_block_rate": 0.02,
                }
            }
        }
    }
    state = initial_rollout(config, "observe")
    apply_observation(state, observation("fixtures", "fixture_replay", passed=True))
    apply_observation(state, observation("history", "historical_replay", passed=True))
    assert state["promotion"]["eligible_warn"] is True
    assert state["promotion"]["eligible_enforce"] is False
    apply_observation(
        state,
        observation("real-round", "round_outcome", nontrivial=True, critical_miss=False, false_block=False),
    )
    assert state["promotion"]["eligible_enforce"] is True


def test_direct_enforce_request_is_downgraded_to_policy_initial_mode():
    config = {"rollout": {"brown_zone_canary": {"initial_mode": "observe"}}}
    state = initial_rollout(config, "enforce")
    assert state["active_mode"] == "observe"
    assert state["requested_mode"] == "enforce"


def test_untrusted_rollout_observation_is_rejected():
    state = initial_rollout({}, "observe")
    untrusted = {"contract": "RolloutObservation/v3", "observation_id": "fake", "kind": "fixture_replay", "passed": True}
    try:
        apply_observation(state, untrusted)
    except ValueError as exc:
        assert "local-core integrity" in str(exc)
    else:
        raise AssertionError("model-authored rollout observation was accepted")


def test_two_global_gate_failures_atomically_switch_active_pointer(tmp_path, monkeypatch):
    current = tmp_path / "current"
    previous = tmp_path / "previous"
    (current / "supervisor_core").mkdir(parents=True)
    (previous / "supervisor_core").mkdir(parents=True)
    pointer = tmp_path / "active-version.json"
    pointer.write_text(json.dumps({
        "contract": "ActiveVersionPointer/v3",
        "active": {"version": "3.1.0", "path": str(current)},
        "previous": {"version": "3.0.0", "path": str(previous)},
    }), encoding="utf-8")
    monkeypatch.setenv("AGENT_SUPERVISOR_ACTIVE_POINTER", str(pointer))
    state = initial_rollout({}, "warn")
    apply_observation(state, observation("failure-1", "global_gate", result="failed"))
    assert state["rollback"]["required"] is False
    apply_observation(state, observation("failure-2", "global_gate", result="failed"))
    assert state["rollback"]["required"] is True
    expected_active = json.loads(pointer.read_text(encoding="utf-8"))["active"]
    result = rollback_active_version(expected_active=expected_active)
    assert result["performed"] is True
    assert json.loads(pointer.read_text(encoding="utf-8"))["active"]["version"] == "3.0.0"
    repeated = rollback_active_version(expected_active=expected_active)
    assert repeated["performed"] is True
    assert repeated["idempotent"] is True
    assert json.loads(pointer.read_text(encoding="utf-8"))["active"]["version"] == "3.0.0"
    unrelated = {"version": "4.0.0", "path": str(tmp_path / "unrelated")}
    mismatch = rollback_active_version(expected_active=unrelated)
    assert mismatch["performed"] is False
    assert mismatch["reason"] == "active-version-cas-mismatch"
    assert json.loads(pointer.read_text(encoding="utf-8"))["active"]["version"] == "3.0.0"


def test_absent_snapshot_cannot_rollback_pointer_that_appears_later(tmp_path, monkeypatch):
    pointer = tmp_path / "active-version.json"
    monkeypatch.setenv("AGENT_SUPERVISOR_ACTIVE_POINTER", str(pointer))
    expected_active = active_version_snapshot()
    assert expected_active is None

    new_release = tmp_path / "new-release"
    old_release = tmp_path / "old-release"
    (new_release / "supervisor_core").mkdir(parents=True)
    (old_release / "supervisor_core").mkdir(parents=True)
    pointer.write_text(json.dumps({
        "contract": "ActiveVersionPointer/v3",
        "active": {"version": "4.0.0", "path": str(new_release)},
        "previous": {"version": "3.0.1", "path": str(old_release)},
    }), encoding="utf-8")

    result = rollback_active_version(expected_active=expected_active)
    assert result == {"performed": False, "reason": "expected-active-identity-required", "target": None}
    assert json.loads(pointer.read_text(encoding="utf-8"))["active"]["version"] == "4.0.0"


def test_global_gate_failure_streak_is_bound_to_active_identity():
    state = initial_rollout({}, "warn")
    apply_observation(state, observation("unbound-1", "global_gate", result="failed", active_version=None))
    apply_observation(state, observation("unbound-2", "global_gate", result="failed", active_version=None))
    assert state["metrics"]["unbound_global_gate_failures"] == 2
    assert state["metrics"]["consecutive_global_gate_failures"] == 0
    assert state["rollback"]["required"] is False

    release_a = {"version": "4.0.0", "path": "C:/agent-supervisor/4.0.0"}
    release_b = {"version": "4.1.0", "path": "C:/agent-supervisor/4.1.0"}
    apply_observation(state, observation("release-a-1", "global_gate", result="failed", active_version=release_a))
    assert state["metrics"]["consecutive_global_gate_failures"] == 1
    assert state["rollback"]["required"] is False
    apply_observation(state, observation("release-a-2", "global_gate", result="failed", active_version=release_a))
    assert state["rollback"]["required"] is True

    apply_observation(state, observation("release-b-1", "global_gate", result="failed", active_version=release_b))
    assert state["metrics"]["global_gate_active_identity"] == release_b
    assert state["metrics"]["consecutive_global_gate_failures"] == 1
    assert state["rollback"]["required"] is False
