from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys

import pytest

from supervisor_core import cli as cli_module
from supervisor_core.attestation import sign_record
from supervisor_core.finalize import finalize_round
from supervisor_core.lifecycle import start_round
from supervisor_core.rollout import (
    RolloutReplayIntegrityError,
    active_version_snapshot,
    apply_observation,
    initial_rollout,
    promote,
    rollback_active_version,
)
from supervisor_core.storage import StateContext


@pytest.fixture(autouse=True)
def isolated_attestation_key(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "AGENT_SUPERVISOR_ATTESTATION_KEY_FILE",
        str(tmp_path / "attestation" / "test.key"),
    )


def _write_release_root(path: Path) -> None:
    core = path / "supervisor_core"
    core.mkdir(parents=True)
    (core / "__init__.py").write_text("", encoding="utf-8")
    (core / "cli.py").write_text("", encoding="utf-8")


def test_launcher_rejects_invalid_contract_and_untrusted_active_path(tmp_path):
    fake = tmp_path / "untrusted" / "supervisor_core"
    fake.mkdir(parents=True)
    (fake / "__init__.py").write_text("", encoding="utf-8")
    (fake / "cli.py").write_text(
        "def main():\n    print('UNTRUSTED_POINTER_EXECUTED')\n    return 0\n",
        encoding="utf-8",
    )
    pointer = tmp_path / "active-version.json"
    pointer.write_text(json.dumps({
        "contract": "WrongPointer/v0",
        "active": {"version": "evil", "path": str(fake.parent)},
    }), encoding="utf-8")
    env = os.environ.copy()
    env["AGENT_SUPERVISOR_ACTIVE_POINTER"] = str(pointer)
    completed = subprocess.run(
        [sys.executable, str(Path(__file__).resolve().parents[1] / "bin" / "agent-supervisor.py"), "--version"],
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert completed.returncode == 0
    assert "UNTRUSTED_POINTER_EXECUTED" not in completed.stdout
    assert completed.stdout.strip().startswith("3.")


def test_launcher_safely_falls_back_when_active_path_resolve_reports_a_loop(
    tmp_path, monkeypatch, capsys
):
    launcher = Path(__file__).resolve().parents[1] / "bin" / "agent-supervisor.py"
    loop_candidate = tmp_path / "looped-release"
    pointer = tmp_path / "active-version.json"
    pointer.write_text(json.dumps({
        "contract": "ActiveVersionPointer/v3",
        "active": {"version": "loop", "path": str(loop_candidate)},
    }), encoding="utf-8")
    monkeypatch.setenv("AGENT_SUPERVISOR_ACTIVE_POINTER", str(pointer))
    original_resolve = Path.resolve

    def resolve_with_loop(self, strict=False):
        if self == loop_candidate:
            raise RuntimeError("Symlink loop")
        return original_resolve(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", resolve_with_loop)
    monkeypatch.setattr(sys, "argv", [str(launcher), "--version"])
    with pytest.raises(SystemExit) as stopped:
        runpy.run_path(str(launcher), run_name="__main__")

    assert stopped.value.code == 0
    assert capsys.readouterr().out.strip().startswith("3.")


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


def test_promotion_replay_rejects_unavailable_attestation_key_without_mutation(
    tmp_path, monkeypatch
):
    key = tmp_path / "promotion.key"
    monkeypatch.setenv("AGENT_SUPERVISOR_ATTESTATION_KEY_FILE", str(key))
    state = initial_rollout({}, "observe")
    apply_observation(state, observation("fixtures", "fixture_replay", passed=True))
    before = copy.deepcopy(state)
    key.write_bytes(b"invalid")

    with pytest.raises(RolloutReplayIntegrityError, match="key unavailable or invalid"):
        promote(state, "warn")

    assert state == before


def test_promotion_replay_rejects_rotated_same_length_attestation_key(
    tmp_path, monkeypatch
):
    key = tmp_path / "promotion.key"
    monkeypatch.setenv("AGENT_SUPERVISOR_ATTESTATION_KEY_FILE", str(key))
    state = initial_rollout({}, "observe")
    apply_observation(state, observation("fixtures", "fixture_replay", passed=True))
    before = copy.deepcopy(state)
    key.write_bytes(b"x" * 32)

    with pytest.raises(RolloutReplayIntegrityError, match="observation integrity invalid"):
        promote(state, "warn")

    assert state == before


def test_rollout_promotion_cli_persists_degraded_state_when_key_is_invalid(
    tmp_path, monkeypatch, capsys
):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state_root = tmp_path / "state"
    ctx = StateContext.build(
        runtime="codex",
        workspace=str(workspace),
        session="session",
        round_id="round",
        state_root=state_root,
    )
    start_round(
        ctx,
        message="promote safely",
        change_mode="replace",
        execution_mode="observe",
    )
    signed = observation("fixtures", "fixture_replay", passed=True)
    project_rollout = ctx.update_project_rollout(
        lambda current: apply_observation(current, signed)
    )
    ctx.update(lambda current: current.update({"rollout": copy.deepcopy(project_rollout)}))
    key = Path(os.environ["AGENT_SUPERVISOR_ATTESTATION_KEY_FILE"])
    key.write_bytes(b"invalid")
    payload = json.dumps({
        "record": {
            "contract": "RolloutPromotion/v3",
            "promotion_id": "promotion-1",
            "requested_mode": "warn",
        }
    })

    code = cli_module.main([
        "event",
        "--runtime", "codex",
        "--workspace", str(workspace),
        "--session", "session",
        "--round", "round",
        "--state-root", str(state_root),
        "--event-type", "rollout_promote",
        "--data-json", payload,
    ])

    assert code == 4
    assert json.loads(capsys.readouterr().out)["health"] == "degraded"
    assert ctx.load()["health"] == "degraded"
    assert any(
        event.get("event_type") == "rollout_replay_degraded"
        for event in ctx.events()
    )


def test_builtin_registered_gate_does_not_require_external_command(tmp_path, monkeypatch):
    workspace = tmp_path / "builtin-workspace"
    workspace.mkdir()
    ctx = StateContext.build(
        runtime="codex",
        workspace=str(workspace),
        session="session",
        round_id="builtin-round",
        state_root=tmp_path / "state",
    )
    state = start_round(
        ctx,
        message="check intent coverage",
        change_mode="replace",
        execution_mode="observe",
        quality_profile={
            "common_gates": [{"id": "config.intent-coverage", "builtin": "intent-coverage"}]
        },
    )
    criterion_id = state["goal"]["acceptance_criteria"][0]["criterion_id"]
    monkeypatch.setattr(
        cli_module,
        "_registered_gate",
        lambda _state, _gate_id: {
            "command": [],
            "precondition": None,
            "builtin": "intent-coverage",
        },
    )

    evidence, execution, code = cli_module._run_registered_gate(
        ctx,
        {
            "event_type": "gate_run",
            "actor": "supervisor-core",
            "record": {
                "gate_id": "config.intent-coverage",
                "criterion_id": criterion_id,
                "collector_responsibility_group": "trusted-runtime",
            },
        },
    )

    assert code == 2
    assert evidence["exit_code"] == 2
    assert execution["command"]["args"] == []
    assert execution["resolved_executable"] is None


def test_finalize_marks_rollout_refreshed_only_after_project_persistence(
    tmp_path, valid_bundle, monkeypatch
):
    ctx = StateContext.build(
        runtime="test",
        project="p",
        workspace=str(tmp_path / "workspace"),
        session="s",
        round_id="finalize-rollout-failure",
        state_root=tmp_path / "state",
    )
    state, events = valid_bundle
    state["rollout"] = {"sentinel": "loaded-before-finalize"}
    ctx.save(state)
    for event in events:
        ctx.append_event(event)

    def fail_after_concurrent_round_update(self, _mutator):
        self.update(
            lambda current: current.update({"rollout": {"sentinel": "concurrent-state"}})
        )
        raise OSError("project rollout unavailable")

    monkeypatch.setattr(
        StateContext,
        "update_project_rollout",
        fail_after_concurrent_round_update,
    )

    finalized, code = finalize_round(ctx)

    assert code == 4
    assert finalized["rollout"] == {"sentinel": "concurrent-state"}
    final_event = [
        event for event in ctx.events() if event.get("event_type") == "round_finalized"
    ][-1]
    assert final_event["rollout_refreshed"] is False


def test_finalize_marks_rollout_refreshed_after_project_persistence(
    tmp_path, valid_bundle
):
    ctx = StateContext.build(
        runtime="test",
        project="p",
        workspace=str(tmp_path / "workspace"),
        session="s",
        round_id="finalize-rollout-success",
        state_root=tmp_path / "state",
    )
    state, events = valid_bundle
    ctx.save(state)
    for event in events:
        ctx.append_event(event)

    _, code = finalize_round(ctx)

    assert code == 0
    final_event = [
        event for event in ctx.events() if event.get("event_type") == "round_finalized"
    ][-1]
    assert final_event["rollout_refreshed"] is True


def test_two_global_gate_failures_atomically_switch_active_pointer(tmp_path, monkeypatch):
    current = tmp_path / "current"
    previous = tmp_path / "previous"
    _write_release_root(current)
    _write_release_root(previous)
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
