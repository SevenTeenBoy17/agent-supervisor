from __future__ import annotations

import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import supervisor_core.cli as cli_module
from supervisor_core.lifecycle import start_round
from supervisor_core.storage import StateContext
from supervisor_core.util import sha256_file
from supervisor_core.validation import validate_state
from supervisor_core.workspace import capture_workspace_snapshot, workspace_delta


ROOT = Path(__file__).resolve().parents[1]


def run_cli(arguments: list[str], env: dict[str, str], expected: int = 0) -> dict:
    completed = subprocess.run(
        [sys.executable, "-m", "supervisor_core", *arguments],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert completed.returncode == expected, completed.stdout + completed.stderr
    return json.loads(completed.stdout)


def run_hook(event: str, payload: dict, env: dict[str, str], expected: int = 0) -> dict:
    completed = subprocess.run(
        [sys.executable, "-m", "supervisor_core", "hook", "--runtime", "claude", "--event", event],
        cwd=ROOT, env=env, input=json.dumps(payload, ensure_ascii=False), capture_output=True,
        text=True, encoding="utf-8", check=False,
    )
    assert completed.returncode == expected, completed.stdout + completed.stderr
    return json.loads(completed.stdout or "{}")


def test_gate_runner_attests_registered_argv_and_resolved_executable(tmp_path):
    workspace = tmp_path / "Windows shim workspace"
    workspace.mkdir()
    ctx = StateContext.build(
        runtime="codex",
        project="shim-project",
        workspace=str(workspace),
        session="shim-session",
        round_id="shim-round",
        state_root=tmp_path / "state",
    )
    registered = [sys.executable, "-c", "print('executable attested')"]
    start_round(
        ctx,
        message="run registered shim gate",
        change_mode="replace",
        execution_mode="observe",
        quality_profile={"common_gates": [{"id": "gate.shim", "command": registered}]},
    )
    evidence, execution, code = cli_module._run_registered_gate(
        ctx,
        {
            "event_type": "gate_run",
            "actor": "trusted-runner",
            "record": {
                "gate_id": "gate.shim",
                "criterion_id": "criterion-1",
                "collector_responsibility_group": "trusted-runtime",
            },
        },
    )
    assert code == 0
    assert evidence["exit_code"] == 0
    assert execution["command"]["args"] == registered
    assert "executable attested" in execution["output_summary"]
    assert execution["resolved_executable"] == str(Path(sys.executable).resolve())
    assert execution["resolved_executable_sha256"] == sha256_file(Path(sys.executable).resolve())
    assert evidence["resolved_executable"] == execution["resolved_executable"]
    assert evidence["resolved_executable_sha256"] == execution["resolved_executable_sha256"]

    tampered = ctx.load()
    tampered["evidence"][0]["resolved_executable_sha256"] = "0" * 64
    errors = validate_state(tampered, ctx.events())["errors"]
    assert any("does not match the locally attested core execution" in error for error in errors)


@pytest.mark.skipif(os.name != "nt", reason="Windows PATH/PATHEXT regression")
@pytest.mark.parametrize(
    ("registered", "shim_name"),
    [
        (["npm"], "npm.cmd"),
        (["tool.v1", "--label", "value with spaces"], "tool.v1.cmd"),
    ],
)
def test_windows_gate_resolution_never_prefers_workspace_local_cmd(
    tmp_path, monkeypatch, registered, shim_name
):
    workspace = tmp_path / "adversarial workspace"
    trusted_bin = tmp_path / "trusted bin"
    workspace.mkdir()
    trusted_bin.mkdir()
    (workspace / shim_name).write_text("@echo FAKE_WORKSPACE_GATE_PASS\r\n", encoding="utf-8")
    trusted_shim = trusted_bin / shim_name
    trusted_shim.write_text("@echo TRUSTED_PATH_GATE_PASS\r\n", encoding="utf-8")

    ctx = StateContext.build(
        runtime="codex",
        project="path-hijack-project",
        workspace=str(workspace),
        session="path-hijack-session",
        round_id="path-hijack-round",
        state_root=tmp_path / "state",
    )
    start_round(
        ctx,
        message="reject workspace executable shadowing",
        change_mode="replace",
        execution_mode="observe",
        quality_profile={"common_gates": [{"id": "gate.path", "command": registered}]},
    )
    monkeypatch.setenv("PATH", str(trusted_bin))
    monkeypatch.setenv("PATHEXT", ".CMD")
    evidence, execution, code = cli_module._run_registered_gate(
        ctx,
        {
            "event_type": "gate_run",
            "actor": "trusted-runner",
            "record": {
                "gate_id": "gate.path",
                "criterion_id": "criterion-1",
                "collector_responsibility_group": "trusted-runtime",
            },
        },
    )
    assert code == 0
    assert "TRUSTED_PATH_GATE_PASS" in execution["output_summary"]
    assert "FAKE_WORKSPACE_GATE_PASS" not in execution["output_summary"]
    assert execution["command"]["args"] == registered
    assert execution["resolved_executable"] == str(trusted_shim.resolve())
    assert evidence["resolved_executable_sha256"] == sha256_file(trusted_shim.resolve())


def test_real_cli_round_reaches_complete_only_with_signed_gate_and_independent_review(tmp_path):
    workspace = tmp_path / "Brown Zone 中文 workspace"
    supervisor_dir = workspace / ".agent-supervisor"
    supervisor_dir.mkdir(parents=True)
    project_file = supervisor_dir / "project.json"
    quality_file = supervisor_dir / "quality.json"
    project_file.write_text(json.dumps({
        "project_id": "e2e",
        "quality_profile": "quality.json",
        "supervisor_scope": {"allowed_change_globs": ["config.json", ".agent-supervisor/**"], "out_of_scope_globs": ["src/**"]},
    }), encoding="utf-8")
    quality_file.write_text(json.dumps({
        "global_gates": ["gate.e2e"],
        "common_gates": [{"id": "gate.e2e", "command": [sys.executable, "-c", "print('E2E_GATE_PASS')"]}],
        "domains": {"config/agent": {"required_gates": ["gate.e2e"]}},
        "profiles": {"config_agent": {"applies_to": ["config.json"], "gates": []}},
    }), encoding="utf-8")
    (workspace / "config.json").write_text('{"version":1}\n', encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(workspace)], check=True)
    subprocess.run(["git", "-C", str(workspace), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(workspace), "config", "user.name", "Supervisor E2E"], check=True)
    subprocess.run(["git", "-C", str(workspace), "add", ".agent-supervisor/project.json", ".agent-supervisor/quality.json", "config.json"], check=True)
    subprocess.run(["git", "-C", str(workspace), "commit", "-qm", "baseline"], check=True)

    env = os.environ.copy()
    env["AGENT_SUPERVISOR_ATTESTATION_KEY_FILE"] = str(tmp_path / "attestation.key")
    env["USERPROFILE"] = str(tmp_path / "home")
    env["HOME"] = str(tmp_path / "home")
    common = [
        "--runtime", "claude", "--workspace", str(workspace), "--session", "e2e-session",
        "--round", "e2e-round", "--project-file", str(project_file),
    ]
    goal = {
        "goal_id": "goal-e2e", "objective": "Prove the complete gate",
        "acceptance_criteria": [{"criterion_id": "criterion-e2e", "description": "Registered gate and independent review pass", "domain": "config-agent", "expected_evidence": ["gate.e2e"], "required": True}],
        "scope": {"in": ["config.json"], "out": ["src/**"]},
    }
    intents = [{"intent_id": "intent-e2e", "text": "implement and verify", "domain": "config-agent", "status": "covered", "reason": "builder completed it", "capability_ids": ["builder"], "phase": 1}]
    started = run_cli(["start", *common, "--message", "implement and verify", "--change-mode", "replace", "--execution-mode", "enforce", "--goal-json", json.dumps(goal), "--intents-json", json.dumps(intents)], env)
    state_file = Path(started["state_file"])
    baseline = json.loads(state_file.read_text(encoding="utf-8"))["workspace_baseline"]
    hook_common = {"session_id": "e2e-session", "cwd": str(workspace)}
    run_hook("PreToolUse", {
        **hook_common, "tool_use_id": "invocation-e2e", "tool_name": "builder",
        "agent_id": "worker", "tool_input": {"capability": "builder"},
    }, env)
    (workspace / "config.json").write_text('{"version":3}\n', encoding="utf-8")
    run_hook("PostToolUse", {
        **hook_common, "tool_use_id": "invocation-e2e", "tool_name": "builder",
        "agent_id": "worker", "tool_input": {"capability": "builder"}, "success": True,
    }, env)
    delta = workspace_delta(baseline, capture_workspace_snapshot(str(workspace), baseline["extra_globs"]))

    def event(event_type: str, record: dict, *, actor: str = "worker", expected: int = 0) -> dict:
        return run_cli(["event", *common, "--event-type", event_type, "--actor", actor, "--data-json", json.dumps({"record": record})], env, expected)

    event("changes_record", {
        "files": delta["files"], "base": delta["base"], "head": delta["head"], "diff_hash": delta["diff_hash"],
        "domains": ["config/agent"], "implementer": "worker", "implementer_responsibility_group": "implementation",
        "implementer_invocation_id": "invocation-e2e", "test_changes": {},
    })
    run_hook("PreToolUse", {
        **hook_common, "tool_use_id": "review-invocation-e2e", "tool_name": "independent-reviewer",
        "agent_id": "reviewer", "tool_input": {"capability": "independent-reviewer"},
    }, env)
    gate = event("gate_run", {
        "gate_id": "gate.e2e", "criterion_id": "criterion-e2e", "evidence_id": "evidence-e2e",
        "collector_responsibility_group": "independent-quality-review",
    }, actor="reviewer")
    assert gate["exit_code"] == 0
    event("task_record", {
        "task_id": "task-e2e", "goal_id": "goal-e2e", "goal_version": 1,
        "criterion_ids": ["criterion-e2e"], "allowed_paths": ["config.json"],
        "expected_evidence": ["gate.e2e"], "status": "done", "evidence_ids": ["evidence-e2e"],
    })
    event("spec_record", {"status": "approved", "hash": "a" * 64, "path": "spec.md", "content": "Exact e2e contract"})
    event("review_record", {
        "contract": "ReviewRecord/v3", "review_id": "review-e2e", "goal_id": "goal-e2e", "goal_version": 1,
        "reviewer": "reviewer", "responsibility_group": "independent-quality-review", "implementer": "worker",
        "base": delta["base"], "head": delta["head"], "diff_hash": delta["diff_hash"],
        "rerun_evidence_ids": ["evidence-e2e"], "verdict": "APPROVE", "category": "config-agent",
        "implementer_invocation_id": "invocation-e2e", "reviewer_invocation_id": "review-invocation-e2e",
        "actor_identity_assurance": "host-hook-observed",
    }, actor="reviewer")
    run_hook("PostToolUse", {
        **hook_common, "tool_use_id": "review-invocation-e2e", "tool_name": "independent-reviewer",
        "agent_id": "reviewer", "tool_input": {"capability": "independent-reviewer"}, "success": True,
    }, env)

    final = run_cli(["finalize", *common], env)
    assert final["terminal_state"] == "complete"
    persisted = json.loads(state_file.read_text(encoding="utf-8"))
    assert persisted["validation"]["valid"] is True
    assert persisted["evidence"][0]["execution_id"]


def test_public_gate_cli_performs_automatic_rollback_after_two_global_failures(tmp_path):
    workspace = tmp_path / "rollback workspace"
    supervisor_dir = workspace / ".agent-supervisor"
    supervisor_dir.mkdir(parents=True)
    project_file = supervisor_dir / "project.json"
    quality_file = supervisor_dir / "quality.json"
    project_file.write_text(json.dumps({
        "project_id": "rollback-e2e", "quality_profile": "quality.json",
        "supervisor_scope": {"allowed_change_globs": [".agent-supervisor/**"], "out_of_scope_globs": []},
    }), encoding="utf-8")
    quality_file.write_text(json.dumps({
        "global_gates": ["gate.fail"],
        "common_gates": [{
            "id": "gate.fail",
            "command": [sys.executable, "-c", "import time; time.sleep(0.15); raise SystemExit(1)"],
        }],
    }), encoding="utf-8")

    current = tmp_path / "current-core"
    previous = tmp_path / "previous-core"
    (current / "supervisor_core").mkdir(parents=True)
    (previous / "supervisor_core").mkdir(parents=True)
    pointer = tmp_path / "active-version.json"
    pointer.write_text(json.dumps({
        "contract": "ActiveVersionPointer/v3",
        "active": {"version": "3.1.0", "path": str(current)},
        "previous": {"version": "3.0.0", "path": str(previous)},
    }), encoding="utf-8")
    env = os.environ.copy()
    env["AGENT_SUPERVISOR_ACTIVE_POINTER"] = str(pointer)
    env["AGENT_SUPERVISOR_ATTESTATION_KEY_FILE"] = str(tmp_path / "rollback-attestation.key")
    common = [
        "--runtime", "codex", "--workspace", str(workspace), "--session", "rollback-session",
        "--round", "rollback-round", "--project-file", str(project_file), "--state-root", str(tmp_path / "state"),
    ]
    run_cli(["start", *common, "--message", "exercise rollback", "--change-mode", "replace", "--execution-mode", "warn"], env)
    gate_payload = json.dumps({"record": {"gate_id": "gate.fail", "criterion_id": "criterion-1", "collector_responsibility_group": "quality"}})
    gate_arguments = ["event", *common, "--event-type", "gate_run", "--actor", "reviewer", "--data-json", gate_payload]
    run_cli(gate_arguments, env, expected=2)
    with ThreadPoolExecutor(max_workers=2) as pool:
        concurrent_results = list(pool.map(lambda _: run_cli(gate_arguments, env, expected=2), range(2)))
    assert len(concurrent_results) == 2
    active = json.loads(pointer.read_text(encoding="utf-8"))["active"]
    assert active["version"] == "3.0.0"
    state = run_cli(["query", *common], env)
    assert state["rollout"]["rollback"]["performed"] is True
    assert state["rollout"]["rollback"]["attempted"] is True
    assert state["rollout"]["rollback"]["attempt_count"] == 1
    assert json.loads(pointer.read_text(encoding="utf-8"))["rollback"]["expected_active"]["version"] == "3.1.0"

    promotion_payload = json.dumps({"record": {
        "contract": "RolloutPromotion/v3",
        "promotion_id": "replay-after-rollback",
        "requested_mode": "observe",
    }})
    run_cli([
        "event", *common, "--event-type", "rollout_promote", "--actor", "supervisor",
        "--data-json", promotion_payload,
    ], env)
    run_cli(gate_arguments, env, expected=2)
    replayed_state = run_cli(["query", *common], env)
    replayed_pointer = json.loads(pointer.read_text(encoding="utf-8"))
    assert replayed_pointer["active"]["version"] == "3.0.0"
    assert replayed_pointer["previous"]["version"] == "3.1.0"
    assert replayed_state["rollout"]["rollback"]["performed"] is True
    assert replayed_state["rollout"]["rollback"]["attempt_count"] == 1


@pytest.mark.parametrize("pointer_effect_before_recovery", [False, True])
def test_stale_rollback_claim_recovers_before_or_after_pointer_effect(
    tmp_path, monkeypatch, pointer_effect_before_recovery
):
    workspace = tmp_path / "rollback recovery workspace"
    workspace.mkdir()
    current = tmp_path / "bad-core"
    previous = tmp_path / "good-core"
    (current / "supervisor_core").mkdir(parents=True)
    (previous / "supervisor_core").mkdir(parents=True)
    pointer = tmp_path / "active-version.json"
    pointer.write_text(json.dumps({
        "contract": "ActiveVersionPointer/v3",
        "active": {"version": "3.1.0", "path": str(current)},
        "previous": {"version": "3.0.0", "path": str(previous)},
    }), encoding="utf-8")
    monkeypatch.setenv("AGENT_SUPERVISOR_ACTIVE_POINTER", str(pointer))
    monkeypatch.setenv("AGENT_SUPERVISOR_ATTESTATION_KEY_FILE", str(tmp_path / "recovery-attestation.key"))

    ctx = StateContext.build(
        runtime="codex",
        project="rollback-recovery",
        workspace=str(workspace),
        session="recovery-session",
        round_id="recovery-round",
        state_root=tmp_path / "state",
    )
    quality = {
        "global_gates": ["gate.fail"],
        "common_gates": [{"id": "gate.fail", "command": [sys.executable, "-c", "raise SystemExit(1)"]}],
    }
    start_round(
        ctx,
        message="recover a claimed rollback",
        change_mode="replace",
        execution_mode="warn",
        project_config={
            "project_id": "rollback-recovery",
            "supervisor_scope": {"allowed_change_globs": [".agent-supervisor/**"], "out_of_scope_globs": []},
        },
        quality_profile=quality,
    )
    payload = {
        "event_type": "gate_run",
        "actor": "reviewer",
        "record": {
            "gate_id": "gate.fail",
            "criterion_id": "criterion-1",
            "collector_responsibility_group": "quality",
        },
    }
    assert cli_module._run_registered_gate(ctx, payload)[2] == 2
    real_rollback = cli_module.rollback_active_version

    def crash_before_effect(*, expected_active=None):
        raise SystemExit("simulated process crash after claim")

    monkeypatch.setattr(cli_module, "rollback_active_version", crash_before_effect)
    with pytest.raises(SystemExit, match="simulated process crash"):
        cli_module._run_registered_gate(ctx, payload)
    claimed = ctx.load_project_rollout()["rollback"]
    assert claimed["claim_status"] == "in_progress"
    assert claimed["attempt_count"] == 1
    assert json.loads(pointer.read_text(encoding="utf-8"))["active"]["version"] == "3.1.0"
    if pointer_effect_before_recovery:
        effect = real_rollback(expected_active=claimed["expected_active"])
        assert effect["performed"] is True
        assert json.loads(pointer.read_text(encoding="utf-8"))["active"]["version"] == "3.0.0"

    def expire_claim(current_rollout):
        current_rollout["rollback"]["claim_expires_at"] = "2000-01-01T00:00:00.000Z"
        return current_rollout

    ctx.update_project_rollout(expire_claim)
    monkeypatch.setattr(cli_module, "rollback_active_version", real_rollback)
    assert cli_module._run_registered_gate(ctx, payload)[2] == 2
    recovered = ctx.load_project_rollout()["rollback"]
    recovered_pointer = json.loads(pointer.read_text(encoding="utf-8"))
    assert recovered_pointer["active"]["version"] == "3.0.0"
    assert recovered["claim_status"] == "completed"
    assert recovered["performed"] is True
    assert recovered["attempt_count"] == 2
    assert recovered["recovery_count"] == 1


def test_unbound_failures_do_not_roll_back_new_release_until_its_own_threshold(tmp_path):
    workspace = tmp_path / "identity-bound rollback workspace"
    supervisor_dir = workspace / ".agent-supervisor"
    supervisor_dir.mkdir(parents=True)
    project_file = supervisor_dir / "project.json"
    quality_file = supervisor_dir / "quality.json"
    project_file.write_text(json.dumps({
        "project_id": "identity-bound-rollback",
        "quality_profile": "quality.json",
        "supervisor_scope": {"allowed_change_globs": [".agent-supervisor/**"], "out_of_scope_globs": []},
    }), encoding="utf-8")
    quality_file.write_text(json.dumps({
        "global_gates": ["gate.fail"],
        "common_gates": [{"id": "gate.fail", "command": [sys.executable, "-c", "raise SystemExit(1)"]}],
    }), encoding="utf-8")
    pointer = tmp_path / "active-version.json"
    env = os.environ.copy()
    env["AGENT_SUPERVISOR_ACTIVE_POINTER"] = str(pointer)
    env["AGENT_SUPERVISOR_ATTESTATION_KEY_FILE"] = str(tmp_path / "identity-attestation.key")
    common = [
        "--runtime", "codex", "--workspace", str(workspace), "--session", "identity-session",
        "--round", "identity-round", "--project-file", str(project_file), "--state-root", str(tmp_path / "state"),
    ]
    run_cli([
        "start", *common, "--message", "bind failures to release identity",
        "--change-mode", "replace", "--execution-mode", "warn",
    ], env)
    gate_payload = json.dumps({"record": {
        "gate_id": "gate.fail",
        "criterion_id": "criterion-1",
        "collector_responsibility_group": "quality",
    }})
    gate_arguments = [
        "event", *common, "--event-type", "gate_run", "--actor", "reviewer", "--data-json", gate_payload,
    ]
    run_cli(gate_arguments, env, expected=2)
    run_cli(gate_arguments, env, expected=2)
    unbound = run_cli(["query", *common], env)["rollout"]
    assert unbound["metrics"]["unbound_global_gate_failures"] == 2
    assert unbound["metrics"]["consecutive_global_gate_failures"] == 0
    assert unbound["rollback"]["required"] is False

    new_release = tmp_path / "new-release"
    old_release = tmp_path / "old-release"
    (new_release / "supervisor_core").mkdir(parents=True)
    (old_release / "supervisor_core").mkdir(parents=True)
    pointer.write_text(json.dumps({
        "contract": "ActiveVersionPointer/v3",
        "active": {"version": "4.0.0", "path": str(new_release)},
        "previous": {"version": "3.0.1", "path": str(old_release)},
    }), encoding="utf-8")
    run_cli(gate_arguments, env, expected=2)
    after_first_bound_failure = run_cli(["query", *common], env)["rollout"]
    assert json.loads(pointer.read_text(encoding="utf-8"))["active"]["version"] == "4.0.0"
    assert after_first_bound_failure["metrics"]["consecutive_global_gate_failures"] == 1
    assert after_first_bound_failure["rollback"]["required"] is False

    run_cli(gate_arguments, env, expected=2)
    after_threshold = run_cli(["query", *common], env)["rollout"]
    assert json.loads(pointer.read_text(encoding="utf-8"))["active"]["version"] == "3.0.1"
    assert after_threshold["rollback"]["performed"] is True
    assert after_threshold["rollback"]["expected_active"]["version"] == "4.0.0"
