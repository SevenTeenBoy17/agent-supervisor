from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

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
    common = [
        "--runtime", "codex", "--workspace", str(workspace), "--session", "e2e-session",
        "--round", "e2e-round", "--project-file", str(project_file), "--state-root", str(tmp_path / "state"),
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
    (workspace / "config.json").write_text('{"version":3}\n', encoding="utf-8")
    delta = workspace_delta(baseline, capture_workspace_snapshot(str(workspace), baseline["extra_globs"]))

    def event(event_type: str, record: dict, *, actor: str = "worker", expected: int = 0) -> dict:
        return run_cli(["event", *common, "--event-type", event_type, "--actor", actor, "--data-json", json.dumps({"record": record})], env, expected)

    event("changes_record", {
        "files": delta["files"], "base": delta["base"], "head": delta["head"], "diff_hash": delta["diff_hash"],
        "domains": ["config/agent"], "implementer": "worker", "implementer_responsibility_group": "implementation", "test_changes": {},
    })
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
    for stage, result in (("invocation_attempt", None), ("invocation_result", "success")):
        arguments = ["event", *common, "--event-type", stage, "--invocation-id", "invocation-e2e", "--capability", "builder", "--actor", "worker"]
        if result:
            arguments.extend(["--result", result])
        run_cli(arguments, env)
    event("review_record", {
        "contract": "ReviewRecord/v3", "review_id": "review-e2e", "goal_id": "goal-e2e", "goal_version": 1,
        "reviewer": "reviewer", "responsibility_group": "independent-quality-review", "implementer": "worker",
        "base": delta["base"], "head": delta["head"], "diff_hash": delta["diff_hash"],
        "rerun_evidence_ids": ["evidence-e2e"], "verdict": "APPROVE", "category": "config-agent",
    }, actor="reviewer")

    final = run_cli(["finalize", *common], env)
    assert final["terminal_state"] == "complete"
    persisted = json.loads(state_file.read_text(encoding="utf-8"))
    assert persisted["validation"]["valid"] is True
    assert persisted["evidence"][0]["execution_id"]
