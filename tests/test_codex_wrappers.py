from __future__ import annotations

import json
import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from supervisor_core.workspace import capture_workspace_snapshot, workspace_delta


ROOT = Path(__file__).resolve().parents[1]
CODEX_SCRIPTS = Path.home() / ".codex" / "skills" / "dev-supervisor" / "scripts"


def _powershell() -> str:
    executable = shutil.which("pwsh") or shutil.which("powershell")
    if not executable:
        pytest.skip("PowerShell is unavailable")
    return executable


def _run_script(
    script: str,
    arguments: list[str],
    *,
    env: dict[str, str],
    expected: int = 0,
) -> dict:
    completed = subprocess.run(
        [_powershell(), "-NoLogo", "-NoProfile", "-File", str(CODEX_SCRIPTS / script), *arguments],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert completed.returncode == expected, completed.stdout + completed.stderr
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    assert lines, f"{script} did not emit JSON"
    return json.loads("\n".join(lines))


def _write_record(path: Path, record: dict) -> None:
    path.write_text(json.dumps({"record": record}, ensure_ascii=False), encoding="utf-8")


def test_powershell_thin_adapters_audit_but_do_not_overclaim_host_identity(tmp_path):
    workspace = tmp_path / "Codex 包装器 workspace"
    supervisor_dir = workspace / ".agent-supervisor"
    supervisor_dir.mkdir(parents=True)
    project_file = supervisor_dir / "project.json"
    quality_file = supervisor_dir / "quality.json"
    project_file.write_text(json.dumps({
        "project_id": "codex-wrapper-e2e",
        "quality_profile": "quality.json",
        "supervisor_scope": {
            "allowed_change_globs": ["config.json", ".agent-supervisor/**"],
            "out_of_scope_globs": ["src/**"],
        },
    }), encoding="utf-8")
    quality_file.write_text(json.dumps({
        "global_gates": ["gate.wrapper"],
        "common_gates": [{
            "id": "gate.wrapper",
            "command": [os.fspath(Path(os.sys.executable)), "-c", "print('WRAPPER_GATE_PASS')"],
        }],
        "domains": {"config/agent": {"required_gates": ["gate.wrapper"]}},
        "profiles": {"config_agent": {"applies_to": ["config.json"], "gates": []}},
    }), encoding="utf-8")
    (workspace / "config.json").write_text('{"version":1}\n', encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(workspace)], check=True)
    subprocess.run(["git", "-C", str(workspace), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(workspace), "config", "user.name", "Supervisor Wrapper E2E"], check=True)
    subprocess.run([
        "git", "-C", str(workspace), "add",
        ".agent-supervisor/project.json", ".agent-supervisor/quality.json", "config.json",
    ], check=True)
    subprocess.run(["git", "-C", str(workspace), "commit", "-qm", "baseline"], check=True)

    fake_home = tmp_path / "isolated-home"
    fake_home.mkdir()
    env = os.environ.copy()
    env["USERPROFILE"] = str(fake_home)
    env["HOME"] = str(fake_home)
    env["AGENT_SUPERVISOR_ACTIVE_POINTER"] = str(ROOT / "active-version.json")
    env["AGENT_SUPERVISOR_ATTESTATION_KEY_FILE"] = str(tmp_path / "attestation.key")
    env["CODEX_THREAD_ID"] = "wrapper-session"
    common = [
        "-Workspace", str(workspace), "-SessionId", "wrapper-session",
        "-RoundId", "wrapper-round",
    ]

    started = _run_script(
        "supervisor-bootstrap.ps1",
        [*common, "-Message", "实现并验证配置监工闭环", "-ChangeMode", "replace", "-ExecutionMode", "enforce"],
        env=env,
    )
    state_file = Path(started["state_file"])
    state = json.loads(state_file.read_text(encoding="utf-8"))
    goal = state["goal"]
    goal_id = goal["goal_id"]
    goal_version = goal["version"]
    criterion_id = goal["acceptance_criteria"][0]["criterion_id"]
    intent_id = state["intents"][0]["intent_id"]
    baseline = state["workspace_baseline"]

    (workspace / "config.json").write_text('{"version":3}\n', encoding="utf-8")
    delta = workspace_delta(baseline, capture_workspace_snapshot(str(workspace), baseline["extra_globs"]))
    records = tmp_path / "records"
    records.mkdir()

    changes_file = records / "changes.json"
    _write_record(changes_file, {
        "files": delta["files"], "base": delta["base"], "head": delta["head"],
        "diff_hash": delta["diff_hash"], "domains": ["config/agent"],
        "implementer": "codex-worker", "implementer_responsibility_group": "implementation",
        "implementer_invocation_id": "invocation-wrapper",
        "test_changes": {},
    })
    _run_script(
        "supervisor-record.ps1",
        [*common, "-RecordType", "changes", "-RecordFile", str(changes_file), "-Actor", "codex-worker"],
        env=env,
    )

    gate = _run_script(
        "supervisor-gate.ps1",
        [*common, "-GateId", "gate.wrapper", "-CriterionId", criterion_id,
         "-CollectorGroup", "independent-quality-review", "-EvidenceId", "evidence-wrapper",
         "-Actor", "codex-reviewer"],
        env=env,
    )
    assert gate["exit_code"] == 0

    intent_file = records / "intent.json"
    _write_record(intent_file, {
        "intent_id": intent_id, "status": "covered", "reason": "implemented and independently verified",
        "capability_ids": ["codex-wrapper"], "phase": 1,
    })
    task_file = records / "task.json"
    _write_record(task_file, {
        "task_id": "task-wrapper", "goal_id": goal_id, "goal_version": goal_version,
        "criterion_ids": [criterion_id], "allowed_paths": ["config.json"],
        "expected_evidence": ["gate.wrapper"], "status": "done", "evidence_ids": ["evidence-wrapper"],
    })
    spec_file = records / "spec.json"
    _write_record(spec_file, {
        "status": "approved", "hash": "b" * 64, "path": "spec.md",
        "content": "Exact wrapper integration contract",
    })
    for record_type, record_file in (("intent", intent_file), ("task", task_file), ("spec", spec_file)):
        _run_script(
            "supervisor-record.ps1",
            [*common, "-RecordType", record_type, "-RecordFile", str(record_file), "-Actor", "codex-worker"],
            env=env,
        )

    for event_type, result in (("invocation_attempt", ""), ("invocation_result", "success")):
        arguments = [
            *common, "-Event", event_type, "-Skill", "codex-wrapper",
            "-InvocationId", "invocation-wrapper", "-Actor", "codex-worker",
        ]
        if result:
            arguments.extend(["-Result", result])
        _run_script("supervisor-event.ps1", arguments, env=env)

    review_file = records / "review.json"
    _write_record(review_file, {
        "contract": "ReviewRecord/v3", "review_id": "review-wrapper",
        "goal_id": goal_id, "goal_version": goal_version,
        "reviewer": "codex-reviewer", "responsibility_group": "independent-quality-review",
        "implementer": "codex-worker", "base": delta["base"], "head": delta["head"],
        "diff_hash": delta["diff_hash"], "rerun_evidence_ids": ["evidence-wrapper"],
        "verdict": "APPROVE", "category": "config-agent",
        "implementer_invocation_id": "invocation-wrapper", "reviewer_invocation_id": "review-invocation-wrapper",
        "actor_identity_assurance": "declared-codex",
    })
    _run_script(
        "supervisor-record.ps1",
        [*common, "-RecordType", "review", "-RecordFile", str(review_file), "-Actor", "codex-reviewer"],
        env=env,
    )

    final = _run_script("supervisor-finalize.ps1", common, env=env, expected=2)
    assert final["terminal_state"] == "incomplete"
    persisted = json.loads(state_file.read_text(encoding="utf-8"))
    assert persisted["validation"]["valid"] is False
    assert any("host-hook-observed" in error for error in persisted["validation"]["errors"])
    _run_script("supervisor-handoff.ps1", common, env=env)
    session_hash = hashlib.sha256(b"wrapper-session").hexdigest()
    assert (workspace / ".agent-supervisor" / "handoffs" / session_hash / "latest.md").is_file()
    assert not (workspace / ".agent-supervisor" / "handoff.md").exists()
    after_handoff = workspace_delta(
        baseline,
        capture_workspace_snapshot(str(workspace), baseline["extra_globs"]),
    )
    assert after_handoff["files"] == delta["files"]
    assert after_handoff["diff_hash"] == delta["diff_hash"]
