from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import supervisor_core.cli as cli_module
import supervisor_core.workspace as workspace_module
from supervisor_core.executable_trust import (
    load_trusted_executable_registry,
    registry_public_record,
)
from supervisor_core.lifecycle import start_round
from supervisor_core.storage import StateContext
from supervisor_core.runtime_bundle import build_runtime_bundle, release_identity
from supervisor_core.util import sha256_file
from supervisor_core.validation import validate_state
from supervisor_core.workspace import capture_workspace_snapshot, workspace_delta


ROOT = Path(__file__).resolve().parents[1]


def _trusted_python_path() -> Path:
    registry = json.loads((ROOT / "trusted-executables.json").read_text(encoding="utf-8"))
    return Path(registry["entries"]["python"]["path"]).resolve(strict=True)


def _git_fixture_env() -> dict[str, str]:
    env = os.environ.copy()
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
        env.pop(name, None)
    return env


def _write_install_source_fixture(home: Path) -> None:
    roots = {
        "codex-adapter": home / ".codex" / "skills" / "dev-supervisor" / "scripts",
        "claude-adapter": home / ".claude" / "skills" / "supervisor" / "scripts",
    }
    for logical_name in workspace_module._required_supervisor_source_names():
        prefix, _, filename = logical_name.partition("/")
        if prefix not in roots:
            continue
        target = roots[prefix] / filename
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(f"fixture:{logical_name}\n", encoding="utf-8")


def _write_trusted_executable_registry(
    install_home: Path,
    entries: dict[str, Path] | None = None,
) -> None:
    if entries is None:
        source = json.loads((ROOT / "trusted-executables.json").read_text(encoding="utf-8"))
        selected = {
            name: Path(source["entries"][name]["path"])
            for name in ("git", "python")
        }
    else:
        selected = entries
    registry = {
        "contract": "TrustedExecutableRegistry/v1",
        "entries": {
            name: {
                "kind": "local",
                "path": str(path.resolve(strict=True)),
                "sha256": sha256_file(path.resolve(strict=True)),
            }
            for name, path in selected.items()
        },
        "generated_at": "2026-08-23T00:00:00.000Z",
    }
    target = install_home / ".agent-supervisor" / "trusted-executables.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(registry, sort_keys=True), encoding="utf-8")


def _write_healthy_skill_fixture(home: Path) -> None:
    contents = (
        "---\n"
        "name: dev-supervisor\n"
        "description: goal implement verify run registered gate breaker capability test exercise rollback bind failures release identity\n"
        "---\n"
        "# Fixture capability\n"
    )
    for runtime in (".codex", ".claude"):
        target = home / runtime / "skills" / "dev-supervisor" / "SKILL.md"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents, encoding="utf-8")
    _write_install_source_fixture(home)
    _write_trusted_executable_registry(home)


def _write_release_root_fixture(path: Path, version: str) -> dict[str, str]:
    core = path / "supervisor_core"
    core.mkdir(parents=True)
    (core / "__init__.py").write_text("VERSION = 'fixture'\n", encoding="utf-8")
    (core / "cli.py").write_text("def main():\n    return 0\n", encoding="utf-8")
    bundle = build_runtime_bundle(path, version)
    bundle_path = path / "runtime" / "supervisor-runtime.zip"
    bundle_path.parent.mkdir(parents=True)
    bundle_path.write_bytes(bundle)
    return release_identity(path, version, "runtime/supervisor-runtime.zip", bundle)


@pytest.fixture(autouse=True)
def _isolated_attestation_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(
        "AGENT_SUPERVISOR_ATTESTATION_KEY_FILE",
        str(tmp_path / "in-process-attestation.key"),
    )


def test_git_fixture_env_drops_inherited_repository_overrides(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
        monkeypatch.setenv(name, f"attacker-{name.lower()}")

    env = _git_fixture_env()

    assert all(name not in env for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"))


def _trusted_quality_controls() -> dict:
    return {
        "completion_policy": {
            "binary_only": True,
            "model_self_score_is_evidence": False,
            "validator_error_terminal": "degraded",
            "allowed_terminal_states": ["complete", "incomplete", "blocked", "user-waived"],
            "complete_requires_all_applicable_gates": True,
            "unresolved_p0_p1_blocks_complete": True,
        },
        "test_integrity": {
            "separate_review_required_for": ["assertion changed with implementation"],
            "green_tests_alone_are_sufficient": False,
        },
        "review": {
            "implementer_and_reviewer_groups_must_differ": True,
            "required_verdicts": ["APPROVE", "REQUEST_CHANGES", "NEEDS_DISCUSSION"],
            "record_must_bind": [
                "actor", "responsibility_group", "base", "head", "diff_hash", "rerun_evidence",
                "implementer_invocation_id", "reviewer_invocation_id", "actor_identity_assurance",
            ],
        },
    }


def _write_config_schemas(supervisor_dir: Path) -> tuple[str, str]:
    schemas = supervisor_dir / "schemas"
    schemas.mkdir(parents=True, exist_ok=True)
    project_schema = schemas / "project.schema.json"
    quality_schema = schemas / "quality.schema.json"
    project_schema.write_text(json.dumps({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["$schema", "project_id", "supervisor_scope"],
        "properties": {
            "$schema": {"type": "string", "minLength": 1},
            "project_id": {"type": "string", "minLength": 1},
            "quality_profile": {"type": "string"},
            "supervisor_scope": {"type": "object"},
        },
        "additionalProperties": True,
    }), encoding="utf-8")
    quality_schema.write_text(json.dumps({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["$schema"],
        "properties": {"$schema": {"type": "string", "minLength": 1}},
        "additionalProperties": True,
    }), encoding="utf-8")
    return "./schemas/project.schema.json", "./schemas/quality.schema.json"


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


def run_cli_authorized_gate(
    common: list[str],
    env: dict[str, str],
    *,
    invocation_id: str,
    actor: str,
    record: dict,
    expected: int,
) -> dict:
    del invocation_id, actor
    bound = {
        key: record[key]
        for key in ("gate_id", "criterion_id", "evidence_id")
        if key in record
    }
    result = run_cli([
        "event", *common, "--event-type", "gate_run",
        "--data-json", json.dumps({"record": bound}),
    ], env, expected=expected)
    return result


def run_hook(event: str, payload: dict, env: dict[str, str], expected: int = 0) -> dict:
    completed = subprocess.run(
        [sys.executable, "-m", "supervisor_core", "hook", "--runtime", "claude", "--event", event],
        cwd=ROOT, env=env, input=json.dumps(payload, ensure_ascii=False), capture_output=True,
        text=True, encoding="utf-8", check=False,
    )
    assert completed.returncode == expected, completed.stdout + completed.stderr
    return json.loads(completed.stdout or "{}")


def _run_authorized_gate(ctx: StateContext, payload: dict):
    if not isinstance(ctx.load().get("trusted_executable_registry"), dict):
        ctx.update(
            lambda current: current.update({
                "trusted_executable_registry": registry_public_record(
                    load_trusted_executable_registry()
                )
            })
        )
    request = {
        key: payload["record"][key]
        for key in ("gate_id", "criterion_id", "evidence_id")
        if key in payload["record"]
    }
    result = cli_module._run_registered_gate(
        ctx, {"event_type": "gate_run", "record": request}
    )
    assert result[0]["collector"] == "supervisor-core"
    assert result[0]["collector_identity_assurance"] == "core-executed-gate"
    return result


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
    trusted_python = _trusted_python_path()
    registered = [str(trusted_python), "-c", "print('executable attested')"]
    start_round(
        ctx,
        message="run registered shim gate",
        change_mode="replace",
        execution_mode="observe",
        quality_profile={"common_gates": [{"id": "gate.shim", "command": registered}]},
    )
    evidence, execution, code = _run_authorized_gate(
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
    assert execution["resolved_executable"] == str(trusted_python)
    assert execution["resolved_executable_sha256"] == sha256_file(trusted_python)
    assert evidence["resolved_executable"] == execution["resolved_executable"]
    assert evidence["resolved_executable_sha256"] == execution["resolved_executable_sha256"]

    tampered = ctx.load()
    tampered["evidence"][0]["resolved_executable_sha256"] = "0" * 64
    errors = validate_state(tampered, ctx.events())["errors"]
    assert any("does not match the locally attested core execution" in error for error in errors)


def test_gate_precondition_is_attested_and_failure_prevents_main_command(tmp_path):
    workspace = tmp_path / "precondition workspace"
    workspace.mkdir()
    marker = workspace / "main-command-ran"
    ctx = StateContext.build(
        runtime="codex",
        project="precondition-project",
        workspace=str(workspace),
        session="precondition-session",
        round_id="precondition-round",
        state_root=tmp_path / "state",
    )
    trusted_python = str(_trusted_python_path())
    precondition = [trusted_python, "-c", "print('SETUP_FAILED'); raise SystemExit(7)"]
    command = [
        trusted_python,
        "-c",
        f"from pathlib import Path; Path({str(marker)!r}).write_text('unsafe')",
    ]
    start_round(
        ctx,
        message="prove ordered gate setup",
        change_mode="replace",
        execution_mode="observe",
        quality_profile={
            "common_gates": [{"id": "gate.precondition", "precondition": precondition, "command": command}]
        },
    )
    evidence, execution, code = _run_authorized_gate(
        ctx,
        {
            "event_type": "gate_run",
            "actor": "trusted-runner",
            "record": {
                "gate_id": "gate.precondition",
                "criterion_id": "criterion-1",
                "collector_responsibility_group": "trusted-runtime",
            },
        },
    )
    assert code == 2
    assert evidence["exit_code"] == 7
    assert execution["precondition"]["command"]["args"] == precondition
    assert execution["precondition"]["exit_code"] == 7
    assert execution["command_executed"] is False
    assert marker.exists() is False
    assert ctx.load()["evidence"] == []


def test_gate_success_attests_precondition_and_main_command(tmp_path):
    workspace = tmp_path / "successful precondition workspace"
    workspace.mkdir()
    ctx = StateContext.build(
        runtime="codex",
        project="successful-precondition-project",
        workspace=str(workspace),
        session="successful-precondition-session",
        round_id="successful-precondition-round",
        state_root=tmp_path / "state",
    )
    trusted_python = str(_trusted_python_path())
    precondition = [trusted_python, "-c", "print('SETUP_PASS')"]
    command = [trusted_python, "-c", "print('MAIN_PASS')"]
    start_round(
        ctx,
        message="prove ordered successful gate",
        change_mode="replace",
        execution_mode="observe",
        quality_profile={
            "common_gates": [{"id": "gate.precondition", "precondition": precondition, "command": command}]
        },
    )
    evidence, execution, code = _run_authorized_gate(
        ctx,
        {
            "event_type": "gate_run",
            "actor": "trusted-runner",
            "record": {
                "gate_id": "gate.precondition",
                "criterion_id": "criterion-1",
                "collector_responsibility_group": "trusted-runtime",
            },
        },
    )
    assert code == 0
    assert execution["precondition"]["exit_code"] == 0
    assert execution["command_executed"] is True
    assert "SETUP_PASS" in execution["precondition"]["output_summary"]
    assert "MAIN_PASS" in execution["output_summary"]
    assert evidence["precondition"] == execution["precondition"]


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
    monkeypatch.setenv("PATH", str(trusted_bin))
    monkeypatch.setenv("PATHEXT", ".CMD")
    install_home = tmp_path / "gate-install-home"
    _write_install_source_fixture(install_home)
    _write_trusted_executable_registry(
        install_home,
        {Path(registered[0]).name.casefold(): trusted_shim},
    )
    monkeypatch.setenv("AGENT_SUPERVISOR_INSTALL_HOME", str(install_home))

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
    evidence, execution, code = _run_authorized_gate(
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
    project_schema, quality_schema = _write_config_schemas(supervisor_dir)
    project_file.write_text(json.dumps({
        "$schema": project_schema,
        "project_id": "e2e",
        "quality_profile": "quality.json",
        "supervisor_scope": {"allowed_change_globs": ["config.json", ".agent-supervisor/**"], "out_of_scope_globs": ["src/**"]},
    }), encoding="utf-8")
    quality_file.write_text(json.dumps({
        "$schema": quality_schema,
        **_trusted_quality_controls(),
        "global_gates": ["gate.e2e"],
        "common_gates": [{"id": "gate.e2e", "command": [str(_trusted_python_path()), "-c", "print('E2E_GATE_PASS')"]}],
        "domains": {"config/agent": {"required_gates": ["gate.e2e"]}},
        "profiles": {"config_agent": {"applies_to": ["config.json"], "gates": []}},
    }), encoding="utf-8")
    (workspace / "config.json").write_text('{"version":1}\n', encoding="utf-8")
    git_env = _git_fixture_env()
    subprocess.run(["git", "init", "-q", str(workspace)], check=True, env=git_env)
    subprocess.run(["git", "-C", str(workspace), "config", "user.email", "test@example.invalid"], check=True, env=git_env)
    subprocess.run(["git", "-C", str(workspace), "config", "user.name", "Supervisor E2E"], check=True, env=git_env)
    subprocess.run(["git", "-C", str(workspace), "add", ".agent-supervisor/project.json", ".agent-supervisor/quality.json", "config.json"], check=True, env=git_env)
    subprocess.run(["git", "-C", str(workspace), "commit", "-qm", "baseline"], check=True, env=git_env)

    env = _git_fixture_env()
    install_home = tmp_path / "install-home"
    isolated_home = tmp_path / "home"
    isolated_home.mkdir()
    _write_healthy_skill_fixture(isolated_home)
    _write_install_source_fixture(install_home)
    _write_trusted_executable_registry(install_home)
    env["AGENT_SUPERVISOR_ATTESTATION_KEY_FILE"] = str(tmp_path / "attestation.key")
    env["USERPROFILE"] = str(isolated_home)
    env["HOME"] = str(isolated_home)
    env["AGENT_SUPERVISOR_INSTALL_HOME"] = str(install_home)
    common = [
        "--runtime", "claude", "--workspace", str(workspace), "--session", "e2e-session",
        "--round", "e2e-round", "--project-file", str(project_file),
    ]
    goal = {
        "goal_id": "goal-e2e", "objective": "Prove the complete gate",
        "acceptance_criteria": [{"criterion_id": "criterion-e2e", "description": "Registered gate and independent review pass", "domain": "config-agent", "expected_evidence": ["gate.e2e"], "required": True}],
        "scope": {"in": ["config.json"], "out": ["src/**"]},
    }
    intents = [{"intent_id": "intent-e2e", "text": "implement and verify", "domain": "config-agent", "status": "deferred", "reason": "awaiting verified builder result", "capability_ids": ["builder"], "phase": 1}]
    started = run_cli(["start", *common, "--message", "implement and verify", "--change-mode", "replace", "--execution-mode", "enforce", "--goal-json", json.dumps(goal), "--intents-json", json.dumps(intents)], env)
    state_file = Path(started["state_file"])
    baseline = json.loads(state_file.read_text(encoding="utf-8"))["workspace_baseline"]
    hook_common = {"session_id": "e2e-session", "cwd": str(workspace)}
    run_hook("PreToolUse", {
        **hook_common, "tool_use_id": "invocation-e2e", "tool_name": "builder",
        "agent_id": "worker", "tool_input": {
            "capability": "builder", "responsibility_group": "implementation"
        },
    }, env)
    (workspace / "config.json").write_text('{"version":3}\n', encoding="utf-8")
    run_hook("PostToolUse", {
        **hook_common, "tool_use_id": "invocation-e2e", "tool_name": "builder",
        "agent_id": "worker", "tool_input": {
            "capability": "builder", "responsibility_group": "implementation"
        }, "success": True,
    }, env)
    delta = workspace_delta(baseline, capture_workspace_snapshot(str(workspace), baseline["extra_globs"]))

    def event(event_type: str, record: dict, *, actor: str = "worker", expected: int = 0) -> dict:
        return run_cli(["event", *common, "--event-type", event_type, "--actor", actor, "--data-json", json.dumps({"record": record})], env, expected)

    event("intent_disposition", {
        "intent_id": "intent-e2e", "status": "covered",
        "reason": "verified successful builder result", "capability_ids": ["builder"],
        "method": "capability", "phase": 1,
    })
    event("changes_record", {
        "files": delta["files"], "base": delta["base"], "head": delta["head"], "diff_hash": delta["diff_hash"],
        "git_object_format": delta["git_object_format"], "git_binding_status": delta["git_binding_status"],
        "git_binding_source": delta["git_binding_source"], "git_repository_root": delta["git_repository_root"],
        "review_artifact": delta["review_artifact"], "review_artifact_sha256": delta["review_artifact_sha256"],
        "git_diff_sha256": delta["git_diff_sha256"], "workspace_base_sha256": delta["workspace_base_sha256"],
        "workspace_head_sha256": delta["workspace_head_sha256"],
        "domains": ["config/agent"], "implementer": "worker", "implementer_responsibility_group": "implementation",
        "implementer_invocation_id": "invocation-e2e", "test_changes": {},
    })
    run_hook("PreToolUse", {
        **hook_common, "tool_use_id": "gate-invocation-e2e", "tool_name": "independent-gate-runner",
        "agent_id": "gate-runner", "tool_input": {
            "capability": "independent-gate-runner",
            "responsibility_group": "independent-quality-review",
        },
    }, env)
    gate = event("gate_run", {
        "gate_id": "gate.e2e", "criterion_id": "criterion-e2e", "evidence_id": "evidence-e2e",
        "collector_responsibility_group": "independent-quality-review",
        "collector_invocation_id": "gate-invocation-e2e",
    }, actor="gate-runner")
    assert gate["exit_code"] == 0
    run_hook("PostToolUse", {
        **hook_common, "tool_use_id": "gate-invocation-e2e", "tool_name": "independent-gate-runner",
        "agent_id": "gate-runner", "tool_input": {
            "capability": "independent-gate-runner",
            "responsibility_group": "independent-quality-review",
        }, "success": True,
    }, env)
    event("task_record", {
        "task_id": "task-e2e", "goal_id": "goal-e2e", "goal_version": 1,
        "criterion_ids": ["criterion-e2e"], "allowed_paths": ["config.json"],
        "expected_evidence": ["gate.e2e"], "status": "done", "evidence_ids": ["evidence-e2e"],
    })
    event("spec_record", {"status": "approved", "hash": "a" * 64, "path": "spec.md", "content": "Exact e2e contract"})
    run_hook("PreToolUse", {
        **hook_common, "tool_use_id": "review-invocation-e2e", "tool_name": "independent-reviewer",
        "agent_id": "reviewer", "tool_input": {
            "capability": "independent-reviewer",
            "responsibility_group": "independent-quality-reviewer",
        },
    }, env)
    run_hook("PostToolUse", {
        **hook_common, "tool_use_id": "review-invocation-e2e", "tool_name": "independent-reviewer",
        "agent_id": "reviewer", "tool_input": {
            "capability": "independent-reviewer",
            "responsibility_group": "independent-quality-reviewer",
        }, "success": True,
    }, env)
    event("review_finalize", {
        "contract": "ReviewRecord/v3", "review_id": "review-e2e", "goal_id": "goal-e2e", "goal_version": 1,
        "reviewer": "reviewer", "reviewer_responsibility_group": "independent-quality-reviewer",
        "implementer": "worker", "implementer_responsibility_group": "implementation",
        "gate_collector": "gate-runner", "gate_collector_responsibility_group": "independent-quality-review",
        "gate_runner_invocation_id": "gate-invocation-e2e",
        "base": delta["base"], "head": delta["head"], "diff_hash": delta["diff_hash"],
        "git_object_format": delta["git_object_format"], "git_binding_status": delta["git_binding_status"],
        "git_binding_source": delta["git_binding_source"], "git_repository_root": delta["git_repository_root"],
        "review_artifact_sha256": delta["review_artifact_sha256"], "git_diff_sha256": delta["git_diff_sha256"],
        "workspace_base_sha256": delta["workspace_base_sha256"], "workspace_head_sha256": delta["workspace_head_sha256"],
        "rerun_evidence_ids": ["evidence-e2e"],
        "evidence_verification": {"status": "VERIFIED", "reviewer": "reviewer", "evidence_ids": ["evidence-e2e"]},
        "verdict": "APPROVE", "category": "config-agent",
        "implementer_invocation_id": "invocation-e2e", "reviewer_invocation_id": "review-invocation-e2e",
    }, actor="reviewer")

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
    project_schema, quality_schema = _write_config_schemas(supervisor_dir)
    project_file.write_text(json.dumps({
        "$schema": project_schema,
        "project_id": "rollback-e2e", "quality_profile": "quality.json",
        "supervisor_scope": {"allowed_change_globs": [".agent-supervisor/**"], "out_of_scope_globs": []},
    }), encoding="utf-8")
    quality_file.write_text(json.dumps({
        "$schema": quality_schema,
        **_trusted_quality_controls(),
        "global_gates": ["gate.fail"],
        "common_gates": [{
            "id": "gate.fail",
            "command": [str(_trusted_python_path()), "-c", "import time; time.sleep(0.15); raise SystemExit(1)"],
        }],
    }), encoding="utf-8")

    current = tmp_path / "current-core"
    previous = tmp_path / "previous-core"
    active_identity = _write_release_root_fixture(current, "3.1.0")
    previous_identity = _write_release_root_fixture(previous, "3.0.0")
    pointer = tmp_path / "active-version.json"
    pointer.write_text(json.dumps({
        "contract": "ActiveVersionPointer/v4",
        "active": active_identity,
        "previous": previous_identity,
    }), encoding="utf-8")
    env = _git_fixture_env()
    isolated_home = tmp_path / "home"
    _write_healthy_skill_fixture(isolated_home)
    env["USERPROFILE"] = str(isolated_home)
    env["HOME"] = str(isolated_home)
    env["AGENT_SUPERVISOR_ACTIVE_POINTER"] = str(pointer)
    env["AGENT_SUPERVISOR_ATTESTATION_KEY_FILE"] = str(tmp_path / "rollback-attestation.key")
    common = [
        "--runtime", "codex", "--workspace", str(workspace), "--session", "rollback-session",
        "--round", "rollback-round", "--project-file", str(project_file), "--state-root", str(tmp_path / "state"),
    ]
    run_cli(["start", *common, "--message", "exercise rollback", "--change-mode", "replace", "--execution-mode", "warn"], env)
    gate_record = {"gate_id": "gate.fail", "criterion_id": "criterion-1", "collector_responsibility_group": "quality"}
    run_cli_authorized_gate(common, env, invocation_id="rollback-gate-0", actor="reviewer", record=gate_record, expected=2)
    with ThreadPoolExecutor(max_workers=2) as pool:
        concurrent_results = list(pool.map(
            lambda index: run_cli_authorized_gate(
                common, env, invocation_id=f"rollback-gate-{index + 1}",
                actor="reviewer", record=gate_record, expected=2,
            ),
            range(2),
        ))
    assert len(concurrent_results) == 2
    active = json.loads(pointer.read_text(encoding="utf-8"))["active"]
    assert active["version"] == "3.0.0"
    state = run_cli(["query", *common], env)
    assert state["rollout"]["rollback"]["performed"] is True
    assert state["rollout"]["rollback"]["attempted"] is True
    assert state["rollout"]["rollback"]["attempt_count"] == 1
    assert state["rollout"]["rollback"]["expected_active"]["version"] == "3.1.0"
    assert set(json.loads(pointer.read_text(encoding="utf-8"))) == {
        "contract", "active", "previous",
    }

    promotion_payload = json.dumps({"record": {
        "contract": "RolloutPromotion/v3",
        "promotion_id": "replay-after-rollback",
        "requested_mode": "observe",
    }})
    run_cli([
        "event", *common, "--event-type", "rollout_promote", "--actor", "supervisor",
        "--data-json", promotion_payload,
    ], env)
    run_cli_authorized_gate(common, env, invocation_id="rollback-gate-replay", actor="reviewer", record=gate_record, expected=2)
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
    active_identity = _write_release_root_fixture(current, "3.1.0")
    previous_identity = _write_release_root_fixture(previous, "3.0.0")
    pointer = tmp_path / "active-version.json"
    pointer.write_text(json.dumps({
        "contract": "ActiveVersionPointer/v4",
        "active": active_identity,
        "previous": previous_identity,
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
        "common_gates": [{"id": "gate.fail", "command": [str(_trusted_python_path()), "-c", "raise SystemExit(1)"]}],
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
    assert _run_authorized_gate(ctx, payload)[2] == 2
    real_rollback = cli_module.rollback_active_version

    def crash_before_effect(*, expected_active=None):
        raise SystemExit("simulated process crash after claim")

    monkeypatch.setattr(cli_module, "rollback_active_version", crash_before_effect)
    with pytest.raises(SystemExit, match="simulated process crash"):
        _run_authorized_gate(ctx, payload)
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
    assert _run_authorized_gate(ctx, payload)[2] == 2
    recovered = ctx.load_project_rollout()["rollback"]
    recovered_pointer = json.loads(pointer.read_text(encoding="utf-8"))
    assert recovered_pointer["active"]["version"] == "3.0.0"
    if pointer_effect_before_recovery:
        assert recovered == {"required": False, "performed": False, "target": None}
        archived = ctx.load_project_rollout()["rollback_history"][-1]
        assert archived["claim_status"] == "retriable"
        assert archived["reason"] == "active-version-cas-mismatch"
        assert archived["attempt_count"] == 2
        assert archived["recovery_count"] == 1
        assert archived["reset_reason"] == "claim-active-version-cas-mismatch"
    else:
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
    project_schema, quality_schema = _write_config_schemas(supervisor_dir)
    project_file.write_text(json.dumps({
        "$schema": project_schema,
        "project_id": "identity-bound-rollback",
        "quality_profile": "quality.json",
        "supervisor_scope": {"allowed_change_globs": [".agent-supervisor/**"], "out_of_scope_globs": []},
    }), encoding="utf-8")
    quality_file.write_text(json.dumps({
        "$schema": quality_schema,
        **_trusted_quality_controls(),
        "global_gates": ["gate.fail"],
        "common_gates": [{"id": "gate.fail", "command": [str(_trusted_python_path()), "-c", "raise SystemExit(1)"]}],
    }), encoding="utf-8")
    pointer = tmp_path / "active-version.json"
    env = _git_fixture_env()
    isolated_home = tmp_path / "home"
    _write_healthy_skill_fixture(isolated_home)
    env["USERPROFILE"] = str(isolated_home)
    env["HOME"] = str(isolated_home)
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
    gate_record = {
        "gate_id": "gate.fail",
        "criterion_id": "criterion-1",
        "collector_responsibility_group": "quality",
    }
    run_cli_authorized_gate(common, env, invocation_id="identity-gate-1", actor="reviewer", record=gate_record, expected=2)
    run_cli_authorized_gate(common, env, invocation_id="identity-gate-2", actor="reviewer", record=gate_record, expected=2)
    unbound = run_cli(["query", *common], env)["rollout"]
    assert unbound["metrics"]["unbound_global_gate_failures"] == 2
    assert unbound["metrics"]["consecutive_global_gate_failures"] == 0
    assert unbound["rollback"]["required"] is False

    new_release = tmp_path / "new-release"
    old_release = tmp_path / "old-release"
    active_identity = _write_release_root_fixture(new_release, "4.0.0")
    previous_identity = _write_release_root_fixture(old_release, "3.0.1")
    pointer.write_text(json.dumps({
        "contract": "ActiveVersionPointer/v4",
        "active": active_identity,
        "previous": previous_identity,
    }), encoding="utf-8")
    run_cli_authorized_gate(common, env, invocation_id="identity-gate-3", actor="reviewer", record=gate_record, expected=2)
    after_first_bound_failure = run_cli(["query", *common], env)["rollout"]
    assert json.loads(pointer.read_text(encoding="utf-8"))["active"]["version"] == "4.0.0"
    assert after_first_bound_failure["metrics"]["consecutive_global_gate_failures"] == 1
    assert after_first_bound_failure["rollback"]["required"] is False

    run_cli_authorized_gate(common, env, invocation_id="identity-gate-4", actor="reviewer", record=gate_record, expected=2)
    after_threshold = run_cli(["query", *common], env)["rollout"]
    assert json.loads(pointer.read_text(encoding="utf-8"))["active"]["version"] == "3.0.1"
    assert after_threshold["rollback"]["performed"] is True
    assert after_threshold["rollback"]["expected_active"]["version"] == "4.0.0"
