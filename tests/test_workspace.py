from __future__ import annotations

import os
import subprocess

import pytest

from supervisor_core import workspace as workspace_module
from supervisor_core.workspace import capture_workspace_snapshot, workspace_delta


@pytest.fixture(autouse=True)
def isolate_git_configuration(monkeypatch):
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    for variable in (
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_COMMON_DIR",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    ):
        monkeypatch.delenv(variable, raising=False)


def test_workspace_tests_clear_inherited_git_repository_context():
    for variable in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
        assert variable not in os.environ


def test_runtime_supervisor_files_cannot_manufacture_a_workspace_diff(tmp_path):
    workspace = tmp_path / "runtime-state workspace"
    contract = workspace / ".agent-supervisor" / "project.json"
    contract.parent.mkdir(parents=True)
    contract.write_text('{"version":1}\n', encoding="utf-8")
    tracked_handoff = workspace / ".agent-supervisor" / "handoffs" / "tracked" / "latest.md"
    tracked_handoff.parent.mkdir(parents=True)
    tracked_handoff.write_text("tracked runtime handoff v1\n", encoding="utf-8")
    tracked_runtime_cache = workspace / ".agent-supervisor" / ".pytest-tmp-versioned" / "result.json"
    tracked_runtime_cache.parent.mkdir(parents=True)
    tracked_runtime_cache.write_text('{"result":1}\n', encoding="utf-8")
    tracked_codex_state = workspace / ".codex-supervisor" / "context-snapshot.md"
    tracked_codex_state.parent.mkdir(parents=True)
    tracked_codex_state.write_text("tracked context v1\n", encoding="utf-8")
    versioned_cache_shapes = [
        workspace / "scripts" / "__pycache__" / "adapter.py",
        workspace / "fixtures" / ".pytest_cache" / "contract.json",
        workspace / "fixtures" / ".pytest-tmp-contract" / "schema.json",
    ]
    for path in versioned_cache_shapes:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("version 1\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(workspace)], check=True)
    subprocess.run([
        "git", "-C", str(workspace), "add",
        ".agent-supervisor/project.json",
        ".agent-supervisor/handoffs/tracked/latest.md",
        ".agent-supervisor/.pytest-tmp-versioned/result.json",
        ".codex-supervisor/context-snapshot.md",
        "scripts/__pycache__/adapter.py",
        "fixtures/.pytest_cache/contract.json",
        "fixtures/.pytest-tmp-contract/schema.json",
    ], check=True)
    subprocess.run([
        "git", "-c", "user.email=test@example.invalid", "-c", "user.name=Supervisor Test",
        "-C", str(workspace), "commit", "-qm", "baseline",
    ], check=True)

    baseline = capture_workspace_snapshot(str(workspace), [".agent-supervisor/**", ".codex-supervisor/**"])
    handoff = workspace / ".agent-supervisor" / "handoffs" / "session" / "latest.md"
    handoff.parent.mkdir(parents=True)
    handoff.write_text("runtime handoff\n", encoding="utf-8")
    pytest_cache = workspace / ".agent-supervisor" / ".pytest-tmp-probe" / "result.json"
    pytest_cache.parent.mkdir(parents=True)
    pytest_cache.write_text("{}\n", encoding="utf-8")
    codex_state = workspace / ".codex-supervisor" / "context-snapshot.md"
    codex_state.parent.mkdir(parents=True, exist_ok=True)
    codex_state.write_text("runtime context\n", encoding="utf-8")
    tracked_handoff.write_text("tracked runtime handoff v2\n", encoding="utf-8")
    tracked_runtime_cache.write_text('{"result":2}\n', encoding="utf-8")
    tracked_codex_state.write_text("tracked context v2\n", encoding="utf-8")

    runtime_only = workspace_delta(
        baseline,
        capture_workspace_snapshot(str(workspace), baseline["extra_globs"]),
    )
    assert runtime_only["files"] == []

    contract.write_text('{"version":2}\n', encoding="utf-8")
    for path in versioned_cache_shapes:
        path.write_text("version 2\n", encoding="utf-8")
    with_contract_change = workspace_delta(
        baseline,
        capture_workspace_snapshot(str(workspace), baseline["extra_globs"]),
    )
    assert with_contract_change["files"] == [
        ".agent-supervisor/project.json",
        "fixtures/.pytest-tmp-contract/schema.json",
        "fixtures/.pytest_cache/contract.json",
        "scripts/__pycache__/adapter.py",
    ]


def test_workspace_snapshot_hashes_link_metadata_without_reading_external_target(tmp_path):
    workspace = tmp_path / "workspace"
    external = tmp_path / "outside.txt"
    workspace.mkdir()
    external.write_text("external secret must not be read\n", encoding="utf-8")
    link = workspace / "linked.txt"
    try:
        os.symlink(external, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable on this host")
    subprocess.run(["git", "init", "-q", str(workspace)], check=True)
    subprocess.run(["git", "-C", str(workspace), "config", "core.symlinks", "true"], check=True)
    subprocess.run(["git", "-C", str(workspace), "add", "linked.txt"], check=True)

    first = capture_workspace_snapshot(str(workspace), ["linked.txt"])
    assert "linked.txt" in first["files"]
    external.write_text("changed external secret\n", encoding="utf-8")
    second = capture_workspace_snapshot(str(workspace), ["linked.txt"])
    assert second["files"]["linked.txt"] == first["files"]["linked.txt"]


def test_workspace_snapshot_returns_explicit_degraded_state_when_git_times_out(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    def timeout(*args, **kwargs):
        assert kwargs["timeout"] == workspace_module._GIT_TIMEOUT_SECONDS
        raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])

    monkeypatch.setattr(workspace_module.subprocess, "run", timeout)

    snapshot = capture_workspace_snapshot(str(workspace))

    assert snapshot["contract"] == "WorkspaceSnapshot/v3"
    assert snapshot["status"] == "degraded"
    assert snapshot["reason"] == "git-timeout"
    assert snapshot["git"] is False


def test_workspace_snapshot_supports_an_unborn_git_repository(tmp_path):
    workspace = tmp_path / "unborn"
    workspace.mkdir()
    (workspace / "new.txt").write_text("new\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(workspace)], check=True)

    snapshot = capture_workspace_snapshot(str(workspace))

    assert snapshot["git"] is True
    assert snapshot["head"] == ""
    assert "new.txt" in snapshot["files"]
