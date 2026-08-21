from __future__ import annotations

import subprocess

from supervisor_core.workspace import capture_workspace_snapshot, workspace_delta


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
    subprocess.run(["git", "-C", str(workspace), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(workspace), "config", "user.name", "Supervisor Test"], check=True)
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
    subprocess.run(["git", "-C", str(workspace), "commit", "-qm", "baseline"], check=True)

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
