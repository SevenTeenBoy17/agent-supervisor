from __future__ import annotations

import argparse
import io
import json
import sys

from supervisor_core.cli import _pretool_policy, command_hook


def test_malformed_hook_without_session_returns_degraded_and_persists_marker(
    tmp_path, monkeypatch, capsys
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CLAUDE_SESSION_ID", raising=False)
    monkeypatch.delenv("CODEX_THREAD_ID", raising=False)
    monkeypatch.setattr(sys, "stdin", io.StringIO("not-json"))
    args = argparse.Namespace(runtime="claude", event="UserPromptSubmit")

    assert command_hook(args) == 4

    response = json.loads(capsys.readouterr().out)
    assert response["agent_supervisor"] == {
        "health": "degraded",
        "error": "InvalidState",
        "fail_open": True,
    }
    marker_text = (tmp_path / ".agent-supervisor" / "adapter-health.json").read_text(
        encoding="utf-8"
    )
    marker = json.loads(marker_text)
    assert marker["health"] == "degraded"
    assert marker["error_type"] == "InvalidState"
    assert "not-json" not in marker_text


def test_active_lease_cannot_expand_goal_or_project_write_scope(tmp_path) -> None:
    state = {
        "workspace": str(tmp_path),
        "goal": {
            "goal_id": "goal-1",
            "version": 1,
            "scope": {"in": [".agent-supervisor/**"], "out": ["src/**"]},
            "t3_action_authorizations": [],
        },
        "project_policy": {
            "allowed_change_globs": [".agent-supervisor/**"],
            "out_of_scope_globs": ["src/**"],
        },
        "tasks": [{
            "task_id": "overbroad-task",
            "goal_id": "goal-1",
            "goal_version": 1,
            "lease_id": "lease-1",
            "lease_status": "active",
            "owner": "worker-a",
            "responsibility_group": "implementation",
            "allowed_paths": ["**"],
        }],
    }

    denied = _pretool_policy(
        state,
        tool_name="Write",
        tool_input={"file_path": str(tmp_path / "src" / "product.py")},
        actor="worker-a",
    )

    assert denied["deny"] is True
    assert denied["category"] == "write-scope"
