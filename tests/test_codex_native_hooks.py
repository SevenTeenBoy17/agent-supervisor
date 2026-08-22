from __future__ import annotations

import argparse
import io
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

import supervisor_core.cli as cli_module
import supervisor_core.workspace as workspace_module
from supervisor_core.cli import command_hook
from supervisor_core.lifecycle import start_round
from supervisor_core.storage import StateContext
from supervisor_core.util import sha256_text
from supervisor_core.validation import _trusted_invocation_for_runtime


RAW_PROMPT = "RAW_PROMPT_SENTINEL_7F29 implement the bounded src change and verify it."


def _git_fixture_env() -> dict[str, str]:
    env = os.environ.copy()
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
        env.pop(name, None)
    return env


@pytest.fixture(autouse=True)
def _isolate_inherited_git_repository(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
        monkeypatch.delenv(name, raising=False)


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


def _quality_controls() -> dict[str, Any]:
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
                "actor",
                "responsibility_group",
                "base",
                "head",
                "diff_hash",
                "rerun_evidence",
                "implementer_invocation_id",
                "reviewer_invocation_id",
                "actor_identity_assurance",
            ],
        },
    }


def _write_codex_workspace(workspace: Path) -> None:
    supervisor = workspace / ".agent-supervisor"
    schemas = supervisor / "schemas"
    schemas.mkdir(parents=True)
    (workspace / "src").mkdir()
    (workspace / "src" / "baseline.py").write_text("VALUE = 1\n", encoding="utf-8")
    generic_schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": True,
    }
    (schemas / "project.schema.json").write_text(
        json.dumps(generic_schema), encoding="utf-8"
    )
    (schemas / "quality.schema.json").write_text(
        json.dumps(generic_schema), encoding="utf-8"
    )
    (supervisor / "project.json").write_text(
        json.dumps(
            {
                "$schema": "schemas/project.schema.json",
                "project_id": "codex-native-hooks",
                "quality_profile": "quality.json",
                "execution_mode": "enforce",
                "supervisor_scope": {
                    "allowed_change_globs": ["src/**"],
                    "out_of_scope_globs": ["secret/**"],
                },
                "privacy": {
                    "persist_raw_prompts": False,
                    "persist_raw_command_arguments": False,
                    "redact_before_persist": True,
                },
            }
        ),
        encoding="utf-8",
    )
    (supervisor / "quality.json").write_text(
        json.dumps(
            {
                "$schema": "schemas/quality.schema.json",
                **_quality_controls(),
                "global_gates": ["gate.native"],
                "common_gates": [
                    {
                        "id": "gate.native",
                        "command": [sys.executable, "-c", "print('native-hook-pass')"],
                    }
                ],
                "domains": {"config/agent": {"required_gates": ["gate.native"]}},
            }
        ),
        encoding="utf-8",
    )
    git_env = _git_fixture_env()
    subprocess.run(["git", "init", "-q", str(workspace)], check=True, env=git_env)
    subprocess.run(
        ["git", "-C", str(workspace), "config", "user.email", "codex-hooks@example.invalid"],
        check=True,
        env=git_env,
    )
    subprocess.run(
        ["git", "-C", str(workspace), "config", "user.name", "Codex Hook Tests"],
        check=True,
        env=git_env,
    )
    subprocess.run(
        ["git", "-C", str(workspace), "add", ".agent-supervisor", "src"],
        check=True,
        env=git_env,
    )
    subprocess.run(
        ["git", "-C", str(workspace), "commit", "-qm", "baseline"],
        check=True,
        env=git_env,
    )


def _run_hook(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    *,
    state_root: Path,
    event: str,
    payload: dict[str, Any],
) -> tuple[int, dict[str, Any]]:
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload, ensure_ascii=False)))
    code = command_hook(
        argparse.Namespace(runtime="codex", event=event, state_root=str(state_root))
    )
    raw = capsys.readouterr().out.strip()
    return code, json.loads(raw or "{}")


@pytest.fixture
def codex_round(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]):
    workspace = tmp_path / "Codex native 中文 workspace"
    workspace.mkdir()
    _write_codex_workspace(workspace)
    state_root = tmp_path / "isolated-state"
    install_home = tmp_path / "install-home"
    _write_install_source_fixture(install_home)
    monkeypatch.setenv("AGENT_SUPERVISOR_ATTESTATION_KEY_FILE", str(tmp_path / "attestation.key"))
    monkeypatch.setenv("AGENT_SUPERVISOR_INSTALL_HOME", str(install_home))
    session = "codex-native-session"
    common = {"session_id": session, "cwd": str(workspace)}

    session_code, session_output = _run_hook(
        monkeypatch,
        capsys,
        state_root=state_root,
        event="SessionStart",
        payload=common,
    )
    assert session_code == 0
    assert session_output["hookSpecificOutput"]["hookEventName"] == "SessionStart"

    prompt_code, prompt_output = _run_hook(
        monkeypatch,
        capsys,
        state_root=state_root,
        event="UserPromptSubmit",
        payload={**common, "prompt": RAW_PROMPT},
    )
    assert prompt_code == 0
    assert prompt_output["hookSpecificOutput"]["hookEventName"] == "UserPromptSubmit"
    state_files = list(state_root.rglob("state.json"))
    assert len(state_files) == 1
    state_file = state_files[0]
    state = json.loads(state_file.read_text(encoding="utf-8"))
    assert state["runtime"] == "codex"
    assert state["workspace"] == str(workspace.resolve())
    assert state_root.resolve() in state_file.resolve().parents
    assert state["supervisor_source_snapshot"]["status"] == "healthy"
    assert all(
        Path(root).is_relative_to(install_home)
        for name, root in state["supervisor_source_snapshot"]["roots"].items()
        if name.endswith("adapter")
    )
    criterion_id = state["goal"]["acceptance_criteria"][0]["criterion_id"]
    state["tasks"] = [
        {
            "task_id": "task-codex-write",
            "goal_id": state["goal"]["goal_id"],
            "goal_version": state["goal"]["version"],
            "criterion_ids": [criterion_id],
            "allowed_paths": ["src/**"],
            "expected_evidence": ["gate.native"],
            "status": "doing",
            "lease_id": "lease-codex-write",
            "lease_status": "active",
            "owner": "codex",
            "responsibility_group": "implementation",
        }
    ]
    # Stop-hook semantics are exercised at the enforce boundary independently
    # of the rollout module's initial observe canary.
    state["execution_mode"] = "enforce"
    state_file.write_text(json.dumps(state), encoding="utf-8")
    ctx = StateContext(
        runtime=state["runtime"],
        project=state["project"],
        workspace=state["workspace"],
        session=state["session"],
        round=state["round"],
        root=state_file.parent,
    )
    return workspace, state_root, common, ctx


def test_codex_apply_patch_scope_and_native_invocation_correlation(
    codex_round, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    workspace, state_root, common, ctx = codex_round
    patch = "*** Begin Patch\n*** Add File: src/new.py\n+VALUE = 2\n*** End Patch"
    pre_code, pre_output = _run_hook(
        monkeypatch,
        capsys,
        state_root=state_root,
        event="PreToolUse",
        payload={
            **common,
            "tool_use_id": "apply-1",
            "tool_name": "apply_patch_v2",
            "tool_input": {"command": patch},
        },
    )
    assert pre_code == 0
    assert pre_output == {}

    post_code, post_output = _run_hook(
        monkeypatch,
        capsys,
        state_root=state_root,
        event="PostToolUse",
        payload={
            **common,
            "tool_use_id": "apply-1",
            "tool_name": "apply_patch_v2",
            "tool_input": {"command": patch},
            "tool_response": {"status": "completed", "exit_code": 0},
        },
    )
    assert post_code == 0
    assert post_output == {}
    state = ctx.load()
    assert _trusted_invocation_for_runtime(
        ctx.events(), "apply-1", actor="codex", state=state
    )
    pair = [
        row
        for row in ctx.events()
        if row.get("invocation_id") == "apply-1"
        and row.get("event_type") in {"invocation_attempt", "invocation_result"}
    ]
    assert [row["identity_assurance"] for row in pair] == [
        "host-hook-observed",
        "host-hook-observed",
    ]
    assert all(row["actor"] == "codex" for row in pair)

    for invocation_id, denied_patch in (
        (
            "outside-1",
            "*** Begin Patch\n*** Add File: secret/escape.py\n+x = 1\n*** End Patch",
        ),
        (
            "absolute-1",
            f"*** Begin Patch\n*** Update File: {(workspace / 'src' / 'absolute.py').resolve()}\n@@\n-x\n+y\n*** End Patch",
        ),
        (
            "malformed-1",
            "*** Begin Patch\n*** Add File src/missing-colon.py\n+x = 1\n*** End Patch",
        ),
    ):
        code, output = _run_hook(
            monkeypatch,
            capsys,
            state_root=state_root,
            event="PreToolUse",
            payload={
                **common,
                "tool_use_id": invocation_id,
                "tool_name": "apply_patch",
                "tool_input": {"patch": denied_patch},
            },
        )
        assert code == 0
        assert output["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_codex_prompt_privacy_persists_hashes_not_raw_prompt(codex_round) -> None:
    _, state_root, _, ctx = codex_round
    persisted_text = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in state_root.rglob("*")
        if path.is_file()
    )
    state = ctx.load()

    assert RAW_PROMPT not in persisted_text
    assert "RAW_PROMPT_SENTINEL_7F29" not in persisted_text
    assert sha256_text(RAW_PROMPT) in persisted_text
    assert state["goal"]["original_request_sha256"] == sha256_text(RAW_PROMPT)
    assert state["prompt_privacy"] == {
        "raw_prompt_persisted": False,
        "request_sha256": sha256_text(RAW_PROMPT),
    }
    assert all("RAW_PROMPT_SENTINEL_7F29" not in row["text"] for row in state["intents"])


def test_privacy_safe_continue_hashes_legacy_prompt_text_without_rewriting_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    workspace = tmp_path / "legacy privacy workspace"
    workspace.mkdir()
    _write_codex_workspace(workspace)
    state_root = tmp_path / "legacy-state"
    install_home = tmp_path / "legacy-install-home"
    _write_install_source_fixture(install_home)
    monkeypatch.setenv("AGENT_SUPERVISOR_ATTESTATION_KEY_FILE", str(tmp_path / "attestation.key"))
    monkeypatch.setenv("AGENT_SUPERVISOR_INSTALL_HOME", str(install_home))
    config = json.loads(
        (workspace / ".agent-supervisor" / "project.json").read_text(encoding="utf-8")
    )
    quality = json.loads(
        (workspace / ".agent-supervisor" / "quality.json").read_text(encoding="utf-8")
    )
    session = "legacy-privacy-session"
    legacy_ctx = StateContext.build(
        runtime="codex",
        project=config["project_id"],
        workspace=str(workspace),
        session=session,
        round_id="legacy-round",
        state_root=state_root,
    )
    legacy_prompt = "LEGACY_RAW_PROMPT_SENTINEL_91C4 implement the private src task"
    legacy = start_round(
        legacy_ctx,
        message=legacy_prompt,
        change_mode="replace",
        execution_mode="observe",
        project_config=config,
        quality_profile=quality,
    )
    assert legacy_prompt in legacy_ctx.state_file.read_text(encoding="utf-8")

    code, output = _run_hook(
        monkeypatch,
        capsys,
        state_root=state_root,
        event="UserPromptSubmit",
        payload={
            "session_id": session,
            "cwd": str(workspace),
            "prompt": "继续完成并验证当前任务",
        },
    )
    assert code == 0
    assert output["hookSpecificOutput"]["hookEventName"] == "UserPromptSubmit"
    pointer = legacy_ctx.previous_pointer()
    new_state_file = Path(pointer["state_file"])
    assert new_state_file != legacy_ctx.state_file
    new_state = json.loads(new_state_file.read_text(encoding="utf-8"))
    new_round_text = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in new_state_file.parent.rglob("*")
        if path.is_file()
    )

    assert legacy_prompt in legacy_ctx.state_file.read_text(encoding="utf-8")
    assert "LEGACY_RAW_PROMPT_SENTINEL_91C4" not in new_round_text
    assert "LEGACY_RAW_PROMPT_SENTINEL_91C4" not in json.dumps(
        new_state.get("prior_rounds", []), ensure_ascii=False
    )
    assert new_state["goal"]["goal_id"] == legacy["goal"]["goal_id"]
    assert new_state["goal"]["version"] == legacy["goal"]["version"] + 1
    assert new_state["goal"]["change_mode"] == "continue"
    assert new_state["goal"]["objective"].startswith("Legacy objective sha256:")
    assert any(
        row["description"].startswith("Legacy criterion sha256:")
        for row in new_state["goal"]["acceptance_criteria"]
    )
    assert any(
        row["text"].startswith("Legacy intent sha256:")
        for row in new_state["intents"]
    )


def test_write_lease_policy_observes_warns_then_blocks_by_rollout_mode(
    codex_round, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _, state_root, common, ctx = codex_round
    state = ctx.load()
    state["tasks"] = []
    ctx.save(state)
    patch = "*** Begin Patch\n*** Add File: src/no-lease.py\n+VALUE = 3\n*** End Patch"

    outputs: dict[str, dict[str, Any]] = {}
    for mode in ("observe", "warn", "enforce"):
        ctx.update(lambda current, mode=mode: current.update({"execution_mode": mode}))
        code, output = _run_hook(
            monkeypatch,
            capsys,
            state_root=state_root,
            event="PreToolUse",
            payload={
                **common,
                "tool_use_id": f"no-lease-{mode}",
                "tool_name": "apply_patch",
                "tool_input": {"command": patch},
            },
        )
        assert code == 0
        outputs[mode] = output

    assert outputs["observe"] == {}
    assert "permissionDecision" not in outputs["warn"]["hookSpecificOutput"]
    assert "would deny" in outputs["warn"]["hookSpecificOutput"]["additionalContext"]
    assert outputs["enforce"]["hookSpecificOutput"]["permissionDecision"] == "deny"
    policy_events = {
        row["invocation_id"]: row
        for row in ctx.events()
        if row.get("event_type") == "pretool_policy"
        and str(row.get("invocation_id", "")).startswith("no-lease-")
    }
    assert policy_events["no-lease-observe"]["status"] == "observed"
    assert policy_events["no-lease-warn"]["status"] == "warned"
    assert policy_events["no-lease-enforce"]["status"] == "denied"
    assert all(row["would_deny"] is True for row in policy_events.values())
    attempted = {
        row.get("invocation_id")
        for row in ctx.events()
        if row.get("event_type") == "invocation_attempt"
    }
    assert {"no-lease-observe", "no-lease-warn"}.issubset(attempted)
    assert "no-lease-enforce" not in attempted


def test_codex_shell_t3_and_failed_posttool_response_are_not_success(
    codex_round, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _, state_root, common, ctx = codex_round
    t3_code, t3_output = _run_hook(
        monkeypatch,
        capsys,
        state_root=state_root,
        event="PreToolUse",
        payload={
            **common,
            "tool_use_id": "t3-1",
            "tool_name": "exec_command",
            "tool_input": {"cmd": "git push --force origin main"},
        },
    )
    assert t3_code == 0
    assert t3_output["hookSpecificOutput"]["permissionDecision"] == "deny"

    safe_payload = {
        **common,
        "tool_use_id": "shell-1",
        "tool_name": "exec_command",
        "tool_input": {"cmd": "python -c \"print('safe')\""},
    }
    assert _run_hook(
        monkeypatch, capsys, state_root=state_root, event="PreToolUse", payload=safe_payload
    ) == (0, {})
    assert _run_hook(
        monkeypatch,
        capsys,
        state_root=state_root,
        event="PostToolUse",
        payload={**safe_payload, "tool_response": {"exitCode": "2", "status": "completed"}},
    ) == (0, {})
    result = next(
        row
        for row in ctx.events()
        if row.get("invocation_id") == "shell-1" and row.get("event_type") == "invocation_result"
    )
    assert result["result"] == "failed"
    assert not _trusted_invocation_for_runtime(
        ctx.events(), "shell-1", actor="codex", state=ctx.load()
    )


def test_codex_subagent_and_stop_lifecycle_never_force_success(
    codex_round, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _, state_root, common, ctx = codex_round
    initial = ctx.load()
    for event in ("SubagentStart", "SubagentStop"):
        code, output = _run_hook(
            monkeypatch,
            capsys,
            state_root=state_root,
            event=event,
            payload={**common, "agent_id": "reviewer-1", "agent_type": "reviewer"},
        )
        assert code == 0
        assert output == {}
    after_subagent = ctx.load()
    assert after_subagent["terminal_state"] == initial["terminal_state"]
    assert after_subagent["stop_attempts"] == initial["stop_attempts"]
    event_types = {row.get("event_type") for row in ctx.events()}
    assert {"subagent_start", "subagent_stop_review"}.issubset(event_types)
    subagent_start = next(
        row for row in ctx.events() if row.get("event_type") == "subagent_start"
    )
    assert subagent_start["actor"] == "reviewer-1"
    assert subagent_start["capability"] == "reviewer"

    session_end_code, session_end_output = _run_hook(
        monkeypatch,
        capsys,
        state_root=state_root,
        event="SessionEnd",
        payload=common,
    )
    assert session_end_code == 0
    assert session_end_output == {}
    session_end = next(
        row for row in ctx.events() if row.get("event_type") == "session_end"
    )
    assert session_end["actor"] == "codex"
    assert session_end["identity_assurance"] == "host-hook-observed"

    outputs = []
    for _ in range(3):
        code, output = _run_hook(
            monkeypatch,
            capsys,
            state_root=state_root,
            event="Stop",
            payload=common,
        )
        assert code == 0
        outputs.append(output)
    assert outputs[0]["decision"] == "block"
    assert outputs[1]["decision"] == "block"
    assert outputs[2] == {}
    final_state = ctx.load()
    assert final_state["stop_attempts"] == 3
    assert final_state["terminal_state"] == "incomplete"
    assert final_state["host_gate"]["stop_cap_reached"] is True


def test_codex_degraded_hook_fails_open_and_persists_health(
    codex_round, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _, state_root, common, ctx = codex_round

    def explode(*args: Any, **kwargs: Any) -> dict[str, Any]:
        raise RuntimeError("synthetic adapter boundary failure")

    monkeypatch.setattr(cli_module, "_pretool_policy", explode)
    code, output = _run_hook(
        monkeypatch,
        capsys,
        state_root=state_root,
        event="PreToolUse",
        payload={
            **common,
            "tool_use_id": "degraded-1",
            "tool_name": "exec_command",
            "tool_input": {"cmd": "python --version"},
        },
    )
    assert code == 4
    assert output["agent_supervisor"] == {
        "health": "degraded",
        "error": "RuntimeError",
        "fail_open": True,
    }
    assert ctx.load()["health"] == "degraded"
    assert any(row.get("event_type") == "adapter_hook_degraded" for row in ctx.events())


def test_codex_session_end_without_active_round_is_valid_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    code, output = _run_hook(
        monkeypatch,
        capsys,
        state_root=tmp_path / "state",
        event="SessionEnd",
        payload={"session_id": "no-round", "cwd": str(tmp_path)},
    )
    assert code == 0
    assert output == {}
