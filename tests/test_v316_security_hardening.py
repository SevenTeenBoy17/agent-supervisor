from __future__ import annotations

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys

import pytest

from supervisor_core import lifecycle
from supervisor_core import workspace as workspace_module
from supervisor_core.attestation import sign_record
from supervisor_core.cli import (
    _apply_state_record,
    _bounded_hook_payload,
    _evaluate_pretool_policy,
    _privacy_safe_prompt_contract,
)
from supervisor_core.executable_trust import (
    ExecutableTrustError,
    authorize_trusted_command,
    trusted_command_approval_sha256,
)
from supervisor_core.rollout import initial_rollout


ROOT = Path(__file__).resolve().parents[1]


def _load_script(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_prompt_persistence_is_hash_only_by_default() -> None:
    message = "private release discussion"
    goal, intents, withheld = _privacy_safe_prompt_contract(
        message,
        {},
        None,
    )

    assert withheld is True
    assert message not in json.dumps(
        {"goal": goal, "intents": intents},
        ensure_ascii=False,
    )


def test_metadata_reader_rejects_oversized_json_before_parsing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = tmp_path / "project.json"
    document.write_text(json.dumps({"value": "x" * 256}), encoding="utf-8")
    monkeypatch.setattr(lifecycle, "_MAX_METADATA_BYTES", 64)

    with pytest.raises(ValueError, match="size limit"):
        lifecycle._read_stable_json_object(document, label="project config")


def test_common_hook_bounds_stdin_and_rejects_duplicate_keys() -> None:
    assert _bounded_hook_payload(io.BytesIO(b'{"ok":true}'), maximum=32) == {
        "ok": True
    }
    with pytest.raises(ValueError, match="size limit"):
        _bounded_hook_payload(io.BytesIO(b"{}x"), maximum=2)
    with pytest.raises(ValueError, match="duplicate keys"):
        _bounded_hook_payload(io.BytesIO(b'{"x":1,"x":2}'), maximum=32)


def test_repository_schema_rejects_regex_keywords_at_any_depth() -> None:
    with pytest.raises(ValueError, match="pattern"):
        lifecycle._reject_unsafe_schema_keywords(
            {
                "allOf": [
                    {"properties": {"name": {"pattern": "(a+)+$"}}},
                ]
            },
            label="project config",
        )


def test_trusted_command_requires_exact_machine_approved_argv(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "runner.bin"
    executable.write_bytes(b"trusted executable fixture")
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    command = [str(executable), "--mode", "safe"]
    approval = trusted_command_approval_sha256(command)
    registry = {
        "entries": {
            "runner": {
                "kind": "local",
                "path": str(executable),
                "sha256": digest,
                "allowed_argv_sha256": [approval],
            }
        }
    }

    resolved, _, _ = authorize_trusted_command(command, registry, cwd=str(tmp_path))
    assert resolved[1:] == command[1:]

    with pytest.raises(ExecutableTrustError, match="argv-not-approved"):
        authorize_trusted_command(
            [str(executable), "--mode", "unsafe"],
            registry,
            cwd=str(tmp_path),
        )


def test_unknown_native_command_effects_fail_closed_for_enforcement() -> None:
    decision = _evaluate_pretool_policy(
        {"goal": {}, "workspace": str(ROOT)},
        tool_name="exec_command",
        tool_input={"cmd": "python -c \"print('ok')\""},
        actor="worker",
    )

    assert decision["deny"] is True
    assert decision["hard_deny"] is False
    assert decision["category"] == "native-command-effects"
    assert decision["reason"] == "native-command-effects-unproven"


def test_rollout_failure_records_approval_required_without_auto_mutation() -> None:
    state = {"rollout": initial_rollout({}, "warn"), "health": "healthy"}
    identity = {
        "contract": "SupervisorReleaseIdentity/v1",
        "version": "3.1.6",
        "path": "C:/sealed/release",
        "bundle_relpath": "runtime/supervisor-runtime.zip",
        "bundle_sha256": "1" * 64,
        "manifest_sha256": "2" * 64,
        "source_tree_sha256": "3" * 64,
    }
    for index in range(2):
        observation = {
            "contract": "RolloutObservation/v3",
            "observation_id": f"failure-{index}",
            "kind": "global_gate",
            "source_contract": "GateExecution/v3",
            "source_id": f"execution-{index}",
            "gate_id": "gate.fail",
            "result": "failed",
            "active_version": identity,
        }
        observation["attestation"] = sign_record(observation)
        _apply_state_record(
            state,
            {"record": observation},
            "rollout_observation",
        )

    rollback = state["rollout"]["rollback"]
    assert rollback["required"] is True
    assert rollback["performed"] is False
    assert rollback["attempted"] is False
    assert rollback["claim_status"] == "approval_required"
    assert state["health"] == "degraded"


def test_git_output_is_bounded_while_streaming(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeProcess:
        def __init__(self) -> None:
            self.stdout = io.BytesIO(b"12345")
            self.stderr = io.BytesIO(b"")
            self.returncode = 0

        def wait(self, timeout=None):
            self.returncode = 0
            return 0

        def kill(self):
            self.returncode = -9

        def poll(self):
            return self.returncode

    monkeypatch.setattr(workspace_module, "_MAX_GIT_OUTPUT_BYTES", 4)
    monkeypatch.setattr(
        workspace_module,
        "_resolve_git_executable",
        lambda workspace: Path(sys.executable),
    )
    monkeypatch.setattr(workspace_module, "_sanitized_git_environment", lambda: {})
    monkeypatch.setattr(
        workspace_module.subprocess,
        "Popen",
        lambda *args, **kwargs: FakeProcess(),
    )

    result = workspace_module._git(tmp_path, "status")

    assert result.returncode == 125
    assert result.stderr == b"agent-supervisor:git-output-limit"


def test_coderabbit_source_policy_never_selects_user_settings() -> None:
    runner = _load_script("review_runner_v316", "bin/run-coderabbit-review.py")
    groups = runner.source_groups(
        project_root=ROOT,
        profile_root=ROOT,
        core_root=ROOT,
    )

    assert all(label != "project" for label, _, _ in groups)
    selected = {
        path.as_posix().casefold()
        for _, _, candidates in groups
        for path in candidates
    }
    assert not any(path.endswith("/.claude/settings.json") for path in selected)
    assert not any(path.endswith("/.codex/hooks.json") for path in selected)


def test_claude_configurator_owns_only_exact_installed_script_paths() -> None:
    configurator = _load_script(
        "configure_v3_hooks_v316",
        "integrations/claude/scripts/configure-v3-hooks.py",
    )
    owned = {
        "type": "command",
        "command": '"python" "C:/Users/example/.claude/skills/supervisor/scripts/sup-v3-hook.py" --event Stop',
    }
    collision = {
        "type": "command",
        "command": '"python" "C:/tools/keep.py" --label sup-v3-hook.py',
    }

    assert configurator.is_supervisor_hook(owned) is True
    assert configurator.is_supervisor_hook(collision) is False


def test_codex_adapter_bounds_stdin_before_json_decode() -> None:
    adapter = _load_script(
        "codex_hook_v316",
        "integrations/codex/scripts/codex-supervisor-hook.py",
    )

    assert adapter._read_bounded_stdin(io.BytesIO(b"{}"), maximum=2) == b"{}"
    with pytest.raises(ValueError, match="stdin-too-large"):
        adapter._read_bounded_stdin(io.BytesIO(b"{}x"), maximum=2)


def test_release_builder_rejects_outputs_outside_release_root(tmp_path: Path) -> None:
    builder = _load_script(
        "release_builder_v316",
        "bin/build-core-release-manifest.py",
    )
    root = tmp_path / "release"
    root.mkdir()

    assert builder._contained_output(root, root / "runtime" / "core.zip").is_relative_to(root)
    with pytest.raises(ValueError, match="outside release root"):
        builder._contained_output(root, tmp_path / "escaped.zip")
