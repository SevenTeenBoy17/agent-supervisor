from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
import threading
from argparse import Namespace
from pathlib import Path

import pytest

from supervisor_core import cli as cli_module
from supervisor_core import lifecycle as lifecycle_module
from supervisor_core.contracts import invocation_event
from supervisor_core.discovery import _version_key
from supervisor_core.executable_trust import (
    load_trusted_executable_registry,
    registry_public_record,
)
from supervisor_core.lifecycle import start_round
from supervisor_core.storage import StateContext
from supervisor_core.util import sha256_text
from supervisor_core.validation import _patterns_overlap, validate_state


def _context(tmp_path: Path, round_id: str) -> StateContext:
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    return StateContext.build(
        runtime="test",
        project="r16",
        workspace=str(workspace),
        session="session",
        round_id=round_id,
        state_root=tmp_path / "state",
    )


def _messages(state: dict, events: list[dict]) -> list[str]:
    return validate_state(state, events)["errors"]


def _trusted_python_registry_record() -> dict:
    executable = Path(sys.executable).resolve(strict=True)
    record = registry_public_record(load_trusted_executable_registry())
    python_entry = record["entries"]["python"]
    assert python_entry == {
        "kind": "local",
        "path": str(executable),
        "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
    }
    return record


def test_project_denied_uses_segment_aware_pattern_intersection(valid_bundle) -> None:
    state, events = valid_bundle
    state["goal"]["scope"]["in"] = ["src/**"]
    state["project_policy"] = {
        "allowed_change_globs": ["src/**"],
        "out_of_scope_globs": ["src/admin/**"],
    }
    state["tasks"][0]["allowed_paths"] = ["src/*/config.json"]

    assert any(
        "overlaps project out-of-scope policy" in error
        for error in _messages(state, events)
    )


def test_segment_aware_pattern_intersection_rejects_disjoint_suffixes(
    valid_bundle,
) -> None:
    assert _patterns_overlap("src/*/config.json", "src/admin/**")
    assert not _patterns_overlap("src/**/private/*.py", "src/**/public/*.py")
    assert not _patterns_overlap("src/foo/**", "src/foobar/**")

    state, events = valid_bundle
    state["goal"]["scope"]["in"] = ["src/**"]
    state["project_policy"] = {
        "allowed_change_globs": ["src/**"],
        "out_of_scope_globs": ["src/**/public/*.py"],
    }
    state["tasks"][0]["allowed_paths"] = ["src/**/private/*.py"]
    assert not any(
        "overlaps project out-of-scope policy" in error
        for error in _messages(state, events)
    )


@pytest.mark.parametrize("change_mode", ["continue", "extend", "replace"])
def test_prior_round_transition_preserves_locked_concurrent_update(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    change_mode: str,
) -> None:
    previous_ctx = _context(tmp_path, "previous")
    start_round(
        previous_ctx,
        message="initial round",
        change_mode="replace",
        execution_mode="observe",
        project_config={},
        quality_profile={},
    )
    next_ctx = _context(tmp_path, f"next-{change_mode}")
    captured_stale_read = threading.Event()
    release_transition = threading.Event()
    original_previous_state = lifecycle_module._previous_state

    def pause_after_previous_read(ctx: StateContext):
        result = original_previous_state(ctx)
        if ctx.round == next_ctx.round:
            captured_stale_read.set()
            assert release_transition.wait(10)
        return result

    monkeypatch.setattr(lifecycle_module, "_previous_state", pause_after_previous_read)
    failures: list[BaseException] = []

    def transition() -> None:
        try:
            start_round(
                next_ctx,
                message=f"{change_mode} round",
                change_mode=change_mode,
                execution_mode="observe",
                project_config={},
                quality_profile={},
            )
        except BaseException as exc:  # pragma: no cover - surfaced below
            failures.append(exc)

    worker = threading.Thread(target=transition)
    worker.start()
    try:
        assert captured_stale_read.wait(10)
        previous_ctx.update(
            lambda state: state.update({"concurrent_marker": "must-survive"})
        )
    finally:
        release_transition.set()
        worker.join(15)

    assert not worker.is_alive()
    assert failures == []
    assert previous_ctx.load()["concurrent_marker"] == "must-survive"


def test_prior_round_transition_rejects_conflicting_successor_without_mutation(
    tmp_path: Path,
) -> None:
    previous_ctx = _context(tmp_path, "previous-conflict")
    start_round(
        previous_ctx,
        message="initial round",
        change_mode="replace",
        execution_mode="observe",
        project_config={},
        quality_profile={},
    )
    first = {"goal_id": "goal-a", "version": 2, "round": "round-a"}
    lifecycle_module._transition_previous_state(
        previous_ctx.state_file,
        change_mode="continue",
        successor=first,
    )
    before = previous_ctx.state_file.read_bytes()

    with pytest.raises(ValueError, match="different successor"):
        lifecycle_module._transition_previous_state(
            previous_ctx.state_file,
            change_mode="replace",
            successor={"goal_id": "goal-b", "version": 1, "round": "round-b"},
        )

    assert previous_ctx.state_file.read_bytes() == before


def test_gate_subprocess_capture_is_bounded_while_running(tmp_path: Path) -> None:
    cap = cli_module._MAX_GATE_CAPTURE_BYTES
    command = [
        sys.executable,
        "-B",
        "-c",
        (
            "import sys; "
            f"sys.stdout.buffer.write(b'A'*{cap * 3}); "
            f"sys.stderr.buffer.write(b'B'*{cap * 2})"
        ),
    ]
    result = cli_module._run_gate_subprocess_bounded(
        command,
        cwd=str(tmp_path),
        timeout_seconds=10,
    )

    assert result["exit_code"] == 0
    assert result["timed_out"] is False
    assert result["stdout_truncated"] is True
    assert result["stderr_truncated"] is True
    assert len(result["stdout"].encode("utf-8")) <= cap
    assert len(result["stderr"].encode("utf-8")) <= cap


def test_gate_subprocess_timeout_remains_structured_and_bounded(tmp_path: Path) -> None:
    result = cli_module._run_gate_subprocess_bounded(
        [sys.executable, "-B", "-c", "import time; time.sleep(5)"],
        cwd=str(tmp_path),
        timeout_seconds=0.05,
    )

    assert result["exit_code"] == 124
    assert result["timed_out"] is True
    assert len(result["stdout"].encode("utf-8")) <= cli_module._MAX_GATE_CAPTURE_BYTES
    assert len(result["stderr"].encode("utf-8")) <= cli_module._MAX_GATE_CAPTURE_BYTES


def test_gate_evidence_retains_hashes_without_persisting_captured_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = "sk-R16-SENTINEL-7F29"
    monkeypatch.setenv("R16_GATE_SENTINEL", sentinel)
    monkeypatch.setattr(cli_module, "_MAX_GATE_CAPTURE_BYTES", 32)
    assert len(sentinel.encode("utf-8")) < cli_module._MAX_GATE_CAPTURE_BYTES
    trusted_registry = _trusted_python_registry_record()
    ctx = _context(tmp_path, "gate")
    state = start_round(
        ctx,
        message="bounded gate evidence",
        change_mode="replace",
        execution_mode="observe",
        project_config={},
        quality_profile={
            "common_gates": [
                {
                    "id": "gate.r16",
                    "command": [
                        sys.executable,
                        "-B",
                        "-c",
                        (
                            "import os,sys; "
                            "sys.stdout.write('x'*200000); "
                            "sys.stderr.write(os.environ['R16_GATE_SENTINEL'])"
                        ),
                    ],
                }
            ]
        },
        goal_supplied={
            "scope": {"in": ["**"], "out": []},
            "acceptance_criteria": [
                {
                    "criterion_id": "criterion-r16",
                    "description": "bounded gate output",
                    "domain": "config-agent",
                    "expected_evidence": ["gate.r16"],
                    "required": True,
                }
            ],
        },
    )
    state = cli_module._initialize_cli_source_snapshot(ctx, state, shadow=False)
    state = ctx.update(
        lambda current: current.update(
            {"trusted_executable_registry": copy.deepcopy(trusted_registry)}
        )
    )
    runner_invocation_id = "gate-runner-r16"
    invocation_binding = cli_module._invocation_state_binding(state)
    ctx.append_event(invocation_event(
        invocation_id=runner_invocation_id,
        capability="independent-gate-runner",
        stage="attempt",
        result=None,
        actor="gate-runner-r16",
        details=invocation_binding,
        identity_assurance="host-hook-observed",
        responsibility_group="independent-gate-execution-r16",
    ))
    evidence, execution, code = cli_module._run_registered_gate(
        ctx,
        {
            "actor": "gate-runner-r16",
            "record": {
                "gate_id": "gate.r16",
                "criterion_id": state["goal"]["acceptance_criteria"][0][
                    "criterion_id"
                ],
                "evidence_id": "evidence-r16",
                "collector_responsibility_group": "independent-gate-execution-r16",
                "collector_invocation_id": runner_invocation_id,
            },
        },
    )
    ctx.append_event(invocation_event(
        invocation_id=runner_invocation_id,
        capability="independent-gate-runner",
        stage="result",
        result="success",
        actor="gate-runner-r16",
        details=invocation_binding,
        identity_assurance="host-hook-observed",
        responsibility_group="independent-gate-execution-r16",
    ))

    persisted = json.dumps(
        {"state": ctx.load(), "events": ctx.events(), "evidence": evidence, "execution": execution},
        ensure_ascii=False,
    )
    assert code == 0
    assert sentinel not in persisted
    assert len(evidence["output_sha256"]) == 64
    assert len(execution["output_summary_sha256"]) == 64


def test_main_unknown_error_is_sanitized_invalid_state(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    sentinel = "R16_EXCEPTION_TEXT_MUST_NOT_ESCAPE"

    class SyntheticParser:
        def parse_args(self, _argv):
            def explode(_args):
                raise LookupError(sentinel)

            return Namespace(func=explode)

    monkeypatch.setattr(cli_module, "build_parser", SyntheticParser)
    assert cli_module.main([]) == 64
    output = capsys.readouterr().out
    record = json.loads(output)
    assert sentinel not in output
    assert record == {
        "error": "unknown",
        "message": "unexpected supervisor failure",
        "ok": False,
    }


@pytest.mark.parametrize("interrupt", [KeyboardInterrupt(), SystemExit(23)])
def test_main_does_not_mask_process_control_exceptions(
    monkeypatch: pytest.MonkeyPatch,
    interrupt: BaseException,
) -> None:
    class SyntheticParser:
        def parse_args(self, _argv):
            def explode(_args):
                raise interrupt

            return Namespace(func=explode)

    monkeypatch.setattr(cli_module, "build_parser", SyntheticParser)
    with pytest.raises(type(interrupt)) as raised:
        cli_module.main([])
    if isinstance(interrupt, SystemExit):
        assert raised.value.code == 23


@pytest.mark.parametrize("name", ["legacy.bin", "settings.local.json"])
def test_migrate_streams_hash_without_loading_unarchived_source_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    name: str,
) -> None:
    source = tmp_path / name
    payload = os.urandom(128 * 1024)
    source.write_bytes(payload)
    original_read_bytes = Path.read_bytes
    original_sha256_file = cli_module.sha256_file
    hashed: list[Path] = []

    def reject_source_read(path: Path) -> bytes:
        if path == source:
            raise AssertionError("unarchived source must not be loaded into memory")
        return original_read_bytes(path)

    def track_hash(path: Path) -> str:
        hashed.append(path)
        return original_sha256_file(path)

    monkeypatch.setattr(Path, "read_bytes", reject_source_read)
    monkeypatch.setattr(cli_module, "sha256_file", track_hash)
    args = [
        "migrate",
        "--source",
        str(source),
        "--runtime",
        "codex",
        "--workspace",
        str(tmp_path / "workspace"),
        "--session",
        "session",
        "--round",
        "round",
        "--state-root",
        str(tmp_path / "state"),
    ]

    assert cli_module.main(args) == 0
    result = json.loads(capsys.readouterr().out)
    manifest = json.loads(
        (Path(result["destination"]) / "manifest.json").read_text(encoding="utf-8")
    )
    assert hashed == [source]
    assert manifest["files"][0]["source_sha256"] == hashlib.sha256(payload).hexdigest()


def test_list_command_classifier_uses_shell_semantics_without_execution() -> None:
    listed = cli_module._t3_command_action(
        {"command": ["git", "push", "origin", "main", "--force-with-lease"]}
    )
    textual = cli_module._t3_command_action(
        {"command": "git push origin main --force-with-lease"}
    )

    assert listed == textual
    assert textual == (
        "force-push",
        sha256_text("git push origin main --force-with-lease"),
    )
    assert cli_module._t3_command_action({"command": ["git", object()]}) is None


def test_huge_numeric_version_component_never_uses_unbounded_int_conversion() -> None:
    huge = "9" * 5000
    assert _version_key(huge) > _version_key("10")
    assert _version_key("00010") == _version_key("10")
