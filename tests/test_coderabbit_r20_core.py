from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from supervisor_core import cli as cli_module
from supervisor_core.constants import EXIT_COMPLETE, EXIT_INCOMPLETE
from supervisor_core.finalize import finalize_round
from supervisor_core.storage import StateContext


def test_worker_and_reviewer_contracts_require_redacted_structured_evidence() -> None:
    core_root = Path(__file__).resolve().parents[1]
    review_bundle = core_root.parent
    review_bundle_mode = (review_bundle / "REVIEW_MANIFEST.json").is_file()
    configured = os.environ.get("AGENT_SUPERVISOR_INSTALL_HOME")
    if review_bundle_mode:
        contract_path = review_bundle / "global-codex" / "subagent-contracts.md"
    else:
        install_home = Path(configured).resolve() if configured else Path.home()
        contract_path = (
            install_home
            / ".codex"
            / "skills"
            / "dev-supervisor"
            / "subagent-contracts.md"
        )
    if not contract_path.is_file() and not (review_bundle_mode or configured):
        pytest.skip("global Codex adapter is not installed on this host")
    assert contract_path.is_file(), f"required subagent contract is missing: {contract_path}"
    contract = contract_path.read_text(encoding="utf-8")
    worker = contract.split("## Worker", 1)[1].split("## Reviewer", 1)[0]
    reviewer = contract.split("## Reviewer", 1)[1].split("## Scheduling", 1)[0]

    for section in (worker, reviewer):
        normalized = " ".join(section.split())
        for required in (
            "command_summaries",
            "exit_code",
            "evidence_record_id",
            "artifact_sha256",
            "output_sha256",
            "failure_summaries",
            "blockers",
        ):
            assert required in normalized
        assert "raw stdout/stderr" in normalized
        assert "full command parameters" in normalized
        assert "internal evidence" in normalized


@pytest.mark.parametrize("malformed_changes", [None, [], "corrupt"])
def test_finalize_non_dict_changes_is_incomplete_without_crashing(
    tmp_path: Path, valid_bundle, malformed_changes: object
) -> None:
    state, events = valid_bundle
    state["changes"] = malformed_changes
    state["tasks"] = []
    ctx = StateContext.build(
        runtime="codex",
        project="r20",
        workspace=str(tmp_path),
        session="non-dict-changes",
        round_id="round-1",
        state_root=tmp_path / "state",
    )
    ctx.save(state)
    for event in events:
        ctx.append_event(event)

    final, exit_code = finalize_round(ctx)

    assert exit_code == EXIT_INCOMPLETE
    assert final["terminal_state"] == "incomplete"
    observations = [
        row for row in ctx.events() if row.get("contract") == "RolloutObservation/v3"
    ]
    assert observations[-1]["nontrivial"] is False


def test_selftest_suite_integrity_uses_recursive_relative_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    tests_root = tmp_path / "tests"
    nested = tests_root / "nested"
    nested.mkdir(parents=True)
    (tests_root / "test_duplicate.py").write_text("def test_top(): pass\n", encoding="utf-8")
    (nested / "test_duplicate.py").write_text("def test_nested(): pass\n", encoding="utf-8")
    responses = [
        subprocess.CompletedProcess(
            [], 0, stdout="tests\\test_duplicate.py::test_top\n", stderr=""
        ),
        subprocess.CompletedProcess([], 0, stdout="1 passed\n", stderr=""),
    ]
    monkeypatch.setattr(cli_module.subprocess, "run", lambda *_args, **_kwargs: responses.pop(0))

    exit_code = cli_module._execute_selftest(
        tmp_path,
        tmp_path / "selftest-temp",
        python_executable=sys.executable,
    )
    result = json.loads(capsys.readouterr().out)

    assert exit_code == EXIT_INCOMPLETE
    assert result["discovered_child_suites"] == [
        "nested/test_duplicate.py",
        "test_duplicate.py",
    ]
    assert result["collected_child_suites"] == ["test_duplicate.py"]
    assert result["all_child_suites_invoked"] is False

    responses.extend([
        subprocess.CompletedProcess(
            [],
            0,
            stdout=(
                "tests\\test_duplicate.py::test_top\n"
                "tests\\nested\\test_duplicate.py::test_nested\n"
            ),
            stderr="",
        ),
        subprocess.CompletedProcess([], 0, stdout="2 passed\n", stderr=""),
    ])
    complete_code = cli_module._execute_selftest(
        tmp_path,
        tmp_path / "selftest-temp-complete",
        python_executable=sys.executable,
    )
    complete = json.loads(capsys.readouterr().out)

    assert complete_code == EXIT_COMPLETE
    assert complete["collected_child_suites"] == [
        "nested/test_duplicate.py",
        "test_duplicate.py",
    ]
    assert complete["all_child_suites_invoked"] is True


@pytest.mark.parametrize("close_error", [RuntimeError, ValueError])
def test_bounded_gate_cleanup_does_not_mask_process_outcome(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, close_error: type[Exception]
) -> None:
    class Stream:
        def read(self, _size: int) -> bytes:
            return b""

        def close(self) -> None:
            raise close_error("simulated closed stream")

    class Process:
        stdout = Stream()
        stderr = Stream()

        def wait(self, timeout: float | None = None) -> int:
            return 7

        def kill(self) -> None:
            raise AssertionError("successful process must not be killed")

    monkeypatch.setattr(cli_module.subprocess, "Popen", lambda *_args, **_kwargs: Process())

    result = cli_module._run_gate_subprocess_bounded(
        ["safe-command"], cwd=str(tmp_path), timeout_seconds=1
    )

    assert result["exit_code"] == 7
    assert result["timed_out"] is False


def test_bounded_gate_join_cleanup_does_not_mask_process_outcome(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Stream:
        def read(self, _size: int) -> bytes:
            return b""

        def close(self) -> None:
            return None

    class Process:
        stdout = Stream()
        stderr = Stream()

        def wait(self, timeout: float | None = None) -> int:
            return 9

        def kill(self) -> None:
            raise AssertionError("successful process must not be killed")

    class CleanupThread:
        def __init__(self, *, target, args, daemon: bool) -> None:
            self._target = target
            self._args = args

        def start(self) -> None:
            self._target(*self._args)

        def join(self, timeout: float | None = None) -> None:
            raise RuntimeError("simulated join cleanup failure")

    monkeypatch.setattr(cli_module.subprocess, "Popen", lambda *_args, **_kwargs: Process())
    monkeypatch.setattr(cli_module.threading, "Thread", CleanupThread)

    result = cli_module._run_gate_subprocess_bounded(
        ["safe-command"], cwd=str(tmp_path), timeout_seconds=1
    )

    assert result["exit_code"] == 9
    assert result["timed_out"] is False
