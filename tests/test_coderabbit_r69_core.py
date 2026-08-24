from __future__ import annotations

import hashlib
from pathlib import Path
import sys

import pytest

from supervisor_core import cli as cli_module


def test_lingering_gate_reader_marks_its_capture_truncated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
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
            return 0

        def kill(self) -> None:
            raise AssertionError("successful process must not be killed")

    class ControlledThread:
        created = 0

        def __init__(self, *, target, args, daemon: bool) -> None:
            del target, args, daemon
            self._index = ControlledThread.created
            ControlledThread.created += 1

        def start(self) -> None:
            return None

        def join(self, timeout: float | None = None) -> None:
            del timeout
            return None

        def is_alive(self) -> bool:
            return self._index == 0

    monkeypatch.setattr(cli_module.subprocess, "Popen", lambda *_args, **_kwargs: Process())
    monkeypatch.setattr(cli_module.threading, "Thread", ControlledThread)

    result = cli_module._run_gate_subprocess_bounded(
        ["safe-command"],
        cwd=str(tmp_path),
        timeout_seconds=1,
    )

    assert result["exit_code"] == 0
    assert result["timed_out"] is False
    assert result["stdout_truncated"] is True
    assert result["stderr_truncated"] is False


def test_unobservable_gate_reader_state_fails_capture_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
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
            return 3

        def kill(self) -> None:
            raise AssertionError("completed process must not be killed")

    class UnobservableThread:
        def __init__(self, *, target, args, daemon: bool) -> None:
            self._target = target
            self._args = args
            del daemon

        def start(self) -> None:
            self._target(*self._args)

        def join(self, timeout: float | None = None) -> None:
            del timeout
            return None

    monkeypatch.setattr(cli_module.subprocess, "Popen", lambda *_args, **_kwargs: Process())
    monkeypatch.setattr(cli_module.threading, "Thread", UnobservableThread)

    result = cli_module._run_gate_subprocess_bounded(
        ["safe-command"],
        cwd=str(tmp_path),
        timeout_seconds=1,
    )

    assert result["exit_code"] == 3
    assert result["stdout_truncated"] is True
    assert result["stderr_truncated"] is True


def test_gate_subprocess_sends_bounded_stdin_and_reports_complete(
    tmp_path: Path,
) -> None:
    payload = (b"bound-runner-input\x00" * 16_384) + b"tail"
    expected = hashlib.sha256(payload).hexdigest()
    result = cli_module._run_gate_subprocess_bounded(
        [
            sys.executable,
            "-I",
            "-S",
            "-B",
            "-c",
            (
                "import hashlib,sys;"
                "value=sys.stdin.buffer.read();"
                "sys.stdout.write(hashlib.sha256(value).hexdigest())"
            ),
        ],
        cwd=str(tmp_path),
        timeout_seconds=10,
        input_bytes=payload,
    )

    assert result["exit_code"] == 0
    assert result["timed_out"] is False
    assert result["stdin_complete"] is True
    assert result["stdout"] == expected
    assert result["stderr"] == ""
    assert result["stdout_truncated"] is False
    assert result["stderr_truncated"] is False


@pytest.mark.parametrize("failure", ["partial", "broken-pipe"])
def test_gate_subprocess_incomplete_stdin_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    class OutputStream:
        def read(self, _size: int) -> bytes:
            return b""

        def close(self) -> None:
            return None

    class InputStream:
        def write(self, value: bytes) -> int:
            if failure == "broken-pipe":
                raise BrokenPipeError
            return max(0, len(value) - 1)

        def flush(self) -> None:
            return None

        def close(self) -> None:
            return None

    class Process:
        stdin = InputStream()
        stdout = OutputStream()
        stderr = OutputStream()

        def wait(self, timeout: float | None = None) -> int:
            del timeout
            return 0

        def kill(self) -> None:
            raise AssertionError("completed process must not be killed")

    class ImmediateThread:
        def __init__(self, *, target, args=(), daemon: bool) -> None:
            self._target = target
            self._args = args
            self._complete = False
            del daemon

        def start(self) -> None:
            self._target(*self._args)
            self._complete = True

        def join(self, timeout: float | None = None) -> None:
            del timeout

        def is_alive(self) -> bool:
            return not self._complete

    monkeypatch.setattr(
        cli_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: Process(),
    )
    monkeypatch.setattr(cli_module.threading, "Thread", ImmediateThread)

    result = cli_module._run_gate_subprocess_bounded(
        ["safe-command"],
        cwd=str(tmp_path),
        timeout_seconds=1,
        input_bytes=b"frozen runner source",
    )

    assert result["exit_code"] == 0
    assert result["timed_out"] is False
    assert result["stdin_complete"] is False


def test_gate_subprocess_rejects_oversized_stdin_before_spawn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cli_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("oversized stdin must not spawn"),
    )

    with pytest.raises(ValueError, match="bounded contract"):
        cli_module._run_gate_subprocess_bounded(
            ["safe-command"],
            cwd=str(tmp_path),
            timeout_seconds=1,
            input_bytes=b"x" * (cli_module._MAX_GATE_STDIN_BYTES + 1),
        )
