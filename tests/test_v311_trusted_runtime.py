from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from supervisor_core import workspace as workspace_module
from supervisor_core.util import sha256_file


def _git_filename() -> str:
    return "git.exe" if os.name == "nt" else "git"


def _make_candidate(directory: Path, name: str | None = None) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    candidate = directory / (name or _git_filename())
    candidate.write_bytes(b"fixture executable")
    if os.name != "nt":
        candidate.chmod(0o755)
    return candidate


def _real_git() -> Path:
    candidate = shutil.which("git")
    assert candidate is not None
    return Path(candidate).resolve(strict=True)


def _write_registry(install_home: Path, executable: Path, *, digest: str | None = None) -> Path:
    registry = install_home / ".agent-supervisor" / "trusted-executables.json"
    registry.parent.mkdir(parents=True, exist_ok=True)
    registry.write_text(
        json.dumps(
            {
                "contract": "TrustedExecutableRegistry/v1",
                "entries": {
                    "git": {
                        "kind": "local",
                        "path": str(executable.absolute()),
                        "sha256": digest or sha256_file(executable),
                    }
                },
                "generated_at": "2026-08-24T00:00:00Z",
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return registry


def test_git_uses_registry_and_ignores_workspace_path_poison(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace_fake = _make_candidate(workspace)
    trusted_git = _real_git()
    _write_registry(tmp_path, trusted_git)
    monkeypatch.setenv("AGENT_SUPERVISOR_INSTALL_HOME", str(tmp_path))
    monkeypatch.setenv("PATH", str(workspace))

    observed: dict[str, object] = {}

    class FakeProcess:
        def __init__(self, command: list[str], **kwargs: object) -> None:
            observed["command"] = command
            observed["kwargs"] = kwargs
            self.stdout = io.BytesIO(b"ok")
            self.stderr = io.BytesIO()
            self.returncode: int | None = None

        def wait(self, timeout: float | None = None) -> int:
            self.returncode = 0
            return self.returncode

        def kill(self) -> None:
            self.returncode = -9

        def poll(self) -> int | None:
            return self.returncode

    monkeypatch.setattr(workspace_module.subprocess, "Popen", FakeProcess)
    result = workspace_module._git(workspace, "status", "--porcelain")

    assert result.returncode == 0
    assert result.stdout == b"ok"
    assert result.stderr == b""
    command = observed["command"]
    assert isinstance(command, list)
    assert Path(command[0]) == trusted_git
    assert Path(command[0]).is_absolute()
    assert Path(command[0]) != workspace_fake.resolve(strict=True)
    kwargs = observed["kwargs"]
    assert isinstance(kwargs, dict)
    assert kwargs["stdin"] is subprocess.DEVNULL
    assert kwargs["stdout"] is subprocess.PIPE
    assert kwargs["stderr"] is subprocess.PIPE
    assert kwargs["shell"] is False
    assert kwargs["bufsize"] == 0
    environment = kwargs["env"]
    assert isinstance(environment, dict)
    assert environment["NoDefaultCurrentDirectoryInExePath"] == "1"
    assert str(workspace) not in environment["PATH"]


@pytest.mark.parametrize("registry_state", ["missing", "malformed", "wrong-contract"])
def test_git_resolution_fails_closed_for_missing_or_invalid_registry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, registry_state: str
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    poison = _make_candidate(tmp_path / "poison")
    monkeypatch.setenv("AGENT_SUPERVISOR_INSTALL_HOME", str(tmp_path))
    monkeypatch.setenv("PATH", str(poison.parent))
    registry = tmp_path / ".agent-supervisor" / "trusted-executables.json"
    if registry_state != "missing":
        registry.parent.mkdir(parents=True)
        registry.write_text(
            "{" if registry_state == "malformed" else json.dumps({"contract": "wrong"}),
            encoding="utf-8",
        )

    assert workspace_module._resolve_git_executable(workspace) is None
    result = workspace_module._git(workspace, "status")
    assert result.returncode == 127
    assert result.stderr == b"agent-supervisor:git-unavailable"


def test_git_resolution_rejects_registered_workspace_executable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace_git = _make_candidate(workspace)
    _write_registry(tmp_path, workspace_git)
    monkeypatch.setenv("AGENT_SUPERVISOR_INSTALL_HOME", str(tmp_path))
    monkeypatch.setenv("PATH", str(workspace))

    assert workspace_module._resolve_git_executable(workspace) is None


def test_git_resolution_rejects_registry_executable_digest_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    copied_git = tmp_path / "trusted-bin" / _git_filename()
    copied_git.parent.mkdir()
    shutil.copyfile(_real_git(), copied_git)
    if os.name != "nt":
        copied_git.chmod(0o755)
    _write_registry(tmp_path, copied_git)
    with copied_git.open("ab") as handle:
        handle.write(b"drift")
    monkeypatch.setenv("AGENT_SUPERVISOR_INSTALL_HOME", str(tmp_path))
    monkeypatch.setenv("PATH", str(copied_git.parent))

    assert workspace_module._resolve_git_executable(workspace) is None


def test_git_resolution_rejects_registered_symlink_or_reparse_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target_dir = tmp_path / "real-bin"
    target_dir.mkdir()
    target_git = target_dir / _git_filename()
    shutil.copyfile(_real_git(), target_git)
    if os.name != "nt":
        target_git.chmod(0o755)
    linked_dir = tmp_path / "linked-bin"
    try:
        linked_dir.symlink_to(target_dir, target_is_directory=True)
    except (OSError, NotImplementedError):
        if os.name != "nt":
            pytest.skip("platform cannot create a directory symlink fixture")
        command_shell = Path(os.environ["COMSPEC"]).resolve(strict=True)
        created = subprocess.run(
            [str(command_shell), "/d", "/c", "mklink", "/J", str(linked_dir), str(target_dir)],
            capture_output=True,
            check=False,
        )
        if created.returncode != 0:
            pytest.skip("platform cannot create a directory reparse fixture")
    linked_git = linked_dir / _git_filename()
    _write_registry(tmp_path, linked_git, digest=sha256_file(target_git))
    monkeypatch.setenv("AGENT_SUPERVISOR_INSTALL_HOME", str(tmp_path))

    assert workspace_module._resolve_git_executable(workspace) is None
