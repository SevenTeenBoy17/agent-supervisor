from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import runpy
import subprocess
import sys
import time
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
ADAPTER = (
    Path(os.environ.get("AGENT_SUPERVISOR_INSTALL_HOME", Path.home()))
    / ".codex"
    / "skills"
    / "dev-supervisor"
    / "scripts"
)
HOOK = ADAPTER / "codex-supervisor-hook.py"
CORE_BRIDGE = ADAPTER / "supervisor-core.ps1"
STAGE_ZERO = ADAPTER / "supervisor-process-job.py"
IDENTITY_FIELDS = {
    "contract",
    "version",
    "path",
    "bundle_relpath",
    "bundle_sha256",
    "manifest_sha256",
    "source_tree_sha256",
}


def _hook_module() -> dict[str, object]:
    return runpy.run_path(str(HOOK))


def _native_powershell() -> Path:
    module = _hook_module()
    path = module["_trusted_powershell"]()
    assert isinstance(path, Path)
    return path


def _identity(release: Path, bundle_relpath: str = "runtime/supervisor-runtime.zip") -> dict[str, str]:
    package = release / "supervisor_core"
    package.mkdir(parents=True, exist_ok=True)
    (package / "__init__.py").write_text("\n", encoding="utf-8")
    (package / "__main__.py").write_text("\n", encoding="utf-8")
    bundle = release / Path(bundle_relpath)
    bundle.parent.mkdir(parents=True, exist_ok=True)
    bundle.write_bytes(b"v3.1.1-stage-zero-fixture")
    return {
        "contract": "SupervisorReleaseIdentity/v1",
        "version": "3.1.1",
        "path": str(release.resolve()),
        "bundle_relpath": bundle_relpath,
        "bundle_sha256": hashlib.sha256(bundle.read_bytes()).hexdigest(),
        "manifest_sha256": "a" * 64,
        "source_tree_sha256": "b" * 64,
    }


def _stage_zero_fixture(tmp_path: Path) -> tuple[Path, Path, dict[str, str], dict[str, str]]:
    home = tmp_path / "profile"
    scripts = home / ".codex" / "skills" / "dev-supervisor" / "scripts"
    scripts.mkdir(parents=True)
    bridge = scripts / "supervisor-core.ps1"
    bridge.write_bytes(CORE_BRIDGE.read_bytes())
    active = _identity(home / ".agent-supervisor-releases" / "v3.1.1")
    previous_release = home / ".agent-supervisor-releases" / "v3.1.0"
    previous = _identity(previous_release)
    previous["version"] = "3.1.0"
    pointer = home / ".agent-supervisor" / "active-version.json"
    pointer.parent.mkdir(parents=True)
    return bridge, pointer, active, previous


def _get_stage_zero_root(bridge: Path, pointer: Path, payload: dict[str, object]) -> Path:
    pointer.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
    escaped = str(bridge).replace("'", "''")
    command = (
        "$ErrorActionPreference='Stop';"
        f". '{escaped}';"
        "[Console]::Out.Write([string](Get-AgentSupervisorCoreRoot))"
    )
    completed = subprocess.run(
        [str(_native_powershell()), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=bridge.parent,
        env=os.environ.copy(),
        input=b"",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=15,
        check=False,
    )
    assert completed.returncode == 0
    assert not completed.stderr
    return Path(completed.stdout.decode("utf-8").strip())


def test_powershell_selection_ignores_systemroot_windir_and_path_poison(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _hook_module()
    trusted = module["_trusted_powershell"]()
    poison = tmp_path / "attacker" / "System32" / "WindowsPowerShell" / "v1.0"
    poison.mkdir(parents=True)
    (poison / "powershell.exe").write_bytes(b"MZ-not-a-real-powershell")
    monkeypatch.setenv("SYSTEMROOT", str(tmp_path / "attacker"))
    monkeypatch.setenv("WINDIR", str(tmp_path / "attacker"))
    monkeypatch.setenv("PATH", str(poison))

    selected = module["_trusted_powershell"]()
    assert selected == trusted
    assert poison not in selected.parents
    with module["_locked_trusted_powershell"]() as locked:
        assert locked[0] == trusted
        assert locked[1].read(2) == b"MZ"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.pop("manifest_sha256"),
        lambda value: value.update({"unexpected": "ambient"}),
        lambda value: value.update({"bundle_sha256": "0" * 63 + "z"}),
        lambda value: value.update({"path": "relative-release"}),
        lambda value: value.update({"bundle_relpath": "../escape.zip"}),
        lambda value: value.update({"bundle_relpath": "runtime\\supervisor-runtime.zip"}),
    ],
    ids=[
        "missing-field",
        "extra-field",
        "bad-sha",
        "relative-path",
        "relative-path-escape",
        "backslash-bundle-path",
    ],
)
def test_stage_zero_rejects_every_malformed_previous_identity(
    tmp_path: Path,
    mutation,
) -> None:
    bridge, pointer, active, previous = _stage_zero_fixture(tmp_path)
    valid_pointer = {
        "contract": "ActiveVersionPointer/v4",
        "active": active,
        "previous": previous,
    }
    accepted = _get_stage_zero_root(bridge, pointer, valid_pointer)
    assert accepted.resolve() == Path(active["path"]).resolve()
    assert set(previous) == IDENTITY_FIELDS

    malformed = copy.deepcopy(previous)
    mutation(malformed)
    rejected = _get_stage_zero_root(
        bridge,
        pointer,
        {
            "contract": "ActiveVersionPointer/v4",
            "active": active,
            "previous": malformed,
        },
    )
    assert rejected.name == ".rejected-core"
    assert rejected.resolve() != Path(active["path"]).resolve()


def test_outer_deadline_strictly_covers_inner_and_tree_cleanup() -> None:
    module = _hook_module()
    for event in ("SessionStart", "UserPromptSubmit", "Stop", "SessionEnd"):
        inner = module["_hook_timeout"](event)
        outer = module["_outer_hook_timeout"](event)
        cleanup = module["OUTER_PROCESS_TREE_CLEANUP_SECONDS"]
        assert outer > inner + cleanup
        assert outer >= (
            inner
            + module["INNER_STARTUP_GRACE_SECONDS"]
            + module["INNER_STREAM_CLEANUP_SECONDS"]
            + module["OUTER_BRIDGE_GRACE_SECONDS"]
        )


def test_frozen_stage_zero_uses_explicit_supported_platform_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    namespace = runpy.run_path(str(STAGE_ZERO), run_name="stage_zero_platform_probe")
    establish = namespace["_establish_platform_containment"]
    globals_ = establish.__globals__
    observed_job_calls: list[str] = []

    monkeypatch.setitem(
        globals_,
        "_enable_kill_on_close",
        lambda: observed_job_calls.append("job") or True,
    )
    monkeypatch.setattr(globals_["sys"], "platform", "win32")
    assert establish() is True
    assert observed_job_calls == ["job"]

    observed_job_calls.clear()
    for platform in ("linux", "linux-musl", "darwin"):
        monkeypatch.setattr(globals_["sys"], "platform", platform)
        assert establish() is True
    assert observed_job_calls == []

    for platform in ("freebsd14", "aix", "cygwin", "unknown"):
        monkeypatch.setattr(globals_["sys"], "platform", platform)
        assert establish() is False
    assert observed_job_calls == []


def test_frozen_stage_zero_unknown_platform_exits_125_before_frame_or_dependencies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    namespace = runpy.run_path(str(STAGE_ZERO), run_name="stage_zero_fail_closed_probe")
    main = namespace["main"]
    globals_ = main.__globals__
    calls: list[str] = []

    monkeypatch.setattr(globals_["sys"], "platform", "unsupported-kernel")
    monkeypatch.setattr(
        globals_["sys"],
        "argv",
        [str(STAGE_ZERO), "--agent-supervisor-bound-bundle", "/logical/launcher"],
    )
    monkeypatch.setitem(
        globals_,
        "_enable_dependency_paths",
        lambda: calls.append("dependencies") or True,
    )
    monkeypatch.setitem(
        globals_,
        "_read_and_install_runtime_frame",
        lambda: calls.append("runtime-frame") or b"",
    )

    assert main() == 125
    assert calls == []


def test_frozen_stage_zero_windows_job_failure_exits_125_before_frame(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    namespace = runpy.run_path(str(STAGE_ZERO), run_name="stage_zero_windows_fail_probe")
    main = namespace["main"]
    globals_ = main.__globals__
    calls: list[str] = []

    monkeypatch.setattr(globals_["sys"], "platform", "win32")
    monkeypatch.setattr(
        globals_["sys"],
        "argv",
        [str(STAGE_ZERO), "--agent-supervisor-bound-bundle", "C:/logical/launcher"],
    )
    monkeypatch.setitem(globals_, "_enable_kill_on_close", lambda: False)
    monkeypatch.setitem(
        globals_,
        "_read_and_install_runtime_frame",
        lambda: calls.append("runtime-frame") or b"",
    )

    assert main() == 125
    assert calls == []


def test_timeout_terminates_complete_process_tree_without_late_state_write(
    tmp_path: Path,
) -> None:
    module = _hook_module()
    powershell = module["_trusted_powershell"]()
    system_directory = module["_windows_system_directory"]()
    late_state = tmp_path / "late-state.json"
    escaped_state = str(late_state).replace("'", "''")
    child_source = (
        "Start-Sleep -Milliseconds 1400;"
        f"[IO.File]::WriteAllText('{escaped_state}','late')"
    )
    encoded_child = base64.b64encode(child_source.encode("utf-16le")).decode("ascii")
    escaped_powershell = str(powershell).replace("'", "''")
    parent_source = (
        f"Start-Process -FilePath '{escaped_powershell}' "
        f"-ArgumentList '-NoLogo','-NoProfile','-EncodedCommand','{encoded_child}' | Out-Null;"
        "Start-Sleep -Seconds 30"
    )
    environment = os.environ.copy()
    environment.update(
        {
            "SYSTEMROOT": str(system_directory.parent),
            "WINDIR": str(system_directory.parent),
            "PATH": str(system_directory),
            "NoDefaultCurrentDirectoryInExePath": "1",
        }
    )

    started = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        module["_run_trusted_powershell"](
            [
                str(powershell),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                parent_source,
            ],
            cwd=tmp_path,
            env=environment,
            input_bytes=b"",
            timeout_seconds=0.25,
            system_directory=system_directory,
        )
    elapsed = time.monotonic() - started
    assert elapsed < 0.25 + module["OUTER_PROCESS_TREE_CLEANUP_SECONDS"] + 1.0
    time.sleep(1.8)
    assert not late_state.exists()


def _write_python_registry(home: Path, executable: Path, digest: str) -> None:
    target = home / ".agent-supervisor" / "trusted-executables.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps({
            "contract": "TrustedExecutableRegistry/v1",
            "entries": {
                "python": {
                    "kind": "local",
                    "path": str(executable),
                    "sha256": digest,
                }
            },
            "generated_at": "2026-08-24T00:00:00Z",
        }),
        encoding="utf-8",
    )


def test_registry_python_rejects_py_launcher_and_digest_drift(
    tmp_path: Path,
) -> None:
    module = _hook_module()
    launcher = tmp_path / "py.exe"
    launcher.write_bytes(b"MZ-synthetic-launcher")
    _write_python_registry(
        tmp_path / "launcher-home",
        launcher,
        hashlib.sha256(launcher.read_bytes()).hexdigest(),
    )
    with pytest.raises(FileNotFoundError, match="trusted_python_missing_or_rejected"):
        module["_trusted_registry_python"](tmp_path / "launcher-home")

    trusted_python = Path(sys.executable).resolve(strict=True)
    _write_python_registry(tmp_path / "drift-home", trusted_python, "0" * 64)
    with pytest.raises(FileNotFoundError, match="trusted_python_lock_failed"):
        with module["_locked_trusted_registry_python"](tmp_path / "drift-home"):
            pytest.fail("digest-drifted interpreter must never be yielded")


def test_core_rejects_launcher_reparse_and_rechecks_locked_command_digest() -> None:
    source = CORE_BRIDGE.read_text(encoding="utf-8")
    hook_source = HOOK.read_text(encoding="utf-8")
    assert "@('python.exe', 'python3.exe')" in source
    assert "@('py.exe'" not in source
    assert "if _path_has_reparse(lexical):" in hook_source
    assert "candidate = _canonical_existing(Path(entry[\"path\"]), directory=False)" in hook_source
    assert "$launcherItem.Attributes -band [IO.FileAttributes]::ReparsePoint" in source
    assert "Register-AgentSupervisorVerifiedFileHash -Path $resolvedLauncher" in source
    assert "$actualCommandSha256 = Get-AgentSupervisorStreamSha256 -Stream $commandLock" in source
    assert "Python command identity changed before process creation" in source


@pytest.mark.parametrize(
    "failure_stage",
    ["create", "configure", "assign", "resume"],
)
def test_job_setup_failure_kills_and_waits_for_suspended_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_stage: str,
) -> None:
    module = _hook_module()
    run = module["_run_trusted_powershell"]
    globals_ = run.__globals__

    class FakeProcess:
        def __init__(self) -> None:
            self.pid = 987654321
            self._handle = 123
            self.returncode = None
            self.kill_called = False
            self.communicate_called = False
            self.wait_called = False

        def poll(self):
            return self.returncode

        def kill(self) -> None:
            self.kill_called = True
            self.returncode = -9

        def communicate(self, input=None, timeout=None):
            self.communicate_called = True
            return b"", b""

        def wait(self, timeout=None):
            self.wait_called = True
            self.returncode = -9
            return self.returncode

    process = FakeProcess()

    class FakeJob:
        def __init__(self) -> None:
            self.terminate_called = False
            self.close_called = False

        def assign_and_resume(self, child) -> None:
            assert child is process
            raise OSError(f"windows_job_{failure_stage}_failed")

        def terminate(self) -> None:
            self.terminate_called = True

        def close(self) -> None:
            self.close_called = True

    jobs: list[FakeJob] = []

    def job_factory():
        if failure_stage in {"create", "configure"}:
            raise OSError(f"windows_job_{failure_stage}_failed")
        job = FakeJob()
        jobs.append(job)
        return job

    monkeypatch.setattr(globals_["subprocess"], "Popen", lambda *args, **kwargs: process)
    monkeypatch.setitem(globals_, "_WindowsKillOnCloseJob", job_factory)

    with pytest.raises(OSError, match=f"windows_job_{failure_stage}_failed"):
        run(
            ["trusted-powershell"],
            cwd=tmp_path,
            env={},
            input_bytes=b"{}",
            timeout_seconds=0.1,
            system_directory=tmp_path,
        )

    assert process.kill_called is True
    assert process.communicate_called is True
    assert process.poll() is not None
    if jobs:
        assert jobs[0].terminate_called is True
        assert jobs[0].close_called is True
