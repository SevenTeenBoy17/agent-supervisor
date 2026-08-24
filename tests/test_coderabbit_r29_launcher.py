from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from supervisor_core.runtime_bundle import build_runtime_bundle, release_identity


SOURCE_LAUNCHER = Path(__file__).resolve().parents[1] / "bin" / "agent-supervisor.py"


def _write_release(path: Path, marker: str, version: str) -> None:
    core = path / "supervisor_core"
    core.mkdir(parents=True)
    (core / "__init__.py").write_text(
        f"RELEASE_MARKER = {marker!r}\n",
        encoding="utf-8",
    )
    (core / "cli.py").write_text(
        "import sys\n"
        "from supervisor_core import RELEASE_MARKER\n\n"
        "def main():\n"
        "    if any(name.startswith('_agent_supervisor_bootstrap_') for name in sys.modules):\n"
        "        print('BOOTSTRAP_NAMESPACE_LEAK')\n"
        "        return 65\n"
        "    print(RELEASE_MARKER)\n"
        "    return 0\n",
        encoding="utf-8",
    )
    bundle = build_runtime_bundle(path, version)
    bundle_path = path / "runtime" / "supervisor-runtime.zip"
    bundle_path.parent.mkdir(parents=True)
    bundle_path.write_bytes(bundle)


def _write_pointer(path: Path, release: Path, version: str) -> None:
    bundle = (release / "runtime" / "supervisor-runtime.zip").read_bytes()
    active = release_identity(
        release,
        version,
        "runtime/supervisor-runtime.zip",
        bundle,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "contract": "ActiveVersionPointer/v4",
                "active": active,
                "previous": None,
            },
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )


def _stage_physical_install(
    install_home: Path,
    *,
    marker: str,
    version: str,
) -> tuple[Path, Path, Path]:
    launcher = install_home / ".agent-supervisor" / "bin" / "agent-supervisor.py"
    launcher.parent.mkdir(parents=True)
    shutil.copy2(SOURCE_LAUNCHER, launcher)
    release = install_home / ".agent-supervisor-releases" / version
    _write_release(release, marker, version)
    pointer = install_home / ".agent-supervisor" / "active-version.json"
    _write_pointer(pointer, release, version)
    return launcher, pointer, release


def _poison_mutable_release_source(release: Path) -> None:
    (release / "supervisor_core" / "__init__.py").write_text(
        "RELEASE_MARKER = 'MUTABLE_RELEASE_SOURCE'\n",
        encoding="utf-8",
    )
    (release / "supervisor_core" / "cli.py").write_text(
        "def main():\n"
        "    print('MUTABLE_RELEASE_SOURCE')\n"
        "    return 91\n",
        encoding="utf-8",
    )


def _launcher_env(environment_home: Path) -> dict[str, str]:
    env = os.environ.copy()
    for name in (
        "AGENT_SUPERVISOR_ACTIVE_POINTER",
        "AGENT_SUPERVISOR_HOME",
        "AGENT_SUPERVISOR_INSTALL_HOME",
        "AGENT_SUPERVISOR_RELEASE_ROOT",
        "PYTHONPATH",
    ):
        env.pop(name, None)
    env.update({
        "HOME": str(environment_home),
        "USERPROFILE": str(environment_home),
        "AGENT_SUPERVISOR_HOME": str(environment_home / "environment supervisor"),
        "AGENT_SUPERVISOR_INSTALL_HOME": str(environment_home),
        "AGENT_SUPERVISOR_RELEASE_ROOT": str(
            environment_home / ".agent-supervisor-releases"
        ),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONIOENCODING": "utf-8",
    })
    return env


def _run_launcher(
    launcher: Path,
    cwd: Path,
    env: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(launcher), "--version"],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
        timeout=15,
    )


def test_launcher_uses_physical_exact_v4_pointer_and_frozen_bundle(
    tmp_path: Path,
) -> None:
    install_home = tmp_path / "physical install"
    launcher, physical_pointer, release = _stage_physical_install(
        install_home,
        marker="PHYSICAL_POINTER_RELEASE",
        version="physical-v4",
    )
    _poison_mutable_release_source(release)
    environment_home = tmp_path / "unrelated environment home"
    environment_home.mkdir()
    cwd = tmp_path / "arbitrary 中文 cwd"
    cwd.mkdir()

    completed = _run_launcher(launcher, cwd, _launcher_env(environment_home))

    assert physical_pointer.is_file()
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "PHYSICAL_POINTER_RELEASE"
    assert "BOOTSTRAP_NAMESPACE_LEAK" not in completed.stdout
    assert "MUTABLE_RELEASE_SOURCE" not in completed.stdout


@pytest.mark.parametrize("override_kind", ["valid", "malformed"])
def test_launcher_ignores_environment_pointer_override(
    tmp_path: Path,
    override_kind: str,
) -> None:
    physical_home = tmp_path / "physical install"
    launcher, physical_pointer, physical_release = _stage_physical_install(
        physical_home,
        marker="PHYSICAL_POINTER_RELEASE",
        version="physical-v4",
    )
    _poison_mutable_release_source(physical_release)
    environment_home = tmp_path / "environment selected install"
    if override_kind == "valid":
        _environment_launcher, override_pointer, _environment_release = (
            _stage_physical_install(
                environment_home,
                marker="ENVIRONMENT_OVERRIDE_RELEASE",
                version="environment-v4",
            )
        )
    else:
        environment_home.mkdir()
        override_pointer = environment_home / "malformed-active-version.json"
        override_pointer.write_text("{malformed\n", encoding="utf-8")
    env = _launcher_env(environment_home)
    env["AGENT_SUPERVISOR_ACTIVE_POINTER"] = str(override_pointer)
    cwd = tmp_path / "unrelated cwd"
    cwd.mkdir()

    completed = _run_launcher(launcher, cwd, env)

    assert Path(env["AGENT_SUPERVISOR_ACTIVE_POINTER"]) != physical_pointer
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "PHYSICAL_POINTER_RELEASE"
    assert "ENVIRONMENT_OVERRIDE_RELEASE" not in completed.stdout
    assert "BOOTSTRAP_NAMESPACE_LEAK" not in completed.stdout
    assert "MUTABLE_RELEASE_SOURCE" not in completed.stdout


@pytest.mark.parametrize("physical_pointer_state", ["missing", "malformed"])
def test_launcher_fails_closed_when_physical_pointer_is_unavailable(
    tmp_path: Path,
    physical_pointer_state: str,
) -> None:
    physical_home = tmp_path / "physical install"
    launcher, physical_pointer, physical_release = _stage_physical_install(
        physical_home,
        marker="PHYSICAL_POINTER_RELEASE",
        version="physical-v4",
    )
    _poison_mutable_release_source(physical_release)
    if physical_pointer_state == "missing":
        physical_pointer.unlink()
    else:
        physical_pointer.write_text("{malformed\n", encoding="utf-8")

    environment_home = tmp_path / "environment fallback install"
    _environment_launcher, override_pointer, _environment_release = (
        _stage_physical_install(
            environment_home,
            marker="ENVIRONMENT_FALLBACK_RELEASE",
            version="environment-v4",
        )
    )
    malicious_root = tmp_path / "environment pythonpath"
    malicious_core = malicious_root / "supervisor_core"
    malicious_core.mkdir(parents=True)
    sentinel = tmp_path / "source-fallback-executed.txt"
    (malicious_core / "__init__.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(sentinel)!r}).write_text('executed', encoding='utf-8')\n",
        encoding="utf-8",
    )
    env = _launcher_env(environment_home)
    env["AGENT_SUPERVISOR_ACTIVE_POINTER"] = str(override_pointer)
    env["PYTHONPATH"] = str(malicious_root)
    cwd = tmp_path / "hostile cwd"
    cwd.mkdir()

    completed = _run_launcher(launcher, cwd, env)

    assert completed.returncode == 64
    assert completed.stdout == ""
    assert completed.stderr == ""
    assert not sentinel.exists()
