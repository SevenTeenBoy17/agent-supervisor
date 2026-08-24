from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

from supervisor_core.runtime_bundle import build_runtime_bundle, release_identity


LAUNCHER = Path(__file__).resolve().parents[1] / "bin" / "agent-supervisor.py"


def _write_release(path: Path, marker: str) -> None:
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
    bundle = build_runtime_bundle(path, "test-release")
    bundle_path = path / "runtime" / "supervisor-runtime.zip"
    bundle_path.parent.mkdir(parents=True)
    bundle_path.write_bytes(bundle)


def _write_pointer(path: Path, release: Path, version: str = "test-release") -> None:
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
            }
        ),
        encoding="utf-8",
    )


def _launcher_env(profile: Path, release_root: Path) -> dict[str, str]:
    env = os.environ.copy()
    env.pop("AGENT_SUPERVISOR_ACTIVE_POINTER", None)
    env.pop("PYTHONPATH", None)
    env["HOME"] = str(profile)
    env["USERPROFILE"] = str(profile)
    env["AGENT_SUPERVISOR_RELEASE_ROOT"] = str(release_root)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def _run_launcher(tmp_path: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(LAUNCHER), "--version"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


def test_launcher_uses_rollout_global_pointer_when_override_is_unset(tmp_path: Path) -> None:
    profile = tmp_path / "profile"
    releases = tmp_path / "releases"
    release = releases / "global"
    _write_release(release, "GLOBAL_POINTER_RELEASE")
    _write_pointer(profile / ".agent-supervisor" / "active-version.json", release)

    completed = _run_launcher(tmp_path, _launcher_env(profile, releases))

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "GLOBAL_POINTER_RELEASE"


def test_launcher_honors_explicit_pointer_over_global_pointer(tmp_path: Path) -> None:
    profile = tmp_path / "profile"
    releases = tmp_path / "releases"
    global_release = releases / "global"
    override_release = releases / "override"
    _write_release(global_release, "GLOBAL_POINTER_RELEASE")
    _write_release(override_release, "OVERRIDE_POINTER_RELEASE")
    _write_pointer(profile / ".agent-supervisor" / "active-version.json", global_release)
    override_pointer = profile / "override-pointer.json"
    _write_pointer(override_pointer, override_release)
    env = _launcher_env(profile, releases)
    env["AGENT_SUPERVISOR_ACTIVE_POINTER"] = "~/override-pointer.json"

    completed = _run_launcher(tmp_path, env)

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "OVERRIDE_POINTER_RELEASE"


def test_launcher_fails_closed_for_malformed_override_pointer(tmp_path: Path) -> None:
    profile = tmp_path / "profile"
    releases = tmp_path / "releases"
    global_release = releases / "global"
    _write_release(global_release, "GLOBAL_POINTER_RELEASE")
    _write_pointer(profile / ".agent-supervisor" / "active-version.json", global_release)
    override_pointer = tmp_path / "malformed-override.json"
    override_pointer.write_text("{malformed", encoding="utf-8")
    env = _launcher_env(profile, releases)
    env["AGENT_SUPERVISOR_ACTIVE_POINTER"] = str(override_pointer)

    completed = _run_launcher(tmp_path, env)

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip().startswith("3.")
