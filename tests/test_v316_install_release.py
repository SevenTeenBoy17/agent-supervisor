from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import stat

import pytest


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "bin" / "install-agent-supervisor.py"


def _load_installer():
    spec = importlib.util.spec_from_file_location("install_agent_supervisor_v316", INSTALLER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_installer_is_dry_run_by_default_and_publishes_pointer_last(
    tmp_path: Path,
) -> None:
    installer = _load_installer()
    install_home = tmp_path / "profile"

    preview = installer.install_release(
        source_root=ROOT,
        install_home=install_home,
        apply=False,
    )

    assert preview["status"] == "dry-run"
    assert not install_home.exists()

    result = installer.install_release(
        source_root=ROOT,
        install_home=install_home,
        apply=True,
    )

    pointer_path = install_home / ".agent-supervisor" / "active-version.json"
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    active = pointer["active"]
    bundle = Path(active["path"]) / active["bundle_relpath"]
    assert result["status"] == "installed"
    assert pointer["contract"] == "ActiveVersionPointer/v4"
    assert active["version"] == "3.1.6"
    assert bundle.is_file()
    assert (install_home / ".agent-supervisor" / "bin" / "agent-supervisor.py").is_file()
    assert (install_home / ".codex" / "skills" / "dev-supervisor" / "SKILL.md").is_file()
    assert (install_home / ".claude" / "skills" / "supervisor" / "SKILL.md").is_file()
    assert not (install_home / ".agent-supervisor" / "trusted-executables.json").exists()
    assert not (Path(active["path"]) / ".attestation-key").exists()


def test_installer_refuses_invalid_existing_pointer_without_overwriting(
    tmp_path: Path,
) -> None:
    installer = _load_installer()
    install_home = tmp_path / "profile"
    pointer = install_home / ".agent-supervisor" / "active-version.json"
    pointer.parent.mkdir(parents=True)
    original = b'{"contract":"untrusted"}\n'
    pointer.write_bytes(original)

    with pytest.raises(ValueError, match="existing active pointer"):
        installer.install_release(
            source_root=ROOT,
            install_home=install_home,
            apply=True,
        )

    assert pointer.read_bytes() == original
    assert not (install_home / ".agent-supervisor-releases").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission regression")
def test_installer_does_not_change_install_home_permissions(tmp_path: Path) -> None:
    installer = _load_installer()
    install_home = tmp_path / "profile"
    install_home.mkdir()
    install_home.chmod(0o755)
    before = stat.S_IMODE(install_home.stat().st_mode)

    installer.install_release(
        source_root=ROOT,
        install_home=install_home,
        apply=True,
    )

    assert stat.S_IMODE(install_home.stat().st_mode) == before
