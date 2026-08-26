from __future__ import annotations

import importlib.util
import hashlib
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


def test_installer_writes_frozen_adapter_bytes_after_source_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    installer = _load_installer()
    source = tmp_path / "source"
    (source / "bin").mkdir(parents=True)
    (source / "VERSION").write_text("3.1.6\n", encoding="ascii")
    (source / "bin" / "agent-supervisor.py").write_bytes(b"trusted launcher\n")
    originals = {
        source / "integrations" / "codex" / "SKILL.md": b"trusted codex adapter\n",
        source / "integrations" / "claude" / "SKILL.md": b"trusted claude adapter\n",
    }
    for path, content in originals.items():
        path.parent.mkdir(parents=True)
        path.write_bytes(content)

    bundle = b"verified runtime bundle"

    def release_identity(release_root: Path, version: str, content: bytes):
        assert content == bundle
        return {
            "bundle_relpath": "runtime/supervisor-runtime.zip",
            "bundle_sha256": hashlib.sha256(content).hexdigest(),
            "contract": "SupervisorReleaseIdentity/v1",
            "manifest_sha256": "1" * 64,
            "path": str(release_root),
            "source_tree_sha256": "2" * 64,
            "version": version,
        }

    bundle_members = {
        "VERSION": b"3.1.6\n",
        "bin/agent-supervisor.py": b"trusted launcher\n",
        "integrations/codex/SKILL.md": originals[
            source / "integrations" / "codex" / "SKILL.md"
        ],
        "integrations/claude/SKILL.md": originals[
            source / "integrations" / "claude" / "SKILL.md"
        ],
    }

    def mutate_after_bundle_build(release_root: Path, version: str, content: bytes):
        identity = release_identity(release_root, version, content)
        for path, original in originals.items():
            path.write_bytes(b"X" * len(original))
        launcher = source / "bin" / "agent-supervisor.py"
        launcher.write_bytes(b"Y" * len(bundle_members["bin/agent-supervisor.py"]))
        return identity

    def forbid_source_adapter_reread(_source_root: Path):
        pytest.fail("installer must derive adapters from the verified runtime bundle")

    monkeypatch.setattr(installer, "build_runtime_bundle", lambda *_args: bundle)
    monkeypatch.setattr(installer, "_release_identity", mutate_after_bundle_build)
    monkeypatch.setattr(
        installer,
        "inspect_runtime_bundle",
        lambda *_args, **_kwargs: {"members": bundle_members},
    )
    monkeypatch.setattr(installer, "_valid_active_pointer", lambda _value: True)
    monkeypatch.setattr(installer, "_adapter_files", forbid_source_adapter_reread)

    install_home = tmp_path / "profile"
    installer.install_release(
        source_root=source,
        install_home=install_home,
        apply=True,
    )

    assert (
        install_home / ".codex" / "skills" / "dev-supervisor" / "SKILL.md"
    ).read_bytes() == originals[source / "integrations" / "codex" / "SKILL.md"]
    assert (
        install_home / ".claude" / "skills" / "supervisor" / "SKILL.md"
    ).read_bytes() == originals[source / "integrations" / "claude" / "SKILL.md"]
    assert (
        install_home / ".agent-supervisor" / "bin" / "agent-supervisor.py"
    ).read_bytes() == bundle_members["bin/agent-supervisor.py"]


def test_stable_read_rejects_descriptor_path_identity_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    installer = _load_installer()
    source = tmp_path / "source.txt"
    replacement = tmp_path / "replacement.txt"
    source.write_bytes(b"trusted-content\n")
    replacement.write_bytes(b"hostile-content\n")
    assert source.stat().st_size == replacement.stat().st_size
    real_open = installer.os.open

    def redirected_open(path, flags, *args):
        target = replacement if Path(path) == source else path
        return real_open(target, flags, *args)

    monkeypatch.setattr(installer.os, "open", redirected_open)

    with pytest.raises(installer.InstallError, match="changed during read"):
        installer._stable_bytes(source, maximum=1024, label="source fixture")


@pytest.mark.skipif(os.name == "nt", reason="POSIX rename-over-open ABA regression")
def test_stable_read_rejects_same_length_rename_aba(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    installer = _load_installer()
    source = tmp_path / "source.txt"
    replacement = tmp_path / "replacement.txt"
    saved = tmp_path / "saved.txt"
    source.write_bytes(b"trusted-content\n")
    replacement.write_bytes(b"hostile-content\n")
    assert source.stat().st_size == replacement.stat().st_size
    real_open = installer.os.open

    def aba_open(path, flags, *args):
        if Path(path) != source:
            return real_open(path, flags, *args)
        os.replace(source, saved)
        os.replace(replacement, source)
        descriptor = real_open(source, flags, *args)
        os.replace(source, replacement)
        os.replace(saved, source)
        return descriptor

    monkeypatch.setattr(installer.os, "open", aba_open)

    with pytest.raises(installer.InstallError, match="changed during read"):
        installer._stable_bytes(source, maximum=1024, label="source fixture")


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
