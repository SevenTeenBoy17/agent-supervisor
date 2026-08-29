from __future__ import annotations

import importlib.util
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

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
    assert active["version"] == "3.1.12"
    assert bundle.is_file()
    assert (Path(active["path"]) / "bin" / "agent-supervisor.py").is_file()
    assert (Path(active["path"]) / "supervisor_core" / "__init__.py").is_file()
    assert (Path(active["path"]) / "supervisor_core" / "__main__.py").is_file()
    assert (install_home / ".agent-supervisor" / "bin" / "agent-supervisor.py").is_file()
    assert (install_home / ".codex" / "skills" / "dev-supervisor" / "SKILL.md").is_file()
    assert (install_home / ".claude" / "skills" / "supervisor" / "SKILL.md").is_file()
    hooks_path = install_home / ".codex" / "hooks.json"
    agents_path = install_home / ".codex" / "AGENTS.md"
    hooks = json.loads(hooks_path.read_text(encoding="utf-8"))
    assert set(hooks["hooks"]) == {
        "SessionStart",
        "UserPromptSubmit",
        "PreToolUse",
        "PermissionRequest",
        "PostToolUse",
        "PreCompact",
        "PostCompact",
        "SubagentStart",
        "SubagentStop",
        "Stop",
        "SessionEnd",
    }
    assert "dev-supervisor" in hooks_path.read_text(encoding="utf-8")
    expected_python = f'"{Path(sys.executable).resolve()}"'
    expected_adapter = str(
        install_home
        / ".codex"
        / "skills"
        / "dev-supervisor"
        / "scripts"
        / "codex-supervisor-hook.py"
    )
    for groups in hooks["hooks"].values():
        managed = groups[-1]["hooks"][0]
        assert managed["commandWindows"].startswith(expected_python + " ")
        assert expected_adapter in managed["commandWindows"]
        assert "py -3" not in managed["commandWindows"]
    agents = agents_path.read_text(encoding="utf-8")
    assert "<!-- agent-supervisor:managed:start -->" in agents
    assert "RoundProcessSummary/v1" in agents
    assert not (install_home / ".agent-supervisor" / "trusted-executables.json").exists()
    assert not (Path(active["path"]) / ".attestation-key").exists()


def test_installer_merges_global_codex_activation_without_losing_user_config(
    tmp_path: Path,
) -> None:
    installer = _load_installer()
    install_home = tmp_path / "profile"
    codex = install_home / ".codex"
    codex.mkdir(parents=True)
    hooks_path = codex / "hooks.json"
    agents_path = codex / "AGENTS.md"
    hooks_path.write_text(
        json.dumps(
            {
                "description": "keep me",
                "hooks": {
                    "Stop": [
                        {
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": "python custom-stop.py",
                                }
                            ]
                        }
                    ]
                },
            }
        ),
        encoding="utf-8",
    )
    agents_path.write_text("# User policy\n\nKeep this text.\n", encoding="utf-8")
    codex.chmod(0o755)
    hooks_path.chmod(0o644)
    agents_path.chmod(0o644)
    codex_mode = stat.S_IMODE(codex.lstat().st_mode)
    hooks_mode = stat.S_IMODE(hooks_path.lstat().st_mode)
    agents_mode = stat.S_IMODE(agents_path.lstat().st_mode)

    installer.install_release(
        source_root=ROOT,
        install_home=install_home,
        apply=True,
    )

    hooks = json.loads(hooks_path.read_text(encoding="utf-8"))
    stop_commands = [
        handler.get("command", "")
        for group in hooks["hooks"]["Stop"]
        for handler in group["hooks"]
    ]
    assert "python custom-stop.py" in stop_commands
    assert sum("codex-supervisor-hook.py" in value for value in stop_commands) == 1
    agents = agents_path.read_text(encoding="utf-8")
    assert agents.count("<!-- agent-supervisor:managed:start -->") == 1
    assert "# User policy" in agents
    assert "Keep this text." in agents
    assert stat.S_IMODE(codex.lstat().st_mode) == codex_mode
    assert stat.S_IMODE(hooks_path.lstat().st_mode) == hooks_mode
    assert stat.S_IMODE(agents_path.lstat().st_mode) == agents_mode


def test_installer_preserves_unrelated_hook_that_mentions_adapter_filename(
    tmp_path: Path,
) -> None:
    installer = _load_installer()
    install_home = tmp_path / "profile"
    codex = install_home / ".codex"
    codex.mkdir(parents=True)
    hooks_path = codex / "hooks.json"
    unrelated = {
        "type": "command",
        "command": "python audit.py --label codex-supervisor-hook.py",
        "commandWindows": "python audit.py --label codex-supervisor-hook.py",
    }
    hooks_path.write_text(
        json.dumps({"hooks": {"Stop": [{"hooks": [unrelated]}]}}),
        encoding="utf-8",
    )

    installer.install_release(
        source_root=ROOT,
        install_home=install_home,
        apply=True,
    )

    hooks = json.loads(hooks_path.read_text(encoding="utf-8"))
    handlers = [handler for group in hooks["hooks"]["Stop"] for handler in group["hooks"]]
    assert unrelated in handlers
    assert len(handlers) == 2


def test_installer_preserves_hook_group_without_handlers_field(
    tmp_path: Path,
) -> None:
    installer = _load_installer()
    install_home = tmp_path / "profile"
    codex = install_home / ".codex"
    codex.mkdir(parents=True)
    hooks_path = codex / "hooks.json"
    metadata_only_group = {"matcher": "custom-tool", "enabled": False}
    hooks_path.write_text(
        json.dumps({"hooks": {"Stop": [metadata_only_group]}}),
        encoding="utf-8",
    )

    installer.install_release(
        source_root=ROOT,
        install_home=install_home,
        apply=True,
    )

    hooks = json.loads(hooks_path.read_text(encoding="utf-8"))
    groups = hooks["hooks"]["Stop"]
    assert groups[0] == metadata_only_group
    assert len(groups) == 2
    assert "codex-supervisor-hook.py" in groups[1]["hooks"][0]["command"]


def test_installer_replaces_legacy_codex_handler_without_type(
    tmp_path: Path,
) -> None:
    installer = _load_installer()
    install_home = tmp_path / "profile"
    codex = install_home / ".codex"
    codex.mkdir(parents=True)
    hooks_path = codex / "hooks.json"
    legacy = installer._legacy_codex_hook_handler("Stop")
    hooks_path.write_text(
        json.dumps({"hooks": {"Stop": [{"hooks": [legacy]}]}}),
        encoding="utf-8",
    )

    installer.install_release(
        source_root=ROOT,
        install_home=install_home,
        apply=True,
    )

    hooks = json.loads(hooks_path.read_text(encoding="utf-8"))
    handlers = [handler for group in hooks["hooks"]["Stop"] for handler in group["hooks"]]
    assert len(handlers) == 1
    assert handlers[0]["type"] == "command"
    assert handlers[0]["command"] != legacy["command"]
    assert handlers[0]["commandWindows"] != legacy["commandWindows"]


def test_installer_replaces_managed_absolute_handler_after_python_moves(
    tmp_path: Path,
) -> None:
    installer = _load_installer()
    install_home = tmp_path / "profile"
    codex = install_home / ".codex"
    codex.mkdir(parents=True)
    hooks_path = codex / "hooks.json"
    old_handler = installer._codex_hook_handler(
        "Stop",
        timeout=30,
        status="Running quality gate",
        install_home=install_home,
        interpreter=tmp_path / "retired-python" / "python.exe",
    )
    hooks_path.write_text(
        json.dumps({"hooks": {"Stop": [{"hooks": [old_handler]}]}}),
        encoding="utf-8",
    )

    installer.install_release(
        source_root=ROOT,
        install_home=install_home,
        apply=True,
    )

    hooks = json.loads(hooks_path.read_text(encoding="utf-8"))
    handlers = [handler for group in hooks["hooks"]["Stop"] for handler in group["hooks"]]
    assert len(handlers) == 1
    assert str(Path(sys.executable).resolve()) in handlers[0]["commandWindows"]
    assert "retired-python" not in handlers[0]["commandWindows"]


def test_codex_hook_command_paths_reject_windows_percent_expansion(
    tmp_path: Path,
) -> None:
    installer = _load_installer()

    with pytest.raises(installer.InstallError, match="path is unsafe"):
        installer._codex_hook_handler(
            "Stop",
            timeout=30,
            status="Running quality gate",
            install_home=tmp_path / "%TEMP%" / "profile",
            interpreter=Path(sys.executable).resolve(),
        )


def test_optional_empty_codex_profile_files_are_treated_as_absent(
    tmp_path: Path,
) -> None:
    installer = _load_installer()
    install_home = tmp_path / "profile"
    codex = install_home / ".codex"
    codex.mkdir(parents=True)
    (codex / "hooks.json").write_bytes(b"")
    (codex / "AGENTS.md").write_bytes(b"")

    result = installer.install_release(
        source_root=ROOT,
        install_home=install_home,
        apply=True,
    )

    assert result["status"] == "installed"
    assert json.loads((codex / "hooks.json").read_text(encoding="utf-8"))["hooks"]
    assert "RoundProcessSummary/v1" in (codex / "AGENTS.md").read_text(encoding="utf-8")


def test_installer_rejects_duplicate_keys_in_existing_codex_hooks(
    tmp_path: Path,
) -> None:
    installer = _load_installer()
    existing = b'{"hooks":{},"hooks":{"Stop":[]}}'

    with pytest.raises(installer.InstallError, match="duplicate keys"):
        installer._merge_codex_hooks(
            existing,
            install_home=tmp_path / "profile",
            interpreter=Path(sys.executable),
        )


def test_installer_repairs_a_missing_member_from_the_matching_immutable_bundle(
    tmp_path: Path,
) -> None:
    installer = _load_installer()
    install_home = tmp_path / "profile"
    installer.install_release(
        source_root=ROOT,
        install_home=install_home,
        apply=True,
    )
    pointer = json.loads(
        (install_home / ".agent-supervisor" / "active-version.json").read_text(
            encoding="utf-8"
        )
    )
    active_root = Path(pointer["active"]["path"])
    member = active_root / "supervisor_core" / "__main__.py"
    expected = member.read_bytes()
    member.unlink()

    installer.install_release(
        source_root=ROOT,
        install_home=install_home,
        apply=True,
    )

    assert member.read_bytes() == expected


@pytest.mark.parametrize(
    "member_name",
    ["../outside.py", "/absolute.py", "C:/drive-relative.py", "bad\\path.py"],
)
def test_release_materialization_rejects_non_portable_member_paths(
    tmp_path: Path,
    member_name: str,
) -> None:
    installer = _load_installer()
    release_root = tmp_path / "release"
    release_root.mkdir()

    with pytest.raises(installer.InstallError, match="member path"):
        installer._materialize_release_members(
            release_root,
            {"members": {member_name: b"bounded\n"}},
        )


def test_global_agents_merge_rejects_ambiguous_managed_markers() -> None:
    installer = _load_installer()
    ambiguous = (
        "<!-- agent-supervisor:managed:start -->\n"
        "<!-- agent-supervisor:managed:start -->\n"
        "<!-- agent-supervisor:managed:end -->\n"
    ).encode("utf-8")

    with pytest.raises(installer.InstallError, match="managed block"):
        installer._merge_global_agents(ambiguous)


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
    (source / "VERSION").write_text("3.1.12\n", encoding="ascii")
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
        "VERSION": b"3.1.12\n",
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
