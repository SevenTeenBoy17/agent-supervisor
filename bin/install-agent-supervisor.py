#!/usr/bin/env python3
"""Build and install one verified Agent Supervisor release without network access.

The command is a dry run unless ``--apply`` is supplied.  It never creates or
modifies the machine-local executable trust registry and publishes the active
version pointer only after the bundle, launcher, and thin adapters are durable.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import sys
import tempfile
from typing import Any, NamedTuple
import uuid


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from supervisor_core.rollout import _valid_active_pointer
from supervisor_core.runtime_bundle import (
    IDENTITY_CONTRACT,
    RuntimeBundleError,
    build_runtime_bundle,
    inspect_runtime_bundle,
)


_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
_MAX_CONTROL_BYTES = 1024 * 1024
_MAX_ADAPTER_FILE_BYTES = 4 * 1024 * 1024
_MAX_ADAPTER_FILES = 128
_MAX_ADAPTER_TOTAL_BYTES = 32 * 1024 * 1024
_ADAPTER_SUFFIXES = {".json", ".md", ".ps1", ".py"}
_CODEX_HOOK_DESCRIPTION = (
    "Agent Supervisor v3 lifecycle hooks. Review and trust changes with /hooks. "
    "Local tool hooks are guardrails; hosted WebSearch is outside their coverage. "
    "SessionEnd uses the official 3-second maximum."
)
_AGENTS_BLOCK_START = "<!-- agent-supervisor:managed:start -->"
_AGENTS_BLOCK_END = "<!-- agent-supervisor:managed:end -->"
_GLOBAL_AGENTS_BLOCK = f"""{_AGENTS_BLOCK_START}
# Agent Supervisor — global Codex activation

For every task with an available workspace, apply the installed `dev-supervisor`
skill before task work and run its bootstrap with the newest request, current
`CODEX_THREAD_ID`, and the correct `continue`, `extend`, or `replace` mode.

Before every final answer, run Supervisor finalization. The answer must end with the
exact rendered `RoundProcessSummary/v1` supplied by Supervisor, including its visual
timeline of Skill, Agent, Plugin/App, and native-command facts, their task
contributions, Evidence IDs, quality gates, redundancy counts, and true terminal
state. If a Stop hook supplies the report, reproduce it verbatim. Missing or degraded
evidence must remain `MISSING`/`incomplete`; never omit the report or invent success.

Codex user hooks in `~/.codex/hooks.json` apply across projects after they are reviewed
with `/hooks`. Project rules and the current user request remain authoritative for
product scope.
{_AGENTS_BLOCK_END}
"""


class InstallError(ValueError):
    pass


class _FrozenAdapter(NamedTuple):
    source: Path
    destination: Path
    content: bytes
    sha256: str


def _safe_command_path(path: Path, *, label: str) -> Path:
    value = _lexical_absolute(path)
    rendered = str(value)
    if not value.is_absolute() or any(
        char in rendered for char in ('"', "%", "\r", "\n", "\x00")
    ):
        raise InstallError(f"{label} path is unsafe")
    return value


def _codex_hook_handler(
    event: str,
    *,
    timeout: int,
    status: str,
    install_home: Path,
    interpreter: Path,
) -> dict[str, Any]:
    python_path = _safe_command_path(interpreter, label="Python interpreter")
    adapter = _safe_command_path(
        install_home
        / ".codex"
        / "skills"
        / "dev-supervisor"
        / "scripts"
        / "codex-supervisor-hook.py",
        label="Codex adapter",
    )
    return {
        "type": "command",
        "command": f"{shlex.quote(str(python_path))} {shlex.quote(str(adapter))} --event {event}",
        "commandWindows": f'"{python_path}" "{adapter}" --event {event}',
        "timeout": timeout,
        "statusMessage": status,
        "async": False,
    }


def _codex_managed_hooks(
    install_home: Path,
    interpreter: Path,
) -> dict[str, list[dict[str, Any]]]:
    definitions = {
        "SessionStart": ("startup|resume|clear|compact", 15, "Starting Supervisor"),
        "UserPromptSubmit": (None, 30, "Aligning goal"),
        "PreToolUse": ("*", 15, "Checking tool policy"),
        "PermissionRequest": ("*", 15, "Checking permission"),
        "PostToolUse": ("*", 15, "Recording tool result"),
        "PreCompact": ("manual|auto", 15, "Preserving context"),
        "PostCompact": ("manual|auto", 15, "Restoring context"),
        "SubagentStart": ("*", 15, "Registering subagent"),
        "SubagentStop": ("*", 20, "Reviewing subagent"),
        "Stop": (None, 30, "Running quality gate"),
        "SessionEnd": ("*", 3, "Closing Supervisor"),
    }
    result: dict[str, list[dict[str, Any]]] = {}
    for event, (matcher, timeout, status) in definitions.items():
        group: dict[str, Any] = {
            "hooks": [
                _codex_hook_handler(
                    event,
                    timeout=timeout,
                    status=status,
                    install_home=install_home,
                    interpreter=interpreter,
                )
            ]
        }
        if matcher is not None:
            group["matcher"] = matcher
        result[event] = [group]
    return result


def _legacy_codex_hook_handler(event: str) -> dict[str, str]:
    return {
        "command": (
            'python3 "$HOME/.codex/skills/dev-supervisor/scripts/'
            f'codex-supervisor-hook.py" --event {event}'
        ),
        "commandWindows": (
            'py -3 "%USERPROFILE%\\.codex\\skills\\dev-supervisor\\scripts\\'
            f'codex-supervisor-hook.py" --event {event}'
        ),
    }


def _is_managed_codex_handler(
    value: Any,
    *,
    event: str,
    expected: dict[str, Any],
) -> bool:
    if not isinstance(value, dict):
        return False
    legacy = _legacy_codex_hook_handler(event)
    commands_match_expected = (
        value.get("command") == expected["command"]
        and value.get("commandWindows") == expected["commandWindows"]
    )
    if commands_match_expected:
        return value.get("type") == "command"
    if value.get("type") == "command":
        try:
            candidate_posix = shlex.split(str(value.get("command") or ""), posix=True)
            expected_posix = shlex.split(str(expected.get("command") or ""), posix=True)
        except ValueError:
            candidate_posix = []
            expected_posix = []
        windows_shape = re.compile(
            r'^"(?P<python>[^"\r\n]+)" "(?P<adapter>[^"\r\n]+)" '
            r'--event (?P<event>[A-Za-z]+)$'
        )
        candidate_windows = windows_shape.fullmatch(
            str(value.get("commandWindows") or "")
        )
        expected_windows = windows_shape.fullmatch(
            str(expected.get("commandWindows") or "")
        )
        if (
            len(candidate_posix) == 4
            and len(expected_posix) == 4
            and candidate_posix[2] == expected_posix[2] == "--event"
            and candidate_posix[1:] == expected_posix[1:]
            and Path(candidate_posix[0]).is_absolute()
            and candidate_windows is not None
            and expected_windows is not None
            and candidate_windows.group("adapter")
            == expected_windows.group("adapter")
            and candidate_windows.group("event") == expected_windows.group("event")
            and Path(candidate_windows.group("python")).is_absolute()
        ):
            return True
    commands_match_legacy = (
        value.get("command") == legacy["command"]
        and value.get("commandWindows") == legacy["commandWindows"]
    )
    return commands_match_legacy and value.get("type") in {None, "command"}


def _merge_codex_hooks(
    existing: bytes | None,
    *,
    install_home: Path,
    interpreter: Path,
) -> bytes:
    if existing is None:
        current: dict[str, Any] = {}
    else:
        try:
            current = json.loads(
                existing.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise InstallError("existing Codex hooks.json is not valid UTF-8 JSON") from exc
        if not isinstance(current, dict):
            raise InstallError("existing Codex hooks.json must be an object")
    merged = json.loads(json.dumps(current, ensure_ascii=False))
    hooks = merged.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise InstallError("existing Codex hooks.json hooks field must be an object")
    for event, managed_groups in _codex_managed_hooks(install_home, interpreter).items():
        expected_handler = managed_groups[0]["hooks"][0]
        existing_groups = hooks.get(event, [])
        if not isinstance(existing_groups, list):
            raise InstallError(f"existing Codex hook event {event} must be a list")
        retained: list[dict[str, Any]] = []
        for raw_group in existing_groups:
            if not isinstance(raw_group, dict):
                raise InstallError(f"existing Codex hook group {event} must be an object")
            group = json.loads(json.dumps(raw_group, ensure_ascii=False))
            if "hooks" not in group:
                retained.append(group)
                continue
            handlers = group["hooks"]
            if not isinstance(handlers, list):
                raise InstallError(f"existing Codex hook handlers {event} must be a list")
            group["hooks"] = [
                handler
                for handler in handlers
                if not _is_managed_codex_handler(
                    handler,
                    event=event,
                    expected=expected_handler,
                )
            ]
            if group["hooks"]:
                retained.append(group)
        hooks[event] = retained + managed_groups
    merged.setdefault("description", _CODEX_HOOK_DESCRIPTION)
    if existing is not None and merged == current:
        return existing
    return json.dumps(merged, ensure_ascii=False, indent=2).encode("utf-8") + b"\n"


def _merge_global_agents(existing: bytes | None) -> bytes:
    if existing is None:
        return _GLOBAL_AGENTS_BLOCK.encode("utf-8")
    try:
        text = existing.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InstallError("existing Codex AGENTS.md is not valid UTF-8") from exc
    start_count = text.count(_AGENTS_BLOCK_START)
    end_count = text.count(_AGENTS_BLOCK_END)
    start = text.find(_AGENTS_BLOCK_START)
    end = text.find(_AGENTS_BLOCK_END)
    if (
        start_count > 1
        or end_count > 1
        or (start < 0) != (end < 0)
        or (start >= 0 and end < start)
    ):
        raise InstallError("existing Codex AGENTS.md has an incomplete managed block")
    if start >= 0:
        end += len(_AGENTS_BLOCK_END)
        merged = text[:start] + _GLOBAL_AGENTS_BLOCK.rstrip("\n") + text[end:]
    elif text.strip():
        merged = _GLOBAL_AGENTS_BLOCK.rstrip("\n") + "\n\n" + text.lstrip("\n")
    else:
        merged = _GLOBAL_AGENTS_BLOCK
    if not merged.endswith("\n"):
        merged += "\n"
    return merged.encode("utf-8")


def _optional_profile_file(path: Path, *, label: str) -> bytes | None:
    if not path.exists() and not path.is_symlink():
        return None
    candidate = _lexical_absolute(path)
    _reject_existing_indirection(candidate, label=label)
    try:
        details = candidate.lstat()
    except OSError as exc:
        raise InstallError(f"{label} is unavailable") from exc
    if stat.S_ISREG(details.st_mode) and details.st_size == 0:
        return None
    return _stable_bytes(path, maximum=_MAX_CONTROL_BYTES, label=label)


def _is_link_or_reparse(path: Path) -> bool:
    details = path.lstat()
    return _stat_is_link_or_reparse(details)


def _stat_is_link_or_reparse(details: os.stat_result) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(details, "st_file_attributes", 0)
    return stat.S_ISLNK(details.st_mode) or bool(reparse_flag and attributes & reparse_flag)


def _portable_file_identity(details: os.stat_result) -> tuple[int, ...]:
    return (
        details.st_mode,
        details.st_dev,
        details.st_ino,
        details.st_size,
        details.st_mtime_ns,
    )


def _lexical_absolute(path: Path) -> Path:
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        raise InstallError("path must be absolute")
    return Path(os.path.abspath(os.fspath(candidate)))


def _reject_existing_indirection(path: Path, *, label: str) -> None:
    absolute = _lexical_absolute(path)
    anchor = Path(absolute.anchor)
    current = anchor
    for part in absolute.relative_to(anchor).parts:
        current /= part
        if not current.exists() and not current.is_symlink():
            continue
        try:
            if _is_link_or_reparse(current):
                raise InstallError(f"{label} contains a symlink or reparse point")
        except OSError as exc:
            raise InstallError(f"{label} is unavailable") from exc


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InstallError("JSON contains duplicate keys")
        result[key] = value
    return result


def _stable_bytes(
    path: Path,
    *,
    maximum: int,
    label: str,
    allow_empty: bool = False,
) -> bytes:
    candidate = _lexical_absolute(path)
    _reject_existing_indirection(candidate, label=label)
    descriptor = -1
    try:
        path_before = candidate.lstat()
        if (
            _stat_is_link_or_reparse(path_before)
            or not stat.S_ISREG(path_before.st_mode)
            or path_before.st_size < (0 if allow_empty else 1)
            or path_before.st_size > maximum
        ):
            raise InstallError(f"{label} size is invalid")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(candidate, flags)
        descriptor_before = os.fstat(descriptor)
        if not stat.S_ISREG(descriptor_before.st_mode):
            raise InstallError(f"{label} is not a regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            content = handle.read(maximum + 1)
        descriptor_after = os.fstat(descriptor)
    except InstallError:
        raise
    except OSError as exc:
        raise InstallError(f"{label} is unreadable") from exc
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass

    try:
        path_after = candidate.lstat()
        _reject_existing_indirection(candidate, label=label)
    except InstallError:
        raise
    except OSError as exc:
        raise InstallError(f"{label} is unreadable") from exc

    # Windows reports creation time through path stat but aliases descriptor
    # ctime to mtime. Compare ctime within each observation channel and bind
    # the path to the descriptor with the portable identity fields.
    cross_identities = {
        _portable_file_identity(path_before),
        _portable_file_identity(descriptor_before),
        _portable_file_identity(descriptor_after),
        _portable_file_identity(path_after),
    }
    if (
        _stat_is_link_or_reparse(path_after)
        or len(cross_identities) != 1
        or path_before.st_ctime_ns != path_after.st_ctime_ns
        or descriptor_before.st_ctime_ns != descriptor_after.st_ctime_ns
        or len(content) != descriptor_before.st_size
    ):
        raise InstallError(f"{label} changed during read")
    return content


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _private_directory(path: Path) -> None:
    _reject_existing_indirection(path.parent, label="installation parent")
    path.mkdir(parents=True, exist_ok=True)
    _reject_existing_indirection(path, label="installation directory")
    try:
        path.chmod(0o700)
    except OSError:
        pass


def _atomic_write(
    path: Path,
    content: bytes,
    *,
    preserve_parent_permissions: bool = False,
) -> None:
    existing_mode: int | None = None
    if preserve_parent_permissions:
        _reject_existing_indirection(path.parent.parent, label="output parent")
        path.parent.mkdir(parents=True, exist_ok=True)
    else:
        _private_directory(path.parent)
    _reject_existing_indirection(path.parent, label="output parent")
    if path.exists() or path.is_symlink():
        _reject_existing_indirection(path, label="output path")
        if not path.is_file():
            raise InstallError("output path is not a regular file")
        existing_mode = stat.S_IMODE(path.lstat().st_mode)
    descriptor, temporary = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    try:
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if preserve_parent_permissions and existing_mode is not None:
            Path(temporary).chmod(existing_mode)
        _reject_existing_indirection(path.parent, label="output parent")
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _source_version(source_root: Path) -> str:
    raw = _stable_bytes(
        source_root / "VERSION",
        maximum=128,
        label="release version",
    )
    try:
        version = raw.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise InstallError("release version is not ASCII") from exc
    if not _VERSION.fullmatch(version):
        raise InstallError("release version is invalid")
    return version


def _release_identity(release_root: Path, version: str, bundle: bytes) -> dict[str, str]:
    inspected = inspect_runtime_bundle(bundle)
    identity = {
        "bundle_relpath": "runtime/supervisor-runtime.zip",
        "bundle_sha256": inspected["bundle_sha256"],
        "contract": IDENTITY_CONTRACT,
        "manifest_sha256": inspected["manifest_sha256"],
        "path": str(_lexical_absolute(release_root)),
        "source_tree_sha256": inspected["source_tree_sha256"],
        "version": version,
    }
    inspect_runtime_bundle(bundle, expected_identity=identity)
    return identity


def _identity_bundle(identity: dict[str, Any], install_home: Path) -> Path:
    root = _lexical_absolute(Path(str(identity.get("path") or "")))
    allowed = (
        install_home / ".agent-supervisor",
        install_home / ".agent-supervisor-releases",
    )
    if not any(root == candidate or root.is_relative_to(candidate) for candidate in allowed):
        raise InstallError("existing active pointer references an outside release")
    relative = PurePosixPath(str(identity.get("bundle_relpath") or ""))
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise InstallError("existing active pointer bundle path is invalid")
    return root.joinpath(*relative.parts)


def _validated_existing_pointer(path: Path, install_home: Path) -> dict[str, Any] | None:
    if not path.exists() and not path.is_symlink():
        return None
    raw = _stable_bytes(path, maximum=_MAX_CONTROL_BYTES, label="existing active pointer")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InstallError("existing active pointer is invalid") from exc
    if not _valid_active_pointer(value):
        raise InstallError("existing active pointer is invalid")
    for name in ("active", "previous"):
        identity = value.get(name)
        if identity is None:
            continue
        bundle_path = _identity_bundle(identity, install_home)
        bundle = _stable_bytes(
            bundle_path,
            maximum=128 * 1024 * 1024,
            label=f"existing {name} bundle",
        )
        try:
            inspect_runtime_bundle(bundle, expected_identity=identity)
        except RuntimeBundleError as exc:
            raise InstallError(f"existing active pointer {name} release is invalid") from exc
    return value


def _adapter_files(source_root: Path) -> list[_FrozenAdapter]:
    mappings = (
        (
            source_root / "integrations" / "codex",
            Path(".codex/skills/dev-supervisor"),
        ),
        (
            source_root / "integrations" / "claude",
            Path(".claude/skills/supervisor"),
        ),
    )
    result: list[_FrozenAdapter] = []
    total = 0
    for source_base, destination_base in mappings:
        _reject_existing_indirection(source_base, label="adapter source")
        if not source_base.is_dir():
            raise InstallError("adapter source is missing")
        for source in sorted(source_base.rglob("*")):
            relative = source.relative_to(source_base)
            if (
                not source.is_file()
                or "__pycache__" in relative.parts
                or "tests" in relative.parts
                or any(part.startswith(".pytest-tmp-") for part in relative.parts)
                or source.suffix.casefold() not in _ADAPTER_SUFFIXES
            ):
                continue
            content = _stable_bytes(
                source,
                maximum=_MAX_ADAPTER_FILE_BYTES,
                label="adapter source file",
            )
            total += len(content)
            result.append(
                _FrozenAdapter(
                    source=source,
                    destination=destination_base / relative,
                    content=content,
                    sha256=hashlib.sha256(content).hexdigest(),
                )
            )
            if len(result) > _MAX_ADAPTER_FILES or total > _MAX_ADAPTER_TOTAL_BYTES:
                raise InstallError("adapter source exceeds installation budget")
    if not result:
        raise InstallError("adapter source is empty")
    return result


def _bundle_member_bytes(
    inspected: dict[str, Any],
    name: str,
    *,
    maximum: int,
    label: str,
) -> bytes:
    members = inspected.get("members") if isinstance(inspected, dict) else None
    content = members.get(name) if isinstance(members, dict) else None
    if (
        not isinstance(content, bytes)
        or len(content) < 1
        or len(content) > maximum
    ):
        raise InstallError(f"{label} is missing or invalid in runtime bundle")
    return content


def _materialize_release_members(
    release_root: Path,
    inspected: dict[str, Any],
) -> int:
    """Materialize the already-verified immutable runtime before pointer publish."""
    members = inspected.get("members") if isinstance(inspected, dict) else None
    if not isinstance(members, dict) or not members:
        raise InstallError("runtime bundle members are unavailable")
    release_absolute = _lexical_absolute(release_root)
    written = 0
    folded: set[str] = set()
    targets: list[tuple[Path, bytes]] = []
    for raw_name, content in sorted(members.items()):
        if not isinstance(raw_name, str) or not isinstance(content, bytes) or not content:
            raise InstallError("runtime bundle member is invalid")
        relative = PurePosixPath(raw_name)
        if (
            relative.is_absolute()
            or any(part in {"", ".", ".."} for part in relative.parts)
            or "\\" in raw_name
            or "\x00" in raw_name
            or any(":" in part for part in relative.parts)
        ):
            raise InstallError("runtime bundle member path is invalid")
        folded_name = relative.as_posix().casefold()
        if folded_name in folded:
            raise InstallError("runtime bundle member path is duplicated")
        folded.add(folded_name)
        target = _lexical_absolute(release_root.joinpath(*relative.parts))
        if not target.is_relative_to(release_absolute):
            raise InstallError("runtime bundle member path is invalid")
        targets.append((target, content))
        if target.exists() or target.is_symlink():
            observed = _stable_bytes(
                target,
                maximum=max(len(content), 1),
                label="installed release member",
            )
            if observed != content:
                raise InstallError(
                    "release version already exists with different member bytes"
                )
            continue
        _atomic_write(target, content)
        written += 1

    for target, content in targets:
        observed = _stable_bytes(
            target,
            maximum=max(len(content), 1),
            label="materialized release member",
        )
        if observed != content:
            raise InstallError("materialized release member verification failed")
    return written


def _materialize_release_identity(
    identity: dict[str, Any],
    install_home: Path,
) -> int:
    bundle_path = _identity_bundle(identity, install_home)
    bundle = _stable_bytes(
        bundle_path,
        maximum=128 * 1024 * 1024,
        label="rollback release bundle",
    )
    try:
        inspected = inspect_runtime_bundle(bundle, expected_identity=identity)
    except RuntimeBundleError as exc:
        raise InstallError("rollback release bundle is invalid") from exc
    return _materialize_release_members(Path(str(identity["path"])), inspected)


def _adapter_files_from_bundle(
    source_root: Path,
    inspected: dict[str, Any],
) -> list[_FrozenAdapter]:
    members = inspected.get("members") if isinstance(inspected, dict) else None
    if not isinstance(members, dict):
        raise InstallError("runtime bundle members are unavailable")
    mappings = (
        (
            ("integrations", "codex"),
            Path(".codex/skills/dev-supervisor"),
            "codex",
        ),
        (
            ("integrations", "claude"),
            Path(".claude/skills/supervisor"),
            "claude",
        ),
    )
    result: list[_FrozenAdapter] = []
    total = 0
    seen_runtimes: set[str] = set()
    destinations: set[str] = set()
    for name in sorted(members):
        content = members[name]
        if not isinstance(name, str) or not isinstance(content, bytes):
            raise InstallError("runtime bundle member map is invalid")
        member = PurePosixPath(name)
        for prefix, destination_base, runtime in mappings:
            if member.parts[:len(prefix)] != prefix:
                continue
            relative_parts = member.parts[len(prefix):]
            if (
                not relative_parts
                or member.suffix.casefold() not in _ADAPTER_SUFFIXES
                or any(part.casefold() in {"tests", "__pycache__"} for part in relative_parts)
                or any(part.startswith(".pytest-tmp-") for part in relative_parts)
                or len(content) < 1
                or len(content) > _MAX_ADAPTER_FILE_BYTES
            ):
                raise InstallError("runtime bundle adapter member is invalid")
            destination = destination_base.joinpath(*relative_parts)
            folded = destination.as_posix().casefold()
            if folded in destinations:
                raise InstallError("runtime bundle adapter destination is duplicated")
            destinations.add(folded)
            total += len(content)
            result.append(
                _FrozenAdapter(
                    source=source_root.joinpath(*member.parts),
                    destination=destination,
                    content=content,
                    sha256=hashlib.sha256(content).hexdigest(),
                )
            )
            seen_runtimes.add(runtime)
            if len(result) > _MAX_ADAPTER_FILES or total > _MAX_ADAPTER_TOTAL_BYTES:
                raise InstallError("runtime bundle adapters exceed installation budget")
            break
    if seen_runtimes != {"codex", "claude"} or not result:
        raise InstallError("runtime bundle adapter snapshot is incomplete")
    return result


def _backup_if_changed(
    target: Path,
    replacement: bytes,
    *,
    install_home: Path,
    backup_root: Path,
) -> bool:
    if not target.exists() and not target.is_symlink():
        return True
    current = _stable_bytes(
        target,
        maximum=max(_MAX_ADAPTER_FILE_BYTES, _MAX_CONTROL_BYTES),
        label="installed file",
        allow_empty=True,
    )
    if current == replacement:
        return False
    relative = target.relative_to(install_home)
    _atomic_write(backup_root / relative, current)
    return True


def install_release(
    *,
    source_root: Path,
    install_home: Path,
    apply: bool,
    install_adapters: bool = True,
    activate_codex: bool = True,
) -> dict[str, Any]:
    source = _lexical_absolute(source_root)
    home = _lexical_absolute(install_home)
    _reject_existing_indirection(source, label="source root")
    _reject_existing_indirection(home, label="installation home")
    if not source.is_dir():
        raise InstallError("source root is missing")

    data_root = home / ".agent-supervisor"
    release_parent = home / ".agent-supervisor-releases"
    pointer_path = data_root / "active-version.json"

    # Validate the current pointer before performing any writes.  A corrupt
    # installation requires manual recovery and must never be overwritten.
    existing_pointer = _validated_existing_pointer(pointer_path, home)
    version = _source_version(source)
    bundle = build_runtime_bundle(source, version)
    release_root = release_parent / version
    identity = _release_identity(release_root, version, bundle)
    inspected = inspect_runtime_bundle(bundle, expected_identity=identity)
    bundled_version = _bundle_member_bytes(
        inspected,
        "VERSION",
        maximum=128,
        label="release version",
    )
    try:
        parsed_bundle_version = bundled_version.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise InstallError("runtime bundle version is not ASCII") from exc
    if parsed_bundle_version != version or not _VERSION.fullmatch(parsed_bundle_version):
        raise InstallError("runtime bundle version does not match release version")
    adapters = (
        _adapter_files_from_bundle(source, inspected)
        if install_adapters
        else []
    )
    launcher = _bundle_member_bytes(
        inspected,
        "bin/agent-supervisor.py",
        maximum=_MAX_ADAPTER_FILE_BYTES,
        label="stage-zero launcher",
    )
    codex_activation = bool(install_adapters and activate_codex)
    codex_hooks_path = home / ".codex" / "hooks.json"
    codex_agents_path = home / ".codex" / "AGENTS.md"
    merged_codex_hooks = None
    merged_codex_agents = None
    if codex_activation:
        merged_codex_hooks = _merge_codex_hooks(
            _optional_profile_file(codex_hooks_path, label="existing Codex hooks"),
            install_home=home,
            interpreter=Path(sys.executable),
        )
        merged_codex_agents = _merge_global_agents(
            _optional_profile_file(codex_agents_path, label="existing Codex AGENTS")
        )

    previous = None
    if existing_pointer is not None:
        previous = (
            existing_pointer.get("previous")
            if existing_pointer.get("active") == identity
            else existing_pointer.get("active")
        )
    new_pointer = {
        "contract": "ActiveVersionPointer/v4",
        "active": identity,
        "previous": previous,
    }
    if not _valid_active_pointer(new_pointer):
        raise InstallError("generated active pointer is invalid")

    plan = {
        "contract": "AgentSupervisorInstallPlan/v1",
        "status": "dry-run" if not apply else "installed",
        "version": version,
        "install_home": str(home),
        "release_root": str(release_root),
        "bundle_sha256": identity["bundle_sha256"],
        "adapter_file_count": len(adapters),
        "codex_global_activation": codex_activation,
        "codex_hooks": str(codex_hooks_path) if codex_activation else None,
        "codex_agents": str(codex_agents_path) if codex_activation else None,
        "pointer": str(pointer_path),
    }
    if not apply:
        return plan

    # The caller owns the profile root.  Preserve its existing permissions;
    # only Supervisor-managed data and release directories are made private.
    _reject_existing_indirection(home.parent, label="installation parent")
    home.mkdir(parents=True, exist_ok=True)
    _reject_existing_indirection(home, label="installation home")
    _private_directory(release_parent)
    _private_directory(release_root)
    bundle_path = release_root / "runtime" / "supervisor-runtime.zip"
    if bundle_path.exists() or bundle_path.is_symlink():
        observed = _stable_bytes(
            bundle_path,
            maximum=128 * 1024 * 1024,
            label="installed release bundle",
        )
        if hashlib.sha256(observed).hexdigest() != identity["bundle_sha256"]:
            raise InstallError("release version already exists with different bytes")
    else:
        _atomic_write(bundle_path, bundle)
    installed_bundle = _stable_bytes(
        bundle_path,
        maximum=128 * 1024 * 1024,
        label="installed release bundle",
    )
    installed_inspected = inspect_runtime_bundle(
        installed_bundle,
        expected_identity=identity,
    )
    plan["release_members_written"] = _materialize_release_members(
        release_root,
        installed_inspected,
    )
    plan["rollback_members_written"] = (
        _materialize_release_identity(previous, home)
        if isinstance(previous, dict)
        else 0
    )

    backup_name = (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        + "-"
        + uuid.uuid4().hex[:12]
    )
    backup_root = data_root / "backups" / backup_name
    changed = _backup_if_changed(
        data_root / "bin" / "agent-supervisor.py",
        launcher,
        install_home=home,
        backup_root=backup_root,
    )
    if changed:
        _atomic_write(data_root / "bin" / "agent-supervisor.py", launcher)

    for adapter in adapters:
        if hashlib.sha256(adapter.content).hexdigest() != adapter.sha256:
            raise InstallError("frozen adapter digest mismatch")
        target = home / adapter.destination
        if _backup_if_changed(
            target,
            adapter.content,
            install_home=home,
            backup_root=backup_root,
        ):
            _atomic_write(target, adapter.content)

    if codex_activation:
        assert merged_codex_hooks is not None and merged_codex_agents is not None
        for target, replacement in (
            (codex_hooks_path, merged_codex_hooks),
            (codex_agents_path, merged_codex_agents),
        ):
            if _backup_if_changed(
                target,
                replacement,
                install_home=home,
                backup_root=backup_root,
            ):
                _atomic_write(
                    target,
                    replacement,
                    preserve_parent_permissions=True,
                )

    if pointer_path.exists() or pointer_path.is_symlink():
        pointer_bytes = _stable_bytes(
            pointer_path,
            maximum=_MAX_CONTROL_BYTES,
            label="existing active pointer",
        )
        _atomic_write(
            backup_root / ".agent-supervisor" / "active-version.json",
            pointer_bytes,
        )

    # Discovery marker published last.  A crash before this point leaves the
    # old active release selected and the new side-by-side bytes undiscovered.
    _atomic_write(pointer_path, _canonical_json_bytes(new_pointer))
    persisted = _validated_existing_pointer(pointer_path, home)
    if persisted != new_pointer:
        raise InstallError("published active pointer verification failed")
    plan["backup_root"] = str(backup_root) if backup_root.exists() else None
    return plan


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT)
    parser.add_argument("--install-home", type=Path, default=Path.home())
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--core-only", action="store_true")
    parser.add_argument(
        "--no-codex-global-activation",
        action="store_true",
        help="install adapters without merging user-level Codex hooks and AGENTS.md",
    )
    args = parser.parse_args(argv)
    try:
        result = install_release(
            source_root=args.source,
            install_home=args.install_home,
            apply=args.apply,
            install_adapters=not args.core_only,
            activate_codex=not args.no_codex_global_activation,
        )
    except (InstallError, RuntimeBundleError, OSError, ValueError) as exc:
        print(
            json.dumps(
                {
                    "contract": "AgentSupervisorInstallResult/v1",
                    "status": "failed",
                    "reason": str(exc),
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 64
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
