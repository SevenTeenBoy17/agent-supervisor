#!/usr/bin/env python3
"""Thin Codex lifecycle adapter for Agent Supervisor v3.

The adapter owns no supervision policy. It preserves every host envelope field,
adds one reserved adapter-health object, and forwards the result to the versioned
shared core with ``runtime=codex``. Core stdout is relayed byte-for-byte.

If the core cannot run, the hook fails open with an empty JSON object while a
bounded, metadata-only marker is retained. A later successful core call receives
that marker through ``_agent_supervisor_adapter.degraded_prior`` so the durable
round remains degraded and cannot be finalized as complete.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import stat
import subprocess
import sys
import time
from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ADAPTER_VERSION = "3.1.6"
POINTER_CONTRACT = "ActiveVersionPointer/v4"
IDENTITY_CONTRACT = "SupervisorReleaseIdentity/v1"
TRUSTED_EXECUTABLE_REGISTRY_CONTRACT = "TrustedExecutableRegistry/v1"
RELEASE_IDENTITY_FIELDS = frozenset({
    "bundle_relpath", "bundle_sha256", "contract", "manifest_sha256",
    "path", "source_tree_sha256", "version",
})
CORE_BRIDGE_LENGTH = 88076
CORE_BRIDGE_SHA256 = "6fe3ec5932e89eb4403140b94440f692a56c4c13eda29ed62d5664be2abd4756"
HOOK_BRIDGE_LENGTH = 2858
HOOK_BRIDGE_SHA256 = "ccc5543ee12a3e8693dd5d5dcb12ce21589eb2f6f3ab1159ce15511a870a5784"
KNOWN_CORE_CODES = {0, 2, 3, 4, 64}
FAIL_OPEN_OUTPUT = b"{}"
MARKER_PERSISTENCE_WARNING = (
    "Supervisor v3 is degraded and its local health marker could not be persisted; "
    "completion must remain incomplete."
)
MAX_SPOOL_BYTES = 64 * 1024
MAX_SPOOL_RECORDS = 64
MAX_STDIN_BYTES = 4 * 1024 * 1024
MAX_HOOK_JSON_NODES = 50_000
MAX_HOOK_JSON_DEPTH = 64
MAX_APPROVED_COMMANDS = 256
RETENTION_SECONDS = 14 * 86400
MAX_MARKERS = 200
MARKER_LOCK_RETRY_SECONDS = 1.5
UNIDENTIFIED_SESSION = "unidentified-hook-session"
INNER_STARTUP_GRACE_SECONDS = 1.5
INNER_STREAM_CLEANUP_SECONDS = 2.0
OUTER_BRIDGE_GRACE_SECONDS = 1.0
OUTER_PROCESS_TREE_CLEANUP_SECONDS = 2.0
CREATE_SUSPENDED = 0x00000004
DEGRADED_REASON_CATEGORIES = frozenset({
    "adapter_exception",
    "core_degraded_response",
    "core_invalid_state",
    "core_missing_or_rejected",
    "core_timeout",
    "core_unexpected_exit",
    "invalid_event",
    "invalid_input",
    "unclassified_degraded",
})

OFFICIAL_EVENTS = frozenset({
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
})
EVENT_ALIASES = {
    "session-start": "SessionStart",
    "prompt-submit": "UserPromptSubmit",
    "user-prompt-submit": "UserPromptSubmit",
    "pre-tool": "PreToolUse",
    "permission-request": "PermissionRequest",
    "post-tool": "PostToolUse",
    "pre-compact": "PreCompact",
    "post-compact": "PostCompact",
    "subagent-start": "SubagentStart",
    "subagent-stop": "SubagentStop",
    "stop": "Stop",
    "session-end": "SessionEnd",
}


def _home() -> Path:
    return _adapter_install_home()


def _lexical_absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def _is_reparse(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    return bool(
        stat.S_ISLNK(info.st_mode)
        or (
            hasattr(info, "st_file_attributes")
            and bool(
                info.st_file_attributes
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
            )
        )
    )


def _path_has_reparse(path: Path) -> bool:
    path = _lexical_absolute(path)
    anchor = Path(path.anchor)
    current = anchor
    for part in path.parts[1:]:
        current /= part
        if _is_reparse(current):
            return True
    return False


def _canonical_existing(path: Path, *, directory: bool) -> Path | None:
    lexical = _lexical_absolute(path)
    try:
        if _path_has_reparse(lexical):
            return None
        if directory and not lexical.is_dir():
            return None
        if not directory and not lexical.is_file():
            return None
        resolved = lexical.resolve(strict=True)
    except OSError:
        return None
    if os.path.normcase(str(resolved)) != os.path.normcase(str(lexical)):
        return None
    return resolved


def _adapter_install_home() -> Path:
    """Derive the only trust anchor from this canonical adapter installation."""
    script = _canonical_existing(Path(__file__), directory=False)
    if script is None or script.name != "codex-supervisor-hook.py":
        raise FileNotFoundError("adapter_layout_rejected")
    try:
        scripts_root = script.parent
        adapter_root = scripts_root.parent
        skills_root = adapter_root.parent
        codex_root = skills_root.parent
        install_home = codex_root.parent
    except IndexError as error:
        raise FileNotFoundError("adapter_layout_rejected") from error
    expected = (
        (scripts_root, "scripts"),
        (adapter_root, "dev-supervisor"),
        (skills_root, "skills"),
        (codex_root, ".codex"),
    )
    if any(path.name.casefold() != name.casefold() for path, name in expected):
        raise FileNotFoundError("adapter_layout_rejected")
    for directory in (scripts_root, adapter_root, skills_root, codex_root, install_home):
        canonical = _canonical_existing(directory, directory=True)
        if canonical is None or os.path.normcase(str(canonical)) != os.path.normcase(str(directory)):
            raise FileNotFoundError("adapter_layout_rejected")
    return install_home


@contextmanager
def _locked_verified_bridge_file(
    name: str, expected_length: int, expected_sha256: str
):
    """Hold a deny-write/delete Windows handle from verification through launch."""
    if os.name != "nt":
        raise FileNotFoundError("windows_bridge_lock_unavailable")
    path = _canonical_existing(Path(__file__).parent / name, directory=False)
    if path is None:
        raise FileNotFoundError("hook_bridge_missing")

    import ctypes
    import msvcrt

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    )
    create_file.restype = ctypes.c_void_p
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (ctypes.c_void_p,)
    close_handle.restype = ctypes.c_int
    raw_handle = create_file(
        str(path),
        0x80000000,  # GENERIC_READ
        0x00000001,  # FILE_SHARE_READ: deny concurrent write and delete/rename
        None,
        3,  # OPEN_EXISTING
        0x00000080,  # FILE_ATTRIBUTE_NORMAL
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if raw_handle in {None, invalid_handle}:
        raise FileNotFoundError("hook_bridge_lock_failed")
    descriptor: int | None = None
    stream = None
    try:
        try:
            descriptor = msvcrt.open_osfhandle(
                int(raw_handle), os.O_RDONLY | getattr(os, "O_BINARY", 0)
            )
            raw_handle = None
            stream = os.fdopen(descriptor, "rb", closefd=True)
            descriptor = None
        except (OSError, ValueError):
            raise FileNotFoundError("hook_bridge_lock_failed") from None
        locked = os.fstat(stream.fileno())
        locked_identity = (locked.st_dev, locked.st_ino, locked.st_size)
        current = _canonical_existing(path, directory=False)
        if current is None:
            raise FileNotFoundError("hook_bridge_rejected")
        observed = current.stat(follow_symlinks=False)
        observed_identity = (observed.st_dev, observed.st_ino, observed.st_size)
        content = stream.read(1024 * 1024 + 1)
        if (
            locked_identity != observed_identity
            or len(content) != locked.st_size
            or len(content) != expected_length
            or hashlib.sha256(content).hexdigest() != expected_sha256
        ):
            raise FileNotFoundError("hook_bridge_rejected")
        stream.seek(0)
        yield path, stream
    finally:
        if stream is not None:
            stream.close()
        elif descriptor is not None:
            os.close(descriptor)
        elif raw_handle not in {None, invalid_handle}:
            close_handle(raw_handle)


def _supported_posix_platform() -> bool:
    return sys.platform.startswith("linux") or sys.platform == "darwin"


def _posix_identity_from_stream(stream: Any) -> tuple[int, int, int, int]:
    observed = os.fstat(stream.fileno())
    return (
        int(observed.st_dev),
        int(observed.st_ino),
        int(observed.st_size),
        int(observed.st_mtime_ns),
    )


def _posix_identity_from_path(path: Path) -> tuple[int, int, int, int]:
    observed = path.stat(follow_symlinks=False)
    return (
        int(observed.st_dev),
        int(observed.st_ino),
        int(observed.st_size),
        int(observed.st_mtime_ns),
    )


def _posix_executable_paths(
    candidate: Path,
    *,
    allowed_names: frozenset[str],
    allowed_roots: tuple[Path, ...],
    require_root_owner: bool,
) -> tuple[Path, Path] | None:
    """Validate one explicit POSIX executable path without consulting PATH."""
    if not _supported_posix_platform():
        return None
    lexical = _lexical_absolute(candidate)
    if not lexical.is_absolute() or lexical.name not in allowed_names:
        return None
    try:
        # A package-manager executable may be a leaf symlink. Directory symlinks,
        # group/other-writable path components, and writable executable objects
        # are never accepted. Registry-bound paths may be owned by the installer;
        # hard-coded fallbacks additionally require an OS-owned chain.
        current = Path(lexical.anchor)
        for component in lexical.parts[1:-1]:
            current /= component
            info = current.lstat()
            if (
                not stat.S_ISDIR(info.st_mode)
                or stat.S_ISLNK(info.st_mode)
                or info.st_mode & 0o022
                or (require_root_owner and info.st_uid != 0)
            ):
                return None
        leaf = lexical.lstat()
        leaf_is_link = stat.S_ISLNK(leaf.st_mode)
        if (
            not (stat.S_ISREG(leaf.st_mode) or leaf_is_link)
            or (not leaf_is_link and leaf.st_mode & 0o022)
            or (require_root_owner and leaf.st_uid != 0)
        ):
            return None
        resolved = lexical.resolve(strict=True)
        resolved_info = resolved.lstat()
        if (
            not stat.S_ISREG(resolved_info.st_mode)
            or stat.S_ISLNK(resolved_info.st_mode)
            or resolved_info.st_mode & 0o022
            or (require_root_owner and resolved_info.st_uid != 0)
        ):
            return None
        current = Path(resolved.anchor)
        for component in resolved.parts[1:-1]:
            current /= component
            info = current.lstat()
            if (
                not stat.S_ISDIR(info.st_mode)
                or stat.S_ISLNK(info.st_mode)
                or info.st_mode & 0o022
                or (require_root_owner and info.st_uid != 0)
            ):
                return None
        for allowed_root in allowed_roots:
            try:
                resolved.relative_to(allowed_root.resolve(strict=True))
                return lexical, resolved
            except (OSError, ValueError):
                continue
    except OSError:
        return None
    return None


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _parse_trusted_executable_registry(content: bytes) -> dict[str, Any]:
    """Parse the machine registry without accepting ambiguous or extra fields."""

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate_registry_key")
            value[key] = item
        return value

    try:
        registry = json.loads(
            content.decode("utf-8"), object_pairs_hook=reject_duplicates
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
        raise FileNotFoundError("trusted_executable_registry_invalid") from None
    if (
        not isinstance(registry, dict)
        or set(registry) != {"contract", "entries", "generated_at"}
        or registry.get("contract") != TRUSTED_EXECUTABLE_REGISTRY_CONTRACT
        or not isinstance(registry.get("generated_at"), str)
        or not isinstance(registry.get("entries"), dict)
        or not registry["entries"]
    ):
        raise FileNotFoundError("trusted_executable_registry_invalid")

    required_fields = {"kind", "path", "sha256"}
    optional_fields = {"allowed_argv_sha256"}
    for name, entry in registry["entries"].items():
        if (
            not isinstance(name, str)
            or name != name.casefold()
            or not 1 <= len(name) <= 64
            or not name[0].isalnum()
            or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789._-" for character in name)
            or not isinstance(entry, dict)
            or not required_fields <= set(entry)
            or bool(set(entry) - required_fields - optional_fields)
            or entry.get("kind") not in {"local", "wsl"}
            or not isinstance(entry.get("path"), str)
            or not entry["path"]
            or not _is_sha256(entry.get("sha256"))
        ):
            raise FileNotFoundError("trusted_executable_registry_invalid")
        approvals = entry.get("allowed_argv_sha256", [])
        if (
            not isinstance(approvals, list)
            or len(approvals) > MAX_APPROVED_COMMANDS
            or any(not _is_sha256(approval) for approval in approvals)
            or len(set(approvals)) != len(approvals)
        ):
            raise FileNotFoundError("trusted_executable_registry_invalid")
        if entry["kind"] == "local":
            if not Path(entry["path"]).is_absolute():
                raise FileNotFoundError("trusted_executable_registry_invalid")
        elif (
            not entry["path"].startswith("/")
            or "\\" in entry["path"]
            or ".." in Path(entry["path"]).parts
        ):
            raise FileNotFoundError("trusted_executable_registry_invalid")
    return registry["entries"]


def _read_trusted_executable_registry(install_home: Path) -> dict[str, Any]:
    registry_path = _canonical_existing(
        install_home / ".agent-supervisor" / "trusted-executables.json",
        directory=False,
    )
    if registry_path is None:
        raise FileNotFoundError("trusted_executable_registry_missing")
    with registry_path.open("rb") as stream:
        before = _posix_identity_from_stream(stream)
        content = stream.read(1024 * 1024 + 1)
    if (
        len(content) > 1024 * 1024
        or _posix_identity_from_path(registry_path) != before
    ):
        raise FileNotFoundError("trusted_executable_registry_changed")

    return _parse_trusted_executable_registry(content)


def _select_posix_executable(
    install_home: Path,
    *,
    registry_names: tuple[str, ...],
    allowed_names: frozenset[str],
    fixed_candidates: tuple[Path, ...],
    require_running_python: bool,
) -> tuple[Path, Path, str | None]:
    allowed_roots = (
        Path("/usr"),
        Path("/usr/local"),
        Path("/opt/microsoft"),
        Path("/opt/homebrew"),
        Path("/opt/local"),
        install_home / ".pyenv" / "versions",
    )
    candidates: list[tuple[Path, str | None, bool]] = []
    try:
        entries = _read_trusted_executable_registry(install_home)
    except FileNotFoundError:
        entries = {}
    for registry_name in registry_names:
        entry = entries.get(registry_name)
        if (
            not isinstance(entry, dict)
            or not {"kind", "path", "sha256"} <= set(entry)
            or bool(set(entry) - {"kind", "path", "sha256", "allowed_argv_sha256"})
            or entry.get("kind") != "local"
            or not isinstance(entry.get("path"), str)
            or not Path(entry["path"]).is_absolute()
            or not _is_sha256(entry.get("sha256"))
        ):
            continue
        candidates.append((Path(entry["path"]), entry["sha256"], False))
    candidates.extend((candidate, None, True) for candidate in fixed_candidates)
    for candidate, expected_sha256, require_root_owner in candidates:
        selected = _posix_executable_paths(
            candidate,
            allowed_names=allowed_names,
            allowed_roots=allowed_roots,
            require_root_owner=require_root_owner,
        )
        if selected is None:
            continue
        lexical, resolved = selected
        if require_running_python:
            try:
                if not os.path.samefile(resolved, Path(sys.executable)):
                    continue
            except OSError:
                continue
        try:
            with resolved.open("rb") as stream:
                before = _posix_identity_from_stream(stream)
                hasher = hashlib.sha256()
                while chunk := stream.read(1024 * 1024):
                    hasher.update(chunk)
            if (
                _posix_identity_from_path(resolved) != before
                or (expected_sha256 is not None and hasher.hexdigest() != expected_sha256)
            ):
                continue
        except OSError:
            continue
        return lexical, resolved, expected_sha256
    raise FileNotFoundError("trusted_posix_executable_missing_or_rejected")


@contextmanager
def _verified_posix_executable(selection: tuple[Path, Path, str | None]):
    lexical, resolved, expected_sha256 = selection
    stream = resolved.open("rb")
    try:
        identity = _posix_identity_from_stream(stream)
        hasher = hashlib.sha256()
        while chunk := stream.read(1024 * 1024):
            hasher.update(chunk)
        if (
            _posix_identity_from_path(resolved) != identity
            or (expected_sha256 is not None and hasher.hexdigest() != expected_sha256)
        ):
            raise FileNotFoundError("posix_executable_changed")
        stream.seek(0)
        yield lexical, stream
        if _posix_identity_from_path(resolved) != identity:
            raise FileNotFoundError("posix_executable_changed")
    finally:
        stream.close()


@contextmanager
def _trusted_posix_python(install_home: Path):
    current = _lexical_absolute(Path(sys.executable))
    fixed = tuple(dict.fromkeys((
        Path("/usr/bin/python3"),
        Path("/usr/local/bin/python3"),
        Path("/opt/homebrew/bin/python3"),
        Path("/opt/local/bin/python3"),
        current,
    )))
    selected = _select_posix_executable(
        install_home,
        registry_names=("python",),
        allowed_names=frozenset({"python", "python3"}),
        fixed_candidates=fixed,
        require_running_python=True,
    )
    with _verified_posix_executable(selected) as executable:
        yield executable


@contextmanager
def _trusted_posix_powershell(install_home: Path):
    selected = _select_posix_executable(
        install_home,
        registry_names=("pwsh", "powershell"),
        allowed_names=frozenset({"pwsh"}),
        fixed_candidates=(
            Path("/usr/bin/pwsh"),
            Path("/usr/local/bin/pwsh"),
            Path("/opt/microsoft/powershell/7/pwsh"),
            Path("/opt/homebrew/bin/pwsh"),
            Path("/opt/local/bin/pwsh"),
        ),
        require_running_python=False,
    )
    with _verified_posix_executable(selected) as executable:
        yield executable


@contextmanager
def _stable_verified_posix_bridge_file(
    name: str, expected_length: int, expected_sha256: str
):
    if not _supported_posix_platform():
        raise FileNotFoundError("posix_bridge_platform_rejected")
    path = _canonical_existing(Path(__file__).parent / name, directory=False)
    if path is None:
        raise FileNotFoundError("hook_bridge_missing")
    stream = path.open("rb")
    try:
        identity = _posix_identity_from_stream(stream)
        content = stream.read(expected_length + 1)
        if (
            identity[2] != expected_length
            or len(content) != expected_length
            or hashlib.sha256(content).hexdigest() != expected_sha256
            or _posix_identity_from_path(path) != identity
        ):
            raise FileNotFoundError("hook_bridge_rejected")
        stream.seek(0)
        yield path, stream
        if _posix_identity_from_path(path) != identity:
            raise FileNotFoundError("hook_bridge_changed")
    finally:
        stream.close()


@contextmanager
def _trusted_posix_hook_bridge_files():
    with ExitStack() as stack:
        core = stack.enter_context(_stable_verified_posix_bridge_file(
            "supervisor-core.ps1", CORE_BRIDGE_LENGTH, CORE_BRIDGE_SHA256
        ))
        hook = stack.enter_context(_stable_verified_posix_bridge_file(
            "supervisor-hook.ps1", HOOK_BRIDGE_LENGTH, HOOK_BRIDGE_SHA256
        ))
        yield core, hook


@contextmanager
def _trusted_hook_bridge_files():
    if _supported_posix_platform():
        with _trusted_posix_hook_bridge_files() as bridges:
            yield bridges
        return
    with ExitStack() as stack:
        core = stack.enter_context(_locked_verified_bridge_file(
            "supervisor-core.ps1", CORE_BRIDGE_LENGTH, CORE_BRIDGE_SHA256
        ))
        hook = stack.enter_context(_locked_verified_bridge_file(
            "supervisor-hook.ps1", HOOK_BRIDGE_LENGTH, HOOK_BRIDGE_SHA256
        ))
        yield core, hook


def _trusted_hook_bridge_source() -> str:
    """Compatibility diagnostic: return the same verified bytes without launching."""
    with _trusted_hook_bridge_files() as (core, hook):
        return (core[1].read() + b"\r\n" + hook[1].read()).decode("utf-8")


def _posix_inline_hook_bridge_source(
    scripts_root: Path, core_bytes: bytes, hook_bytes: bytes
) -> str:
    """Inline hash-verified bridge bytes instead of dot-sourcing mutable paths."""
    try:
        core_source = core_bytes.decode("utf-8", "strict")
        hook_source = hook_bytes.decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise FileNotFoundError("hook_bridge_encoding_rejected") from None
    core_anchor = "$script:AgentSupervisorAdapterScriptsRoot = $PSScriptRoot"
    if core_source.count(core_anchor) != 1:
        raise FileNotFoundError("core_bridge_root_anchor_rejected")
    escaped_root = str(scripts_root).replace("'", "''")
    core_source = core_source.replace(
        core_anchor,
        f"$script:AgentSupervisorAdapterScriptsRoot = '{escaped_root}'",
        1,
    )
    hook_lines = hook_source.splitlines(keepends=True)
    expected_prefix = (
        "$ErrorActionPreference = 'Stop'",
        "$coreBridge = Join-Path $PSScriptRoot 'supervisor-core.ps1'",
        ". $coreBridge",
    )
    if (
        len(hook_lines) < 4
        or tuple(line.rstrip("\r\n") for line in hook_lines[:3]) != expected_prefix
    ):
        raise FileNotFoundError("hook_bridge_bootstrap_anchor_rejected")
    return core_source + "\n" + "".join(hook_lines[3:])


def _windows_system_directory() -> Path:
    """Resolve System32 from the OS, never from the inherited environment."""
    if os.name != "nt":
        raise FileNotFoundError("windows_system_directory_unavailable")

    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_system_directory = kernel32.GetSystemDirectoryW
    get_system_directory.argtypes = (ctypes.c_wchar_p, ctypes.c_uint32)
    get_system_directory.restype = ctypes.c_uint32
    capacity = 260
    while capacity <= 32768:
        buffer = ctypes.create_unicode_buffer(capacity)
        length = int(get_system_directory(buffer, capacity))
        if length == 0:
            raise FileNotFoundError("windows_system_directory_unavailable")
        if length < capacity:
            system_directory = _canonical_existing(Path(buffer.value), directory=True)
            if (
                system_directory is None
                or system_directory.name.casefold() != "system32"
                or not system_directory.is_absolute()
            ):
                raise FileNotFoundError("windows_system_directory_rejected")
            return system_directory
        capacity = length + 1
    raise FileNotFoundError("windows_system_directory_rejected")


def _trusted_powershell() -> Path:
    system_directory = _windows_system_directory()
    expected = _lexical_absolute(
        system_directory / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    )
    candidate = _canonical_existing(expected, directory=False)
    if (
        candidate is None
        or candidate.name.casefold() != "powershell.exe"
        or os.path.normcase(str(candidate)) != os.path.normcase(str(expected))
        or candidate.parent.name.casefold() != "v1.0"
        or candidate.parent.parent.name.casefold() != "windowspowershell"
        or os.path.normcase(str(candidate.parent.parent.parent))
        != os.path.normcase(str(system_directory))
    ):
        raise FileNotFoundError("powershell_missing_or_rejected")
    return candidate


@contextmanager
def _locked_trusted_powershell():
    """Hold the OS-selected PowerShell executable immutable through execution."""
    if os.name != "nt":
        raise FileNotFoundError("powershell_lock_unavailable")
    path = _trusted_powershell()

    import ctypes
    import msvcrt

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    )
    create_file.restype = ctypes.c_void_p
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (ctypes.c_void_p,)
    close_handle.restype = ctypes.c_int
    raw_handle = create_file(
        str(path),
        0x80000000,  # GENERIC_READ
        0x00000001,  # FILE_SHARE_READ: deny write, delete, and replacement
        None,
        3,  # OPEN_EXISTING
        0x00000080,  # FILE_ATTRIBUTE_NORMAL
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if raw_handle in {None, invalid_handle}:
        raise FileNotFoundError("powershell_lock_failed")
    descriptor: int | None = None
    stream = None
    try:
        try:
            descriptor = msvcrt.open_osfhandle(
                int(raw_handle), os.O_RDONLY | getattr(os, "O_BINARY", 0)
            )
            raw_handle = None
            stream = os.fdopen(descriptor, "rb", closefd=True)
            descriptor = None
            locked = os.fstat(stream.fileno())
            observed_path = _trusted_powershell()
            observed = observed_path.stat(follow_symlinks=False)
            if (
                (locked.st_dev, locked.st_ino, locked.st_size)
                != (observed.st_dev, observed.st_ino, observed.st_size)
                or locked.st_size < 2
                or stream.read(2) != b"MZ"
            ):
                raise FileNotFoundError("powershell_identity_rejected")
            stream.seek(0)
        except (OSError, ValueError):
            raise FileNotFoundError("powershell_lock_failed") from None
        yield path, stream, _windows_system_directory()
    finally:
        if stream is not None:
            stream.close()
        elif descriptor is not None:
            os.close(descriptor)
        elif raw_handle not in {None, invalid_handle}:
            close_handle(raw_handle)


def _trusted_registry_python(install_home: Path) -> tuple[Path, str]:
    registry_path = _canonical_existing(
        install_home / ".agent-supervisor" / "trusted-executables.json",
        directory=False,
    )
    if registry_path is None:
        raise FileNotFoundError("trusted_executable_registry_missing")
    with registry_path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        content = stream.read(1024 * 1024 + 1)
    after_path = _canonical_existing(registry_path, directory=False)
    if after_path is None:
        raise FileNotFoundError("trusted_executable_registry_rejected")
    after = after_path.stat(follow_symlinks=False)
    if (
        len(content) > 1024 * 1024
        or (before.st_dev, before.st_ino, before.st_size)
        != (after.st_dev, after.st_ino, after.st_size)
    ):
        raise FileNotFoundError("trusted_executable_registry_changed")

    entries = _parse_trusted_executable_registry(content)
    entry = entries.get("python")
    if (
        not isinstance(entry, dict)
        or not {"kind", "path", "sha256"} <= set(entry)
        or bool(set(entry) - {"kind", "path", "sha256", "allowed_argv_sha256"})
        or entry.get("kind") != "local"
        or not isinstance(entry.get("path"), str)
        or not Path(entry["path"]).is_absolute()
        or not _is_sha256(entry.get("sha256"))
    ):
        raise FileNotFoundError("trusted_python_registry_entry_invalid")
    candidate = _canonical_existing(Path(entry["path"]), directory=False)
    if candidate is None or candidate.name.casefold() not in {
        "python.exe",
        "python3.exe",
    }:
        raise FileNotFoundError("trusted_python_missing_or_rejected")
    return candidate, entry["sha256"]


@contextmanager
def _locked_trusted_registry_python(install_home: Path):
    """Lock the registry-bound Python executable while PowerShell resolves it."""
    if os.name != "nt":
        raise FileNotFoundError("trusted_python_lock_unavailable")
    path, expected_sha256 = _trusted_registry_python(install_home)

    import ctypes
    import msvcrt

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    )
    create_file.restype = ctypes.c_void_p
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (ctypes.c_void_p,)
    close_handle.restype = ctypes.c_int
    raw_handle = create_file(
        str(path),
        0x80000000,
        0x00000001,
        None,
        3,
        0x00000080,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if raw_handle in {None, invalid_handle}:
        raise FileNotFoundError("trusted_python_lock_failed")
    descriptor: int | None = None
    stream = None
    try:
        try:
            descriptor = msvcrt.open_osfhandle(
                int(raw_handle), os.O_RDONLY | getattr(os, "O_BINARY", 0)
            )
            raw_handle = None
            stream = os.fdopen(descriptor, "rb", closefd=True)
            descriptor = None
            locked = os.fstat(stream.fileno())
            observed_path = _canonical_existing(path, directory=False)
            if observed_path is None:
                raise FileNotFoundError("trusted_python_identity_rejected")
            observed = observed_path.stat(follow_symlinks=False)
            hasher = hashlib.sha256()
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                hasher.update(chunk)
            if (
                (locked.st_dev, locked.st_ino, locked.st_size)
                != (observed.st_dev, observed.st_ino, observed.st_size)
                or hasher.hexdigest() != expected_sha256
            ):
                raise FileNotFoundError("trusted_python_identity_rejected")
            stream.seek(0)
        except (OSError, ValueError):
            raise FileNotFoundError("trusted_python_lock_failed") from None
        yield path, stream
    finally:
        if stream is not None:
            stream.close()
        elif descriptor is not None:
            os.close(descriptor)
        elif raw_handle not in {None, invalid_handle}:
            close_handle(raw_handle)


def _install_home() -> Path:
    return _adapter_install_home()


def _sha(value: Any) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8", "replace")).hexdigest()


def _event_name(explicit: str | None, payload: dict[str, Any]) -> str:
    raw = explicit or payload.get("hook_event_name") or ""
    value = str(raw)
    return EVENT_ALIASES.get(value, value)


def _session_id(payload: dict[str, Any]) -> str:
    return str(
        payload.get("session_id")
        or os.environ.get("CODEX_THREAD_ID")
        or UNIDENTIFIED_SESSION
    )


def _fallback_paths(session_id: str) -> tuple[Path, Path]:
    root = _adapter_install_home() / ".agent-supervisor" / "fallback" / "codex"
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return root / f"{date}.jsonl", root / "markers" / f"{_sha(session_id)}.json"


def _marker_paths(session_id: str) -> tuple[Path, ...]:
    session_marker = _fallback_paths(session_id)[1]
    unknown_marker = _fallback_paths(UNIDENTIFIED_SESSION)[1]
    return (session_marker,) if session_marker == unknown_marker else (session_marker, unknown_marker)


def _has_degraded_marker(session_id: str) -> bool:
    return any(path.is_file() for path in _marker_paths(session_id))


def _clear_degraded_markers(session_id: str) -> None:
    # A durable acknowledgement covers the current named session and any
    # unidentified degradation that was forwarded with it. Other named-session
    # markers remain isolated and must survive.
    for marker in _marker_paths(session_id):
        lock = marker.with_suffix(".lock")
        fd = _acquire_lock(lock, timeout_seconds=0.25)
        if fd is None:
            # A concurrent writer wins over recovery cleanup.
            continue
        try:
            marker.unlink(missing_ok=True)
        except OSError:
            # Keeping a marker is conservative: the next round stays degraded.
            pass
        finally:
            _release_lock(fd, lock)


def _acquire_lock(lock: Path, timeout_seconds: float = 1.5) -> int | None:
    deadline = time.monotonic() + timeout_seconds
    try:
        lock.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        return None
    while time.monotonic() < deadline:
        try:
            return os.open(str(lock), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            try:
                if time.time() - lock.stat().st_mtime > 30:
                    lock.unlink(missing_ok=True)
                    continue
            except OSError:
                pass
            time.sleep(0.02)
        except OSError:
            return None
    return None


def _release_lock(fd: int | None, lock: Path) -> None:
    if fd is not None:
        try:
            os.close(fd)
        except OSError:
            pass
    try:
        lock.unlink(missing_ok=True)
    except OSError:
        pass


def _safe_reason_category(reason: Any) -> str:
    if isinstance(reason, str) and reason in DEGRADED_REASON_CATEGORIES:
        return reason
    return "unclassified_degraded"


def _write_degraded_marker(
    marker_path: Path,
    record: dict[str, Any],
    recorded_at: str,
    lock_timeout_seconds: float = 0.25,
) -> bool:
    """Atomically retain health independently from the contended spool lock."""
    lock = marker_path.with_suffix(".lock")
    fd = _acquire_lock(lock, timeout_seconds=lock_timeout_seconds)
    if fd is None:
        # Another marker writer may already have completed. Never remove or
        # overwrite its evidence without owning the dedicated marker lock.
        return marker_path.is_file()

    marker_tmp: Path | None = None
    temp_fd: int | None = None
    try:
        marker_path.parent.mkdir(parents=True, exist_ok=True)
        first_seen = recorded_at
        try:
            existing = json.loads(marker_path.read_text(encoding="utf-8"))
            if isinstance(existing, dict) and isinstance(existing.get("first_seen"), str):
                first_seen = existing["first_seen"]
        except (OSError, TypeError, ValueError):
            pass
        marker = {
            "contract": "AdapterHealth/v3",
            "runtime": "codex",
            "adapter_version": ADAPTER_VERSION,
            "session_sha256": record["session_sha256"],
            "health": "degraded",
            "first_seen": first_seen,
            "last_seen": recorded_at,
            "reason_category": record["reason_category"],
            "recovery_requires": "successful durable shared-core acknowledgement",
        }
        encoded = json.dumps(marker, ensure_ascii=True, separators=(",", ":")).encode("ascii")
        marker_tmp = marker_path.with_name(
            f".{marker_path.name}.{os.getpid()}.{time.time_ns()}.tmp"
        )
        temp_fd = os.open(str(marker_tmp), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        with os.fdopen(temp_fd, "wb") as handle:
            temp_fd = None
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(marker_tmp, marker_path)
        marker_tmp = None
        return True
    except OSError:
        return False
    finally:
        if temp_fd is not None:
            try:
                os.close(temp_fd)
            except OSError:
                pass
        if marker_tmp is not None:
            try:
                marker_tmp.unlink(missing_ok=True)
            except OSError:
                pass
        _release_lock(fd, lock)


def _retention_snapshots(directory: Path, pattern: str):
    snapshots = []
    try:
        candidates = directory.glob(pattern)
    except OSError:
        return []
    for candidate in candidates:
        try:
            info = candidate.lstat()
            if not stat.S_ISREG(info.st_mode) or _is_reparse(candidate):
                continue
            snapshots.append((candidate, info))
        except OSError:
            continue
    return sorted(snapshots, key=lambda item: item[1].st_mtime, reverse=True)


def _same_snapshot(path: Path, expected) -> bool:
    try:
        current = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISREG(current.st_mode)
        and not _is_reparse(path)
        and (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns)
        == (expected.st_dev, expected.st_ino, expected.st_size, expected.st_mtime_ns)
    )


def _prune_retention(directory: Path, pattern: str, keep: int, cutoff: float) -> None:
    for index, (stale, snapshot) in enumerate(_retention_snapshots(directory, pattern)):
        if index < keep and snapshot.st_mtime >= cutoff:
            continue
        stale_lock = stale.with_suffix(".lock")
        stale_fd = _acquire_lock(stale_lock, timeout_seconds=0.05)
        if stale_fd is None:
            continue
        try:
            if _same_snapshot(stale, snapshot):
                stale.unlink()
        except OSError:
            pass
        finally:
            _release_lock(stale_fd, stale_lock)


def _tail_lines(path: Path) -> list[bytes]:
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            start = max(0, size - MAX_SPOOL_BYTES)
            preceding = b"\n"
            if start:
                handle.seek(start - 1)
                preceding = handle.read(1)
            handle.seek(start)
            data = handle.read(MAX_SPOOL_BYTES)
    except OSError:
        return []
    if start and preceding != b"\n":
        boundary = data.find(b"\n")
        if boundary < 0:
            return []
        data = data[boundary + 1 :]
    complete: list[bytes] = []
    for line in data.splitlines():
        if not line:
            continue
        try:
            decoded = json.loads(line)
        except (TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(decoded, dict):
            complete.append(line)
    return complete[-MAX_SPOOL_RECORDS + 1 :]


def _record_degraded(event: str, payload: dict[str, Any], reason: str, input_bytes: int) -> bool:
    """Persist bounded metadata only; never prompt, command, or result values."""
    session_id = _session_id(payload)
    log_path, marker_path = _fallback_paths(session_id)
    recorded_at = datetime.now(timezone.utc).isoformat()
    safe_reason = _safe_reason_category(reason)
    record = {
        "contract": "AdapterDegradedEvent/v3",
        "runtime": "codex",
        "adapter_version": ADAPTER_VERSION,
        "recorded_at": recorded_at,
        "hook_event": event if event in OFFICIAL_EVENTS else "unknown",
        "health": "degraded",
        "reason_category": safe_reason,
        "session_sha256": _sha(session_id),
        "workspace_sha256": _sha(payload.get("cwd")),
        "input_bytes": max(0, int(input_bytes)),
        "payload_key_count": min(len(payload), 1_000_000),
    }
    encoded = json.dumps(record, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    # Health is the completion guard. Persist it with a dedicated lock before
    # attempting the best-effort diagnostic spool, whose lock may be contended.
    marker_recorded = _write_degraded_marker(marker_path, record, recorded_at)
    if not marker_recorded:
        # A short collision is normal under concurrent hooks. Retry once with the
        # adapter's full bounded lock budget, and return the durable result so tests
        # and callers can observe whether completion health was actually retained.
        marker_recorded = _write_degraded_marker(
            marker_path,
            record,
            recorded_at,
            lock_timeout_seconds=MARKER_LOCK_RETRY_SECONDS,
        )

    lock = log_path.with_suffix(".lock")
    fd = _acquire_lock(lock)
    if fd is None:
        return marker_recorded
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        lines = _tail_lines(log_path)
        lines.append(encoded)
        while len(lines) > MAX_SPOOL_RECORDS:
            lines.pop(0)
        content = b"\n".join(lines) + (b"\n" if lines else b"")
        while lines and len(content) > MAX_SPOOL_BYTES:
            lines.pop(0)
            content = b"\n".join(lines) + (b"\n" if lines else b"")
        spool_tmp = log_path.with_name(f"{log_path.name}.{os.getpid()}.tmp")
        spool_tmp.write_bytes(content)
        os.replace(spool_tmp, log_path)

        cutoff = time.time() - RETENTION_SECONDS
        _prune_retention(log_path.parent, "????-??-??.jsonl", 14, cutoff)
        _prune_retention(marker_path.parent, "*.json", MAX_MARKERS, cutoff)
    except OSError:
        pass
    finally:
        _release_lock(fd, lock)
    return marker_recorded


class _HookPayloadError(ValueError):
    """The untrusted host envelope violates the adapter input contract."""


def _reject_hook_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _HookPayloadError("hook-payload-duplicate-key")
        value[key] = item
    return value


def _reject_hook_nonfinite_constant(_value: str) -> Any:
    raise _HookPayloadError("hook-payload-nonfinite-number")


def _validate_hook_payload_complexity(value: Any) -> None:
    """Apply additive node and depth budgets without recursive traversal."""
    nodes = 0
    pending: list[tuple[Any, int]] = [(value, 1)]
    while pending:
        current, depth = pending.pop()
        nodes += 1
        if nodes > MAX_HOOK_JSON_NODES or depth > MAX_HOOK_JSON_DEPTH:
            raise _HookPayloadError("hook-payload-complexity-limit")
        if isinstance(current, str):
            if any(0xD800 <= ord(character) <= 0xDFFF for character in current):
                raise _HookPayloadError("hook-payload-invalid-unicode-scalar")
        elif isinstance(current, float) and not math.isfinite(current):
            raise _HookPayloadError("hook-payload-nonfinite-number")
        elif isinstance(current, dict):
            pending.extend((key, depth + 1) for key in current)
            pending.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            pending.extend((item, depth + 1) for item in current)


def _parse_payload(raw: bytes) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _HookPayloadError("hook-payload-invalid") from exc
    try:
        decoded = json.loads(
            text,
            object_pairs_hook=_reject_hook_duplicate_keys,
            parse_constant=_reject_hook_nonfinite_constant,
        )
    except _HookPayloadError:
        raise
    except (ValueError, RecursionError) as exc:
        raise _HookPayloadError("hook-payload-invalid") from exc
    if not isinstance(decoded, dict):
        raise _HookPayloadError("hook-payload-object-required")
    _validate_hook_payload_complexity(decoded)
    return decoded


def _read_bounded_stdin(stream: Any, *, maximum: int = MAX_STDIN_BYTES) -> bytes:
    """Read at most one byte beyond the hook contract, then fail closed."""
    if isinstance(maximum, bool) or not isinstance(maximum, int) or not 0 <= maximum <= MAX_STDIN_BYTES:
        raise ValueError("stdin-limit-invalid")
    raw = stream.read(maximum + 1)
    if not isinstance(raw, bytes):
        raise TypeError("stdin-must-be-bytes")
    if len(raw) > maximum:
        raise ValueError("stdin-too-large")
    return raw


def _hook_timeout(event: str) -> float:
    defaults = {"SessionEnd": 2.0, "Stop": 25.0, "UserPromptSubmit": 20.0}
    raw = os.environ.get("AGENT_SUPERVISOR_HOOK_TIMEOUT")
    try:
        value = float(raw) if raw is not None else defaults.get(event, 10.0)
    except ValueError:
        value = defaults.get(event, 10.0)
    if not math.isfinite(value):
        value = defaults.get(event, 10.0)
    return min(max(value, 0.01), 120.0)


def _minimal_hook_environment() -> dict[str, str]:
    """Build a child environment from an exact, non-secret allowlist."""
    environment: dict[str, str] = {}
    for name in ("TEMP", "TMP"):
        raw = os.environ.get(name)
        if not raw or "\x00" in raw or not Path(raw).is_absolute():
            continue
        candidate = _canonical_existing(Path(raw), directory=True)
        if candidate is not None:
            environment[name] = str(candidate)
    for name in ("LANG", "LC_ALL", "LC_CTYPE"):
        raw = os.environ.get(name)
        if (
            raw
            and len(raw) <= 64
            and all(
                character.isascii()
                and (character.isalnum() or character in "_.@-")
                for character in raw
            )
        ):
            environment[name] = raw
    session_id = os.environ.get("CODEX_THREAD_ID")
    if (
        session_id
        and len(session_id) <= 256
        and all(
            character.isascii()
            and (character.isalnum() or character in "._:-")
            for character in session_id
        )
    ):
        environment["CODEX_THREAD_ID"] = session_id
    return environment


def _outer_hook_timeout(event: str) -> float:
    """Cover the entire inner deadline plus startup and stream-cleanup grace."""
    return (
        _hook_timeout(event)
        + INNER_STARTUP_GRACE_SECONDS
        + INNER_STREAM_CLEANUP_SECONDS
        + OUTER_BRIDGE_GRACE_SECONDS
    )


class _WindowsKillOnCloseJob:
    """A suspended-start Job Object boundary for one PowerShell process tree."""

    def __init__(self) -> None:
        if os.name != "nt":
            raise OSError("windows_job_unavailable")

        import ctypes
        from ctypes import wintypes

        class _BasicLimit(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class _IoCounters(ctypes.Structure):
            _fields_ = [
                ("ReadOperationCount", ctypes.c_ulonglong),
                ("WriteOperationCount", ctypes.c_ulonglong),
                ("OtherOperationCount", ctypes.c_ulonglong),
                ("ReadTransferCount", ctypes.c_ulonglong),
                ("WriteTransferCount", ctypes.c_ulonglong),
                ("OtherTransferCount", ctypes.c_ulonglong),
            ]

        class _ExtendedLimit(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", _BasicLimit),
                ("IoInfo", _IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.SetInformationJobObject.argtypes = (
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        )
        kernel32.SetInformationJobObject.restype = wintypes.BOOL
        kernel32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
        kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel32.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
        kernel32.TerminateJobObject.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel32.CloseHandle.restype = wintypes.BOOL
        ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
        ntdll.NtResumeProcess.argtypes = (wintypes.HANDLE,)
        ntdll.NtResumeProcess.restype = ctypes.c_long

        handle = kernel32.CreateJobObjectW(None, None)
        if not handle:
            raise OSError("windows_job_create_failed")
        limits = _ExtendedLimit()
        limits.BasicLimitInformation.LimitFlags = 0x00002000  # KILL_ON_JOB_CLOSE
        if not kernel32.SetInformationJobObject(
            handle,
            9,  # JobObjectExtendedLimitInformation
            ctypes.byref(limits),
            ctypes.sizeof(limits),
        ):
            kernel32.CloseHandle(handle)
            raise OSError("windows_job_configuration_failed")
        self._handle = handle
        self._kernel32 = kernel32
        self._ntdll = ntdll

    def assign_and_resume(self, process: subprocess.Popen[bytes]) -> None:
        if self._handle is None:
            raise OSError("windows_job_closed")
        process_handle = int(process._handle)  # type: ignore[attr-defined]
        if not self._kernel32.AssignProcessToJobObject(self._handle, process_handle):
            raise OSError("windows_job_assignment_failed")
        if int(self._ntdll.NtResumeProcess(process_handle)) != 0:
            raise OSError("windows_process_resume_failed")

    def terminate(self) -> None:
        if self._handle is not None:
            self._kernel32.TerminateJobObject(self._handle, 1)

    def close(self) -> None:
        if self._handle is not None:
            self._kernel32.CloseHandle(self._handle)
            self._handle = None


def _terminate_process_tree(
    process: subprocess.Popen[bytes],
    job: _WindowsKillOnCloseJob | None,
    system_directory: Path | None,
) -> None:
    """Terminate the complete child tree, then wait within a fixed cleanup budget."""
    deadline = time.monotonic() + OUTER_PROCESS_TREE_CLEANUP_SECONDS
    if job is not None:
        try:
            job.terminate()
        except Exception:
            # Continue to the direct child fallback and bounded wait even when
            # the Job API itself reports a teardown error.
            pass
        finally:
            try:
                job.close()
            except Exception:
                pass
    elif os.name == "nt" and system_directory is not None:
        taskkill = _canonical_existing(system_directory / "taskkill.exe", directory=False)
        if taskkill is not None:
            trusted_root = system_directory.parent
            cleanup_env = {
                "SYSTEMROOT": str(trusted_root),
                "WINDIR": str(trusted_root),
                "PATH": str(system_directory),
                "PATHEXT": ".COM;.EXE;.BAT;.CMD",
                "NoDefaultCurrentDirectoryInExePath": "1",
            }
            try:
                subprocess.run(
                    [str(taskkill), "/PID", str(process.pid), "/T", "/F"],
                    env=cleanup_env,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=max(0.01, deadline - time.monotonic()),
                    check=False,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            except (OSError, subprocess.TimeoutExpired):
                pass
    elif os.name != "nt":
        try:
            import signal

            os.killpg(process.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            pass

    if process.poll() is None:
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.communicate(timeout=max(0.01, deadline - time.monotonic()))
    except (OSError, subprocess.TimeoutExpired):
        try:
            process.wait(timeout=max(0.01, deadline - time.monotonic()))
        except (OSError, subprocess.TimeoutExpired):
            pass


def _run_trusted_powershell(
    arguments: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    input_bytes: bytes,
    timeout_seconds: float,
    system_directory: Path | None,
) -> tuple[int, bytes]:
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    if os.name == "nt":
        creationflags |= CREATE_SUSPENDED
    process = subprocess.Popen(
        arguments,
        cwd=cwd,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=creationflags,
        start_new_session=(os.name != "nt"),
    )
    job: _WindowsKillOnCloseJob | None = None
    if os.name == "nt":
        try:
            job = _WindowsKillOnCloseJob()
            job.assign_and_resume(process)
        except Exception:
            # The process was created suspended. Job create/configure/assign or
            # resume failure must never leave that process behind for a later
            # resume or delayed state write.
            _terminate_process_tree(process, job, system_directory)
            raise
    try:
        stdout, _stderr = process.communicate(input=input_bytes, timeout=timeout_seconds)
        return int(process.returncode), stdout
    except subprocess.TimeoutExpired:
        _terminate_process_tree(process, job, system_directory)
        raise
    except Exception:
        _terminate_process_tree(process, job, system_directory)
        raise
    finally:
        if job is not None:
            job.close()


def _forward(event: str, payload: dict[str, Any], degraded_prior: bool) -> tuple[int, bytes]:
    forwarded = dict(payload)
    # This namespace is owned by the adapter. All official host fields and
    # values remain unchanged.
    forwarded["_agent_supervisor_adapter"] = {
        "adapter_version": ADAPTER_VERSION,
        "degraded_prior": degraded_prior,
    }
    payload_bytes = json.dumps(
        forwarded,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(payload_bytes) > MAX_STDIN_BYTES:
        raise ValueError("forwarded-stdin-too-large")
    install_home = _adapter_install_home()
    env = _minimal_hook_environment()
    inner_timeout = _hook_timeout(event)
    env["AGENT_SUPERVISOR_HOOK_EVENT"] = event
    env["AGENT_SUPERVISOR_HOOK_TIMEOUT_SECONDS"] = format(inner_timeout, ".6g")
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    if not _supported_posix_platform():
        if os.name != "nt" or sys.platform != "win32":
            raise FileNotFoundError("hook_platform_rejected")
        with (
            _locked_trusted_powershell() as (powershell, _powershell_lock, system_directory),
            _locked_trusted_registry_python(install_home) as (python, _python_lock),
        ):
            trusted_windows_root = system_directory.parent
            trusted_cmd = _canonical_existing(system_directory / "cmd.exe", directory=False)
            if trusted_cmd is None:
                raise FileNotFoundError("trusted_command_processor_missing")
            env["SYSTEMROOT"] = str(trusted_windows_root)
            env["WINDIR"] = str(trusted_windows_root)
            env["PATH"] = os.pathsep.join(
                (str(system_directory), str(powershell.parent), str(python.parent))
            )
            env["PATHEXT"] = ".COM;.EXE;.BAT;.CMD"
            env["COMSPEC"] = str(trusted_cmd)
            env["AGENT_SUPERVISOR_PYTHON"] = str(python)
            env["NoDefaultCurrentDirectoryInExePath"] = "1"
            with _trusted_hook_bridge_files() as (_core_bridge, hook_bridge):
                return _run_trusted_powershell(
                    [
                        str(powershell),
                        "-NoLogo",
                        "-NoProfile",
                        "-NonInteractive",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-File",
                        str(hook_bridge[0]),
                    ],
                    cwd=install_home,
                    env=env,
                    input_bytes=payload_bytes,
                    timeout_seconds=_outer_hook_timeout(event),
                    system_directory=system_directory,
                )
    with (
        _trusted_posix_powershell(install_home) as (powershell, _powershell_lock),
        _trusted_posix_python(install_home) as (python, _python_lock),
        _trusted_posix_hook_bridge_files() as (core_bridge, hook_bridge),
    ):
        env["HOME"] = str(install_home)
        env["USERPROFILE"] = str(install_home)
        env["PATH"] = os.pathsep.join(dict.fromkeys(
            (str(powershell.parent), str(python.parent))
        ))
        env["AGENT_SUPERVISOR_PYTHON"] = str(python)
        bridge_source = _posix_inline_hook_bridge_source(
            Path(__file__).parent,
            core_bridge[1].read(),
            hook_bridge[1].read(),
        )
        return _run_trusted_powershell(
            [
                str(powershell),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                bridge_source,
            ],
            cwd=install_home,
            env=env,
            input_bytes=payload_bytes,
            timeout_seconds=_outer_hook_timeout(event),
            system_directory=None,
        )


def _response_health(stdout: bytes) -> tuple[bool, bool]:
    try:
        response = json.loads(stdout.decode("utf-8")) if stdout.strip() else {}
    except (TypeError, ValueError, UnicodeDecodeError):
        return False, False
    health = response.get("agent_supervisor") if isinstance(response, dict) else None
    if not isinstance(health, dict):
        return False, False
    core_degraded = health.get("health") == "degraded"
    # A bare truthy acknowledgement is not sufficient. The shared core must
    # explicitly attest that degraded health was durably recorded before the
    # adapter may remove its fallback marker.
    durable_ack = core_degraded and health.get("durable_ack") is True
    return core_degraded, durable_ack


def _emit_fail_open(marker_recorded: bool = True) -> None:
    output = FAIL_OPEN_OUTPUT
    if not marker_recorded:
        output = json.dumps(
            {"systemMessage": MARKER_PERSISTENCE_WARNING},
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("ascii")
    sys.stdout.buffer.write(output)
    sys.stdout.buffer.flush()


def _report_marker_result(marker_recorded: bool) -> None:
    """Expose a persistence failure without echoing payload or exception content."""
    if not marker_recorded:
        sys.stderr.write(MARKER_PERSISTENCE_WARNING + "\n")
        sys.stderr.flush()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("legacy_event", nargs="?")
    parser.add_argument("--event")
    args, _ = parser.parse_known_args(argv)

    payload: dict[str, Any] = {}
    explicit_event = args.event or args.legacy_event
    try:
        raw = _read_bounded_stdin(sys.stdin.buffer)
    except ValueError:
        event = EVENT_ALIASES.get(str(explicit_event or ""), str(explicit_event or ""))
        marker_recorded = _record_degraded(
            event, payload, "invalid_input", MAX_STDIN_BYTES + 1
        )
        _emit_fail_open(marker_recorded)
        return 0
    except (OSError, TypeError):
        event = EVENT_ALIASES.get(str(explicit_event or ""), str(explicit_event or ""))
        marker_recorded = _record_degraded(event, payload, "invalid_input", 0)
        _emit_fail_open(marker_recorded)
        return 0
    try:
        payload = _parse_payload(raw)
    except (UnicodeDecodeError, TypeError, ValueError, json.JSONDecodeError):
        event = EVENT_ALIASES.get(str(explicit_event or ""), str(explicit_event or ""))
        marker_recorded = _record_degraded(event, payload, "invalid_input", len(raw))
        _emit_fail_open(marker_recorded)
        return 0

    event = _event_name(explicit_event, payload)
    if event not in OFFICIAL_EVENTS:
        marker_recorded = _record_degraded(event, payload, "invalid_event", len(raw))
        _emit_fail_open(marker_recorded)
        return 0

    session_id = _session_id(payload)
    degraded_prior = _has_degraded_marker(session_id)
    try:
        returncode, stdout = _forward(event, payload, degraded_prior)
    except (TypeError, ValueError):
        marker_recorded = _record_degraded(event, payload, "invalid_input", len(raw))
        _emit_fail_open(marker_recorded)
        return 0
    except FileNotFoundError:
        marker_recorded = _record_degraded(event, payload, "core_missing_or_rejected", len(raw))
        _emit_fail_open(marker_recorded)
        return 0
    except subprocess.TimeoutExpired:
        marker_recorded = _record_degraded(event, payload, "core_timeout", len(raw))
        _emit_fail_open(marker_recorded)
        return 0
    except Exception:
        marker_recorded = _record_degraded(event, payload, "adapter_exception", len(raw))
        _emit_fail_open(marker_recorded)
        return 0

    if returncode not in KNOWN_CORE_CODES:
        marker_recorded = _record_degraded(event, payload, "core_unexpected_exit", len(raw))
        _emit_fail_open(marker_recorded)
        return 0

    core_degraded, durable_ack = _response_health(stdout)
    if degraded_prior and durable_ack:
        _clear_degraded_markers(session_id)
    if returncode == 64:
        # Invalid state is a fresh, fail-closed health signal even when the core
        # durably acknowledged an older degraded marker in the same response.
        _report_marker_result(_record_degraded(event, payload, "core_invalid_state", len(raw)))
    elif returncode == 4 and not (degraded_prior and durable_ack):
        _report_marker_result(_record_degraded(event, payload, "core_degraded_response", len(raw)))
    elif core_degraded and not durable_ack:
        _report_marker_result(_record_degraded(event, payload, "core_degraded_response", len(raw)))

    # The core owns the event-specific Codex output contract. Do not decode,
    # trim, append a newline, or echo stderr (which may contain user content).
    if stdout:
        sys.stdout.buffer.write(stdout)
        sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
