#!/usr/bin/env python3
"""Claude Code thin adapter for Agent Supervisor v3.

The adapter deliberately owns no policy.  It forwards the original hook envelope to
the versioned shared core under ``~/.agent-supervisor`` and keeps only a redacted,
bounded degraded spool when that core cannot run.  Hook process failures are always
fail-open to Claude Code; the persisted degraded marker prevents a later finalize from
being reported as complete.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import math
import os
import re
import stat
import struct
import subprocess
import sys
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any


ADAPTER_VERSION = "3.1.6"
POINTER_CONTRACT = "ActiveVersionPointer/v4"
IDENTITY_CONTRACT = "SupervisorReleaseIdentity/v1"
MANIFEST_CONTRACT = "SupervisorRuntimeManifest/v1"
MANIFEST_MEMBER = "SUPERVISOR-RUNTIME-MANIFEST.json"
POINTER_FIELDS = frozenset({"active", "contract", "previous"})
IDENTITY_FIELDS = frozenset(
    {
        "bundle_relpath",
        "bundle_sha256",
        "contract",
        "manifest_sha256",
        "path",
        "source_tree_sha256",
        "version",
    }
)
MANIFEST_FIELDS = frozenset({"contract", "files", "source_tree_sha256", "version"})
MANIFEST_ROW_FIELDS = frozenset({"kind", "module", "path", "sha256", "size"})
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
MAX_POINTER_BYTES = 1024 * 1024
MAX_BUNDLE_BYTES = 16 * 1024 * 1024
MAX_MEMBER_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024
MAX_MEMBERS = 512
MAX_HOOK_PAYLOAD_BYTES = 4 * 1024 * 1024
KNOWN_CORE_CODES = {0, 2, 3, 4, 64}
REGISTERED_HOOK_TIMEOUT_SECONDS = 10.0
HOOK_TIMEOUT_SAFETY_MARGIN_SECONDS = 1.0
EVENT_ALIASES = {
    "session-start": "SessionStart",
    "prompt-submit": "UserPromptSubmit",
    "pre-tool": "PreToolUse",
    "post-tool": "PostToolUse",
    "post-tool-failure": "PostToolUseFailure",
    "stop": "Stop",
    "subagent-start": "SubagentStart",
    "subagent-stop": "SubagentStop",
}
SAFE_FILE_NOT_FOUND_REASONS = frozenset(
    {"active_pointer_rejected", "core_rejected", "core_missing"}
)
FAILURE_STATUSES = frozenset(
    {"error", "failed", "failure", "denied", "rejected", "cancelled", "canceled"}
)


def _safe_file_not_found_reason(exc: FileNotFoundError) -> str:
    """Keep actionable adapter categories without persisting exception paths."""
    token = exc.args[0] if exc.args else ""
    return token if isinstance(token, str) and token in SAFE_FILE_NOT_FOUND_REASONS else "core_missing"


def _home() -> Path:
    # Path.home() does not consistently honor a synthetic USERPROFILE in every
    # Windows Python build, while Claude and the harness both define it.
    raw = os.environ.get("USERPROFILE") or os.environ.get("HOME")
    return Path(raw).expanduser() if raw else Path.home()


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
    current = Path(path.anchor)
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


def _ensure_private_directory(path: Path) -> Path:
    """Create a link-free directory chain with owner-only modes where supported."""
    target = _lexical_absolute(path)
    pending: list[Path] = []
    current = target
    while True:
        try:
            info = current.lstat()
        except FileNotFoundError:
            pending.append(current)
            parent = current.parent
            if parent == current:
                raise OSError("private_directory_parent_missing")
            current = parent
            continue
        if _is_reparse(current) or not stat.S_ISDIR(info.st_mode):
            raise OSError("private_directory_invalid")
        if _canonical_existing(current, directory=True) is None:
            raise OSError("private_directory_untrusted")
        break

    for directory in reversed(pending):
        try:
            os.mkdir(directory, 0o700)
        except FileExistsError:
            pass
        if _canonical_existing(directory, directory=True) is None:
            raise OSError("private_directory_create_failed")
        if os.name == "posix":
            os.chmod(directory, 0o700)

    if _canonical_existing(target, directory=True) is None:
        raise OSError("private_directory_invalid")
    if os.name == "posix":
        os.chmod(target, 0o700)
    return target


def _open_private_regular(path: Path, flags: int) -> int:
    """Open one regular file without following links and constrain it to mode 0600."""
    descriptor = os.open(
        path,
        flags | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise OSError("private_file_not_regular")
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
            opened = os.fstat(descriptor)
        try:
            current = path.lstat()
        except OSError:
            raise OSError("private_file_path_missing") from None
        if (
            _is_reparse(path)
            or not stat.S_ISREG(current.st_mode)
            or _file_identity(opened) != _file_identity(current)
        ):
            raise OSError("private_file_path_invalid")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _atomic_private_replace(path: Path, payload: bytes) -> None:
    """Durably replace one file from a private same-directory temporary file."""
    _ensure_private_directory(path.parent)
    temporary = path.with_name(
        "." + path.name + "." + str(os.getpid()) + "." + str(time.time_ns()) + ".tmp"
    )
    descriptor = -1
    try:
        descriptor = _open_private_regular(
            temporary,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
        )
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
            written_identity = _file_identity(os.fstat(handle.fileno()))
        current = temporary.lstat()
        if (
            _is_reparse(temporary)
            or not stat.S_ISREG(current.st_mode)
            or _file_identity(current) != written_identity
        ):
            raise OSError("private_temporary_changed")
        os.replace(temporary, path)
        try:
            directory_fd = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            pass
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def _within(candidate: Path, root: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def _trusted_core(path: Path, allowed_roots: list[Path]) -> Path | None:
    candidate = _canonical_existing(path, directory=True)
    if candidate is None:
        return None
    roots = [
        canonical
        for root in allowed_roots
        if (canonical := _canonical_existing(root, directory=True)) is not None
    ]
    if not any(_within(candidate, root) for root in roots):
        return None

    package = _canonical_existing(candidate / "supervisor_core", directory=True)
    if package is None or not _within(package, candidate):
        return None
    required = {
        package / "__init__.py",
        package / "__main__.py",
    }
    trusted_sources: set[Path] = set()
    try:
        for current_text, directory_names, file_names in os.walk(
            package, topdown=True, followlinks=False
        ):
            current = _canonical_existing(Path(current_text), directory=True)
            if current is None or not _within(current, package):
                return None
            for directory_name in directory_names:
                child = _canonical_existing(current / directory_name, directory=True)
                if child is None or not _within(child, package):
                    return None
            for file_name in file_names:
                source = _canonical_existing(current / file_name, directory=False)
                if source is None or not _within(source, package):
                    return None
                if file_name.casefold().endswith(".py"):
                    trusted_sources.add(source)
    except OSError:
        return None
    if not required.issubset(trusted_sources):
        return None
    return candidate


class _BootstrapError(ValueError):
    """A frozen pointer-v4 runtime could not be established."""


def _file_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_mode),
        int(value.st_size),
        int(value.st_mtime_ns),
        # POSIX ctime is inode change-time and catches same-size hardlink writes
        # even if an attacker restores mtime. Windows st_ctime is creation time,
        # so it is not a useful mutation signal there.
        int(value.st_ctime_ns) if os.name == "posix" else 0,
    )


def _stable_read(path: Path, maximum: int) -> bytes:
    """Return one descriptor-bound regular-file snapshot without following links."""
    absolute = _lexical_absolute(path)
    if not absolute.is_absolute() or _path_has_reparse(absolute):
        raise _BootstrapError("path-indirection")
    before = absolute.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size < 1 or before.st_size > maximum:
        raise _BootstrapError("file-size-invalid")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(absolute, flags)
    try:
        opened_before = os.fstat(descriptor)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise _BootstrapError("file-size-invalid")
        opened_after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after = absolute.lstat()
    if _path_has_reparse(absolute) or not (
        _file_identity(before)
        == _file_identity(opened_before)
        == _file_identity(opened_after)
        == _file_identity(after)
    ):
        raise _BootstrapError("file-changed-during-read")
    content = b"".join(chunks)
    if len(content) != before.st_size:
        raise _BootstrapError("file-read-truncated")
    return content


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _BootstrapError("duplicate-json-key")
        value[key] = item
    return value


def _json_object(content: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _BootstrapError(label + "-json-invalid") from exc
    if not isinstance(value, dict):
        raise _BootstrapError(label + "-object-required")
    return value


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _safe_member_path(value: Any) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise _BootstrapError("member-path-invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise _BootstrapError("member-path-invalid")
    return path.as_posix()


def _identity_paths(
    identity: Any,
    allowed_roots: list[Path],
) -> tuple[dict[str, Any], Path, Path]:
    if (
        not isinstance(identity, dict)
        or set(identity) != IDENTITY_FIELDS
        or identity.get("contract") != IDENTITY_CONTRACT
        or not isinstance(identity.get("version"), str)
        or not identity["version"]
        or identity["version"] != identity["version"].strip()
        or any(
            not isinstance(identity.get(name), str)
            or SHA256_PATTERN.fullmatch(identity[name]) is None
            for name in ("bundle_sha256", "manifest_sha256", "source_tree_sha256")
        )
    ):
        raise _BootstrapError("release-identity-invalid")
    raw_root = identity.get("path")
    if not isinstance(raw_root, str) or not raw_root or "\x00" in raw_root:
        raise _BootstrapError("release-root-invalid")
    release_root = Path(raw_root).expanduser()
    if not release_root.is_absolute() or any(part in {".", ".."} for part in release_root.parts):
        raise _BootstrapError("release-root-invalid")
    release_root = _canonical_existing(release_root, directory=True)
    trusted_roots = [
        root
        for candidate in allowed_roots
        if (root := _canonical_existing(candidate, directory=True)) is not None
    ]
    if release_root is None or not any(_within(release_root, root) for root in trusted_roots):
        raise _BootstrapError("release-root-untrusted")
    relative_bundle = _safe_member_path(identity.get("bundle_relpath"))
    bundle_path = _canonical_existing(
        release_root.joinpath(*PurePosixPath(relative_bundle).parts),
        directory=False,
    )
    if bundle_path is None or not _within(bundle_path, release_root):
        raise _BootstrapError("bundle-path-invalid")
    return identity, release_root, bundle_path


def _inspect_runtime_bundle(
    identity: dict[str, Any],
    bundle: bytes,
) -> dict[str, Any]:
    if hashlib.sha256(bundle).hexdigest() != identity["bundle_sha256"]:
        raise _BootstrapError("bundle-digest-mismatch")
    try:
        archive = zipfile.ZipFile(io.BytesIO(bundle), "r")
    except (OSError, zipfile.BadZipFile) as exc:
        raise _BootstrapError("bundle-zip-invalid") from exc
    with archive:
        infos = archive.infolist()
        if not infos or len(infos) > MAX_MEMBERS:
            raise _BootstrapError("bundle-member-count-invalid")
        names: list[str] = []
        folded: set[str] = set()
        total = 0
        for info in infos:
            name = _safe_member_path(info.filename)
            if name.casefold() in folded or info.is_dir():
                raise _BootstrapError("bundle-member-duplicate")
            folded.add(name.casefold())
            names.append(name)
            if info.flag_bits & 0x1 or info.compress_type != zipfile.ZIP_STORED:
                raise _BootstrapError("bundle-member-encoding-invalid")
            if info.file_size < 1 or info.file_size > MAX_MEMBER_BYTES:
                raise _BootstrapError("bundle-member-size-invalid")
            total += info.file_size
            if total > MAX_TOTAL_BYTES:
                raise _BootstrapError("bundle-expanded-size-invalid")
        if MANIFEST_MEMBER not in names:
            raise _BootstrapError("bundle-manifest-missing")
        manifest_bytes = archive.read(MANIFEST_MEMBER)
        manifest = _json_object(manifest_bytes, "runtime-manifest")
        if (
            set(manifest) != MANIFEST_FIELDS
            or manifest.get("contract") != MANIFEST_CONTRACT
            or manifest_bytes != _canonical_json(manifest)
            or manifest.get("version") != identity["version"]
            or manifest.get("source_tree_sha256") != identity["source_tree_sha256"]
            or hashlib.sha256(manifest_bytes).hexdigest() != identity["manifest_sha256"]
            or not isinstance(manifest.get("files"), list)
        ):
            raise _BootstrapError("runtime-manifest-invalid")
        rows: list[dict[str, Any]] = []
        row_names: list[str] = []
        modules: set[str] = set()
        for row in manifest["files"]:
            if not isinstance(row, dict) or set(row) != MANIFEST_ROW_FIELDS:
                raise _BootstrapError("runtime-manifest-row-invalid")
            name = _safe_member_path(row.get("path"))
            module = row.get("module")
            if (
                name == MANIFEST_MEMBER
                or not isinstance(row.get("kind"), str)
                or not isinstance(row.get("size"), int)
                or isinstance(row.get("size"), bool)
                or row["size"] < 1
                or not isinstance(row.get("sha256"), str)
                or SHA256_PATTERN.fullmatch(row["sha256"]) is None
                or (
                    module is not None
                    and (
                        not isinstance(module, str)
                        or not (module == "supervisor_core" or module.startswith("supervisor_core."))
                        or module in modules
                    )
                )
            ):
                raise _BootstrapError("runtime-manifest-row-invalid")
            if isinstance(module, str):
                modules.add(module)
            try:
                content = archive.read(name)
            except KeyError as exc:
                raise _BootstrapError("runtime-member-missing") from exc
            if len(content) != row["size"] or hashlib.sha256(content).hexdigest() != row["sha256"]:
                raise _BootstrapError("runtime-member-digest-mismatch")
            rows.append(row)
            row_names.append(name)
        if (
            row_names != sorted(row_names)
            or len({name.casefold() for name in row_names}) != len(row_names)
            or set(names) != {MANIFEST_MEMBER, *row_names}
            or hashlib.sha256(_canonical_json(rows)).hexdigest() != identity["source_tree_sha256"]
            or "supervisor_core" not in modules
            or "supervisor_core.cli" not in modules
        ):
            raise _BootstrapError("runtime-manifest-members-invalid")
    return manifest


def _active_pointer_location() -> tuple[Path, list[Path]]:
    default = _lexical_absolute(_home() / ".agent-supervisor")
    pointer = Path(
        os.environ.get("AGENT_SUPERVISOR_ACTIVE_POINTER", str(default / "active-version.json"))
    ).expanduser()
    if not pointer.is_absolute():
        raise _BootstrapError("active-pointer-path-invalid")
    allowed_roots = [default, default.parent / ".agent-supervisor-releases"]
    configured_release = os.environ.get("AGENT_SUPERVISOR_RELEASE_ROOT")
    if configured_release:
        release = Path(configured_release).expanduser()
        if not release.is_absolute():
            raise _BootstrapError("configured-release-root-invalid")
        allowed_roots.append(release)
    return pointer, allowed_roots


def _load_active_runtime() -> dict[str, Any]:
    """Freeze and fully verify the exact v4 pointer and runtime bundle bytes."""
    try:
        pointer_path, allowed_roots = _active_pointer_location()
        pointer_file = _canonical_existing(pointer_path, directory=False)
        if pointer_file is None:
            raise _BootstrapError("active-pointer-missing")
        pointer_bytes = _stable_read(pointer_file, MAX_POINTER_BYTES)
        pointer = _json_object(pointer_bytes, "active-pointer")
        if (
            set(pointer) != POINTER_FIELDS
            or pointer.get("contract") != POINTER_CONTRACT
            or pointer_bytes != _canonical_json(pointer)
        ):
            raise _BootstrapError("active-pointer-v4-required")
        identity, release_root, bundle_path = _identity_paths(pointer.get("active"), allowed_roots)
        bundle = _stable_read(bundle_path, MAX_BUNDLE_BYTES)
        manifest = _inspect_runtime_bundle(identity, bundle)
        previous = pointer.get("previous")
        if previous is not None:
            previous_identity, _previous_root, previous_bundle_path = _identity_paths(
                previous, allowed_roots
            )
            previous_bundle = _stable_read(previous_bundle_path, MAX_BUNDLE_BYTES)
            _inspect_runtime_bundle(previous_identity, previous_bundle)
        return {
            "bundle": bundle,
            "bundle_path": bundle_path,
            "identity": dict(identity),
            "manifest": manifest,
            "pointer": pointer_file,
            "release_root": release_root,
        }
    except (OSError, TypeError, ValueError, zipfile.BadZipFile) as exc:
        raise FileNotFoundError("active_pointer_rejected") from exc


def _read_active_record(pointer_path: Path) -> dict[str, str] | None:
    """Compatibility diagnostic backed by the same complete v4 verification."""
    try:
        configured, _allowed_roots = _active_pointer_location()
        if os.path.normcase(str(_lexical_absolute(pointer_path))) != os.path.normcase(
            str(_lexical_absolute(configured))
        ):
            return None
        frozen = _load_active_runtime()
    except (FileNotFoundError, OSError, TypeError, ValueError):
        return None
    identity = frozen["identity"]
    return {
        "version": identity["version"],
        "path": identity["path"],
        "pointer": str(frozen["pointer"]),
    }


def _read_active_target(pointer_path: Path) -> Path | None:
    try:
        configured, _allowed_roots = _active_pointer_location()
        if os.path.normcase(str(_lexical_absolute(pointer_path))) != os.path.normcase(
            str(_lexical_absolute(configured))
        ):
            return None
        return _load_active_runtime()["release_root"]
    except (FileNotFoundError, OSError, TypeError, ValueError):
        return None


def _resolve_active_pointer_selection() -> tuple[Path, dict[str, str]]:
    frozen = _load_active_runtime()
    identity = frozen["identity"]
    return frozen["release_root"], {
        "source": "active-pointer-v4-bundle",
        "declared_path": identity["path"],
        "declared_version": identity["version"],
        "pointer": str(frozen["pointer"]),
        "bundle_path": str(frozen["bundle_path"]),
        "bundle_sha256": identity["bundle_sha256"],
        "manifest_sha256": identity["manifest_sha256"],
        "source_tree_sha256": identity["source_tree_sha256"],
    }


def _resolve_core_selection(
    *, require_active_pointer: bool = False
) -> tuple[Path, dict[str, str]]:
    del require_active_pointer
    return _resolve_active_pointer_selection()


def _core_root(*, require_active_pointer: bool = False) -> Path:
    return _resolve_core_selection(require_active_pointer=require_active_pointer)[0]


def _installation_home() -> Path:
    """Return the real profile containing the installed .claude tree."""
    try:
        for parent in Path(__file__).resolve().parents:
            if parent.name.casefold() == ".claude":
                return parent.parent
    except (OSError, RuntimeError):
        pass
    return _home()


def _hook_timeout() -> float:
    raw = os.environ.get("AGENT_SUPERVISOR_HOOK_TIMEOUT", "8")
    try:
        value = float(raw)
    except (TypeError, ValueError):
        value = 8.0
    if not math.isfinite(value):
        value = 8.0
    internal_ceiling = REGISTERED_HOOK_TIMEOUT_SECONDS - HOOK_TIMEOUT_SAFETY_MARGIN_SECONDS
    return max(0.1, min(value, internal_ceiling))


def _sha(value: Any) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8", "replace")).hexdigest()


def _event_name(explicit: str | None, payload: dict[str, Any]) -> str:
    raw = explicit or payload.get("hook_event_name") or payload.get("hookEventName") or ""
    return EVENT_ALIASES.get(str(raw), str(raw))


def _session_id(payload: dict[str, Any]) -> str:
    return str(
        payload.get("session_id")
        or payload.get("sessionId")
        or os.environ.get("CLAUDE_SESSION_ID")
        or "unknown"
    )


def _fallback_paths(session_id: str) -> tuple[Path, Path]:
    root = _home() / ".agent-supervisor" / "fallback" / "claude"
    return root / (datetime.now(timezone.utc).strftime("%Y-%m-%d") + ".jsonl"), root / "markers" / (_sha(session_id) + ".json")


def _prepare_fallback_storage() -> None:
    root = _home() / ".agent-supervisor"
    for directory in (root, root / "fallback", root / "fallback" / "claude", root / "fallback" / "claude" / "markers"):
        _ensure_private_directory(directory)


def _has_degraded_marker(session_id: str) -> bool:
    marker = _fallback_paths(session_id)[1]
    try:
        info = marker.lstat()
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and not _is_reparse(marker)


def _degraded_session_lock(session_id: str) -> Path:
    """Return the single lock that serializes marker writes and clears."""
    return _fallback_paths(session_id)[1].with_suffix(".lock")


def _clear_degraded_marker(session_id: str) -> None:
    """Clear only the retry marker after the core has durably received it."""
    lock = _degraded_session_lock(session_id)
    fd = _acquire_lock(lock)
    if fd is None:
        return
    try:
        _fallback_paths(session_id)[1].unlink(missing_ok=True)
    except OSError:
        # Failure to clear is itself safe: the next core call remains degraded.
        pass
    finally:
        _release_lock(fd, lock)


def _result_status(event: str, payload: dict[str, Any]) -> str:
    if event == "PreToolUse":
        return "attempt"
    if event == "PostToolUseFailure":
        return "failed"
    if event == "PostToolUse":
        result = payload.get("tool_result", payload.get("tool_response"))
        if isinstance(result, dict):
            if result.get("is_error") is True or result.get("success") is False:
                return "failed"
            if str(result.get("status") or "").strip().casefold() in FAILURE_STATUSES:
                return "failed"
        if str(payload.get("status") or "").strip().casefold() in FAILURE_STATUSES:
            return "failed"
        return "success"
    return "observed"


def _acquire_lock(lock: Path, timeout_seconds: float = 1.5) -> int | None:
    deadline = time.monotonic() + timeout_seconds
    try:
        _ensure_private_directory(lock.parent)
    except OSError:
        return None
    while time.monotonic() < deadline:
        try:
            return _open_private_regular(
                lock,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            )
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


def _atomic_create_marker_if_absent(marker_path: Path, marker_record: dict[str, Any]) -> bool:
    """Best-effort no-clobber marker creation when the session lock is unavailable.

    Write and fsync a unique same-directory file first, then hard-link it into the
    final name.  The link is an atomic create-if-absent operation: an existing marker
    is never replaced or opened, and readers never observe a partially written JSON
    document.  If the filesystem cannot provide that guarantee, fail open instead of
    falling back to an unsafe unlocked overwrite.
    """
    tmp: Path | None = None
    try:
        _ensure_private_directory(marker_path.parent)
        try:
            existing = marker_path.lstat()
        except FileNotFoundError:
            existing = None
        if existing is not None:
            return stat.S_ISREG(existing.st_mode) and not _is_reparse(marker_path)
        tmp = marker_path.with_name(
            marker_path.name
            + ".fallback-"
            + str(os.getpid())
            + "-"
            + str(time.time_ns())
            + ".tmp"
        )
        payload = json.dumps(
            marker_record,
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("utf-8")
        fd = _open_private_regular(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(str(tmp), str(marker_path))
            return True
        except FileExistsError:
            # Another writer won the race. Preserve its complete marker verbatim.
            try:
                existing = marker_path.lstat()
            except OSError:
                return False
            return stat.S_ISREG(existing.st_mode) and not _is_reparse(marker_path)
        except OSError:
            return False
    except (OSError, TypeError, ValueError):
        return False
    finally:
        if tmp is not None:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass


def _retention_snapshots(directory: Path, pattern: str):
    """Capture stable direct-file identities without letting a stat race abort pruning."""
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


def _record_degraded(event: str, payload: dict[str, Any], reason: str) -> None:
    """Persist metadata only: never prompt text, command arguments, or tool output."""
    session_id = _session_id(payload)
    log_path, marker_path = _fallback_paths(session_id)
    try:
        _prepare_fallback_storage()
    except OSError:
        return
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "adapter_version": ADAPTER_VERSION,
        "event": event or "unknown",
        "status": "degraded",
        "reason_category": reason,
        "session_sha256": _sha(session_id),
        "workspace_sha256": _sha(payload.get("cwd")),
        "invocation_id": str(payload.get("tool_use_id") or payload.get("toolUseId") or ""),
        "tool_name": str(payload.get("tool_name") or payload.get("toolName") or "")[:120],
        "result_status": _result_status(event, payload),
        "payload_field_count": len(payload),
        "known_fields_present": [
            key
            for key in (
                "session_id",
                "sessionId",
                "cwd",
                "tool_use_id",
                "toolUseId",
                "tool_name",
                "toolName",
                "tool_result",
                "tool_response",
            )
            if key in payload
        ],
    }
    marker_record = {
        "session_sha256": record["session_sha256"],
        "degraded": True,
        "first_seen": record["ts"],
        "reason_category": reason,
    }
    session_lock = _degraded_session_lock(session_id)
    session_fd = _acquire_lock(session_lock)
    if session_fd is None:
        _atomic_create_marker_if_absent(marker_path, marker_record)
        return
    try:
        _atomic_private_replace(
            marker_path,
            json.dumps(
                marker_record, ensure_ascii=True, separators=(",", ":")
            ).encode("utf-8"),
        )

        # Daily logs are shared by sessions, so keep their append lock separate
        # while holding the session lock that protects the marker transition.
        log_lock = log_path.with_suffix(".lock")
        log_fd = _acquire_lock(log_lock)
        if log_fd is not None:
            try:
                _ensure_private_directory(log_path.parent)
                descriptor = _open_private_regular(
                    log_path,
                    os.O_CREAT | os.O_APPEND | os.O_WRONLY,
                )
                with os.fdopen(descriptor, "a", encoding="utf-8", newline="\n") as handle:
                    opened_identity = _file_identity(os.fstat(handle.fileno()))
                    handle.write(
                        json.dumps(record, ensure_ascii=True, separators=(",", ":"))
                        + "\n"
                    )
                    handle.flush()
                    os.fsync(handle.fileno())
                    current = log_path.lstat()
                    if (
                        _is_reparse(log_path)
                        or not stat.S_ISREG(current.st_mode)
                        or _file_identity(current) != _file_identity(os.fstat(handle.fileno()))
                        or _file_identity(current)[:2] != opened_identity[:2]
                    ):
                        raise OSError("degraded_log_changed")
            finally:
                _release_lock(log_fd, log_lock)

        # Bounded fallback retention.  The shared core owns normal log retention.
        cutoff = time.time() - 14 * 86400
        _prune_retention(log_path.parent, "????-??-??.jsonl", 14, cutoff)
        _prune_retention(marker_path.parent, "*.json", 200, cutoff)
    except OSError:
        # The hook contract is fail-open; an unwritable degraded spool must not
        # turn a core failure into a host-level hook crash.
        return
    finally:
        _release_lock(session_fd, session_lock)


def _payload(raw: bytes) -> dict[str, Any]:
    try:
        decoded = json.loads(raw.decode("utf-8", "replace")) if raw.strip() else {}
    except (TypeError, ValueError):
        return {}
    return decoded if isinstance(decoded, dict) else {}


FROZEN_RUNTIME_RUNNER = r'''
import hashlib
import importlib.abc
import importlib.util
import io
import json
import re
import struct
import sys
import types
import zipfile
from pathlib import PurePosixPath

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

IDENTITY_FIELDS = {
    "bundle_relpath", "bundle_sha256", "contract", "manifest_sha256",
    "path", "source_tree_sha256", "version",
}
ROW_FIELDS = {"kind", "module", "path", "sha256", "size"}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MANIFEST_NAME = "SUPERVISOR-RUNTIME-MANIFEST.json"


def reject_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate-json-key")
        value[key] = item
    return value


def canonical(value):
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def safe_path(value):
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ValueError("invalid-member-path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("invalid-member-path")
    return path.as_posix()


def exact(stream, size):
    chunks = []
    remaining = size
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            raise ValueError("frame-truncated")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def load_frame():
    stream = sys.stdin.buffer
    header = exact(stream, 12)
    identity_size, bundle_size, payload_size = struct.unpack(">III", header)
    if not (1 <= identity_size <= 65536 and 1 <= bundle_size <= 16 * 1024 * 1024):
        raise ValueError("frame-size-invalid")
    if payload_size > 4 * 1024 * 1024:
        raise ValueError("payload-size-invalid")
    identity_bytes = exact(stream, identity_size)
    bundle = exact(stream, bundle_size)
    payload = exact(stream, payload_size)
    if stream.read(1):
        raise ValueError("frame-trailing-data")
    identity = json.loads(identity_bytes.decode("utf-8"), object_pairs_hook=reject_duplicates)
    if (
        not isinstance(identity, dict)
        or set(identity) != IDENTITY_FIELDS
        or identity.get("contract") != "SupervisorReleaseIdentity/v1"
        or identity_bytes != canonical(identity)
        or not isinstance(identity.get("version"), str)
        or not identity["version"]
        or identity["version"] != identity["version"].strip()
        or any(
            not isinstance(identity.get(name), str) or not SHA256.fullmatch(identity[name])
            for name in ("bundle_sha256", "manifest_sha256", "source_tree_sha256")
        )
        or hashlib.sha256(bundle).hexdigest() != identity["bundle_sha256"]
    ):
        raise ValueError("release-identity-invalid")
    return identity, bundle, payload


def inspect_bundle(identity, bundle):
    with zipfile.ZipFile(io.BytesIO(bundle), "r") as archive:
        infos = archive.infolist()
        if not infos or len(infos) > 512:
            raise ValueError("member-count-invalid")
        names = []
        folded = set()
        total = 0
        for info in infos:
            name = safe_path(info.filename)
            if name.casefold() in folded or info.is_dir():
                raise ValueError("member-duplicate")
            folded.add(name.casefold())
            names.append(name)
            if info.flag_bits & 1 or info.compress_type != zipfile.ZIP_STORED:
                raise ValueError("member-encoding-invalid")
            if info.file_size < 1 or info.file_size > 4 * 1024 * 1024:
                raise ValueError("member-size-invalid")
            total += info.file_size
            if total > 16 * 1024 * 1024:
                raise ValueError("expanded-size-invalid")
        if MANIFEST_NAME not in names:
            raise ValueError("manifest-missing")
        manifest_bytes = archive.read(MANIFEST_NAME)
        manifest = json.loads(
            manifest_bytes.decode("utf-8"), object_pairs_hook=reject_duplicates
        )
        if (
            not isinstance(manifest, dict)
            or set(manifest) != {"contract", "files", "source_tree_sha256", "version"}
            or manifest.get("contract") != "SupervisorRuntimeManifest/v1"
            or manifest_bytes != canonical(manifest)
            or manifest.get("version") != identity["version"]
            or manifest.get("source_tree_sha256") != identity["source_tree_sha256"]
            or hashlib.sha256(manifest_bytes).hexdigest() != identity["manifest_sha256"]
            or not isinstance(manifest.get("files"), list)
        ):
            raise ValueError("manifest-invalid")
        resources = {}
        module_rows = {}
        rows = []
        row_names = []
        for row in manifest["files"]:
            if not isinstance(row, dict) or set(row) != ROW_FIELDS:
                raise ValueError("manifest-row-invalid")
            name = safe_path(row.get("path"))
            module = row.get("module")
            if (
                name == MANIFEST_NAME
                or not isinstance(row.get("kind"), str)
                or not isinstance(row.get("size"), int)
                or isinstance(row.get("size"), bool)
                or row["size"] < 1
                or not isinstance(row.get("sha256"), str)
                or not SHA256.fullmatch(row["sha256"])
                or (
                    module is not None
                    and (
                        not isinstance(module, str)
                        or not (module == "supervisor_core" or module.startswith("supervisor_core."))
                        or module in module_rows
                    )
                )
            ):
                raise ValueError("manifest-row-invalid")
            content = archive.read(name)
            if len(content) != row["size"] or hashlib.sha256(content).hexdigest() != row["sha256"]:
                raise ValueError("member-digest-invalid")
            resources[name] = content
            if isinstance(module, str):
                module_rows[module] = (name, name.endswith("/__init__.py"))
            rows.append(row)
            row_names.append(name)
        if (
            row_names != sorted(row_names)
            or len({name.casefold() for name in row_names}) != len(row_names)
            or set(names) != {MANIFEST_NAME, *row_names}
            or hashlib.sha256(canonical(rows)).hexdigest() != identity["source_tree_sha256"]
            or "supervisor_core" not in module_rows
            or "supervisor_core.cli" not in module_rows
        ):
            raise ValueError("manifest-members-invalid")
    return manifest, resources, module_rows


def install(identity, manifest, resources, module_rows):
    class MemoryLoader(importlib.abc.Loader):
        def __init__(self, name):
            self.name = name

        def create_module(self, spec):
            return None

        def exec_module(self, module):
            path, is_package = module_rows[self.name]
            logical = str(identity["path"]).rstrip("\\/") + "/" + path
            module.__file__ = logical
            module.__loader__ = self
            module.__cached__ = None
            if is_package:
                module.__path__ = [logical.rsplit("/", 1)[0]]
            exec(compile(resources[path], logical, "exec"), module.__dict__, module.__dict__)

        def get_source(self, fullname):
            return resources[module_rows[fullname][0]].decode("utf-8")

        def get_data(self, path):
            normalized = path.replace("\\", "/")
            prefix = str(identity["path"]).replace("\\", "/").rstrip("/") + "/"
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix):]
            value = resources.get(safe_path(normalized))
            if not isinstance(value, bytes):
                raise OSError("unmanifested-runtime-resource")
            return value

    class MemoryFinder(importlib.abc.MetaPathFinder):
        def find_spec(self, fullname, path=None, target=None):
            if fullname == "supervisor_core" or fullname.startswith("supervisor_core."):
                if fullname not in module_rows:
                    raise ModuleNotFoundError("unmanifested-runtime-module: " + fullname)
                return importlib.util.spec_from_loader(
                    fullname,
                    MemoryLoader(fullname),
                    is_package=module_rows[fullname][1],
                )
            return None

    for name in tuple(sys.modules):
        if name == "supervisor_core" or name.startswith("supervisor_core."):
            sys.modules.pop(name, None)
    finder = MemoryFinder()
    runtime = types.ModuleType("_agent_supervisor_bound_runtime")
    runtime.contract = "SupervisorBoundRuntime/v1"
    runtime.core_root = identity["path"]
    runtime.identity = dict(identity)
    runtime.manifest = dict(manifest)
    runtime.resources = dict(resources)
    runtime.finder = finder
    sys.modules[runtime.__name__] = runtime
    sys.meta_path.insert(0, finder)


def run():
    identity, bundle, payload = load_frame()
    manifest, resources, module_rows = inspect_bundle(identity, bundle)
    install(identity, manifest, resources, module_rows)
    event, state_root = sys.argv[1], sys.argv[2]
    sys.argv = [
        "agent-supervisor", "hook", "--runtime", "claude", "--event", event,
        "--state-root", state_root,
    ]
    sys.stdin = io.TextIOWrapper(io.BytesIO(payload), encoding="utf-8")
    from supervisor_core.cli import main
    return int(main())


try:
    raise SystemExit(run())
except SystemExit:
    raise
except BaseException:
    raise SystemExit(64)
'''


def _run_frozen_runtime(
    frozen: dict[str, Any],
    event: str,
    forwarded: dict[str, Any],
) -> tuple[int, bytes]:
    payload_bytes = json.dumps(
        forwarded,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(payload_bytes) > MAX_HOOK_PAYLOAD_BYTES:
        raise ValueError("hook_payload_too_large")
    identity_bytes = _canonical_json(frozen["identity"])
    bundle = frozen["bundle"]
    frame = (
        struct.pack(">III", len(identity_bytes), len(bundle), len(payload_bytes))
        + identity_bytes
        + bundle
        + payload_bytes
    )
    env = dict(os.environ)
    for name in tuple(env):
        if name.casefold() in {"pythonhome", "pythoninspect", "pythonpath", "pythonstartup"}:
            env.pop(name, None)
    env["AGENT_SUPERVISOR_INSTALL_HOME"] = str(_installation_home())
    state_root = _home() / ".agent-supervisor" / "state"
    proc = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-c",
            FROZEN_RUNTIME_RUNNER,
            event,
            str(state_root),
        ],
        input=frame,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        cwd=str(_installation_home()),
        timeout=_hook_timeout(),
        check=False,
    )
    return proc.returncode, proc.stdout


def _forward(event: str, payload: dict[str, Any]) -> tuple[int, bytes]:
    frozen = _load_active_runtime()
    forwarded = dict(payload)
    forwarded["hook_event_name"] = event
    forwarded.setdefault("session_id", _session_id(payload))
    forwarded["_agent_supervisor_adapter"] = {
        "adapter_version": ADAPTER_VERSION,
        "degraded_prior": _has_degraded_marker(_session_id(payload)),
    }
    return _run_frozen_runtime(frozen, event, forwarded)


def _core_reported_degraded(stdout: bytes) -> bool:
    if not stdout.strip():
        return False
    try:
        response = json.loads(stdout.decode("utf-8", "replace"))
    except (TypeError, ValueError):
        return False
    return (
        isinstance(response, dict)
        and isinstance(response.get("agent_supervisor"), dict)
        and response["agent_supervisor"].get("health") == "degraded"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("legacy_event", nargs="?")
    parser.add_argument("--event")
    args, _ = parser.parse_known_args(argv)

    try:
        raw = sys.stdin.buffer.read()
    except Exception:
        # The input stream itself can fail before any payload exists. Keep the
        # category fixed and path-free; never echo the exception or partial bytes.
        payload: dict[str, Any] = {}
        event = _event_name(args.event or args.legacy_event, payload) or "unknown"
        _record_degraded(event, payload, "stdin_read_failed")
        return 0
    payload = _payload(raw)
    event = _event_name(args.event or args.legacy_event, payload)
    if not event:
        _record_degraded("unknown", payload, "invalid_event")
        return 0

    try:
        returncode, stdout = _forward(event, payload)
        if returncode not in KNOWN_CORE_CODES:
            _record_degraded(event, payload, "core_unexpected_exit")
            return 0
        if returncode == 64:
            _record_degraded(event, payload, "core_invalid_state")
        elif returncode == 4 or _core_reported_degraded(stdout):
            _record_degraded(event, payload, "core_degraded_response")
        else:
            _clear_degraded_marker(_session_id(payload))
        # The core emits the event-specific Claude hook contract.  Preserve it
        # byte-for-byte; never echo stderr because it may contain user content.
        if stdout:
            sys.stdout.buffer.write(stdout)
            sys.stdout.buffer.flush()
        return 0
    except FileNotFoundError as exc:
        _record_degraded(event, payload, _safe_file_not_found_reason(exc))
    except subprocess.TimeoutExpired:
        _record_degraded(event, payload, "core_timeout")
    except Exception:
        _record_degraded(event, payload, "adapter_exception")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
