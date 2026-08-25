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
import stat
import sys
import tempfile
from typing import Any
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


class InstallError(ValueError):
    pass


def _is_link_or_reparse(path: Path) -> bool:
    details = path.lstat()
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(details, "st_file_attributes", 0)
    return stat.S_ISLNK(details.st_mode) or bool(reparse_flag and attributes & reparse_flag)


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


def _stable_bytes(path: Path, *, maximum: int, label: str) -> bytes:
    candidate = _lexical_absolute(path)
    _reject_existing_indirection(candidate, label=label)
    try:
        before = candidate.stat(follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or before.st_size < 1 or before.st_size > maximum:
            raise InstallError(f"{label} size is invalid")
        with candidate.open("rb") as handle:
            content = handle.read(maximum + 1)
        after = candidate.stat(follow_symlinks=False)
    except InstallError:
        raise
    except OSError as exc:
        raise InstallError(f"{label} is unreadable") from exc
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_after or len(content) != before.st_size:
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


def _atomic_write(path: Path, content: bytes) -> None:
    _private_directory(path.parent)
    _reject_existing_indirection(path.parent, label="output parent")
    if path.exists() or path.is_symlink():
        _reject_existing_indirection(path, label="output path")
        if not path.is_file():
            raise InstallError("output path is not a regular file")
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


def _adapter_files(source_root: Path) -> list[tuple[Path, Path]]:
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
    result: list[tuple[Path, Path]] = []
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
            result.append((source, destination_base / relative))
            if len(result) > _MAX_ADAPTER_FILES or total > _MAX_ADAPTER_TOTAL_BYTES:
                raise InstallError("adapter source exceeds installation budget")
    if not result:
        raise InstallError("adapter source is empty")
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
    adapters = _adapter_files(source) if install_adapters else []
    launcher = _stable_bytes(
        source / "bin" / "agent-supervisor.py",
        maximum=_MAX_ADAPTER_FILE_BYTES,
        label="stage-zero launcher",
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
    inspect_runtime_bundle(installed_bundle, expected_identity=identity)

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

    for source_path, relative_target in adapters:
        content = _stable_bytes(
            source_path,
            maximum=_MAX_ADAPTER_FILE_BYTES,
            label="adapter source file",
        )
        target = home / relative_target
        if _backup_if_changed(
            target,
            content,
            install_home=home,
            backup_root=backup_root,
        ):
            _atomic_write(target, content)

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
    args = parser.parse_args(argv)
    try:
        result = install_release(
            source_root=args.source,
            install_home=args.install_home,
            apply=args.apply,
            install_adapters=not args.core_only,
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
