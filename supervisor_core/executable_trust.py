from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any


REGISTRY_CONTRACT = "TrustedExecutableRegistry/v1"
_ENTRY_FIELDS = {"kind", "path", "sha256"}
_ENTRY_OPTIONAL_FIELDS = {"allowed_argv_sha256"}
_ROOT_FIELDS = {"contract", "entries", "generated_at"}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024
_HASH_CHUNK_BYTES = 1024 * 1024
_MAX_COMMAND_ARGUMENTS = 256
_MAX_COMMAND_ARGUMENT_BYTES = 16 * 1024
_MAX_APPROVED_COMMANDS = 256


class ExecutableTrustError(ValueError):
    """The machine-local executable trust registry is absent or invalid."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ExecutableTrustError("duplicate-registry-key")
        result[key] = value
    return result


def _install_home() -> Path:
    configured = os.environ.get("AGENT_SUPERVISOR_INSTALL_HOME")
    candidate = Path(configured) if configured else Path.home()
    if not candidate.is_absolute():
        raise ExecutableTrustError("install-home-not-absolute")
    return Path(os.path.abspath(os.fspath(candidate)))


def trusted_executable_registry_path() -> Path:
    return _install_home() / ".agent-supervisor" / "trusted-executables.json"


def _is_link_or_reparse(path: Path) -> bool:
    details = path.lstat()
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(details, "st_file_attributes", 0)
    return stat.S_ISLNK(details.st_mode) or bool(reparse_flag and attributes & reparse_flag)


def _stable_bytes(path: Path, maximum: int = 1024 * 1024) -> bytes:
    lexical = Path(os.path.abspath(os.fspath(path)))
    current = Path(lexical.anchor)
    for part in lexical.parts[1:]:
        current /= part
        try:
            if _is_link_or_reparse(current):
                raise ExecutableTrustError("registry-path-indirection")
        except OSError as exc:
            raise ExecutableTrustError("registry-path-unavailable") from exc
    try:
        resolved = lexical.resolve(strict=True)
        if os.path.normcase(str(resolved)) != os.path.normcase(str(lexical)):
            raise ExecutableTrustError("registry-path-alias")
        before = resolved.stat(follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or before.st_size < 2 or before.st_size > maximum:
            raise ExecutableTrustError("registry-size-invalid")
        with resolved.open("rb") as handle:
            content = handle.read(maximum + 1)
        after = resolved.stat(follow_symlinks=False)
    except OSError as exc:
        raise ExecutableTrustError("registry-read-failed") from exc
    before_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if before_identity != after_identity or len(content) != before.st_size:
        raise ExecutableTrustError("registry-changed-during-read")
    return content


def _stable_local_executable(path: str, expected_sha256: str) -> tuple[str, str]:
    candidate = Path(path)
    if not candidate.is_absolute():
        raise ExecutableTrustError("trusted-executable-path-not-absolute")
    lexical = Path(os.path.abspath(os.fspath(candidate)))
    current = Path(lexical.anchor)
    for part in lexical.parts[1:]:
        current /= part
        try:
            if _is_link_or_reparse(current):
                raise ExecutableTrustError("trusted-executable-path-indirection")
        except OSError as exc:
            raise ExecutableTrustError("trusted-executable-unavailable") from exc
    try:
        resolved = lexical.resolve(strict=True)
        if os.path.normcase(str(resolved)) != os.path.normcase(str(lexical)):
            raise ExecutableTrustError("trusted-executable-path-alias")
        before = resolved.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size < 2
            or before.st_size > _MAX_EXECUTABLE_BYTES
        ):
            raise ExecutableTrustError("trusted-executable-size-invalid")
        digest = hashlib.sha256()
        observed_size = 0
        with resolved.open("rb") as handle:
            while True:
                chunk = handle.read(_HASH_CHUNK_BYTES)
                if not chunk:
                    break
                observed_size += len(chunk)
                if observed_size > _MAX_EXECUTABLE_BYTES:
                    raise ExecutableTrustError("trusted-executable-size-invalid")
                digest.update(chunk)
        after = resolved.stat(follow_symlinks=False)
    except ExecutableTrustError:
        raise
    except OSError as exc:
        raise ExecutableTrustError("trusted-executable-read-failed") from exc
    before_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if before_identity != after_identity or observed_size != before.st_size:
        raise ExecutableTrustError("trusted-executable-changed-during-read")
    observed = digest.hexdigest()
    if observed != expected_sha256:
        raise ExecutableTrustError("trusted-executable-digest-mismatch")
    return str(lexical), observed


def load_trusted_executable_registry(path: Path | None = None) -> dict[str, Any]:
    registry_path = path or trusted_executable_registry_path()
    content = _stable_bytes(registry_path)
    try:
        value = json.loads(content.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ExecutableTrustError("registry-json-invalid") from exc
    if not isinstance(value, dict) or set(value) != _ROOT_FIELDS:
        raise ExecutableTrustError("registry-contract-shape-invalid")
    if value.get("contract") != REGISTRY_CONTRACT or not isinstance(value.get("generated_at"), str):
        raise ExecutableTrustError("registry-contract-invalid")
    entries = value.get("entries")
    if not isinstance(entries, dict) or not entries:
        raise ExecutableTrustError("registry-entries-empty")
    normalized: dict[str, dict[str, str]] = {}
    for raw_name, raw_entry in entries.items():
        name = str(raw_name).casefold()
        if name != raw_name or not _NAME.fullmatch(name):
            raise ExecutableTrustError("registry-entry-name-invalid")
        if (
            not isinstance(raw_entry, dict)
            or not _ENTRY_FIELDS <= set(raw_entry)
            or set(raw_entry) - _ENTRY_FIELDS - _ENTRY_OPTIONAL_FIELDS
        ):
            raise ExecutableTrustError("registry-entry-shape-invalid")
        kind = raw_entry.get("kind")
        raw_path = raw_entry.get("path")
        digest = raw_entry.get("sha256")
        if kind not in {"local", "wsl"} or not isinstance(raw_path, str) or not raw_path:
            raise ExecutableTrustError("registry-entry-value-invalid")
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise ExecutableTrustError("registry-entry-digest-invalid")
        raw_approvals = raw_entry.get("allowed_argv_sha256", [])
        if (
            not isinstance(raw_approvals, list)
            or len(raw_approvals) > _MAX_APPROVED_COMMANDS
            or any(not isinstance(item, str) or not _SHA256.fullmatch(item) for item in raw_approvals)
            or len(set(raw_approvals)) != len(raw_approvals)
        ):
            raise ExecutableTrustError("registry-entry-argv-approvals-invalid")
        approvals = sorted(raw_approvals)
        if kind == "local":
            canonical_path, observed = _stable_local_executable(raw_path, digest)
            normalized[name] = {
                "kind": kind,
                "path": canonical_path,
                "sha256": observed,
                "allowed_argv_sha256": approvals,
            }
        else:
            if not raw_path.startswith("/") or "\\" in raw_path or ".." in Path(raw_path).parts:
                raise ExecutableTrustError("registry-wsl-path-invalid")
            normalized[name] = {
                "kind": kind,
                "path": raw_path,
                "sha256": digest,
                "allowed_argv_sha256": approvals,
            }
    return {
        "contract": REGISTRY_CONTRACT,
        "entries": normalized,
        "generated_at": value["generated_at"],
        "registry_path": str(Path(registry_path).resolve(strict=True)),
        "registry_sha256": hashlib.sha256(content).hexdigest(),
    }


def registry_public_record(registry: dict[str, Any]) -> dict[str, Any]:
    return {
        "contract": registry.get("contract"),
        "entries": registry.get("entries"),
        "generated_at": registry.get("generated_at"),
        "registry_path": registry.get("registry_path"),
        "registry_sha256": registry.get("registry_sha256"),
    }


def verify_registry_record(record: Any) -> dict[str, Any]:
    current = load_trusted_executable_registry()
    if not isinstance(record, dict) or registry_public_record(current) != record:
        raise ExecutableTrustError("trusted-executable-registry-drift")
    return current


def resolve_trusted_executable(
    token: str,
    registry: dict[str, Any],
    *,
    cwd: str | None = None,
) -> tuple[str, str]:
    value = str(token or "").strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        value = value[1:-1]
    value = os.path.expandvars(os.path.expanduser(value))
    entries = registry.get("entries") if isinstance(registry, dict) else None
    if not isinstance(entries, dict):
        raise ExecutableTrustError("trusted-executable-registry-invalid")
    explicit = os.path.isabs(value) or bool(os.path.dirname(value))
    if os.name == "nt" and re.match(r"^[A-Za-z]:", value):
        explicit = True
    if explicit:
        candidate = Path(value)
        if not candidate.is_absolute():
            if not cwd:
                raise ExecutableTrustError("relative-executable-without-cwd")
            candidate = Path(cwd) / candidate
        expected_path = os.path.normcase(str(Path(os.path.abspath(os.fspath(candidate)))))
        matches = [
            entry for entry in entries.values()
            if isinstance(entry, dict)
            and entry.get("kind") == "local"
            and os.path.normcase(str(entry.get("path") or "")) == expected_path
        ]
        if len(matches) != 1:
            raise ExecutableTrustError("explicit-executable-not-registered")
        entry = matches[0]
    else:
        key = value.casefold()
        entry = entries.get(key)
        if not isinstance(entry, dict) or entry.get("kind") != "local":
            raise ExecutableTrustError("executable-alias-not-registered")
    return _stable_local_executable(str(entry["path"]), str(entry["sha256"]))


def trusted_command_approval_sha256(command: list[str]) -> str:
    """Return the machine-policy digest for one exact canonical argv vector."""
    if (
        not isinstance(command, list)
        or not command
        or len(command) > _MAX_COMMAND_ARGUMENTS
        or any(
            not isinstance(item, str)
            or not item
            or "\x00" in item
            or len(item.encode("utf-8")) > _MAX_COMMAND_ARGUMENT_BYTES
            for item in command
        )
    ):
        raise ExecutableTrustError("trusted-command-argv-invalid")
    encoded = json.dumps(
        command,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def authorize_trusted_command(
    command: list[str],
    registry: dict[str, Any],
    *,
    cwd: str | None = None,
) -> tuple[list[str], str, str]:
    """Resolve argv[0] and require machine-owned approval of every argument."""
    if not isinstance(command, list) or not command:
        raise ExecutableTrustError("trusted-command-argv-invalid")
    resolved, executable_sha256 = resolve_trusted_executable(
        str(command[0]),
        registry,
        cwd=cwd,
    )
    canonical = [resolved, *[str(item) for item in command[1:]]]
    approval = trusted_command_approval_sha256(canonical)
    entries = registry.get("entries") if isinstance(registry, dict) else None
    matching = [
        entry
        for entry in entries.values()
        if isinstance(entry, dict)
        and entry.get("kind") == "local"
        and os.path.normcase(str(entry.get("path") or ""))
        == os.path.normcase(resolved)
    ] if isinstance(entries, dict) else []
    if len(matching) != 1:
        raise ExecutableTrustError("trusted-command-entry-ambiguous")
    approvals = matching[0].get("allowed_argv_sha256", [])
    # Executing a trusted binary without arguments does not let repository
    # metadata select an interpreter grammar or a workspace script. Any
    # argument-bearing command requires an exact machine-owned digest.
    if len(canonical) > 1 and approval not in approvals:
        raise ExecutableTrustError("trusted-command-argv-not-approved")
    return canonical, resolved, executable_sha256


def trusted_path(registry: dict[str, Any]) -> str:
    entries = registry.get("entries") if isinstance(registry, dict) else None
    if not isinstance(entries, dict):
        raise ExecutableTrustError("trusted-executable-registry-invalid")
    directories: list[str] = []
    observed: set[str] = set()
    for entry in entries.values():
        if not isinstance(entry, dict) or entry.get("kind") != "local":
            continue
        parent = str(Path(str(entry["path"])).parent)
        key = os.path.normcase(parent)
        if key not in observed:
            observed.add(key)
            directories.append(parent)
    if not directories:
        raise ExecutableTrustError("trusted-executable-path-empty")
    return os.pathsep.join(directories)
