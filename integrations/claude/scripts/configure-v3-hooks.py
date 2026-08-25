#!/usr/bin/env python3
"""Replace only Supervisor-owned hook commands in Claude user settings."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any


EVENTS = (
    "SessionStart",
    "UserPromptSubmit",
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
    "Stop",
    "SubagentStart",
    "SubagentStop",
)
LEGACY_EVENTS = frozenset(
    {
        "session-start",
        "prompt-submit",
        "pre-tool",
        "post-tool",
        "post-tool-failure",
        "stop",
        "subagent-start",
        "subagent-stop",
    }
)
PYTHON_EXECUTABLE = re.compile(r"^(?:py|python(?:3(?:\.\d+)?)?)(?:\.exe)?$", re.IGNORECASE)
DIRECT_COMMAND_TOKEN = re.compile(r'''(?:"([^"]*)"|'([^']*)'|([^\s"']+))''')
UNQUOTED_SHELL_META = re.compile(r"[`$;&|<>(){}\[\]*?~%!]")
DOUBLE_QUOTED_EXPANSION = re.compile(r"[`$%!]")


def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def _is_reparse(info: os.stat_result) -> bool:
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


def _file_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_mode),
        int(info.st_size),
        int(info.st_mtime_ns),
        int(info.st_ctime_ns) if os.name == "posix" else 0,
    )


def read_settings_snapshot(
    path: Path,
) -> tuple[bytes, int, tuple[int, int, int, int, int, int]]:
    """Read one regular settings file without following a final-path link."""
    before = path.lstat()
    if _is_reparse(before) or not stat.S_ISREG(before.st_mode):
        raise OSError("settings_path_not_regular")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened_before = os.fstat(descriptor)
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        opened_after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after = path.lstat()
    identity = _file_identity(before)
    if (
        _is_reparse(after)
        or not stat.S_ISREG(after.st_mode)
        or identity
        != _file_identity(opened_before)
        or identity
        != _file_identity(opened_after)
        or identity
        != _file_identity(after)
    ):
        raise OSError("settings_changed_during_read")
    content = b"".join(chunks)
    if len(content) != before.st_size:
        raise OSError("settings_read_truncated")
    return content, stat.S_IMODE(before.st_mode), identity


def durable_atomic_replace(
    path: Path,
    content: bytes,
    original_mode: int,
    original_identity: tuple[int, int, int, int, int, int],
) -> None:
    """Privately write and atomically replace one same-directory settings file."""
    descriptor = -1
    temporary: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(
            prefix="." + path.name + "." + str(os.getpid()) + ".",
            suffix=".tmp",
            dir=str(path.parent),
        )
        temporary = Path(name)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        # The copy is 0600 while it contains incomplete bytes. Apply the target's
        # original mode only after the durable write and before the atomic swap, so
        # a mode-restoration failure cannot leave partially committed settings.
        os.chmod(temporary, original_mode)
        current = path.lstat()
        if _is_reparse(current) or _file_identity(current) != original_identity:
            raise OSError("settings_changed_before_replace")
        os.replace(temporary, path)
        temporary = None
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
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        except OSError:
            pass


def valid_hook_container(settings: dict[str, Any]) -> bool:
    """Reject malformed existing event containers before any migration write."""
    hooks = settings.get("hooks")
    if hooks is None:
        return True
    if not isinstance(hooks, dict):
        return False
    return all(isinstance(groups, list) for groups in hooks.values())


def _direct_command_parts(command: Any) -> list[tuple[str, str]] | None:
    """Parse only plain argv-like commands; reject shell syntax and empty tokens."""
    if (
        not isinstance(command, str)
        or not command.strip(" \t")
        or "\r" in command
        or "\n" in command
    ):
        return None
    parts: list[tuple[str, str]] = []
    offset = len(command) - len(command.lstrip(" \t"))
    end = len(command.rstrip(" \t"))
    while offset < end:
        match = DIRECT_COMMAND_TOKEN.match(command, offset)
        if match is None:
            return None
        group_index, token = next(
            ((index, value) for index, value in enumerate(match.groups()) if value is not None),
            (-1, ""),
        )
        if not token:
            return None
        quote = '"' if group_index == 0 else "'" if group_index == 1 else ""
        parts.append((token, quote))
        offset = match.end()
        if offset < end:
            separator = re.match(r"[ \t]+", command[offset:])
            if separator is None:
                return None
            offset += separator.end()
    return parts


def _direct_command_tokens(command: Any) -> list[str] | None:
    parts = _direct_command_parts(command)
    return [value for value, _quote in parts] if parts is not None else None


def _safe_path_token(value: str, quote: str) -> bool:
    if quote == '"':
        return DOUBLE_QUOTED_EXPANSION.search(value) is None
    return UNQUOTED_SHELL_META.search(value) is None


def _supervisor_script_name(value: str) -> str | None:
    normalized = value.replace("\\", "/")
    lowered = normalized.casefold()
    prefix = "/.claude/skills/supervisor/scripts/"
    if prefix not in lowered:
        return None
    before, separator, name = lowered.rpartition(prefix)
    if not separator or not before or "/" in name:
        return None
    return name if name in {"sup-log.py", "sup-v3-hook.py"} else None


def is_supervisor_hook(hook: Any) -> bool:
    """Recognize only exact direct invocations emitted by Supervisor installers."""
    if not isinstance(hook, dict) or hook.get("type") != "command":
        return False
    parts = _direct_command_parts(hook.get("command"))
    if parts is None or len(parts) < 3:
        return False
    tokens = [value for value, _quote in parts]
    executable = tokens[0].replace("\\", "/").rsplit("/", 1)[-1].casefold()
    argument_offset = 1
    if tokens[1:3] == ["-I", "-S"]:
        argument_offset = 3
    if len(tokens) <= argument_offset:
        return False
    if not _safe_path_token(*parts[0]) or not _safe_path_token(*parts[argument_offset]):
        return False
    script = _supervisor_script_name(tokens[argument_offset])
    if PYTHON_EXECUTABLE.fullmatch(executable) is None or script is None:
        return False
    arguments = tokens[argument_offset + 1 :]
    if script == "sup-log.py":
        return argument_offset == 1 and len(arguments) == 1 and arguments[0] in LEGACY_EVENTS
    return len(arguments) == 2 and arguments[0] == "--event" and arguments[1] in EVENTS


def without_supervisor(settings: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(settings)
    hooks = result.get("hooks")
    if not isinstance(hooks, dict):
        return result
    for event in list(hooks):
        groups = hooks.get(event)
        if not isinstance(groups, list):
            continue
        kept_groups = []
        removed_from_event = False
        for group in groups:
            if not isinstance(group, dict):
                kept_groups.append(group)
                continue
            entries = group.get("hooks")
            if not isinstance(entries, list):
                kept_groups.append(group)
                continue
            kept = [entry for entry in entries if not is_supervisor_hook(entry)]
            removed = len(kept) != len(entries)
            if not removed:
                kept_groups.append(group)
                continue
            removed_from_event = True
            if kept:
                clone = copy.deepcopy(group)
                clone["hooks"] = kept
                kept_groups.append(clone)
            elif set(group) != {"matcher", "hooks"} or group.get("matcher") != "*":
                clone = copy.deepcopy(group)
                clone["hooks"] = []
                kept_groups.append(clone)
        if not removed_from_event:
            continue
        if kept_groups:
            hooks[event] = kept_groups
        else:
            hooks.pop(event, None)
    if not hooks:
        result.pop("hooks", None)
    return result


def main() -> int:
    home = Path(os.environ.get("USERPROFILE") or os.environ.get("HOME") or Path.home())
    settings_path = home / ".claude" / "settings.json"
    adapter = home / ".claude" / "skills" / "supervisor" / "scripts" / "sup-v3-hook.py"
    try:
        original_bytes, original_mode, original_identity = read_settings_snapshot(settings_path)
    except OSError:
        print(json.dumps({"updated": False, "error": "settings_read_failed"}, separators=(",", ":")))
        return 64
    try:
        original = json.loads(original_bytes.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        print(json.dumps({"updated": False, "error": "invalid_json"}, separators=(",", ":")))
        return 64
    if not isinstance(original, dict):
        print(json.dumps({"updated": False, "error": "invalid_root"}, separators=(",", ":")))
        return 64
    if not valid_hook_container(original):
        print(json.dumps({"updated": False, "error": "invalid_hooks"}, separators=(",", ":")))
        return 64

    preserved_before = without_supervisor(original)
    updated = copy.deepcopy(preserved_before)
    hooks = updated.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        print(json.dumps({"updated": False, "error": "invalid_hooks"}, separators=(",", ":")))
        return 64

    command_path = adapter.as_posix()
    python_path = Path(sys.executable).as_posix()
    for event in EVENTS:
        entry = {
            "type": "command",
            "command": f'"{python_path}" -I -S "{command_path}" --event {event}',
            "timeout": 10,
        }
        # Never commit a command that a later migration cannot prove is ours.
        # This fails closed for renamed/free-threaded interpreters and shell-
        # expansion characters instead of installing an immortal duplicate hook.
        if not is_supervisor_hook(entry):
            print(
                json.dumps(
                    {"updated": False, "error": "unsupported_hook_command"},
                    separators=(",", ":"),
                )
            )
            return 64
        hooks.setdefault(event, []).append(
            {
                "matcher": "*",
                "hooks": [entry],
            }
        )

    preserved_after = without_supervisor(updated)
    preserved = digest(preserved_before) == digest(preserved_after)
    if not preserved:
        print(json.dumps({"updated": False, "error": "preservation_check_failed"}, separators=(",", ":")))
        return 64

    encoded = (json.dumps(updated, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    try:
        durable_atomic_replace(settings_path, encoded, original_mode, original_identity)
    except OSError:
        print(json.dumps({"updated": False, "error": "settings_write_failed"}, separators=(",", ":")))
        return 64
    report = {
        "updated": True,
        "non_supervisor_preserved": True,
        "before_sha256": hashlib.sha256(original_bytes).hexdigest(),
        "after_sha256": hashlib.sha256(encoded).hexdigest(),
        "preserved_semantic_sha256": digest(preserved_before),
        "registered_events": list(EVENTS),
        "supervisor_hook_count": len(EVENTS),
    }
    print(json.dumps(report, ensure_ascii=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
