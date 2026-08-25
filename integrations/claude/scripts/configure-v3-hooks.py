#!/usr/bin/env python3
"""Replace only Supervisor-owned hook commands in Claude user settings."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
import time
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


def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def durable_atomic_replace(path: Path, content: bytes) -> None:
    """Write, fsync, and atomically replace one same-directory settings file."""
    temporary = path.with_name(
        "." + path.name + "." + str(os.getpid()) + "." + str(time.time_ns()) + ".tmp"
    )
    try:
        # Path.write_bytes remains the single write boundary used by the existing
        # fault-injection harness. Reopen only to force the complete bytes durable
        # before the same-directory atomic replacement.
        temporary.write_bytes(content)
        with temporary.open("rb+") as handle:
            handle.flush()
            os.fsync(handle.fileno())
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
        try:
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


def is_supervisor_hook(hook: Any) -> bool:
    if not isinstance(hook, dict):
        return False
    command = str(hook.get("command", "")).replace("\\", "/").lower()
    return (
        "sup-log.py" in command
        or "sup-v3-hook.py" in command
        or "/skills/supervisor/scripts/sup-" in command
    )


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
        for group in groups:
            if not isinstance(group, dict):
                kept_groups.append(group)
                continue
            entries = group.get("hooks")
            if not isinstance(entries, list):
                kept_groups.append(group)
                continue
            kept = [entry for entry in entries if not is_supervisor_hook(entry)]
            if kept:
                clone = copy.deepcopy(group)
                clone["hooks"] = kept
                kept_groups.append(clone)
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
        original_bytes = settings_path.read_bytes()
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
        hooks.setdefault(event, []).append(
            {
                "matcher": "*",
                "hooks": [
                    {
                        "type": "command",
                        "command": f'"{python_path}" "{command_path}" --event {event}',
                        "timeout": 10,
                    }
                ],
            }
        )

    preserved_after = without_supervisor(updated)
    preserved = digest(preserved_before) == digest(preserved_after)
    if not preserved:
        print(json.dumps({"updated": False, "error": "preservation_check_failed"}, separators=(",", ":")))
        return 64

    encoded = (json.dumps(updated, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    try:
        durable_atomic_replace(settings_path, encoded)
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
