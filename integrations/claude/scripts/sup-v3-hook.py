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
import json
import math
import os
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ADAPTER_VERSION = "3.1.5"
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


def _read_active_record(pointer_path: Path) -> dict[str, str] | None:
    pointer_file = _canonical_existing(pointer_path, directory=False)
    if pointer_file is None:
        return None
    try:
        pointer = json.loads(pointer_file.read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError):
        return None
    active = pointer.get("active") if isinstance(pointer, dict) else None
    if (
        not isinstance(pointer, dict)
        or pointer.get("contract") not in {"ActiveVersionPointer/v3", "ActiveVersionPointer/v4"}
        or not isinstance(active, dict)
        or not isinstance(active.get("version"), str)
        or not active["version"].strip()
        or not isinstance(active.get("path"), str)
        or not active["path"].strip()
    ):
        return None
    candidate = Path(active["path"]).expanduser()
    if not candidate.is_absolute():
        return None
    return {
        "version": active["version"].strip(),
        "path": str(candidate),
        "pointer": str(pointer_file),
    }


def _read_active_target(pointer_path: Path) -> Path | None:
    record = _read_active_record(pointer_path)
    return Path(record["path"]) if record is not None else None


def _resolve_active_pointer_selection() -> tuple[Path, dict[str, str]]:
    default = _lexical_absolute(_home() / ".agent-supervisor")
    allowed_roots = [default, default.parent / ".agent-supervisor-releases"]
    configured_release = os.environ.get("AGENT_SUPERVISOR_RELEASE_ROOT")
    if configured_release:
        release = Path(configured_release).expanduser()
        if release.is_absolute():
            allowed_roots.append(release)

    pointer = Path(
        os.environ.get("AGENT_SUPERVISOR_ACTIVE_POINTER", str(default / "active-version.json"))
    ).expanduser()
    if not pointer.is_absolute():
        raise FileNotFoundError("active_pointer_rejected")
    active = _read_active_record(pointer)
    if active is None:
        raise FileNotFoundError("active_pointer_rejected")
    trusted = _trusted_core(Path(active["path"]), allowed_roots)
    if trusted is None:
        raise FileNotFoundError("active_pointer_rejected")
    return trusted, {
        "source": "active-pointer",
        "declared_path": active["path"],
        "declared_version": active["version"],
        "pointer": active["pointer"],
    }


def _resolve_core_selection(
    *, require_active_pointer: bool = False
) -> tuple[Path, dict[str, str]]:
    explicit = os.environ.get("AGENT_SUPERVISOR_HOME") or os.environ.get("AGENT_SUPERVISOR_CORE")
    if explicit:
        candidate = Path(explicit).expanduser()
        trusted = _trusted_core(candidate, [candidate]) if candidate.is_absolute() else None
        if trusted is None:
            raise FileNotFoundError("core_rejected")
        return trusted, {
            "source": "explicit",
            "declared_path": str(candidate),
        }

    default = _lexical_absolute(_home() / ".agent-supervisor")
    try:
        return _resolve_active_pointer_selection()
    except FileNotFoundError:
        if require_active_pointer:
            raise

    trusted_default = _trusted_core(default, [default])
    if trusted_default is None:
        raise FileNotFoundError("core_missing")
    return trusted_default, {
        "source": "default",
        "declared_path": str(default),
    }


def _core_root(*, require_active_pointer: bool = False) -> Path:
    return _resolve_core_selection(
        require_active_pointer=require_active_pointer
    )[0]


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


def _has_degraded_marker(session_id: str) -> bool:
    return _fallback_paths(session_id)[1].exists()


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
        marker_path.parent.mkdir(parents=True, exist_ok=True)
        if marker_path.exists():
            return True
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
        fd = os.open(str(tmp), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(str(tmp), str(marker_path))
            return True
        except FileExistsError:
            # Another writer won the race. Preserve its complete marker verbatim.
            return marker_path.is_file()
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
        marker_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = marker_path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(
                marker_record,
                ensure_ascii=True,
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        os.replace(tmp, marker_path)

        # Daily logs are shared by sessions, so keep their append lock separate
        # while holding the session lock that protects the marker transition.
        log_lock = log_path.with_suffix(".lock")
        log_fd = _acquire_lock(log_lock)
        if log_fd is not None:
            try:
                log_path.parent.mkdir(parents=True, exist_ok=True)
                with log_path.open("a", encoding="utf-8", newline="\n") as handle:
                    handle.write(
                        json.dumps(record, ensure_ascii=True, separators=(",", ":"))
                        + "\n"
                    )
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


def _forward(event: str, payload: dict[str, Any]) -> tuple[int, bytes]:
    core_root = _core_root()
    if not (core_root / "supervisor_core").is_dir():
        raise FileNotFoundError("core_missing")

    forwarded = dict(payload)
    forwarded["hook_event_name"] = event
    forwarded.setdefault("session_id", _session_id(payload))
    forwarded["_agent_supervisor_adapter"] = {
        "adapter_version": ADAPTER_VERSION,
        "degraded_prior": _has_degraded_marker(_session_id(payload)),
    }
    env = dict(os.environ)
    # The selected core is already provenance-checked. Do not let the caller's cwd
    # or PYTHONPATH place a different ``supervisor_core`` package ahead of it.
    env["PYTHONPATH"] = str(core_root)
    # Keep mutable state under the host-selected profile while binding source
    # identity to the real installation.  This makes isolated profiles and
    # Unicode/space-path harnesses deterministic without weakening provenance.
    env["AGENT_SUPERVISOR_INSTALL_HOME"] = str(_installation_home())
    state_root = _home() / ".agent-supervisor" / "state"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "supervisor_core",
            "hook",
            "--runtime",
            "claude",
            "--event",
            event,
            "--state-root",
            str(state_root),
        ],
        input=json.dumps(forwarded, ensure_ascii=False).encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        cwd=str(core_root),
        timeout=_hook_timeout(),
        check=False,
    )
    return proc.returncode, proc.stdout


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
