from __future__ import annotations

import json
import os
import secrets
import socket
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator

from .constants import DEFAULT_MAX_EVENT_BYTES, DEFAULT_RETENTION_DAYS, DEFAULT_ROTATIONS
from .util import json_load, redact_for_persistence, sha256_bytes, sha256_text, slug, utc_now


class LockTimeout(RuntimeError):
    pass


_LOCK_HOST = socket.gethostname().casefold()
_LOCAL_LOCKS_GUARD = threading.Lock()
_LOCAL_LOCKS: dict[str, threading.Lock] = {}


def _local_lock(path: Path) -> threading.Lock:
    key = os.path.normcase(str(path.absolute()))
    with _LOCAL_LOCKS_GUARD:
        return _LOCAL_LOCKS.setdefault(key, threading.Lock())


def _windows_process_probe(pid: int) -> tuple[str, str | None]:
    """Return process liveness and its kernel creation identity on Windows."""
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.GetProcessTimes.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
    ]
    kernel32.GetProcessTimes.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    process_query_limited_information = 0x1000
    handle = kernel32.OpenProcess(process_query_limited_information, False, pid)
    if not handle:
        # ERROR_INVALID_PARAMETER is how OpenProcess reports a PID that does
        # not exist. Access denied is deliberately unknown, never dead.
        return ("dead", None) if ctypes.get_last_error() == 87 else ("unknown", None)
    try:
        created = wintypes.FILETIME()
        exited = wintypes.FILETIME()
        kernel = wintypes.FILETIME()
        user = wintypes.FILETIME()
        if not kernel32.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(exited), ctypes.byref(kernel), ctypes.byref(user)):
            return "alive", None
        ticks = (created.dwHighDateTime << 32) | created.dwLowDateTime
        return "alive", f"windows-filetime:{ticks}"
    finally:
        kernel32.CloseHandle(handle)


def _posix_process_probe(pid: int) -> tuple[str, str | None]:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return "dead", None
    except PermissionError:
        return "unknown", None
    except OSError:
        return "unknown", None

    # Linux exposes a start-time tick that disambiguates PID reuse. Other
    # POSIX hosts retain the conservative live result without guessing.
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        fields = raw.rsplit(")", 1)[1].strip().split()
        return "alive", f"linux-start-ticks:{fields[19]}"
    except (FileNotFoundError, IndexError, OSError):
        return "alive", None


def _process_probe(pid: int) -> tuple[str, str | None]:
    if pid <= 0:
        return "dead", None
    return _windows_process_probe(pid) if os.name == "nt" else _posix_process_probe(pid)


def _lock_owner(raw: bytes) -> dict[str, Any] | None:
    try:
        value = json.loads(raw.decode("utf-8"))
        if isinstance(value, dict):
            return value
    except (UnicodeDecodeError, json.JSONDecodeError):
        pass

    # v3.0.4 compatibility: ``<pid> <created_epoch>``. The record has no host
    # identity, so a local PID probe cannot safely authorize deletion on a
    # shared filesystem.
    try:
        pid, created = raw.decode("ascii").split(maxsplit=1)
        return {"version": 0, "pid": int(pid), "created_at": float(created), "host": None}
    except (UnicodeDecodeError, ValueError):
        return None


def _lock_snapshot(path: Path) -> tuple[tuple[int, int], bytes] | None:
    """Read a stable path identity plus contents, or fail closed on races."""
    try:
        before = path.stat()
        raw = path.read_bytes()
        after = path.stat()
    except (FileNotFoundError, PermissionError, OSError):
        return None
    before_identity = (before.st_dev, before.st_ino)
    after_identity = (after.st_dev, after.st_ino)
    return (after_identity, raw) if before_identity == after_identity else None


def _owner_confirmed_dead(owner: dict[str, Any]) -> bool:
    if str(owner.get("host", "")).casefold() != _LOCK_HOST:
        return False
    try:
        pid = int(owner["pid"])
    except (KeyError, TypeError, ValueError):
        return False
    status, current_start = _process_probe(pid)
    if status == "dead":
        return True
    recorded_start = owner.get("process_start")
    return bool(
        status == "alive"
        and isinstance(recorded_start, str)
        and recorded_start
        and current_start
        and recorded_start != current_start
    )


def _reclaim_confirmed_dead_lock(path: Path) -> bool:
    observed = _lock_snapshot(path)
    if observed is None:
        return False
    identity, raw = observed
    owner = _lock_owner(raw)
    if owner is None or not _owner_confirmed_dead(owner):
        return False
    # Compare immediately before release. If the path was replaced while the
    # owner was probed, leave the successor untouched.
    if _lock_snapshot(path) != (identity, raw):
        return False
    try:
        path.unlink()
        return True
    except (FileNotFoundError, PermissionError, OSError):
        return False


def _release_self_created_lock(
    path: Path, identity: tuple[int, int] | None, owner_payload: bytes
) -> bool:
    """Remove only the still-identical partial lock created by this attempt."""
    if identity is None:
        return False
    observed = _lock_snapshot(path)
    if observed is None or observed[0] != identity:
        return False
    # An interrupted write can leave any prefix, including an empty file.  A
    # different payload is treated as a successor/foreign owner and preserved.
    if not owner_payload.startswith(observed[1]):
        return False
    if _lock_snapshot(path) != observed:
        return False
    try:
        path.unlink()
        return True
    except (FileNotFoundError, PermissionError, OSError):
        return False


def _release_owned_lock(path: Path, identity: tuple[int, int], nonce: str) -> None:
    deadline = time.monotonic() + 1.0
    while True:
        observed = _lock_snapshot(path)
        if observed is None:
            if not path.exists() or time.monotonic() >= deadline:
                return
            time.sleep(0.005)
            continue
        if observed[0] != identity:
            return
        owner = _lock_owner(observed[1])
        if owner is None or owner.get("owner_nonce") != nonce:
            return
        try:
            path.unlink()
            return
        except FileNotFoundError:
            return
        except (PermissionError, OSError):
            if time.monotonic() >= deadline:
                return
            time.sleep(0.005)


@contextmanager
def _exclusive_file_lock(path: Path, timeout: float) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + timeout
    fd: int | None = None
    identity: tuple[int, int] | None = None
    created_identity: tuple[int, int] | None = None
    nonce = secrets.token_hex(16)
    _, process_start = _process_probe(os.getpid())
    owner_payload = json.dumps({
        "version": 1,
        "pid": os.getpid(),
        "process_start": process_start,
        "host": _LOCK_HOST,
        "owner_nonce": nonce,
        "created_at": time.time(),
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")
    while identity is None:
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except (FileExistsError, PermissionError):
            # Windows may report a sharing violation as PermissionError while a
            # different process/thread owns the O_EXCL lock file.
            if _reclaim_confirmed_dead_lock(path):
                # Reclaiming a stale owner can itself consume the caller's
                # complete wait budget.  Do not turn a successful cleanup into
                # an acquisition that happened after the advertised deadline.
                if time.monotonic() >= deadline:
                    raise LockTimeout(f"lock timeout: {path}")
                continue
            if time.monotonic() >= deadline:
                raise LockTimeout(f"lock timeout: {path}")
            time.sleep(0.01)
            continue
        try:
            # Bind cleanup to the descriptor we actually created.  A path
            # snapshot can already describe a replacement owner if the
            # pathname was swapped after O_EXCL creation.
            created_stat = os.fstat(fd)
            created_identity = (created_stat.st_dev, created_stat.st_ino)
            written = 0
            while written < len(owner_payload):
                count = os.write(fd, owner_payload[written:])
                if count <= 0:
                    raise OSError("lock owner write made no progress")
                written += count
            os.fsync(fd)
        except BaseException:
            os.close(fd)
            fd = None
            _release_self_created_lock(path, created_identity, owner_payload)
            raise
        os.close(fd)
        fd = None
        observed = _lock_snapshot(path)
        if (
            observed is None
            or observed[0] != created_identity
            or (_lock_owner(observed[1]) or {}).get("owner_nonce") != nonce
        ):
            if observed is not None:
                _release_owned_lock(path, observed[0], nonce)
            raise RuntimeError(f"could not verify acquired lock: {path}")
        identity = observed[0]
    try:
        yield
    finally:
        if identity is not None:
            _release_owned_lock(path, identity, nonce)


@contextmanager
def exclusive_lock(path: Path, timeout: float = 10.0) -> Iterator[None]:
    """Cross-process lock with an in-process guard to avoid OS lock storms."""
    deadline = time.monotonic() + timeout
    local = _local_lock(path)
    if not local.acquire(timeout=max(0.0, deadline - time.monotonic())):
        raise LockTimeout(f"lock timeout: {path}")
    try:
        with _exclusive_file_lock(path, max(0.0, deadline - time.monotonic())):
            yield
    finally:
        local.release()


def atomic_write_bytes(path: Path, payload: bytes, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp")
    try:
        fd = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            temp.chmod(mode)
        except OSError:
            pass
        os.replace(temp, path)
        try:
            path.chmod(mode)
        except OSError:
            pass
    finally:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass


def _append_bytes_fsync(path: Path, payload: bytes, *, mode: int = 0o600) -> None:
    """Append one durable payload without replacing the existing ledger inode."""
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_CREAT | os.O_WRONLY | os.O_APPEND | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, mode)
    try:
        written = 0
        while written < len(payload):
            count = os.write(fd, payload[written:])
            if count <= 0:
                raise OSError("event ledger append made no progress")
            written += count
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        path.chmod(mode)
    except OSError:
        pass


def atomic_write_json(path: Path, value: Any) -> None:
    payload = json.dumps(redact_for_persistence(value), ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    atomic_write_bytes(path, payload)


@dataclass(frozen=True)
class StateContext:
    runtime: str
    project: str
    workspace: str
    session: str
    round: str
    root: Path

    @classmethod
    def build(
        cls,
        *,
        runtime: str,
        workspace: str,
        session: str,
        round_id: str,
        project: str | None = None,
        state_root: str | Path | None = None,
    ) -> "StateContext":
        resolved_workspace = str(Path(workspace).resolve())
        project_name = project or Path(resolved_workspace).name or "project"
        base = Path(state_root).expanduser() if state_root else Path.home() / ".agent-supervisor" / "state"
        path = (
            base
            / slug(runtime)
            / slug(project_name)
            / slug(resolved_workspace)
            / slug(session)
            / slug(round_id)
        )
        return cls(runtime, project_name, resolved_workspace, session, round_id, path)

    @property
    def state_file(self) -> Path:
        return self.root / "state.json"

    @property
    def events_file(self) -> Path:
        return self.root / "events.jsonl"

    @property
    def session_root(self) -> Path:
        return self.root.parent

    @property
    def workspace_state_root(self) -> Path:
        return self.session_root.parent

    @property
    def project_rollout_file(self) -> Path:
        return self.workspace_state_root / "rollout.json"

    def initialize(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)

    def load(self) -> dict[str, Any]:
        self.initialize()
        with exclusive_lock(self.root / ".state.lock"):
            value = json_load(self.state_file, {})
        return value if isinstance(value, dict) else {}

    def save(self, state: dict[str, Any]) -> None:
        self.initialize()
        with exclusive_lock(self.root / ".state.lock"):
            atomic_write_json(self.state_file, state)

    def update(self, mutator: Callable[[dict[str, Any]], Any]) -> dict[str, Any]:
        """Atomically read, mutate, and replace authoritative state.

        Locking only the final write permits concurrent event processes to load the
        same revision and silently overwrite one another. Keep the full
        read-modify-write transaction under one per-round lock instead.
        """
        self.initialize()
        with exclusive_lock(self.root / ".state.lock"):
            state = json_load(self.state_file, {})
            if not isinstance(state, dict) or not state:
                raise ValueError("active round state missing")
            mutator(state)
            atomic_write_json(self.state_file, state)
            return state

    def append_event(self, event: dict[str, Any]) -> dict[str, Any]:
        self.initialize()
        with exclusive_lock(self.root / ".events.lock"):
            return self._append_event_locked(event)

    def _append_event_locked(self, event: dict[str, Any]) -> dict[str, Any]:
        sequence_path = self.root / "event-sequence.json"
        sequence_state = json_load(sequence_path, {})
        last_sequence: int | None = None
        if isinstance(sequence_state, dict) and sequence_state.get("contract") == "EventSequence/v3":
            try:
                candidate_sequence = int(sequence_state["last_sequence"])
                candidate_size = int(sequence_state["active_ledger_size"])
                candidate_tail_size = int(sequence_state["last_record_size"])
                candidate_tail_hash = str(sequence_state["last_record_sha256"])
                actual_size = self.events_file.stat().st_size
                if (
                    candidate_sequence >= 1
                    and candidate_size == actual_size
                    and 0 < candidate_tail_size <= actual_size
                    and len(candidate_tail_hash) == 64
                ):
                    with self.events_file.open("rb") as handle:
                        handle.seek(-candidate_tail_size, os.SEEK_END)
                        tail = handle.read(candidate_tail_size)
                    tail_record = json.loads(tail.decode("utf-8"))
                    if (
                        sha256_bytes(tail) == candidate_tail_hash
                        and isinstance(tail_record, dict)
                        and int(tail_record.get("sequence", 0)) == candidate_sequence
                    ):
                        last_sequence = candidate_sequence
            except (KeyError, TypeError, ValueError, OverflowError, OSError, UnicodeError, json.JSONDecodeError):
                last_sequence = None
        if last_sequence is None:
            # Missing/stale sidecars fall back to a complete retained-ledger
            # recovery.  Normal appends validate only the last durable record.
            last_sequence = 0
            for candidate in [self.events_file, *sorted(self.root.glob("events.*.jsonl"))]:
                if not candidate.exists():
                    continue
                try:
                    lines = candidate.read_bytes().splitlines()
                except OSError:
                    continue
                for existing_line in lines:
                    if not existing_line.strip():
                        continue
                    try:
                        row = json.loads(existing_line.decode("utf-8"))
                        last_sequence = max(last_sequence, int(row.get("sequence", 0))) if isinstance(row, dict) else last_sequence
                    except (UnicodeError, ValueError, json.JSONDecodeError):
                        continue
        clean = redact_for_persistence(event)
        clean["sequence"] = last_sequence + 1
        clean.setdefault("recorded_at", utc_now())
        line = (json.dumps(clean, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
        existing_size = self.events_file.stat().st_size if self.events_file.exists() else 0
        separator = b""
        if existing_size:
            with self.events_file.open("rb") as handle:
                handle.seek(-1, os.SEEK_END)
                if handle.read(1) not in {b"\n", b"\r"}:
                    # Preserve a torn tail for diagnosis, but keep the next
                    # valid record on its own parseable JSONL boundary.
                    separator = b"\n"
        if existing_size + len(separator) + len(line) > DEFAULT_MAX_EVENT_BYTES:
            self._rotate_locked()
            separator = b""
        _append_bytes_fsync(self.events_file, separator + line)
        active_ledger_size = self.events_file.stat().st_size
        atomic_write_json(sequence_path, {
            "contract": "EventSequence/v3",
            "last_sequence": clean["sequence"],
            "active_ledger_size": active_ledger_size,
            "last_record_size": len(line),
            "last_record_sha256": sha256_bytes(line),
        })
        return clean

    def transact(
        self,
        mutator: Callable[[dict[str, Any]], Any],
        event: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Serialize a state mutation with its audit event.

        The event is made durable first, so an event-write failure cannot commit
        unaudited state. A host crash after that append may leave an auditable
        orphan event, but never a state mutation with no corresponding record.
        """
        self.initialize()
        with exclusive_lock(self.root / ".round.lock", timeout=30.0):
            with exclusive_lock(self.root / ".state.lock"):
                with exclusive_lock(self.root / ".events.lock"):
                    state = json_load(self.state_file, {})
                    if not isinstance(state, dict) or not state:
                        raise ValueError("active round state missing")
                    mutator(state)
                    payload = dict(event)
                    payload.setdefault("transaction_id", secrets.token_hex(16))
                    recorded = self._append_event_locked(payload)
                    atomic_write_json(self.state_file, state)
                    return state, recorded

    def events(self) -> list[dict[str, Any]]:
        self.initialize()
        with exclusive_lock(self.root / ".events.lock"):
            return self._events_locked()

    def _events_locked(self) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        degraded: list[tuple[str, int]] = []
        # Rotation renames the newest previous ledger to events.1.jsonl. Read
        # oldest-to-newest, then sort by the authoritative monotonic sequence so
        # validation never forgets attempts, signed gate executions, or reviews
        # merely because the active file crossed its size limit.
        candidates = [
            *(self.root / f"events.{index}.jsonl" for index in range(DEFAULT_ROTATIONS, 0, -1)),
            self.events_file,
        ]
        for candidate in candidates:
            if not candidate.exists():
                continue
            malformed_lines = 0
            try:
                lines = candidate.read_bytes().splitlines()
            except OSError:
                degraded.append((candidate.name, 1))
                continue
            for raw_line in lines:
                if not raw_line.strip():
                    continue
                try:
                    row = json.loads(raw_line.decode("utf-8"))
                    if not isinstance(row, dict):
                        raise ValueError("event row is not an object")
                    int(row.get("sequence", 0))
                    result.append(row)
                except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
                    malformed_lines += 1
            if malformed_lines:
                degraded.append((candidate.name, malformed_lines))
        result.sort(key=lambda row: int(row.get("sequence", 0)))
        next_sequence = max((int(row.get("sequence", 0)) for row in result), default=0)
        for source_file, malformed_lines in degraded:
            next_sequence += 1
            result.append({
                "event_type": "event_ledger_degraded",
                "status": "degraded",
                "summary": "malformed event ledger records ignored",
                "source_file": source_file,
                "malformed_lines": malformed_lines,
                "sequence": next_sequence,
                "recorded_at": utc_now(),
            })
        return result

    def _rotate_locked(self) -> None:
        for index in range(DEFAULT_ROTATIONS, 0, -1):
            src = self.root / ("events.jsonl" if index == 1 else f"events.{index - 1}.jsonl")
            dst = self.root / f"events.{index}.jsonl"
            if src.exists():
                if index == DEFAULT_ROTATIONS:
                    dst.unlink(missing_ok=True)
                os.replace(src, dst)

    def update_session_pointer(self, data: dict[str, Any]) -> None:
        with exclusive_lock(self.session_root / ".session.lock"):
            atomic_write_json(self.session_root / "current.json", data)

    def previous_pointer(self) -> dict[str, Any]:
        value = json_load(self.session_root / "current.json", {})
        return value if isinstance(value, dict) else {}

    def load_project_rollout(self) -> dict[str, Any]:
        with exclusive_lock(self.workspace_state_root / ".rollout.lock"):
            value = json_load(self.project_rollout_file, {})
        return value if isinstance(value, dict) else {}

    def update_project_rollout(self, mutator: Callable[[dict[str, Any]], dict[str, Any] | None]) -> dict[str, Any]:
        self.workspace_state_root.mkdir(parents=True, exist_ok=True)
        with exclusive_lock(self.workspace_state_root / ".rollout.lock"):
            current = json_load(self.project_rollout_file, {})
            if not isinstance(current, dict):
                current = {}
            replacement = mutator(current)
            value = replacement if isinstance(replacement, dict) else current
            atomic_write_json(self.project_rollout_file, value)
            return value


def default_session(runtime: str) -> str:
    normalized_runtime = runtime.lower()
    names = ["CODEX_THREAD_ID", "CLAUDE_SESSION_ID"] if normalized_runtime == "codex" else ["CLAUDE_SESSION_ID", "CODEX_THREAD_ID"]
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    if normalized_runtime in {"codex", "claude"}:
        raise ValueError(f"{normalized_runtime} session identity unavailable")
    return f"anonymous-{sha256_text(str(os.getpid()))[:8]}"


def default_round() -> str:
    return utc_now().replace(":", "").replace("-", "").replace(".", "")


def prune_old_state(base: Path, retention_days: int = DEFAULT_RETENTION_DAYS) -> int:
    """Delete only expired rotated log files, never active state or goals."""
    cutoff = time.time() - retention_days * 86400
    removed = 0
    if not base.exists():
        return removed
    for path in base.rglob("events.*.jsonl"):
        try:
            # Rotation and pruning share the event lock so a stat/unlink race
            # cannot delete a newly rotated successor at the same path.
            with exclusive_lock(path.parent / ".events.lock", timeout=0.25):
                if path.stat().st_mtime < cutoff:
                    path.unlink()
                    removed += 1
        except (FileNotFoundError, PermissionError, OSError, LockTimeout):
            continue
    return removed
