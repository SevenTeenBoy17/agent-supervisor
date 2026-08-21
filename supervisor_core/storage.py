from __future__ import annotations

import json
import os
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator

from .constants import DEFAULT_MAX_EVENT_BYTES, DEFAULT_RETENTION_DAYS, DEFAULT_ROTATIONS
from .util import json_load, redact, sha256_text, slug, utc_now


class LockTimeout(RuntimeError):
    pass


@contextmanager
def exclusive_lock(path: Path, timeout: float = 10.0) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + timeout
    fd: int | None = None
    while fd is None:
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, f"{os.getpid()} {time.time()}".encode("ascii"))
        except (FileExistsError, PermissionError):
            # Windows may report a sharing violation as PermissionError while a
            # different process/thread owns the O_EXCL lock file.
            try:
                if time.time() - path.stat().st_mtime > 120:
                    path.unlink(missing_ok=True)
                    continue
            except (FileNotFoundError, PermissionError):
                continue
            if time.monotonic() >= deadline:
                raise LockTimeout(f"lock timeout: {path}")
            time.sleep(0.01)
    try:
        yield
    finally:
        if fd is not None:
            os.close(fd)
        path.unlink(missing_ok=True)


def atomic_write_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp")
    with temp.open("wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, path)


def atomic_write_json(path: Path, value: Any) -> None:
    payload = json.dumps(redact(value), ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
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
            existing = self.events_file.read_text(encoding="utf-8") if self.events_file.exists() else ""
            sequence_path = self.root / "event-sequence.json"
            sequence_state = json_load(sequence_path, {})
            last_sequence = int(sequence_state.get("last_sequence", 0)) if isinstance(sequence_state, dict) else 0
            if last_sequence <= 0:
                # Backward-compatible recovery for pre-v3.0.1 ledgers.
                for candidate in [self.events_file, *sorted(self.root.glob("events.*.jsonl"))]:
                    if not candidate.exists():
                        continue
                    for line in candidate.read_text(encoding="utf-8").splitlines():
                        if line.strip():
                            try:
                                last_sequence = max(last_sequence, int(json.loads(line).get("sequence", 0)))
                            except (ValueError, json.JSONDecodeError):
                                continue
            clean = redact(event)
            clean["sequence"] = last_sequence + 1
            clean.setdefault("recorded_at", utc_now())
            line = json.dumps(clean, ensure_ascii=False, sort_keys=True) + "\n"
            if len(existing.encode("utf-8")) + len(line.encode("utf-8")) > DEFAULT_MAX_EVENT_BYTES:
                self._rotate_locked()
                existing = ""
            atomic_write_bytes(self.events_file, (existing + line).encode("utf-8"))
            atomic_write_json(sequence_path, {"last_sequence": clean["sequence"]})
            return clean

    def events(self) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
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
            for line in candidate.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    result.append(json.loads(line))
        result.sort(key=lambda row: int(row.get("sequence", 0)))
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
    names = ["CODEX_THREAD_ID", "CLAUDE_SESSION_ID"] if runtime.lower() == "codex" else ["CLAUDE_SESSION_ID", "CODEX_THREAD_ID"]
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
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
        if path.stat().st_mtime < cutoff:
            path.unlink(missing_ok=True)
            removed += 1
    return removed
