#!/usr/bin/env python3
"""Scan publishable files and optional Git blobs without printing secret values."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import threading
import time
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
MAX_FILES = 4096
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_GIT_INDEX_BYTES = 32 * 1024 * 1024
MAX_HISTORY_OBJECTS = 100_000
MAX_HISTORY_BYTES = 512 * 1024 * 1024
GIT_TIMEOUT_SECONDS = 60
_OID = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")


class SecretScanError(RuntimeError):
    pass


def _credential_detector(root: Path) -> Callable[[bytes], str | None]:
    runner = root / "bin" / "run-coderabbit-review.py"
    spec = importlib.util.spec_from_file_location("agent_supervisor_secret_detector", runner)
    if spec is None or spec.loader is None:
        raise SecretScanError("credential detector is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    detector = getattr(module, "credential_finding", None)
    if not callable(detector):
        raise SecretScanError("credential detector is unavailable")
    return detector


def _run_git(root: Path, args: list[str], *, maximum: int) -> bytes:
    environment = os.environ.copy()
    for name in (
        "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR",
        "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    ):
        environment.pop(name, None)
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_CONFIG_GLOBAL"] = os.devnull
    if maximum < 1:
        raise SecretScanError("git scan output budget is invalid")
    try:
        process = subprocess.Popen(
            ["git", "-C", str(root), *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )
    except OSError as exc:
        raise SecretScanError("git scan command unavailable") from exc
    if process.stdout is None or process.stderr is None:
        try:
            process.kill()
        except OSError:
            pass
        raise SecretScanError("git scan command streams unavailable")

    total = [0]
    lock = threading.Lock()
    exceeded = threading.Event()

    def drain(stream) -> bytes:
        chunks: list[bytes] = []
        while True:
            chunk = stream.read(64 * 1024)
            if not chunk:
                break
            with lock:
                total[0] += len(chunk)
                over_budget = total[0] > maximum
            if over_budget:
                exceeded.set()
                break
            chunks.append(chunk)
        return b"".join(chunks)

    timed_out = False
    deadline = time.monotonic() + GIT_TIMEOUT_SECONDS
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            stdout_future = pool.submit(drain, process.stdout)
            stderr_future = pool.submit(drain, process.stderr)
            while process.poll() is None:
                if exceeded.wait(0.01):
                    try:
                        process.kill()
                    except OSError:
                        pass
                    break
                if time.monotonic() >= deadline:
                    timed_out = True
                    try:
                        process.kill()
                    except OSError:
                        pass
                    break
            process.wait(timeout=5)
            stdout = stdout_future.result()
            stderr_future.result()
    except (OSError, subprocess.TimeoutExpired) as exc:
        try:
            process.kill()
        except OSError:
            pass
        raise SecretScanError("git scan command unavailable or timed out") from exc
    if exceeded.is_set():
        if process.poll() is not None:
            try:
                process.kill()
            except OSError:
                pass
        raise SecretScanError("git scan command exceeded output budget")
    if timed_out:
        raise SecretScanError("git scan command unavailable or timed out")
    if process.returncode != 0:
        raise SecretScanError("git scan command failed")
    return stdout


def _is_link_or_reparse(path: Path) -> bool:
    details = path.lstat()
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(details, "st_file_attributes", 0)
    return stat.S_ISLNK(details.st_mode) or bool(reparse_flag and attributes & reparse_flag)


def _publishable_paths(root: Path) -> list[tuple[str, Path]]:
    raw = _run_git(
        root,
        ["ls-files", "-co", "--exclude-standard", "-z"],
        maximum=MAX_GIT_INDEX_BYTES,
    )
    names = [value for value in raw.split(b"\0") if value]
    if len(names) > MAX_FILES:
        raise SecretScanError("publishable file count exceeds budget")
    result: list[tuple[str, Path]] = []
    root_resolved = root.resolve(strict=True)
    for encoded in names:
        name = encoded.decode("utf-8", errors="surrogateescape")
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts or "\x00" in name:
            raise SecretScanError("publishable path is unsafe")
        path = root / relative
        if not path.exists() and not path.is_symlink():
            continue
        if _is_link_or_reparse(path):
            raise SecretScanError("publishable path contains a link or reparse point")
        resolved = path.resolve(strict=True)
        try:
            resolved.relative_to(root_resolved)
        except ValueError as exc:
            raise SecretScanError("publishable path escapes repository") from exc
        if resolved.is_file():
            result.append((name.replace("\\", "/"), resolved))
    return sorted(result)


def _stable_file(path: Path) -> bytes:
    before = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE_BYTES:
        raise SecretScanError("publishable file exceeds size budget")
    with path.open("rb") as handle:
        content = handle.read(MAX_FILE_BYTES + 1)
    after = path.stat(follow_symlinks=False)
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_after or len(content) != before.st_size:
        raise SecretScanError("publishable file changed during scan")
    return content


def _history_blob_index(root: Path) -> list[tuple[str, int]]:
    raw = _run_git(
        root,
        [
            "cat-file",
            "--batch-all-objects",
            "--batch-check=%(objectname) %(objecttype) %(objectsize)",
        ],
        maximum=MAX_GIT_INDEX_BYTES,
    )
    blobs: list[tuple[str, int]] = []
    for line in raw.decode("ascii", errors="strict").splitlines():
        fields = line.split(" ")
        if len(fields) != 3:
            raise SecretScanError("Git object index is malformed")
        oid, kind, raw_size = fields
        if not _OID.fullmatch(oid) or not raw_size.isdigit():
            raise SecretScanError("Git object index is malformed")
        if kind != "blob":
            continue
        size = int(raw_size)
        blobs.append((oid, size))
        if len(blobs) > MAX_HISTORY_OBJECTS:
            raise SecretScanError("Git history object count exceeds budget")
    return blobs


def scan_repository(root: Path, *, include_history: bool) -> dict[str, Any]:
    repository = Path(root).expanduser().resolve(strict=True)
    detector = _credential_detector(ROOT)
    findings: list[dict[str, str]] = []
    total = 0
    current_count = 0
    for relative, path in _publishable_paths(repository):
        content = _stable_file(path)
        total += len(content)
        current_count += 1
        if total > MAX_TOTAL_BYTES:
            raise SecretScanError("publishable tree exceeds byte budget")
        category = detector(content)
        if category:
            findings.append(
                {"scope": "current", "path": relative, "category": category}
            )

    history_count = 0
    history_total = 0
    if include_history:
        for oid, size in _history_blob_index(repository):
            history_count += 1
            history_total += size
            if size > MAX_FILE_BYTES:
                findings.append(
                    {
                        "scope": "history",
                        "object": oid,
                        "category": "history-blob-size-limit",
                    }
                )
                continue
            if history_total > MAX_HISTORY_BYTES:
                raise SecretScanError("Git history exceeds byte budget")
            content = _run_git(
                repository,
                ["cat-file", "blob", oid],
                maximum=MAX_FILE_BYTES,
            )
            if len(content) != size:
                raise SecretScanError("Git history blob changed during scan")
            category = detector(content)
            if category:
                findings.append(
                    {"scope": "history", "object": oid, "category": category}
                )

    findings.sort(
        key=lambda row: (
            row.get("scope", ""),
            row.get("path", row.get("object", "")),
            row.get("category", ""),
        )
    )
    return {
        "contract": "ReleaseSecretScan/v1",
        "status": "clean" if not findings else "findings",
        "findings": findings,
        "current_files_scanned": current_count,
        "current_bytes_scanned": total,
        "history_blobs_scanned": history_count,
        "history_bytes_indexed": history_total,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--history", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = scan_repository(args.root, include_history=args.history)
    except (SecretScanError, OSError, UnicodeError, ValueError) as exc:
        result = {
            "contract": "ReleaseSecretScan/v1",
            "status": "degraded",
            "reason": str(exc),
            "findings": [],
        }
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 4
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "clean" else 2


if __name__ == "__main__":
    raise SystemExit(main())
