from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time

import pytest

import supervisor_core.storage as storage_module
from supervisor_core.contracts import validate_review_shape
from supervisor_core.storage import atomic_write_json
from supervisor_core.util import canonical_sha256
from supervisor_core.workspace import (
    _ESCAPED_WORKSPACE_PATH_PREFIX,
    _RAW_WORKSPACE_PATH_PREFIX,
    _persistent_workspace_path,
    capture_workspace_snapshot,
    workspace_delta,
)


def _lock_owner_temp(path: Path, lock_path: Path) -> bool:
    return (
        path.parent == lock_path.parent
        and path.name.startswith(f".{lock_path.name}.")
        and path.name.endswith(".owner.tmp")
    )


def _assert_no_lock_artifacts(lock_path: Path) -> None:
    assert not lock_path.exists()
    assert not list(lock_path.parent.glob(f".{lock_path.name}.*.owner.tmp"))


@pytest.mark.parametrize("value", [None, [], ["review"], "review", 7])
def test_validate_review_shape_rejects_non_mapping_without_exception(value) -> None:
    assert validate_review_shape(value) is False


def test_owner_is_invisible_until_complete_payload_is_fsynced_and_published(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lock_path = tmp_path / "visibility.lock"
    real_open = storage_module.os.open
    real_write = storage_module.os.write
    target_fds: set[int] = set()
    partial_written = threading.Event()
    finish_write = threading.Event()
    holder_entered = threading.Event()
    release_holder = threading.Event()

    def tracked_open(path, *args, **kwargs) -> int:
        fd = real_open(path, *args, **kwargs)
        if _lock_owner_temp(Path(path), lock_path):
            target_fds.add(fd)
        return fd

    def paused_write(fd: int, payload: bytes) -> int:
        if fd in target_fds and not partial_written.is_set():
            count = real_write(fd, payload[:7])
            partial_written.set()
            assert finish_write.wait(5)
            return count
        return real_write(fd, payload)

    monkeypatch.setattr(storage_module.os, "open", tracked_open)
    monkeypatch.setattr(storage_module.os, "write", paused_write)

    errors: list[BaseException] = []

    def acquire() -> None:
        try:
            with storage_module._exclusive_file_lock(lock_path, timeout=5):
                holder_entered.set()
                assert release_holder.wait(5)
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    thread = threading.Thread(target=acquire)
    thread.start()
    assert partial_written.wait(5)
    assert not lock_path.exists(), "a zero/partial owner became externally visible"
    finish_write.set()
    assert holder_entered.wait(5)
    owner = json.loads(lock_path.read_text(encoding="utf-8"))
    assert owner["owner_nonce"]
    release_holder.set()
    thread.join(5)
    assert not thread.is_alive()
    assert errors == []
    _assert_no_lock_artifacts(lock_path)


def test_one_hundred_contenders_never_overlap_or_observe_partial_owner(
    tmp_path: Path,
) -> None:
    lock_path = tmp_path / "hundred.lock"
    guard = threading.Lock()
    active = 0
    max_active = 0
    acquired: list[str] = []

    def contender(index: int) -> None:
        nonlocal active, max_active
        with storage_module._exclusive_file_lock(lock_path, timeout=20):
            owner = json.loads(lock_path.read_text(encoding="utf-8"))
            nonce = str(owner["owner_nonce"])
            with guard:
                active += 1
                max_active = max(max_active, active)
                acquired.append(f"{index}:{nonce}")
            time.sleep(0.001)
            with guard:
                active -= 1

    with ThreadPoolExecutor(max_workers=100) as pool:
        futures = [pool.submit(contender, index) for index in range(100)]
        for future in futures:
            future.result(timeout=25)

    assert len(acquired) == 100
    assert len({row.split(":", 1)[1] for row in acquired}) == 100
    assert max_active == 1
    _assert_no_lock_artifacts(lock_path)


def test_no_clobber_publish_preserves_existing_complete_owner(tmp_path: Path) -> None:
    lock_path = tmp_path / "existing.lock"
    existing = b'{"owner_nonce":"existing-owner"}'
    lock_path.write_bytes(existing)
    temp = tmp_path / ".existing.owner.tmp"
    temp.write_bytes(b'{"owner_nonce":"candidate-owner"}')
    assert storage_module._publish_lock_no_clobber(temp, lock_path) is False
    assert lock_path.read_bytes() == existing
    assert temp.exists()


@pytest.mark.parametrize("fault", ["create", "write", "fsync", "publish", "directory-fsync"])
def test_lock_preparation_and_publication_faults_leave_no_visible_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    lock_path = tmp_path / f"{fault}.lock"
    real_open = storage_module.os.open
    real_write = storage_module.os.write
    real_fsync = storage_module.os.fsync
    target_fds: set[int] = set()

    def tracked_open(path, *args, **kwargs) -> int:
        candidate = Path(path)
        if fault == "create" and _lock_owner_temp(candidate, lock_path):
            raise OSError("injected lock owner create failure")
        fd = real_open(path, *args, **kwargs)
        if _lock_owner_temp(candidate, lock_path):
            target_fds.add(fd)
        return fd

    def failed_write(fd: int, payload: bytes) -> int:
        if fault == "write" and fd in target_fds:
            real_write(fd, payload[:5])
            raise OSError("injected lock owner write failure")
        return real_write(fd, payload)

    def failed_fsync(fd: int) -> None:
        if fault == "fsync" and fd in target_fds:
            raise OSError("injected lock owner fsync failure")
        real_fsync(fd)

    monkeypatch.setattr(storage_module.os, "open", tracked_open)
    monkeypatch.setattr(storage_module.os, "write", failed_write)
    monkeypatch.setattr(storage_module.os, "fsync", failed_fsync)
    if fault == "publish":
        monkeypatch.setattr(
            storage_module,
            "_publish_lock_no_clobber",
            lambda _temp, _path: (_ for _ in ()).throw(
                OSError("injected lock owner publish failure")
            ),
        )
    if fault == "directory-fsync":
        monkeypatch.setattr(
            storage_module,
            "_fsync_parent_directory",
            lambda _directory: (_ for _ in ()).throw(
                OSError("injected directory fsync failure")
            ),
        )

    with pytest.raises(OSError, match="injected"):
        with storage_module._exclusive_file_lock(lock_path, timeout=0.5):
            pytest.fail("a failed owner publication must not acquire the lock")
    _assert_no_lock_artifacts(lock_path)


def test_complete_confirmed_dead_owner_is_reclaimed_after_atomic_publication(
    tmp_path: Path,
) -> None:
    lock_path = tmp_path / "stale.lock"
    lock_path.write_text(
        json.dumps(
            {
                "version": 1,
                "pid": 2_147_483_647,
                "process_start": "dead-process",
                "host": socket.gethostname().casefold(),
                "owner_nonce": "stale-owner",
                "created_at": 0,
            }
        ),
        encoding="utf-8",
    )
    with storage_module._exclusive_file_lock(lock_path, timeout=1):
        owner = json.loads(lock_path.read_text(encoding="utf-8"))
        assert owner["owner_nonce"] != "stale-owner"
    _assert_no_lock_artifacts(lock_path)


def test_raw_path_encoding_is_utf8_safe_and_namespace_injective() -> None:
    raw_text = b"raw-\xff.txt".decode("utf-8", errors="surrogateescape")
    raw_hex = b"raw-\xff.txt".hex()
    raw_key = _persistent_workspace_path(raw_text)
    colliding_valid_name = raw_key
    escaped_valid_key = _persistent_workspace_path(colliding_valid_name)
    assert raw_key == f"{_RAW_WORKSPACE_PATH_PREFIX}{raw_hex}"
    assert escaped_valid_key.startswith(_ESCAPED_WORKSPACE_PATH_PREFIX)
    assert escaped_valid_key != raw_key
    json.dumps(
        {raw_key: "raw", escaped_valid_key: "valid"}, ensure_ascii=False
    ).encode("utf-8")


@pytest.mark.skipif(os.name == "nt", reason="raw-byte filenames are unavailable on Windows")
def test_real_non_utf8_git_filename_survives_snapshot_delta_hash_and_storage(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "raw-path-repo"
    repo.mkdir()

    def git(*args: str) -> None:
        subprocess.run(
            ["git", *args], cwd=repo, check=True, capture_output=True
        )

    git("init", "-q")
    git("config", "user.name", "Supervisor Test")
    git("config", "user.email", "supervisor@example.invalid")
    (repo / "seed.txt").write_text("seed\n", encoding="utf-8")
    git("add", "seed.txt")
    git("commit", "-qm", "seed")
    baseline = capture_workspace_snapshot(str(repo))

    raw_relative = b"raw-\xff.txt"
    raw_path = os.path.join(os.fsencode(repo), raw_relative)
    fd = os.open(raw_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(fd, b"raw-name\n")
    finally:
        os.close(fd)
    expected_raw_key = f"{_RAW_WORKSPACE_PATH_PREFIX}{raw_relative.hex()}"
    collision = repo / expected_raw_key
    collision.write_text("valid utf-8 collision candidate\n", encoding="utf-8")

    current = capture_workspace_snapshot(str(repo))
    escaped_collision = _persistent_workspace_path(expected_raw_key)
    assert expected_raw_key in current["files"]
    assert escaped_collision in current["files"]
    assert expected_raw_key != escaped_collision
    assert current["snapshot_hash"] == capture_workspace_snapshot(str(repo))["snapshot_hash"]

    delta = workspace_delta(baseline, current)
    assert expected_raw_key in delta["files"]
    assert escaped_collision in delta["files"]
    canonical_sha256(delta)
    json.dumps(delta, ensure_ascii=False, sort_keys=True).encode("utf-8")
    destination = tmp_path / "raw-snapshot.json"
    atomic_write_json(destination, {"snapshot": current, "delta": delta})
    persisted = json.loads(destination.read_text(encoding="utf-8"))
    assert expected_raw_key in persisted["snapshot"]["files"]
