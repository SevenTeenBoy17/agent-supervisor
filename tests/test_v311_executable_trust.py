from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from supervisor_core import cli as cli_module
from supervisor_core import executable_trust as trust_module


def _write_registry(root: Path, executable: Path, digest: str) -> Path:
    registry = root / ".agent-supervisor" / "trusted-executables.json"
    registry.parent.mkdir(parents=True, exist_ok=True)
    registry.write_text(
        json.dumps({
            "contract": "TrustedExecutableRegistry/v1",
            "entries": {
                "runner": {
                    "kind": "local",
                    "path": str(executable.resolve()),
                    "sha256": digest,
                }
            },
            "generated_at": "2026-08-24T00:00:00Z",
        }, sort_keys=True),
        encoding="utf-8",
    )
    return registry


def test_large_executable_is_hashed_in_bounded_chunks(tmp_path: Path, monkeypatch) -> None:
    executable = tmp_path / "large-runner.exe"
    size = 65 * 1024 * 1024 + 17
    with executable.open("wb") as handle:
        handle.seek(size - 1)
        handle.write(b"x")
    digest = hashlib.sha256()
    with executable.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    registry_path = _write_registry(tmp_path, executable, digest.hexdigest())

    real_open = Path.open
    observed_reads: list[int] = []

    class BoundedReader:
        def __init__(self, wrapped):
            self._wrapped = wrapped

        def __enter__(self):
            self._wrapped.__enter__()
            return self

        def __exit__(self, *args):
            return self._wrapped.__exit__(*args)

        def read(self, size: int = -1):
            observed_reads.append(size)
            assert 0 <= size <= trust_module._HASH_CHUNK_BYTES
            return self._wrapped.read(size)

    def guarded_open(path: Path, *args, **kwargs):
        opened = real_open(path, *args, **kwargs)
        if Path(path) == executable and args and "r" in str(args[0]):
            return BoundedReader(opened)
        return opened

    monkeypatch.setattr(Path, "open", guarded_open)
    loaded = trust_module.load_trusted_executable_registry(registry_path)

    assert loaded["entries"]["runner"]["sha256"] == digest.hexdigest()
    assert len(observed_reads) > 64
    assert max(observed_reads) == trust_module._HASH_CHUNK_BYTES


def test_path_poisoning_is_ignored_and_unregistered_alias_fails(
    tmp_path: Path, monkeypatch
) -> None:
    trusted = tmp_path / "trusted" / "runner.exe"
    poisoned = tmp_path / "poison" / "runner.exe"
    trusted.parent.mkdir()
    poisoned.parent.mkdir()
    trusted.write_bytes(b"trusted-runner\n")
    poisoned.write_bytes(b"poisoned-runner\n")
    registry_path = _write_registry(
        tmp_path, trusted, hashlib.sha256(trusted.read_bytes()).hexdigest()
    )
    registry = trust_module.load_trusted_executable_registry(registry_path)
    monkeypatch.setenv("PATH", str(poisoned.parent) + os.pathsep + os.environ.get("PATH", ""))

    resolved, executable_path, digest = cli_module._resolve_gate_command(
        ["runner", "--safe"], cwd=str(tmp_path), trusted_registry=registry
    )

    assert Path(resolved[0]) == trusted.resolve()
    assert Path(executable_path) == trusted.resolve()
    assert digest == hashlib.sha256(trusted.read_bytes()).hexdigest()
    with pytest.raises(FileNotFoundError, match="round-bound trust registry"):
        cli_module._resolve_gate_command(
            ["unregistered", "--unsafe"], cwd=str(tmp_path), trusted_registry=registry
        )


def test_round_bound_registry_drift_is_rejected(tmp_path: Path, monkeypatch) -> None:
    executable = tmp_path / "runner.exe"
    executable.write_bytes(b"trusted-runner\n")
    registry_path = _write_registry(
        tmp_path, executable, hashlib.sha256(executable.read_bytes()).hexdigest()
    )
    monkeypatch.setenv("AGENT_SUPERVISOR_INSTALL_HOME", str(tmp_path))
    record = trust_module.registry_public_record(
        trust_module.load_trusted_executable_registry(registry_path)
    )
    payload = json.loads(registry_path.read_text(encoding="utf-8"))
    payload["generated_at"] = "2026-08-24T00:00:01Z"
    registry_path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")

    with pytest.raises(
        trust_module.ExecutableTrustError,
        match="trusted-executable-registry-drift",
    ):
        trust_module.verify_registry_record(record)
