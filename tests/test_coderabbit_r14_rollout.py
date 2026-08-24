from __future__ import annotations

import json
from pathlib import Path

import pytest

from supervisor_core.rollout import (
    active_version_snapshot,
    resolve_active_root,
    rollback_active_version,
)
from supervisor_core.runtime_bundle import build_runtime_bundle, release_identity


def _release(path: Path, version: str) -> dict[str, str]:
    package = path / "supervisor_core"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("VERSION = 'fixture'\n", encoding="utf-8")
    (package / "cli.py").write_text("def main():\n    return 0\n", encoding="utf-8")
    bundle = build_runtime_bundle(path, version)
    bundle_path = path / "runtime" / "supervisor-runtime.zip"
    bundle_path.parent.mkdir(parents=True)
    bundle_path.write_bytes(bundle)
    return release_identity(path, version, "runtime/supervisor-runtime.zip", bundle)


def _pointer(path: Path, active: dict[str, str], previous=None, *, contract="ActiveVersionPointer/v4") -> None:
    path.write_text(
        json.dumps({"contract": contract, "active": active, "previous": previous}),
        encoding="utf-8",
    )


def test_v4_pointer_resolves_only_a_real_deterministic_bundle(tmp_path, monkeypatch):
    fallback = tmp_path / "fallback"
    active_root = tmp_path / "active"
    _release(fallback, "fallback")
    active = _release(active_root, "4.0.0")
    pointer = tmp_path / "active-version.json"
    _pointer(pointer, active)
    monkeypatch.setenv("AGENT_SUPERVISOR_ACTIVE_POINTER", str(pointer))

    assert resolve_active_root(fallback) == active_root.resolve()
    assert active_version_snapshot() == active


@pytest.mark.parametrize("corruption", ["bundle", "identity"])
def test_corrupt_bundle_or_identity_is_not_an_active_snapshot(
    tmp_path, monkeypatch, corruption
):
    fallback = tmp_path / "fallback"
    active_root = tmp_path / "active"
    _release(fallback, "fallback")
    active = _release(active_root, "4.0.0")
    if corruption == "bundle":
        bundle_path = active_root / active["bundle_relpath"]
        payload = bytearray(bundle_path.read_bytes())
        payload[-1] ^= 0x01
        bundle_path.write_bytes(bytes(payload))
    else:
        active["manifest_sha256"] = "0" * 64
    pointer = tmp_path / "active-version.json"
    _pointer(pointer, active)
    monkeypatch.setenv("AGENT_SUPERVISOR_ACTIVE_POINTER", str(pointer))

    assert resolve_active_root(fallback) == fallback.resolve()
    assert active_version_snapshot() is None


def test_wrong_outer_pointer_contract_fails_closed(tmp_path, monkeypatch):
    fallback = tmp_path / "fallback"
    active_root = tmp_path / "active"
    _release(fallback, "fallback")
    active = _release(active_root, "4.0.0")
    pointer = tmp_path / "active-version.json"
    _pointer(pointer, active, contract="ActiveVersionPointer/v3")
    monkeypatch.setenv("AGENT_SUPERVISOR_ACTIVE_POINTER", str(pointer))

    assert resolve_active_root(fallback) == fallback.resolve()
    assert active_version_snapshot() is None


def test_inflight_snapshot_cannot_roll_back_a_rotated_pointer(tmp_path, monkeypatch):
    release_a = _release(tmp_path / "release-a", "4.0.0")
    release_b = _release(tmp_path / "release-b", "4.1.0")
    previous = _release(tmp_path / "previous", "3.1.0")
    pointer = tmp_path / "active-version.json"
    _pointer(pointer, release_a, previous)
    monkeypatch.setenv("AGENT_SUPERVISOR_ACTIVE_POINTER", str(pointer))
    snapshot_a = active_version_snapshot()
    assert snapshot_a == release_a

    _pointer(pointer, release_b, release_a)
    before = pointer.read_bytes()
    result = rollback_active_version(expected_active=snapshot_a)

    assert result["performed"] is False
    assert result["reason"] == "active-version-cas-mismatch"
    assert pointer.read_bytes() == before
