from __future__ import annotations

from pathlib import Path

import pytest

import supervisor_core.cli as cli_module
import supervisor_core.lifecycle as lifecycle_module
import supervisor_core.storage as storage_module
from supervisor_core.attestation import sign_record, verify_record
from supervisor_core.cli import _apply_patch_write_paths
from supervisor_core.storage import StateContext
from supervisor_core.validation import _path_allowed, _pattern_within
from supervisor_core.workspace import path_matches_lease


@pytest.mark.parametrize(
    "patch",
    [
        "*** Begin Patch\n*** Add File: src/../escape.py\n+x = 1\n*** End Patch",
        (
            "*** Begin Patch\n*** Update File: src/current.py\n"
            "*** Move to: ../escape.py\n@@\n-old\n+new\n*** End Patch"
        ),
    ],
)
def test_apply_patch_rejects_parent_segments_in_headers_and_moves(patch: str) -> None:
    paths, error = _apply_patch_write_paths({"patch": patch})

    assert paths == []
    assert error == "apply_patch paths cannot contain parent traversal"


def test_short_attestation_key_is_rejected_without_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_file = tmp_path / "short-attestation.key"
    key_file.write_bytes(b"too-short")
    monkeypatch.setenv("AGENT_SUPERVISOR_ATTESTATION_KEY_FILE", str(key_file))

    before = key_file.read_bytes()
    with pytest.raises(RuntimeError, match="attestation key unavailable"):
        sign_record({"contract": "ConcurrentFixture/v3", "index": 1})

    assert key_file.read_bytes() == before
    assert not verify_record({
        "contract": "ConcurrentFixture/v3",
        "index": 1,
        "attestation": "0" * 64,
    })


def test_cli_snapshot_initialization_uses_lifecycle_failure_wrapper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable_capture() -> dict[str, object]:
        raise OSError("simulated source capture failure")

    monkeypatch.setattr(
        lifecycle_module.workspace_module,
        "capture_supervisor_source_snapshot",
        unavailable_capture,
    )
    ctx = StateContext.build(
        runtime="test",
        project="snapshot-wrapper",
        workspace=str(tmp_path),
        session="session",
        round_id="round",
        state_root=tmp_path / "state",
    )

    result = cli_module._initialize_cli_source_snapshot(ctx, {}, shadow=True)

    assert result["health"] == "degraded"
    assert result["supervisor_source_snapshot"] == {
        "contract": "SupervisorSourceSnapshot/v3",
        "status": "unavailable",
        "reason": "capture-failed:OSError",
    }


def test_legacy_unbound_lock_owner_is_never_probed_or_reclaimed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock_path = tmp_path / "legacy.lock"
    lock_path.write_bytes(b"424242 1.0")
    probes: list[int] = []

    def locally_dead(pid: int) -> tuple[str, None]:
        probes.append(pid)
        return "dead", None

    monkeypatch.setattr(storage_module, "_process_probe", locally_dead)

    assert storage_module._reclaim_confirmed_dead_lock(lock_path) is False
    assert lock_path.exists()
    assert probes == []


def test_segment_globs_keep_star_within_one_segment_and_double_star_recursive() -> None:
    shallow = "src/module.py"
    nested = "src/nested/module.py"

    assert _path_allowed(shallow, ["src/*"]) is True
    assert path_matches_lease(shallow, ["src/*"]) is True
    assert _path_allowed(nested, ["src/*"]) is False
    assert path_matches_lease(nested, ["src/*"]) is False
    assert _pattern_within(nested, "src/*") is False
    assert _pattern_within("src/**", "src/*") is False
    assert _pattern_within("src/*.py", "src/*") is True
    assert _path_allowed(nested, ["src/**"]) is True
    assert path_matches_lease(nested, ["src/**"]) is True
    assert _pattern_within(nested, "src/**") is True
