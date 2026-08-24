from __future__ import annotations

import json
from pathlib import Path

from supervisor_core import cli as cli_module
from supervisor_core.finalize import finalize_round
from supervisor_core.lifecycle import start_round
from supervisor_core.rollout import rollback_active_version
from supervisor_core.runtime_bundle import build_runtime_bundle, release_identity
from supervisor_core.storage import StateContext, atomic_write_json


def test_rollback_rejects_directory_without_supervisor_release_markers(
    tmp_path, monkeypatch
):
    current = tmp_path / "current"
    previous = tmp_path / "previous"
    package = current / "supervisor_core"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("VERSION = 'fixture'\n", encoding="utf-8")
    (package / "cli.py").write_text("def main():\n    return 0\n", encoding="utf-8")
    bundle = build_runtime_bundle(current, "3.1.0")
    bundle_path = current / "runtime" / "supervisor-runtime.zip"
    bundle_path.parent.mkdir(parents=True)
    bundle_path.write_bytes(bundle)
    previous.mkdir()
    pointer = tmp_path / "active-version.json"
    expected_active = release_identity(
        current,
        "3.1.0",
        "runtime/supervisor-runtime.zip",
        bundle,
    )
    unavailable_previous = {
        **expected_active,
        "version": "3.0.0",
        "path": str(previous.resolve()),
    }
    pointer.write_text(
        json.dumps(
            {
                "contract": "ActiveVersionPointer/v4",
                "active": expected_active,
                "previous": unavailable_previous,
            }
        ),
        encoding="utf-8",
    )
    before = pointer.read_bytes()
    monkeypatch.setenv("AGENT_SUPERVISOR_ACTIVE_POINTER", str(pointer))

    result = rollback_active_version(expected_active=expected_active)

    assert result == {
        "performed": False,
        "reason": "previous-version-unavailable",
        "target": None,
    }
    assert pointer.read_bytes() == before


def test_start_round_recovers_corrupt_project_rollout_as_degraded(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    ctx = StateContext.build(
        runtime="codex",
        project="p",
        workspace=str(workspace),
        session="s",
        round_id="r",
        state_root=tmp_path / "state",
    )
    ctx.initialize()
    atomic_write_json(
        ctx.project_rollout_file,
        {"contract": "RolloutState/v3", "active_mode": "corrupt"},
    )

    state = start_round(
        ctx,
        message="recover corrupt rollout",
        change_mode="replace",
        execution_mode="observe",
        project_config={"project_id": "p"},
        quality_profile={},
    )

    assert state["rollout"]["active_mode"] == "observe"
    assert ctx.load_project_rollout()["active_mode"] == "observe"
    assert state["health"] == "degraded"
    assert any(
        event.get("event_type") == "rollout_start_degraded"
        and event.get("status") == "degraded"
        for event in ctx.events()
    )
    finalized, code = finalize_round(ctx)
    assert code == 4
    assert finalized["terminal_state"] == "incomplete"


def _migrate_args(source: Path, tmp_path: Path) -> list[str]:
    return [
        "migrate",
        "--source",
        str(source),
        "--runtime",
        "codex",
        "--workspace",
        str(tmp_path / "workspace"),
        "--session",
        "s",
        "--round",
        "r",
        "--state-root",
        str(tmp_path / "state"),
    ]


def test_migrate_rejects_single_reparse_file_before_read(tmp_path, monkeypatch):
    source = tmp_path / "legacy.json"
    source.write_text('{"safe": true}\n', encoding="utf-8")
    reads: list[Path] = []
    original_read_bytes = Path.read_bytes

    def reject_reparse(path: Path, *, label: str) -> None:
        if Path(path) == source:
            raise ValueError(f"{label} contains a symlink or reparse point")

    def track_read(path: Path) -> bytes:
        if path == source:
            reads.append(path)
        return original_read_bytes(path)

    monkeypatch.setattr(cli_module, "_reject_reparse_path", reject_reparse, raising=False)
    monkeypatch.setattr(Path, "read_bytes", track_read)

    assert cli_module.main(_migrate_args(source, tmp_path)) == 64
    assert reads == []


def test_migrate_rejects_rglob_reparse_entry_before_read(tmp_path, monkeypatch):
    source = tmp_path / "legacy"
    source.mkdir()
    linked_entry = source / "linked.json"
    linked_entry.write_text('{"safe": true}\n', encoding="utf-8")
    reads: list[Path] = []
    original_read_bytes = Path.read_bytes

    def reject_reparse(path: Path, *, label: str) -> None:
        if Path(path) == linked_entry:
            raise ValueError(f"{label} contains a symlink or reparse point")

    def track_read(path: Path) -> bytes:
        if path == linked_entry:
            reads.append(path)
        return original_read_bytes(path)

    monkeypatch.setattr(cli_module, "_reject_reparse_path", reject_reparse, raising=False)
    monkeypatch.setattr(Path, "read_bytes", track_read)

    assert cli_module.main(_migrate_args(source, tmp_path)) == 64
    assert reads == []
