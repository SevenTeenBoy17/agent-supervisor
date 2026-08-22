from __future__ import annotations

import copy
import json
import os
from pathlib import Path

import pytest

import supervisor_core.discovery as discovery_module
import supervisor_core.storage as storage_module
from supervisor_core.cli import (
    _initialize_cli_source_snapshot,
    _rollback_claim_lease_seconds,
    _t3_command_action,
    main,
)
from supervisor_core.discovery import RootSpec, parse_roots, scan_skills
from supervisor_core.lifecycle import _privacy_safe_previous_for_carry
from supervisor_core.routing import route_intents
from supervisor_core.storage import StateContext
from supervisor_core.util import sha256_text
from supervisor_core.validation import validate_state


def _context(tmp_path: Path) -> StateContext:
    return StateContext.build(
        runtime="codex",
        project="workspace",
        workspace=str(tmp_path / "workspace"),
        session="session-r2",
        round_id="round-r2",
        state_root=tmp_path / "state",
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("goal", "malformed"),
        ("acceptance_criteria", None),
        ("waiver_authorizations", None),
        ("waivers", None),
        ("changes", None),
        ("changes", "malformed"),
    ],
)
def test_malformed_goal_waiver_and_changes_records_fail_closed_without_crash(
    valid_bundle, field: str, value
) -> None:
    state, events = valid_bundle
    if field in {"acceptance_criteria", "waiver_authorizations"}:
        state["goal"][field] = value
    else:
        state[field] = value

    report = validate_state(state, events)

    assert report["valid"] is False
    assert report["errors"]


def test_valid_event_sequence_sidecar_avoids_full_ledger_scan(
    tmp_path: Path, monkeypatch
) -> None:
    ctx = _context(tmp_path)
    assert ctx.append_event({"event_type": "one"})["sequence"] == 1
    sidecar = json.loads((ctx.root / "event-sequence.json").read_text(encoding="utf-8"))
    assert sidecar["contract"] == "EventSequence/v3"
    real_read_bytes = Path.read_bytes

    def reject_ledger_scan(path: Path) -> bytes:
        if path.name.startswith("events") and path.suffix == ".jsonl":
            raise AssertionError("a valid sidecar must not trigger a full ledger scan")
        return real_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", reject_ledger_scan)
    assert ctx.append_event({"event_type": "two"})["sequence"] == 2


def test_stale_event_sequence_sidecar_recovers_from_ledger(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    assert ctx.append_event({"event_type": "one"})["sequence"] == 1
    sidecar_path = ctx.root / "event-sequence.json"
    sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
    sidecar["active_ledger_size"] -= 1
    sidecar_path.write_text(json.dumps(sidecar), encoding="utf-8")

    assert ctx.append_event({"event_type": "two"})["sequence"] == 2


def test_lock_creation_identity_is_captured_from_descriptor_before_write(
    tmp_path: Path, monkeypatch
) -> None:
    lock_path = tmp_path / "identity.lock"
    real_fstat = storage_module.os.fstat
    observed: dict[str, object] = {}

    def tracking_fstat(fd: int):
        metadata = real_fstat(fd)
        observed["descriptor_identity"] = (metadata.st_dev, metadata.st_ino)
        return metadata

    def successor_snapshot(path: Path):
        assert path == lock_path
        return (9_999_999, 8_888_888), b""

    def fail_write(fd: int, payload: bytes) -> int:
        raise OSError("simulated lock write failure")

    def capture_cleanup(path: Path, identity, owner_payload: bytes) -> bool:
        observed["cleanup_identity"] = identity
        path.unlink(missing_ok=True)
        return False

    monkeypatch.setattr(storage_module.os, "fstat", tracking_fstat)
    monkeypatch.setattr(storage_module, "_lock_snapshot", successor_snapshot)
    monkeypatch.setattr(storage_module.os, "write", fail_write)
    monkeypatch.setattr(storage_module, "_release_self_created_lock", capture_cleanup)

    with pytest.raises(OSError, match="simulated"):
        with storage_module._exclusive_file_lock(lock_path, timeout=0.1):
            pytest.fail("the failing writer cannot acquire the lock")

    assert observed["cleanup_identity"] == observed["descriptor_identity"]
    assert observed["cleanup_identity"] != (9_999_999, 8_888_888)


def test_legacy_carry_sanitizes_all_later_copied_free_text_idempotently() -> None:
    sentinel = "RAW-LEGACY-PROMPT-SENTINEL-R2"
    source_authorization_hash = sha256_text(sentinel)
    previous = {
        "round": "prior-round",
        "goal": {
            "goal_id": "goal-1",
            "version": 7,
            "objective": sentinel,
            "constraints": [sentinel],
            "non_goals": [sentinel],
            "assumptions": [sentinel],
            "risks": [sentinel],
            "acceptance_criteria": [{"criterion_id": "criterion-1", "description": sentinel}],
        },
        "intents": [{"intent_id": "intent-1", "text": sentinel, "reason": sentinel}],
        "tasks": [{"task_id": "task-1", "description": sentinel, "reason": sentinel}],
        "evidence": [{
            "evidence_id": "evidence-1",
            "output_summary": {"detail": sentinel, "nested": [{"arbitrary": sentinel}]},
            "precondition": {"output_summary": sentinel},
        }],
        "reviews": [{"review_id": "review-1", "summary": sentinel, "findings": [sentinel, {"detail": sentinel}]}],
        "claims": [{"claim_id": "claim-1", "source_locator": sentinel, "statement_sha256": "a" * 64}],
        "waivers": [{
            "waiver_id": "waiver-1",
            "source_authorization": sentinel,
            "source_authorization_sha256": source_authorization_hash,
            "reason": sentinel,
        }],
        "changes": {"files": ["safe/path.py"], "diff": sentinel, "diff_hash": "b" * 64},
        "spec": {"path": "spec.md", "content": sentinel, "hash": "c" * 64},
        "prior_rounds": [{
            "round": "nested-round",
            "tasks": [{"task_id": "nested-task", "description": sentinel}],
            "evidence": [{"evidence_id": "nested-evidence", "output_summary": sentinel}],
        }],
    }
    original = copy.deepcopy(previous)
    config = {"privacy": {"persist_raw_prompts": False}}

    carried = _privacy_safe_previous_for_carry(previous, config)

    assert sentinel not in json.dumps(carried, ensure_ascii=False)
    assert previous == original
    assert carried["goal"]["goal_id"] == "goal-1"
    assert carried["goal"]["version"] == 7
    assert carried["changes"]["files"] == ["safe/path.py"]
    assert carried["waivers"][0]["source_authorization_sha256"] == source_authorization_hash
    assert _privacy_safe_previous_for_carry(carried, config) == carried


def test_zero_skill_reviewed_flag_cannot_authorize_zero_skill_route() -> None:
    result = route_intents(
        message="no matching capability",
        inventory={"skills": []},
        zero_skill_reviewed=True,
    )
    assert result["zero_skill_reviewed"] is True
    assert result["review_required"] is True
    assert result["valid"] is False


def _write_skill(path: Path, *, name: str, version: str | None = None) -> None:
    path.mkdir(parents=True)
    version_line = f"version: {version}\n" if version is not None else ""
    (path / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: test duplicate\n{version_line}---\n# test\n",
        encoding="utf-8",
    )


def test_discovery_prefers_concrete_version_over_unknown(tmp_path: Path) -> None:
    root = tmp_path / "skills"
    _write_skill(root / "unknown-copy", name="same-skill")
    _write_skill(root / "known-copy", name="same-skill", version="1.2.3")

    inventory = scan_skills([RootSpec(root, "test")])
    active = [row for row in inventory["skills"] if row["name"] == "same-skill" and row["active"]]

    assert len(active) == 1
    assert active[0]["version"] == "1.2.3"


def test_claude_plugin_registry_rejects_empty_install_path(
    tmp_path: Path, monkeypatch
) -> None:
    home = tmp_path / "home"
    plugin_root = tmp_path / "ambient" / "skills" / "would-be-plugin"
    _write_skill(plugin_root, name="ambient-skill")
    registry_dir = home / ".claude" / "plugins"
    registry_dir.mkdir(parents=True)
    (registry_dir / "installed_plugins.json").write_text(json.dumps({
        "plugins": {"empty@example": [{"installPath": "", "version": "9.9.9"}]}
    }), encoding="utf-8")
    settings_dir = home / ".claude"
    (settings_dir / "settings.json").write_text(json.dumps({
        "enabledPlugins": {"empty@example": True}
    }), encoding="utf-8")
    monkeypatch.chdir(tmp_path / "ambient")
    monkeypatch.setattr(discovery_module.Path, "home", classmethod(lambda cls: home))

    roots = parse_roots([], "claude")

    assert not any(root.source.startswith("claude-plugin:") for root in roots)


def test_migration_retries_without_overwriting_partial_destination(
    tmp_path: Path, capsys
) -> None:
    source = tmp_path / "legacy-source"
    source.mkdir()
    (source / "state.json").write_text('{"safe":true}\n', encoding="utf-8")
    workspace = tmp_path / "workspace"
    state_root = tmp_path / "state"
    ctx = StateContext.build(
        runtime="codex",
        project=workspace.name,
        workspace=str(workspace),
        session="migration-r2",
        round_id="round-r2",
        state_root=state_root,
    )
    partial = ctx.root / "legacy" / f"import-{sha256_text(str(source.resolve()))[:12]}"
    partial.mkdir(parents=True)
    marker = partial / "partial.marker"
    marker.write_text("preserve me", encoding="utf-8")
    args = [
        "migrate", "--source", str(source), "--runtime", "codex",
        "--workspace", str(workspace), "--session", "migration-r2",
        "--round", "round-r2", "--state-root", str(state_root),
    ]

    assert main(args) == 0
    result = json.loads(capsys.readouterr().out)
    destination = Path(result["destination"])
    assert destination != partial
    assert marker.read_text(encoding="utf-8") == "preserve me"
    assert (destination / "manifest.json").exists()
    assert main(args) == 64
    assert "already exists" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("value", "expected"),
    [("bad", 30), (None, 30), ("0", 1), ("999999", 3600), (True, 30)],
)
def test_rollback_claim_lease_env_is_defensively_parsed(value, expected) -> None:
    assert _rollback_claim_lease_seconds(value) == expected


def test_goal_json_must_be_an_object(tmp_path: Path, capsys) -> None:
    exit_code = main([
        "start", "--runtime", "codex", "--workspace", str(tmp_path),
        "--session", "goal-json-r2", "--round", "round-r2",
        "--state-root", str(tmp_path / "state"), "--message", "goal",
        "--change-mode", "replace", "--goal-json", "[]",
    ])
    assert exit_code == 64
    assert "--goal-json must be an object" in capsys.readouterr().out


@pytest.mark.parametrize(
    "command",
    ["git push origin +main:main", ["git", "push", "origin", "+HEAD:main"]],
)
def test_plus_refspec_is_detected_as_force_push(command) -> None:
    assert _t3_command_action({"command": command})[0] == "force-push"


def test_hook_runtime_rejects_unknown_runtime(capsys) -> None:
    assert main(["hook", "--runtime", "other", "--event", "SessionStart"]) == 64
    assert "invalid choice" in capsys.readouterr().out


def test_source_snapshot_initialization_preserves_concurrent_state(
    tmp_path: Path
) -> None:
    ctx = _context(tmp_path)
    snapshot = {"contract": "SupervisorSourceSnapshot/v3", "status": "unavailable"}
    ctx.save({"supervisor_source_snapshot": copy.deepcopy(snapshot), "concurrent": "new"})
    stale = {"supervisor_source_snapshot": copy.deepcopy(snapshot), "concurrent": "old"}

    result = _initialize_cli_source_snapshot(ctx, stale, shadow=False)

    assert result["concurrent"] == "new"
    assert ctx.load()["concurrent"] == "new"
    assert ctx.load()["health"] == "degraded"
