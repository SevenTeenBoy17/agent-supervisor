from __future__ import annotations

import json
import sys
from contextlib import contextmanager
from pathlib import Path

import pytest

import supervisor_core.attestation as attestation_module
import supervisor_core.cli as cli_module
import supervisor_core.lifecycle as lifecycle_module
import supervisor_core.rollout as rollout_module
from supervisor_core.attestation import sign_record, verify_record
from supervisor_core.discovery import baseline_report, write_baseline
from supervisor_core.lifecycle import read_project_config, read_quality_profile, start_round
from supervisor_core.storage import StateContext


def _context(tmp_path: Path, round_id: str = "round-1") -> StateContext:
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    return StateContext.build(
        runtime="codex",
        project="r17",
        workspace=str(workspace),
        session="session",
        round_id=round_id,
        state_root=tmp_path / "state",
    )


def _gate_context(tmp_path: Path) -> StateContext:
    ctx = _context(tmp_path)
    start_round(
        ctx,
        message="run one registered gate",
        change_mode="replace",
        execution_mode="observe",
        quality_profile={
            "common_gates": [
                {
                    "id": "gate.atomic",
                    "command": [sys.executable, "-c", "raise SystemExit(0)"],
                }
            ]
        },
    )
    return ctx


def _gate_payload() -> dict[str, object]:
    return {
        "actor": "quality-runner",
        "record": {
            "gate_id": "gate.atomic",
            "criterion_id": "criterion-1",
            "collector_responsibility_group": "quality",
        },
    }


def test_gate_evidence_and_execution_use_one_state_event_transaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = _gate_context(tmp_path)
    original_transact = StateContext.transact
    transaction_calls: list[str] = []

    def tracked_transact(self, mutator, event):
        transaction_calls.append(str(event.get("event_type")))
        return original_transact(self, mutator, event)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("gate persistence must not split state and event writes")

    monkeypatch.setattr(cli_module, "_verify_current_source_snapshot", lambda *_args: "source-hash")
    monkeypatch.setattr(StateContext, "transact", tracked_transact)
    monkeypatch.setattr(StateContext, "update", forbidden)
    monkeypatch.setattr(StateContext, "append_event", forbidden)

    evidence, execution, code = cli_module._run_registered_gate(ctx, _gate_payload())

    assert code == 0
    assert transaction_calls == ["gate_execution"]
    assert any(row.get("evidence_id") == evidence["evidence_id"] for row in ctx.load()["evidence"])
    assert execution["execution_id"] in {
        row.get("execution_id") for row in ctx.events() if row.get("event_type") == "gate_execution"
    }


def test_gate_event_failure_cannot_commit_unaudited_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = _gate_context(tmp_path)
    before_state = ctx.state_file.read_bytes()
    before_events = ctx.events_file.read_bytes()
    original_append = StateContext._append_event_locked

    def fail_gate_event(self, event):
        if event.get("event_type") == "gate_execution":
            raise OSError("simulated ledger failure")
        return original_append(self, event)

    monkeypatch.setattr(cli_module, "_verify_current_source_snapshot", lambda *_args: "source-hash")
    monkeypatch.setattr(StateContext, "_append_event_locked", fail_gate_event)

    with pytest.raises(OSError, match="ledger failure"):
        cli_module._run_registered_gate(ctx, _gate_payload())

    assert ctx.state_file.read_bytes() == before_state
    assert ctx.events_file.read_bytes() == before_events


def test_start_round_does_not_advance_rollout_before_predecessor_transition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _context(tmp_path, "round-1")
    start_round(
        first,
        message="first round",
        change_mode="replace",
        execution_mode="observe",
        quality_profile={},
    )
    rollout_before = first.project_rollout_file.read_bytes()
    pointer = first.session_root / "current.json"
    pointer_before = pointer.read_bytes()
    update_calls = 0
    original_update = StateContext.update_project_rollout

    def tracked_update(self, mutator):
        nonlocal update_calls
        update_calls += 1
        return original_update(self, mutator)

    def reject_transition(*_args, **_kwargs):
        raise RuntimeError("simulated predecessor transition failure")

    monkeypatch.setattr(StateContext, "update_project_rollout", tracked_update)
    monkeypatch.setattr(lifecycle_module, "_transition_previous_state", reject_transition)
    second = _context(tmp_path, "round-2")

    with pytest.raises(RuntimeError, match="transition failure"):
        start_round(
            second,
            message="extend round",
            change_mode="extend",
            execution_mode="warn",
            quality_profile={},
        )

    assert update_calls == 0
    assert first.project_rollout_file.read_bytes() == rollout_before
    assert pointer.read_bytes() == pointer_before


def test_discovery_baseline_identity_is_relocatable_but_still_content_bound(
    tmp_path: Path,
) -> None:
    original = {
        "name": "portable-skill",
        "version": "1.2.3",
        "source": "codex-personal",
        "path": "C:/Users/first/.codex/skills/portable-skill/SKILL.md",
        "sha256": "a" * 64,
        "availability": "enabled",
        "manual_only": False,
    }
    baseline = tmp_path / "baseline.json"
    write_baseline({"skills": [original]}, baseline)

    relocated = {
        "skills": [
            {
                **original,
                "path": "D:/Profiles/second/.codex/skills/portable-skill/SKILL.md",
            }
        ]
    }
    report = baseline_report(relocated, baseline)
    assert report["missing"] == report["added"] == report["changed"] == []

    hash_drift = baseline_report(
        {"skills": [{**relocated["skills"][0], "sha256": "b" * 64}]},
        baseline,
    )
    assert len(hash_drift["changed"]) == 1

    version_drift = baseline_report(
        {"skills": [{**relocated["skills"][0], "version": "2.0.0"}]},
        baseline,
    )
    assert len(version_drift["changed"]) == 1

    source_drift = baseline_report(
        {"skills": [{**relocated["skills"][0], "source": "claude-personal"}]},
        baseline,
    )
    assert len(source_drift["missing"]) == 1
    assert len(source_drift["added"]) == 1


def _release_root(path: Path) -> Path:
    core = path / "supervisor_core"
    core.mkdir(parents=True)
    (core / "__init__.py").write_text("", encoding="utf-8")
    (core / "cli.py").write_text("", encoding="utf-8")
    return path


def test_resolve_active_root_reads_under_lock_and_rejects_non_release_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fallback = _release_root(tmp_path / "fallback")
    active = _release_root(tmp_path / "active")
    pointer = tmp_path / "active-version.json"
    pointer.write_text(
        json.dumps({"active": {"version": "4.0.0", "path": str(active)}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("AGENT_SUPERVISOR_ACTIVE_POINTER", str(pointer))
    original_lock = rollout_module.exclusive_lock
    lock_depth = 0
    observed_reads: list[bool] = []
    original_load = rollout_module.json_load

    @contextmanager
    def tracked_lock(path, *args, **kwargs):
        nonlocal lock_depth
        with original_lock(path, *args, **kwargs):
            lock_depth += 1
            try:
                yield
            finally:
                lock_depth -= 1

    def tracked_load(path, default):
        if Path(path) == pointer:
            observed_reads.append(lock_depth > 0)
        return original_load(path, default)

    monkeypatch.setattr(rollout_module, "exclusive_lock", tracked_lock)
    monkeypatch.setattr(rollout_module, "json_load", tracked_load)

    assert rollout_module.resolve_active_root(fallback) == active.resolve()
    assert observed_reads == [True]

    arbitrary = tmp_path / "arbitrary"
    arbitrary.mkdir()
    pointer.write_text(
        json.dumps({"active": {"version": "4.0.1", "path": str(arbitrary)}}),
        encoding="utf-8",
    )
    assert rollout_module.resolve_active_root(fallback) == fallback.resolve()


def test_existing_short_attestation_key_fails_closed_without_overwrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_file = tmp_path / "short.key"
    original = b"attacker-controlled-short-key"
    key_file.write_bytes(original)
    monkeypatch.setenv("AGENT_SUPERVISOR_ATTESTATION_KEY_FILE", str(key_file))

    with pytest.raises(RuntimeError, match="attestation key unavailable"):
        sign_record({"contract": "ShortKeyFixture/v3"})

    assert key_file.read_bytes() == original
    assert verify_record({"contract": "ShortKeyFixture/v3", "attestation": "0" * 64}) is False


def test_existing_unreadable_attestation_key_fails_closed_without_overwrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_file = tmp_path / "unreadable.key"
    original = b"x" * 32
    key_file.write_bytes(original)
    monkeypatch.setenv("AGENT_SUPERVISOR_ATTESTATION_KEY_FILE", str(key_file))
    original_read = Path.read_bytes

    def denied_read(path: Path) -> bytes:
        if path == key_file:
            raise PermissionError("simulated unreadable key")
        return original_read(path)

    monkeypatch.setattr(Path, "read_bytes", denied_read)

    with pytest.raises(RuntimeError, match="attestation key unavailable"):
        sign_record({"contract": "UnreadableKeyFixture/v3"})

    assert original_read(key_file) == original


def test_absent_attestation_key_is_created_once_and_is_usable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_file = tmp_path / "new" / "attestation.key"
    monkeypatch.setenv("AGENT_SUPERVISOR_ATTESTATION_KEY_FILE", str(key_file))
    record = {"contract": "NewKeyFixture/v3"}
    record["attestation"] = sign_record(record)

    assert key_file.is_file()
    assert len(key_file.read_bytes()) >= 32
    assert verify_record(record)


def test_selftest_cleans_temp_tree_when_collection_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed_base: list[Path] = []

    def explode(command, **_kwargs):
        base = Path(command[command.index("--basetemp") + 1]).parent
        observed_base.append(base)
        raise RuntimeError("simulated collection crash")

    monkeypatch.setattr(cli_module.subprocess, "run", explode)

    with pytest.raises(RuntimeError, match="collection crash"):
        cli_module.command_selftest(object())

    assert observed_base
    assert not observed_base[0].exists()


def test_relative_project_file_and_quality_profile_resolve_from_workspace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    config = workspace / "config"
    config.mkdir(parents=True)
    project_file = config / "project.json"
    quality_file = config / "quality.json"
    project_file.write_text("{}", encoding="utf-8")
    quality_file.write_text("{}", encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    observed: list[Path] = []

    def validated(path: Path, *, label: str, kind: str):
        observed.append(path)
        return {"quality_profile": "quality.json"} if kind == "project" else {"profile": "ok"}

    monkeypatch.setattr(lifecycle_module, "_validated_json_document", validated)

    project = read_project_config("config/project.json", str(workspace))
    quality = read_quality_profile(project, "config/project.json", str(workspace))

    assert quality == {"profile": "ok"}
    assert observed == [project_file.resolve(), quality_file.resolve()]
