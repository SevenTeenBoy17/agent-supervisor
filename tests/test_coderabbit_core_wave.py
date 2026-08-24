from __future__ import annotations

import copy
import json
import os
import subprocess
import time
from argparse import Namespace
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

import supervisor_core.storage as storage_module
import supervisor_core.cli as cli_module
from supervisor_core.attestation import sign_record
from supervisor_core.cli import (
    InvalidState,
    _gate_timeout_seconds,
    _known_write_paths,
    _reject_sensitive_contract_input,
    _t3_command_action,
)
from supervisor_core.contracts import build_goal, normalize_intents
from supervisor_core.discovery import baseline_report, write_baseline
from supervisor_core.rollout import apply_observation, initial_rollout, promote
from supervisor_core.routing import route_intents
from supervisor_core.storage import StateContext, atomic_write_json, exclusive_lock, prune_old_state
from supervisor_core.util import canonical_sha256, json_load, sha256_text
from supervisor_core.validation import (
    _is_test_path,
    _path_allowed,
    _registered_gate_definitions,
    _validate_evidence,
    _validate_gate_registry,
    validate_state,
)
from supervisor_core.workspace import _hash_workspace_entry, path_matches_lease


def _context(tmp_path: Path) -> StateContext:
    return StateContext.build(
        runtime="test",
        project="core-wave",
        workspace=str(tmp_path),
        session="session",
        round_id="round",
        state_root=tmp_path / "state-root",
    )


def _observation(observation_id: str, kind: str, **values: object) -> dict[str, object]:
    record: dict[str, object] = {
        "contract": "RolloutObservation/v3",
        "observation_id": observation_id,
        "kind": kind,
        "source_contract": "RoundFinalization/v3",
        "source_id": f"source-{observation_id}",
        **values,
    }
    record["attestation"] = sign_record(record)
    return record


@pytest.mark.parametrize(
    "tool_name",
    ["WriteFileV2", "write_file_v2", "mcp__filesystem__edit-v3", "notebook_edit@2"],
)
def test_versioned_write_tool_names_still_trigger_path_extraction(tool_name: str) -> None:
    assert _known_write_paths(tool_name, {"file_path": "src/owned.py"}) == ["src/owned.py"]


def test_versioned_read_tool_does_not_become_a_write_tool() -> None:
    assert _known_write_paths("read_file_v2", {"file_path": "src/owned.py"}) == []


def test_safe_hash_bound_authorization_survives_persistence_unchanged(tmp_path: Path) -> None:
    source = "SUPERVISOR-WAIVE criterion-1"
    value = {
        "waivers": [{
            "source_authorization": source,
            "source_authorization_sha256": sha256_text(source),
        }]
    }
    destination = tmp_path / "safe.json"
    atomic_write_json(destination, value)
    assert json.loads(destination.read_text(encoding="utf-8")) == value


def test_sensitive_hash_bound_authorization_is_rejected_without_persistence(tmp_path: Path) -> None:
    source = "SUPERVISOR-WAIVE criterion-1 token=DO-NOT-PERSIST"
    destination = tmp_path / "unsafe.json"
    with pytest.raises(ValueError, match="sensitive-integrity-bound-record"):
        atomic_write_json(destination, {
            "source_authorization": source,
            "source_authorization_sha256": sha256_text(source),
        })
    assert not destination.exists()


def test_sensitive_contract_input_is_rejected_before_round_side_effects() -> None:
    _reject_sensitive_contract_input("review the authorization boundary", "prompt")
    with pytest.raises(InvalidState, match="cannot be persisted"):
        _reject_sensitive_contract_input("rotate token=DO-NOT-PERSIST", "prompt")


def test_sensitive_goal_cannot_be_redacted_after_request_manifest_binding(valid_bundle, tmp_path: Path) -> None:
    state, _ = copy.deepcopy(valid_bundle)
    state["goal"]["objective"] = "rotate token=DO-NOT-PERSIST"
    manifest = state["request_manifest"]
    manifest["goal_sha256"] = canonical_sha256(state["goal"])
    manifest["attestation"] = sign_record(manifest)
    ctx = _context(tmp_path)
    with pytest.raises(ValueError, match="sensitive-integrity-bound-record"):
        ctx.save(state)
    assert not ctx.state_file.exists()


def test_partial_self_created_lock_is_removed_and_next_attempt_succeeds(tmp_path: Path, monkeypatch) -> None:
    lock_path = tmp_path / "partial.lock"
    real_open = storage_module.os.open
    real_write = storage_module.os.write
    real_close = storage_module.os.close
    target_fds: set[int] = set()
    faulted = False

    def track_lock_fd(path, *args, **kwargs) -> int:
        fd = real_open(path, *args, **kwargs)
        candidate = Path(path)
        if (
            candidate.parent == lock_path.parent
            and candidate.name.startswith(f".{lock_path.name}.")
            and candidate.name.endswith(".owner.tmp")
        ):
            target_fds.add(fd)
        return fd

    def fail_once(fd: int, payload: bytes) -> int:
        nonlocal faulted
        if fd in target_fds and not faulted:
            faulted = True
            real_write(fd, payload[:7])
            raise OSError("simulated partial lock write")
        return real_write(fd, payload)

    def track_close(fd: int) -> None:
        try:
            real_close(fd)
        finally:
            target_fds.discard(fd)

    monkeypatch.setattr(storage_module.os, "open", track_lock_fd)
    monkeypatch.setattr(storage_module.os, "write", fail_once)
    monkeypatch.setattr(storage_module.os, "close", track_close)
    read_fd, write_fd = os.pipe()
    try:
        unrelated = b"unrelated-descriptor-write"
        assert storage_module.os.write(write_fd, unrelated) == len(unrelated)
    finally:
        os.close(write_fd)
        os.close(read_fd)
    with pytest.raises(OSError, match="simulated partial"):
        with exclusive_lock(lock_path, timeout=0.2):
            pass
    assert not target_fds
    assert not lock_path.exists()
    with exclusive_lock(lock_path, timeout=0.5):
        assert lock_path.exists()
    assert not target_fds


def test_short_lock_write_is_completed_before_acquisition(tmp_path: Path, monkeypatch) -> None:
    lock_path = tmp_path / "short-write.lock"
    real_open = storage_module.os.open
    real_write = storage_module.os.write
    real_close = storage_module.os.close
    target_fds: set[int] = set()

    def track_lock_fd(path, *args, **kwargs) -> int:
        fd = real_open(path, *args, **kwargs)
        candidate = Path(path)
        if (
            candidate.parent == lock_path.parent
            and candidate.name.startswith(f".{lock_path.name}.")
            and candidate.name.endswith(".owner.tmp")
        ):
            target_fds.add(fd)
        return fd

    def short_write(fd: int, payload: bytes) -> int:
        if fd in target_fds:
            return real_write(fd, payload[: max(1, len(payload) // 3)])
        return real_write(fd, payload)

    def track_close(fd: int) -> None:
        try:
            real_close(fd)
        finally:
            target_fds.discard(fd)

    monkeypatch.setattr(storage_module.os, "open", track_lock_fd)
    monkeypatch.setattr(storage_module.os, "write", short_write)
    monkeypatch.setattr(storage_module.os, "close", track_close)
    read_fd, write_fd = os.pipe()
    try:
        unrelated = b"unrelated-descriptor-write"
        assert storage_module.os.write(write_fd, unrelated) == len(unrelated)
    finally:
        os.close(write_fd)
        os.close(read_fd)
    with exclusive_lock(lock_path, timeout=0.5):
        owner = json.loads(lock_path.read_text(encoding="utf-8"))
        assert owner["owner_nonce"]
    assert not target_fds

    # A later unrelated descriptor may reuse the same integer. Closed owner
    # descriptors must not remain marked as short-write targets.
    unrelated_path = tmp_path / "fd-reuse-counterexample.bin"
    unrelated_fd = real_open(
        unrelated_path,
        os.O_CREAT | os.O_WRONLY | os.O_TRUNC,
        0o600,
    )
    try:
        unrelated = b"full-unrelated-write"
        assert storage_module.os.write(unrelated_fd, unrelated) == len(unrelated)
    finally:
        storage_module.os.close(unrelated_fd)
    assert unrelated_path.read_bytes() == b"full-unrelated-write"


def test_self_created_lock_cleanup_preserves_replacement_owner(tmp_path: Path) -> None:
    lock_path = tmp_path / "replacement.lock"
    lock_path.write_bytes(b"")
    original = storage_module._lock_snapshot(lock_path)
    assert original is not None
    lock_path.unlink()
    replacement = b'{"owner_nonce":"replacement"}'
    lock_path.write_bytes(replacement)
    assert storage_module._release_self_created_lock(lock_path, original[0], b'{"owner_nonce":"ours"}') is False
    assert lock_path.read_bytes() == replacement


def test_test_prefix_is_anchored_to_filename_start() -> None:
    assert _is_test_path("src/test_market.py") is True
    assert _is_test_path("src/market.test.ts") is True
    assert _is_test_path("src/contest_market.py") is False
    assert _is_test_path("src/latest_snapshot.py") is False


def test_workspace_parent_walk_terminates_for_entry_outside_root(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    assert _hash_workspace_entry(root, outside, "outside.txt") == sha256_text(
        "unsafe-or-unreadable-entry:outside.txt"
    )


def test_path_globs_are_case_sensitive_on_every_platform() -> None:
    assert path_matches_lease("src/Agent.py", ["src/**"]) is True
    assert path_matches_lease("Src/Agent.py", ["src/**"]) is False
    assert _path_allowed("Src/Agent.py", ["src/**"]) is False


def test_cross_project_enforce_requires_at_least_one_real_round() -> None:
    state = initial_rollout({
        "rollout": {
            "cross_project_default": {
                "mode": "observe",
                "promotion_requires_nontrivial_rounds": 0,
                "max_false_block_rate": 0.02,
                "critical_misses": 0,
            }
        }
    }, "observe")
    apply_observation(state, _observation("fixtures", "fixture_replay", passed=True))
    apply_observation(state, _observation("history", "historical_replay", passed=True))
    assert state["promotion"]["eligible_enforce"] is False
    apply_observation(state, _observation(
        "round", "round_outcome", nontrivial=True, critical_miss=False, false_block=False
    ))
    assert state["promotion"]["eligible_enforce"] is True


def test_invalid_global_gate_result_is_rejected_before_any_state_mutation() -> None:
    state = initial_rollout({}, "observe")
    before = copy.deepcopy(state)
    record = _observation(
        "invalid-global", "global_gate", result="maybe",
        active_version={"version": "3.1.0", "path": "C:/release"},
    )
    with pytest.raises(ValueError, match="result invalid"):
        apply_observation(state, record)
    assert state == before


def test_missing_required_group_does_not_route_to_unrelated_top_match() -> None:
    routed = route_intents(
        message="review the API",
        supplied_intents=[{
            "intent_id": "intent-1",
            "text": "review the API",
            "domain": "review",
            "required_responsibility_groups": ["independent-review"],
        }],
        inventory={"capabilities": [{
            "id": "engineering-backend-architect",
            "description": "API review and backend implementation",
            "responsibility_group": "implementation",
        }]},
    )
    assert routed["selected_capabilities"] == []
    assert routed["coverage"][0]["status"] == "skipped"
    assert "independent-review" in routed["coverage"][0]["reason"]


def test_bounded_glob_requires_a_fixed_leading_segment() -> None:
    schema = json.loads(
        (Path(__file__).resolve().parents[1] / "supervisor_core" / "schemas" / "project-config.schema.json")
        .read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema)

    def config(pattern: str) -> dict[str, object]:
        return {
            "$schema": "schemas/project.schema.json",
            "project_id": "bounded-glob",
            "supervisor_scope": {
                "allowed_change_globs": [pattern],
                "out_of_scope_globs": [],
            },
        }

    assert list(validator.iter_errors(config("src/**"))) == []
    assert list(validator.iter_errors(config(".agent-supervisor/**"))) == []
    for unbounded in ("**/src/**", "*/src/**", "[ab]/src/**", "./*/src/**"):
        assert list(validator.iter_errors(config(unbounded))), unbounded


def test_duplicate_gate_ids_and_unknown_builtins_are_rejected() -> None:
    errors: list[str] = []
    _validate_gate_registry({
        "common_gates": [
            {"id": "gate.same", "command": ["python", "-V"]},
            {"id": "gate.same", "command": ["python", "-V"]},
        ],
        "gates": [{"id": "gate.unknown", "builtin": "trust-caller"}],
    }, errors)
    assert "duplicate quality gate id: gate.same" in errors
    assert "quality gate gate.unknown has unsupported builtin" in errors


def test_non_string_started_at_is_reported_not_raised(valid_bundle) -> None:
    state, events = copy.deepcopy(valid_bundle)
    state["started_at"] = {"unexpected": "object"}
    result = validate_state(state, events)
    assert result["valid"] is False
    assert "state started_at invalid" in result["errors"]


def test_prune_tolerates_file_disappearing_between_stat_and_unlink(tmp_path: Path, monkeypatch) -> None:
    rotated = tmp_path / "round" / "events.1.jsonl"
    rotated.parent.mkdir()
    rotated.write_text("{}\n", encoding="utf-8")
    os.utime(rotated, (0, 0))
    real_stat = Path.stat
    raced = False

    def racing_stat(path: Path, *args, **kwargs):
        nonlocal raced
        result = real_stat(path, *args, **kwargs)
        if path == rotated and not raced:
            raced = True
            path.unlink()
        return result

    monkeypatch.setattr(Path, "stat", racing_stat)
    assert prune_old_state(tmp_path, retention_days=1) == 0
    assert raced is True


def test_event_ledger_uses_durable_append_without_inode_replacement(tmp_path: Path, monkeypatch) -> None:
    ctx = _context(tmp_path)
    real_open = storage_module.os.open
    real_fsync = storage_module.os.fsync
    real_atomic_write = storage_module.atomic_write_bytes
    append_flags: list[int] = []
    event_fds: set[int] = set()
    event_fsyncs = 0

    def tracking_open(path, flags, *args, **kwargs):
        fd = real_open(path, flags, *args, **kwargs)
        if Path(path) == ctx.events_file:
            append_flags.append(flags)
            event_fds.add(fd)
        return fd

    def tracking_fsync(fd: int) -> None:
        nonlocal event_fsyncs
        if fd in event_fds:
            event_fsyncs += 1
        real_fsync(fd)

    def reject_event_replace(path, payload, *args, **kwargs):
        assert Path(path) != ctx.events_file, "events.jsonl must not use read-rewrite replacement"
        return real_atomic_write(path, payload, *args, **kwargs)

    monkeypatch.setattr(storage_module.os, "open", tracking_open)
    monkeypatch.setattr(storage_module.os, "fsync", tracking_fsync)
    monkeypatch.setattr(storage_module, "atomic_write_bytes", reject_event_replace)

    recorded = ctx.append_event({"event_type": "durable-append"})
    assert recorded["sequence"] == 1
    assert any(flags & os.O_APPEND for flags in append_flags)
    assert event_fsyncs >= 1
    assert json.loads(ctx.events_file.read_text(encoding="utf-8"))["event_type"] == "durable-append"


def test_event_sequence_recovers_when_sidecar_is_stale_or_malformed(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    assert ctx.append_event({"event_type": "one"})["sequence"] == 1
    assert ctx.append_event({"event_type": "two"})["sequence"] == 2
    (ctx.root / "event-sequence.json").write_text('{"last_sequence":"broken"}\n', encoding="utf-8")
    assert ctx.append_event({"event_type": "three"})["sequence"] == 3
    assert [row["sequence"] for row in ctx.events()] == [1, 2, 3]


@pytest.mark.parametrize(
    ("state_factory", "requested", "message"),
    [
        (lambda: initial_rollout({}, "observe"), "invalid", "move forward"),
        (lambda: initial_rollout({}, "observe"), "enforce", "skip"),
        (lambda: initial_rollout({}, "observe"), "warn", "metrics"),
        (
            lambda: {**initial_rollout({}, "warn"), "active_mode": "warn"},
            "observe",
            "move forward",
        ),
    ],
)
def test_failed_rollout_promotion_is_side_effect_free(state_factory, requested: str, message: str) -> None:
    state = state_factory()
    before = copy.deepcopy(state)
    with pytest.raises(ValueError, match=message):
        promote(state, requested)
    assert state == before


def test_rollout_reuse_normalizes_modes_and_rejects_corrupt_active_mode() -> None:
    previous = initial_rollout({}, "observe")
    previous["active_mode"] = " ENFORCE "
    normalized = initial_rollout({}, " WARN ", previous)
    assert normalized["active_mode"] == "enforce"
    assert normalized["requested_mode"] == "warn"

    previous["active_mode"] = "mystery"
    with pytest.raises(ValueError, match="active mode invalid"):
        initial_rollout({}, "observe", previous)


@pytest.mark.parametrize("payload", [b"{not-json", b'\xff\xfe{"value":1}'])
def test_json_load_returns_default_for_malformed_or_non_utf8_state(tmp_path: Path, payload: bytes) -> None:
    path = tmp_path / "state.json"
    path.write_bytes(payload)
    sentinel = {"safe": "default"}
    assert json_load(path, sentinel) is sentinel


def test_json_load_returns_default_for_read_oserror(tmp_path: Path) -> None:
    sentinel = object()
    assert json_load(tmp_path, sentinel) is sentinel


def test_evidence_validity_is_scoped_to_each_record_not_id_prefix(valid_bundle) -> None:
    state, events = copy.deepcopy(valid_bundle)
    bad = copy.deepcopy(state["evidence"][0])
    bad["evidence_id"] = "evidence-10"
    bad["exit_code"] = 7
    state["evidence"] = [bad, copy.deepcopy(state["evidence"][0])]
    errors: list[str] = []

    _, _, satisfied = _validate_evidence(state, {"criterion-1"}, events, errors)

    assert "evidence evidence-10 command failed" in errors
    assert satisfied["criterion-1"] == {"lint"}


def test_commandless_builtin_keeps_canonical_pseudo_command() -> None:
    definitions = _registered_gate_definitions({
        "gates": [{"id": "gate.finalize", "builtin": "goal-finalize"}],
    })
    assert definitions["gate.finalize"] == {
        "command": ["supervisor-builtin", "goal-finalize"],
        "precondition": None,
        "builtin": "goal-finalize",
    }


def test_omitted_domain_and_criterion_id_are_consistent_and_stable() -> None:
    first = build_goal(
        "verify output",
        change_mode="replace",
        supplied={"acceptance_criteria": [{"description": "binary output is verified"}]},
    )
    criterion = first["acceptance_criteria"][0]
    assert criterion["domain"] == "general"
    assert normalize_intents([{"text": "binary output is verified"}])[0]["domain"] == "general"

    second = build_goal(
        "continue verification",
        change_mode="continue",
        previous_goal=first,
        supplied={"acceptance_criteria": [{"description": "binary output is verified"}]},
    )
    assert len(second["acceptance_criteria"]) == 1
    assert second["acceptance_criteria"][0]["criterion_id"] == criterion["criterion_id"]


def test_legacy_sequential_criterion_is_not_duplicated_on_continue() -> None:
    previous = build_goal(
        "legacy goal",
        change_mode="replace",
        supplied={"acceptance_criteria": [{
            "criterion_id": "criterion-1",
            "description": "same semantic criterion",
            "domain": "general",
        }]},
    )
    continued = build_goal(
        "continue",
        change_mode="continue",
        previous_goal=previous,
        supplied={"acceptance_criteria": [{"description": "same semantic criterion"}]},
    )
    assert [row["criterion_id"] for row in continued["acceptance_criteria"]] == ["criterion-1"]


@pytest.mark.parametrize("newline", ["\n", "\r\n", "\r"])
def test_recursive_delete_is_detected_after_a_command_boundary(newline: str) -> None:
    action = _t3_command_action({"command": f"echo safe{newline}rm -rf exact-target"})
    assert action is not None
    assert action[0] == "recursive-delete"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [(None, 1200), (True, 1200), ("invalid", 1200), (-99, 1), (0, 1), (7, 7), (999999, 1800)],
)
def test_gate_timeout_is_parsed_and_clamped(raw, expected: int) -> None:
    assert _gate_timeout_seconds(raw) == expected


def test_baseline_reports_each_duplicate_version_hash_instead_of_name_only(tmp_path: Path) -> None:
    inventory = {
        "skills": [
            {
                "name": "duplicate-skill", "version": "1.0.0", "source": "fixture",
                "path": "C:/skills/v1/SKILL.md", "sha256": "1" * 64,
                "availability": "duplicate-inactive", "manual_only": False,
            },
            {
                "name": "duplicate-skill", "version": "2.0.0", "source": "fixture",
                "path": "C:/skills/v2/SKILL.md", "sha256": "2" * 64,
                "availability": "enabled", "manual_only": False,
            },
        ]
    }
    baseline = tmp_path / "baseline.json"
    write_baseline(inventory, baseline)
    changed = copy.deepcopy(inventory)
    changed["skills"][0]["sha256"] = "3" * 64

    report = baseline_report(changed, baseline)

    assert report["expected"] == report["actual"] == 2
    assert report["missing"] == []
    assert report["added"] == []
    assert len(report["changed"]) == 1

    removed = baseline_report({"skills": [copy.deepcopy(inventory["skills"][1])]}, baseline)
    assert len(removed["missing"]) == 1
    assert removed["missing"][0]["version"] == "1.0.0"
    assert removed["changed"] == []


def test_baseline_deduplicates_identical_inventory_rows(tmp_path: Path) -> None:
    row = {
        "name": "same", "version": "1.0.0", "source": "fixture", "path": "C:/same/SKILL.md",
        "sha256": "a" * 64, "availability": "enabled", "manual_only": False,
    }
    inventory = {"skills": [copy.deepcopy(row), copy.deepcopy(row)]}
    baseline = tmp_path / "baseline.json"
    write_baseline(inventory, baseline)
    assert len(json.loads(baseline.read_text(encoding="utf-8"))["skills"]) == 1
    report = baseline_report(inventory, baseline)
    assert report["expected"] == report["actual"] == 1


def test_finalize_exception_persists_degraded_incomplete_and_returns_four(tmp_path: Path, monkeypatch) -> None:
    ctx = _context(tmp_path)
    ctx.save({"execution_mode": "enforce", "stop_attempts": 0, "health": "healthy"})
    monkeypatch.setattr(cli_module, "_context", lambda *args, **kwargs: ctx)
    monkeypatch.setattr(cli_module, "_verify_current_source_snapshot", lambda *args, **kwargs: "snapshot")
    monkeypatch.setattr(cli_module, "finalize_round", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("boom")))

    code = cli_module.command_finalize(Namespace(stop_attempt=None, blocked=False))

    state = ctx.load()
    assert code == 4
    assert state["terminal_state"] == "incomplete"
    assert state["health"] == "degraded"
    assert state["host_gate"]["should_block"] is True
    assert any(row.get("event_type") == "round_finalize_degraded" for row in ctx.events())


def test_selftest_invocation_flag_is_independent_of_test_success(monkeypatch) -> None:
    tests_root = Path(cli_module.__file__).resolve().parents[1] / "tests"
    suites = sorted(path.name for path in tests_root.glob("test_*.py"))
    collect_output = "\n".join(f"tests/{name}::test_collected" for name in suites)
    calls = 0

    def fake_run(command, **kwargs):
        nonlocal calls
        calls += 1
        basetemp = Path(command[command.index("--basetemp") + 1])
        assert basetemp.parent.is_dir()
        if "--collect-only" in command:
            return subprocess.CompletedProcess(command, 0, stdout=collect_output, stderr="")
        return subprocess.CompletedProcess(command, 1, stdout="one test failed", stderr="")

    emitted: list[dict[str, object]] = []
    monkeypatch.setattr(cli_module.subprocess, "run", fake_run)
    monkeypatch.setattr(cli_module, "_emit", emitted.append)

    code = cli_module.command_selftest(Namespace())

    assert calls == 2
    assert code == 2
    assert emitted[0]["all_child_suites_invoked"] is True
    assert emitted[0]["collection_exit_code"] == 0


def test_installed_selftest_uses_bound_tests_and_never_writes_release(
    tmp_path: Path, monkeypatch
) -> None:
    data_root = tmp_path / "data" / ".agent-supervisor"
    data_root.mkdir(parents=True)
    trusted = tmp_path / "trusted" / "python.exe"
    trusted.parent.mkdir()
    trusted.write_bytes(b"trusted-python\n")
    release = tmp_path / "releases" / "v3.1.1"
    release.mkdir(parents=True)
    sentinel = release / "immutable.txt"
    sentinel.write_text("unchanged", encoding="utf-8")
    resources = {
        "supervisor_core/__init__.py": b"BOUND = True\n",
        "tests/test_bound_canary.py": b"def test_bound_canary():\n    assert True\n",
    }
    registry = {
        "registry_path": str(data_root / "trusted-executables.json"),
        "registry_sha256": "a" * 64,
        "entries": {
            "python": {
                "kind": "local",
                "path": str(trusted.resolve()),
                "sha256": "b" * 64,
            }
        },
    }
    observed: dict[str, object] = {}

    def fake_execute(root: Path, base_temp: Path, *, environment=None) -> int:
        observed["root"] = root
        observed["base_temp"] = base_temp
        assert root != Path(cli_module.__file__).resolve().parents[1]
        assert root.is_relative_to(data_root / ".selftest-tmp")
        assert (root / "tests" / "test_bound_canary.py").read_bytes() == resources[
            "tests/test_bound_canary.py"
        ]
        assert base_temp.is_relative_to(data_root / ".selftest-tmp")
        assert environment["PYTHONPATH"] == str(root)
        assert environment["TEMP"] == str(base_temp)
        assert not any(path.is_relative_to(release) for path in (root, base_temp))
        return 0

    monkeypatch.setattr(cli_module, "load_trusted_executable_registry", lambda: registry)
    monkeypatch.setattr(cli_module, "bound_resource_map", lambda: resources)
    monkeypatch.setattr(cli_module, "_execute_selftest", fake_execute)

    assert cli_module.command_selftest(Namespace()) == 0
    assert sentinel.read_text(encoding="utf-8") == "unchanged"
    assert not Path(observed["root"]).exists()
    assert not Path(observed["base_temp"]).exists()
