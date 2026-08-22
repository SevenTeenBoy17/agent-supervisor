from __future__ import annotations

import builtins
import copy
import json
from pathlib import Path

import pytest

import supervisor_core.lifecycle as lifecycle_module
import supervisor_core.workspace as workspace_module
from supervisor_core.finalize import finalize_round
from supervisor_core.contracts import build_goal
from supervisor_core.lifecycle import read_project_config, read_quality_profile, start_round
from supervisor_core.storage import StateContext
from supervisor_core.util import sha256_bytes, sha256_text


def context(tmp_path: Path, round_id: str) -> StateContext:
    return StateContext.build(runtime="test", project="p", workspace=str(tmp_path / "workspace"), session="s", round_id=round_id, state_root=tmp_path / "state")


def write_schema_document(path: Path, *, required_key: str, extra: dict | None = None) -> Path:
    schema = path.parent / "schemas" / f"{path.stem}.schema.json"
    schema.parent.mkdir(parents=True, exist_ok=True)
    schema.write_text(
        json.dumps(
            {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "required": ["$schema", required_key],
                "properties": {
                    "$schema": {"type": "string", "minLength": 1},
                    required_key: {"type": "string", "minLength": 1},
                },
                "additionalProperties": True,
            }
        ),
        encoding="utf-8",
    )
    document = {"$schema": f"./schemas/{schema.name}", required_key: "valid"}
    document.update(extra or {})
    path.write_text(json.dumps(document), encoding="utf-8")
    return schema


def safe_scope() -> dict[str, list[str]]:
    return {"allowed_change_globs": ["config/**"], "out_of_scope_globs": ["secrets/**"]}


def safe_quality_controls() -> dict:
    return {
        "completion_policy": {
            "binary_only": True,
            "model_self_score_is_evidence": False,
            "validator_error_terminal": "degraded",
            "allowed_terminal_states": ["complete", "incomplete", "blocked", "user-waived"],
            "complete_requires_all_applicable_gates": True,
            "unresolved_p0_p1_blocks_complete": True,
        },
        "test_integrity": {
            "separate_review_required_for": ["assertion changed with implementation"],
            "green_tests_alone_are_sufficient": False,
        },
        "review": {
            "implementer_and_reviewer_groups_must_differ": True,
            "required_verdicts": ["APPROVE", "REQUEST_CHANGES", "NEEDS_DISCUSSION"],
            "record_must_bind": [
                "actor",
                "responsibility_group",
                "base",
                "head",
                "diff_hash",
                "rerun_evidence",
                "implementer_invocation_id",
                "reviewer_invocation_id",
                "actor_identity_assurance",
            ],
        },
    }


def test_project_and_quality_documents_validate_relative_schema_paths(tmp_path):
    project_path = tmp_path / "project.json"
    write_schema_document(project_path, required_key="project_id", extra={"supervisor_scope": safe_scope()})
    quality_path = tmp_path / "quality.json"
    write_schema_document(
        quality_path,
        required_key="profile_id",
        extra={
            **safe_quality_controls(),
            "global_gates": ["gate.test"],
            "common_gates": [{"id": "gate.test", "command": ["python", "-V"]}],
        },
    )

    project = read_project_config(str(project_path), str(tmp_path))
    quality = read_quality_profile(
        {"quality_profile": quality_path.name},
        str(project_path),
        str(tmp_path),
    )

    assert project["project_id"] == "valid"
    assert quality["profile_id"] == "valid"


def test_loaded_config_rejects_missing_schema_and_invalid_instance(tmp_path):
    missing_schema = tmp_path / "missing-schema.json"
    missing_schema.write_text(json.dumps({"project_id": "arbitrary"}), encoding="utf-8")
    with pytest.raises(ValueError, match=r"\$schema"):
        read_project_config(str(missing_schema), str(tmp_path))

    invalid = tmp_path / "invalid.json"
    schema = write_schema_document(invalid, required_key="project_id")
    invalid.write_text(json.dumps({"$schema": f"./schemas/{schema.name}", "project_id": ""}), encoding="utf-8")
    with pytest.raises(ValueError, match="validation failed"):
        read_project_config(str(invalid), str(tmp_path))


def test_config_loading_fails_closed_when_jsonschema_dependency_is_missing(tmp_path, monkeypatch):
    project_path = tmp_path / "project.json"
    write_schema_document(project_path, required_key="project_id", extra={"supervisor_scope": safe_scope()})
    real_import = builtins.__import__

    def blocked_import(name, *args, **kwargs):
        if name == "jsonschema":
            raise ImportError("blocked for test")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked_import)
    with pytest.raises(ValueError, match="jsonschema dependency"):
        read_project_config(str(project_path), str(tmp_path))


def test_weak_declared_schemas_cannot_bypass_core_contracts(tmp_path):
    schemas = tmp_path / "schemas"
    schemas.mkdir()
    weak_schema = schemas / "weak.schema.json"
    weak_schema.write_text(json.dumps({"type": "object"}), encoding="utf-8")

    project_path = tmp_path / "project.json"
    project_path.write_text(
        json.dumps({"$schema": "./schemas/weak.schema.json", "project_id": "unsafe"}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="core schema validation failed"):
        read_project_config(str(project_path), str(tmp_path))
    project_path.write_text(
        json.dumps({
            "$schema": "./schemas/weak.schema.json",
            "project_id": "unsafe",
            "supervisor_scope": {"allowed_change_globs": ["**"], "out_of_scope_globs": []},
        }),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="core schema validation failed"):
        read_project_config(str(project_path), str(tmp_path))

    quality_path = tmp_path / "quality.json"
    quality_path.write_text(
        json.dumps({
            "$schema": "./schemas/weak.schema.json",
            "global_gates": ["gate.invalid"],
            "common_gates": [{"id": "gate.invalid", "command": ["python", "-V"]}],
        }),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="completion_policy"):
        read_quality_profile(
            {"quality_profile": quality_path.name},
            str(project_path),
            str(tmp_path),
        )
    quality_path.write_text(
        json.dumps({
            "$schema": "./schemas/weak.schema.json",
            **safe_quality_controls(),
            "global_gates": ["gate.invalid"],
            "common_gates": [{"id": "gate.invalid", "command": []}],
        }),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="core schema validation failed"):
        read_quality_profile(
            {"quality_profile": quality_path.name},
            str(project_path),
            str(tmp_path),
        )
    quality_path.write_text(
        json.dumps({
            "$schema": "./schemas/weak.schema.json",
            **safe_quality_controls(),
            "global_gates": ["gate.missing"],
            "common_gates": [{"id": "gate.safe", "command": ["python", "-V"]}],
        }),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="unregistered required gates"):
        read_quality_profile(
            {"quality_profile": quality_path.name},
            str(project_path),
            str(tmp_path),
        )


def test_schema_reference_cannot_escape_config_directory_or_use_external_ref(tmp_path):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    outside = tmp_path / "outside.schema.json"
    outside.write_text(json.dumps({"type": "object"}), encoding="utf-8")
    project_path = config_dir / "project.json"
    project_path.write_text(
        json.dumps({"$schema": "../outside.schema.json", "project_id": "p", "supervisor_scope": safe_scope()}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="escape"):
        read_project_config(str(project_path), str(tmp_path))

    schemas = config_dir / "schemas"
    schemas.mkdir()
    external_ref = schemas / "external-ref.schema.json"
    external_ref.write_text(
        json.dumps({"type": "object", "$ref": "https://example.invalid/schema.json"}),
        encoding="utf-8",
    )
    project_path.write_text(
        json.dumps({
            "$schema": "./schemas/external-ref.schema.json",
            "project_id": "p",
            "supervisor_scope": safe_scope(),
        }),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="external.*ref"):
        read_project_config(str(project_path), str(tmp_path))
    project_path.write_text(
        json.dumps({
            "$schema": "./schemas/external-ref.schema.json:alternate",
            "project_id": "p",
            "supervisor_scope": safe_scope(),
        }),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="escape"):
        read_project_config(str(project_path), str(tmp_path))


def test_schema_reference_rejects_symlink_or_reparse_point(tmp_path):
    schemas = tmp_path / "schemas"
    schemas.mkdir()
    target = schemas / "target.schema.json"
    target.write_text(json.dumps({"type": "object"}), encoding="utf-8")
    linked = schemas / "linked.schema.json"
    try:
        linked.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation unavailable")
    project_path = tmp_path / "project.json"
    project_path.write_text(
        json.dumps({
            "$schema": "./schemas/linked.schema.json",
            "project_id": "p",
            "supervisor_scope": safe_scope(),
        }),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="symlink|reparse"):
        read_project_config(str(project_path), str(tmp_path))


def test_schema_reference_is_confined_to_sibling_schemas_root(tmp_path):
    direct_sibling = tmp_path / "project.schema.json"
    direct_sibling.write_text(json.dumps({"type": "object"}), encoding="utf-8")
    project_path = tmp_path / "project.json"
    project_path.write_text(
        json.dumps({
            "$schema": "./project.schema.json",
            "project_id": "p",
            "supervisor_scope": safe_scope(),
        }),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="sibling schemas"):
        read_project_config(str(project_path), str(tmp_path))


def test_schema_reference_reparse_guard_is_deterministic(tmp_path, monkeypatch):
    project_path = tmp_path / "project.json"
    schema = write_schema_document(project_path, required_key="project_id", extra={"supervisor_scope": safe_scope()})
    real_reparse_check = lifecycle_module._is_reparse_point
    monkeypatch.setattr(
        lifecycle_module,
        "_is_reparse_point",
        lambda path: path == schema or real_reparse_check(path),
    )
    with pytest.raises(ValueError, match="symlink|reparse"):
        read_project_config(str(project_path), str(tmp_path))


def test_project_and_quality_config_paths_reject_reparse_before_resolution(tmp_path, monkeypatch):
    project_path = tmp_path / "project.json"
    write_schema_document(project_path, required_key="project_id", extra={"supervisor_scope": safe_scope()})
    quality_path = tmp_path / "quality.json"
    write_schema_document(
        quality_path,
        required_key="profile_id",
        extra={
            **safe_quality_controls(),
            "global_gates": ["gate.test"],
            "common_gates": [{"id": "gate.test", "command": ["python", "-V"]}],
        },
    )
    real_reparse_check = lifecycle_module._is_reparse_point
    monkeypatch.setattr(
        lifecycle_module,
        "_is_reparse_point",
        lambda path: path == project_path or real_reparse_check(path),
    )
    with pytest.raises(ValueError, match="symlink|reparse"):
        read_project_config(str(project_path), str(tmp_path))

    monkeypatch.setattr(
        lifecycle_module,
        "_is_reparse_point",
        lambda path: path == quality_path or real_reparse_check(path),
    )
    with pytest.raises(ValueError, match="symlink|reparse"):
        read_quality_profile(
            {"quality_profile": quality_path.name},
            str(project_path),
            str(tmp_path),
        )


@pytest.mark.parametrize("failure", ["missing", "exception", "invalid"])
def test_source_snapshot_unavailable_degrades_start(tmp_path, monkeypatch, failure):
    if failure == "missing":
        monkeypatch.delattr(workspace_module, "capture_supervisor_source_snapshot", raising=False)
    elif failure == "exception":
        def fail_snapshot():
            raise OSError("source unavailable")

        monkeypatch.setattr(workspace_module, "capture_supervisor_source_snapshot", fail_snapshot, raising=False)
    else:
        monkeypatch.setattr(
            workspace_module,
            "capture_supervisor_source_snapshot",
            lambda: {"contract": "SupervisorSourceSnapshot/v3", "status": "healthy"},
        )
    state = start_round(
        context(tmp_path, f"snapshot-{failure}"),
        message="capture source",
        change_mode="replace",
        execution_mode="observe",
        project_config={},
        quality_profile={},
        shadow=True,
    )
    assert state["health"] == "degraded"
    assert state["supervisor_source_snapshot"]["status"] == "unavailable"


def test_degraded_source_snapshot_degrades_start(tmp_path, monkeypatch):
    monkeypatch.setattr(
        workspace_module,
        "capture_supervisor_source_snapshot",
        lambda: {
            "contract": "SupervisorSourceSnapshot/v3",
            "status": "degraded",
            "snapshot_sha256": "b" * 64,
        },
    )
    state = start_round(
        context(tmp_path, "snapshot-degraded"),
        message="capture degraded source",
        change_mode="replace",
        execution_mode="observe",
        project_config={},
        quality_profile={},
        shadow=True,
    )
    assert state["health"] == "degraded"


def test_source_snapshot_is_persisted_when_available(tmp_path, monkeypatch):
    expected = {"contract": "SupervisorSourceSnapshot/v3", "status": "available", "source_sha256": "a" * 64}
    monkeypatch.setattr(
        workspace_module,
        "capture_supervisor_source_snapshot",
        lambda: copy.deepcopy(expected),
        raising=False,
    )
    ctx = context(tmp_path, "snapshot-available")
    state = start_round(
        ctx,
        message="capture source",
        change_mode="replace",
        execution_mode="observe",
        project_config={},
        quality_profile={},
    )
    assert state["supervisor_source_snapshot"] == expected
    assert ctx.load()["supervisor_source_snapshot"] == expected


def test_shadow_start_is_a_read_only_preview(tmp_path):
    persisted_ctx = context(tmp_path, "persisted-round")
    persisted = start_round(
        persisted_ctx,
        message="existing goal",
        change_mode="replace",
        execution_mode="warn",
        project_config={},
        quality_profile={},
    )
    state_root = tmp_path / "state"

    def snapshot_tree() -> tuple[set[str], dict[str, bytes]]:
        directories = {
            str(path.relative_to(state_root))
            for path in state_root.rglob("*")
            if path.is_dir()
        }
        files = {
            str(path.relative_to(state_root)): path.read_bytes()
            for path in state_root.rglob("*")
            if path.is_file()
        }
        return directories, files

    before = snapshot_tree()
    shadow_ctx = context(tmp_path, "shadow-round")
    preview = start_round(
        shadow_ctx,
        message="preview an extension",
        change_mode="extend",
        execution_mode="enforce",
        project_config={},
        quality_profile={},
        shadow=True,
    )
    after = snapshot_tree()

    assert before == after
    assert not shadow_ctx.state_file.exists()
    assert preview["shadow"] is True
    assert preview["goal"]["goal_id"] == persisted["goal"]["goal_id"]
    assert preview["goal"]["version"] == persisted["goal"]["version"] + 1


def test_continue_extend_keep_goal_identity_and_replace_supersedes(tmp_path):
    c1 = context(tmp_path, "r1")
    s1 = start_round(c1, message="one", change_mode="continue", execution_mode="warn", project_config={}, quality_profile={})
    c2 = context(tmp_path, "r2")
    s2 = start_round(c2, message="two", change_mode="extend", execution_mode="warn", project_config={}, quality_profile={})
    assert s2["goal"]["goal_id"] == s1["goal"]["goal_id"]
    assert s2["goal"]["version"] == 2
    assert s2["goal"]["scope"]["in"] == ["**"]
    assert s2["prior_rounds"][0]["goal"]["version"] == 1
    assert s2["lineage"]["relationship"] == "extend"
    assert c1.load()["extended_by"]["round"] == "r2"
    final_prior_hash = sha256_bytes(c1.state_file.read_bytes())
    assert s2["prior_rounds"][0]["source_state_sha256"] == final_prior_hash
    assert s2["lineage"]["previous_state_sha256"] == final_prior_hash
    c3 = context(tmp_path, "r3")
    s3 = start_round(c3, message="three", change_mode="replace", execution_mode="warn", project_config={}, quality_profile={})
    assert s3["goal"]["goal_id"] != s2["goal"]["goal_id"]
    assert c2.load()["superseded_by"]["goal_id"] == s3["goal"]["goal_id"]


def test_prior_rounds_are_bounded_with_a_verifiable_archive_anchor(tmp_path):
    states = []
    contexts = []
    for index in range(25):
        ctx = context(tmp_path, f"bounded-{index:02d}")
        state = start_round(
            ctx,
            message=f"continue round {index}",
            change_mode="continue",
            execution_mode="warn",
            project_config={},
            quality_profile={},
        )
        contexts.append(ctx)
        states.append(state)

    latest = states[-1]
    archive = latest["prior_round_archive"]
    assert len(latest["prior_rounds"]) == lifecycle_module._MAX_INLINE_PRIOR_ROUNDS
    assert archive["contract"] == "PriorRoundArchiveReference/v3"
    assert archive["archived_round_count"] == 4
    anchor = Path(archive["anchor_state_file"])
    assert anchor.is_file()
    assert sha256_bytes(anchor.read_bytes()) == archive["anchor_state_sha256"]
    assert latest["prior_rounds"][0]["round"] == "bounded-04"


def test_goal_builder_does_not_mutate_previous_list_aliases():
    previous = {
        "goal_id": "goal-existing",
        "version": 1,
        "objective": "existing objective",
        "acceptance_criteria": [{"criterion_id": "criterion-existing", "description": "existing"}],
        "waiver_authorizations": [{"criterion_id": "criterion-existing", "request_sha256": "a" * 64}],
    }
    before = copy.deepcopy(previous)
    message = "A separately authenticated waiver request."
    build_goal(
        message,
        change_mode="continue",
        previous_goal=previous,
        trusted_authorizations={
            "request_sha256": sha256_text(message),
            "waiver_criterion_ids": ["criterion-new"],
            "t3_action_sha256s": [],
        },
    )
    assert previous == before


def test_generated_criteria_follow_atomic_intent_domains_and_domain_gates(tmp_path):
    ctx = context(tmp_path, "domain-r1")
    state = start_round(
        ctx,
        message="Implement the UI, API, and DB, then have an independent reviewer review it.",
        change_mode="continue",
        execution_mode="warn",
        project_config={},
        quality_profile={
            "global_gates": ["global-gate"],
            "domains": {
                "ui": {"required_gates": ["ui-gate"]},
                "api/db": {"required_gates": ["api-db-gate"]},
                "review": {"required_gates": ["review-gate"]},
            },
        },
    )
    criteria = state["goal"]["acceptance_criteria"]
    assert {row["domain"] for row in criteria} == {"ui", "api", "db", "review"}
    by_domain = {row["domain"]: row for row in criteria}
    assert by_domain["ui"]["expected_evidence"] == ["global-gate", "ui-gate"]
    assert by_domain["api"]["expected_evidence"] == ["global-gate", "api-db-gate"]
    assert by_domain["db"]["expected_evidence"] == ["global-gate", "api-db-gate"]
    assert by_domain["review"]["expected_evidence"] == ["global-gate", "review-gate"]
    assert all(row["domain"] != "config-agent" for row in criteria)


def test_extend_adds_domain_derived_criteria_without_rewriting_prior_criteria(tmp_path):
    first_ctx = context(tmp_path, "domain-extend-r1")
    first = start_round(
        first_ctx,
        message="Implement the UI",
        change_mode="continue",
        execution_mode="warn",
        project_config={},
        quality_profile={},
    )
    second_ctx = context(tmp_path, "domain-extend-r2")
    second = start_round(
        second_ctx,
        message="Add an API and DB",
        change_mode="extend",
        execution_mode="warn",
        project_config={},
        quality_profile={},
    )
    assert {row["domain"] for row in first["goal"]["acceptance_criteria"]} == {"ui"}
    assert {row["domain"] for row in second["goal"]["acceptance_criteria"]} == {"ui", "api", "db"}


def test_unresolved_criteria_and_intents_survive_continue_and_replace_forces_new_id(tmp_path):
    first_ctx = context(tmp_path, "carry-r1")
    first = start_round(
        first_ctx,
        message="requirement A",
        change_mode="continue",
        execution_mode="warn",
        project_config={},
        quality_profile={},
        goal_supplied={
            "goal_id": "goal-a",
            "objective": "Finish requirement A",
            "acceptance_criteria": [{"criterion_id": "criterion-a", "description": "A passes", "expected_evidence": ["gate-a"]}],
        },
        intents_supplied=[{"intent_id": "intent-a", "text": "finish A", "status": "deferred", "reason": "still pending"}],
    )
    second_ctx = context(tmp_path, "carry-r2")
    second = start_round(
        second_ctx,
        message="continue with B",
        change_mode="continue",
        execution_mode="warn",
        project_config={},
        quality_profile={},
        goal_supplied={
            "goal_id": "goal-a",
            "objective": "Silently replace A",
            "acceptance_criteria": [{"criterion_id": "criterion-b", "description": "B passes", "expected_evidence": ["gate-b"]}],
        },
        intents_supplied=[{"intent_id": "intent-a", "text": "finish B", "status": "deferred", "reason": "new work"}],
    )
    assert second["goal"]["goal_id"] == first["goal"]["goal_id"]
    assert second["goal"]["objective"] == "Finish requirement A"
    assert {row["criterion_id"] for row in second["goal"]["acceptance_criteria"]} == {"criterion-a", "criterion-b"}
    assert {row["text"] for row in second["intents"]} == {"finish A", "finish B"}
    assert len({row["intent_id"] for row in second["intents"]}) == 2

    replacement_ctx = context(tmp_path, "carry-r3")
    replacement = start_round(
        replacement_ctx,
        message="replace with C",
        change_mode="replace",
        execution_mode="warn",
        project_config={},
        quality_profile={},
        goal_supplied={"goal_id": second["goal"]["goal_id"], "objective": "C"},
    )
    assert replacement["goal"]["goal_id"] != second["goal"]["goal_id"]


def test_adapter_default_scope_uses_project_lease_and_carries_records(tmp_path):
    c1 = context(tmp_path, "r1")
    first = start_round(
        c1,
        message="implement adapter",
        change_mode="continue",
        execution_mode="warn",
        project_config={"supervisor_scope": {"allowed_change_globs": ["config/**"], "out_of_scope_globs": ["src/**"]}},
        quality_profile={},
    )
    first["tasks"] = [{"task_id": "t1", "status": "done"}]
    first["evidence"] = [{"evidence_id": "e1"}]
    c1.save(first)
    c2 = context(tmp_path, "r2")
    second = start_round(
        c2,
        message="继续",
        change_mode="continue",
        execution_mode="warn",
        project_config={"supervisor_scope": {"allowed_change_globs": ["config/**"], "out_of_scope_globs": ["src/**"]}},
        quality_profile={},
    )
    assert second["goal"]["scope"] == {"in": ["config/**"], "out": ["src/**"]}
    assert second["prior_rounds"][0]["tasks"] == [{"task_id": "t1", "status": "done"}]
    assert second["prior_rounds"][0]["evidence"] == [{"evidence_id": "e1"}]


def test_stop_cap_never_converts_incomplete_to_complete(tmp_path):
    ctx = context(tmp_path, "r1")
    start_round(ctx, message="incomplete", change_mode="continue", execution_mode="enforce", project_config={}, quality_profile={})
    for stop in (1, 2, 3):
        state, code = finalize_round(ctx, stop_attempt=stop)
        assert state["terminal_state"] == "incomplete"
        assert code == 2
    assert state["host_gate"]["stop_cap_reached"] is True
    assert state["host_gate"]["should_block"] is False


def test_promoted_enforce_blocks_only_first_two_stop_attempts(tmp_path):
    ctx = context(tmp_path, "r-promoted")
    state = start_round(ctx, message="incomplete", change_mode="continue", execution_mode="observe", project_config={}, quality_profile={})
    state["execution_mode"] = "enforce"
    state["rollout"]["active_mode"] = "enforce"
    ctx.save(state)
    decisions = []
    for stop in (1, 2, 3):
        finalized, _ = finalize_round(ctx, stop_attempt=stop)
        decisions.append(finalized["host_gate"]["should_block"])
        assert finalized["terminal_state"] == "incomplete"
    assert decisions == [True, True, False]


def test_degraded_prior_never_completes(tmp_path, valid_bundle):
    ctx = context(tmp_path, "r1")
    state, events = valid_bundle
    state.update(runtime="test", project="p", workspace=str(tmp_path / "workspace"), session="s", round="r1", health="degraded")
    ctx.save(state)
    for event in events:
        ctx.append_event(event)
    final, code = finalize_round(ctx)
    assert final["terminal_state"] == "incomplete"
    assert code == 4


def test_successful_finalize_commits_complete_with_final_event(tmp_path, valid_bundle):
    ctx = context(tmp_path, "final-event-success")
    state, events = valid_bundle
    ctx.save(state)
    for event in events:
        ctx.append_event(event)

    final, code = finalize_round(ctx)

    assert final["terminal_state"] == "complete"
    assert code == 0
    assert ctx.load()["terminal_state"] == "complete"
    finalized_events = [event for event in ctx.events() if event.get("event_type") == "round_finalized"]
    assert finalized_events[-1]["status"] == "complete"


def test_round_finalized_event_failure_never_commits_complete(tmp_path, valid_bundle, monkeypatch):
    ctx = context(tmp_path, "final-event-failure")
    state, events = valid_bundle
    ctx.save(state)
    for event in events:
        ctx.append_event(event)
    original_append = StateContext._append_event_locked

    def fail_final_event(self, event):
        if event.get("event_type") == "round_finalized":
            raise OSError("simulated final audit failure")
        return original_append(self, event)

    monkeypatch.setattr(StateContext, "_append_event_locked", fail_final_event)

    with pytest.raises(OSError, match="final audit failure"):
        finalize_round(ctx)

    persisted = ctx.load()
    assert persisted.get("terminal_state") is None
    assert all(event.get("event_type") != "round_finalized" for event in ctx.events())


def test_rollout_observation_event_failure_degrades_finalization(tmp_path, valid_bundle, monkeypatch):
    ctx = context(tmp_path, "rollout-event-failure")
    state, events = valid_bundle
    ctx.save(state)
    for event in events:
        ctx.append_event(event)
    original_append = StateContext._append_event_locked

    def fail_rollout_event(self, event):
        if event.get("contract") == "RolloutObservation/v3":
            raise OSError("simulated rollout audit failure")
        return original_append(self, event)

    monkeypatch.setattr(StateContext, "_append_event_locked", fail_rollout_event)

    final, code = finalize_round(ctx)

    assert final["terminal_state"] == "incomplete"
    assert final["health"] == "degraded"
    assert code == 4
    assert any("rollout observation event persistence degraded" in error for error in final["validation"]["errors"])
    finalized_events = [event for event in ctx.events() if event.get("event_type") == "round_finalized"]
    assert finalized_events[-1]["status"] == "incomplete"
