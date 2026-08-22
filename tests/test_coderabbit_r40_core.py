from __future__ import annotations

import copy
from pathlib import Path

import pytest

from supervisor_core import cli as cli_module
from supervisor_core.finalize import finalize_round
from supervisor_core.lifecycle import start_round
from supervisor_core.rollout import initial_rollout
from supervisor_core.storage import StateContext, atomic_write_json


_ABSENT = object()


def _policy_state(tmp_path: Path, policy: object = _ABSENT) -> dict[str, object]:
    workspace = tmp_path / "workspace"
    (workspace / "src" / "allowed").mkdir(parents=True, exist_ok=True)
    (workspace / "src" / "private").mkdir(parents=True, exist_ok=True)
    state: dict[str, object] = {
        "workspace": str(workspace),
        "goal": {
            "goal_id": "goal-1",
            "version": 1,
            "scope": {"in": ["src/**"], "out": []},
            "t3_action_authorizations": [],
        },
        "tasks": [
            {
                "task_id": "task-1",
                "goal_id": "goal-1",
                "goal_version": 1,
                "lease_id": "lease-1",
                "lease_status": "active",
                "owner": "worker-a",
                "responsibility_group": "implementation",
                "allowed_paths": ["src/**"],
            }
        ],
    }
    if policy is not _ABSENT:
        state["project_policy"] = copy.deepcopy(policy)
    return state


def _write_decision(state: dict[str, object], relative: str) -> dict[str, object]:
    target = Path(str(state["workspace"])) / relative
    return cli_module._pretool_policy(
        state,
        tool_name="Write",
        tool_input={"file_path": str(target)},
        actor="worker-a",
    )


def test_absent_project_policy_does_not_restrict_goal_and_lease_authorized_write(
    tmp_path: Path,
) -> None:
    decision = _write_decision(_policy_state(tmp_path), "src/allowed/new.py")

    assert decision["deny"] is False
    assert decision["status"] == "authorized"


def test_explicit_project_allow_and_deny_globs_are_enforced(tmp_path: Path) -> None:
    state = _policy_state(
        tmp_path,
        {
            "allowed_change_globs": ["src/**"],
            "out_of_scope_globs": ["src/private/**"],
        },
    )

    assert _write_decision(state, "src/allowed/new.py")["deny"] is False
    denied = _write_decision(state, "src/private/new.py")
    assert denied["deny"] is True
    assert denied["category"] == "write-scope"


def test_explicit_empty_project_allow_is_not_treated_as_absent(tmp_path: Path) -> None:
    state = _policy_state(
        tmp_path,
        {"allowed_change_globs": [], "out_of_scope_globs": []},
    )

    denied = _write_decision(state, "src/allowed/new.py")
    assert denied["deny"] is True
    assert denied["category"] == "write-scope"


@pytest.mark.parametrize(
    "policy",
    [
        None,
        [],
        {},
        {"allowed_change_globs": "src/**", "out_of_scope_globs": []},
        {"allowed_change_globs": ["src/**", None], "out_of_scope_globs": []},
        {"allowed_change_globs": ["**"], "out_of_scope_globs": []},
        {"allowed_change_globs": ["src/**"], "out_of_scope_globs": [None]},
        {"allowed_change_globs": ["src/**"]},
        {"out_of_scope_globs": ["src/private/**"]},
    ],
)
def test_explicit_malformed_project_policy_fails_closed(
    tmp_path: Path, policy: object
) -> None:
    denied = _write_decision(_policy_state(tmp_path, policy), "src/allowed/new.py")

    assert denied["deny"] is True
    assert denied["category"] == "write-scope"


def _round_context(tmp_path: Path, name: str) -> StateContext:
    workspace = tmp_path / name / "workspace"
    workspace.mkdir(parents=True)
    return StateContext.build(
        runtime="codex",
        project=name,
        workspace=str(workspace),
        session="session",
        round_id="round",
        state_root=tmp_path / "state",
    )


def test_start_round_preserves_absent_empty_and_malformed_policy_distinction(
    tmp_path: Path,
) -> None:
    absent = start_round(
        _round_context(tmp_path, "absent"),
        message="absent policy",
        change_mode="replace",
        execution_mode="observe",
        project_config={},
        quality_profile={},
    )
    empty = start_round(
        _round_context(tmp_path, "empty"),
        message="empty policy",
        change_mode="replace",
        execution_mode="observe",
        project_config={
            "supervisor_scope": {
                "allowed_change_globs": [],
                "out_of_scope_globs": [],
            }
        },
        quality_profile={},
    )
    malformed = start_round(
        _round_context(tmp_path, "malformed"),
        message="malformed policy",
        change_mode="replace",
        execution_mode="observe",
        project_config={"supervisor_scope": None},
        quality_profile={},
    )

    assert "project_policy" not in absent
    assert empty["project_policy"] == {
        "allowed_change_globs": [],
        "out_of_scope_globs": [],
    }
    assert malformed["project_policy"] is None


@pytest.mark.parametrize(
    ("policy", "expected_error"),
    [
        (_ABSENT, None),
        (
            {
                "allowed_change_globs": ["src/**"],
                "out_of_scope_globs": ["src/private/**"],
            },
            None,
        ),
        (
            {"allowed_change_globs": [], "out_of_scope_globs": []},
            "project policy allowed_change_globs invalid",
        ),
        (None, "project policy must be an object when configured"),
        ([], "project policy must be an object when configured"),
        ({}, "project policy allowed_change_globs invalid"),
        (
            {"allowed_change_globs": "src/**", "out_of_scope_globs": []},
            "project policy allowed_change_globs invalid",
        ),
    ],
)
def test_start_to_finalize_preserves_project_policy_presence_and_fails_closed(
    tmp_path: Path,
    policy: object,
    expected_error: str | None,
) -> None:
    ctx = _round_context(tmp_path, f"finalize-{len(str(policy))}")
    project_config: dict[str, object] = {}
    if policy is not _ABSENT:
        project_config["supervisor_scope"] = copy.deepcopy(policy)
    started = start_round(
        ctx,
        message="finalize policy matrix",
        change_mode="replace",
        execution_mode="observe",
        project_config=project_config,
        quality_profile={},
    )

    finalized, exit_code = finalize_round(ctx)
    errors = finalized["validation"]["errors"]
    policy_errors = [error for error in errors if error.startswith("project policy")]

    assert ("project_policy" in started) is (policy is not _ABSENT)
    assert ("project_policy" in finalized) is (policy is not _ABSENT)
    assert exit_code != 0
    if expected_error is None:
        assert policy_errors == []
    else:
        assert expected_error in policy_errors


def test_round_started_uses_normalized_persisted_rollout_mode(tmp_path: Path) -> None:
    ctx = _round_context(tmp_path, "normalized-rollout")
    ctx.initialize()
    rollout = initial_rollout({}, "observe")
    rollout["active_mode"] = "WARN"
    atomic_write_json(ctx.project_rollout_file, rollout)

    state = start_round(
        ctx,
        message="normalize rollout",
        change_mode="replace",
        execution_mode="enforce",
        project_config={},
        quality_profile={},
    )
    started = [event for event in ctx.events() if event.get("event_type") == "round_started"]

    assert state["execution_mode"] == "warn"
    assert started[-1]["execution_mode"] == "warn"


def test_round_started_uses_safe_fallback_mode_when_rollout_is_degraded(
    tmp_path: Path,
) -> None:
    ctx = _round_context(tmp_path, "degraded-rollout")
    ctx.initialize()
    atomic_write_json(
        ctx.project_rollout_file,
        {"contract": "RolloutState/v3", "active_mode": "corrupt"},
    )

    state = start_round(
        ctx,
        message="recover rollout",
        change_mode="replace",
        execution_mode="enforce",
        project_config={
            "rollout": {"cross_project_default": {"mode": "warn"}}
        },
        quality_profile={},
    )
    events = ctx.events()
    started = [event for event in events if event.get("event_type") == "round_started"]

    assert state["execution_mode"] == "warn"
    assert state["health"] == "degraded"
    assert started[-1]["execution_mode"] == "warn"
    assert any(event.get("event_type") == "rollout_start_degraded" for event in events)
