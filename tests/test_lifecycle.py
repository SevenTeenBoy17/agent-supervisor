from __future__ import annotations

import copy
from pathlib import Path

from supervisor_core.finalize import finalize_round
from supervisor_core.lifecycle import start_round
from supervisor_core.storage import StateContext


def context(tmp_path: Path, round_id: str) -> StateContext:
    return StateContext.build(runtime="test", project="p", workspace=str(tmp_path / "workspace"), session="s", round_id=round_id, state_root=tmp_path / "state")


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
    c3 = context(tmp_path, "r3")
    s3 = start_round(c3, message="three", change_mode="replace", execution_mode="warn", project_config={}, quality_profile={})
    assert s3["goal"]["goal_id"] != s2["goal"]["goal_id"]
    assert c2.load()["superseded_by"]["goal_id"] == s3["goal"]["goal_id"]


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
