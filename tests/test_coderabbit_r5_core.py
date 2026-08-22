from __future__ import annotations

import json
from argparse import Namespace
from pathlib import Path

import supervisor_core.cli as cli_module
import supervisor_core.contracts as contracts_module
from supervisor_core.contracts import build_goal
from supervisor_core.routing import route_intents
from supervisor_core.storage import StateContext


def test_same_capability_is_scheduled_in_each_selected_role() -> None:
    routed = route_intents(
        message="",
        inventory={
            "skills": [{
                "id": "dual-capability",
                "description": "implement and review",
                "active": True,
                "automatic": True,
                "availability": "enabled",
                "health": "healthy",
            }]
        },
        supplied_intents=[
            {"intent_id": "implement", "text": "implement", "role": "implementation"},
            {"intent_id": "review", "text": "review", "role": "review"},
        ],
    )

    assert routed["selected_capabilities"] == ["dual-capability"]
    assert [phase["role"] for phase in routed["phases"]] == ["implementation", "review"]
    assert routed["phases"][1]["depends_on"] == [1]
    coverage = {row["intent_id"]: row for row in routed["coverage"]}
    assert coverage["implement"]["phases"] == [1]
    assert coverage["review"]["phases"] == [2]


def test_all_missing_required_responsibility_groups_are_routing_errors() -> None:
    routed = route_intents(
        message="",
        inventory={
            "skills": [{
                "id": "builder",
                "description": "build implementation",
                "responsibility_group": "implementation",
            }]
        },
        supplied_intents=[
            {"intent_id": "build", "text": "build"},
            {
                "intent_id": "review-a",
                "text": "review",
                "required_responsibility_groups": ["independent-review"],
            },
            {
                "intent_id": "review-b",
                "text": "audit",
                "required_responsibility_groups": ["security-review"],
            },
        ],
    )

    assert routed["selected_capabilities"] == ["builder"]
    assert routed["zero_skill"] is False
    assert routed["valid"] is False
    assert len(routed["errors"]) == 2
    assert any(error.startswith("review-a:") and "independent-review" in error for error in routed["errors"])
    assert any(error.startswith("review-b:") and "security-review" in error for error in routed["errors"])


def test_continue_preserves_and_stably_deduplicates_contract_lists() -> None:
    previous = build_goal(
        "initial request",
        change_mode="replace",
        supplied={
            "constraints": ["keep", "shared"],
            "non_goals": ["old non-goal"],
            "assumptions": ["old assumption"],
            "risks": ["old risk"],
        },
    )

    continued = build_goal(
        "continue request",
        change_mode="continue",
        previous_goal=previous,
        supplied={
            "constraints": ["shared", "new"],
            "non_goals": ["new non-goal"],
            "assumptions": ["old assumption", "new assumption"],
            "risks": ["new risk"],
        },
    )

    assert continued["constraints"] == ["keep", "shared", "new"]
    assert continued["non_goals"] == ["old non-goal", "new non-goal"]
    assert continued["assumptions"] == ["old assumption", "new assumption"]
    assert continued["risks"] == ["old risk", "new risk"]


def test_finalize_does_not_bind_unrelated_criterion_to_builtin_gate(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    ctx = StateContext.build(
        runtime="codex",
        project="r5",
        workspace=str(tmp_path),
        session="session",
        round_id="round",
        state_root=tmp_path / "state",
    )
    ctx.save({
        "workspace": str(tmp_path),
        "execution_mode": "observe",
        "health": "healthy",
        "stop_attempts": 0,
        "changes": {"domains": []},
        "evidence": [],
        "quality_profile": {
            "global_gates": ["gate.intent-coverage"],
            "gates": [{"id": "gate.intent-coverage", "builtin": "intent-coverage"}],
        },
        "goal": {
            "acceptance_criteria": [{
                "criterion_id": "criterion-unrelated",
                "domain": "general",
                "expected_evidence": ["gate.other"],
            }]
        },
    })
    executed: list[str] = []

    monkeypatch.setattr(cli_module, "_context", lambda *_args, **_kwargs: ctx)
    monkeypatch.setattr(cli_module, "_verify_current_source_snapshot", lambda *_args, **_kwargs: "a" * 64)
    monkeypatch.setattr(
        cli_module,
        "_run_registered_gate",
        lambda *_args, **_kwargs: executed.append("ran"),
    )

    def finalize(context: StateContext, **_kwargs):
        state = context.load()
        state.update({
            "terminal_state": "incomplete",
            "host_gate": {"should_block": False},
            "validation": {"valid": False, "health": "degraded", "errors": []},
        })
        return state, 4

    monkeypatch.setattr(cli_module, "finalize_round", finalize)

    assert cli_module.command_finalize(Namespace(stop_attempt=None, blocked=False)) == 4
    capsys.readouterr()
    assert executed == []
    state = ctx.load()
    assert state["health"] == "degraded"
    events = ctx.events()
    assert events[-1]["event_type"] == "builtin_finalize_degraded"
    assert events[-1]["summary"] == "InvalidState"


def test_main_returns_structured_degraded_result_for_runtime_attestation_failure(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    def unavailable(_record):
        raise RuntimeError("attestation service unavailable")

    monkeypatch.setattr(contracts_module, "sign_record", unavailable)

    exit_code = cli_module.main([
        "start",
        "--runtime", "codex",
        "--workspace", str(tmp_path),
        "--session", "session",
        "--round", "round",
        "--state-root", str(tmp_path / "state"),
        "--message", "test runtime failure handling",
        "--change-mode", "replace",
    ])

    assert exit_code == 4
    output = json.loads(capsys.readouterr().out)
    assert output == {
        "error": "RuntimeError",
        "health": "degraded",
        "message": "attestation service unavailable",
        "ok": False,
    }
