from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any

import pytest

from supervisor_core.attestation import sign_record
from supervisor_core.cli import (
    InvalidState,
    _context,
    _pretool_policy,
    command_event,
    emit_stage_checkpoint,
    goal_drift_report,
)
from supervisor_core.contracts import (
    build_round_process_summary,
    render_round_process_summary,
)
from supervisor_core.finalize import finalize_round
from supervisor_core.storage import StateContext
from supervisor_core.util import sha256_text
from supervisor_core.validation import validate_state
from test_codex_native_hooks import (
    RAW_PROMPT,
    _run_hook,
    _write_codex_workspace,
    _write_install_source_fixture,
)


@pytest.fixture
def codex_round(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]):
    workspace = tmp_path / "Codex native 中文 workspace"
    workspace.mkdir()
    _write_codex_workspace(workspace)
    state_root = tmp_path / "isolated-state"
    install_home = tmp_path / "install-home"
    _write_install_source_fixture(install_home)
    monkeypatch.setenv("AGENT_SUPERVISOR_ATTESTATION_KEY_FILE", str(tmp_path / "attestation.key"))
    monkeypatch.setenv("AGENT_SUPERVISOR_INSTALL_HOME", str(install_home))
    session = "codex-native-session"
    common = {"session_id": session, "cwd": str(workspace)}
    session_code, session_output = _run_hook(
        monkeypatch, capsys, state_root=state_root, event="SessionStart", payload=common
    )
    assert session_code == 0
    assert session_output["hookSpecificOutput"]["hookEventName"] == "SessionStart"
    prompt_code, prompt_output = _run_hook(
        monkeypatch,
        capsys,
        state_root=state_root,
        event="UserPromptSubmit",
        payload={**common, "prompt": RAW_PROMPT},
    )
    assert prompt_code == 0
    assert prompt_output["hookSpecificOutput"]["hookEventName"] == "UserPromptSubmit"
    state_files = list(state_root.rglob("state.json"))
    assert len(state_files) == 1
    state_file = state_files[0]
    state = json.loads(state_file.read_text(encoding="utf-8"))
    criterion_id = state["goal"]["acceptance_criteria"][0]["criterion_id"]
    state["tasks"] = [{
        "task_id": "task-codex-write",
        "goal_id": state["goal"]["goal_id"],
        "goal_version": state["goal"]["version"],
        "criterion_ids": [criterion_id],
        "allowed_paths": ["src/**"],
        "expected_evidence": ["gate.native"],
        "status": "doing",
        "lease_id": "lease-codex-write",
        "lease_status": "active",
        "owner": "codex",
        "responsibility_group": "implementation",
    }]
    state["execution_mode"] = "enforce"
    state_file.write_text(json.dumps(state), encoding="utf-8")
    ctx = StateContext(
        runtime=state["runtime"],
        project=state["project"],
        workspace=state["workspace"],
        session=state["session"],
        round=state["round"],
        root=state_file.parent,
    )
    return workspace, state_root, common, ctx


def test_prompt_start_persists_current_discovery_and_route(codex_round) -> None:
    _, _state_root, _common, ctx = codex_round
    state = ctx.load()
    assert state["goal"]["change_mode"] in {"continue", "extend", "replace"}
    assert state["goal"]["goal_id"]
    assert state["intents"]
    discovery = state["discovery"]
    inventory = state["capability_inventory"]
    route = state["capability_route"]
    assert discovery["inventory_sha256"]
    assert inventory["skills"] or inventory.get("agents") is not None
    assert route["inventory_sha256"] == discovery["inventory_sha256"]
    assert "coverage" in route
    assert route["message"].startswith("sha256:") or isinstance(route.get("coverage"), list)


def test_pretool_policy_records_risk_tier_lease_and_criterion_binding(tmp_path: Path) -> None:
    allowed = tmp_path / "src" / "allowed"
    allowed.mkdir(parents=True)
    goal = {
        "goal_id": "goal-1",
        "version": 1,
        "t3_action_authorizations": [],
        "scope": {"in": ["**"], "out": []},
        "acceptance_criteria": [
            {
                "criterion_id": "criterion-1",
                "description": "bounded write",
                "domain": "config-agent",
                "expected_evidence": ["lint"],
                "required": True,
            }
        ],
    }
    unbound = {
        "workspace": str(tmp_path),
        "goal": goal,
        "tasks": [{
            "task_id": "task-unbound",
            "goal_id": "goal-1",
            "goal_version": 1,
            "lease_id": "lease-unbound",
            "lease_status": "active",
            "owner": "worker-a",
            "responsibility_group": "implementation",
            "allowed_paths": ["src/allowed/**"],
        }],
    }
    denied = _pretool_policy(
        unbound,
        tool_name="Write",
        tool_input={"file_path": str(allowed / "new.py")},
        actor="worker-a",
    )
    assert denied["deny"] is True
    assert denied["risk_tier"] == "write"
    assert denied["reason"] == "active lease is not bound to a current goal criterion"

    bound = copy.deepcopy(unbound)
    bound["tasks"][0]["criterion_ids"] = ["criterion-1"]
    allowed_policy = _pretool_policy(
        bound,
        tool_name="Write",
        tool_input={"file_path": str(allowed / "new.py")},
        actor="worker-a",
    )
    assert allowed_policy["deny"] is False
    assert allowed_policy["risk_tier"] == "write"
    assert allowed_policy["criterion_ids"] == ["criterion-1"]
    assert allowed_policy["goal_id"] == "goal-1"
    assert allowed_policy["goal_version"] == 1

    t3 = _pretool_policy(
        bound,
        tool_name="Bash",
        tool_input={"command": "git push --force origin main"},
        actor="worker-a",
    )
    assert t3["deny"] is True
    assert t3["risk_tier"] == "t3"
    assert t3["category"] == "force-push"


def test_pretool_hook_persists_structured_lease_and_risk_fields(
    codex_round, monkeypatch, capsys
) -> None:
    _, state_root, common, ctx = codex_round
    code, _output = _run_hook(
        monkeypatch,
        capsys,
        state_root=state_root,
        event="PreToolUse",
        payload={
            **common,
            "tool_use_id": "write-1",
            "tool_name": "apply_patch",
            "tool_input": {
                "command": "*** Begin Patch\n*** Update File: src/baseline.py\n@@\n-VALUE = 1\n+VALUE = 2\n*** End Patch"
            },
        },
    )
    assert code == 0
    policy = next(
        row
        for row in ctx.events()
        if row.get("event_type") == "pretool_policy" and row.get("invocation_id") == "write-1"
    )
    assert policy["category"] in {"write-lease", "write-scope"}
    assert policy["risk_tier"] == "write"
    assert policy["goal_id"] == ctx.load()["goal"]["goal_id"]
    assert "criterion_ids" in policy


def test_posttool_failure_is_not_counted_as_success(
    codex_round, monkeypatch, capsys
) -> None:
    _, state_root, common, ctx = codex_round
    payload = {
        **common,
        "tool_use_id": "shell-fail",
        "tool_name": "exec_command",
        "tool_input": {"cmd": "python -c \"print('ok')\""},
    }
    assert _run_hook(monkeypatch, capsys, state_root=state_root, event="PreToolUse", payload=payload)[0] == 0
    assert _run_hook(
        monkeypatch,
        capsys,
        state_root=state_root,
        event="PostToolUse",
        payload={**payload, "tool_response": {"isError": True, "exitCode": 2}},
    )[0] == 0
    result = next(
        row
        for row in ctx.events()
        if row.get("invocation_id") == "shell-fail" and row.get("event_type") == "invocation_result"
    )
    assert result["result"] == "failed"
    assert result["result"] != "success"


def test_precompact_and_subagent_write_handoff_and_detect_goal_drift(
    codex_round, monkeypatch, capsys, tmp_path: Path
) -> None:
    _, state_root, common, ctx = codex_round
    compact_code, compact_output = _run_hook(
        monkeypatch,
        capsys,
        state_root=state_root,
        event="PreCompact",
        payload=common,
    )
    assert compact_code == 0
    assert compact_output == {}
    checkpoint = next(
        row for row in ctx.events() if row.get("event_type") == "stage_checkpoint"
    )
    assert checkpoint["reason"] == "precompact"
    assert checkpoint["goal_drift"]["status"] == "aligned"
    assert checkpoint["handoff_written"] is True
    assert checkpoint["handoff_sha256"]
    session_hash = __import__("hashlib").sha256(common["session_id"].encode("utf-8")).hexdigest()
    handoff = Path(common["cwd"]) / ".agent-supervisor" / "handoffs" / session_hash / "latest.md"
    assert handoff.is_file()
    assert handoff.read_text(encoding="utf-8").startswith("# RoundProcessSummary/v1")

    drifted = ctx.load()
    drifted["goal"] = copy.deepcopy(drifted["goal"])
    drifted["goal"]["objective"] = "mutated objective that is not the signed contract"
    ctx.save(drifted)
    assert goal_drift_report(ctx.load())["status"] == "drift"
    sub_code, _sub_output = _run_hook(
        monkeypatch,
        capsys,
        state_root=state_root,
        event="SubagentStart",
        payload={**common, "agent_id": "reviewer-1", "agent_type": "reviewer"},
    )
    assert sub_code == 0
    drift_checkpoint = [
        row
        for row in ctx.events()
        if row.get("event_type") == "stage_checkpoint" and row.get("reason") == "subagent_start"
    ][-1]
    assert drift_checkpoint["status"] == "drift"
    assert drift_checkpoint["goal_drift"]["status"] == "drift"
    report = validate_state(ctx.load(), ctx.events())
    assert report["valid"] is False
    assert any("goal drift recorded at stage checkpoint" in error for error in report["errors"])


def test_phase_transition_handoff_event_binds_goal_drift(tmp_path: Path, valid_bundle) -> None:
    state, events = copy.deepcopy(valid_bundle)
    args = argparse.Namespace(
        runtime=state["runtime"],
        workspace=str(state["workspace"]),
        session=state["session"],
        round=state["round"],
        state_root=str(tmp_path / "state"),
        event_type="handoff_requested",
        phase="context-preservation",
        status="requested",
        summary="phase-transition",
        capability=None,
        command_category=None,
        actor="codex-adapter",
        responsibility_group=None,
        invocation_id=None,
        result=None,
        data_json=None,
        project_file=None,
    )
    ctx = _context(args)
    ctx.save(state)
    for event in events:
        ctx.append_event(event)
    assert command_event(args) == 0
    recorded = [
        row for row in ctx.events() if row.get("event_type") in {"handoff_requested", "stage_checkpoint"}
    ]
    requested = next(row for row in recorded if row.get("event_type") == "handoff_requested")
    checkpoint = next(row for row in recorded if row.get("event_type") == "stage_checkpoint")
    assert requested["summary"] == "phase-transition"
    assert requested["goal_drift"]["status"] == "aligned"
    assert checkpoint["reason"] == "phase-transition"
    assert checkpoint["handoff_written"] is True


def test_stop_stays_incomplete_for_missing_gate_out_of_scope_failed_review_and_p0p1(
    tmp_path: Path, valid_bundle
) -> None:
    def _finalize(mutator) -> dict[str, Any]:
        state, events = copy.deepcopy(valid_bundle)
        ctx = StateContext.build(
            runtime="test",
            project="example",
            workspace=str(state["workspace"]),
            session="stop-session",
            round_id="stop-round",
            state_root=str(tmp_path / f"state-{mutator.__name__}"),
        )
        mutator(state)
        ctx.save(state)
        for event in events:
            ctx.append_event(event)
        final, code = finalize_round(ctx, stop_attempt=3)
        assert final["terminal_state"] != "complete"
        assert code != 0
        assert final["host_gate"]["stop_cap_reached"] is True
        return final

    def missing_gate(state: dict[str, Any]) -> None:
        state["evidence"] = []

    def out_of_scope(state: dict[str, Any]) -> None:
        state["changes"]["files"] = ["product/secret.ts"]

    def failed_reviewer(state: dict[str, Any]) -> None:
        review = state["reviews"][0]
        review["verdict"] = "REQUEST_CHANGES"
        review["attestation"] = sign_record(review)

    def unresolved_p0(state: dict[str, Any]) -> None:
        review = state["reviews"][0]
        review["verdict"] = "APPROVE"
        review["unresolved_p0_p1"] = 1
        review["attestation"] = sign_record(review)

    missing = _finalize(missing_gate)
    assert any("evidence" in error or "quality gate" in error for error in missing["validation"]["errors"])
    scoped = _finalize(out_of_scope)
    assert any("out-of-scope" in error for error in scoped["validation"]["errors"])
    reviewed = _finalize(failed_reviewer)
    combined = "\n".join(reviewed["validation"]["errors"])
    assert "REQUEST_CHANGES" in combined
    p0 = _finalize(unresolved_p0)
    assert p0["terminal_state"] == "incomplete"
    assert any("P0/P1" in error for error in p0["validation"]["errors"])


def test_stop_stays_incomplete_when_review_findings_contain_p0(
    tmp_path: Path, valid_bundle
) -> None:
    state, events = copy.deepcopy(valid_bundle)
    ctx = StateContext.build(
        runtime="test",
        project="example",
        workspace=str(state["workspace"]),
        session="findings-session",
        round_id="findings-round",
        state_root=str(tmp_path / "state-findings-p0"),
    )
    review = state["reviews"][0]
    review["verdict"] = "APPROVE"
    review["unresolved_p0_p1"] = 0
    review["review_output_artifact"] = {"review_summary": {"issues": []}}
    review["findings"] = [{"id": "secret-leak", "severity": "P0"}]
    review["attestation"] = sign_record(review)
    ctx.save(state)
    for event in events:
        ctx.append_event(event)
    final, code = finalize_round(ctx, stop_attempt=3)
    assert code != 0
    assert final["terminal_state"] != "complete"
    combined = "\n".join(final["validation"]["errors"])
    assert "P0/P1" in combined
    assert "secret-leak" in combined


def test_validator_exception_records_degraded_and_cannot_complete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = StateContext.build(
        runtime="test",
        project="example",
        workspace=str(tmp_path / "workspace"),
        session="degraded-session",
        round_id="degraded-round",
        state_root=str(tmp_path / "state"),
    )
    (tmp_path / "workspace").mkdir()
    ctx.save({"execution_mode": "enforce", "stop_attempts": 0, "health": "healthy", "goal": {"goal_id": "g", "version": 1}})

    def explode(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise RuntimeError("validator-boom")

    monkeypatch.setattr("supervisor_core.finalize.validate_state", explode)
    final, code = finalize_round(ctx)
    assert code == 4
    assert final["terminal_state"] == "incomplete"
    assert final["health"] == "degraded"
    assert any("validator exception" in error for error in final["validation"]["errors"])


def test_caller_cannot_forge_gate_identity_with_self_reported_fields(
    tmp_path: Path, valid_bundle
) -> None:
    state, events = copy.deepcopy(valid_bundle)
    state["runtime"] = "codex"
    args = argparse.Namespace(
        runtime="codex",
        workspace=str(state["workspace"]),
        session=state["session"],
        round=state["round"],
        state_root=str(tmp_path / "state"),
        event_type="gate_run",
        phase=None,
        status=None,
        summary=None,
        capability=None,
        command_category=None,
        actor="forged-collector",
        responsibility_group="forged-group",
        invocation_id="forged-invocation",
        result="success",
        data_json=json.dumps({
            "record": {
                "gate_id": "lint",
                "criterion_id": "criterion-1",
                "collector": "forged-collector",
                "collector_responsibility_group": "forged-group",
                "exit_code": 0,
                "command": ["echo", "forged"],
            }
        }),
        project_file=None,
    )
    ctx = _context(args)
    ctx.save(state)
    for event in events:
        ctx.append_event(event)
    with pytest.raises(InvalidState, match="may request only"):
        command_event(args)
    assert not any(row.get("event_type") == "gate_execution" for row in ctx.events())


def test_emit_stage_checkpoint_is_structured_and_short(tmp_path: Path, valid_bundle) -> None:
    state, events = copy.deepcopy(valid_bundle)
    workspace = Path(str(state["workspace"]))
    ctx = StateContext.build(
        runtime="test",
        project="example",
        workspace=str(workspace),
        session="check-session",
        round_id="check-round",
        state_root=str(tmp_path / "state"),
    )
    ctx.save(state)
    for event in events:
        ctx.append_event(event)
    recorded = emit_stage_checkpoint(ctx, ctx.load(), reason="precompact", actor="runtime")
    assert recorded["event_type"] == "stage_checkpoint"
    assert recorded["goal_drift"]["status"] == "aligned"
    handoff_path = (
        workspace / ".agent-supervisor" / "handoffs" / sha256_text("check-session") / "latest.md"
    )
    text = handoff_path.read_text(encoding="utf-8")
    assert recorded["handoff_sha256"] == sha256_text(text)
    assert text.startswith("# RoundProcessSummary/v1")
    assert text.count("\n") <= 20
    assert "Traceback" not in text


_NATIVE_PATCH = (
    "*** Begin Patch\n*** Update File: src/baseline.py\n@@\n-VALUE = 1\n+VALUE = 2\n*** End Patch"
)


def _event_kind(row: dict[str, Any]) -> str:
    details = row.get("details") if isinstance(row.get("details"), dict) else {}
    return str(details.get("kind") or "")


@pytest.mark.parametrize(
    "tool_name,tool_input,should_deny",
    [
        ("exec_command", {"cmd": "python -c \"print('ok')\""}, True),
        ("apply_patch", {"command": _NATIVE_PATCH}, False),
        ("apply_patch_v2", {"command": _NATIVE_PATCH}, False),
        ("Bash", {"command": "python -c \"print('ok')\""}, True),
    ],
)
def test_posttool_native_tools_persist_native_command_kind(
    codex_round,
    monkeypatch,
    capsys,
    tool_name: str,
    tool_input: dict[str, str],
    should_deny: bool,
) -> None:
    _, state_root, common, ctx = codex_round
    invocation_id = f"native-{tool_name}"
    payload = {
        **common,
        "tool_use_id": invocation_id,
        "tool_name": tool_name,
        "tool_input": tool_input,
    }
    pre_code, pre_output = _run_hook(
        monkeypatch,
        capsys,
        state_root=state_root,
        event="PreToolUse",
        payload=payload,
    )
    assert pre_code == 0
    if should_deny:
        assert pre_output["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert (
            "native-command-effects"
            in pre_output["hookSpecificOutput"]["permissionDecisionReason"]
        )
        invocation_rows = [
            row
            for row in ctx.events()
            if row.get("invocation_id") == invocation_id
            and row.get("event_type") in {"invocation_attempt", "invocation_result"}
        ]
        assert invocation_rows == []
        summary = build_round_process_summary(ctx.load(), ctx.events())
        assert not any(
            isinstance(row, dict) and row.get("canonical_id") == tool_name
            for row in summary["timeline"]
        )
        assert f"Command｜{tool_name}｜" not in render_round_process_summary(summary)
        return

    assert pre_output == {}
    assert _run_hook(
        monkeypatch,
        capsys,
        state_root=state_root,
        event="PostToolUse",
        payload={**payload, "tool_response": {"exitCode": 0}},
    )[0] == 0
    attempt = next(
        row
        for row in ctx.events()
        if row.get("invocation_id") == invocation_id and row.get("event_type") == "invocation_attempt"
    )
    result = next(
        row
        for row in ctx.events()
        if row.get("invocation_id") == invocation_id and row.get("event_type") == "invocation_result"
    )
    assert _event_kind(attempt) == "native_command"
    assert _event_kind(result) == "native_command"
    assert result["result"] == "success"
    summary = build_round_process_summary(ctx.load(), ctx.events())
    by_id = {
        str(row["canonical_id"]): row
        for row in summary["timeline"]
        if isinstance(row, dict)
    }
    native_row = by_id[tool_name]
    assert native_row["kind"] == "native_command"
    assert native_row["status"] == "success"
    view = render_round_process_summary(summary)
    assert f"Command｜{tool_name}｜success" in view
    assert f"Skill｜{tool_name}｜" not in view


def test_posttool_native_failure_keeps_native_command_kind(
    codex_round, monkeypatch, capsys
) -> None:
    _, state_root, common, ctx = codex_round
    payload = {
        **common,
        "tool_use_id": "native-fail",
        "tool_name": "apply_patch",
        "tool_input": {"command": _NATIVE_PATCH},
    }
    assert _run_hook(
        monkeypatch,
        capsys,
        state_root=state_root,
        event="PreToolUse",
        payload=payload,
    ) == (0, {})
    assert _run_hook(
        monkeypatch,
        capsys,
        state_root=state_root,
        event="PostToolUse",
        payload={**payload, "tool_response": {"isError": True, "exitCode": 2}},
    )[0] == 0
    result = next(
        row
        for row in ctx.events()
        if row.get("invocation_id") == "native-fail" and row.get("event_type") == "invocation_result"
    )
    assert result["result"] == "failed"
    assert _event_kind(result) == "native_command"
    summary = build_round_process_summary(ctx.load(), ctx.events())
    native_row = next(
        row
        for row in summary["timeline"]
        if isinstance(row, dict) and row.get("canonical_id") == "apply_patch"
    )
    assert native_row["kind"] == "native_command"
    assert native_row["status"] == "failed"
    view = render_round_process_summary(summary)
    assert "Command｜apply_patch｜failed" in view


def test_skill_and_unknown_tools_are_not_forced_native(
    codex_round, monkeypatch, capsys
) -> None:
    _, state_root, common, ctx = codex_round
    skill_payload = {
        **common,
        "tool_use_id": "skill-1",
        "tool_name": "Skill",
        "tool_input": {"skill": "dev-supervisor"},
    }
    unknown_payload = {
        **common,
        "tool_use_id": "vendor-1",
        "tool_name": "VendorAudit",
        "tool_input": {},
    }
    for payload in (skill_payload, unknown_payload):
        assert _run_hook(monkeypatch, capsys, state_root=state_root, event="PreToolUse", payload=payload)[0] == 0
        assert _run_hook(
            monkeypatch,
            capsys,
            state_root=state_root,
            event="PostToolUse",
            payload={**payload, "tool_response": {"exitCode": 0}},
        )[0] == 0
    skill_result = next(
        row
        for row in ctx.events()
        if row.get("invocation_id") == "skill-1" and row.get("event_type") == "invocation_result"
    )
    unknown_result = next(
        row
        for row in ctx.events()
        if row.get("invocation_id") == "vendor-1" and row.get("event_type") == "invocation_result"
    )
    assert _event_kind(skill_result) != "native_command"
    assert _event_kind(unknown_result) != "native_command"
    summary = build_round_process_summary(ctx.load(), ctx.events())
    by_id = {
        str(row["canonical_id"]): row
        for row in summary["timeline"]
        if isinstance(row, dict)
    }
    assert by_id["dev-supervisor"]["kind"] == "skill"
    assert by_id["VendorAudit"]["kind"] != "native_command"
    view = render_round_process_summary(summary)
    assert "Command｜dev-supervisor｜" not in view
    assert "Command｜VendorAudit｜" not in view


def test_uninventoried_skill_label_cannot_spoof_signed_timeline(
    codex_round, monkeypatch, capsys
) -> None:
    _, state_root, common, ctx = codex_round
    payload = {
        **common,
        "tool_use_id": "spoofed-skill",
        "tool_name": "Skill",
        "tool_input": {"skill": "not-installed-capability"},
    }
    assert _run_hook(
        monkeypatch, capsys, state_root=state_root, event="PreToolUse", payload=payload
    )[0] == 0
    assert _run_hook(
        monkeypatch,
        capsys,
        state_root=state_root,
        event="PostToolUse",
        payload={**payload, "tool_response": {"exitCode": 0}},
    )[0] == 0

    result = next(
        row
        for row in ctx.events()
        if row.get("invocation_id") == "spoofed-skill"
        and row.get("event_type") == "invocation_result"
    )
    assert result["capability"] == "Skill"
