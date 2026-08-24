from __future__ import annotations

from argparse import Namespace
import copy
import json
from pathlib import Path

import pytest

import supervisor_core.cli as cli_module
from supervisor_core.attestation import sign_record, verify_record
from supervisor_core.contracts import invocation_event
from supervisor_core.executable_trust import (
    load_trusted_executable_registry,
    registry_public_record,
)
from supervisor_core.storage import StateContext
from supervisor_core.validation import _trusted_invocation_for_runtime, validate_state


def _context(tmp_path: Path, *, builtin: str = "goal-finalize") -> StateContext:
    ctx = StateContext.build(
        runtime="codex",
        project="r48-core",
        workspace=str(tmp_path),
        session="session-r48",
        round_id="round-r48",
        state_root=tmp_path / "state",
    )
    gate_id = f"gate.{builtin}"
    ctx.save({
        "schema_version": 3,
        "runtime": "codex",
        "project": "r48-core",
        "workspace": str(tmp_path.resolve()),
        "session": "session-r48",
        "round": "round-r48",
        "execution_mode": "observe",
        "health": "healthy",
        "stop_attempts": 0,
        "goal": {
            "goal_id": "goal-r48",
            "version": 1,
            "acceptance_criteria": [{
                "criterion_id": "criterion-r48",
                "domain": "config-agent",
                "expected_evidence": [gate_id],
            }],
        },
        "request_manifest": {"contract": "RequestManifest/v3", "round": "round-r48"},
        "changes": {"domains": ["config-agent"]},
        "intents": [] if builtin == "intent-coverage" else [{"status": "covered"}],
        "evidence": [],
        "trusted_executable_registry": registry_public_record(
            load_trusted_executable_registry()
        ),
        "quality_profile": {
            "global_gates": [],
            "gates": [{"id": gate_id, "builtin": builtin}],
            "domains": {"config/agent": {"required_gates": [gate_id]}},
        },
    })
    return ctx


def _fake_finalize(context: StateContext, **_kwargs):
    state = context.load()
    state.update({
        "terminal_state": "complete",
        "host_gate": {"should_block": False},
        "validation": {"valid": True, "health": "healthy", "errors": []},
    })
    return state, 0


def test_finalize_autoruns_missing_builtin_with_unique_trusted_invocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    ctx = _context(tmp_path)
    monkeypatch.setattr(cli_module, "_context", lambda *_args, **_kwargs: ctx)
    monkeypatch.setattr(
        cli_module, "_verify_current_source_snapshot", lambda *_args, **_kwargs: "a" * 64
    )
    monkeypatch.setattr(cli_module, "finalize_round", _fake_finalize)

    assert cli_module.command_finalize(Namespace(stop_attempt=None, blocked=False)) == 0
    capsys.readouterr()

    evidence = ctx.load()["evidence"]
    assert len(evidence) == 1
    assert evidence[0]["gate_id"] == "gate.goal-finalize"
    invocation_id = evidence[0]["collector_invocation_id"]
    pair = [
        row for row in ctx.events()
        if row.get("invocation_id") == invocation_id
        and row.get("event_type") in {"invocation_attempt", "invocation_result"}
    ]
    assert [row["event_type"] for row in pair] == [
        "invocation_attempt", "invocation_result"
    ]
    assert all(row["actor"] == "supervisor-core" for row in pair)
    assert all(row["responsibility_group"] == "trusted-runtime" for row in pair)
    assert all(row["identity_assurance"] == "core-trusted-finalize" for row in pair)
    assert pair[1]["result"] == "success"
    assert all(verify_record(row) for row in pair)
    assert _trusted_invocation_for_runtime(
        ctx.events(), invocation_id,
        actor="supervisor-core",
        responsibility_group="trusted-runtime",
        state=ctx.load(),
    )


def test_finalize_records_failed_result_when_builtin_gate_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    ctx = _context(tmp_path, builtin="intent-coverage")
    monkeypatch.setattr(cli_module, "_context", lambda *_args, **_kwargs: ctx)
    monkeypatch.setattr(
        cli_module, "_verify_current_source_snapshot", lambda *_args, **_kwargs: "a" * 64
    )
    monkeypatch.setattr(cli_module, "finalize_round", _fake_finalize)

    assert cli_module.command_finalize(Namespace(stop_attempt=None, blocked=False)) == 0
    capsys.readouterr()
    results = [
        row for row in ctx.events()
        if row.get("event_type") == "invocation_result"
        and row.get("capability") == "supervisor-core-builtin:gate.intent-coverage"
    ]
    assert len(results) == 1
    assert results[0]["result"] == "failed"
    assert ctx.load()["evidence"] == []


@pytest.mark.parametrize("mismatch", ["actor", "group", "assurance", "id"])
def test_finalize_internal_gate_rejects_identity_group_assurance_and_id_mismatch(
    tmp_path: Path, mismatch: str
) -> None:
    ctx = _context(tmp_path)
    state = ctx.load()
    invocation_id = "invocation-r48"
    attempt = cli_module._finalize_invocation_event(
        state,
        invocation_id=invocation_id,
        gate_id="gate.goal-finalize",
        criterion_id="criterion-r48",
        stage="attempt",
        result=None,
    )
    actor = "supervisor-core"
    group = "trusted-runtime"
    requested_id = invocation_id
    if mismatch == "actor":
        actor = "forged-supervisor"
    elif mismatch == "group":
        group = "forged-runtime"
    elif mismatch == "assurance":
        attempt["identity_assurance"] = "codex-explicit-audit"
        attempt["attestation"] = sign_record(attempt)
    else:
        requested_id = "invocation-does-not-exist"
    ctx.append_event(attempt)

    with pytest.raises(cli_module.InvalidState):
        cli_module._run_registered_gate(
            ctx,
            {
                "event_type": "gate_run",
                "actor": actor,
                "record": {
                    "gate_id": "gate.goal-finalize",
                    "criterion_id": "criterion-r48",
                    "collector": actor,
                    "collector_responsibility_group": group,
                    "collector_invocation_id": requested_id,
                },
            },
            finalize_internal=True,
        )
    assert ctx.load()["evidence"] == []
    assert not any(row.get("event_type") == "gate_grant" for row in ctx.events())


def test_review_gate_raw_streams_are_transient_and_never_persisted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = _context(tmp_path)
    state = ctx.load()
    state["quality_profile"] = {
        "common_gates": [{
            "id": "review.coderabbit",
            "command": [
                "supervisor-trusted-core-runner",
                "bin/run-coderabbit-review.py",
                "--review-category",
                "independent",
            ],
            "precondition": ["trusted-precondition"],
            "trusted_core_runner": True,
        }],
    }
    state["changes"] = {
        "diff_hash": "d" * 64,
        "workspace_base_sha256": "b" * 64,
        "workspace_head_sha256": "c" * 64,
    }
    ctx.save(state)
    binding = {
        "contract": "ReviewArtifactBindingInput/v1",
        "workspace_base_sha256": "b" * 64,
        "workspace_head_sha256": "c" * 64,
        "diff_hash": "d" * 64,
        "workspace_delta_manifest": {},
    }
    monkeypatch.setattr(
        cli_module,
        "_review_binding_input",
        lambda _state, **_kwargs: copy.deepcopy(binding),
    )
    monkeypatch.setattr(
        cli_module, "_verify_current_source_snapshot", lambda *_args, **_kwargs: "a" * 64
    )
    monkeypatch.setattr(
        cli_module,
        "_trusted_core_runner_command",
        lambda *_args, **_kwargs: ["trusted-review"],
    )
    monkeypatch.setattr(
        cli_module,
        "_resolve_gate_command",
        lambda command, **_kwargs: (list(command), "C:/trusted/gate.exe", "e" * 64),
    )
    pre_stdout = "PRECONDITION-PRIVATE-SENTINEL" + "p" * 5000
    pre_stderr = "PRECONDITION-STDERR-SENTINEL" + "q" * 5000
    main_stdout = "REVIEW-PRIVATE-SENTINEL" + "r" * 5000
    main_stderr = "REVIEW-STDERR-SENTINEL" + "s" * 5000
    outputs = iter([
        {
            "exit_code": 0, "stdout": pre_stdout, "stderr": pre_stderr,
            "stdout_truncated": False, "stderr_truncated": False,
            "timed_out": False,
        },
        {
            "exit_code": 0, "stdout": main_stdout, "stderr": main_stderr,
            "stdout_truncated": False, "stderr_truncated": False,
            "timed_out": False,
        },
    ])
    monkeypatch.setattr(
        cli_module, "_run_gate_subprocess_bounded", lambda *_args, **_kwargs: next(outputs)
    )
    parsed_artifact = {
        "contract": "ReviewOutputArtifact/v1",
        "review_category": "independent",
        "verified": True,
    }

    def parse(stdout: str, stderr: str, supplied_binding: dict, **_kwargs):
        assert stdout == main_stdout
        assert stderr == main_stderr
        assert supplied_binding == binding
        return copy.deepcopy(parsed_artifact), "verified"

    monkeypatch.setattr(cli_module, "_parse_review_gate_output", parse)
    issued_reviews: list[dict] = []
    monkeypatch.setattr(
        cli_module,
        "_issue_automated_external_review",
        lambda _ctx, **kwargs: issued_reviews.append(copy.deepcopy(kwargs)),
    )
    execution, evidence, exit_code = cli_module._run_registered_gate(
        ctx,
        {
            "event_type": "gate_run",
            "record": {
                "gate_id": "review.coderabbit",
                "criterion_id": "criterion-r48",
                "evidence_id": "evidence-r48",
            },
        },
    )

    assert exit_code == 0
    assert evidence["collector"] == "supervisor-core"
    assert evidence["collector_responsibility_group"] == "trusted-core-gate-execution"
    assert evidence["collector_identity_assurance"] == "core-executed-gate"
    assert evidence["collector_completion_eligible"] is True
    assert issued_reviews[0]["review_output"]["review_category"] == "independent"
    for record in (execution["precondition"], evidence["precondition"]):
        assert not {"raw_output", "raw_stdout", "raw_stderr"} & set(record)
    durable = ctx.state_file.read_bytes() + ctx.events_file.read_bytes()
    for sentinel in (
        b"PRECONDITION-PRIVATE-SENTINEL",
        b"PRECONDITION-STDERR-SENTINEL",
        b"REVIEW-PRIVATE-SENTINEL",
        b"REVIEW-STDERR-SENTINEL",
    ):
        assert sentinel not in durable


def test_done_task_with_non_list_allowed_paths_reports_shape_error_without_crashing(
    valid_bundle,
) -> None:
    state, events = copy.deepcopy(valid_bundle)
    state["tasks"][0]["allowed_paths"] = 7
    report = validate_state(state, events)
    assert report["valid"] is False
    assert any("allowed paths empty" in error for error in report["errors"])
