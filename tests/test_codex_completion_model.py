from __future__ import annotations

import copy
import json
import sys
import types
from pathlib import Path

import pytest

from supervisor_core.attestation import sign_record
from supervisor_core import cli as cli_module
from supervisor_core import workspace as workspace_module
from supervisor_core.contracts import invocation_event
from supervisor_core.executable_trust import (
    load_trusted_executable_registry,
    registry_public_record,
)
from supervisor_core.lifecycle import start_round
from supervisor_core.storage import StateContext
from supervisor_core.util import canonical_sha256, sha256_file
from supervisor_core.validation import (
    _completion_trusted_invocations,
    _trusted_invocation_for_runtime,
)


def _request_binding(state: dict) -> dict:
    goal = state["goal"]
    return {
        "runtime": state["runtime"],
        "project": state["project"],
        "workspace": str(Path(state["workspace"]).resolve()),
        "session": state["session"],
        "round": state["round"],
        "goal_id": goal["goal_id"],
        "goal_version": goal["version"],
        "request_manifest_sha256": canonical_sha256(state["request_manifest"]),
    }


def _as_codex_state(state: dict) -> dict:
    state = copy.deepcopy(state)
    state["runtime"] = "codex"
    manifest = state["request_manifest"]
    manifest["runtime"] = "codex"
    manifest.pop("attestation", None)
    manifest["attestation"] = sign_record(manifest)
    return state


def _codex_pair(
    state: dict,
    *,
    invocation_id: str = "codex-skill-1",
    capability: str = "dev-supervisor",
    actor: str = "codex-agent",
    group: str = "local-capability-execution",
    result: str = "success",
) -> list[dict]:
    details = {"phase": "implementation", **_request_binding(state)}
    return [
        invocation_event(
            invocation_id=invocation_id,
            capability=capability,
            stage="attempt",
            result=None,
            actor=actor,
            responsibility_group=group,
            identity_assurance="codex-explicit-audit",
            details=copy.deepcopy(details),
        ),
        invocation_event(
            invocation_id=invocation_id,
            capability=capability,
            stage="result",
            result=result,
            actor=actor,
            responsibility_group=group,
            identity_assurance="codex-explicit-audit",
            details=copy.deepcopy(details),
        ),
    ]


def _resign(event: dict) -> None:
    event.pop("attestation", None)
    event["attestation"] = sign_record(event)


def _gate_context(tmp_path: Path) -> StateContext:
    registry = load_trusted_executable_registry()
    public_registry = registry_public_record(registry)
    trusted_python = public_registry["entries"]["python"]["path"]
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    ctx = StateContext.build(
        runtime="codex",
        project="completion-model",
        workspace=str(workspace),
        session="session-gate",
        round_id="round-gate",
        state_root=tmp_path / "state",
    )
    start_round(
        ctx,
        message="run the registered quality gate",
        change_mode="replace",
        execution_mode="observe",
        quality_profile={
            "common_gates": [
                {
                    "id": "gate.safe",
                    "command": [trusted_python, "-c", "print('registered')"],
                }
            ]
        },
        goal_supplied={
            "acceptance_criteria": [
                {
                    "criterion_id": "criterion-gate",
                    "description": "registered gate passes",
                    "domain": "general",
                    "expected_evidence": ["gate.safe"],
                    "required": True,
                }
            ]
        },
    )
    ctx.update(
        lambda state: state.update({
            "trusted_executable_registry": public_registry
        })
    )
    return ctx


def _coderabbit_summary() -> dict:
    return {
        "engine": "coderabbit",
        "authenticated": True,
        "status": "pass",
        "exit_code": 0,
        "structured_events": 2,
        "terminal_outcome": "success",
        "finding_count": 0,
        "complete_reported_findings": 0,
        "blocking_findings": 0,
        "severity_counts": {"critical": 0, "major": 0, "minor": 0},
        "protocol_blockers": [],
        "context_bound": True,
        "issues": [],
        "stdout_sha256": "1" * 64,
        "stderr_sha256": "2" * 64,
    }


def _review_binding_and_output(category: str = "independent") -> tuple[dict, dict]:
    manifest = {"config.json": {"before": "3" * 64, "after": "4" * 64}}
    binding = {
        "contract": "ReviewArtifactBindingInput/v1",
        "workspace_base_sha256": "5" * 64,
        "workspace_head_sha256": "6" * 64,
        "diff_hash": canonical_sha256(manifest),
        "workspace_delta_manifest": manifest,
    }
    output = {
        "contract": "ReviewOutputArtifact/v1",
        "review_category": category,
        "review_artifact": {
            "kind": "git-bundle-v1",
            "bundle_path": "C:/sealed/review.bundle",
            "bundle_sha256": "7" * 64,
            "manifest_path": "C:/sealed/review.manifest.json",
            "manifest_sha256": "8" * 64,
        },
        "review_summary": _coderabbit_summary(),
        "base": "9" * 40,
        "head": "a" * 40,
        "git_object_format": "sha1",
        "git_diff_sha256": "b" * 64,
        "workspace_base_sha256": binding["workspace_base_sha256"],
        "workspace_head_sha256": binding["workspace_head_sha256"],
        "diff_hash": binding["diff_hash"],
    }
    return binding, output


def _automated_review_context(
    valid_bundle, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[StateContext, dict, dict, dict]:
    registry = load_trusted_executable_registry()
    public_registry = registry_public_record(registry)
    trusted_python = public_registry["entries"]["python"]["path"]
    state, _ = valid_bundle
    state = _as_codex_state(state)
    repository = Path(state["workspace"])
    state["workspace_baseline"] = workspace_module.capture_workspace_snapshot(
        str(repository)
    )
    (repository / "config.json").write_text('{"v":3}\n', encoding="utf-8")
    state["changes"] = cli_module._core_codex_changes_record(
        state, {"domains": ["config/agent"]}
    )
    state["evidence"] = []
    state["reviews"] = []
    state["quality_profile"] = {
        "common_gates": [
            {
                "id": "review.coderabbit",
                "trusted_core_runner": True,
                "command": [
                    "supervisor-trusted-core-runner",
                    "bin/run-coderabbit-review.py",
                    "--review-category",
                    "independent",
                ],
            }
        ]
    }
    state["goal"]["acceptance_criteria"][0]["expected_evidence"] = [
        "review.coderabbit"
    ]
    state["request_manifest"]["goal_sha256"] = canonical_sha256(state["goal"])
    state["request_manifest"].pop("attestation", None)
    state["request_manifest"]["attestation"] = sign_record(
        state["request_manifest"]
    )
    state["tasks"][0]["expected_evidence"] = ["review.coderabbit"]
    state["tasks"][0]["evidence_ids"] = ["evidence-review-1"]
    state["supervisor_source_snapshot"] = (
        cli_module.capture_validated_supervisor_source_snapshot()
    )
    state["trusted_executable_registry"] = public_registry
    ctx = StateContext.build(
        runtime="codex",
        project="completion-review",
        workspace=state["workspace"],
        session=state["session"],
        round_id=state["round"],
        state_root=tmp_path / "review-state",
    )
    ctx.initialize()
    ctx.save(state)
    monkeypatch.setattr(cli_module.sys, "executable", trusted_python)

    def run(_command: list[str], **kwargs) -> dict:
        binding_path = Path(kwargs["extra_env"]["AGENT_SUPERVISOR_REVIEW_BINDING_FILE"])
        binding = json.loads(binding_path.read_text(encoding="utf-8"))
        source_frame = json.loads(kwargs["input_bytes"].decode("ascii"))
        assert source_frame["contract"] == "SupervisorReviewSourceFrame/v1"
        assert source_frame["resources"]["bin/run-coderabbit-review.py"]
        assert (
            source_frame["core_manifest_sha256"]
            == binding["review_core_manifest_sha256"]
        )
        assert binding["supervisor_source_snapshot_sha256"]
        assert kwargs["replace_env"] is True
        _, output = _review_binding_and_output()
        output["workspace_base_sha256"] = binding["workspace_base_sha256"]
        output["workspace_head_sha256"] = binding["workspace_head_sha256"]
        output["diff_hash"] = binding["diff_hash"]
        monkeypatch.setattr(
            workspace_module,
            "validate_review_artifact",
            lambda *_args, **_kwargs: (
                True,
                "verified",
                    {
                        "workspace_delta_manifest": binding["workspace_delta_manifest"],
                        "git_diff_sha256": output["git_diff_sha256"],
                        "source_review_manifest": binding["review_adapter_manifest"],
                        **{
                            field: binding[field]
                            for field in (
                                "supervisor_source_snapshot_sha256",
                                "review_core_manifest_sha256",
                                "review_adapter_manifest_sha256",
                            )
                            if field in binding
                        },
                    },
            ),
        )
        return {
            "exit_code": 0,
            "stdout": json.dumps(output, sort_keys=True, separators=(",", ":")),
            "stderr": "",
            "stdout_truncated": False,
            "stderr_truncated": False,
            "timed_out": False,
        }

    monkeypatch.setattr(cli_module, "_run_gate_subprocess_bounded", run)
    evidence, execution, code = cli_module._run_registered_gate(
        ctx,
        {
            "event_type": "gate_run",
            "record": {
                "gate_id": "review.coderabbit",
                "criterion_id": "criterion-1",
                "evidence_id": "evidence-review-1",
            },
        },
    )
    assert code == 0, {
        "execution_status": execution.get("status"),
        "health": ctx.load().get("health"),
        "output_summary": execution.get("output_summary"),
    }
    reviews = ctx.load()["reviews"]
    assert len(reviews) == 1
    return ctx, evidence, execution, reviews[0]


def test_unique_round_bound_codex_skill_success_contributes_to_intent(valid_bundle) -> None:
    state, _ = valid_bundle
    state = _as_codex_state(state)
    events = _codex_pair(state)

    capabilities, results, errors = _completion_trusted_invocations(state, events)

    assert capabilities == {"dev-supervisor"}
    assert results["codex-skill-1"]["result"] == "success"
    assert errors == []


@pytest.mark.parametrize("result", ["failed", "refused", "cancelled", "manual-specialized"])
def test_non_success_codex_skill_result_never_contributes(valid_bundle, result: str) -> None:
    state, _ = valid_bundle
    state = _as_codex_state(state)

    capabilities, _, _ = _completion_trusted_invocations(
        state, _codex_pair(state, result=result)
    )

    assert capabilities == set()


def test_attempt_only_and_duplicate_codex_events_never_contribute(valid_bundle) -> None:
    state, _ = valid_bundle
    state = _as_codex_state(state)
    pair = _codex_pair(state)

    attempt_only, _, _ = _completion_trusted_invocations(state, pair[:1])
    duplicate_attempt, _, duplicate_errors = _completion_trusted_invocations(
        state, [pair[0], copy.deepcopy(pair[0]), pair[1]]
    )

    assert attempt_only == set()
    assert duplicate_attempt == set()
    assert duplicate_errors


@pytest.mark.parametrize(
    ("target", "mutation"),
    [
        ("result", lambda row: row.update({"capability": "other-capability"})),
        ("result", lambda row: row.update({"actor": "other-actor"})),
        ("result", lambda row: row.update({"responsibility_group": "other-group"})),
        ("attempt", lambda row: row["details"].update({"round": "other-round"})),
        (
            "result",
            lambda row: row["details"].update(
                {"request_manifest_sha256": "0" * 64}
            ),
        ),
    ],
    ids=["capability", "actor", "group", "round", "request-manifest"],
)
def test_codex_skill_binding_mismatch_never_contributes(
    valid_bundle, target: str, mutation
) -> None:
    state, _ = valid_bundle
    state = _as_codex_state(state)
    pair = _codex_pair(state)
    row = pair[0] if target == "attempt" else pair[1]
    mutation(row)
    _resign(row)

    capabilities, _, _ = _completion_trusted_invocations(state, pair)

    assert capabilities == set()


def test_locally_audited_codex_skill_never_establishes_actor_or_group_identity(
    valid_bundle,
) -> None:
    state, _ = valid_bundle
    state = _as_codex_state(state)
    events = _codex_pair(state)

    capabilities, _, _ = _completion_trusted_invocations(state, events)

    assert capabilities == {"dev-supervisor"}
    assert not _trusted_invocation_for_runtime(
        events,
        "codex-skill-1",
        actor="codex-agent",
        responsibility_group="local-capability-execution",
        state=state,
    )
    for forbidden_group in (
        "implementation",
        "independent-review",
        "independent-gate-runner",
    ):
        assert not _trusted_invocation_for_runtime(
            events,
            "codex-skill-1",
            actor="codex-agent",
            responsibility_group=forbidden_group,
            state=state,
        )


def test_codex_gate_run_mints_fixed_core_collector_and_uses_registered_argv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = _gate_context(tmp_path)
    monkeypatch.setattr(
        cli_module,
        "_verify_current_source_snapshot",
        lambda *_args, **_kwargs: "a" * 64,
    )
    seen: list[list[str]] = []

    def run(command: list[str], **_kwargs) -> dict:
        seen.append(command)
        return {
            "exit_code": 0,
            "stdout": "registered\n",
            "stderr": "",
            "stdout_truncated": False,
            "stderr_truncated": False,
            "timed_out": False,
        }

    monkeypatch.setattr(cli_module, "_run_gate_subprocess_bounded", run)

    evidence, execution, code = cli_module._run_registered_gate(
        ctx,
        {
            "event_type": "gate_run",
            "record": {
                "gate_id": "gate.safe",
                "criterion_id": "criterion-gate",
                "evidence_id": "evidence-safe",
            },
        },
    )

    assert code == 0
    assert len(seen) == 1
    assert seen[0][1:] == ["-c", "print('registered')"]
    assert evidence["collector"] == execution["collector"] == "supervisor-core"
    assert (
        evidence["collector_responsibility_group"]
        == execution["collector_responsibility_group"]
        == "trusted-core-gate-execution"
    )
    assert evidence["collector_identity_assurance"] == "core-executed-gate"
    assert evidence["collector_completion_eligible"] is True
    invocation_id = evidence["collector_invocation_id"]
    pair = [
        row
        for row in ctx.events()
        if row.get("invocation_id") == invocation_id
        and row.get("event_type") in {"invocation_attempt", "invocation_result"}
    ]
    assert len(pair) == 2
    assert pair[0]["result"] is None
    assert pair[1]["result"] == "success"


@pytest.mark.parametrize(
    "forbidden",
    [
        {"collector": "caller"},
        {"collector_responsibility_group": "caller-group"},
        {"collector_invocation_id": "caller-id"},
        {"command": ["caller-command"]},
        {"timeout_seconds": 999},
    ],
    ids=["actor", "group", "invocation", "command", "timeout"],
)
def test_codex_gate_run_caller_cannot_choose_execution_identity_or_command(
    tmp_path: Path, forbidden: dict
) -> None:
    ctx = _gate_context(tmp_path)
    request = {
        "gate_id": "gate.safe",
        "criterion_id": "criterion-gate",
        **forbidden,
    }

    with pytest.raises(cli_module.InvalidState):
        cli_module._run_registered_gate(
            ctx,
            {"event_type": "gate_run", "record": request},
        )

    assert ctx.load()["evidence"] == []


def test_gate_resolution_ignores_path_poisoning_and_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    poisoned = tmp_path / ("unregistered-gate.exe" if sys.platform == "win32" else "unregistered-gate")
    poisoned.write_bytes(b"not a trusted executable")
    monkeypatch.setenv("PATH", str(tmp_path))
    registry = load_trusted_executable_registry()

    with pytest.raises(FileNotFoundError, match="round-bound trust registry"):
        cli_module._resolve_gate_command(
            ["unregistered-gate"],
            cwd=str(tmp_path),
            trusted_registry=registry,
        )


@pytest.mark.parametrize(
    ("process_result", "expected_code", "expected_status", "expected_health"),
    [
        (
            {
                "exit_code": 7,
                "stdout": "",
                "stderr": "gate failed",
                "stdout_truncated": False,
                "stderr_truncated": False,
                "timed_out": False,
            },
            2,
            "failed",
            "healthy",
        ),
        (
            {
                "exit_code": -1,
                "stdout": "",
                "stderr": "",
                "stdout_truncated": False,
                "stderr_truncated": False,
                "timed_out": True,
            },
            4,
            "degraded",
            "degraded",
        ),
    ],
    ids=["failure", "timeout"],
)
def test_codex_core_gate_failure_and_timeout_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    process_result: dict,
    expected_code: int,
    expected_status: str,
    expected_health: str,
) -> None:
    ctx = _gate_context(tmp_path)
    monkeypatch.setattr(
        cli_module,
        "_verify_current_source_snapshot",
        lambda *_args, **_kwargs: "a" * 64,
    )
    monkeypatch.setattr(
        cli_module,
        "_run_gate_subprocess_bounded",
        lambda *_args, **_kwargs: copy.deepcopy(process_result),
    )

    evidence, execution, code = cli_module._run_registered_gate(
        ctx,
        {
            "event_type": "gate_run",
            "record": {
                "gate_id": "gate.safe",
                "criterion_id": "criterion-gate",
            },
        },
    )

    assert code == expected_code
    assert execution["status"] == expected_status
    assert evidence["evidence_id"] not in {
        row.get("evidence_id") for row in ctx.load()["evidence"]
    }
    assert ctx.load()["health"] == expected_health
    result_events = [
        row
        for row in ctx.events()
        if row.get("event_type") == "invocation_result"
        and row.get("identity_assurance") == "core-executed-gate"
    ]
    assert len(result_events) == 1
    assert result_events[0]["result"] == "failed"


def test_trusted_coderabbit_runner_requires_exact_core_marker_and_source_hash() -> None:
    core_root = Path(cli_module.__file__).resolve().parent.parent
    runner = core_root / "bin" / "run-coderabbit-review.py"
    state = {
        "supervisor_source_snapshot": {
            "roots": {"shared-core": str(core_root)},
            "files": {
                "shared-core/bin/run-coderabbit-review.py": {
                    "status": "hashed",
                    "sha256": sha256_file(runner),
                    "size": runner.stat().st_size,
                }
            },
        }
    }
    exact_gate = {
        "trusted_core_runner": True,
        "command": [
            "supervisor-trusted-core-runner",
            "bin/run-coderabbit-review.py",
            "--review-category",
            "independent",
        ],
    }

    resolved = cli_module._trusted_core_runner_command(
        state, "review.coderabbit", exact_gate
    )

    assert isinstance(resolved, list)
    assert type(resolved) is not list
    assert resolved[:6] == [str(Path(sys.executable)), "-I", "-S", "-X", "utf8", "-c"]
    assert isinstance(resolved[6], str) and "sys.stdin.buffer.read()" in resolved[6]
    assert resolved[7] == "shared-core/bin/run-coderabbit-review.py"
    assert resolved[-2:] == ["--review-category", "independent"]
    assert resolved.input_bytes == runner.read_bytes()
    assert "input_bytes" not in json.dumps(resolved)

    wrapper = copy.deepcopy(exact_gate)
    wrapper["command"][1] = "project/wrapper.py"
    with pytest.raises(cli_module.InvalidState):
        cli_module._trusted_core_runner_command(
            state, "review.coderabbit", wrapper
        )

    drifted = copy.deepcopy(state)
    drifted["supervisor_source_snapshot"]["files"][
        "shared-core/bin/run-coderabbit-review.py"
    ]["sha256"] = "0" * 64
    with pytest.raises(cli_module.InvalidState):
        cli_module._trusted_core_runner_command(
            drifted, "review.coderabbit", exact_gate
        )


def test_bound_coderabbit_runner_uses_frozen_resource_after_disk_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = tmp_path / "release"
    disk_runner = release / "bin" / "run-coderabbit-review.py"
    disk_runner.parent.mkdir(parents=True)
    trusted = b"raise SystemExit(0)\n"
    disk_runner.write_bytes(b"raise SystemExit(91)\n")
    logical = "shared-core/bin/run-coderabbit-review.py"
    state = {
        "supervisor_source_snapshot": {
            "roots": {"shared-core": str(release.resolve())},
            "files": {
                logical: {
                    "status": "hashed",
                    "sha256": cli_module.sha256_bytes(trusted),
                    "size": len(trusted),
                }
            },
        }
    }
    bound_runtime = types.SimpleNamespace(
        contract="SupervisorBoundRuntime/v1",
        identity={
            "contract": "SupervisorReleaseIdentity/v1",
            "path": str(release.resolve()),
        },
        resources={"bin/run-coderabbit-review.py": trusted},
    )
    monkeypatch.setitem(
        sys.modules,
        "_agent_supervisor_bound_runtime",
        bound_runtime,
    )
    gate = {
        "trusted_core_runner": True,
        "command": [
            "supervisor-trusted-core-runner",
            "bin/run-coderabbit-review.py",
            "--review-category",
            "independent",
        ],
    }

    first = cli_module._trusted_core_runner_command(
        state, "review.coderabbit", gate
    )
    disk_runner.write_bytes(b"raise SystemExit(92)\n")
    second = cli_module._trusted_core_runner_command(
        state, "review.coderabbit", gate
    )

    for command in (first, second):
        assert isinstance(command, list)
        assert type(command) is not list
        assert command[1:6] == ["-I", "-S", "-X", "utf8", "-c"]
        assert command[7] == logical
        assert command.input_bytes == trusted
        assert "input_bytes" not in json.dumps(command)


def test_coderabbit_review_output_accepts_only_exact_bound_complete_approval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding, output = _review_binding_and_output()
    monkeypatch.setattr(
        workspace_module,
        "validate_review_artifact",
        lambda *_args, **_kwargs: (
            True,
            "verified",
            {
                "workspace_delta_manifest": binding["workspace_delta_manifest"],
                "git_diff_sha256": output["git_diff_sha256"],
            },
        ),
    )

    parsed, reason = cli_module._parse_review_gate_output(
        json.dumps(output, sort_keys=True, separators=(",", ":")),
        "",
        binding,
    )

    assert reason == "verified"
    assert parsed == output


@pytest.mark.parametrize(
    ("mutation", "expected_reason"),
    [
        (
            lambda output: output["review_summary"].update(
                {"authenticated": False}
            ),
            "review-summary-success-metadata-invalid",
        ),
        (
            lambda output: output["review_summary"].update(
                {"context_bound": False}
            ),
            "review-summary-success-metadata-invalid",
        ),
        (
            lambda output: output.update({"diff_hash": "0" * 64}),
            "review-output-diff_hash-mismatch",
        ),
        (
            lambda output: output["review_summary"].update(
                {
                    "finding_count": 1,
                    "complete_reported_findings": 0,
                }
            ),
            "review-summary-count-mismatch",
        ),
        (
            lambda output: output["review_summary"].update(
                {
                    "blocking_findings": 1,
                    "finding_count": 1,
                    "complete_reported_findings": 1,
                    "severity_counts": {"critical": 1, "major": 0, "minor": 0},
                    "issues": [
                        {
                            "kind": "finding",
                            "severity": "critical",
                            "path": "config.json",
                            "line": 1,
                            "title": "blocking",
                            "message": "must fix",
                        }
                    ],
                }
            ),
            "review-summary-count-mismatch",
        ),
    ],
    ids=["unauthenticated", "unbound-context", "wrong-diff", "incomplete-findings", "blocking"],
)
def test_coderabbit_review_output_fails_closed_on_forged_or_incomplete_result(
    monkeypatch: pytest.MonkeyPatch, mutation, expected_reason: str
) -> None:
    binding, output = _review_binding_and_output()
    mutation(output)
    monkeypatch.setattr(
        workspace_module,
        "validate_review_artifact",
        lambda *_args, **_kwargs: (
            True,
            "verified",
            {
                "workspace_delta_manifest": binding["workspace_delta_manifest"],
                "git_diff_sha256": output["git_diff_sha256"],
            },
        ),
    )

    parsed, reason = cli_module._parse_review_gate_output(
        json.dumps(output, sort_keys=True, separators=(",", ":")),
        "",
        binding,
    )

    assert parsed is None
    assert reason == expected_reason


def test_core_issues_automated_review_only_from_core_gate_provenance(
    valid_bundle, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _ctx, evidence, _execution, review = _automated_review_context(
        valid_bundle, tmp_path, monkeypatch
    )

    assert review is not None
    assert review["review_mode"] == "automated-external"
    assert review["review_category"] == "independent"
    assert review["verdict"] == "APPROVE"
    assert review["unresolved_p0_p1"] == 0
    assert review["actor_identity_assurance"] == "core-attested-external-review"
    assert review["issued_by"] == "supervisor-core-automated-external-review"
    assert review["findings"] == evidence["review_output_artifact"]["review_summary"]["issues"]


@pytest.mark.parametrize(
    "mutation",
    [
        lambda evidence, execution: evidence.update({"collector": "caller"}),
        lambda evidence, execution: evidence.update(
            {"collector_responsibility_group": "caller-group"}
        ),
        lambda evidence, execution: evidence.update(
            {"collector_identity_assurance": "codex-explicit-audit"}
        ),
        lambda evidence, execution: evidence.update(
            {"collector_invocation_id": "caller-invocation"}
        ),
        lambda evidence, execution: execution.update({"attestation": "0" * 64}),
    ],
    ids=["actor", "group", "assurance", "invocation", "execution-attestation"],
)
def test_forged_gate_provenance_cannot_trigger_core_issued_external_review(
    valid_bundle,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation,
) -> None:
    ctx, evidence, execution, _review = _automated_review_context(
        valid_bundle, tmp_path, monkeypatch
    )
    state = ctx.load()
    state["reviews"] = []
    ctx.save(state)
    mutation(evidence, execution)

    with pytest.raises(cli_module.InvalidState):
        cli_module._issue_automated_external_review(
            ctx,
            evidence=evidence,
            execution=execution,
            review_output=copy.deepcopy(evidence["review_output_artifact"]),
        )

    assert ctx.load()["reviews"] == []


def test_caller_cannot_submit_an_automated_external_review_directly(
    valid_bundle, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx, _evidence, _execution, review = _automated_review_context(
        valid_bundle, tmp_path, monkeypatch
    )
    forged = copy.deepcopy(review)
    forged["review_id"] = "caller-review"

    with pytest.raises(cli_module.InvalidState):
        cli_module._finalize_review(
            ctx,
            {
                "event_type": "review_finalize",
                "actor": "caller",
                "record": forged,
            },
        )


def test_codex_changes_record_uses_only_core_observed_workspace_identity(
    valid_bundle,
) -> None:
    state, _ = valid_bundle
    state = _as_codex_state(state)
    repository = Path(state["workspace"])
    state["workspace_baseline"] = workspace_module.capture_workspace_snapshot(
        str(repository)
    )
    (repository / "config.json").write_text('{"v":3}\n', encoding="utf-8")

    record = cli_module._core_codex_changes_record(
        state,
        {"domains": ["config/agent"]},
    )

    assert record["files"] == ["config.json"]
    assert record["implementer"] == "codex-local-workspace"
    assert record["implementer_responsibility_group"] == "local-workspace-producer"
    assert record["producer_identity_assurance"] == "core-observed-local-workspace"
    assert record["issued_by"] == "supervisor-core-workspace-observer"
    assert record["implementer_invocation_id"] == f"core-workspace-{record['diff_hash'][:24]}"
    assert sign_record({key: value for key, value in record.items() if key != "attestation"}) == record["attestation"]


@pytest.mark.parametrize(
    "forbidden_field",
    [
        "implementer",
        "implementer_responsibility_group",
        "implementer_invocation_id",
        "producer_identity_assurance",
        "issued_by",
        "issued_at",
        "attestation",
    ],
)
def test_codex_changes_record_rejects_caller_declared_producer_identity(
    valid_bundle, forbidden_field: str
) -> None:
    state, _ = valid_bundle
    state = _as_codex_state(state)
    state["workspace_baseline"] = workspace_module.capture_workspace_snapshot(
        state["workspace"]
    )

    with pytest.raises(cli_module.InvalidState):
        cli_module._core_codex_changes_record(
            state,
            {"domains": ["config/agent"], forbidden_field: "caller-value"},
        )


def test_claude_host_observed_identity_remains_completion_trusted(valid_bundle) -> None:
    state, events = valid_bundle
    state = copy.deepcopy(state)
    state["runtime"] = "claude"
    manifest = state["request_manifest"]
    manifest["runtime"] = "claude"
    manifest.pop("attestation", None)
    manifest["attestation"] = sign_record(manifest)
    binding = _request_binding(state)
    pair = [
        invocation_event(
            invocation_id="claude-host-1",
            capability="host-capability",
            stage=stage,
            result="success" if stage == "result" else None,
            actor="claude-worker",
            responsibility_group="implementation",
            identity_assurance="host-hook-observed",
            details=copy.deepcopy(binding),
        )
        for stage in ("attempt", "result")
    ]

    assert _trusted_invocation_for_runtime(
        pair,
        "claude-host-1",
        actor="claude-worker",
        responsibility_group="implementation",
        state=state,
    )
    capabilities, _, errors = _completion_trusted_invocations(state, pair)
    assert capabilities == {"host-capability"}
    assert errors == []
