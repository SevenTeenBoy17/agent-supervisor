from __future__ import annotations

import copy

from supervisor_core.attestation import sign_record
from supervisor_core.util import canonical_sha256
from supervisor_core import validation
from supervisor_core import workspace as workspace_module


def _snapshot(label: str) -> dict[str, object]:
    payload: dict[str, object] = {
        "contract": "SupervisorSourceSnapshot/v3",
        "status": "healthy",
        "roots": {
            "shared-core": "C:/trusted/core",
            "codex-adapter": "C:/trusted/codex",
            "claude-adapter": "C:/trusted/claude",
        },
        "files": {
            name: {
                "status": "hashed",
                "sha256": canonical_sha256(label),
                "size": len(label),
            }
            for name in workspace_module._required_supervisor_source_names()
        },
    }
    payload["snapshot_sha256"] = canonical_sha256(payload)
    return payload


def test_real_runtime_rejects_source_change_after_round_start(monkeypatch) -> None:
    state = {"runtime": "codex", "supervisor_source_snapshot": _snapshot("before")}
    monkeypatch.setattr(validation, "capture_supervisor_source_snapshot", lambda: _snapshot("after"))
    errors: list[str] = []

    assert validation._validate_supervisor_source_snapshot(state, errors) is None
    assert "Supervisor source changed after round start" in errors


def test_real_runtime_rejects_missing_or_self_inconsistent_snapshot(monkeypatch) -> None:
    invalid = _snapshot("invalid")
    invalid["files"] = {}
    state = {"runtime": "codex", "supervisor_source_snapshot": invalid}
    monkeypatch.setattr(validation, "capture_supervisor_source_snapshot", lambda: _snapshot("current"))
    errors: list[str] = []

    assert validation._validate_supervisor_source_snapshot(state, errors) is None
    assert any("trusted Supervisor source snapshot" in error for error in errors)


def test_self_consistent_snapshot_without_host_adapter_manifest_is_rejected() -> None:
    incomplete = _snapshot("incomplete")
    incomplete["files"].pop("codex-adapter/supervisor-bootstrap.ps1")
    incomplete["snapshot_sha256"] = canonical_sha256(
        {key: value for key, value in incomplete.items() if key != "snapshot_sha256"}
    )

    assert workspace_module.validated_supervisor_source_snapshot_hash(incomplete) is None


def test_evidence_and_execution_must_bind_to_round_source_snapshot(valid_bundle) -> None:
    state, _ = valid_bundle
    state["runtime"] = "codex"
    current = _snapshot("current")
    stale = _snapshot("stale")
    state["supervisor_source_snapshot"] = current
    record = state["evidence"][0]
    record["execution_id"] = "execution-stale-source"
    record["source_snapshot_hash"] = stale["snapshot_sha256"]
    execution = {
        "contract": "GateExecution/v3",
        "event_type": "gate_execution",
        "execution_id": record["execution_id"],
        "evidence_id": record["evidence_id"],
        "gate_id": record["gate_id"],
        "criterion_id": record["criterion_id"],
        "goal_id": record["goal_id"],
        "goal_version": record["goal_version"],
        "exit_code": record["exit_code"],
        "cwd": record["cwd"],
        "collected_at": record["collected_at"],
        "base": record["base"],
        "head": record["head"],
        "diff_hash": record["diff_hash"],
        "collector": record["collector"],
        "collector_responsibility_group": record["collector_responsibility_group"],
        "output_sha256": record["output_sha256"],
        "artifact_hash": record["artifact_hash"],
        "resolved_executable": record.get("resolved_executable"),
        "resolved_executable_sha256": record.get("resolved_executable_sha256"),
        "precondition": record.get("precondition"),
        "command_executed": record.get("command_executed"),
        "output_summary": record["output_summary"],
        "state_started_at": state["started_at"],
        "workspace_snapshot_hash": None,
        "source_snapshot_hash": stale["snapshot_sha256"],
    }
    execution["attestation"] = sign_record(copy.deepcopy(execution))
    errors: list[str] = []

    validation._validate_evidence(state, {"criterion-1"}, [execution], errors)

    assert any("different Supervisor source snapshot" in error for error in errors)
