from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from supervisor_core import validation
from supervisor_core import workspace as workspace_module
from supervisor_core.attestation import sign_record
from supervisor_core.contracts import normalize_intents
from supervisor_core.lifecycle import start_round
from supervisor_core.storage import StateContext
from supervisor_core.util import canonical_sha256, sha256_bytes


@pytest.fixture(autouse=True)
def _isolated_attestation_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "AGENT_SUPERVISOR_ATTESTATION_KEY_FILE",
        str(tmp_path / "attestation.key"),
    )


def _context(tmp_path: Path, round_id: str) -> StateContext:
    return StateContext.build(
        runtime="test",
        project="p",
        workspace=str(tmp_path / "workspace"),
        session="s",
        round_id=round_id,
        state_root=tmp_path / "state",
    )


def _source_snapshot(label: str) -> dict[str, object]:
    snapshot: dict[str, object] = {
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
    snapshot["snapshot_sha256"] = canonical_sha256(snapshot)
    return snapshot


def _gate_execution(state: dict[str, object]) -> dict[str, object]:
    record = state["evidence"][0]  # type: ignore[index]
    execution: dict[str, object] = {
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
        "source_snapshot_hash": record["source_snapshot_hash"],
    }
    execution["attestation"] = sign_record(copy.deepcopy(execution))
    return execution


def test_lineage_hash_matches_exact_atomic_json_bytes_not_object_digest(tmp_path: Path) -> None:
    first = _context(tmp_path, "round-1")
    start_round(
        first,
        message="first round",
        change_mode="continue",
        execution_mode="warn",
        project_config={},
        quality_profile={},
    )
    second = _context(tmp_path, "round-2")
    state = start_round(
        second,
        message="extend the first round",
        change_mode="extend",
        execution_mode="warn",
        project_config={},
        quality_profile={},
    )

    persisted_bytes = first.state_file.read_bytes()
    persisted_object = json.loads(persisted_bytes.decode("utf-8"))
    byte_digest = sha256_bytes(persisted_bytes)
    object_digest = canonical_sha256(persisted_object)

    assert byte_digest != object_digest
    assert state["lineage"]["previous_state_sha256"] == byte_digest
    assert state["prior_rounds"][0]["source_state_sha256"] == byte_digest


@pytest.mark.parametrize("phase", ["later", {}, [], float("nan"), float("inf")])
def test_non_numeric_intent_phase_falls_back_to_zero(phase: object) -> None:
    intent = normalize_intents([{"text": "route safely", "phase": phase}])[0]

    assert intent["phase"] == 0


def test_numeric_string_intent_phase_preserves_existing_normalization() -> None:
    assert normalize_intents([{"text": "route safely", "phase": "2"}])[0]["phase"] == 2


@pytest.mark.parametrize("baseline", [None, "invalid", []])
def test_invalid_workspace_baseline_fails_closed_during_evidence_validation(
    valid_bundle,
    baseline: object,
) -> None:
    state, _ = valid_bundle
    state["runtime"] = "codex"
    state["workspace_baseline"] = baseline
    snapshot = _source_snapshot("current")
    state["supervisor_source_snapshot"] = snapshot
    record = state["evidence"][0]
    record["execution_id"] = "execution-invalid-baseline"
    record["source_snapshot_hash"] = snapshot["snapshot_sha256"]
    execution = _gate_execution(state)
    errors: list[str] = []

    validation._validate_evidence(state, {"criterion-1"}, [execution], errors)

    assert "evidence evidence-1 cannot bind to a valid workspace baseline" in errors
