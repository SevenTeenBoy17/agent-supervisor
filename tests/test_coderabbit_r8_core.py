from __future__ import annotations

import copy

import pytest

from supervisor_core.attestation import sign_record
from supervisor_core.rollout import (
    RolloutReplayIntegrityError,
    apply_observation,
    initial_rollout,
    promote,
)
from supervisor_core.validation import validate_state


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
    ("field", "expected_error"),
    [
        ("tasks", "tasks must be an array"),
        ("evidence", "evidence must be an array"),
        ("intents", "intents must be an array"),
        ("reviews", "reviews must be an array"),
        ("waivers", "waivers must be an array"),
    ],
)
def test_nullable_top_level_collections_fail_closed_without_raising(
    valid_bundle,
    field: str,
    expected_error: str,
) -> None:
    state, events = valid_bundle
    state[field] = None

    report = validate_state(state, events)

    assert report["valid"] is False
    assert expected_error in report["errors"]


def test_nullable_reviews_fail_closed_on_zero_skill_and_test_integrity_paths(valid_bundle) -> None:
    state, events = valid_bundle
    state["reviews"] = None
    state["intents"] = [{
        **state["intents"][0],
        "status": "skipped",
        "reason": "independent routing found no relevant capability",
        "capability_ids": [],
    }]
    state["changes"]["test_changes"] = {"assertions_changed": True}

    report = validate_state(state, events)

    assert report["valid"] is False
    assert "reviews must be an array" in report["errors"]
    assert "zero-skill round lacks approving routing review" in report["errors"]
    assert "test deletion/skip/threshold/assertion change lacks separate test-integrity review" in report["errors"]


def test_nullable_criteria_and_events_fail_closed_without_raising(valid_bundle) -> None:
    state, _ = valid_bundle
    state["goal"]["acceptance_criteria"] = None

    report = validate_state(state, None)  # type: ignore[arg-type]

    assert report["valid"] is False
    assert "GoalContract acceptance criteria empty" in report["errors"]
    assert "events must be an array" in report["errors"]


def test_observation_retention_covers_configured_window_and_preserves_early_miss(
    tmp_path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("AGENT_SUPERVISOR_ATTESTATION_KEY_FILE", str(tmp_path / "attestation.key"))
    state = initial_rollout(
        {
            "rollout": {
                "cross_project_default": {
                    "promotion_requires_nontrivial_rounds": 80,
                    "critical_misses": 0,
                    "max_false_block_rate": 0.02,
                }
            }
        },
        "observe",
    )
    apply_observation(state, _observation("fixtures", "fixture_replay", passed=True))
    apply_observation(state, _observation("history", "historical_replay", passed=True))
    apply_observation(
        state,
        _observation(
            "early-critical-miss",
            "round_outcome",
            nontrivial=True,
            critical_miss=True,
            false_block=False,
        ),
    )
    for index in range(160):
        apply_observation(
            state,
            _observation(
                f"round-{index}",
                "round_outcome",
                nontrivial=True,
                critical_miss=False,
                false_block=False,
            ),
        )

    checkpoint = state["observation_checkpoint"]
    assert isinstance(checkpoint, dict)
    assert 80 <= len(state["observations"]) < 163
    assert checkpoint["covered_observations"] + len(state["observations"]) == 163
    assert state["observation_total_count"] == 163
    assert state["metrics"]["critical_misses"] == 1
    assert state["promotion"]["eligible_enforce"] is False

    promote(state, "warn")
    assert state["metrics"]["critical_misses"] == 1
    with pytest.raises(ValueError, match="enforce promotion metrics are not satisfied"):
        promote(state, "enforce")


def test_checkpoint_replay_preserves_rollback_lineage_and_rejects_tampering(
    tmp_path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("AGENT_SUPERVISOR_ATTESTATION_KEY_FILE", str(tmp_path / "attestation.key"))
    state = initial_rollout({}, "observe")
    active = {
        "contract": "SupervisorReleaseIdentity/v1",
        "version": "4.0.0",
        "path": "C:/releases/4.0.0",
        "bundle_relpath": "runtime/supervisor-runtime.zip",
        "bundle_sha256": "1" * 64,
        "manifest_sha256": "2" * 64,
        "source_tree_sha256": "3" * 64,
    }
    for record in (
        _observation("fixtures", "fixture_replay", passed=True),
        _observation("history", "historical_replay", passed=True),
        _observation("gate-failure-1", "global_gate", result="failed", active_version=active),
        _observation("gate-failure-2", "global_gate", result="failed", active_version=active),
    ):
        apply_observation(state, record)
    for index in range(100):
        apply_observation(
            state,
            _observation(
                f"round-{index}",
                "round_outcome",
                nontrivial=True,
                critical_miss=False,
                false_block=False,
            ),
        )

    assert len(state["observations"]) == 64
    assert state["observation_checkpoint"]["covered_observations"] == 40
    assert state["rollback"]["required"] is True
    promote(state, "warn")
    assert state["rollback"]["required"] is True

    tampered = copy.deepcopy(state)
    tampered["observation_checkpoint"]["metrics"]["nontrivial_rounds"] += 1
    with pytest.raises(RolloutReplayIntegrityError, match="observation integrity invalid"):
        promote(tampered, "enforce")

    promote(state, "enforce")
    assert state["active_mode"] == "enforce"


def test_bounded_and_uncompacted_replay_have_identical_metrics(
    tmp_path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("AGENT_SUPERVISOR_ATTESTATION_KEY_FILE", str(tmp_path / "attestation.key"))
    policy = {
        "rollout": {
            "cross_project_default": {
                "promotion_requires_nontrivial_rounds": 50,
                "critical_misses": 2,
                "max_false_block_rate": 0.05,
            }
        }
    }
    bounded = initial_rollout(policy, "observe")
    uncompacted = initial_rollout(policy, "observe")
    records = [
        _observation("fixtures", "fixture_replay", passed=True),
        _observation("history", "historical_replay", passed=True),
    ]
    records.extend(
        _observation(
            f"round-{index}",
            "round_outcome",
            nontrivial=True,
            critical_miss=index in {7, 71},
            false_block=index in {11, 91},
        )
        for index in range(120)
    )
    for record in records:
        apply_observation(bounded, record)
        apply_observation(uncompacted, record, _compact=False)

    assert len(bounded["observations"]) == 64
    assert len(uncompacted["observations"]) == 122
    assert bounded["metrics"] == uncompacted["metrics"]
    assert bounded["promotion"] == uncompacted["promotion"]
    assert bounded["rollback"] == uncompacted["rollback"]

    promote(bounded, "warn")
    promote(uncompacted, "warn")
    assert bounded["metrics"] == uncompacted["metrics"]
