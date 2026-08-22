from __future__ import annotations

import copy
from pathlib import Path

import pytest

from supervisor_core.attestation import sign_record
from supervisor_core.rollout import (
    RolloutReplayIntegrityError,
    apply_observation,
    initial_rollout,
    promote,
)


@pytest.fixture(autouse=True)
def _isolated_attestation_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "AGENT_SUPERVISOR_ATTESTATION_KEY_FILE",
        str(tmp_path / "attestation.key"),
    )


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


def test_recent_compacted_observation_id_cannot_be_replayed_or_recounted() -> None:
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
    rounds = [
        _observation(
            f"round-{index}",
            "round_outcome",
            nontrivial=True,
            critical_miss=False,
            false_block=False,
        )
        for index in range(250)
    ]
    for record in rounds:
        apply_observation(state, record)

    checkpoint = state["observation_checkpoint"]
    compacted_ids = checkpoint["compacted_observation_ids"]
    retained_ids = {record["observation_id"] for record in state["observations"]}
    assert len(state["observations"]) == 88
    assert len(compacted_ids) == 88
    assert checkpoint["compacted_observation_id_limit"] == 88
    assert "round-100" in compacted_ids
    assert set(compacted_ids).isdisjoint(retained_ids)
    before = copy.deepcopy(state)

    with pytest.raises(ValueError, match="duplicate compacted rollout observation"):
        apply_observation(state, rounds[100])

    assert state == before
    assert state["metrics"]["nontrivial_rounds"] == 250
    promote(state, "warn")
    promote(state, "enforce")
    assert state["active_mode"] == "enforce"


def test_signed_checkpoint_cannot_exceed_bounded_compacted_id_window() -> None:
    state = initial_rollout({}, "observe")
    for index in range(100):
        apply_observation(
            state,
            _observation(
                f"round-{index}",
                "round_outcome",
                nontrivial=True,
                false_block=False,
            ),
        )
    tampered = copy.deepcopy(state)
    checkpoint = tampered["observation_checkpoint"]
    checkpoint["compacted_observation_ids"] = [f"forged-{index}" for index in range(65)]
    checkpoint["last_observation_id"] = "forged-64"
    checkpoint["attestation"] = sign_record(checkpoint)

    with pytest.raises(RolloutReplayIntegrityError, match="observation integrity invalid"):
        promote(tampered, "warn")


def test_legacy_checkpoint_last_id_is_protected_and_upgraded() -> None:
    state = initial_rollout({}, "observe")
    rounds = [
        _observation(
            f"round-{index}",
            "round_outcome",
            nontrivial=True,
            false_block=False,
        )
        for index in range(101)
    ]
    for record in rounds[:100]:
        apply_observation(state, record)
    legacy = state["observation_checkpoint"]
    legacy.pop("compacted_observation_ids")
    legacy["attestation"] = sign_record(legacy)
    assert legacy["last_observation_id"] == "round-35"

    with pytest.raises(ValueError, match="duplicate compacted rollout observation"):
        apply_observation(state, rounds[35])
    apply_observation(state, rounds[100])

    upgraded_ids = state["observation_checkpoint"]["compacted_observation_ids"]
    assert upgraded_ids == ["round-35", "round-36"]
    assert state["observation_total_count"] == 101


def test_policy_window_decrease_recompacts_a_valid_larger_id_window() -> None:
    larger_policy = {
        "rollout": {
            "cross_project_default": {
                "promotion_requires_nontrivial_rounds": 80,
            }
        }
    }
    state = initial_rollout(larger_policy, "observe")
    for index in range(200):
        apply_observation(
            state,
            _observation(
                f"round-{index}",
                "round_outcome",
                nontrivial=True,
                false_block=False,
            ),
        )
    assert state["observation_checkpoint"]["compacted_observation_id_limit"] == 88
    assert len(state["observation_checkpoint"]["compacted_observation_ids"]) == 88

    state = initial_rollout({}, "observe", previous=state)
    apply_observation(
        state,
        _observation(
            "round-after-policy-change",
            "round_outcome",
            nontrivial=True,
            false_block=False,
        ),
    )

    checkpoint = state["observation_checkpoint"]
    assert checkpoint["compacted_observation_id_limit"] == 64
    assert len(checkpoint["compacted_observation_ids"]) == 64
    assert len(state["observations"]) == 64
    assert state["metrics"]["nontrivial_rounds"] == 201
