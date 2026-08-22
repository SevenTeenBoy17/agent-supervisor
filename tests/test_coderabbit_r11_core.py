from __future__ import annotations

import copy
import os
from pathlib import Path

from supervisor_core.attestation import sign_record
from supervisor_core.discovery import RootSpec, scan_skills
from supervisor_core.finalize import finalize_round
from supervisor_core.rollout import (
    apply_observation,
    checkpoint_observation_ids,
    initial_rollout,
)
from supervisor_core.storage import StateContext


def _round_observation(observation_id: str) -> dict[str, object]:
    record: dict[str, object] = {
        "contract": "RolloutObservation/v3",
        "observation_id": observation_id,
        "kind": "round_outcome",
        "source_contract": "RoundFinalization/v3",
        "source_id": observation_id,
        "nontrivial": True,
        "terminal_candidate": "complete",
        "adjudication_pending": True,
    }
    record["attestation"] = sign_record(record)
    return record


def test_suite_attestation_key_is_isolated_to_each_test_tmp_path(tmp_path: Path) -> None:
    assert Path(os.environ["AGENT_SUPERVISOR_ATTESTATION_KEY_FILE"]) == (
        tmp_path / "attestation.key"
    )


def test_disabled_cache_root_remains_disabled(tmp_path: Path) -> None:
    root = tmp_path / "disabled-cache"
    skill = root / "sample"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text(
        "---\nname: sample\ndescription: disabled cache fixture\n---\n",
        encoding="utf-8",
    )

    inventory = scan_skills(
        [RootSpec(root, "disabled-cache", enabled=False, cache=True)]
    )

    assert len(inventory["skills"]) == 1
    discovered = inventory["skills"][0]
    assert discovered["availability"] == "disabled"
    assert discovered["active"] is False
    assert discovered["automatic"] is False


def test_finalize_treats_signed_compacted_round_id_as_already_recorded(
    tmp_path: Path,
    valid_bundle,
) -> None:
    state, events = valid_bundle
    ctx = StateContext.build(
        runtime=state["runtime"],
        project=state["project"],
        workspace=state["workspace"],
        session=state["session"],
        round_id=state["round"],
        state_root=tmp_path / "state",
    )
    observation_id = f"round-{state['session']}-{state['round']}"
    rollout = initial_rollout({}, "observe")
    apply_observation(rollout, _round_observation(observation_id))
    for index in range(64):
        apply_observation(rollout, _round_observation(f"later-{index}"))
    assert observation_id not in {
        row["observation_id"] for row in rollout["observations"]
    }
    assert observation_id in rollout["observation_checkpoint"][
        "compacted_observation_ids"
    ]
    assert observation_id in checkpoint_observation_ids(rollout)
    before = copy.deepcopy(rollout)
    state["rollout"] = copy.deepcopy(rollout)
    ctx.save(state)
    ctx.update_project_rollout(lambda _current: copy.deepcopy(rollout))
    for event in events:
        ctx.append_event(event)

    finalized, code = finalize_round(ctx)

    assert code == 0
    assert finalized["terminal_state"] == "complete"
    assert ctx.load_project_rollout() == before
