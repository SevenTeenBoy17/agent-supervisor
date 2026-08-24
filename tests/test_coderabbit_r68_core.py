from __future__ import annotations

import pytest

from supervisor_core.contracts import build_goal


@pytest.mark.parametrize(
    "invalid_entries",
    [
        [None],
        [7, True, None],
        [False, 3.14, []],
    ],
)
def test_explicit_all_invalid_acceptance_criteria_are_rejected(
    invalid_entries: list[object],
) -> None:
    with pytest.raises(
        ValueError,
        match="supplied acceptance criteria contain no valid string or object entries",
    ):
        build_goal(
            "validate explicit criteria",
            change_mode="replace",
            supplied={"acceptance_criteria": invalid_entries},
        )


def test_omitted_or_explicit_empty_acceptance_criteria_keep_default() -> None:
    omitted = build_goal("default criterion", change_mode="replace")
    explicit_empty = build_goal(
        "default criterion",
        change_mode="replace",
        supplied={"acceptance_criteria": []},
    )

    assert omitted["acceptance_criteria"] == explicit_empty["acceptance_criteria"]
    assert [row["description"] for row in omitted["acceptance_criteria"]] == [
        "default criterion"
    ]
    assert omitted["acceptance_criteria"][0]["expected_evidence"] == [
        "goal-output"
    ]


def test_mixed_valid_and_invalid_acceptance_criteria_preserve_valid_entries() -> None:
    goal = build_goal(
        "mixed criteria",
        change_mode="replace",
        supplied={
            "acceptance_criteria": [
                None,
                7,
                "string criterion",
                {"description": "object criterion", "domain": "config/agent"},
                True,
            ]
        },
    )

    assert [row["description"] for row in goal["acceptance_criteria"]] == [
        "string criterion",
        "object criterion",
    ]
    assert [row["domain"] for row in goal["acceptance_criteria"]] == [
        "general",
        "config/agent",
    ]


@pytest.mark.parametrize("change_mode", ["continue", "extend"])
def test_all_invalid_continuation_criteria_reject_before_previous_merge(
    change_mode: str,
) -> None:
    previous = build_goal(
        "existing goal",
        change_mode="replace",
        supplied={"acceptance_criteria": ["existing valid criterion"]},
    )

    with pytest.raises(
        ValueError,
        match="supplied acceptance criteria contain no valid string or object entries",
    ):
        build_goal(
            "continue existing goal",
            change_mode=change_mode,
            previous_goal=previous,
            supplied={"acceptance_criteria": [None, 7, True]},
        )
