from __future__ import annotations

import pytest

from supervisor_core.validation import validate_state


@pytest.mark.parametrize(
    "hostile_links",
    [
        None,
        "criterion-1",
        {"criterion-1": True},
        7,
        [None],
        [{}],
        [""],
        ["criterion-1", None],
    ],
    ids=(
        "null",
        "string",
        "object",
        "integer",
        "list-null",
        "list-object",
        "list-blank",
        "list-mixed",
    ),
)
def test_task_criterion_ids_hostile_values_fail_closed_without_crashing(
    valid_bundle,
    hostile_links,
) -> None:
    state, events = valid_bundle
    state["tasks"][0]["criterion_ids"] = hostile_links

    report = validate_state(state, events)

    assert report["valid"] is False
    assert any("criterion links invalid" in error for error in report["errors"])
