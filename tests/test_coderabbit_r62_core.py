from __future__ import annotations

import pytest

from supervisor_core import cli as cli_module
from supervisor_core.contracts import build_goal


@pytest.mark.parametrize(
    "gate_id",
    [
        "Review.coderabbit",
        "review.CodeRabbit",
        "REVIEW.CODERABBIT",
        "Review.code-review-graph.build",
        "review.Code-Review-Graph.build",
        "review.code-review-Graph.impact",
    ],
)
def test_review_binding_gate_ids_reject_mixed_case(gate_id: str) -> None:
    assert cli_module._requires_review_binding_file(gate_id) is False


@pytest.mark.parametrize(
    "gate_id",
    [
        " review.coderabbit",
        "review.coderabbit ",
        "\treview.code-review-graph.build",
        "review.code-review-graph.impact\n",
    ],
)
def test_review_binding_gate_ids_reject_surrounding_whitespace(
    gate_id: str,
) -> None:
    assert cli_module._requires_review_binding_file(gate_id) is False


@pytest.mark.parametrize(
    "gate_id",
    [
        "review.coderabbit",
        "review.code-review-graph.build",
        "review.code-review-graph.impact",
    ],
)
def test_review_binding_gate_ids_preserve_exact_lowercase_semantics(
    gate_id: str,
) -> None:
    assert cli_module._requires_review_binding_file(gate_id) is True


@pytest.mark.parametrize("description", ["", " \t\r\n "])
def test_build_goal_rejects_empty_normalized_acceptance_criterion(
    description: str,
) -> None:
    with pytest.raises(
        ValueError,
        match="acceptance criterion 1 description must not be empty",
    ):
        build_goal(
            "verify the goal contract",
            change_mode="replace",
            supplied={"acceptance_criteria": [{"description": description}]},
        )


def test_build_goal_preserves_normal_nonempty_acceptance_criterion_behavior() -> None:
    goal = build_goal(
        "verify the goal contract",
        change_mode="replace",
        supplied={
            "acceptance_criteria": [
                {
                    "description": "  evidence is verified  ",
                    "domain": " research ",
                    "expected_evidence": [" research.claims "],
                }
            ]
        },
    )

    criterion = goal["acceptance_criteria"][0]
    assert criterion["description"] == "evidence is verified"
    assert criterion["domain"] == "research"
    assert criterion["expected_evidence"] == ["research.claims"]
    assert criterion["required"] is True
