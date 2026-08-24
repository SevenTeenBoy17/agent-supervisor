from __future__ import annotations

import copy

import pytest

from supervisor_core import validation as validation_module


def _coderabbit_output() -> dict:
    return {
        "review_category": "independent",
        "review_summary": {"engine": "coderabbit"},
    }


def _graph_output(check: str) -> dict:
    return {
        "review_summary": {
            "engine": "code-review-graph",
            "check": check,
        }
    }


@pytest.mark.parametrize(
    ("gate_id", "output"),
    [
        ("review.coderabbit", _coderabbit_output()),
        ("review.code-review-graph.build", _graph_output("build")),
        ("review.code-review-graph.impact", _graph_output("impact")),
    ],
)
def test_review_output_binding_accepts_only_exact_lowercase_positive_ids(
    gate_id: str,
    output: dict,
) -> None:
    assert validation_module._review_output_matches_gate(gate_id, output) == (
        True,
        "verified",
    )


@pytest.mark.parametrize(
    ("gate_id", "output"),
    [
        ("Review.coderabbit", _coderabbit_output()),
        ("review.CodeRabbit", _coderabbit_output()),
        ("review.Code-Review-Graph.build", _graph_output("build")),
        ("review.code-review-Graph.impact", _graph_output("impact")),
        (" review.coderabbit", _coderabbit_output()),
        ("review.coderabbit ", _coderabbit_output()),
        ("\treview.code-review-graph.build", _graph_output("build")),
        ("review.code-review-graph.impact\n", _graph_output("impact")),
    ],
)
def test_review_output_binding_rejects_case_and_whitespace_variants(
    gate_id: str,
    output: dict,
) -> None:
    assert validation_module._review_output_matches_gate(gate_id, output) == (
        False,
        "review-summary-gate-unsupported",
    )


def test_review_output_binding_rejects_cross_engine_and_graph_check() -> None:
    assert validation_module._review_output_matches_gate(
        "review.coderabbit",
        _graph_output("build"),
    ) == (False, "review-summary-engine-mismatch")
    assert validation_module._review_output_matches_gate(
        "review.code-review-graph.build",
        _coderabbit_output(),
    ) == (False, "review-summary-engine-mismatch")
    assert validation_module._review_output_matches_gate(
        "review.code-review-graph.build",
        _graph_output("impact"),
    ) == (False, "review-summary-graph-check-mismatch")


def _registered_gate_evidence_errors(
    valid_bundle: tuple[dict, list[dict]],
    gate_id: str,
    *,
    claim_review_artifacts: bool,
) -> list[str]:
    state, events = copy.deepcopy(valid_bundle)
    state["quality_profile"]["common_gates"][0]["id"] = gate_id
    evidence = state["evidence"][0]
    evidence["gate_id"] = gate_id
    if claim_review_artifacts:
        evidence["review_binding_input_sha256"] = "f" * 64
        evidence["review_output_artifact"] = _coderabbit_output()

    errors: list[str] = []
    validation_module._validate_evidence(
        state,
        {"criterion-1"},
        events,
        errors,
        observed={"manifest": {}},
    )
    return errors


@pytest.mark.parametrize(
    "gate_id",
    [
        "Review.coderabbit",
        "review.CodeRabbit",
        "review.Code-Review-Graph.build",
        "review.code-review-Graph.impact",
        " review.coderabbit",
        "review.coderabbit ",
        "\treview.code-review-graph.build",
        "review.code-review-graph.impact\n",
    ],
)
def test_noncanonical_registered_gates_follow_non_review_evidence_rules(
    valid_bundle: tuple[dict, list[dict]],
    gate_id: str,
) -> None:
    assert _registered_gate_evidence_errors(
        valid_bundle,
        gate_id,
        claim_review_artifacts=False,
    ) == []

    errors = _registered_gate_evidence_errors(
        valid_bundle,
        gate_id,
        claim_review_artifacts=True,
    )
    assert errors == [
        "evidence evidence-1 non-review gate claims review binding input",
        "evidence evidence-1 non-review gate claims review output artifact",
    ]


@pytest.mark.parametrize(
    "gate_id",
    [
        "review.coderabbit",
        "review.code-review-graph.build",
        "review.code-review-graph.impact",
    ],
)
def test_exact_lowercase_registered_gates_require_review_binding(
    valid_bundle: tuple[dict, list[dict]],
    gate_id: str,
) -> None:
    assert _registered_gate_evidence_errors(
        valid_bundle,
        gate_id,
        claim_review_artifacts=False,
    ) == ["evidence evidence-1 review gate lacks core-observed binding input"]
