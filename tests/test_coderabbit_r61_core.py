from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from supervisor_core import validation as validation_module
from supervisor_core import workspace as workspace_module
from supervisor_core.util import canonical_sha256


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
        "stdout_sha256": "a" * 64,
        "stderr_sha256": "b" * 64,
    }


def _graph_summary(check: str = "build") -> dict:
    return {
        "engine": "code-review-graph",
        "check": check,
        "status": "pass",
        "exit_code": 0,
        "output_sha256": "c" * 64,
    }


def _minor_summary() -> dict:
    summary = _coderabbit_summary()
    summary.update(
        {
            "finding_count": 1,
            "complete_reported_findings": 1,
            "severity_counts": {"critical": 0, "major": 0, "minor": 1},
            "issues": [
                {
                    "kind": "finding",
                    "severity": "nitpick",
                    "path": "src/safe module.py",
                    "line": 7,
                    "title": "[REDACTED:credential]",
                    "message": "Sensitive value removed before persistence.",
                }
            ],
        }
    )
    return summary


def _binding_and_output(
    summary: dict, *, review_category: str = "independent"
) -> tuple[dict, dict]:
    delta = {"config.json": {"before": "1" * 64, "after": "2" * 64}}
    binding = {
        "contract": "ReviewArtifactBindingInput/v1",
        "base": "1" * 40,
        "head": "2" * 40,
        "workspace_base_sha256": "3" * 64,
        "workspace_head_sha256": "4" * 64,
        "diff_hash": canonical_sha256(delta),
        "workspace_delta_manifest": delta,
    }
    output = {
        "contract": "ReviewOutputArtifact/v1",
        "review_category": review_category,
        "review_artifact": {
            "kind": "git-bundle-v1",
            "bundle_path": "C:/sealed/review.bundle",
            "bundle_sha256": "5" * 64,
            "manifest_path": "C:/sealed/review.manifest.json",
            "manifest_sha256": "6" * 64,
        },
        "review_summary": summary,
        "base": "7" * 40,
        "head": "8" * 40,
        "git_object_format": "sha1",
        "git_diff_sha256": "9" * 64,
        "workspace_base_sha256": binding["workspace_base_sha256"],
        "workspace_head_sha256": binding["workspace_head_sha256"],
        "diff_hash": binding["diff_hash"],
    }
    return binding, output


def _assert_summary_invalid(summary: dict) -> None:
    valid, _ = workspace_module._validate_review_summary(summary)
    assert not valid


@pytest.mark.parametrize("summary", [_coderabbit_summary(), _minor_summary(), _graph_summary("build"), _graph_summary("impact")])
def test_strict_review_summaries_accept_valid_variants(summary) -> None:
    valid, reason = workspace_module._validate_review_summary(summary)
    assert valid, reason


def test_review_output_requires_summary_and_returns_the_same_validated_artifact(monkeypatch) -> None:
    binding, output = _binding_and_output(_coderabbit_summary())
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

    valid, reason, validated = workspace_module.validate_review_output_artifact(
        output, binding
    )
    assert valid, reason
    assert validated is output

    missing = copy.deepcopy(output)
    missing.pop("review_summary")
    assert workspace_module.validate_review_output_artifact(missing, binding)[0] is False
    extra = copy.deepcopy(output)
    extra["unexpected"] = True
    assert workspace_module.validate_review_output_artifact(extra, binding)[0] is False


def test_summary_rejects_missing_extra_and_count_inconsistency() -> None:
    missing = _coderabbit_summary()
    missing.pop("issues")
    _assert_summary_invalid(missing)
    extra = _coderabbit_summary()
    extra["reviewed_files"] = 1
    _assert_summary_invalid(extra)

    for field, value in (
        ("complete_reported_findings", 1),
        ("finding_count", 1),
        ("blocking_findings", 1),
    ):
        summary = _coderabbit_summary()
        summary[field] = value
        _assert_summary_invalid(summary)

    wrong_bucket = _minor_summary()
    wrong_bucket["issues"][0]["severity"] = "p1"
    _assert_summary_invalid(wrong_bucket)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("exit_code", True),
        ("structured_events", True),
        ("finding_count", False),
        ("complete_reported_findings", False),
        ("blocking_findings", False),
    ],
)
def test_summary_rejects_booleans_as_integers(field, value) -> None:
    summary = _coderabbit_summary()
    summary[field] = value
    _assert_summary_invalid(summary)

    severity = _coderabbit_summary()
    severity["severity_counts"]["minor"] = True
    _assert_summary_invalid(severity)


@pytest.mark.parametrize("field", ["path", "title", "message"])
def test_summary_rejects_secret_bearing_issue_strings(field) -> None:
    summary = _minor_summary()
    summary["issues"][0][field] = "token=DO-NOT-PERSIST"
    _assert_summary_invalid(summary)


@pytest.mark.parametrize(
    "path",
    ["", "/absolute.py", "C:/absolute.py", "src\\file.py", "src/../file.py", "src//file.py", "src:file.py", " leading.py", "trailing.py ", "src/line\nbreak.py"],
)
def test_summary_rejects_unsafe_issue_paths(path) -> None:
    summary = _minor_summary()
    summary["issues"][0]["path"] = path
    _assert_summary_invalid(summary)


@pytest.mark.parametrize("line", [0, -1, True, "1"])
def test_summary_rejects_invalid_issue_line(line) -> None:
    summary = _minor_summary()
    summary["issues"][0]["line"] = line
    _assert_summary_invalid(summary)


def test_summary_rejects_invalid_issue_kind_severity_and_text_bounds() -> None:
    for field, value in (
        ("kind", "error"),
        ("severity", "unknown"),
        ("title", ""),
        ("title", " " * 3),
        ("title", "x" * 161),
        ("message", "x" * 501),
    ):
        summary = _minor_summary()
        summary["issues"][0][field] = value
        _assert_summary_invalid(summary)


def test_summary_rejects_blockers_forged_success_metadata_and_stream_hashes() -> None:
    blocked = _coderabbit_summary()
    blocked["protocol_blockers"] = ["unparseable-event"]
    _assert_summary_invalid(blocked)

    for field, value in (
        ("authenticated", False),
        ("authenticated", 1),
        ("status", "fail"),
        ("exit_code", 2),
        ("structured_events", 0),
        ("terminal_outcome", "failure"),
        ("context_bound", False),
    ):
        summary = _coderabbit_summary()
        summary[field] = value
        _assert_summary_invalid(summary)

    for field, value in (
        ("stdout_sha256", "A" * 64),
        ("stderr_sha256", "0" * 63),
        ("stdout_sha256", True),
    ):
        summary = _coderabbit_summary()
        summary[field] = value
        _assert_summary_invalid(summary)


def test_summary_rejects_impossible_blocking_severity_success() -> None:
    summary = _minor_summary()
    summary["issues"][0]["severity"] = "high"
    summary["severity_counts"] = {"critical": 0, "major": 1, "minor": 0}
    _assert_summary_invalid(summary)


def test_graph_summary_is_strict_and_gate_binding_rejects_cross_engine_or_check() -> None:
    graph = _graph_summary("build")
    extra = copy.deepcopy(graph)
    extra["authenticated"] = True
    _assert_summary_invalid(extra)
    forged = copy.deepcopy(graph)
    forged["exit_code"] = False
    _assert_summary_invalid(forged)

    _, coderabbit_output = _binding_and_output(
        _coderabbit_summary(), review_category="independent"
    )
    _, graph_output = _binding_and_output(graph, review_category="independent")
    assert validation_module._review_output_matches_gate(
        "review.coderabbit", coderabbit_output
    )[0]
    assert validation_module._review_output_matches_gate(
        "review.code-review-graph.build", graph_output
    )[0]
    assert not validation_module._review_output_matches_gate(
        "review.coderabbit", graph_output
    )[0]
    assert not validation_module._review_output_matches_gate(
        "review.code-review-graph.build", coderabbit_output
    )[0]
    assert not validation_module._review_output_matches_gate(
        "review.code-review-graph.impact", graph_output
    )[0]
    assert not validation_module._review_output_matches_gate(
        "review.code-review-graph.unknown", graph_output
    )[0]
    _, test_integrity_output = _binding_and_output(
        _coderabbit_summary(), review_category="test-integrity"
    )
    assert validation_module._review_output_matches_gate(
        "review.coderabbit.test-integrity", test_integrity_output
    )[0]
    assert not validation_module._review_output_matches_gate(
        "review.coderabbit", test_integrity_output
    )[0]


def test_contract_schema_parses_and_encodes_both_strict_summary_variants() -> None:
    schema = json.loads(
        (Path(__file__).parents[1] / "schemas" / "contracts.schema.json").read_text(
            encoding="utf-8"
        )
    )
    Draft202012Validator.check_schema(schema)
    summary_schema = {
        "$schema": schema["$schema"],
        "$ref": "#/$defs/ReviewSummary",
        "$defs": schema["$defs"],
    }
    validator = Draft202012Validator(summary_schema)
    validator.validate(_coderabbit_summary())
    validator.validate(_minor_summary())
    validator.validate(_graph_summary("build"))
    invalid = _coderabbit_summary()
    invalid["unexpected"] = True
    assert list(validator.iter_errors(invalid))
    for unsafe_path in (
        "",
        "/absolute.py",
        "C:/absolute.py",
        "src\\file.py",
        "src/../file.py",
        "src//file.py",
        "src:file.py",
        " leading.py",
        "trailing.py ",
        "src/line\nbreak.py",
    ):
        invalid_path = _minor_summary()
        invalid_path["issues"][0]["path"] = unsafe_path
        assert list(validator.iter_errors(invalid_path)), unsafe_path
