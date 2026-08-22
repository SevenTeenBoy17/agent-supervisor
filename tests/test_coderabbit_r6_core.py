from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import supervisor_core.discovery as discovery_module
from supervisor_core.cli import _t3_command_action
from supervisor_core.contracts import build_goal
from supervisor_core.discovery import RootSpec, _frontmatter, scan_skills
from supervisor_core.lifecycle import _privacy_safe_previous_for_carry
from supervisor_core.util import sha256_text
from supervisor_core.validation import validate_state


@pytest.mark.parametrize("target", ["criterion", "evidence", "intent", "waiver"])
@pytest.mark.parametrize("bad_id", [["criterion-1"], {"id": "criterion-1"}])
def test_non_string_identifiers_fail_validation_without_crashing(valid_bundle, target, bad_id) -> None:
    state, events = valid_bundle
    if target == "criterion":
        state["goal"]["acceptance_criteria"][0]["criterion_id"] = bad_id
    elif target == "evidence":
        state["evidence"][0]["criterion_id"] = bad_id
    elif target == "intent":
        state["intents"][0]["intent_id"] = bad_id
    else:
        state["waivers"] = [{"criterion_id": bad_id}]

    report = validate_state(state, events)

    assert report["valid"] is False
    expected = {
        "criterion": "id missing or duplicate",
        "evidence": "criterion link invalid",
        "intent": "id missing or duplicate",
        "waiver": "waiver criterion link invalid",
    }[target]
    assert any(expected in error for error in report["errors"])


def test_identifier_membership_uses_trimmed_values_for_duplicate_detection(valid_bundle) -> None:
    state, events = valid_bundle
    state["goal"]["acceptance_criteria"].append({
        "criterion_id": " criterion-1 ",
        "description": "duplicate criterion",
        "domain": "config-agent",
        "expected_evidence": ["lint"],
        "required": True,
    })
    state["intents"].append({
        "contract": "IntentCoverage/v3",
        "intent_id": " intent-1 ",
        "text": "duplicate intent",
        "status": "skipped",
        "reason": "duplicate fixture",
        "capability_ids": [],
    })

    errors = validate_state(state, events)["errors"]

    assert any("criterion[1] id missing or duplicate" in error for error in errors)
    assert any("intent[1] id missing or duplicate" in error for error in errors)


def test_t3_regex_classifier_documents_its_best_effort_boundary() -> None:
    documentation = _t3_command_action.__doc__ or ""
    assert "best-effort" in documentation
    assert "not a host security boundary" in documentation
    assert "bypass" in documentation


def test_privacy_carry_only_opaques_declared_free_text_fields() -> None:
    previous = {
        "machine_identifier": "must-remain-stable",
        "review": {
            "review_id": "review-1",
            "findings": {"nested": ["private human prose"]},
        },
    }

    carried = _privacy_safe_previous_for_carry(
        previous,
        {"privacy": {"persist_raw_prompts": False}},
    )

    assert carried["machine_identifier"] == "must-remain-stable"
    assert carried["review"]["review_id"] == "review-1"
    assert carried["review"]["findings"]["nested"][0].startswith("Legacy findings sha256:")
    assert "private human prose" not in json.dumps(carried)


def test_waivers_require_explicit_trusted_request_binding() -> None:
    legal_message = "SUPERVISOR-WAIVE: criterion-a\n豁免 criterion-b"
    assert build_goal(
        legal_message, change_mode="replace"
    )["waiver_authorizations"] == []
    legal = build_goal(
        legal_message,
        change_mode="replace",
        trusted_authorizations={
            "request_sha256": sha256_text(legal_message),
            "waiver_criterion_ids": ["criterion-a", "criterion-b"],
            "t3_action_sha256s": [],
        },
    )
    assert [row["criterion_id"] for row in legal["waiver_authorizations"]] == [
        "criterion-a",
        "criterion-b",
    ]

    for prose in (
        "Please note SUPERVISOR-WAIVE: criterion-a",
        "说明：豁免 criterion-b",
        "SUPERVISOR-WAIVE: criterion-a because the test is hard",
        "SUPERVISOR-WAIVE:\ncriterion-a",
        "豁免\ncriterion-b",
    ):
        assert build_goal(prose, change_mode="replace")["waiver_authorizations"] == []


@pytest.mark.parametrize("opening", ["---suffix", " ---", "----"])
def test_frontmatter_requires_an_exact_first_line(tmp_path: Path, opening: str) -> None:
    path = tmp_path / "SKILL.md"
    text = f"{opening}\nname: attacker-controlled\n---\n# ordinary body\n"
    path.write_text(text, encoding="utf-8")

    metadata, body = _frontmatter(path)

    assert metadata == {}
    assert body == text


def test_frontmatter_accepts_exact_crlf_delimiters(tmp_path: Path) -> None:
    path = tmp_path / "SKILL.md"
    path.write_bytes(b"---\r\nname: valid-skill\r\ndescription: valid\r\n---\r\n# Body\r\n")

    metadata, body = _frontmatter(path)

    assert metadata["name"] == "valid-skill"
    assert body == "# Body\n" or body == "# Body\r\n"


def _write_skill(path: Path, name: str) -> None:
    path.mkdir(parents=True, exist_ok=True)
    (path / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: fixture\n---\n# Body\n",
        encoding="utf-8",
    )


def test_reparse_entries_are_skipped_individually_without_losing_the_root(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "skills"
    _write_skill(root / "healthy", "healthy")
    _write_skill(root / "pretend-linked-directory", "escaped-directory")
    _write_skill(root / "pretend-linked-entry", "escaped-entry")
    linked_directory = root / "pretend-linked-directory"
    linked_entry = root / "pretend-linked-entry" / "SKILL.md"
    real_check = discovery_module._is_link_or_reparse

    def classify(path: Path, metadata=None) -> bool:
        return path in {linked_directory, linked_entry} or real_check(path, metadata)

    monkeypatch.setattr(discovery_module, "_is_link_or_reparse", classify)

    inventory = scan_skills([RootSpec(root, "test")])

    assert [row["name"] for row in inventory["skills"]] == ["healthy"]
    ignored = {Path(row["path"]): row["reason"] for row in inventory["ignored"]}
    assert ignored[linked_directory] == "symlink-or-reparse-directory"
    assert ignored[linked_entry] == "symlink-or-reparse-entry"


def test_real_symlink_escape_is_not_followed_when_supported(tmp_path: Path) -> None:
    root = tmp_path / "skills"
    outside = tmp_path / "outside"
    _write_skill(root / "healthy", "healthy")
    _write_skill(outside / "external", "must-not-load")
    root.mkdir(parents=True, exist_ok=True)
    link = root / "escape"
    try:
        os.symlink(outside, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlink creation is unavailable")

    inventory = scan_skills([RootSpec(root, "test")])

    assert [row["name"] for row in inventory["skills"]] == ["healthy"]
    assert any(Path(row["path"]) == link and row["reason"].startswith("symlink-or-reparse") for row in inventory["ignored"])
