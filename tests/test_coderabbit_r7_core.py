from __future__ import annotations

import json
from pathlib import Path

from supervisor_core.attestation import sign_record
from supervisor_core.rollout import apply_observation, initial_rollout, promote
from supervisor_core.routing import _clause_has_term, route_intents
from supervisor_core.util import redact


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


def test_json_secret_values_are_fully_redacted_without_consuming_neighbors() -> None:
    source = json.dumps({
        "token": "abc, 123; with spaces",
        "password": "quoted secret",
        "authorization": "Bearer abc.def",
        "next": "safe",
    }, separators=(",", ":"))

    sanitized = redact(source)

    assert json.loads(sanitized) == {
        "token": "[REDACTED]",
        "password": "[REDACTED]",
        "authorization": "[REDACTED]",
        "next": "safe",
    }


def test_optional_key_and_value_quotes_preserve_delimiters_and_adjacent_fields() -> None:
    assert redact("token=abc} next=safe") == "token=[REDACTED]} next=safe"
    assert redact("'api_key': 'a,b;c', 'next': 'safe'") == (
        "'api_key': '[REDACTED]', 'next': 'safe'"
    )
    assert redact('token: "escaped \\" value", status: ok') == (
        'token: "[REDACTED]", status: ok'
    )
    assert redact('{"not_token":"safe","status":"ok"}') == (
        '{"not_token":"safe","status":"ok"}'
    )
    assert redact(redact("token=abc123")) == "token=[REDACTED]"
    authorization = "authorization: Bearer abc} status=safe"
    assert redact(authorization) == "authorization: [REDACTED]} status=safe"
    assert redact(redact(authorization)) == "authorization: [REDACTED]} status=safe"


def test_completed_rollback_is_not_required_again_for_the_same_lineage(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv(
        "AGENT_SUPERVISOR_ATTESTATION_KEY_FILE",
        str(tmp_path / "attestation.key"),
    )
    state = initial_rollout({}, "observe")
    active = {"version": "4.0.0", "path": "C:/releases/4.0.0"}
    target = {"version": "3.1.0", "path": "C:/releases/3.1.0"}
    state["metrics"]["global_gate_active_identity"] = active
    state["rollback"] = {
        "required": True,
        "attempted": True,
        "performed": True,
        "expected_active": active,
        "target_active": target,
    }

    for index in range(2):
        apply_observation(
            state,
            _observation(
                f"failure-{index}",
                "global_gate",
                result="failed",
                active_version=active,
            ),
        )

    assert state["rollback"]["performed"] is True
    assert state["rollback"]["required"] is False


def test_promotion_replay_preserves_performed_without_requiring_again(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv(
        "AGENT_SUPERVISOR_ATTESTATION_KEY_FILE",
        str(tmp_path / "attestation.key"),
    )
    state = initial_rollout({}, "observe")
    active = {"version": "4.0.0", "path": "C:/releases/4.0.0"}
    target = {"version": "3.1.0", "path": "C:/releases/3.1.0"}
    for record in (
        _observation("fixtures", "fixture_replay", passed=True),
        _observation("history", "historical_replay", passed=True),
        _observation("failure-1", "global_gate", result="failed", active_version=active),
        _observation("failure-2", "global_gate", result="failed", active_version=active),
    ):
        apply_observation(state, record)
    state["rollback"].update({
        "required": False,
        "attempted": True,
        "performed": True,
        "expected_active": active,
        "target_active": target,
    })

    promote(state, "warn")

    assert state["rollback"]["performed"] is True
    assert state["rollback"]["required"] is False


def test_clause_term_boundaries_reject_english_substrings_but_support_chinese() -> None:
    assert _clause_has_term("build pipeline", "ui") is False
    assert _clause_has_term("suitable pipeline", "ui") is False
    assert _clause_has_term("build-ui pipeline", "ui") is True
    assert _clause_has_term("需要优化学生界面体验", "界面") is True


def test_ui_domain_does_not_route_to_build_substring_and_chinese_match_still_routes() -> None:
    inventory = {
        "skills": [
            {"id": "build-runner", "description": "build pipelines"},
            {"id": "visual-designer", "description": "学生界面设计"},
        ]
    }
    english = route_intents(
        message="",
        inventory={"skills": [inventory["skills"][0]]},
        supplied_intents=[{"intent_id": "ui", "text": "render a page", "domain": "ui"}],
    )
    chinese = route_intents(
        message="",
        inventory=inventory,
        supplied_intents=[{"intent_id": "ui", "text": "实现学生界面", "domain": "ui"}],
    )

    assert english["selected_capabilities"] == []
    assert chinese["selected_capabilities"] == ["visual-designer"]
