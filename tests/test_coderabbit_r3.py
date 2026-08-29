from __future__ import annotations

import argparse
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from jsonschema import Draft202012Validator

import supervisor_core.cli as cli_module
import supervisor_core.storage as storage_module
from supervisor_core.lifecycle import _privacy_safe_previous_for_carry
from supervisor_core.rollout import initial_rollout
from supervisor_core.routing import route_intents
from supervisor_core.storage import LockTimeout


def test_dead_lock_reclaim_cannot_acquire_after_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ticks = iter((100.0, 100.2))
    monkeypatch.setattr(storage_module.time, "monotonic", lambda: next(ticks, 100.2))
    monkeypatch.setattr(
        storage_module, "_publish_lock_no_clobber", lambda _temp, _path: False
    )
    monkeypatch.setattr(storage_module, "_reclaim_confirmed_dead_lock", lambda _path: True)

    with pytest.raises(LockTimeout):
        with storage_module._exclusive_file_lock(tmp_path / "expired.lock", timeout=0.1):
            pytest.fail("a reclaimed lock must not be acquired after its deadline")


def test_privacy_carry_preserves_rollout_machine_reasons_but_redacts_prose() -> None:
    sentinel = "RAW ROLLOUT PROSE SENTINEL"
    previous = {
        "rollout": {
            "contract": "RolloutState/v3",
            "active_mode": "enforce",
            "rollback": {
                "reason": "active-version-cas-mismatch",
                "reset_reason": "new-active-version-observed",
                "summary": sentinel,
            },
            "rollback_history": [
                {"reason": sentinel, "reset_reason": sentinel, "summary": sentinel}
            ],
        }
    }

    carried = _privacy_safe_previous_for_carry(
        previous, {"privacy": {"persist_raw_prompts": False}}
    )

    assert carried["rollout"]["rollback"]["reason"] == "active-version-cas-mismatch"
    assert carried["rollout"]["rollback"]["reset_reason"] == "new-active-version-observed"
    assert sentinel not in json.dumps(carried, ensure_ascii=False)
    assert carried["rollout"]["rollback_history"][0]["reason"].startswith("Legacy reason sha256:")
    assert carried["rollout"]["rollback_history"][0]["reset_reason"].startswith("Legacy reset_reason sha256:")
    replayed = initial_rollout({}, "enforce", carried["rollout"])
    assert replayed["rollback"]["reason"] == "active-version-cas-mismatch"


def test_open_circuit_uses_normalized_enforce_mode(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    events: list[dict[str, object]] = []

    class FakeContext:
        def load(self) -> dict[str, object]:
            return {
                "execution_mode": "  ENFORCE\t",
                "capability_inventory": {
                    "skills": [
                        {
                            "id": "fragile-capability",
                            "active": True,
                            "automatic": True,
                            "user_invocable": True,
                            "availability": "enabled",
                            "health": "healthy",
                            "error": "",
                        }
                    ]
                },
                "capability_breakers": {
                    "fragile-capability": {
                        "open": True,
                        "fallback_id": "safe-fallback",
                    }
                },
            }

        def append_event(self, event: dict[str, object]) -> None:
            events.append(event)

    monkeypatch.setattr(cli_module, "_hook_context", lambda *_args, **_kwargs: SimpleNamespace())
    monkeypatch.setattr(cli_module, "_context", lambda *_args, **_kwargs: FakeContext())
    monkeypatch.setattr(
        cli_module.sys,
        "stdin",
        io.StringIO(
            json.dumps(
                {
                    "tool_name": "Skill",
                    "tool_input": {"skill": "fragile-capability"},
                    "tool_use_id": "invocation-r3",
                }
            )
        ),
    )

    result = cli_module.command_hook(
        argparse.Namespace(runtime="codex", event="PreToolUse", state_root=None)
    )
    output = json.loads(capsys.readouterr().out)

    assert result == 0
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert events[0]["event_type"] == "invocation_fallback_required"


def test_clean_event_payload_rejects_caller_supplied_attestation() -> None:
    args = argparse.Namespace(
        data_json=json.dumps({"attestation": "f" * 64}),
        event_type="custom_event",
        phase=None,
        status=None,
        capability=None,
        command_category=None,
        summary=None,
        actor=None,
        responsibility_group=None,
        invocation_id=None,
        result=None,
    )

    with pytest.raises(cli_module.InvalidState, match="attestation is forbidden"):
        cli_module._clean_event_payload(args)


def test_clean_event_payload_rejects_caller_invocation_kind_attribution() -> None:
    args = argparse.Namespace(
        data_json=json.dumps({
            "kind": "skill",
            "capability_kind": "agent",
            "tool_kind": "native",
        }),
        event_type="invocation_attempt",
        phase="implementation",
        status=None,
        capability="exec_command",
        command_category="native-command",
        summary="structured audit event",
        actor=None,
        responsibility_group=None,
        invocation_id="invocation-kind-spoof",
        result=None,
    )

    payload = cli_module._clean_event_payload(args)

    assert "kind" not in payload
    assert "capability_kind" not in payload
    assert "tool_kind" not in payload
    assert payload["capability"] == "exec_command"


@pytest.mark.parametrize(
    "override",
    [
        {"active": False},
        {"availability": "disabled"},
        {"health": "unavailable"},
        {"error": "ambiguous-cross-source"},
        {"automatic": False, "user_invocable": False},
    ],
)
def test_inventory_capability_attribution_requires_scanner_invocability(
    override: dict[str, object],
) -> None:
    row: dict[str, object] = {
        "id": "untrusted-capability",
        "active": True,
        "automatic": True,
        "user_invocable": True,
        "availability": "enabled",
        "health": "healthy",
        "error": "",
    }
    row.update(override)
    state = {
        "capability_inventory": {
            "skills": [row]
        }
    }

    observed = cli_module._inventory_bound_capability_name(
        state,
        tool_name="Skill",
        tool_input={"skill": "untrusted-capability"},
        payload={},
    )
    breaker_key = cli_module._inventory_bound_breaker_capability_name(
        state,
        tool_name="Skill",
        tool_input={"skill": "untrusted-capability"},
        payload={},
    )

    assert observed == "Skill"
    assert breaker_key is None


def test_unbound_skill_failures_do_not_share_or_open_a_breaker() -> None:
    state: dict[str, object] = {
        "capability_inventory": {
            "skills": [{
                "id": "known-capability",
                "active": True,
                "automatic": True,
                "user_invocable": True,
                "availability": "enabled",
                "health": "healthy",
                "error": "",
            }]
        }
    }

    for declared in ("unknown-a", "unknown-b"):
        breaker_key = cli_module._inventory_bound_breaker_capability_name(
            state,
            tool_name="Skill",
            tool_input={"skill": declared},
            payload={},
        )
        assert breaker_key is None
        cli_module._record_breaker_result(state, breaker_key, "failed")

    assert "capability_breakers" not in state


@pytest.mark.parametrize(
    "automatic,user_invocable",
    [(True, False), (False, True)],
)
def test_scanner_invocable_skill_uses_same_identity_for_timeline_and_breaker(
    automatic: bool, user_invocable: bool
) -> None:
    state = {
        "capability_inventory": {
            "skills": [{
                "id": "known-capability",
                "active": True,
                "automatic": automatic,
                "user_invocable": user_invocable,
                "availability": "enabled",
                "health": "healthy",
                "error": "",
            }]
        }
    }

    assert cli_module._core_bound_invocation_kinds(
        state, "known-capability", None
    ) == ("skill", "skill")
    assert cli_module._inventory_bound_breaker_capability_name(
        state,
        tool_name="Skill",
        tool_input={"skill": "known-capability"},
        payload={},
    ) == "known-capability"


def test_zero_skill_review_flag_is_evaluated_but_never_self_authorizes() -> None:
    missing = route_intents(message="unmatched", inventory={"skills": []})
    claimed = route_intents(
        message="unmatched", inventory={"skills": []}, zero_skill_reviewed=True
    )

    assert missing["valid"] is False
    assert missing["zero_skill_review_status"] == "missing"
    assert "missing" in missing["errors"][0]
    assert claimed["valid"] is False
    assert claimed["zero_skill_review_status"] == "claimed-unverified"
    assert "flag is not evidence" in claimed["errors"][0]


@pytest.mark.parametrize("suffix", ["\r", "\n", "\r\n"])
def test_project_relative_path_schema_rejects_trailing_line_breaks(suffix: str) -> None:
    schema_path = (
        Path(__file__).resolve().parents[1]
        / "supervisor_core"
        / "schemas"
        / "project-config.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    instance = {
        "$schema": "schemas/project.schema.json",
        "project_id": "p",
        "quality_profile": f"quality-profile.json{suffix}",
        "supervisor_scope": {
            "allowed_change_globs": ["src/**"],
            "out_of_scope_globs": [],
        },
    }

    errors = list(Draft202012Validator(schema).iter_errors(instance))

    assert errors
