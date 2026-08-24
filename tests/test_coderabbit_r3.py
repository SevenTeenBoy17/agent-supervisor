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
