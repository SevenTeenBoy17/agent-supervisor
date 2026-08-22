from __future__ import annotations

import json

from supervisor_core.rollout import rollback_active_version


def test_rollback_rejects_previous_identity_without_version(tmp_path, monkeypatch):
    current = tmp_path / "current"
    previous = tmp_path / "previous"
    current.mkdir()
    previous.mkdir()
    pointer = tmp_path / "active-version.json"
    expected_active = {"version": "3.1.0", "path": str(current)}
    pointer.write_text(
        json.dumps(
            {
                "contract": "ActiveVersionPointer/v3",
                "active": expected_active,
                "previous": {"version": "", "path": str(previous)},
            }
        ),
        encoding="utf-8",
    )
    before = pointer.read_bytes()
    monkeypatch.setenv("AGENT_SUPERVISOR_ACTIVE_POINTER", str(pointer))

    result = rollback_active_version(expected_active=expected_active)

    assert result == {
        "performed": False,
        "reason": "previous-version-unavailable",
        "target": None,
    }
    assert pointer.read_bytes() == before
