from __future__ import annotations

import json

from supervisor_core.rollout import rollback_active_version
from supervisor_core.runtime_bundle import build_runtime_bundle, release_identity


def _write_release(path, version):
    package = path / "supervisor_core"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("VERSION = 'fixture'\n", encoding="utf-8")
    (package / "cli.py").write_text("def main():\n    return 0\n", encoding="utf-8")
    bundle = build_runtime_bundle(path, version)
    bundle_path = path / "runtime" / "supervisor-runtime.zip"
    bundle_path.parent.mkdir(parents=True)
    bundle_path.write_bytes(bundle)
    return release_identity(path, version, "runtime/supervisor-runtime.zip", bundle)


def test_rollback_rejects_previous_identity_without_version(tmp_path, monkeypatch):
    current = tmp_path / "current"
    previous = tmp_path / "previous"
    expected_active = _write_release(current, "3.1.0")
    invalid_previous = _write_release(previous, "3.0.0")
    invalid_previous["version"] = ""
    pointer = tmp_path / "active-version.json"
    pointer.write_text(
        json.dumps(
            {
                    "contract": "ActiveVersionPointer/v4",
                    "active": expected_active,
                    "previous": invalid_previous,
            }
        ),
        encoding="utf-8",
    )
    before = pointer.read_bytes()
    monkeypatch.setenv("AGENT_SUPERVISOR_ACTIVE_POINTER", str(pointer))

    result = rollback_active_version(expected_active=expected_active)

    assert result == {
        "performed": False,
        "reason": "active-pointer-invalid",
        "target": None,
    }
    assert pointer.read_bytes() == before
