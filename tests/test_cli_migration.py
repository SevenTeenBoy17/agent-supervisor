from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from supervisor_core.cli import _classify_goal_change, main
from supervisor_core.runtime_bundle import build_runtime_bundle, release_identity
from supervisor_core.util import canonical_sha256, sha256_file
from supervisor_core.validation import validate_state


ROOT = Path(__file__).resolve().parents[1]
CODEX_ADAPTER_FILES = (
    "codex-supervisor-hook.py",
    "supervisor-bootstrap.ps1",
    "supervisor-core.ps1",
    "supervisor-event.ps1",
    "supervisor-finalize.ps1",
    "supervisor-gate.ps1",
    "supervisor-handoff.ps1",
    "supervisor-hook.ps1",
    "supervisor-process-job.py",
    "supervisor-record.ps1",
    "supervisor-turn-ended.ps1",
    "supervisor-validate.ps1",
)
CLAUDE_ADAPTER_FILES = ("sup-v3-hook.py", "sup-selftest.py", "sup-discover.py")


def _write_healthy_skill_fixture(home: Path) -> None:
    target = home / ".codex" / "skills" / "dev-supervisor" / "SKILL.md"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        "---\n"
        "name: dev-supervisor\n"
        "description: goal implement verify run registered gate breaker capability test\n"
        "---\n"
        "# Fixture capability\n",
        encoding="utf-8",
    )


def _write_trusted_executable_registry(home: Path) -> None:
    git_path = shutil.which("git")
    assert git_path is not None
    executables = {
        "git": Path(git_path).resolve(),
        "python": Path(sys.executable).resolve(),
    }
    registry = home / ".agent-supervisor" / "trusted-executables.json"
    registry.parent.mkdir(parents=True, exist_ok=True)
    registry.write_text(
        json.dumps(
            {
                "contract": "TrustedExecutableRegistry/v1",
                "entries": {
                    name: {
                        "kind": "local",
                        "path": str(path),
                        "sha256": sha256_file(path),
                    }
                    for name, path in executables.items()
                },
                "generated_at": "2026-08-24T00:00:00Z",
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def _use_isolated_skill_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    _write_healthy_skill_fixture(home)
    _write_trusted_executable_registry(home)
    adapter_roots = (
        home / ".codex" / "skills" / "dev-supervisor" / "scripts",
        home / ".claude" / "skills" / "supervisor" / "scripts",
    )
    for root, filenames in zip(
        adapter_roots,
        (CODEX_ADAPTER_FILES, CLAUDE_ADAPTER_FILES),
        strict=True,
    ):
        root.mkdir(parents=True, exist_ok=True)
        for filename in filenames:
            (root / filename).write_text(f"fixture:{filename}\n", encoding="utf-8")
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("HOME", str(home))


def _validate_adapter_roots(
    roots: tuple[Path, Path], *, installation_expected: bool
) -> str | None:
    exists = tuple(root.exists() for root in roots)
    if not any(exists) and not installation_expected:
        return "global Claude/Codex adapters are not installed on this host"
    if not all(exists):
        raise RuntimeError(f"partial adapter installation: {roots}")
    missing = [
        str(root / "scripts" / filename)
        for root, filenames in zip(roots, (CODEX_ADAPTER_FILES, CLAUDE_ADAPTER_FILES), strict=True)
        for filename in filenames
        if not (root / "scripts" / filename).is_file()
    ]
    if missing:
        raise RuntimeError(f"adapter installation is damaged; missing: {', '.join(missing)}")
    return None


def _resolve_adapter_roots() -> tuple[tuple[Path, Path], str | None]:
    review_bundle = ROOT.parent
    review_bundle_mode = (review_bundle / "REVIEW_MANIFEST.json").is_file()
    configured = os.environ.get("AGENT_SUPERVISOR_INSTALL_HOME")
    if review_bundle_mode:
        roots = (review_bundle / "global-codex", review_bundle / "global-claude")
    else:
        if configured:
            install_home = Path(configured).resolve()
        elif ROOT.name == ".agent-supervisor":
            install_home = ROOT.parent
        else:
            install_home = Path.home()
        roots = (
            install_home / ".codex" / "skills" / "dev-supervisor",
            install_home / ".claude" / "skills" / "supervisor",
        )
    skip_reason = _validate_adapter_roots(
        roots,
        installation_expected=review_bundle_mode or bool(configured),
    )
    return roots, skip_reason


(CODEX_ROOT, CLAUDE_ROOT), _ADAPTER_SKIP_REASON = _resolve_adapter_roots()


def test_adapter_roots_skip_only_when_both_are_genuinely_absent(tmp_path: Path) -> None:
    roots = (tmp_path / "codex", tmp_path / "claude")
    assert _validate_adapter_roots(roots, installation_expected=False)
    roots[0].mkdir()
    with pytest.raises(RuntimeError, match="partial adapter installation"):
        _validate_adapter_roots(roots, installation_expected=False)


def test_existing_but_damaged_adapter_installation_fails(tmp_path: Path) -> None:
    roots = (tmp_path / "codex", tmp_path / "claude")
    for root in roots:
        (root / "scripts").mkdir(parents=True)
    (roots[0] / "scripts" / CODEX_ADAPTER_FILES[0]).write_text("present\n", encoding="utf-8")
    (roots[1] / "scripts" / CLAUDE_ADAPTER_FILES[0]).write_text("present\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="installation is damaged"):
        _validate_adapter_roots(roots, installation_expected=False)


def test_adapter_installation_rejects_missing_process_job_launcher(tmp_path: Path) -> None:
    roots = (tmp_path / "codex", tmp_path / "claude")
    for root, filenames in zip(
        roots,
        (CODEX_ADAPTER_FILES, CLAUDE_ADAPTER_FILES),
        strict=True,
    ):
        scripts = root / "scripts"
        scripts.mkdir(parents=True)
        for filename in filenames:
            (scripts / filename).write_text(f"fixture:{filename}\n", encoding="utf-8")
    (roots[0] / "scripts" / "supervisor-process-job.py").unlink()

    with pytest.raises(
        RuntimeError,
        match=r"missing: .*supervisor-process-job\.py",
    ):
        _validate_adapter_roots(roots, installation_expected=True)


def _hermetic_hook_env(home: Path) -> dict[str, str]:
    codex_target = home / ".codex" / "skills" / "dev-supervisor" / "scripts"
    claude_target = home / ".claude" / "skills" / "supervisor" / "scripts"
    codex_target.mkdir(parents=True)
    claude_target.mkdir(parents=True)
    for filename in CODEX_ADAPTER_FILES:
        shutil.copy2(CODEX_ROOT / "scripts" / filename, codex_target / filename)
    for filename in CLAUDE_ADAPTER_FILES:
        shutil.copy2(CLAUDE_ROOT / "scripts" / filename, claude_target / filename)
    _write_trusted_executable_registry(home)
    env = os.environ.copy()
    for key in (
        "AGENT_SUPERVISOR_ACTIVE_POINTER",
        "AGENT_SUPERVISOR_HOME",
        "AGENT_SUPERVISOR_INSTALL_HOME",
        "AGENT_SUPERVISOR_RELEASE_ROOT",
        "CODEX_THREAD_ID",
        "CLAUDE_SESSION_ID",
        "PYTHONPATH",
    ):
        env.pop(key, None)
    env.update({
        "USERPROFILE": str(home),
        "HOME": str(home),
        "AGENT_SUPERVISOR_INSTALL_HOME": str(home),
    })
    return env


def test_invalid_cli_state_uses_exit_64(capsys):
    assert main(["query", "--runtime", "codex", "--workspace", "Z:/does-not-exist", "--session", "missing"]) == 64
    assert "InvalidState" in capsys.readouterr().out
    assert main(["query", "--runtime", "test", "--workspace", ".", "--session", "s"]) == 64


def test_latest_round_resolves_pointer_and_missing_query_is_invalid(tmp_path, capsys, monkeypatch):
    _use_isolated_skill_home(tmp_path, monkeypatch)
    common = ["--runtime", "codex", "--workspace", str(tmp_path), "--session", "s", "--state-root", str(tmp_path / "state")]
    assert main(["start", *common, "--round", "real-round", "--message", "goal", "--change-mode", "replace", "--execution-mode", "observe"]) == 0
    capsys.readouterr()
    assert main(["query", *common, "--round", "latest"]) == 0
    assert json.loads(capsys.readouterr().out)["round"] == "real-round"
    assert main(["query", "--runtime", "codex", "--workspace", str(tmp_path), "--session", "missing", "--round", "latest", "--state-root", str(tmp_path / "state")]) == 64
    missing_output = capsys.readouterr().out
    assert "active round" in missing_output or "no active round" in missing_output


def test_migration_is_redacted_archive_and_refuses_overwrite(tmp_path, capsys):
    source = tmp_path / "legacy"
    source.mkdir()
    (source / "ledger.json").write_text('{"old":true,"token":"abc123"}\n', encoding="utf-8")
    (source / "settings.local.json").write_text('{"password":"do-not-copy"}\n', encoding="utf-8")
    args = ["migrate", "--source", str(source), "--runtime", "codex", "--workspace", str(tmp_path / "workspace"), "--session", "s", "--round", "r", "--state-root", str(tmp_path / "state")]
    assert main(args) == 0
    result = json.loads(capsys.readouterr().out)
    destination = Path(result["destination"])
    assert "abc123" not in (destination / "ledger.json").read_text(encoding="utf-8")
    assert not (destination / "settings.local.json").exists()
    manifest = json.loads((destination / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["redacted_archive"] is True
    assert any(row["omitted_reason"] == "sensitive-name" for row in manifest["files"])
    assert main(args) == 64
    assert "abc123" in (source / "ledger.json").read_text(encoding="utf-8")


def test_event_cli_updates_authoritative_state_records(tmp_path, capsys, monkeypatch):
    _use_isolated_skill_home(tmp_path, monkeypatch)
    state_root = tmp_path / "state"
    common = ["--runtime", "codex", "--workspace", str(tmp_path), "--session", "s", "--round", "r", "--state-root", str(state_root)]
    assert main(["start", *common, "--message", "implement", "--change-mode", "replace", "--execution-mode", "observe"]) == 0
    started = json.loads(capsys.readouterr().out)
    state_file = Path(started["state_file"])

    records = [
        ("spec_record", {"status": "approved", "hash": "a" * 64, "path": "spec.md", "content": "resolved contract"}),
        ("task_record", {"task_id": "task-1", "goal_id": "g", "goal_version": 1, "criterion_ids": ["criterion-1"], "allowed_paths": ["config.json"], "expected_evidence": ["test"], "status": "doing", "evidence_ids": []}),
        ("evidence_record", {"evidence_id": "e-1", "command": {"category": "test", "args": ["pytest", "token=abc123"]}}),
        ("changes_record", {"files": ["config.json"], "diff_hash": "b" * 64}),
    ]
    for event_type, record in records:
        assert main(["event", *common, "--event-type", event_type, "--data-json", json.dumps({"record": record})]) == 0
        capsys.readouterr()
    assert main([
        "event", *common, "--event-type", "review_record", "--data-json",
        json.dumps({"record": {"review_id": "review-1", "verdict": "APPROVE"}}),
    ]) == 64
    capsys.readouterr()
    assert main(["event", *common, "--event-type", "intent_disposition", "--data-json", json.dumps({"record": {"intent_id": "intent-1", "status": "skipped", "reason": "covered manually", "capability_ids": [], "method": "manual-specialized", "phase": 1}})]) == 0
    capsys.readouterr()

    state = json.loads(state_file.read_text(encoding="utf-8"))
    assert state["spec"]["status"] == "approved"
    assert state["tasks"][0]["task_id"] == "task-1"
    assert state["evidence"][0]["evidence_id"] == "e-1"
    assert state["evidence"][0]["command"]["args"][1].endswith("[REDACTED]")
    assert state["reviews"] == []
    assert state["changes"]["files"] == []
    assert state["changes"]["diff_hash"] == canonical_sha256({})
    assert state["changes"]["implementer"] == "codex-local-workspace"
    assert state["changes"]["producer_identity_assurance"] == "core-observed-local-workspace"
    assert state["intents"][0]["status"] == "skipped"


def test_gate_runner_attests_real_exit_and_rejects_self_report(tmp_path, capsys, monkeypatch):
    _use_isolated_skill_home(tmp_path, monkeypatch)
    monkeypatch.setenv("AGENT_SUPERVISOR_ATTESTATION_KEY_FILE", str(tmp_path / "attestation.key"))
    state_root = tmp_path / "state"
    common = ["--runtime", "codex", "--workspace", str(tmp_path), "--session", "attested", "--round", "r", "--state-root", str(state_root)]
    assert main(["start", *common, "--message", "run registered gate", "--change-mode", "replace", "--execution-mode", "observe"]) == 0
    started = json.loads(capsys.readouterr().out)
    state_file = Path(started["state_file"])
    state = json.loads(state_file.read_text(encoding="utf-8"))
    criterion_id = state["goal"]["acceptance_criteria"][0]["criterion_id"]
    state["quality_profile"] = {
        "global_gates": ["gate.real"],
        "common_gates": [{"id": "gate.real", "command": [sys.executable, "-c", "raise SystemExit(99)"]}],
        "domains": {"config/agent": {"required_gates": ["gate.real"]}},
    }
    state_file.write_text(json.dumps(state), encoding="utf-8")
    request = {"record": {
        "gate_id": "gate.real", "criterion_id": criterion_id,
        "evidence_id": "real-evidence",
    }}
    assert main(["event", *common, "--event-type", "gate_run", "--data-json", json.dumps(request)]) == 2
    runner_output = json.loads(capsys.readouterr().out)
    assert runner_output["exit_code"] == 99
    state = json.loads(state_file.read_text(encoding="utf-8"))
    assert state["evidence"] == []
    events = [json.loads(line) for line in state_file.with_name("events.jsonl").read_text(encoding="utf-8").splitlines()]
    assert any(
        event.get("event_type") == "gate_execution"
        and event.get("exit_code") == 99
        and event.get("collector") == "supervisor-core"
        and event.get("collector_identity_assurance") == "core-executed-gate"
        for event in events
    )
    report = validate_state(state, events)
    assert not any("lacks a valid local-core execution" in error for error in report["errors"])
    assert any("required quality gate missing" in error for error in report["errors"])

    forged = {
        "contract": "EvidenceRecord/v3", "evidence_id": "forged", "execution_id": "invented",
        "criterion_id": criterion_id, "goal_id": state["goal"]["goal_id"], "goal_version": state["goal"]["version"],
        "command": {"category": "quality-gate", "args": state["quality_profile"]["common_gates"][0]["command"]},
        "cwd": str(tmp_path), "collected_at": state["started_at"], "exit_code": 0,
        "output_summary": "all passed", "artifact_hash": "b" * 64, "output_sha256": "b" * 64,
        "base": "a" * 64, "head": "a" * 64, "diff_hash": "a" * 64,
        "collector": "reviewer-a", "collector_responsibility_group": "quality",
        "gate_id": "gate.real", "relevant": True,
    }
    assert main(["event", *common, "--event-type", "evidence_record", "--data-json", json.dumps({"record": forged})]) == 0
    capsys.readouterr()
    forged_state = json.loads(state_file.read_text(encoding="utf-8"))
    forged_report = validate_state(forged_state, events)
    assert any("lacks a valid local-core execution attestation" in error for error in forged_report["errors"])


def test_two_failures_open_breaker_but_untrusted_fallback_is_unavailable(tmp_path, capsys, monkeypatch):
    _use_isolated_skill_home(tmp_path, monkeypatch)
    project = tmp_path / ".agent-supervisor" / "project.json"
    project.parent.mkdir()
    schema = project.parent / "schemas" / "project.schema.json"
    schema.parent.mkdir()
    schema.write_text(json.dumps({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["$schema", "project_id", "agent_roles", "supervisor_scope"],
        "properties": {
            "$schema": {"type": "string", "minLength": 1},
            "project_id": {"type": "string", "minLength": 1},
            "agent_roles": {"type": "array"},
            "supervisor_scope": {
                "type": "object",
                "required": ["allowed_change_globs", "out_of_scope_globs"],
                "properties": {
                    "allowed_change_globs": {"type": "array", "items": {"type": "string"}},
                    "out_of_scope_globs": {"type": "array", "items": {"type": "string"}},
                },
                "additionalProperties": False,
            },
        },
        "additionalProperties": False,
    }), encoding="utf-8")
    project.write_text(json.dumps({
        "$schema": "./schemas/project.schema.json", "project_id": "p",
        "agent_roles": [{"id": "primary-agent", "fallback_id": "fallback-agent"}],
        "supervisor_scope": {"allowed_change_globs": [".agent-supervisor/**"], "out_of_scope_globs": []},
    }), encoding="utf-8")
    common = ["--runtime", "codex", "--workspace", str(tmp_path), "--session", "breaker", "--round", "r", "--project-file", str(project), "--state-root", str(tmp_path / "state")]
    assert main(["start", *common, "--message", "registered breaker capability", "--change-mode", "replace", "--execution-mode", "observe"]) == 0
    state_file = Path(json.loads(capsys.readouterr().out)["state_file"])
    for index in (1, 2):
        invocation_id = f"inv-{index}"
        assert main(["event", *common, "--event-type", "invocation_attempt", "--invocation-id", invocation_id, "--capability", "primary-agent", "--actor", "worker"]) == 0
        capsys.readouterr()
        assert main(["event", *common, "--event-type", "invocation_result", "--invocation-id", invocation_id, "--capability", "primary-agent", "--actor", "worker", "--result", "failed"]) == 0
        capsys.readouterr()
    row = json.loads(state_file.read_text(encoding="utf-8"))["capability_breakers"]["primary-agent"]
    assert row["open"] is True
    assert "active_capability" not in row
    assert row["fallback_status"] == "unavailable"
    assert row["fallback_unavailable_reason"] == "trusted-inventory-fallback-unavailable"
    assert json.loads(state_file.read_text(encoding="utf-8"))["health"] == "degraded"
    assert main(["event", *common, "--event-type", "invocation_attempt", "--invocation-id", "inv-3", "--capability", "primary-agent", "--actor", "worker"]) == 4
    response = json.loads(capsys.readouterr().out)
    assert response["fallback_required"] is None


def test_two_failures_do_not_activate_toml_only_unverified_fallback(
    tmp_path, capsys, monkeypatch
):
    _use_isolated_skill_home(tmp_path, monkeypatch)
    agents = tmp_path / ".codex" / "agents"
    agents.mkdir(parents=True)
    primary_manifest = agents / "primary-agent.toml"
    fallback_manifest = agents / "fallback-agent.toml"
    primary_manifest.write_text(
        'name = "primary-agent"\n'
        'description = "Registered breaker capability implementation owner"\n'
        'sandbox_mode = "workspace-write"\n',
        encoding="utf-8",
    )
    fallback_manifest.write_text(
        'name = "fallback-agent"\n'
        'description = "Registered breaker capability fallback owner"\n'
        'sandbox_mode = "workspace-write"\n',
        encoding="utf-8",
    )
    project = tmp_path / ".agent-supervisor" / "project.json"
    project.parent.mkdir()
    schema = project.parent / "schemas" / "project.schema.json"
    schema.parent.mkdir()
    schema.write_text(json.dumps({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["$schema", "project_id", "agent_roles", "supervisor_scope"],
        "properties": {
            "$schema": {"type": "string", "minLength": 1},
            "project_id": {"type": "string", "minLength": 1},
            "agent_roles": {"type": "array"},
            "supervisor_scope": {
                "type": "object",
                "required": ["allowed_change_globs", "out_of_scope_globs"],
                "properties": {
                    "allowed_change_globs": {"type": "array", "items": {"type": "string"}},
                    "out_of_scope_globs": {"type": "array", "items": {"type": "string"}},
                },
                "additionalProperties": False,
            },
        },
        "additionalProperties": False,
    }), encoding="utf-8")
    project.write_text(json.dumps({
        "$schema": "./schemas/project.schema.json",
        "project_id": "p",
        "agent_roles": [{
            "id": "primary-agent",
            "config": ".codex/agents/primary-agent.toml",
            "responsibility_group": "implementation",
            "fallback_id": "fallback-agent",
            "fallback_config": ".codex/agents/fallback-agent.toml",
        }],
        "supervisor_scope": {
            "allowed_change_globs": [".agent-supervisor/**"],
            "out_of_scope_globs": [],
        },
    }), encoding="utf-8")
    common = [
        "--runtime", "codex", "--workspace", str(tmp_path), "--session", "trusted-breaker",
        "--round", "r", "--project-file", str(project), "--state-root", str(tmp_path / "state"),
    ]
    assert main([
        "start", *common, "--message", "registered breaker capability",
        "--change-mode", "replace", "--execution-mode", "observe",
    ]) == 0
    state_file = Path(json.loads(capsys.readouterr().out)["state_file"])
    started = json.loads(state_file.read_text(encoding="utf-8"))
    assert len(started["discovery"]["inventory_sha256"]) == 64
    assert started["capability_route"]["inventory_sha256"] == started["discovery"][
        "inventory_sha256"
    ]
    assert all(
        row["host_liveness_status"] == "unverified"
        and row["health"] == "unknown"
        and row["availability"] == "unavailable"
        and row["active"] is False
        and row["automatic"] is False
        for row in started["capability_inventory"]["agents"]
    )
    for index in (1, 2):
        invocation_id = f"trusted-inv-{index}"
        assert main([
            "event", *common, "--event-type", "invocation_attempt",
            "--invocation-id", invocation_id, "--capability", "primary-agent",
            "--actor", "worker",
        ]) == 0
        capsys.readouterr()
        assert main([
            "event", *common, "--event-type", "invocation_result",
            "--invocation-id", invocation_id, "--capability", "primary-agent",
            "--actor", "worker", "--result", "failed",
        ]) == 0
        capsys.readouterr()
    state = json.loads(state_file.read_text(encoding="utf-8"))
    row = state["capability_breakers"]["primary-agent"]
    assert row["open"] is True
    assert row["fallback_status"] == "unavailable"
    assert "active_capability" not in row
    assert "fallback_binding" not in row
    assert row["fallback_unavailable_reason"] == "trusted-inventory-fallback-unavailable"
    assert state["health"] == "degraded"
    assert main([
        "event", *common, "--event-type", "invocation_attempt",
        "--invocation-id", "trusted-inv-3", "--capability", "primary-agent",
        "--actor", "worker",
    ]) == 4
    response = json.loads(capsys.readouterr().out)
    assert response["fallback_required"] is None


def test_bin_bootstrap_runs_from_arbitrary_cwd(tmp_path):
    fixture_version = "fixture-v4-direct-launcher"
    install_home = tmp_path / "physical install home"
    pointer_root = install_home / ".agent-supervisor"
    launcher = pointer_root / "bin" / "agent-supervisor.py"
    launcher.parent.mkdir(parents=True)
    shutil.copy2(ROOT / "bin" / "agent-supervisor.py", launcher)

    release = (
        install_home
        / ".agent-supervisor-releases"
        / fixture_version
    )
    package = release / "supervisor_core"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text(
        '"""Hermetic direct-launcher fixture."""\n',
        encoding="utf-8",
    )
    (package / "cli.py").write_text(
        (
            "import sys\n\n"
            "def main(argv=None):\n"
            "    args = list(sys.argv[1:] if argv is None else argv)\n"
            "    if args == ['--version']:\n"
            f"        print({fixture_version!r})\n"
            "        return 0\n"
            "    return 64\n"
        ),
        encoding="utf-8",
    )
    bundle_relative = "runtime/supervisor-runtime.zip"
    bundle = build_runtime_bundle(release, fixture_version)
    bundle_path = release / Path(bundle_relative)
    bundle_path.parent.mkdir()
    bundle_path.write_bytes(bundle)
    active = release_identity(
        release,
        fixture_version,
        bundle_relative,
        bundle,
    )
    physical_pointer = pointer_root / "active-version.json"
    physical_pointer.write_text(
        json.dumps(
            {
                "contract": "ActiveVersionPointer/v4",
                "active": active,
                "previous": None,
            },
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )

    arbitrary_cwd = tmp_path / "unrelated 中文 cwd"
    arbitrary_cwd.mkdir()
    environment_home = tmp_path / "unrelated environment home"
    environment_home.mkdir()
    override_pointer = tmp_path / "malformed environment override.json"
    override_pointer.write_text("{}\n", encoding="utf-8")
    env = os.environ.copy()
    for key in (
        "AGENT_SUPERVISOR_ACTIVE_POINTER",
        "AGENT_SUPERVISOR_HOME",
        "AGENT_SUPERVISOR_INSTALL_HOME",
        "AGENT_SUPERVISOR_RELEASE_ROOT",
        "PYTHONPATH",
    ):
        env.pop(key, None)
    env.update({
        "AGENT_SUPERVISOR_ACTIVE_POINTER": str(override_pointer),
        "AGENT_SUPERVISOR_HOME": str(tmp_path / "untrusted supervisor home"),
        "AGENT_SUPERVISOR_INSTALL_HOME": str(environment_home),
        "AGENT_SUPERVISOR_RELEASE_ROOT": str(tmp_path / "untrusted releases"),
        "HOME": str(environment_home),
        "USERPROFILE": str(environment_home),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONIOENCODING": "utf-8",
    })

    completed = subprocess.run(
        [sys.executable, str(launcher), "--version"],
        cwd=arbitrary_cwd,
        env=env,
        text=True,
        capture_output=True,
        encoding="utf-8",
        check=False,
        timeout=15,
    )

    assert Path(env["AGENT_SUPERVISOR_ACTIVE_POINTER"]) != physical_pointer
    assert completed.returncode == 0
    assert completed.stdout.strip() == fixture_version
    assert completed.stderr == ""


@pytest.mark.skipif(_ADAPTER_SKIP_REASON is not None, reason=_ADAPTER_SKIP_REASON or "")
def test_hook_session_start_handles_unicode_space_path(tmp_path):
    workspace = tmp_path / "中文 path"
    workspace.mkdir()
    isolated_home = tmp_path / "home"
    isolated_home.mkdir()
    payload = json.dumps({"session_id": "s", "cwd": str(workspace), "hook_event_name": "SessionStart"}, ensure_ascii=False)
    root = Path(__file__).resolve().parents[1]
    completed = subprocess.run(
        [sys.executable, "-m", "supervisor_core", "hook", "--runtime", "claude", "--event", "SessionStart"],
        cwd=root,
        env=_hermetic_hook_env(isolated_home),
        input=payload,
        text=True,
        capture_output=True,
        encoding="utf-8",
    )
    assert completed.returncode == 0
    result = json.loads(completed.stdout)
    assert "ready" in result["hookSpecificOutput"]["additionalContext"]


@pytest.mark.skipif(_ADAPTER_SKIP_REASON is not None, reason=_ADAPTER_SKIP_REASON or "")
def test_session_start_does_not_claim_recovery_before_a_goal_round_acknowledges_degraded_state(tmp_path):
    workspace = tmp_path / "degraded 中文 path"
    workspace.mkdir()
    isolated_home = tmp_path / "home"
    isolated_home.mkdir()
    payload = json.dumps({
        "session_id": "degraded-session",
        "cwd": str(workspace),
        "hook_event_name": "SessionStart",
        "_agent_supervisor_adapter": {"adapter_version": "3.0.1", "degraded_prior": True},
    }, ensure_ascii=False)
    env = _hermetic_hook_env(isolated_home)
    root = Path(__file__).resolve().parents[1]
    completed = subprocess.run(
        [sys.executable, "-m", "supervisor_core", "hook", "--runtime", "claude", "--event", "SessionStart"],
        cwd=root, input=payload, text=True, capture_output=True, encoding="utf-8", env=env, check=False,
    )
    assert completed.returncode == 4
    result = json.loads(completed.stdout)
    assert result["agent_supervisor"] == {"health": "degraded", "durable_ack": True}
    health_records = list((isolated_home / ".agent-supervisor" / "state").rglob("adapter-health.json"))
    assert len(health_records) == 1
    assert json.loads(health_records[0].read_text(encoding="utf-8"))["recovery_requires"] == "durable active round acknowledgement"


def test_goal_change_classifier_never_silently_replaces_unfinished_work():
    previous = {
        "terminal_state": "incomplete",
        "goal": {
            "goal_id": "g",
            "objective": "Complete the database migration",
            "acceptance_criteria": [{"description": "migration tests pass"}],
        },
    }
    assert _classify_goal_change("测试还没跑完，请跑测试", previous) == "continue"
    assert _classify_goal_change("Please finish the migration tests", previous) == "continue"
    assert _classify_goal_change("另外补充并发测试", previous) == "extend"
    assert _classify_goal_change("新任务：改做文档", previous) == "replace"
    assert _classify_goal_change("IMPLEMENT_LOGIN_PAGE_WITH_OAUTH_AND_UI", previous) == "replace"
