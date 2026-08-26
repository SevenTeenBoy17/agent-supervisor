from __future__ import annotations

import argparse
import io
import json
import os
import sys
from pathlib import Path

import pytest

from supervisor_core import cli as cli_module
from supervisor_core import lifecycle as lifecycle_module
from supervisor_core import workspace as workspace_module
from supervisor_core.cli import _evaluate_builtin_gate, main
from supervisor_core.contracts import build_goal
from supervisor_core.executable_trust import trusted_command_approval_sha256
from supervisor_core.routing import split_intents
from supervisor_core.util import sha256_file, sha256_text


def _common(tmp_path: Path, *, session: str = "worker-a-session") -> list[str]:
    skill_root = tmp_path / "skills"
    skill = skill_root / "dev-supervisor"
    skill.mkdir(parents=True, exist_ok=True)
    (skill / "SKILL.md").write_text(
        "---\n"
        "name: dev-supervisor\n"
        "description: Supervisor capability routing and registered quality gates\n"
        "---\n"
        "# Deterministic test capability\n",
        encoding="utf-8",
    )
    return [
        "--runtime", "codex",
        "--workspace", str(tmp_path),
        "--session", session,
        "--round", "worker-a-round",
        "--state-root", str(tmp_path / "state"),
    ]


def _source_snapshot(marker: str) -> dict:
    snapshot = {
        "contract": "SupervisorSourceSnapshot/v3",
        "status": "healthy",
        "roots": {
            "shared-core": "trusted/core",
            "codex-adapter": "trusted/codex",
            "claude-adapter": "trusted/claude",
        },
        "files": {
            name: {"status": "hashed", "sha256": marker * 64, "size": 1}
            for name in workspace_module._required_supervisor_source_names()
        },
    }
    snapshot["snapshot_sha256"] = sha256_text(
        json.dumps(snapshot, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    )
    return snapshot


def _start(tmp_path: Path, capsys: pytest.CaptureFixture[str], *, session: str = "worker-a-session") -> tuple[list[str], Path]:
    common = _common(tmp_path, session=session)
    assert main([
        "start", *common,
        "--roots", f"{tmp_path / 'skills'}|test-fixture|true|false",
        "--message", "Use dev-supervisor to run the registered quality gate",
        "--change-mode", "replace",
        "--execution-mode", "enforce",
    ]) == 0
    state_file = Path(json.loads(capsys.readouterr().out)["state_file"])
    return common, state_file


def test_source_snapshot_is_deterministic_and_whitelisted(tmp_path, monkeypatch) -> None:
    core = tmp_path / "core"
    codex = tmp_path / "codex"
    claude = tmp_path / "claude"
    for root in (core, codex, claude):
        root.mkdir()
    for relative in workspace_module._CORE_SOURCE_WHITELIST:
        path = core / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"source:{relative}\n", encoding="utf-8")
    for filename in workspace_module._CODEX_ADAPTER_WHITELIST:
        (codex / filename).write_text(f"# adapter:{filename}\n", encoding="utf-8")
    for filename in workspace_module._CLAUDE_ADAPTER_WHITELIST:
        (claude / filename).write_text(f"# adapter:{filename}\n", encoding="utf-8")
    (codex / "supervisor-untrusted-extra.ps1").write_text("# must not join trust set\n", encoding="utf-8")
    monkeypatch.setattr(
        workspace_module,
        "_supervisor_source_roots",
        lambda: {"shared-core": core, "codex-adapter": codex, "claude-adapter": claude},
    )
    first = workspace_module.capture_supervisor_source_snapshot()
    second = workspace_module.capture_supervisor_source_snapshot()

    assert first == second
    assert first["contract"] == "SupervisorSourceSnapshot/v3"
    assert first["status"] == "healthy"
    assert len(first["snapshot_sha256"]) == 64
    assert workspace_module.validated_supervisor_source_snapshot_hash(first) == first["snapshot_sha256"]
    assert "shared-core/supervisor_core/cli.py" in first["files"]
    assert set(first["files"]) == workspace_module._required_supervisor_source_names()
    assert "codex-adapter/supervisor-untrusted-extra.ps1" not in first["files"]
    assert all(Path(name).is_absolute() is False for name in first["files"])


def test_static_core_manifest_covers_every_runtime_source_file() -> None:
    core_root = Path(workspace_module.__file__).resolve().parents[1]
    runtime_sources = {
        "bin/agent-supervisor.py",
        "bin/build-core-release-manifest.py",
        "bin/run-coderabbit-review.py",
    } | {
        path.relative_to(core_root).as_posix()
        for path in (core_root / "supervisor_core").rglob("*")
        if path.is_file() and path.suffix in {".py", ".json"}
    }

    assert set(workspace_module._CORE_SOURCE_WHITELIST) == runtime_sources


def test_source_roots_normalize_a_host_config_install_marker(tmp_path, monkeypatch) -> None:
    install_home = tmp_path / "portable user"
    monkeypatch.setenv("AGENT_SUPERVISOR_INSTALL_HOME", str(install_home / ".claude"))

    roots = workspace_module._supervisor_source_roots()

    assert roots["codex-adapter"] == install_home / ".codex" / "skills" / "dev-supervisor" / "scripts"
    assert roots["claude-adapter"] == install_home / ".claude" / "skills" / "supervisor" / "scripts"


def test_source_snapshot_degrades_when_a_required_host_adapter_is_missing(tmp_path, monkeypatch) -> None:
    core = tmp_path / "core"
    codex = tmp_path / "codex"
    claude = tmp_path / "claude"
    for root in (core, codex, claude):
        root.mkdir()
    for relative in workspace_module._CORE_SOURCE_WHITELIST:
        path = core / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"source:{relative}\n", encoding="utf-8")
    for filename in workspace_module._CODEX_ADAPTER_WHITELIST:
        if filename != "supervisor-finalize.ps1":
            (codex / filename).write_text(f"# adapter:{filename}\n", encoding="utf-8")
    for filename in workspace_module._CLAUDE_ADAPTER_WHITELIST:
        (claude / filename).write_text(f"# adapter:{filename}\n", encoding="utf-8")
    monkeypatch.setattr(
        workspace_module,
        "_supervisor_source_roots",
        lambda: {"shared-core": core, "codex-adapter": codex, "claude-adapter": claude},
    )

    snapshot = workspace_module.capture_supervisor_source_snapshot()

    assert snapshot["status"] == "degraded"
    assert snapshot["files"]["codex-adapter/supervisor-finalize.ps1"]["status"] == "missing"
    assert workspace_module.validated_supervisor_source_snapshot_hash(snapshot) is None


def test_source_snapshot_rejects_reparse_without_reading_target(tmp_path, monkeypatch) -> None:
    core = tmp_path / "core"
    codex = tmp_path / "codex"
    claude = tmp_path / "claude"
    core.mkdir()
    codex.mkdir()
    claude.mkdir()
    for relative in workspace_module._CORE_SOURCE_WHITELIST:
        path = core / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"safe:{relative}\n", encoding="utf-8")
    for filename in workspace_module._CODEX_ADAPTER_WHITELIST:
        (codex / filename).write_text(f"# adapter:{filename}\n", encoding="utf-8")
    for filename in workspace_module._CLAUDE_ADAPTER_WHITELIST:
        (claude / filename).write_text(f"# adapter:{filename}\n", encoding="utf-8")
    external = tmp_path / "external-secret.py"
    external.write_text("must-not-be-read\n", encoding="utf-8")
    linked = core / "supervisor_core" / "cli.py"
    linked.unlink()
    try:
        os.symlink(external, linked)
    except (OSError, NotImplementedError):
        linked.write_text("must-not-be-read\n", encoding="utf-8")
        real_reparse_check = workspace_module._is_reparse_point
        monkeypatch.setattr(
            workspace_module,
            "_is_reparse_point",
            lambda path: Path(path) == linked or real_reparse_check(path),
        )
    monkeypatch.setattr(
        workspace_module,
        "_supervisor_source_roots",
        lambda: {"shared-core": core, "codex-adapter": codex, "claude-adapter": claude},
    )

    snapshot = workspace_module.capture_supervisor_source_snapshot()

    assert snapshot["status"] == "degraded"
    assert snapshot["files"]["shared-core/supervisor_core/cli.py"]["status"] == "rejected-reparse"
    assert "must-not-be-read" not in json.dumps(snapshot)


def test_gate_binds_source_snapshot_and_source_change_blocks_old_evidence(tmp_path, capsys, monkeypatch) -> None:
    first_snapshot = _source_snapshot("a")
    second_snapshot = _source_snapshot("b")
    monkeypatch.setattr(
        lifecycle_module.workspace_module,
        "capture_supervisor_source_snapshot",
        lambda: first_snapshot,
    )
    install_home = tmp_path / "install-home"
    registry_path = install_home / ".agent-supervisor" / "trusted-executables.json"
    registry_path.parent.mkdir(parents=True)
    trusted_python = Path(sys.executable).resolve(strict=True)
    gate_command = [str(trusted_python), "-c", "print('ok')"]
    registry_path.write_text(
        json.dumps({
            "contract": "TrustedExecutableRegistry/v1",
            "entries": {
                "python": {
                    "kind": "local",
                    "path": str(trusted_python),
                    "sha256": sha256_file(trusted_python),
                    "allowed_argv_sha256": [
                        trusted_command_approval_sha256(gate_command)
                    ],
                }
            },
            "generated_at": "2026-08-24T00:00:00Z",
        }, sort_keys=True),
        encoding="utf-8",
    )
    monkeypatch.setenv("AGENT_SUPERVISOR_INSTALL_HOME", str(install_home))
    common, state_file = _start(tmp_path, capsys)
    state = json.loads(state_file.read_text(encoding="utf-8"))
    criterion_id = state["goal"]["acceptance_criteria"][0]["criterion_id"]
    state["supervisor_source_snapshot"] = first_snapshot
    state["quality_profile"] = {
        "global_gates": [],
        "common_gates": [{"id": "gate.source", "command": gate_command}],
    }
    state_file.write_text(json.dumps(state), encoding="utf-8")
    request = json.dumps({"record": {
        "gate_id": "gate.source",
        "criterion_id": criterion_id,
        "evidence_id": "source-evidence",
    }})

    assert main(["event", *common, "--event-type", "gate_run", "--data-json", request]) == 0
    execution = json.loads(capsys.readouterr().out)
    persisted = json.loads(state_file.read_text(encoding="utf-8"))
    assert execution["source_snapshot_hash"] == first_snapshot["snapshot_sha256"]
    assert persisted["evidence"][0]["source_snapshot_hash"] == first_snapshot["snapshot_sha256"]
    assert persisted["evidence"][0]["collector"] == "supervisor-core"
    assert persisted["evidence"][0]["collector_responsibility_group"] == "trusted-core-gate-execution"
    assert persisted["evidence"][0]["collector_identity_assurance"] == "core-executed-gate"
    assert persisted["evidence"][0]["collector_completion_eligible"] is True

    monkeypatch.setattr(
        lifecycle_module.workspace_module,
        "capture_supervisor_source_snapshot",
        lambda: second_snapshot,
    )
    assert main(["event", *common, "--event-type", "gate_run", "--data-json", request]) == 4
    degraded = json.loads(capsys.readouterr().out)
    persisted = json.loads(state_file.read_text(encoding="utf-8"))
    assert degraded["error"] == "SupervisorSourceSnapshotMismatch"
    assert persisted["health"] == "degraded"
    assert len(persisted["evidence"]) == 1
    events = [json.loads(line) for line in state_file.with_name("events.jsonl").read_text(encoding="utf-8").splitlines()]
    mismatch = [event for event in events if event.get("event_type") == "supervisor_source_snapshot_mismatch"][-1]
    assert mismatch["expected_snapshot_sha256"] == first_snapshot["snapshot_sha256"]
    assert mismatch["observed_snapshot_sha256"] == second_snapshot["snapshot_sha256"]


def test_hook_exception_persists_degraded_adapter_health_and_returns_4(tmp_path, capsys, monkeypatch) -> None:
    prompt = "private prompt must not be persisted"
    payload = {
        "session_id": "degraded-hook-session",
        "cwd": str(tmp_path),
        "prompt": prompt,
        "hook_event_name": "UserPromptSubmit",
    }
    monkeypatch.setattr(cli_module.sys, "stdin", io.StringIO(json.dumps(payload)))
    monkeypatch.setattr(cli_module, "read_quality_profile", lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("boom")))

    assert main(["hook", "--runtime", "claude", "--event", "UserPromptSubmit"]) == 4
    response = json.loads(capsys.readouterr().out)
    assert response["agent_supervisor"]["health"] == "degraded"
    health_file = tmp_path / ".agent-supervisor" / "adapter-health.json"
    assert health_file.is_file()
    persisted = health_file.read_text(encoding="utf-8")
    assert json.loads(persisted)["health"] == "degraded"
    assert prompt not in persisted
    assert "boom" not in persisted


def test_pretool_write_paths_require_canonical_matching_active_lease(tmp_path) -> None:
    allowed = tmp_path / "src" / "allowed"
    allowed.mkdir(parents=True)
    state = {
        "workspace": str(tmp_path),
        "goal": {
            "goal_id": "goal-1", "version": 1, "t3_action_authorizations": [],
            "scope": {"in": ["**"], "out": []},
        },
        "tasks": [{
            "task_id": "task-1",
            "goal_id": "goal-1",
            "goal_version": 1,
            "lease_id": "lease-1",
            "lease_status": "active",
            "owner": "worker-a",
            "responsibility_group": "implementation",
            "allowed_paths": ["src/allowed/**"],
        }],
    }

    allowed_result = cli_module._pretool_policy(
        state, tool_name="Write", tool_input={"file_path": str(allowed / "new.py")}, actor="worker-a"
    )
    assert allowed_result["deny"] is False

    for unsafe in (
        str(tmp_path / "outside.py"),
        "src/allowed/../outside.py",
        str(tmp_path.parent / "escaped.py"),
    ):
        denied = cli_module._pretool_policy(
            state, tool_name="Edit", tool_input={"file_path": unsafe}, actor="worker-a"
        )
        assert denied["deny"] is True
        assert denied["category"] == "write-lease"

    wrong_owner = cli_module._pretool_policy(
        state, tool_name="Write", tool_input={"file_path": str(allowed / "new.py")}, actor="worker-b"
    )
    assert wrong_owner["deny"] is True


def test_t3_command_is_denied_until_goal_contains_exact_action_hash() -> None:
    command = "git push --force origin main"
    state = {"workspace": ".", "tasks": [], "goal": {"t3_action_authorizations": []}}
    denied = cli_module._pretool_policy(
        state, tool_name="Bash", tool_input={"command": command}, actor="worker-a"
    )
    assert denied["deny"] is True
    assert denied["category"] == "force-push"
    assert denied["action_sha256"] == sha256_text(command)
    assert command not in json.dumps(denied)

    granting_request_sha256 = "b" * 64
    state["goal"]["t3_action_authorizations"] = [{
        "action_sha256": denied["action_sha256"],
        "request_sha256": granting_request_sha256,
    }]
    approved = cli_module._pretool_policy(
        state, tool_name="Bash", tool_input={"command": command}, actor="worker-a"
    )
    assert approved["deny"] is False
    assert approved["action_sha256"] == denied["action_sha256"]
    assert approved["granting_request_sha256"] == granting_request_sha256

    state["goal"]["t3_action_authorizations"] = [denied["action_sha256"]]
    legacy = cli_module._pretool_policy(
        state, tool_name="Bash", tool_input={"command": command}, actor="worker-a"
    )
    assert legacy["deny"] is True

    state["goal"]["t3_action_authorizations"] = [{
        "action_sha256": denied["action_sha256"].upper(),
        "request_sha256": granting_request_sha256,
    }]
    noncanonical = cli_module._pretool_policy(
        state, tool_name="Bash", tool_input={"command": command}, actor="worker-a"
    )
    assert noncanonical["deny"] is True


@pytest.mark.parametrize(
    "command, category",
    [
        ("rm -r build", "recursive-delete"),
        ("Remove-Item -LiteralPath build -Recurse", "recursive-delete"),
        ("npx prisma migrate deploy", "db-migration"),
        ("vercel --prod", "deploy"),
        ("gh secret set TOKEN", "secret-mutation"),
        ("stripe refunds create", "billing"),
        ("resend email send", "mail-send"),
        ("binance order buy", "money-trade"),
    ],
)
def test_t3_command_categories_are_hashed_and_denied(command, category) -> None:
    result = cli_module._pretool_policy(
        {"workspace": ".", "tasks": [], "goal": {"t3_action_authorizations": []}},
        tool_name="Bash",
        tool_input={"command": command},
        actor="worker-a",
    )
    assert result["deny"] is True
    assert result["category"] == category
    assert result["action_sha256"] == sha256_text(command)
    assert command not in json.dumps(result)


def test_goal_requires_explicit_hash_bound_t3_authorization() -> None:
    approved = "a" * 64
    message = f"deploy after review\nSUPERVISOR-APPROVE-T3: {approved}\nSUPERVISOR-APPROVE-T3: not-a-hash"
    assert build_goal(
        message,
        change_mode="replace",
    )["t3_action_authorizations"] == []
    goal = build_goal(
        message,
        change_mode="replace",
        trusted_authorizations={
            "request_sha256": sha256_text(message),
            "waiver_criterion_ids": [],
            "t3_action_sha256s": [approved],
        },
    )
    assert goal["t3_action_authorizations"] == [{
        "action_sha256": approved,
        "request_sha256": sha256_text(message),
    }]

    continued = build_goal("continue", change_mode="continue", previous_goal=goal)
    assert continued["t3_action_authorizations"] == goal["t3_action_authorizations"]
    replaced = build_goal("replace", change_mode="replace", previous_goal=continued)
    assert replaced["t3_action_authorizations"] == []


def test_manual_specialized_no_longer_bypasses_intent_invocation_coverage() -> None:
    text = "perform specialist review"
    state = {
        "intents": [{
            "intent_id": "intent-1",
            "text": text,
            "domain": "review",
            "status": "covered",
            "reason": "claimed manual review",
            "method": "manual-specialized",
            "capability_ids": [],
        }],
        "intent_manifest": [{"intent_id": "intent-1", "text_sha256": sha256_text(text), "domain": "review"}],
    }
    code, artifact = _evaluate_builtin_gate(state, [], "intent-coverage", finalize_internal=False)
    assert code == 2
    assert any(
        "no completion-trusted correlated invocation" in failure
        for failure in artifact["failures"]
    )


@pytest.mark.parametrize(
    "message, expected_fragments",
    [
        ("修复接口，补充测试", ["修复接口", "补充测试"]),
        ("Fix auth, add tests", ["Fix auth", "add tests"]),
        ("1. Fix auth 2. Add tests", ["Fix auth", "Add tests"]),
        ("Fix auth and then add tests", ["Fix auth", "add tests"]),
        ("修复接口并且补充测试", ["修复接口", "补充测试"]),
    ],
)
def test_split_intents_handles_commas_numbering_and_obvious_conjunctions(message, expected_fragments) -> None:
    texts = {row["text"] for row in split_intents(message)}
    assert set(expected_fragments).issubset(texts)


def test_query_output_is_confined_to_session_handoff_directory(tmp_path, capsys, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    session = "query-session"
    common, _ = _start(tmp_path, capsys, session=session)
    allowed_root = tmp_path / ".agent-supervisor" / "handoffs" / sha256_text(session)
    allowed = allowed_root / "latest.md"

    assert main(["query", *common, "--format", "handoff", "--output", str(allowed)]) == 0
    capsys.readouterr()
    assert allowed.is_file()

    for escaped in (
        tmp_path / "outside.md",
        Path(".agent-supervisor") / "handoffs" / sha256_text(session) / ".." / "escaped.md",
        Path("..") / "escaped.md",
    ):
        assert main(["query", *common, "--format", "handoff", "--output", str(escaped)]) == 64
        capsys.readouterr()
    assert not (tmp_path / "outside.md").exists()
    assert not (tmp_path / ".agent-supervisor" / "handoffs" / "escaped.md").exists()


def test_query_output_rejects_reparse_parent(tmp_path, capsys, monkeypatch) -> None:
    session = "query-reparse-session"
    common, _ = _start(tmp_path, capsys, session=session)
    allowed_root = tmp_path / ".agent-supervisor" / "handoffs" / sha256_text(session)
    allowed_root.mkdir(parents=True)
    external = tmp_path / "external"
    external.mkdir()
    linked = allowed_root / "linked"
    try:
        os.symlink(external, linked, target_is_directory=True)
    except (OSError, NotImplementedError):
        linked.mkdir()
        real_reparse_check = workspace_module._is_reparse_point
        monkeypatch.setattr(
            workspace_module,
            "_is_reparse_point",
            lambda path: Path(path) == linked or real_reparse_check(path),
        )

    assert main(["query", *common, "--format", "handoff", "--output", str(linked / "latest.md")]) == 64
    capsys.readouterr()
    assert not (external / "latest.md").exists()
