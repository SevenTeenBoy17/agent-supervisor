from __future__ import annotations

import base64
import json
import hashlib
import os
import runpy
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from supervisor_core.workspace import capture_workspace_snapshot, workspace_delta


ROOT = Path(__file__).resolve().parents[1]


def _resolve_adapter_roots() -> tuple[Path, Path]:
    review_bundle = ROOT.parent
    review_bundle_mode = (review_bundle / "REVIEW_MANIFEST.json").is_file()
    configured = os.environ.get("AGENT_SUPERVISOR_INSTALL_HOME")
    if review_bundle_mode:
        codex_root = review_bundle / "global-codex"
        claude_root = review_bundle / "global-claude"
    else:
        if configured:
            install_home = Path(configured).resolve()
        elif ROOT.name == ".agent-supervisor":
            install_home = ROOT.parent
        else:
            install_home = Path.home()
        codex_root = install_home / ".codex" / "skills" / "dev-supervisor"
        claude_root = install_home / ".claude" / "skills" / "supervisor"
    root_exists = (codex_root.exists(), claude_root.exists())
    installation_expected = review_bundle_mode or bool(configured)
    if not any(root_exists):
        if not installation_expected:
            pytest.skip(
                "global Claude/Codex adapters are not installed on this host",
                allow_module_level=True,
            )
        raise RuntimeError(
            f"expected adapter installation unavailable: {(codex_root, claude_root)}"
        )
    if not all(root_exists):
        raise RuntimeError(
            f"partial adapter installation: {(codex_root, claude_root)}"
        )
    if not (codex_root / "scripts" / "supervisor-bootstrap.ps1").is_file():
        raise RuntimeError(f"Codex adapter under test is missing: {codex_root}")
    if not (claude_root / "scripts" / "sup-v3-hook.py").is_file():
        raise RuntimeError(f"Claude adapter under test is missing: {claude_root}")
    return codex_root, claude_root


CODEX_ROOT, CLAUDE_ROOT = _resolve_adapter_roots()
CODEX_SCRIPTS = CODEX_ROOT / "scripts"
CODEX_ADAPTER_FILES = (
    "codex-supervisor-hook.py",
    "supervisor-bootstrap.ps1",
    "supervisor-core.ps1",
    "supervisor-event.ps1",
    "supervisor-finalize.ps1",
    "supervisor-gate.ps1",
    "supervisor-handoff.ps1",
    "supervisor-record.ps1",
    "supervisor-turn-ended.ps1",
    "supervisor-validate.ps1",
)
CLAUDE_ADAPTER_FILES = ("sup-v3-hook.py", "sup-selftest.py", "sup-discover.py")


@pytest.fixture(autouse=True)
def _isolate_inherited_git_repository(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
        monkeypatch.delenv(name, raising=False)


def test_unconfigured_missing_adapter_roots_skip_but_expected_or_partial_fail(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    empty_home = tmp_path / "empty-home"
    empty_home.mkdir()
    monkeypatch.setattr(sys.modules[__name__], "ROOT", tmp_path / "shared-core")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: empty_home))
    monkeypatch.delenv("AGENT_SUPERVISOR_INSTALL_HOME", raising=False)

    with pytest.raises(pytest.skip.Exception):
        _resolve_adapter_roots()

    configured_home = tmp_path / "configured-home"
    monkeypatch.setenv("AGENT_SUPERVISOR_INSTALL_HOME", str(configured_home))
    with pytest.raises(RuntimeError, match="expected adapter installation unavailable"):
        _resolve_adapter_roots()

    monkeypatch.delenv("AGENT_SUPERVISOR_INSTALL_HOME")
    (empty_home / ".codex" / "skills" / "dev-supervisor").mkdir(parents=True)
    with pytest.raises(RuntimeError, match="partial adapter installation"):
        _resolve_adapter_roots()


def _hermetic_adapter_env(home: Path, *, session_id: str | None) -> dict[str, str]:
    codex_target = home / ".codex" / "skills" / "dev-supervisor" / "scripts"
    claude_target = home / ".claude" / "skills" / "supervisor" / "scripts"
    codex_target.mkdir(parents=True)
    claude_target.mkdir(parents=True)
    for filename in CODEX_ADAPTER_FILES:
        shutil.copy2(CODEX_ROOT / "scripts" / filename, codex_target / filename)
    for filename in CLAUDE_ADAPTER_FILES:
        shutil.copy2(CLAUDE_ROOT / "scripts" / filename, claude_target / filename)
    pointer = home / "active-version.json"
    pointer.write_text(json.dumps({
        "contract": "ActiveVersionPointer/v3",
        "active": {"version": "test-source", "path": str(ROOT)},
        "previous": {"version": "none", "path": str(ROOT)},
    }), encoding="utf-8")
    env = os.environ.copy()
    for key in (
        "AGENT_SUPERVISOR_ACTIVE_POINTER",
        "AGENT_SUPERVISOR_HOME",
        "AGENT_SUPERVISOR_INSTALL_HOME",
        "AGENT_SUPERVISOR_RELEASE_ROOT",
        "CODEX_THREAD_ID",
        "CLAUDE_SESSION_ID",
        "GIT_DIR",
        "GIT_INDEX_FILE",
        "GIT_WORK_TREE",
        "PYTHONPATH",
    ):
        env.pop(key, None)
    env.update({
        "USERPROFILE": str(home),
        "HOME": str(home),
        "AGENT_SUPERVISOR_INSTALL_HOME": str(home),
        "AGENT_SUPERVISOR_ACTIVE_POINTER": str(pointer),
        "AGENT_SUPERVISOR_RELEASE_ROOT": str(ROOT),
    })
    if session_id is not None:
        env["CODEX_THREAD_ID"] = session_id
    return env


def _git_fixture_env() -> dict[str, str]:
    env = os.environ.copy()
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
        env.pop(name, None)
    return env


def _trusted_quality_controls() -> dict:
    return {
        "completion_policy": {
            "binary_only": True,
            "model_self_score_is_evidence": False,
            "validator_error_terminal": "degraded",
            "allowed_terminal_states": ["complete", "incomplete", "blocked", "user-waived"],
            "complete_requires_all_applicable_gates": True,
            "unresolved_p0_p1_blocks_complete": True,
        },
        "test_integrity": {
            "separate_review_required_for": ["assertion changed with implementation"],
            "green_tests_alone_are_sufficient": False,
        },
        "review": {
            "implementer_and_reviewer_groups_must_differ": True,
            "required_verdicts": ["APPROVE", "REQUEST_CHANGES", "NEEDS_DISCUSSION"],
            "record_must_bind": [
                "actor", "responsibility_group", "base", "head", "diff_hash", "rerun_evidence",
                "implementer_invocation_id", "reviewer_invocation_id", "actor_identity_assurance",
            ],
        },
    }


def _write_config_schemas(supervisor_dir: Path) -> tuple[str, str]:
    schemas = supervisor_dir / "schemas"
    schemas.mkdir(parents=True, exist_ok=True)
    project_schema = schemas / "project.schema.json"
    quality_schema = schemas / "quality.schema.json"
    project_schema.write_text(json.dumps({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["$schema", "project_id", "supervisor_scope"],
        "properties": {
            "$schema": {"type": "string", "minLength": 1},
            "project_id": {"type": "string", "minLength": 1},
            "quality_profile": {"type": "string"},
            "supervisor_scope": {"type": "object"},
        },
        "additionalProperties": True,
    }), encoding="utf-8")
    quality_schema.write_text(json.dumps({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["$schema"],
        "properties": {"$schema": {"type": "string", "minLength": 1}},
        "additionalProperties": True,
    }), encoding="utf-8")
    return "./schemas/project.schema.json", "./schemas/quality.schema.json"


def _powershell() -> str:
    executable = shutil.which("pwsh") or shutil.which("powershell")
    if not executable:
        pytest.skip("PowerShell is unavailable")
    return executable


def _run_script(
    script: str,
    arguments: list[str],
    *,
    env: dict[str, str],
    expected: int = 0,
) -> dict:
    completed = subprocess.run(
        [_powershell(), "-NoLogo", "-NoProfile", "-File", str(CODEX_SCRIPTS / script), *arguments],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert completed.returncode == expected, completed.stdout + completed.stderr
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    assert lines, f"{script} did not emit JSON"
    return json.loads("\n".join(lines))


def _write_record(path: Path, record: dict) -> None:
    path.write_text(json.dumps({"record": record}, ensure_ascii=False), encoding="utf-8")


def test_installed_ledger_template_is_schema_valid():
    template = json.loads((CODEX_ROOT / "templates" / "ledger.template.json").read_text(encoding="utf-8"))
    schema = json.loads((CODEX_ROOT / "templates" / "ledger.schema.json").read_text(encoding="utf-8"))

    Draft202012Validator(schema).validate(template)


def test_powershell_thin_adapters_complete_with_explicit_audit_without_overclaiming_host_identity(tmp_path):
    workspace = tmp_path / "Codex 包装器 workspace"
    supervisor_dir = workspace / ".agent-supervisor"
    supervisor_dir.mkdir(parents=True)
    project_file = supervisor_dir / "project.json"
    quality_file = supervisor_dir / "quality.json"
    project_schema, quality_schema = _write_config_schemas(supervisor_dir)
    project_file.write_text(json.dumps({
        "$schema": project_schema,
        "project_id": "codex-wrapper-e2e",
        "quality_profile": "quality.json",
        "supervisor_scope": {
            "allowed_change_globs": ["config.json", ".agent-supervisor/**"],
            "out_of_scope_globs": ["src/**"],
        },
    }), encoding="utf-8")
    quality_file.write_text(json.dumps({
        "$schema": quality_schema,
        **_trusted_quality_controls(),
        "global_gates": ["gate.wrapper"],
        "common_gates": [{
            "id": "gate.wrapper",
            "command": [os.fspath(Path(os.sys.executable)), "-c", "print('WRAPPER_GATE_PASS')"],
        }],
        "domains": {"config/agent": {"required_gates": ["gate.wrapper"]}},
        "profiles": {"config_agent": {"applies_to": ["config.json"], "gates": []}},
    }), encoding="utf-8")
    (workspace / "config.json").write_text('{"version":1}\n', encoding="utf-8")
    git_env = _git_fixture_env()
    subprocess.run(["git", "init", "-q", str(workspace)], check=True, env=git_env)
    subprocess.run(["git", "-C", str(workspace), "config", "user.email", "test@example.invalid"], check=True, env=git_env)
    subprocess.run(["git", "-C", str(workspace), "config", "user.name", "Supervisor Wrapper E2E"], check=True, env=git_env)
    subprocess.run([
        "git", "-C", str(workspace), "add",
        ".agent-supervisor/project.json", ".agent-supervisor/quality.json", "config.json",
    ], check=True, env=git_env)
    subprocess.run(["git", "-C", str(workspace), "commit", "-qm", "baseline"], check=True, env=git_env)

    fake_home = tmp_path / "isolated-home"
    fake_home.mkdir()
    env = _hermetic_adapter_env(fake_home, session_id="wrapper-session")
    env["AGENT_SUPERVISOR_ATTESTATION_KEY_FILE"] = str(tmp_path / "attestation.key")
    common = [
        "-Workspace", str(workspace), "-SessionId", "wrapper-session",
        "-RoundId", "wrapper-round",
    ]

    started = _run_script(
        "supervisor-bootstrap.ps1",
        [*common, "-Message", "实现并验证配置监工闭环", "-ChangeMode", "replace", "-ExecutionMode", "enforce"],
        env=env,
    )
    state_file = Path(started["state_file"])
    state = json.loads(state_file.read_text(encoding="utf-8"))
    goal = state["goal"]
    goal_id = goal["goal_id"]
    goal_version = goal["version"]
    criterion_ids = [row["criterion_id"] for row in goal["acceptance_criteria"]]
    intent_ids = [row["intent_id"] for row in state["intents"]]
    baseline = state["workspace_baseline"]

    (workspace / "config.json").write_text('{"version":3}\n', encoding="utf-8")
    delta = workspace_delta(baseline, capture_workspace_snapshot(str(workspace), baseline["extra_globs"]))
    records = tmp_path / "records"
    records.mkdir()

    changes_file = records / "changes.json"
    _write_record(changes_file, {
        "files": delta["files"], "base": delta["base"], "head": delta["head"],
        "diff_hash": delta["diff_hash"], "domains": ["config/agent"],
        "implementer": "codex-worker", "implementer_responsibility_group": "implementation",
        "implementer_invocation_id": "invocation-wrapper",
        "test_changes": {},
    })
    _run_script(
        "supervisor-record.ps1",
        [*common, "-RecordType", "changes", "-RecordFile", str(changes_file), "-Actor", "codex-worker"],
        env=env,
    )

    evidence_ids = []
    for index, criterion_id in enumerate(criterion_ids, start=1):
        evidence_id = f"evidence-wrapper-{index}"
        evidence_ids.append(evidence_id)
        gate = _run_script(
            "supervisor-gate.ps1",
            [*common, "-GateId", "gate.wrapper", "-CriterionId", criterion_id,
             "-CollectorGroup", "independent-quality-review", "-EvidenceId", evidence_id,
             "-Actor", "codex-reviewer"],
            env=env,
        )
        assert gate["exit_code"] == 0

    for index, intent_id in enumerate(intent_ids, start=1):
        intent_file = records / f"intent-{index}.json"
        _write_record(intent_file, {
            "intent_id": intent_id, "status": "covered", "reason": "implemented and independently verified",
            "capability_ids": ["codex-wrapper"], "phase": 1,
        })
        _run_script(
            "supervisor-record.ps1",
            [*common, "-RecordType", "intent", "-RecordFile", str(intent_file), "-Actor", "codex-worker"],
            env=env,
        )
    task_file = records / "task.json"
    _write_record(task_file, {
        "task_id": "task-wrapper", "goal_id": goal_id, "goal_version": goal_version,
        "criterion_ids": criterion_ids, "allowed_paths": ["config.json"],
        "expected_evidence": ["gate.wrapper"], "status": "done", "evidence_ids": evidence_ids,
    })
    spec_file = records / "spec.json"
    _write_record(spec_file, {
        "status": "approved", "hash": "b" * 64, "path": "spec.md",
        "content": "Exact wrapper integration contract",
    })
    for record_type, record_file in (("task", task_file), ("spec", spec_file)):
        _run_script(
            "supervisor-record.ps1",
            [*common, "-RecordType", record_type, "-RecordFile", str(record_file), "-Actor", "codex-worker"],
            env=env,
        )

    for invocation_id, capability, actor in (
        ("invocation-wrapper", "codex-wrapper", "codex-worker"),
        ("review-invocation-wrapper", "independent-reviewer", "codex-reviewer"),
    ):
        for event_type, result in (("invocation_attempt", ""), ("invocation_result", "success")):
            arguments = [
                *common, "-Event", event_type, "-Skill", capability,
                "-InvocationId", invocation_id, "-Actor", actor,
            ]
            if result:
                arguments.extend(["-Result", result])
            _run_script("supervisor-event.ps1", arguments, env=env)

    review_file = records / "review.json"
    _write_record(review_file, {
        "contract": "ReviewRecord/v3", "review_id": "review-wrapper",
        "goal_id": goal_id, "goal_version": goal_version,
        "reviewer": "codex-reviewer", "responsibility_group": "independent-quality-review",
        "implementer": "codex-worker", "base": delta["base"], "head": delta["head"],
        "diff_hash": delta["diff_hash"], "rerun_evidence_ids": evidence_ids,
        "verdict": "APPROVE", "category": "config-agent",
        "implementer_invocation_id": "invocation-wrapper", "reviewer_invocation_id": "review-invocation-wrapper",
        "actor_identity_assurance": "codex-explicit-audit",
    })
    _run_script(
        "supervisor-record.ps1",
        [*common, "-RecordType", "review", "-RecordFile", str(review_file), "-Actor", "codex-reviewer"],
        env=env,
    )

    final = _run_script("supervisor-finalize.ps1", common, env=env)
    assert final["terminal_state"] == "complete"
    persisted = json.loads(state_file.read_text(encoding="utf-8"))
    assert persisted["validation"]["valid"] is True
    assert any("not host lifecycle observation" in warning for warning in persisted["validation"]["warnings"])
    _run_script("supervisor-handoff.ps1", common, env=env)
    handoff_events = [
        json.loads(line)
        for line in state_file.with_name("events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert any(
        event.get("event_type") == "handoff_requested"
        and event.get("summary") == "phase-transition"
        for event in handoff_events
    )
    session_hash = hashlib.sha256(b"wrapper-session").hexdigest()
    assert (workspace / ".agent-supervisor" / "handoffs" / session_hash / "latest.md").is_file()
    assert not (workspace / ".agent-supervisor" / "handoff.md").exists()
    after_handoff = workspace_delta(
        baseline,
        capture_workspace_snapshot(str(workspace), baseline["extra_globs"]),
    )
    assert after_handoff["files"] == delta["files"]
    assert after_handoff["diff_hash"] == delta["diff_hash"]


def test_powershell_finalize_adapter_exposes_blocked_terminal(tmp_path):
    workspace = tmp_path / "Codex blocked workspace"
    supervisor_dir = workspace / ".agent-supervisor"
    supervisor_dir.mkdir(parents=True)
    project_schema, _ = _write_config_schemas(supervisor_dir)
    (supervisor_dir / "project.json").write_text(json.dumps({
        "$schema": project_schema,
        "project_id": "codex-blocked-wrapper-e2e",
        "supervisor_scope": {
            "allowed_change_globs": [".agent-supervisor/**"],
            "out_of_scope_globs": [],
        },
    }), encoding="utf-8")

    fake_home = tmp_path / "isolated-home"
    fake_home.mkdir()
    env = _hermetic_adapter_env(fake_home, session_id="blocked-wrapper-session")
    env["AGENT_SUPERVISOR_ATTESTATION_KEY_FILE"] = str(tmp_path / "attestation.key")
    common = [
        "-Workspace", str(workspace), "-SessionId", "blocked-wrapper-session",
        "-RoundId", "blocked-wrapper-round",
    ]

    started = _run_script(
        "supervisor-bootstrap.ps1",
        [*common, "-Message", "Record a genuine external blocker", "-ChangeMode", "replace", "-ExecutionMode", "observe"],
        env=env,
    )
    final = _run_script("supervisor-finalize.ps1", [*common, "-Blocked"], env=env, expected=3)

    assert final["terminal_state"] == "blocked"
    persisted = json.loads(Path(started["state_file"]).read_text(encoding="utf-8"))
    assert persisted["terminal_state"] == "blocked"


def test_powershell_bootstrap_forwards_structured_goal_and_intents_files(tmp_path):
    workspace = tmp_path / "typed bootstrap workspace"
    supervisor_dir = workspace / ".agent-supervisor"
    schemas = supervisor_dir / "schemas"
    schemas.mkdir(parents=True)
    project_schema = schemas / "project.schema.json"
    project_schema.write_text(json.dumps({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["$schema", "project_id", "supervisor_scope"],
        "properties": {
            "$schema": {"type": "string"},
            "project_id": {"type": "string"},
            "supervisor_scope": {"type": "object"},
        },
        "additionalProperties": False,
    }), encoding="utf-8")
    project_file = supervisor_dir / "project.json"
    project_file.write_text(json.dumps({
        "$schema": "./schemas/project.schema.json",
        "project_id": "typed-bootstrap",
        "supervisor_scope": {"allowed_change_globs": ["config.json"], "out_of_scope_globs": []},
    }), encoding="utf-8")
    goal_file = tmp_path / "goal.json"
    goal_file.write_text(json.dumps({
        "objective": "Implement the typed UI contract",
        "scope": {"in": ["config.json"], "out": ["src/**"]},
        "acceptance_criteria": [{
            "criterion_id": "criterion-ui",
            "description": "UI contract is verified",
            "domain": "ui",
            "expected_evidence": ["goal-output"],
        }],
    }), encoding="utf-8")
    intents_file = tmp_path / "intents.json"
    intents_file.write_text(json.dumps([{
        "intent_id": "intent-ui",
        "text": "Implement the typed UI contract",
        "domain": "ui",
    }]), encoding="utf-8")
    fake_home = tmp_path / "isolated-home"
    fake_home.mkdir()
    env = _hermetic_adapter_env(fake_home, session_id="typed-wrapper-session")
    env["AGENT_SUPERVISOR_ATTESTATION_KEY_FILE"] = str(tmp_path / "attestation.key")
    started = _run_script(
        "supervisor-bootstrap.ps1",
        [
            "-Workspace", str(workspace), "-SessionId", "typed-wrapper-session",
            "-RoundId", "typed-wrapper-round", "-Message", "typed bootstrap",
            "-ChangeMode", "replace", "-ExecutionMode", "observe",
            "-ProjectFile", str(project_file), "-GoalFile", str(goal_file),
            "-IntentsFile", str(intents_file),
        ],
        env=env,
    )
    state = json.loads(Path(started["state_file"]).read_text(encoding="utf-8"))
    assert state["goal"]["objective"] == "Implement the typed UI contract"
    assert state["goal"]["scope"] == {"in": ["config.json"], "out": ["src/**"]}
    assert state["intents"][0]["intent_id"] == "intent-ui"
    assert state["intents"][0]["domain"] == "ui"


def test_powershell_bootstrap_rejects_pid_scoped_session_fallback(tmp_path):
    workspace = tmp_path / "missing session workspace"
    workspace.mkdir()
    fake_home = tmp_path / "isolated-home"
    fake_home.mkdir()
    env = _hermetic_adapter_env(fake_home, session_id=None)
    completed = subprocess.run(
        [
            _powershell(), "-NoLogo", "-NoProfile", "-File",
            str(CODEX_SCRIPTS / "supervisor-bootstrap.ps1"),
            "-Workspace", str(workspace), "-RoundId", "missing-session-round",
            "-Message", "must be stable", "-ChangeMode", "replace",
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert completed.returncode == 64
    assert "stable SessionId" in completed.stderr


def _native_hook_env(home: Path) -> dict[str, str]:
    env = os.environ.copy()
    for key in (
        "AGENT_SUPERVISOR_ACTIVE_POINTER",
        "AGENT_SUPERVISOR_CORE",
        "AGENT_SUPERVISOR_HOME",
        "AGENT_SUPERVISOR_HOOK_TIMEOUT",
        "AGENT_SUPERVISOR_INSTALL_HOME",
        "AGENT_SUPERVISOR_RELEASE_ROOT",
        "CLAUDE_SESSION_ID",
        "CODEX_THREAD_ID",
        "FAKE_CORE_CAPTURE",
        "FAKE_CORE_EXIT",
        "FAKE_CORE_STDOUT_B64",
        "PYTHONPATH",
    ):
        env.pop(key, None)
    env.update({
        "HOME": str(home),
        "USERPROFILE": str(home),
        "PYTHONDONTWRITEBYTECODE": "1",
    })
    return env


def _run_native_hook(
    adapter: Path,
    payload: bytes,
    env: dict[str, str],
    workspace: Path,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, str(adapter), "--event", "SessionStart"],
        cwd=workspace,
        env=env,
        input=payload,
        capture_output=True,
        check=False,
        timeout=10,
    )


def _write_native_fake_core(root: Path) -> None:
    package = root / "supervisor_core"
    package.mkdir(parents=True, exist_ok=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "__main__.py").write_text(
        textwrap.dedent(
            """
            import base64
            import os
            import sys
            from pathlib import Path

            raw = sys.stdin.buffer.read()
            capture = os.environ.get("FAKE_CORE_CAPTURE")
            if capture:
                Path(capture).write_bytes(raw)
            output = os.environ.get("FAKE_CORE_STDOUT_B64")
            if output:
                sys.stdout.buffer.write(base64.b64decode(output))
            raise SystemExit(int(os.environ.get("FAKE_CORE_EXIT", "0")))
            """
        ).lstrip(),
        encoding="utf-8",
    )


def _seed_native_degraded_marker(tmp_path: Path) -> tuple[
    Path, Path, dict[str, str], bytes, Path
]:
    home = tmp_path / "adapter home"
    workspace = tmp_path / "workspace"
    home.mkdir()
    workspace.mkdir()
    adapter = (
        home / ".codex" / "skills" / "dev-supervisor" / "scripts"
        / "codex-supervisor-hook.py"
    )
    adapter.parent.mkdir(parents=True)
    shutil.copy2(CODEX_SCRIPTS / "codex-supervisor-hook.py", adapter)
    env = _native_hook_env(home)
    payload = json.dumps({
        "session_id": "durable-ack-session",
        "cwd": str(workspace),
        "hook_event_name": "SessionStart",
        "source": "startup",
    }).encode("utf-8")
    missing = _run_native_hook(adapter, payload, env, workspace)
    assert missing.returncode == 0
    assert missing.stdout == b"{}"
    markers = list(
        (home / ".agent-supervisor" / "fallback" / "codex" / "markers").glob("*.json")
    )
    assert len(markers) == 1
    _write_native_fake_core(home / ".agent-supervisor")
    return adapter, workspace, env, payload, markers[0]


@pytest.mark.parametrize("exit_code", [0, 2, 3])
def test_native_hook_never_clears_degraded_marker_for_exit_without_durable_ack(
    exit_code: int, tmp_path: Path
) -> None:
    adapter, workspace, env, payload, marker = _seed_native_degraded_marker(tmp_path)
    capture = tmp_path / "forwarded.json"
    env.update({
        "FAKE_CORE_CAPTURE": str(capture),
        "FAKE_CORE_EXIT": str(exit_code),
        "FAKE_CORE_STDOUT_B64": base64.b64encode(b"{}").decode("ascii"),
    })

    completed = _run_native_hook(adapter, payload, env, workspace)

    assert completed.returncode == 0
    assert completed.stdout == b"{}"
    assert marker.is_file()
    forwarded = json.loads(capture.read_text(encoding="utf-8"))
    assert forwarded["_agent_supervisor_adapter"]["degraded_prior"] is True


@pytest.mark.parametrize(
    "response",
    [
        b"not-json",
        b'{"agent_supervisor":{"durable_ack":true}}',
        b'{"agent_supervisor":[]}',
    ],
)
def test_native_hook_rejects_malformed_or_unscoped_durable_ack(
    response: bytes, tmp_path: Path
) -> None:
    adapter, workspace, env, payload, marker = _seed_native_degraded_marker(tmp_path)
    env["FAKE_CORE_STDOUT_B64"] = base64.b64encode(response).decode("ascii")

    completed = _run_native_hook(adapter, payload, env, workspace)

    assert completed.returncode == 0
    assert completed.stdout == response
    assert marker.is_file()


def test_native_hook_clears_marker_only_for_structurally_valid_durable_ack(
    tmp_path: Path,
) -> None:
    adapter, workspace, env, payload, marker = _seed_native_degraded_marker(tmp_path)
    response = b'{"agent_supervisor":{"health":"degraded","durable_ack":true}}'
    env.update({
        "FAKE_CORE_EXIT": "4",
        "FAKE_CORE_STDOUT_B64": base64.b64encode(response).decode("ascii"),
    })

    completed = _run_native_hook(adapter, payload, env, workspace)

    assert completed.returncode == 0
    assert completed.stdout == response
    assert not marker.exists()


def test_python_allowed_roots_ignore_core_selection_environment(tmp_path: Path) -> None:
    powershell = _powershell()
    profile_home = tmp_path / "profile-home"
    profile_home.mkdir()
    known_user_install = profile_home / "AppData" / "Local" / "Programs" / "Python"
    known_user_install.mkdir(parents=True)
    malicious_profile_python = profile_home / "python.exe"
    malicious_profile_python.write_bytes(b"not an interpreter")
    untrusted_roots = [
        tmp_path / "core-home",
        tmp_path / "core-override",
        tmp_path / "release-root",
        tmp_path / "python-roots",
    ]
    for path in untrusted_roots:
        path.mkdir()
    env = os.environ.copy()
    env.update({
        "USERPROFILE": str(profile_home),
        "HOME": str(profile_home),
        "AGENT_SUPERVISOR_HOME": str(untrusted_roots[0]),
        "AGENT_SUPERVISOR_CORE": str(untrusted_roots[1]),
        "AGENT_SUPERVISOR_RELEASE_ROOT": str(untrusted_roots[2]),
        "AGENT_SUPERVISOR_PYTHON_ROOTS": str(untrusted_roots[3]),
    })
    core_script = CODEX_SCRIPTS / "supervisor-core.ps1"
    escaped_script = str(core_script).replace("'", "''")
    escaped_malicious = str(malicious_profile_python).replace("'", "''")
    completed = subprocess.run(
        [
            powershell,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            (
                f". '{escaped_script}'; "
                "$roots = @(Get-AgentSupervisorPythonAllowedRoots); "
                f"$malicious = Resolve-AgentSupervisorTrustedPythonPath -Candidate '{escaped_malicious}' -AllowedRoots $roots -KnownExecutables @(); "
                "$value = [pscustomobject]@{ roots = $roots; malicious = $malicious }; "
                "$value | ConvertTo-Json -Compress"
            ),
        ],
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    result = json.loads(completed.stdout)
    roots = {
        os.path.normcase(str(Path(path).resolve()))
        for path in result["roots"]
    }
    assert os.path.normcase(str(profile_home.resolve())) not in roots
    assert os.path.normcase(str(known_user_install.resolve())) in roots
    assert roots.isdisjoint(
        os.path.normcase(str(path.resolve())) for path in untrusted_roots
    )
    assert result["malicious"] is None


def test_spool_tail_drops_oversized_unterminated_partial_record(tmp_path: Path) -> None:
    hook = runpy.run_path(str(CODEX_SCRIPTS / "codex-supervisor-hook.py"))
    hook_globals = hook["_tail_lines"].__globals__
    hook_globals["MAX_SPOOL_BYTES"] = 32
    spool = tmp_path / "oversized.jsonl"
    spool.write_bytes(b"x" * 128)

    assert hook["_tail_lines"](spool) == []


def test_spool_never_writes_partial_json_when_single_record_exceeds_cap(
    tmp_path: Path,
) -> None:
    hook = runpy.run_path(str(CODEX_SCRIPTS / "codex-supervisor-hook.py"))
    hook_globals = hook["_record_degraded"].__globals__
    hook_globals["MAX_SPOOL_BYTES"] = 64
    hook_globals["_home"] = lambda: tmp_path

    hook["_record_degraded"](
        "Stop",
        {"session_id": "oversized-record", "cwd": str(tmp_path)},
        "core_timeout",
        0,
    )

    spool, marker = hook["_fallback_paths"]("oversized-record")
    assert spool.read_bytes() == b""
    assert json.loads(marker.read_text(encoding="utf-8"))["health"] == "degraded"
