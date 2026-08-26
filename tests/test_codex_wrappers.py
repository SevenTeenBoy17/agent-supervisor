from __future__ import annotations

import base64
import copy
import json
import hashlib
import io
import os
import re
import runpy
import shutil
import site
import subprocess
import sys
import sysconfig
import textwrap
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from supervisor_core.executable_trust import trusted_command_approval_sha256
from supervisor_core import workspace as workspace_module
from supervisor_core.runtime_bundle import build_runtime_bundle, release_identity
from supervisor_core.workspace import capture_workspace_snapshot, workspace_delta


ROOT = Path(__file__).resolve().parents[1]
INSTALLED_ADAPTER_TEST_ENV = "AGENT_SUPERVISOR_TEST_INSTALLED_ADAPTERS"
NATIVE_HOOK_TEST_TIMEOUT_SECONDS = 45


def _trusted_python_path() -> Path:
    return Path(sys.executable).resolve(strict=True)


def _host_executable_path(name: str) -> Path:
    candidate = sys.executable if name == "python" else shutil.which(name)
    assert candidate is not None, f"required host executable is unavailable: {name}"
    return Path(candidate).resolve(strict=True)


def _write_trusted_executable_registry(
    home: Path,
    *,
    names: tuple[str, ...] = ("git", "python"),
) -> Path:
    """Create a strict fixture registry from executables verified on this host."""
    entries: dict[str, dict[str, object]] = {}
    for name in names:
        executable = _host_executable_path(name)
        hasher = hashlib.sha256()
        with executable.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                hasher.update(chunk)
        entry: dict[str, object] = {
            "kind": "local",
            "path": str(executable),
            "sha256": hasher.hexdigest(),
        }
        if name == "python":
            entry["allowed_argv_sha256"] = [
                trusted_command_approval_sha256([
                    str(executable),
                    "-c",
                    "print('WRAPPER_GATE_PASS')",
                ])
            ]
        entries[name] = entry
    registry = {
        "contract": "TrustedExecutableRegistry/v1",
        "entries": entries,
        "generated_at": "2026-08-25T00:00:00Z",
    }
    target = home / ".agent-supervisor" / "trusted-executables.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(registry, separators=(",", ":")),
        encoding="utf-8",
    )
    return target


def _resolve_adapter_roots() -> tuple[Path, Path]:
    review_bundle = ROOT.parent
    review_bundle_mode = (review_bundle / "REVIEW_MANIFEST.json").is_file()
    installed_opt_in = os.environ.get(INSTALLED_ADAPTER_TEST_ENV)
    if installed_opt_in not in {None, "1"}:
        raise RuntimeError(f"{INSTALLED_ADAPTER_TEST_ENV} must be exactly '1' when set")
    configured = os.environ.get("AGENT_SUPERVISOR_INSTALL_HOME")
    if review_bundle_mode:
        codex_root = review_bundle / "global-codex"
        claude_root = review_bundle / "global-claude"
    elif installed_opt_in == "1":
        install_home = Path(configured).resolve() if configured else Path.home().resolve()
        codex_root = install_home / ".codex" / "skills" / "dev-supervisor"
        claude_root = install_home / ".claude" / "skills" / "supervisor"
    else:
        codex_root = ROOT / "integrations" / "codex"
        claude_root = ROOT / "integrations" / "claude"
    root_exists = (codex_root.exists(), claude_root.exists())
    if not any(root_exists):
        raise RuntimeError(
            f"expected adapter sources unavailable: {(codex_root, claude_root)}"
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
    "supervisor-hook.ps1",
    "supervisor-process-job.py",
    "supervisor-record.ps1",
    "supervisor-turn-ended.ps1",
    "supervisor-validate.ps1",
)
CLAUDE_ADAPTER_FILES = ("sup-v3-hook.py", "sup-selftest.py", "sup-discover.py")


@pytest.fixture(autouse=True)
def _isolate_inherited_git_repository(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
        monkeypatch.delenv(name, raising=False)


def test_repository_adapter_sources_are_default_and_installed_sources_require_opt_in(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configured_home = tmp_path / "configured-home"
    monkeypatch.setenv("AGENT_SUPERVISOR_INSTALL_HOME", str(configured_home))
    monkeypatch.delenv(INSTALLED_ADAPTER_TEST_ENV, raising=False)
    assert _resolve_adapter_roots() == (
        ROOT / "integrations" / "codex",
        ROOT / "integrations" / "claude",
    )

    monkeypatch.setenv(INSTALLED_ADAPTER_TEST_ENV, "1")
    with pytest.raises(RuntimeError, match="expected adapter sources unavailable"):
        _resolve_adapter_roots()

    monkeypatch.setenv(INSTALLED_ADAPTER_TEST_ENV, "true")
    with pytest.raises(RuntimeError, match="must be exactly '1'"):
        _resolve_adapter_roots()


def _hermetic_adapter_env(home: Path, *, session_id: str | None) -> dict[str, str]:
    codex_target = home / ".codex" / "skills" / "dev-supervisor" / "scripts"
    claude_target = home / ".claude" / "skills" / "supervisor" / "scripts"
    codex_target.mkdir(parents=True)
    claude_target.mkdir(parents=True)
    (codex_target.parent / "SKILL.md").write_text(
        "---\n"
        "name: dev-supervisor\n"
        "description: Supervisor configuration quality implementation verification blocker UI contract typed bootstrap 监工 验证 实现\n"
        "---\n"
        "# Test Supervisor capability\n",
        encoding="utf-8",
    )
    for filename in CODEX_ADAPTER_FILES:
        shutil.copy2(CODEX_ROOT / "scripts" / filename, codex_target / filename)
    for filename in CLAUDE_ADAPTER_FILES:
        shutil.copy2(CLAUDE_ROOT / "scripts" / filename, claude_target / filename)
    core_target = home / ".agent-supervisor-releases" / "test-source"
    shutil.copytree(ROOT / "supervisor_core", core_target / "supervisor_core")
    shutil.copytree(ROOT / "bin", core_target / "bin")
    shutil.copytree(ROOT / "schemas", core_target / "schemas")
    for filename in ("VERSION", "pyproject.toml"):
        if (ROOT / filename).is_file():
            shutil.copy2(ROOT / filename, core_target / filename)
    bundle = build_runtime_bundle(core_target, "test-source")
    bundle_path = core_target / "runtime" / "supervisor-runtime.zip"
    bundle_path.parent.mkdir(parents=True)
    bundle_path.write_bytes(bundle)
    active_identity = release_identity(
        core_target,
        "test-source",
        "runtime/supervisor-runtime.zip",
        bundle,
    )
    pointer = home / ".agent-supervisor" / "active-version.json"
    pointer.parent.mkdir(parents=True)
    _write_trusted_executable_registry(home)
    pointer.write_text(json.dumps({
        "contract": "ActiveVersionPointer/v4",
        "active": active_identity,
        "previous": None,
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
    scripts_root = CODEX_SCRIPTS
    configured_home = env.get("AGENT_SUPERVISOR_INSTALL_HOME")
    if configured_home:
        installed_scripts = (
            Path(configured_home) / ".codex" / "skills" / "dev-supervisor" / "scripts"
        )
        if (installed_scripts / script).is_file():
            scripts_root = installed_scripts
    completed = subprocess.run(
        [_powershell(), "-NoLogo", "-NoProfile", "-File", str(scripts_root / script), *arguments],
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


def _run_gate_adapter_with_fake_child(
    tmp_path: Path,
    *,
    exit_code: int,
    stdout: str,
    stderr: str,
) -> subprocess.CompletedProcess[str]:
    scripts = tmp_path / "gate-adapter" / "scripts"
    scripts.mkdir(parents=True)
    gate_script = scripts / "supervisor-gate.ps1"
    shutil.copy2(CODEX_SCRIPTS / gate_script.name, gate_script)
    (scripts / "supervisor-event.ps1").write_text(
        textwrap.dedent(
            r"""
            param(
                [string]$Workspace,
                [string]$RoundId,
                [string]$SessionId,
                [string]$Event,
                [string]$Actor,
                [string]$ResponsibilityGroup,
                [string]$DataJson
            )
            [Console]::Out.Write($env:FAKE_GATE_CHILD_STDOUT)
            [Console]::Error.Write($env:FAKE_GATE_CHILD_STDERR)
            exit ([int]$env:FAKE_GATE_CHILD_EXIT)
            """
        ).lstrip(),
        encoding="utf-8",
    )
    env = os.environ.copy()
    env.update({
        "FAKE_GATE_CHILD_EXIT": str(exit_code),
        "FAKE_GATE_CHILD_STDOUT": stdout,
        "FAKE_GATE_CHILD_STDERR": stderr,
    })
    return subprocess.run(
        [
            _powershell(), "-NoLogo", "-NoProfile", "-File", str(gate_script),
            "-GateId", "gate.wrapper", "-CriterionId", "criterion-wrapper",
            "-CollectorGroup", "independent-quality-review",
            "-CollectorInvocationId", "gate-invocation-wrapper",
            "-Workspace", str(tmp_path), "-RoundId", "round-wrapper",
            "-SessionId", "session-wrapper",
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


@pytest.mark.parametrize("exit_code", [1, 4, 7, 125])
def test_gate_adapter_maps_non_contract_child_exit_to_redacted_degraded(
    exit_code: int,
    tmp_path: Path,
) -> None:
    completed = _run_gate_adapter_with_fake_child(
        tmp_path,
        exit_code=exit_code,
        stdout="SENSITIVE_CHILD_STDOUT",
        stderr="SENSITIVE_CHILD_STDERR",
    )

    assert completed.returncode == 4
    assert completed.stdout == ""
    lines = [line for line in completed.stderr.splitlines() if line.strip()]
    assert len(lines) == 1
    failure = json.loads(lines[0])
    assert failure == {
        "status": "degraded",
        "reason": "gate-adapter-failure",
        "child_exit_code": exit_code,
        "message": "Supervisor gate event recording failed; state is degraded.",
    }
    assert "SENSITIVE_CHILD_STDOUT" not in completed.stdout + completed.stderr
    assert "SENSITIVE_CHILD_STDERR" not in completed.stdout + completed.stderr


@pytest.mark.parametrize("exit_code", [0, 2, 3, 64])
def test_gate_adapter_forwards_only_structured_contract_exit_codes(
    exit_code: int,
    tmp_path: Path,
) -> None:
    stdout = '{"status":"contract-result"}\n'
    stderr = "contract-diagnostic\n"
    completed = _run_gate_adapter_with_fake_child(
        tmp_path,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
    )

    assert completed.returncode == exit_code
    if exit_code == 0:
        assert completed.stdout == stdout
        assert completed.stderr == ""
    else:
        assert completed.stdout == ""
        lines = [line for line in completed.stderr.splitlines() if line.strip()]
        assert len(lines) == 1
        assert json.loads(lines[0]) == {
            "status": "degraded",
            "reason": {
                2: "gate-event-incomplete",
                3: "gate-event-blocked",
                64: "gate-event-invalid-state",
            }[exit_code],
            "child_exit_code": exit_code,
            "message": "Supervisor gate event did not complete; captured failure output was suppressed.",
        }
    assert "contract-diagnostic" not in completed.stdout + completed.stderr


def _write_record(path: Path, record: dict) -> None:
    path.write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")


def test_installed_ledger_template_is_schema_valid():
    template = json.loads((CODEX_ROOT / "templates" / "ledger.template.json").read_text(encoding="utf-8"))
    schema = json.loads((CODEX_ROOT / "templates" / "ledger.schema.json").read_text(encoding="utf-8"))

    Draft202012Validator(schema).validate(template)


def test_readme_lists_the_complete_codex_thin_adapter_deployment_set() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    required = {
        "codex-supervisor-hook.py",
        "supervisor-bootstrap.ps1",
        "supervisor-core.ps1",
        "supervisor-event.ps1",
        "supervisor-finalize.ps1",
        "supervisor-gate.ps1",
        "supervisor-handoff.ps1",
        "supervisor-process-job.py",
        "supervisor-record.ps1",
        "supervisor-turn-ended.ps1",
        "supervisor-validate.ps1",
    }
    assert all(f"`{name}`" in readme for name in required)
    assert "shared runtime dependency" in readme


def test_process_job_launcher_is_bound_to_the_trusted_source_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    roots = {
        "shared-core": tmp_path / "shared-core",
        "codex-adapter": tmp_path / "codex-adapter",
        "claude-adapter": tmp_path / "claude-adapter",
    }
    for root in roots.values():
        root.mkdir(parents=True)
    for relative in workspace_module._CORE_SOURCE_WHITELIST:
        source = ROOT / relative
        target = roots["shared-core"] / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    for filename in workspace_module._CODEX_ADAPTER_WHITELIST:
        shutil.copy2(CODEX_SCRIPTS / filename, roots["codex-adapter"] / filename)
    for filename in workspace_module._CLAUDE_ADAPTER_WHITELIST:
        shutil.copy2(
            CLAUDE_ROOT / "scripts" / filename,
            roots["claude-adapter"] / filename,
        )
    monkeypatch.setattr(workspace_module, "_supervisor_source_roots", lambda: roots)

    first = workspace_module.capture_supervisor_source_snapshot()
    launcher_name = "codex-adapter/supervisor-process-job.py"
    launcher = roots["codex-adapter"] / "supervisor-process-job.py"

    assert first["status"] == "healthy"
    assert first["files"][launcher_name] == {
        "status": "hashed",
        "sha256": hashlib.sha256(launcher.read_bytes()).hexdigest(),
        "size": launcher.stat().st_size,
    }
    assert (
        workspace_module.validated_supervisor_source_snapshot_hash(first)
        == first["snapshot_sha256"]
    )

    launcher.write_bytes(launcher.read_bytes() + b"\n# tampered fixture\n")
    tampered = workspace_module.capture_supervisor_source_snapshot()
    assert tampered["status"] == "healthy"
    assert tampered["files"][launcher_name]["sha256"] != first["files"][launcher_name]["sha256"]
    assert tampered["snapshot_sha256"] != first["snapshot_sha256"]

    launcher.unlink()
    missing = workspace_module.capture_supervisor_source_snapshot()
    assert missing["status"] == "degraded"
    assert missing["files"][launcher_name]["status"] == "missing"
    assert workspace_module.validated_supervisor_source_snapshot_hash(missing) is None


def test_core_bridge_returns_the_exact_frozen_stage_zero_bytes() -> None:
    bridge = CODEX_SCRIPTS / "supervisor-core.ps1"
    stage_zero = CODEX_SCRIPTS / "supervisor-process-job.py"
    escaped = str(bridge).replace("'", "''")
    command = (
        "$ErrorActionPreference='Stop';"
        f". '{escaped}';"
        "$encoded=Get-AgentSupervisorContainmentLauncherSource;"
        "if ([string]::IsNullOrWhiteSpace($encoded)) { exit 125 };"
        "[Console]::OpenStandardOutput().Write("
        "[Convert]::FromBase64String($encoded),0,"
        "[Convert]::FromBase64String($encoded).Length)"
    )

    completed = subprocess.run(
        [
            _powershell(),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command,
        ],
        capture_output=True,
        check=False,
        timeout=15,
    )

    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
    assert completed.stdout == stage_zero.read_bytes()


@pytest.mark.parametrize(
    "case",
    [
        "goal-bool-version",
        "criterion-scalar",
        "criterion-bool-required",
        "scope-scalar",
        "task-scalar",
        "task-missing-id",
        "task-bool-version",
        "intent-scalar",
        "intent-bool-phase",
        "invocation-scalar",
        "evidence-scalar",
        "review-scalar",
        "waiver-scalar",
    ],
)
def test_installed_ledger_schema_rejects_malformed_array_items(case: str) -> None:
    template = json.loads(
        (CODEX_ROOT / "templates" / "ledger.template.json").read_text(
            encoding="utf-8"
        )
    )
    schema = json.loads(
        (CODEX_ROOT / "templates" / "ledger.schema.json").read_text(
            encoding="utf-8"
        )
    )
    candidate = copy.deepcopy(template)
    if case == "goal-bool-version":
        candidate["goal"]["version"] = True
    elif case == "criterion-scalar":
        candidate["goal"]["acceptance_criteria"] = [7]
    elif case == "criterion-bool-required":
        candidate["goal"]["acceptance_criteria"][0]["required"] = 1
    elif case == "scope-scalar":
        candidate["goal"]["in_scope"] = [False]
    elif case == "task-scalar":
        candidate["tasks"] = ["not-a-task"]
    elif case == "task-missing-id":
        candidate["tasks"][0].pop("task_id")
    elif case == "task-bool-version":
        candidate["tasks"][0]["goal_version"] = True
    elif case == "intent-scalar":
        candidate["intent_coverage"] = [3]
    elif case == "intent-bool-phase":
        candidate["intent_coverage"][0]["phase"] = False
    elif case == "invocation-scalar":
        candidate["invocations"] = ["not-an-invocation"]
    elif case == "evidence-scalar":
        candidate["evidence"] = [0]
    elif case == "review-scalar":
        candidate["reviews"] = [True]
    elif case == "waiver-scalar":
        candidate["waivers"] = [None]
    else:  # pragma: no cover - parametrization is closed above.
        raise AssertionError(case)

    assert list(Draft202012Validator(schema).iter_errors(candidate)), case


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
            "command": [os.fspath(_trusted_python_path()), "-c", "print('WRAPPER_GATE_PASS')"],
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
        "git_object_format": delta["git_object_format"], "git_binding_status": delta["git_binding_status"],
        "git_binding_source": delta["git_binding_source"], "git_repository_root": delta["git_repository_root"],
        "review_artifact": delta["review_artifact"], "review_artifact_sha256": delta["review_artifact_sha256"],
        "git_diff_sha256": delta["git_diff_sha256"], "workspace_base_sha256": delta["workspace_base_sha256"],
        "workspace_head_sha256": delta["workspace_head_sha256"],
        "test_changes": {},
    })
    _run_script(
        "supervisor-record.ps1",
        [*common, "-RecordType", "changes", "-RecordFile", str(changes_file), "-Actor", "codex-worker"],
        env=env,
    )

    evidence_ids = []
    _run_script(
        "supervisor-event.ps1",
        [*common, "-Event", "invocation_attempt", "-Skill", "independent-gate-runner",
         "-InvocationId", "gate-invocation-wrapper", "-Actor", "codex-gate-runner",
         "-ResponsibilityGroup", "independent-quality-review"],
        env=env,
    )
    for index, criterion_id in enumerate(criterion_ids, start=1):
        evidence_id = f"evidence-wrapper-{index}"
        evidence_ids.append(evidence_id)
        gate = _run_script(
            "supervisor-gate.ps1",
            [*common, "-GateId", "gate.wrapper", "-CriterionId", criterion_id,
             "-CollectorGroup", "independent-quality-review", "-EvidenceId", evidence_id,
             "-CollectorInvocationId", "gate-invocation-wrapper", "-Actor", "codex-gate-runner"],
            env=env,
        )
        assert gate["exit_code"] == 0
    _run_script(
        "supervisor-event.ps1",
        [*common, "-Event", "invocation_result", "-Skill", "independent-gate-runner",
         "-InvocationId", "gate-invocation-wrapper", "-Actor", "codex-gate-runner",
         "-ResponsibilityGroup", "independent-quality-review", "-Result", "success"],
        env=env,
    )

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

    for invocation_id, capability, actor, responsibility_group in (
        ("invocation-wrapper", "codex-wrapper", "codex-worker", "implementation"),
        (
            "review-invocation-wrapper", "independent-reviewer", "codex-reviewer",
            "independent-quality-reviewer",
        ),
    ):
        for event_type, result in (("invocation_attempt", ""), ("invocation_result", "success")):
            arguments = [
                *common, "-Event", event_type, "-Skill", capability,
                "-InvocationId", invocation_id, "-Actor", actor,
                "-ResponsibilityGroup", responsibility_group,
            ]
            if result:
                arguments.extend(["-Result", result])
            _run_script("supervisor-event.ps1", arguments, env=env)

    review_file = records / "review.json"
    _write_record(review_file, {"record": {
        "contract": "ReviewRecord/v3", "review_id": "review-wrapper",
        "goal_id": goal_id, "goal_version": goal_version,
        "reviewer": "codex-reviewer", "reviewer_responsibility_group": "independent-quality-reviewer",
        "implementer": "codex-worker", "implementer_responsibility_group": "implementation",
        "gate_collector": "codex-gate-runner", "gate_collector_responsibility_group": "independent-quality-review",
        "gate_runner_invocation_id": "gate-invocation-wrapper",
        "base": delta["base"], "head": delta["head"],
        "diff_hash": delta["diff_hash"], "rerun_evidence_ids": evidence_ids,
        "git_object_format": delta["git_object_format"], "git_binding_status": delta["git_binding_status"],
        "git_binding_source": delta["git_binding_source"], "git_repository_root": delta["git_repository_root"],
        "review_artifact_sha256": delta["review_artifact_sha256"], "git_diff_sha256": delta["git_diff_sha256"],
        "workspace_base_sha256": delta["workspace_base_sha256"], "workspace_head_sha256": delta["workspace_head_sha256"],
        "evidence_verification": {"status": "VERIFIED", "reviewer": "codex-reviewer", "evidence_ids": evidence_ids},
        "verdict": "APPROVE", "category": "config-agent",
        "implementer_invocation_id": "invocation-wrapper", "reviewer_invocation_id": "review-invocation-wrapper",
    }})
    rejected_review = _run_script(
        "supervisor-event.ps1",
        [*common, "-Event", "review_finalize", "-DataFile", str(review_file), "-Actor", "codex-reviewer"],
        env=env,
        expected=64,
    )
    assert "reviewer lacks a successful trusted invocation" in rejected_review["message"]

    final = _run_script("supervisor-finalize.ps1", common, env=env, expected=2)
    assert final["terminal_state"] == "incomplete"
    persisted = json.loads(state_file.read_text(encoding="utf-8"))
    assert persisted["validation"]["valid"] is False
    assert "changed diff lacks independent ReviewRecord" in persisted["validation"]["errors"]
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
        [*common, "-Message", "Supervisor: record a genuine external blocker", "-ChangeMode", "replace", "-ExecutionMode", "observe"],
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
    persisted = json.dumps(state, ensure_ascii=False)
    assert state["goal"]["objective"].startswith("Complete host request sha256:")
    assert "Implement the typed UI contract" not in persisted
    assert state["prompt_privacy"]["raw_prompt_persisted"] is False
    assert state["intents"][0]["intent_id"] == "intent-ui"
    assert state["intents"][0]["domain"] == "ui"
    assert state["intents"][0]["text"].startswith("Host intent 1 (ui) sha256:")


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


def test_codex_entrypoints_ignore_workspace_and_pythonpath_module_hijacks(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "hostile workspace"
    workspace.mkdir()
    fake_home = tmp_path / "isolated install"
    fake_home.mkdir()
    malicious = workspace / "attacker-pythonpath"
    malicious_core = malicious / "supervisor_core"
    malicious_core.mkdir(parents=True)
    sentinel = tmp_path / "hijack-sentinel"
    side_effect = (
        "from pathlib import Path\n"
        "import os\n"
        "Path(os.environ['SUPERVISOR_HIJACK_SENTINEL']).write_text('ran', encoding='utf-8')\n"
    )
    (malicious / "sitecustomize.py").write_text(side_effect, encoding="utf-8")
    (malicious_core / "__init__.py").write_text(side_effect, encoding="utf-8")
    (malicious_core / "__main__.py").write_text(side_effect, encoding="utf-8")
    workspace_core = workspace / "supervisor_core"
    shutil.copytree(malicious_core, workspace_core)

    env = _hermetic_adapter_env(fake_home, session_id="isolation-session")
    env.update({
        "PYTHONPATH": str(malicious),
        "SUPERVISOR_HIJACK_SENTINEL": str(sentinel),
    })
    started = _run_script(
        "supervisor-bootstrap.ps1",
        [
            "-Workspace", str(workspace),
            "-RoundId", "isolation-round",
            "-Message", "Supervisor configuration quality verification",
            "-ChangeMode", "replace",
        ],
        env=env,
    )
    assert started["namespace"]["round"] == "isolation-round"
    common = [
        "-Workspace", str(workspace),
        "-RoundId", "isolation-round",
        "-SessionId", "isolation-session",
    ]
    _run_script(
        "supervisor-event.ps1",
        [
            *common,
            "-Event", "observation",
            "-Message", "trusted launcher remained isolated",
            "-Actor", "qa-isolation-test",
        ],
        env=env,
    )
    _run_script(
        "supervisor-validate.ps1", [*common, "-Json"], env=env, expected=2
    )
    _run_script("supervisor-finalize.ps1", common, env=env, expected=2)
    handoff = subprocess.run(
        [
            _powershell(), "-NoLogo", "-NoProfile", "-File",
            str(
                fake_home / ".codex" / "skills" / "dev-supervisor" / "scripts"
                / "supervisor-handoff.ps1"
            ),
            *common,
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert handoff.returncode == 0, handoff.stdout + handoff.stderr
    assert not sentinel.exists()

    for script_name in (
        "supervisor-bootstrap.ps1",
        "supervisor-event.ps1",
        "supervisor-validate.ps1",
        "supervisor-finalize.ps1",
        "supervisor-handoff.ps1",
    ):
        source = (CODEX_SCRIPTS / script_name).read_text(encoding="utf-8")
        assert "Resolve-AgentSupervisorTrustedLauncherPath" in source
        assert "'-E'" in source
        assert "'-P'" in source
        assert "'utf8'" in source
        assert "$launcherPath" in source
        assert "-m', 'supervisor_core" not in source


def test_codex_adapters_ignore_environment_core_and_profile_trust_overrides(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "environment trust workspace"
    workspace.mkdir()
    attacker_home = tmp_path / "attacker profile"
    attacker_core = attacker_home / ".agent-supervisor-releases" / "attacker"
    attacker_launcher = attacker_core / "bin" / "agent-supervisor.py"
    attacker_package = attacker_core / "supervisor_core"
    attacker_launcher.parent.mkdir(parents=True)
    attacker_package.mkdir(parents=True)
    sentinel = tmp_path / "environment-core-sentinel"
    malicious_source = (
        "from pathlib import Path\n"
        "import os\n"
        "Path(os.environ['SUPERVISOR_ENV_CORE_SENTINEL']).write_text('ran', encoding='utf-8')\n"
    )
    attacker_launcher.write_text(malicious_source, encoding="utf-8")
    (attacker_package / "__init__.py").write_text("ATTACKER = True\n", encoding="utf-8")
    (attacker_package / "cli.py").write_text(malicious_source, encoding="utf-8")
    (attacker_package / "__main__.py").write_text(malicious_source, encoding="utf-8")
    attacker_bundle = build_runtime_bundle(attacker_core, "attacker")
    attacker_bundle_path = attacker_core / "runtime" / "supervisor-runtime.zip"
    attacker_bundle_path.parent.mkdir(parents=True)
    attacker_bundle_path.write_bytes(attacker_bundle)
    attacker_identity = release_identity(
        attacker_core,
        "attacker",
        "runtime/supervisor-runtime.zip",
        attacker_bundle,
    )
    attacker_pointer = attacker_home / ".agent-supervisor" / "active-version.json"
    attacker_pointer.parent.mkdir(parents=True)
    attacker_pointer.write_text(json.dumps({
        "contract": "ActiveVersionPointer/v4",
        "active": attacker_identity,
        "previous": None,
    }), encoding="utf-8")

    trusted_home = tmp_path / "trusted adapter installation"
    trusted_home.mkdir()
    env = _hermetic_adapter_env(
        trusted_home,
        session_id="environment-trust-session",
    )
    trusted_scripts = (
        trusted_home / ".codex" / "skills" / "dev-supervisor" / "scripts"
    )
    env.update({
        "AGENT_SUPERVISOR_HOME": str(attacker_core),
        "AGENT_SUPERVISOR_CORE": str(attacker_core),
        "AGENT_SUPERVISOR_ACTIVE_POINTER": str(attacker_pointer),
        "AGENT_SUPERVISOR_RELEASE_ROOT": str(attacker_home),
        "AGENT_SUPERVISOR_INSTALL_HOME": str(attacker_home),
        "USERPROFILE": str(attacker_home),
        "HOME": str(attacker_home),
        "SUPERVISOR_ENV_CORE_SENTINEL": str(sentinel),
        "CODEX_THREAD_ID": "environment-trust-session",
    })
    for variable in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONINSPECT"):
        env.pop(variable, None)
    bootstrap = subprocess.run(
        [
            _powershell(), "-NoLogo", "-NoProfile", "-File",
            str(trusted_scripts / "supervisor-bootstrap.ps1"),
            "-Workspace", str(workspace),
            "-RoundId", "environment-trust-round",
            "-Message", "verify adapter anchored trust",
            "-ChangeMode", "replace",
            "-Shadow",
        ],
        cwd=workspace,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert bootstrap.returncode in {0, 2}
    assert not sentinel.exists()

    payload = json.dumps({
        "session_id": "environment-trust-no-round",
        "cwd": str(workspace),
        "hook_event_name": "SessionEnd",
    }).encode("utf-8")
    native = subprocess.run(
        [
            sys.executable, "-E", "-P", "-X", "utf8",
            str(trusted_scripts / "codex-supervisor-hook.py"),
            "--event", "SessionEnd",
        ],
        cwd=workspace,
        env=env,
        input=payload,
        capture_output=True,
        check=False,
        timeout=10,
    )
    assert native.returncode == 0
    assert json.loads(native.stdout.decode("utf-8")) == {}
    assert not sentinel.exists()


def test_windows_process_tree_termination_never_resolves_taskkill_from_path() -> None:
    source = (CODEX_SCRIPTS / "supervisor-core.ps1").read_text(encoding="utf-8")
    assert "[Environment]::SystemDirectory" in source
    assert "taskkill.exe" in source
    assert "$killerInfo.FileName = 'taskkill.exe'" not in source
    assert "Get-Command 'taskkill" not in source


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
        "AGENT_SUPERVISOR_INSTALL_HOME": str(home),
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
    *,
    event: str = "SessionStart",
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            sys.executable,
            "-E",
            "-P",
            "-X",
            "utf8",
            str(adapter),
            "--event",
            event,
        ],
        cwd=workspace,
        env=env,
        input=payload,
        capture_output=True,
        check=False,
        # The production Stop path has a 25-second inner budget plus the serial
        # five-second identity preflight, both startup/stream cleanup budgets,
        # and outer bridge grace. The harness also leaves room for tree cleanup
        # and a degraded marker if that production deadline is exhausted.
        timeout=NATIVE_HOOK_TEST_TIMEOUT_SECONDS,
    )


def test_native_hook_harness_timeout_exceeds_maximum_outer_deadline() -> None:
    hook = runpy.run_path(str(ROOT / "integrations" / "codex" / "scripts" / "codex-supervisor-hook.py"))
    required = (
        hook["_outer_hook_timeout"]("Stop")
        + hook["OUTER_PROCESS_TREE_CLEANUP_SECONDS"]
        + hook["MARKER_LOCK_RETRY_SECONDS"]
    )
    assert NATIVE_HOOK_TEST_TIMEOUT_SECONDS > required


def _write_native_fake_core(
    home: Path,
    *,
    response: bytes = b"{}",
    exit_code: int = 0,
    capture: Path | None = None,
    environment_probe: Path | None = None,
    poisoned_appdata: Path | None = None,
    poisoned_localappdata: Path | None = None,
) -> None:
    root = home / ".agent-supervisor-releases" / "native-fake"
    package = root / "supervisor_core"
    package.mkdir(parents=True, exist_ok=True)
    (package / "__init__.py").write_text("VERSION = 'native-fake'\n", encoding="utf-8")
    encoded_response = base64.b64encode(response).decode("ascii")
    capture_path = str(capture) if capture is not None else ""
    environment_probe_path = str(environment_probe) if environment_probe is not None else ""
    poisoned_appdata_path = str(poisoned_appdata) if poisoned_appdata is not None else ""
    poisoned_localappdata_path = (
        str(poisoned_localappdata) if poisoned_localappdata is not None else ""
    )
    fake_source = textwrap.dedent(
        f"""
            import base64
            import json
            import os
            import sys
            from pathlib import Path

            def main(argv=None):
                raw = sys.stdin.buffer.read()
                capture = {capture_path!r}
                if capture:
                    Path(capture).write_bytes(raw)
                environment_probe = {environment_probe_path!r}
                if environment_probe:
                    Path(environment_probe).write_text(json.dumps({{
                        "names": sorted(os.environ),
                        "appdata_present": bool(os.environ.get("APPDATA")),
                        "localappdata_present": bool(os.environ.get("LOCALAPPDATA")),
                        "appdata_is_poison": os.environ.get("APPDATA") == {poisoned_appdata_path!r},
                        "localappdata_is_poison": os.environ.get("LOCALAPPDATA") == {poisoned_localappdata_path!r},
                    }}, separators=(",", ":")), encoding="utf-8")
                sys.stdout.buffer.write(base64.b64decode({encoded_response!r}))
                return {exit_code!r}
        """
    ).lstrip()
    (package / "cli.py").write_text(fake_source, encoding="utf-8")
    (package / "__main__.py").write_text(
        "from .cli import main\nraise SystemExit(main())\n",
        encoding="utf-8",
    )
    launcher = root / "bin" / "agent-supervisor.py"
    launcher.parent.mkdir(parents=True, exist_ok=True)
    launcher.write_text(
        "from supervisor_core.cli import main\nraise SystemExit(main())\n",
        encoding="utf-8",
    )
    bundle = build_runtime_bundle(root, "native-fake")
    bundle_path = root / "runtime" / "supervisor-runtime.zip"
    bundle_path.parent.mkdir(parents=True)
    bundle_path.write_bytes(bundle)
    active = release_identity(
        root,
        "native-fake",
        "runtime/supervisor-runtime.zip",
        bundle,
    )
    pointer = home / ".agent-supervisor" / "active-version.json"
    pointer.parent.mkdir(parents=True, exist_ok=True)
    pointer.write_text(
        json.dumps({
            "contract": "ActiveVersionPointer/v4",
            "active": active,
            "previous": None,
        }),
        encoding="utf-8",
    )


def test_native_hook_ignores_workspace_and_pythonpath_module_hijacks(
    tmp_path: Path,
) -> None:
    home = tmp_path / "native isolated home"
    workspace = tmp_path / "native hostile workspace"
    adapter = (
        home / ".codex" / "skills" / "dev-supervisor" / "scripts"
        / "codex-supervisor-hook.py"
    )
    workspace.mkdir()
    env = _hermetic_adapter_env(home, session_id="native-isolation-session")

    malicious = workspace / "attacker-pythonpath"
    malicious_core = malicious / "supervisor_core"
    malicious_core.mkdir(parents=True)
    sentinel = tmp_path / "native-hijack-sentinel"
    side_effect = (
        "from pathlib import Path\n"
        "import os\n"
        "Path(os.environ['SUPERVISOR_HIJACK_SENTINEL']).write_text('ran', encoding='utf-8')\n"
    )
    (malicious / "sitecustomize.py").write_text(side_effect, encoding="utf-8")
    (malicious_core / "__init__.py").write_text(side_effect, encoding="utf-8")
    (malicious_core / "__main__.py").write_text(side_effect, encoding="utf-8")
    shutil.copytree(malicious_core, workspace / "supervisor_core")

    env.update({
        "AGENT_SUPERVISOR_HOME": str(ROOT),
        "PYTHONPATH": str(malicious),
        "SUPERVISOR_HIJACK_SENTINEL": str(sentinel),
    })
    capture = tmp_path / "native-event-capture.json"
    expected_response = b'{"native_core_reached":true}'
    _write_native_fake_core(
        home,
        response=expected_response,
        capture=capture,
    )
    payload = json.dumps({
        "session_id": "native-isolation-session",
        "cwd": str(workspace),
        "hook_event_name": "SessionStart",
        "source": "startup",
    }).encode("utf-8")

    official_events = (
        "SessionStart",
        "UserPromptSubmit",
        "PreToolUse",
        "PermissionRequest",
        "PostToolUse",
        "PreCompact",
        "PostCompact",
        "SubagentStart",
        "SubagentStop",
        "Stop",
        "SessionEnd",
    )
    for event in official_events:
        capture.unlink(missing_ok=True)
        event_payload = json.loads(payload.decode("utf-8"))
        event_payload["hook_event_name"] = event
        completed = _run_native_hook(
            adapter,
            json.dumps(event_payload).encode("utf-8"),
            env,
            workspace,
            event=event,
        )
        assert completed.returncode == 0
        assert completed.stdout == expected_response
        assert capture.is_file()
        forwarded = json.loads(capture.read_text(encoding="utf-8"))
        assert forwarded["hook_event_name"] == event
    assert not sentinel.exists()
    source = adapter.read_text(encoding="utf-8")
    assert "_trusted_hook_bridge_source" in source
    assert "_trusted_powershell" in source
    assert '"-EncodedCommand"' not in source
    assert '"-File"' in source
    assert "CreateFileW" in source
    assert "0x00000001" in source
    assert "cwd=install_home" in source
    assert "def _minimal_hook_environment()" in source
    assert "env = _minimal_hook_environment()" in source
    assert "dict(os.environ)" not in source
    assert "os.environ.copy()" not in source


def test_native_hook_child_environment_drops_poison_and_preserves_os_known_folders(
    tmp_path: Path,
) -> None:
    home = tmp_path / "allowlist home"
    workspace = tmp_path / "allowlist workspace"
    workspace.mkdir()
    if os.name != "nt":
        # PowerShell exposes these POSIX profile directories as its safe
        # APPDATA/LOCALAPPDATA equivalents only when they already exist.
        (home / ".config").mkdir(parents=True)
        (home / ".local" / "share").mkdir(parents=True)
    adapter = (
        home / ".codex" / "skills" / "dev-supervisor" / "scripts"
        / "codex-supervisor-hook.py"
    )
    adapter.parent.mkdir(parents=True)
    for filename in (
        "codex-supervisor-hook.py",
        "supervisor-hook.ps1",
        "supervisor-core.ps1",
        "supervisor-process-job.py",
    ):
        shutil.copy2(CODEX_SCRIPTS / filename, adapter.parent / filename)
    _write_trusted_executable_registry(home, names=("python",))
    poison_appdata = tmp_path / "caller appdata"
    poison_localappdata = tmp_path / "caller localappdata"
    poison_appdata.mkdir()
    poison_localappdata.mkdir()
    probe = tmp_path / "environment-probe.json"
    _write_native_fake_core(
        home,
        environment_probe=probe,
        poisoned_appdata=poison_appdata,
        poisoned_localappdata=poison_localappdata,
    )
    env = _native_hook_env(home)
    forbidden = {
        "SYNTHETIC_TOKEN": "sentinel",
        "SYNTHETIC_SECRET": "sentinel",
        "SYNTHETIC_KEY": "sentinel",
        "SYNTHETIC_CREDENTIAL": "sentinel",
        "PSModulePath": str(tmp_path / "attacker modules"),
        "COR_ENABLE_PROFILING": "1",
        "COMPlus_ReadyToRun": "0",
    }
    env.update(forbidden)
    env["APPDATA"] = str(poison_appdata)
    env["LOCALAPPDATA"] = str(poison_localappdata)
    payload = json.dumps({
        "session_id": "environment-allowlist-session",
        "cwd": str(workspace),
        "hook_event_name": "SessionStart",
        "source": "startup",
    }).encode("utf-8")

    completed = _run_native_hook(adapter, payload, env, workspace)

    assert completed.returncode == 0
    assert json.loads(completed.stdout.decode("utf-8")) == {}
    observed = json.loads(probe.read_text(encoding="utf-8"))
    names = set(observed["names"])
    assert names.isdisjoint(forbidden)
    assert not any(name.startswith(("COR_", "COMPlus_")) for name in names)
    assert observed["appdata_present"] is True
    assert observed["localappdata_present"] is True
    assert observed["appdata_is_poison"] is False
    assert observed["localappdata_is_poison"] is False


@pytest.mark.skipif(os.name != "nt", reason="Windows bridge share-lock regression")
def test_native_hook_holds_verified_bridge_files_read_only_until_launch_returns(
    tmp_path: Path,
) -> None:
    home = tmp_path / "locked bridge home"
    _hermetic_adapter_env(home, session_id="locked-bridge-session")
    adapter = (
        home / ".codex" / "skills" / "dev-supervisor" / "scripts"
        / "codex-supervisor-hook.py"
    )
    namespace = runpy.run_path(str(adapter), run_name="locked_bridge_probe")
    core_path = adapter.parent / "supervisor-core.ps1"
    replacement = tmp_path / "replacement.ps1"
    replacement.write_bytes(core_path.read_bytes())

    with namespace["_trusted_hook_bridge_files"]() as (core, hook):
        assert core[1].closed is False
        assert hook[1].closed is False
        with pytest.raises(OSError):
            with core_path.open("ab"):
                pass
        with pytest.raises(OSError):
            os.replace(replacement, core_path)

    assert core[1].closed is True
    assert hook[1].closed is True


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
    for filename in (
        "codex-supervisor-hook.py",
        "supervisor-hook.ps1",
        "supervisor-core.ps1",
        "supervisor-process-job.py",
    ):
        shutil.copy2(CODEX_SCRIPTS / filename, adapter.parent / filename)
    _write_trusted_executable_registry(home, names=("python",))
    env = _native_hook_env(home)
    payload = json.dumps({
        "session_id": "durable-ack-session",
        "cwd": str(workspace),
        "hook_event_name": "SessionStart",
        "source": "startup",
    }).encode("utf-8")
    missing = _run_native_hook(adapter, payload, env, workspace)
    assert missing.returncode == 0
    assert missing.stdout in {b"", b"{}"}
    markers = list(
        (home / ".agent-supervisor" / "fallback" / "codex" / "markers").glob("*.json")
    )
    assert len(markers) == 1
    return adapter, workspace, env, payload, markers[0]


@pytest.mark.parametrize("exit_code", [0, 2, 3])
def test_native_hook_never_clears_degraded_marker_for_exit_without_durable_ack(
    exit_code: int, tmp_path: Path
) -> None:
    adapter, workspace, env, payload, marker = _seed_native_degraded_marker(tmp_path)
    capture = tmp_path / "forwarded.json"
    _write_native_fake_core(
        Path(env["USERPROFILE"]),
        response=b"{}",
        exit_code=exit_code,
        capture=capture,
    )

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
    _write_native_fake_core(Path(env["USERPROFILE"]), response=response)

    completed = _run_native_hook(adapter, payload, env, workspace)

    assert completed.returncode == 0
    assert completed.stdout == response
    assert marker.is_file()


def test_native_hook_clears_marker_only_for_structurally_valid_durable_ack(
    tmp_path: Path,
) -> None:
    adapter, workspace, env, payload, marker = _seed_native_degraded_marker(tmp_path)
    response = b'{"agent_supervisor":{"health":"degraded","durable_ack":true}}'
    _write_native_fake_core(
        Path(env["USERPROFILE"]),
        response=response,
        exit_code=4,
    )

    completed = _run_native_hook(adapter, payload, env, workspace)

    assert completed.returncode == 0
    assert completed.stdout == response
    assert not marker.exists()


def test_python_allowed_roots_ignore_core_selection_environment(tmp_path: Path) -> None:
    if os.name != "nt":
        pytest.skip("Windows trusted-Python path semantics")
    powershell = _powershell()
    profile_home = tmp_path / "profile-home"
    profile_home.mkdir()
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
    assert roots
    assert roots.isdisjoint(
        os.path.normcase(str(path.resolve())) for path in untrusted_roots
    )
    assert result["malicious"] is None


@pytest.mark.parametrize(
    ("scenario", "expected"),
    [
        ("legal-relative-leaf-link", r"C:\trusted\python3.exe"),
        ("broken-link", None),
        ("directory-target", None),
        ("link-chain", None),
        ("resolve-path-erases-link-chain", None),
        ("cross-root", None),
        ("wrong-target-name", None),
    ],
)
def test_trusted_python_leaf_link_resolution_is_deterministic_and_fail_closed(
    tmp_path: Path,
    scenario: str,
    expected: str | None,
) -> None:
    if os.name != "nt":
        pytest.skip("Windows trusted-Python path semantics")
    harness = tmp_path / "trusted-python-link-harness.ps1"
    harness.write_text(
        textwrap.dedent(
            r"""
            param(
                [Parameter(Mandatory = $true)][string]$CoreScript,
                [Parameter(Mandatory = $true)][string]$Scenario
            )
            . $CoreScript

            $candidate = 'C:\trusted\python.exe'
            $allowedRoot = 'C:\trusted'
            $insideTarget = 'C:\trusted\python3.exe'
            $finalTarget = 'C:\trusted\python3.14.exe'
            $outsideTarget = 'C:\outside\python3.exe'
            $wrongNameTarget = 'C:\trusted\not-python.exe'
            $targetValue = switch ($Scenario) {
                'legal-relative-leaf-link' { 'python3.exe' }
                'cross-root' { $outsideTarget }
                'wrong-target-name' { $wrongNameTarget }
                'resolve-path-erases-link-chain' { $insideTarget }
                default { $insideTarget }
            }

            function Test-AgentSupervisorDirectoryChain {
                param([string]$Directory)
                return $true
            }
            function Test-Path {
                param(
                    [string]$LiteralPath,
                    [string]$PathType
                )
                if ($LiteralPath -ieq $candidate) { return $true }
                if ($Scenario -eq 'broken-link' -and $LiteralPath -ieq $insideTarget) {
                    return $false
                }
                if ($Scenario -eq 'directory-target' -and $LiteralPath -ieq $insideTarget) {
                    return ($PathType -ne 'Leaf')
                }
                return $true
            }
            function Resolve-Path {
                param(
                    [string]$LiteralPath,
                    [string]$ErrorAction
                )
                if (
                    $Scenario -eq 'resolve-path-erases-link-chain' -and
                    ($LiteralPath -ieq $candidate -or $LiteralPath -ieq $insideTarget)
                ) {
                    return [pscustomobject]@{ Path = $finalTarget }
                }
                [pscustomobject]@{ Path = $LiteralPath }
            }
            function Get-Item {
                param(
                    [string]$LiteralPath,
                    [switch]$Force,
                    [string]$ErrorAction
                )
                if ($LiteralPath -ieq $candidate) {
                    return [pscustomobject]@{
                        PSIsContainer = $false
                        Attributes = [IO.FileAttributes]::ReparsePoint
                        Target = @($targetValue)
                    }
                }
                $isDirectory = $Scenario -eq 'directory-target' -and $LiteralPath -ieq $insideTarget
                $isLinkChain = (
                    $Scenario -eq 'link-chain' -and $LiteralPath -ieq $insideTarget
                ) -or (
                    $Scenario -eq 'resolve-path-erases-link-chain' -and
                    $LiteralPath -ieq $insideTarget
                )
                return [pscustomobject]@{
                    PSIsContainer = $isDirectory
                    Attributes = if ($isLinkChain) {
                        [IO.FileAttributes]::ReparsePoint
                    } else {
                        [IO.FileAttributes]::Normal
                    }
                }
            }
            function Register-AgentSupervisorVerifiedFileHash {
                param([string]$Path, [hashtable]$Registry)
                return $true
            }

            $result = Resolve-AgentSupervisorTrustedPythonPath `
                -Candidate $candidate `
                -AllowedRoots @($allowedRoot) `
                -KnownExecutables @($candidate)
            [pscustomobject]@{ result = $result } | ConvertTo-Json -Compress
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [
            _powershell(),
            "-NoLogo",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(harness),
            str(CODEX_SCRIPTS / "supervisor-core.ps1"),
            scenario,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert json.loads(completed.stdout)["result"] == expected


def test_spool_tail_drops_oversized_unterminated_partial_record(tmp_path: Path) -> None:
    hook = runpy.run_path(str(CODEX_SCRIPTS / "codex-supervisor-hook.py"))
    hook_globals = hook["_tail_lines"].__globals__
    hook_globals["MAX_SPOOL_BYTES"] = 32
    spool = tmp_path / "oversized.jsonl"
    spool.write_bytes(b"x" * 128)

    assert hook["_tail_lines"](spool) == []


def test_hook_bounds_ingress_and_rechecks_serialized_forwarding() -> None:
    hook = runpy.run_path(
        str(CODEX_SCRIPTS / "codex-supervisor-hook.py"),
        run_name="bounded_hook_ingress",
    )

    class ReadProbe(io.BytesIO):
        requested: int | None = None

        def read(self, size: int = -1) -> bytes:
            self.requested = size
            return super().read(size)

    stream = ReadProbe(b"{}")
    assert hook["_read_bounded_stdin"](stream, maximum=2) == b"{}"
    assert stream.requested == 3
    with pytest.raises(ValueError, match="stdin-too-large"):
        hook["_read_bounded_stdin"](io.BytesIO(b"{}x"), maximum=2)

    forward_globals = hook["_forward"].__globals__
    forward_globals["MAX_STDIN_BYTES"] = 64
    with pytest.raises(ValueError, match="forwarded-stdin-too-large"):
        hook["_forward"](
            "SessionStart",
            {"session_id": "bounded-forward", "value": "x" * 64},
            False,
        )
    assert hook["ADAPTER_VERSION"] == "3.1.6"


def test_hook_oversized_stdin_is_rejected_without_parsing_or_echoing_payload() -> None:
    hook = runpy.run_path(
        str(CODEX_SCRIPTS / "codex-supervisor-hook.py"),
        run_name="privacy_safe_hook_overflow",
    )
    hook_globals = hook["main"].__globals__
    secret = b'{' + b'"private":"' + b'x' * hook["MAX_STDIN_BYTES"] + b'"}'
    captured: dict[str, object] = {}

    def record(event: str, payload: dict, reason: str, input_bytes: int) -> bool:
        captured.update({
            "event": event,
            "payload": payload,
            "reason": reason,
            "input_bytes": input_bytes,
        })
        return True

    hook_globals["sys"] = _ModuleProxy(
        sys,
        stdin=_ModuleProxy(sys.stdin, buffer=io.BytesIO(secret)),
    )
    hook_globals["_record_degraded"] = record
    hook_globals["_emit_fail_open"] = lambda marker_recorded: captured.update({
        "marker_recorded": marker_recorded,
    })
    hook_globals["_parse_payload"] = lambda _raw: pytest.fail(
        "oversized stdin reached JSON parsing"
    )

    assert hook["main"](["--event", "SessionStart"]) == 0
    assert captured == {
        "event": "SessionStart",
        "payload": {},
        "reason": "invalid_input",
        "input_bytes": hook["MAX_STDIN_BYTES"] + 1,
        "marker_recorded": True,
    }
    assert b"private" not in json.dumps(captured, default=str).encode("utf-8")


def test_hook_payload_parser_rejects_ambiguous_and_complex_json_at_boundaries() -> None:
    hook = runpy.run_path(
        str(CODEX_SCRIPTS / "codex-supervisor-hook.py"),
        run_name="strict_hook_payload_boundaries",
    )

    with pytest.raises(ValueError, match="invalid"):
        hook["_parse_payload"](b'{"private":"\xff"}')
    with pytest.raises(ValueError, match="duplicate"):
        hook["_parse_payload"](b'{"session_id":"first","session_id":"second"}')
    with pytest.raises(ValueError, match="duplicate"):
        hook["_parse_payload"](
            br'{"session_id":"first","\u0073ession_id":"second"}'
        )
    for raw in (
        br'{"tool_name":"secret-\ud800"}',
        b'{"value":NaN}',
        b'{"value":Infinity}',
        b'{"value":-Infinity}',
        b'{"value":1e400}',
    ):
        with pytest.raises(ValueError):
            hook["_parse_payload"](raw)
    assert hook["_parse_payload"](
        br'{"value":1e308,"tool_name":"\ud83d\ude80"}'
    ) == {"value": 1e308, "tool_name": "🚀"}

    depth_value: object = 0
    for _ in range(hook["MAX_HOOK_JSON_DEPTH"] - 2):
        depth_value = [depth_value]
    at_depth_limit = json.dumps(
        {"value": depth_value}, separators=(",", ":")
    ).encode("utf-8")
    assert isinstance(hook["_parse_payload"](at_depth_limit), dict)
    depth_value = [depth_value]
    over_depth_limit = json.dumps(
        {"value": depth_value}, separators=(",", ":")
    ).encode("utf-8")
    with pytest.raises(ValueError, match="complexity"):
        hook["_parse_payload"](over_depth_limit)

    boundary_items = hook["MAX_HOOK_JSON_NODES"] - 3
    at_node_limit = json.dumps(
        {"items": [0] * boundary_items}, separators=(",", ":")
    ).encode("utf-8")
    assert len(hook["_parse_payload"](at_node_limit)["items"]) == boundary_items
    over_node_limit = json.dumps(
        {"items": [0] * (boundary_items + 1)}, separators=(",", ":")
    ).encode("utf-8")
    with pytest.raises(ValueError, match="complexity"):
        hook["_parse_payload"](over_node_limit)


def test_invalid_hook_payloads_fail_open_with_empty_metadata_only_record() -> None:
    hook = runpy.run_path(
        str(CODEX_SCRIPTS / "codex-supervisor-hook.py"),
        run_name="privacy_safe_invalid_hook_payloads",
    )
    hook_globals = hook["main"].__globals__
    secret = "adapter-boundary-secret-must-not-persist"
    depth_value: object = secret
    for _ in range(hook["MAX_HOOK_JSON_DEPTH"] - 1):
        depth_value = [depth_value]
    boundary_items = hook["MAX_HOOK_JSON_NODES"] - 2
    cases = {
        "invalid-utf8": b'{"private":"' + secret.encode("ascii") + b'\xff"}',
        "duplicate-key": (
            b'{"private":"'
            + secret.encode("ascii")
            + b'","private":"second"}'
        ),
        "lone-surrogate": (
            b'{"tool_name":"'
            + secret.encode("ascii")
            + br'-\ud800"}'
        ),
        "nonfinite-constant": (
            b'{"session_id":NaN,"private":"'
            + secret.encode("ascii")
            + b'"}'
        ),
        "nonfinite-overflow": (
            b'{"session_id":1e400,"private":"'
            + secret.encode("ascii")
            + b'"}'
        ),
        "over-depth": json.dumps(
            {"value": depth_value}, separators=(",", ":")
        ).encode("utf-8"),
        "over-node": json.dumps(
            {"items": [secret] * boundary_items}, separators=(",", ":")
        ).encode("utf-8"),
    }

    for label, raw in cases.items():
        captured: dict[str, object] = {}

        def record(event: str, payload: dict, reason: str, input_bytes: int) -> bool:
            captured.update({
                "event": event,
                "payload": payload,
                "reason": reason,
                "input_bytes": input_bytes,
            })
            return True

        hook_globals["sys"] = _ModuleProxy(
            sys,
            stdin=_ModuleProxy(sys.stdin, buffer=io.BytesIO(raw)),
        )
        hook_globals["_record_degraded"] = record
        hook_globals["_emit_fail_open"] = lambda marker_recorded: captured.update({
            "marker_recorded": marker_recorded,
        })
        hook_globals["_forward"] = lambda *_args, **_kwargs: pytest.fail(
            f"{label} invalid payload reached forwarding"
        )

        assert hook["main"](["--event", "SessionStart"]) == 0
        assert captured == {
            "event": "SessionStart",
            "payload": {},
            "reason": "invalid_input",
            "input_bytes": len(raw),
            "marker_recorded": True,
        }
        assert secret not in repr(captured)


def test_hook_registry_accepts_only_valid_optional_argv_approvals() -> None:
    hook = runpy.run_path(
        str(CODEX_SCRIPTS / "codex-supervisor-hook.py"),
        run_name="strict_hook_registry",
    )
    entry = {
        "kind": "local",
        "path": str(_trusted_python_path()),
        "sha256": "a" * 64,
        "allowed_argv_sha256": ["b" * 64],
    }

    def encoded(candidate: dict) -> bytes:
        return json.dumps({
            "contract": "TrustedExecutableRegistry/v1",
            "entries": {"python": candidate},
            "generated_at": "2026-08-25T00:00:00Z",
        }).encode("utf-8")

    parsed = hook["_parse_trusted_executable_registry"](encoded(entry))
    assert parsed["python"]["allowed_argv_sha256"] == ["b" * 64]

    invalid_entries = (
        {**entry, "allowed_argv_sha256": "b" * 64},
        {**entry, "allowed_argv_sha256": ["b" * 64, "b" * 64]},
        {**entry, "allowed_argv_sha256": ["B" * 64]},
        {**entry, "unexpected": True},
    )
    for invalid in invalid_entries:
        with pytest.raises(FileNotFoundError, match="trusted_executable_registry_invalid"):
            hook["_parse_trusted_executable_registry"](encoded(invalid))


def test_powershell_registry_accepts_valid_optional_argv_approvals_and_rejects_scalar(
    tmp_path: Path,
) -> None:
    home = tmp_path / "registry adapter home"
    scripts = home / ".codex" / "skills" / "dev-supervisor" / "scripts"
    scripts.mkdir(parents=True)
    shutil.copy2(CODEX_SCRIPTS / "supervisor-core.ps1", scripts / "supervisor-core.ps1")
    python_path = _trusted_python_path()
    digest = hashlib.sha256(python_path.read_bytes()).hexdigest()
    registry = home / ".agent-supervisor" / "trusted-executables.json"
    registry.parent.mkdir(parents=True)

    def resolve(entry: dict) -> str:
        registry.write_text(json.dumps({
            "contract": "TrustedExecutableRegistry/v1",
            "entries": {"python": entry},
            "generated_at": "2026-08-25T00:00:00Z",
        }), encoding="utf-8")
        escaped = str(scripts / "supervisor-core.ps1").replace("'", "''")
        completed = subprocess.run(
            [
                _powershell(),
                "-NoLogo",
                "-NoProfile",
                "-Command",
                f". '{escaped}'; [Console]::Out.Write([string](Get-AgentSupervisorTrustedRegistryPythonPath))",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
            timeout=20,
        )
        assert completed.returncode == 0, completed.stdout + completed.stderr
        return completed.stdout

    base_entry = {
        "kind": "local",
        "path": str(python_path),
        "sha256": digest,
    }
    assert Path(resolve({
        **base_entry,
        "allowed_argv_sha256": ["c" * 64],
    })).resolve(strict=True) == python_path.resolve(strict=True)
    assert resolve({
        **base_entry,
        "allowed_argv_sha256": "c" * 64,
    }) == ""
    if os.name != "nt":
        uppercase_python = tmp_path / "Python3.11"
        uppercase_python.write_bytes(b"not-a-python-runtime")
        assert resolve({
            "kind": "local",
            "path": str(uppercase_python),
            "sha256": hashlib.sha256(uppercase_python.read_bytes()).hexdigest(),
        }) == ""


def _ci_runtime_copy_script_for_test() -> str:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    match = re.search(
        r"\$runtimeRelative = @'\n(?P<script>.*?)\n\s*'@ \| & \$sourcePython -",
        workflow,
        re.DOTALL,
    )
    assert match is not None
    script = textwrap.dedent(match.group("script"))
    source_assignment = "source = Path(sys.base_prefix).resolve(strict=True)"
    executable_assignment = "running_executable = Path(sys.executable).resolve(strict=True)"
    assert source_assignment in script
    assert executable_assignment in script
    script = script.replace(
        source_assignment,
        'source = Path(os.environ["TEST_RUNTIME_SOURCE"]).resolve(strict=True)',
        1,
    ).replace(
        executable_assignment,
        'running_executable = Path(os.environ["TEST_RUNTIME_EXECUTABLE"])'
        ".resolve(strict=True)",
        1,
    )
    return script


def test_ci_runtime_rebinds_loader_exports_path_and_uses_setup_python_identity() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    prepare = re.search(
        r"- name: Prepare hermetic Supervisor test runtime\n(?P<body>.*?)"
        r"\n\s+- name: Run tests",
        workflow,
        re.DOTALL,
    )
    assert prepare is not None
    body = prepare.group("body")

    assert "$ciPython = Join-Path ([string]$env:pythonLocation) 'python.exe'" in body
    assert "'@ | & $sourcePython -" in body
    assert "[string](Get-Command python -CommandType Application" not in body
    assert "& $patchElf --set-rpath $runtimeLibraryRoot $ciPython" in body
    assert "& $patchElf --print-rpath $ciPython" in body
    assert "Remove-Item Env:LD_LIBRARY_PATH" in body
    assert "$env:LD_LIBRARY_PATH = $runtimeLibraryRoot" in body
    assert "$inheritedLdLibraryPath" not in body
    assert '"LD_LIBRARY_PATH=$runtimeLibraryRoot" >> $env:GITHUB_ENV' in body
    assert "(Join-Path $runtimeRoot 'bin') >> $env:GITHUB_PATH" in body
    assert body.index("& $patchElf --set-rpath") < body.index("registry.write_text(")
    target_loader_binding = body.index("$env:LD_LIBRARY_PATH = $runtimeLibraryRoot")
    job_loader_binding = body.index(
        '"LD_LIBRARY_PATH=$runtimeLibraryRoot" >> $env:GITHUB_ENV'
    )
    assert body.index("Remove-Item Env:LD_LIBRARY_PATH") < target_loader_binding
    assert target_loader_binding < job_loader_binding
    assert job_loader_binding < body.index("registry.write_text(")
    assert job_loader_binding < body.index("bin/install-agent-supervisor.py")


def test_ci_hardens_posix_powershell_before_executing_repository_code() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    setup_index = workflow.index("- name: Set up Python")
    harden_index = workflow.index("- name: Harden hosted POSIX executable trust chain")
    scan_index = workflow.index("- name: Scan publishable tree and Git history")
    install_index = workflow.index("- name: Install project")
    assert setup_index < harden_index < scan_index < install_index

    harden = re.search(
        r"- name: Harden hosted POSIX executable trust chain\n(?P<body>.*?)"
        r"\n\s+- name: Scan publishable tree and Git history",
        workflow,
        re.DOTALL,
    )
    assert harden is not None
    body = harden.group("body")
    assert "if: runner.os != 'Windows'" in body
    assert 'root = expected.resolve(strict=True)' in body
    assert 'if root != expected:' in body
    assert "not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)" in body
    assert "info.st_uid != 0" in body
    assert "not stat.S_ISREG(executable_info.st_mode)" in body
    assert body.count("$powerShellTrustProbe | & $sourcePython -") == 2

    preflight = body.index("AGENT_SUPERVISOR_CI_POWERSHELL_PHASE = 'pre'")
    preflight_run = body.index("$powerShellTrustProbe | & $sourcePython -", preflight)
    opt_harden = body.index("& sudo chmod 'go-w' -- '/opt'")
    microsoft_harden = body.index("& sudo chmod 'go-w' -- '/opt/microsoft'")
    powershell_harden = body.index(
        "& sudo chmod 'go-w' -- '/opt/microsoft/powershell'"
    )
    tree_harden = body.index("& sudo chmod -R 'go-w' -- $powerShellRoot")
    postflight = body.index("AGENT_SUPERVISOR_CI_POWERSHELL_PHASE = 'post'")
    postflight_run = body.index("$powerShellTrustProbe | & $sourcePython -", postflight)
    assert preflight < preflight_run < opt_harden
    assert opt_harden < microsoft_harden < powershell_harden < tree_harden
    assert tree_harden < postflight < postflight_run
    assert 'print("CI_POWERSHELL_TRUST_TREE_PASS")' in body


def test_powershell_python_allowed_roots_remain_an_array_after_empty_branch() -> None:
    source = (CODEX_SCRIPTS / "supervisor-core.ps1").read_text(encoding="utf-8")

    assert "[string[]]$rawRoots = @()" in source
    assert "$rawRoots = if ($runningOnWindows)" not in source
    assert "$rawRoots += (Join-Path $profileHome '.pyenv/versions')" in source


def _create_test_directory_link(link: Path, target: Path) -> None:
    if os.name == "nt":
        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)],
            check=True,
            capture_output=True,
            text=True,
        )
    else:
        link.symlink_to(target, target_is_directory=True)


def _remove_test_directory_link(link: Path) -> None:
    if os.name == "nt":
        link.rmdir()
    else:
        link.unlink()


def test_ci_runtime_copy_rejects_external_link_or_reparse_point(
    tmp_path: Path,
) -> None:
    script = _ci_runtime_copy_script_for_test()

    source = tmp_path / "source"
    external = tmp_path / "external"
    runtime = source / "bin" / "python"
    target = tmp_path / "target"
    runtime.parent.mkdir(parents=True)
    external.mkdir()
    runtime.write_bytes(b"test-runtime")
    link = source / "external-link"
    _create_test_directory_link(link, external)
    try:
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=ROOT,
            env={
                **os.environ,
                "AGENT_SUPERVISOR_CI_RUNTIME_ROOT": str(target),
                "TEST_RUNTIME_SOURCE": str(source),
                "TEST_RUNTIME_EXECUTABLE": str(runtime),
            },
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    finally:
        if link.exists():
            _remove_test_directory_link(link)

    assert result.returncode != 0
    assert "external runtime link or reparse point rejected" in (
        result.stdout + result.stderr
    )
    assert not target.exists()


def test_ci_runtime_copy_dereferences_an_internal_link_without_residual_metadata(
    tmp_path: Path,
) -> None:
    script = _ci_runtime_copy_script_for_test()
    source = tmp_path / "source"
    internal = source / "runtime-lib"
    runtime = source / "bin" / "python"
    target = tmp_path / "target"
    internal.mkdir(parents=True)
    runtime.parent.mkdir(parents=True, exist_ok=True)
    (internal / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    runtime.write_bytes(b"test-runtime")
    link = source / "internal-link"
    _create_test_directory_link(link, internal)
    try:
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=ROOT,
            env={
                **os.environ,
                "AGENT_SUPERVISOR_CI_RUNTIME_ROOT": str(target),
                "TEST_RUNTIME_SOURCE": str(source),
                "TEST_RUNTIME_EXECUTABLE": str(runtime),
            },
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    finally:
        if link.exists():
            _remove_test_directory_link(link)

    assert result.returncode == 0, result.stdout + result.stderr
    assert (target / runtime.relative_to(source)).read_bytes() == b"test-runtime"
    copied_link = target / "internal-link"
    assert (copied_link / "module.py").read_text(encoding="utf-8") == "VALUE = 1\n"
    assert not copied_link.is_symlink()
    if hasattr(copied_link, "is_junction"):
        assert not copied_link.is_junction()


@pytest.mark.skipif(os.name == "nt", reason="POSIX runtime permission regression")
def test_ci_runtime_copy_removes_group_and_other_write_permissions(
    tmp_path: Path,
) -> None:
    script = _ci_runtime_copy_script_for_test()
    source = tmp_path / "source"
    runtime = source / "bin" / "python"
    library = source / "lib" / "libpython-test.so"
    target = tmp_path / "target"
    runtime.parent.mkdir(parents=True)
    library.parent.mkdir(parents=True)
    runtime.write_bytes(b"test-runtime")
    library.write_bytes(b"test-library")
    for candidate in (source, runtime.parent, runtime, library.parent, library):
        candidate.chmod(0o777)

    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT,
        env={
            **os.environ,
            "AGENT_SUPERVISOR_CI_RUNTIME_ROOT": str(target),
            "TEST_RUNTIME_SOURCE": str(source),
            "TEST_RUNTIME_EXECUTABLE": str(runtime),
        },
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    copied_paths = (target, *target.rglob("*"))
    assert all(path.lstat().st_mode & 0o022 == 0 for path in copied_paths)


def test_spool_never_writes_partial_json_when_single_record_exceeds_cap(
    tmp_path: Path,
) -> None:
    hook = runpy.run_path(str(CODEX_SCRIPTS / "codex-supervisor-hook.py"))
    hook_globals = hook["_record_degraded"].__globals__
    hook_globals["MAX_SPOOL_BYTES"] = 64
    hook_globals["_adapter_install_home"] = lambda: tmp_path

    hook["_record_degraded"](
        "Stop",
        {"session_id": "oversized-record", "cwd": str(tmp_path)},
        "core_timeout",
        0,
    )

    spool, marker = hook["_fallback_paths"]("oversized-record")
    assert spool.read_bytes() == b""
    assert json.loads(marker.read_text(encoding="utf-8"))["health"] == "degraded"


class _ModuleProxy:
    def __init__(self, wrapped, **overrides):
        self._wrapped = wrapped
        self.__dict__.update(overrides)

    def __getattr__(self, name):
        return getattr(self._wrapped, name)


def _write_posix_hook_fixture(
    tmp_path: Path,
    *,
    pwsh_digest_valid: bool = True,
    include_pwsh: bool = True,
) -> tuple[dict, Path, Path, Path]:
    home = tmp_path / "posix-home"
    scripts = home / ".codex" / "skills" / "dev-supervisor" / "scripts"
    scripts.mkdir(parents=True)
    for name in (
        "codex-supervisor-hook.py",
        "supervisor-core.ps1",
        "supervisor-hook.ps1",
    ):
        shutil.copy2(CODEX_SCRIPTS / name, scripts / name)
    runtime = home / ".pyenv" / "versions" / "3.10" / "bin"
    runtime.mkdir(parents=True)
    pwsh = runtime / "pwsh"
    python_link = runtime / "python3"
    python_runtime = runtime / "python3.10"
    pwsh.write_bytes(b"trusted-pwsh-binary")
    python_link.write_bytes(b"lexical-python-launcher")
    python_runtime.write_bytes(b"resolved-python-runtime")
    entries = {
        "python": {
            "kind": "local",
            "path": str(python_link),
            "sha256": hashlib.sha256(python_runtime.read_bytes()).hexdigest(),
        }
    }
    if include_pwsh:
        entries["pwsh"] = {
            "kind": "local",
            "path": str(pwsh),
            "sha256": (
                hashlib.sha256(pwsh.read_bytes()).hexdigest()
                if pwsh_digest_valid
                else "0" * 64
            ),
        }
    registry = home / ".agent-supervisor" / "trusted-executables.json"
    registry.parent.mkdir(parents=True)
    registry.write_text(json.dumps({
        "contract": "TrustedExecutableRegistry/v1",
        "entries": entries,
        "generated_at": "2026-08-24T00:00:00Z",
    }), encoding="utf-8")
    hook = runpy.run_path(str(scripts / "codex-supervisor-hook.py"), run_name="posix_real")
    globals_ = hook["_forward"].__globals__
    globals_["sys"] = _ModuleProxy(sys, platform="linux", executable=str(python_runtime))
    original_paths = globals_["_posix_executable_paths"]

    def host_neutral_paths(candidate: Path, **kwargs):
        candidate = Path(candidate)
        if candidate.name not in kwargs["allowed_names"] or not candidate.is_file():
            return original_paths(candidate, **kwargs)
        resolved = python_runtime if candidate == python_link else candidate.resolve(strict=True)
        allowed = home / ".pyenv" / "versions"
        try:
            resolved.relative_to(allowed)
        except ValueError:
            return None
        return candidate, resolved

    globals_["_posix_executable_paths"] = host_neutral_paths
    return hook, home, pwsh, python_runtime


@pytest.mark.parametrize("platform_name", ["linux", "darwin"])
def test_posix_hook_forward_uses_real_selection_hash_identity_and_frozen_bridge(
    platform_name: str,
    tmp_path: Path,
) -> None:
    hook, home, pwsh, python_runtime = _write_posix_hook_fixture(tmp_path)
    globals_ = hook["_forward"].__globals__
    globals_["sys"] = _ModuleProxy(sys, platform=platform_name, executable=str(python_runtime))
    captured: dict[str, object] = {}

    selected_python = globals_["_select_posix_executable"](
        home,
        registry_names=("python",),
        allowed_names=frozenset({"python", "python3"}),
        fixed_candidates=(),
        require_running_python=True,
    )
    assert selected_python[0].name == "python3"
    assert selected_python[1].name == "python3.10"

    def windows_only_called(*_args, **_kwargs):
        raise AssertionError("POSIX hook entered a Windows-only trust primitive")

    def run(arguments: list[str], **kwargs):
        captured["arguments"] = arguments
        captured["kwargs"] = kwargs
        return 0, b"{}"

    globals_["_locked_trusted_powershell"] = windows_only_called
    globals_["_locked_trusted_registry_python"] = windows_only_called
    globals_["_run_trusted_powershell"] = run

    assert hook["_forward"](
        "SessionStart",
        {"session_id": f"{platform_name}-success", "cwd": str(tmp_path)},
        False,
    ) == (0, b"{}")

    arguments = captured["arguments"]
    kwargs = captured["kwargs"]
    assert arguments[0] == str(pwsh)
    assert "-Command" in arguments and "-File" not in arguments
    assert "$script:AgentSupervisorAdapterScriptsRoot" in arguments[-1]
    assert ". $coreBridge" not in arguments[-1]
    assert kwargs["cwd"] == home
    assert kwargs["system_directory"] is None
    assert kwargs["timeout_seconds"] == hook["_outer_hook_timeout"]("SessionStart")
    assert kwargs["env"]["AGENT_SUPERVISOR_PYTHON"] == str(selected_python[0])
    assert kwargs["env"]["PATH"] == str(pwsh.parent)
    forwarded = json.loads(kwargs["input_bytes"].decode("utf-8"))
    assert forwarded["_agent_supervisor_adapter"]["degraded_prior"] is False


@pytest.mark.parametrize("failure", ["missing-pwsh", "digest-mismatch"])
def test_posix_hook_real_executable_selection_rejects_missing_or_wrong_digest(
    failure: str,
    tmp_path: Path,
) -> None:
    hook, home, _pwsh, _python = _write_posix_hook_fixture(
        tmp_path,
        include_pwsh=failure != "missing-pwsh",
        pwsh_digest_valid=failure != "digest-mismatch",
    )
    with pytest.raises(FileNotFoundError):
        hook["_select_posix_executable"](
            home,
            registry_names=("pwsh", "powershell"),
            allowed_names=frozenset({"pwsh"}),
            fixed_candidates=(),
            require_running_python=False,
        )


def test_posix_real_executable_selection_accepts_an_explicit_fixed_candidate(
    tmp_path: Path,
) -> None:
    hook, home, pwsh, _python = _write_posix_hook_fixture(
        tmp_path,
        include_pwsh=False,
    )
    selected = hook["_select_posix_executable"](
        home,
        registry_names=("pwsh", "powershell"),
        allowed_names=frozenset({"pwsh"}),
        fixed_candidates=(pwsh,),
        require_running_python=False,
    )
    assert selected == (pwsh, pwsh, None)


def test_posix_executable_name_policy_accepts_only_numeric_python_versions() -> None:
    hook = runpy.run_path(
        str(CODEX_SCRIPTS / "codex-supervisor-hook.py"),
        run_name="posix_name_policy",
    )
    allowed = hook["_allowed_posix_executable_name"]
    python_names = frozenset({"python", "python3"})

    for name in ("python", "python3", "python3.11", "python3.14.1"):
        assert allowed(name, python_names) is True
    for name in (
        "python3.",
        "python3.alpha",
        "python3.11-config",
        "python3-config",
        "python311",
        "pwsh",
    ):
        assert allowed(name, python_names) is False
    assert allowed("python3.11", frozenset({"pwsh"})) is False


@pytest.mark.skipif(
    os.name != "nt" or shutil.which("wsl.exe") is None,
    reason="Windows-hosted WSL integration requires Windows and wsl.exe",
)
def test_wsl_posix_production_selection_covers_versioned_python_and_pwsh_branches() -> None:
    wsl = shutil.which("wsl.exe")
    assert wsl is not None
    usable = subprocess.run(
        [wsl, "-e", "true"],
        capture_output=True,
        check=False,
        timeout=10,
    )
    if usable.returncode != 0:
        pytest.skip("Windows-hosted WSL integration requires a usable distribution")
    translated = subprocess.run(
        [wsl, "-e", "wslpath", "-a", str(CODEX_SCRIPTS / "codex-supervisor-hook.py")],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
        timeout=10,
    )
    assert translated.returncode == 0
    hook_path = translated.stdout.strip()
    assert hook_path.startswith("/")
    source = textwrap.dedent(
        """
        import json, pathlib, runpy, shutil, tempfile

        hook = runpy.run_path(__import__('sys').argv[1], run_name='wsl_posix_contract')
        python = pathlib.Path('/usr/bin/python3')
        direct = hook['_posix_executable_paths'](
            python,
            allowed_names=frozenset({'python', 'python3'}),
            allowed_roots=(pathlib.Path('/usr'),),
            require_root_owner=True,
        )
        selected_python = hook['_select_posix_executable'](
            pathlib.Path('/root'),
            registry_names=(),
            allowed_names=frozenset({'python', 'python3'}),
            fixed_candidates=(python,),
            require_running_python=True,
        )
        config_rejected = hook['_posix_executable_paths'](
            pathlib.Path('/usr/bin/python3-config'),
            allowed_names=frozenset({'python', 'python3'}),
            allowed_roots=(pathlib.Path('/usr'),),
            require_root_owner=True,
        ) is None
        install_home = pathlib.Path(tempfile.mkdtemp(prefix='agent-supervisor-posix-', dir='/root'))
        try:
            missing = False
            try:
                hook['_select_posix_executable'](
                    install_home,
                    registry_names=('pwsh', 'powershell'),
                    allowed_names=frozenset({'pwsh'}),
                    fixed_candidates=(),
                    require_running_python=False,
                )
            except FileNotFoundError:
                missing = True
            fixed_pwsh = install_home / '.pyenv' / 'versions' / 'test' / 'bin' / 'pwsh'
            fixed_pwsh.parent.mkdir(parents=True)
            fixed_pwsh.write_bytes(b'#!/bin/sh\\nexit 0\\n')
            fixed_pwsh.chmod(0o755)
            fixed = hook['_select_posix_executable'](
                install_home,
                registry_names=(),
                allowed_names=frozenset({'pwsh'}),
                fixed_candidates=(fixed_pwsh,),
                require_running_python=False,
            )
            with hook['_trusted_posix_python'](install_home) as trusted_python:
                trusted_lexical = str(trusted_python[0])
            result = {
                'directLexical': str(direct[0]),
                'directResolvedLeaf': direct[1].name,
                'selectedLexical': str(selected_python[0]),
                'selectedResolvedLeaf': selected_python[1].name,
                'configRejected': config_rejected,
                'missingWithEmptyFixedCandidates': missing,
                'fixedPwsh': str(fixed[0]),
                'fixedExpectedDigest': fixed[2],
                'trustedPythonLexical': trusted_lexical,
                'nativePwshAvailable': shutil.which('pwsh') is not None,
            }
            print(json.dumps(result, separators=(',', ':')))
        finally:
            shutil.rmtree(install_home)
        """
    )
    completed = subprocess.run(
        [wsl, "-e", "python3", "-I", "-S", "-X", "utf8", "-c", source, hook_path],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    observed = json.loads(completed.stdout)
    assert observed["directLexical"] == "/usr/bin/python3"
    assert re.fullmatch(r"python3\.\d+", observed["directResolvedLeaf"])
    assert observed["selectedLexical"] == "/usr/bin/python3"
    assert re.fullmatch(r"python3\.\d+", observed["selectedResolvedLeaf"])
    assert observed["configRejected"] is True
    assert observed["missingWithEmptyFixedCandidates"] is True
    assert observed["fixedPwsh"].endswith("/.pyenv/versions/test/bin/pwsh")
    assert observed["fixedExpectedDigest"] is None
    assert observed["trustedPythonLexical"] == "/usr/bin/python3"
    assert isinstance(observed["nativePwshAvailable"], bool)


def test_posix_executable_selection_rejects_python_config_leaf_with_real_helper(
    tmp_path: Path,
) -> None:
    hook, home, _pwsh, _python = _write_posix_hook_fixture(tmp_path)
    candidate = home / ".pyenv" / "versions" / "3.10" / "bin" / "python3-config"
    candidate.write_bytes(b"not-a-python-runtime")
    assert hook["_posix_executable_paths"](
        candidate,
        allowed_names=frozenset({"python", "python3"}),
        allowed_roots=(home / ".pyenv" / "versions",),
        require_root_owner=False,
    ) is None


def test_posix_real_bridge_digest_and_post_yield_identity_changes_fail_closed(
    tmp_path: Path,
) -> None:
    hook, _home, _pwsh, _python = _write_posix_hook_fixture(tmp_path)
    globals_ = hook["_forward"].__globals__
    core = Path(globals_["__file__"]).parent / "supervisor-core.ps1"

    original = core.read_bytes()
    core.write_bytes(original + b"\n# tamper")
    with pytest.raises(FileNotFoundError, match="hook_bridge_rejected"):
        with hook["_trusted_posix_hook_bridge_files"]():
            pass

    core.write_bytes(original)
    context = hook["_stable_verified_posix_bridge_file"](
        "supervisor-core.ps1",
        len(original),
        hashlib.sha256(original).hexdigest(),
    )
    with pytest.raises(FileNotFoundError, match="hook_bridge_changed"):
        with context:
            os.utime(core, ns=(core.stat().st_atime_ns, core.stat().st_mtime_ns + 1_000_000))


def test_unknown_hook_platform_fails_closed_before_windows_trust_resolution(
    tmp_path: Path,
) -> None:
    hook = runpy.run_path(
        str(CODEX_SCRIPTS / "codex-supervisor-hook.py"),
        run_name="unknown_platform_forward",
    )
    globals_ = hook["_forward"].__globals__
    globals_["sys"] = _ModuleProxy(sys, platform="plan9")
    globals_["os"] = _ModuleProxy(os, name="posix")
    globals_["_adapter_install_home"] = lambda: tmp_path

    with pytest.raises(FileNotFoundError, match="hook_platform_rejected"):
        hook["_forward"](
            "SessionStart",
            {"session_id": "unknown-platform", "cwd": str(tmp_path)},
            False,
        )


def test_windows_hook_forward_still_uses_locked_file_bridge_and_job_runner(
    tmp_path: Path,
) -> None:
    hook = runpy.run_path(
        str(CODEX_SCRIPTS / "codex-supervisor-hook.py"),
        run_name="windows_forward_regression",
    )
    globals_ = hook["_forward"].__globals__

    class Context:
        def __init__(self, value):
            self.value = value

        def __enter__(self):
            return self.value

        def __exit__(self, *_args):
            return False

    def posix_only_called(*_args, **_kwargs):
        raise AssertionError("Windows hook entered a POSIX-only trust primitive")

    system_directory = tmp_path / "Windows" / "System32"
    powershell = (
        system_directory / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    )
    python = tmp_path / "Python" / "python.exe"
    cmd = system_directory / "cmd.exe"
    hook_bridge = tmp_path / "supervisor-hook.ps1"
    captured: dict[str, object] = {}

    globals_["sys"] = _ModuleProxy(sys, platform="win32")
    globals_["os"] = _ModuleProxy(os, name="nt")
    globals_["_adapter_install_home"] = lambda: tmp_path
    globals_["_minimal_hook_environment"] = lambda: {}
    globals_["_locked_trusted_powershell"] = lambda: Context(
        (powershell, object(), system_directory)
    )
    globals_["_locked_trusted_registry_python"] = lambda _home: Context(
        (python, object())
    )
    globals_["_trusted_hook_bridge_files"] = lambda: Context((
        (tmp_path / "supervisor-core.ps1", object()),
        (hook_bridge, object()),
    ))
    globals_["_canonical_existing"] = lambda path, *, directory: (
        cmd if path == cmd and directory is False else None
    )
    globals_["_trusted_posix_powershell"] = posix_only_called
    globals_["_trusted_posix_python"] = posix_only_called
    globals_["_trusted_posix_hook_bridge_files"] = posix_only_called

    def run(arguments: list[str], **kwargs):
        captured["arguments"] = arguments
        captured["kwargs"] = kwargs
        return 0, b"{}"

    globals_["_run_trusted_powershell"] = run

    assert hook["_forward"](
        "SessionStart",
        {"session_id": "windows-regression", "cwd": str(tmp_path)},
        False,
    ) == (0, b"{}")
    arguments = captured["arguments"]
    assert isinstance(arguments, list)
    assert arguments[0] == str(powershell)
    assert "-File" in arguments
    assert "-Command" not in arguments
    assert arguments[-1] == str(hook_bridge)
    kwargs = captured["kwargs"]
    assert isinstance(kwargs, dict)
    assert kwargs["system_directory"] == system_directory
    assert kwargs["cwd"] == tmp_path
    assert kwargs["env"]["COMSPEC"] == str(cmd)
    assert kwargs["env"]["AGENT_SUPERVISOR_PYTHON"] == str(python)


def test_powershell_python_command_executes_dependency_root_policy(tmp_path: Path) -> None:
    python_path = _trusted_python_path()
    trusted_root = tmp_path / "trusted-dependencies"
    site_packages = trusted_root / "lib" / "site-packages"
    dist_packages = trusted_root / "lib" / "dist-packages"
    outside_root = tmp_path / "outside-dependencies"
    outside_site = outside_root / "site-packages"
    for directory in (site_packages, dist_packages, outside_site):
        directory.mkdir(parents=True)
    harness = tmp_path / "python-dependency-policy.ps1"
    harness.write_text(textwrap.dedent(
        f"""
        param([string]$Core, [string]$PythonPath, [string]$TrustedRoot, [string]$OutsideRoot)
        . $Core
        $script:Scenario = ''
        $script:ObservedIdentityProbe = $false
        function Get-Command {{ @() }}
        function Get-AgentSupervisorPythonAllowedRoots {{
            if ($script:Scenario -eq 'zero') {{ return @() }}
            return @((Split-Path -Parent $PythonPath), $TrustedRoot)
        }}
        function Get-AgentSupervisorTrustedRegistryPythonPath {{
            if ($script:Scenario -eq 'zero') {{ return $null }}
            return $PythonPath
        }}
        function Invoke-AgentSupervisorPython {{
            param(
                [string]$Command, [string[]]$PrefixArgs, [string[]]$Arguments,
                [string]$Operation, [double]$TimeoutSeconds,
                [switch]$CaptureOutput, [switch]$SuppressOutput,
                [switch]$IsolatedEnvironment, [switch]$Silent
            )
            $script:ObservedIdentityProbe = Test-AgentSupervisorFixedPythonProbe `
                -Operation $Operation -PrefixArgs $PrefixArgs -Arguments $Arguments
            $site = switch ($script:Scenario) {{
                'site' {{ Join-Path $TrustedRoot 'lib\\site-packages' }}
                'dist' {{ Join-Path $TrustedRoot 'lib\\dist-packages' }}
                default {{ Join-Path $OutsideRoot 'site-packages' }}
            }}
            $dependency = if ($script:Scenario -in @('site','dist')) {{ $TrustedRoot }} else {{ $OutsideRoot }}
            $payload = @{{
                executable = $PythonPath
                site_paths = @($site)
                dependency_roots = @($dependency)
            }} | ConvertTo-Json -Compress
            return [pscustomobject]@{{ ExitCode = 0; StandardOutput = $payload }}
        }}
        $results = @{{}}
        foreach ($scenario in @('site','dist','outside','zero')) {{
            $script:Scenario = $scenario
            $script:ObservedIdentityProbe = $false
            $resolved = Get-AgentSupervisorPythonCommand
            $results[$scenario] = @{{
                accepted = $null -ne $resolved
                identityProbe = $script:ObservedIdentityProbe
                dependencyLeaf = if (@($script:AgentSupervisorVerifiedDependencyRoots).Count) {{
                    Split-Path -Leaf $script:AgentSupervisorVerifiedDependencyRoots[0]
                }} else {{ '' }}
            }}
        }}
        $windowsCandidate = Resolve-AgentSupervisorTrustedPythonPath `
            -Candidate $PythonPath `
            -AllowedRoots @((Split-Path -Parent $PythonPath)) `
            -KnownExecutables @($PythonPath)
        $configCandidate = Join-Path (Split-Path -Parent $PythonPath) 'python3-config.exe'
        $windowsConfig = Resolve-AgentSupervisorTrustedPythonPath `
            -Candidate $configCandidate `
            -AllowedRoots @((Split-Path -Parent $PythonPath)) `
            -KnownExecutables @($configCandidate)
        @{{ results = $results; windowsCandidate = $windowsCandidate; windowsConfig = $windowsConfig }} |
            ConvertTo-Json -Compress -Depth 8
        """
    ).strip() + "\n", encoding="utf-8")
    completed = subprocess.run(
        [
            _powershell(), "-NoLogo", "-NoProfile", "-File", str(harness),
            str(CODEX_SCRIPTS / "supervisor-core.ps1"), str(python_path),
            str(trusted_root), str(outside_root),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    observed = json.loads(completed.stdout)
    assert observed["results"]["site"] == {
        "accepted": True,
        "identityProbe": True,
        "dependencyLeaf": "site-packages",
    }
    assert observed["results"]["dist"] == {
        "accepted": True,
        "identityProbe": True,
        "dependencyLeaf": "dist-packages",
    }
    assert observed["results"]["outside"]["accepted"] is False
    assert observed["results"]["zero"]["accepted"] is False
    assert observed["windowsCandidate"] == str(python_path)
    assert observed["windowsConfig"] is None


def test_powershell_python_command_runs_real_production_identity_probe(
    tmp_path: Path,
) -> None:
    python_path = _trusted_python_path()
    scripts = tmp_path / "identity home" / ".codex" / "skills" / "dev-supervisor" / "scripts"
    scripts.mkdir(parents=True)
    core_script = scripts / "supervisor-core.ps1"
    shutil.copy2(CODEX_SCRIPTS / core_script.name, core_script)
    harness = tmp_path / "real-python-identity-probe.ps1"
    harness.write_text(textwrap.dedent(
        """
        param([string]$Core, [string]$PythonPath, [string]$RuntimeRoot)
        . $Core
        function Get-Command { @() }
        function Get-AgentSupervisorTrustedRegistryPythonPath {
            return Resolve-AgentSupervisorTrustedPythonPath `
                -Candidate $PythonPath `
                -AllowedRoots @($RuntimeRoot) `
                -KnownExecutables @($PythonPath)
        }
        $resolved = Get-AgentSupervisorPythonCommand
        $accepted = $null -ne $resolved
        $command = if ($accepted) { [string]$resolved.Command } else { '' }
        $dependencies = @($script:AgentSupervisorVerifiedDependencyRoots)

        function Get-AgentSupervisorPythonAllowedRoots { return @() }
        function Get-AgentSupervisorTrustedRegistryPythonPath { return $null }
        $zero = Get-AgentSupervisorPythonCommand
        @{
            accepted = $accepted
            command = $command
            dependencies = $dependencies
            zeroAccepted = $null -ne $zero
        } | ConvertTo-Json -Compress -Depth 8
        """
    ).strip() + "\n", encoding="utf-8")
    completed = subprocess.run(
        [
            _powershell(), "-NoLogo", "-NoProfile", "-File", str(harness),
            str(core_script), str(python_path), str(Path(sys.base_prefix).resolve()),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    observed = json.loads(completed.stdout)
    assert observed["accepted"] is True
    assert Path(observed["command"]) == python_path
    dependencies = {Path(value).resolve() for value in observed["dependencies"]}
    expected_system_site = Path(sysconfig.get_paths()["purelib"]).resolve()
    expected_user_site = Path(site.getusersitepackages()).resolve()
    assert expected_system_site in dependencies
    if expected_user_site.is_dir():
        assert expected_user_site in dependencies
    assert all(path.name in {"site-packages", "dist-packages"} for path in dependencies)
    assert observed["zeroAccepted"] is False
