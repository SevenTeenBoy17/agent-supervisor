from __future__ import annotations

import copy
import hashlib
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from supervisor_core.attestation import sign_record
from supervisor_core.contracts import invocation_event
from supervisor_core.util import canonical_sha256


def digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


@pytest.fixture(autouse=True)
def isolated_attestation_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "AGENT_SUPERVISOR_ATTESTATION_KEY_FILE",
        str(tmp_path / "attestation.key"),
    )


@pytest.fixture
def valid_bundle(tmp_path: Path):
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    repository = tmp_path / "fixture-repository"
    repository.mkdir()
    git_environment = os.environ.copy()
    git_environment["GIT_CONFIG_NOSYSTEM"] = "1"
    git_environment["GIT_CONFIG_GLOBAL"] = os.devnull
    for variable in (
        "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR",
        "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    ):
        git_environment.pop(variable, None)

    def git(*args: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            ["git", "-C", str(repository), *args],
            check=True,
            capture_output=True,
            env=git_environment,
        )

    git("init", "-q")
    git("config", "user.email", "fixture@example.invalid")
    git("config", "user.name", "Supervisor Fixture")
    (repository / "config.json").write_text('{"v":1}\n', encoding="utf-8")
    git("add", "config.json")
    git("commit", "-qm", "fixture base")
    base_hash = git("rev-parse", "HEAD").stdout.decode().strip()
    (repository / "config.json").write_text('{"v":2}\n', encoding="utf-8")
    git("add", "config.json")
    git("commit", "-qm", "fixture head")
    head_hash = git("rev-parse", "HEAD").stdout.decode().strip()
    diff = git(
        "diff", "--binary", "--full-index", "--no-ext-diff", base_hash, head_hash
    ).stdout.decode("utf-8", errors="replace")
    diff_hash = digest(diff)
    workspace_base_hash = digest("workspace-base")
    workspace_head_hash = digest("workspace-head")
    repository_root = str(repository.resolve())
    goal_id = "goal-valid"
    state = {
        "schema_version": 3,
        "runtime": "test",
        "project": "example",
        "workspace": repository_root,
        "session": "session-a",
        "round": "round-a",
        "execution_mode": "enforce",
        "goal": {
            "contract": "GoalContract/v3",
            "goal_id": goal_id,
            "version": 1,
            "original_request_sha256": digest("implement v3"),
            "change_mode": "continue",
            "objective": "Implement validated supervisor behavior",
            "acceptance_criteria": [{"criterion_id": "criterion-1", "description": "All binary gates pass", "domain": "config-agent", "expected_evidence": ["lint"], "required": True}],
            "scope": {"in": ["config.json"], "out": ["product/**"]},
            "constraints": [], "non_goals": [], "assumptions": [], "risks": [], "created_at": now,
        },
        "intents": [{"contract": "IntentCoverage/v3", "intent_id": "intent-1", "text": "implement", "status": "covered", "reason": "completed by core-builder", "capability_ids": ["core-builder"], "method": "capability", "phase": 1}],
        "intent_manifest": [{"intent_id": "intent-1", "text_sha256": digest("implement"), "domain": "general"}],
        "attestation_authority": {
            "contract": "AttestationAuthority/v3", "scheme": "local-process-hmac-sha256",
            "assurance": "local-integrity-only", "same_user_adversary_resistant": False,
            "limitation": "detects accidental/out-of-band mutation but is not a host security boundary",
        },
        "tasks": [{"task_id": "task-1", "goal_id": goal_id, "goal_version": 1, "criterion_ids": ["criterion-1"], "allowed_paths": ["config.json"], "expected_evidence": ["lint"], "status": "done", "evidence_ids": ["evidence-1"]}],
        "evidence": [{"contract": "EvidenceRecord/v3", "evidence_id": "evidence-1", "execution_id": "execution-1", "criterion_id": "criterion-1", "goal_id": goal_id, "goal_version": 1, "command": {"category": "test", "args": ["pytest", "-q"]}, "cwd": repository_root, "collected_at": now, "exit_code": 0, "output_summary": "42 tests passed", "artifact_hash": digest("42 tests passed"), "output_sha256": digest("42 tests passed"), "base": base_hash, "head": head_hash, "git_object_format": "sha1", "git_binding_status": "verified", "git_binding_source": "workspace", "git_repository_root": repository_root, "review_artifact_sha256": None, "git_diff_sha256": None, "workspace_base_sha256": workspace_base_hash, "workspace_head_sha256": workspace_head_hash, "diff_hash": diff_hash, "collector": "gate-runner-a", "collector_responsibility_group": "independent-gate-execution", "collector_invocation_id": "inv-gate-runner", "collector_identity_assurance": "host-hook-observed", "gate_grant_id": "gate-grant-1", "gate_id": "lint", "relevant": True}],
        "reviews": [{"contract": "ReviewRecord/v3", "review_id": "review-1", "goal_id": goal_id, "goal_version": 1, "reviewer": "reviewer-a", "reviewer_responsibility_group": "quality-review", "implementer": "worker-a", "implementer_responsibility_group": "implementation", "gate_collector": "gate-runner-a", "gate_collector_responsibility_group": "independent-gate-execution", "gate_runner_invocation_id": "inv-gate-runner", "base": base_hash, "head": head_hash, "git_object_format": "sha1", "git_binding_status": "verified", "git_binding_source": "workspace", "git_repository_root": repository_root, "review_artifact_sha256": None, "git_diff_sha256": None, "workspace_base_sha256": workspace_base_hash, "workspace_head_sha256": workspace_head_hash, "diff_hash": diff_hash, "rerun_evidence_ids": ["evidence-1"], "evidence_verification": {"status": "VERIFIED", "reviewer": "reviewer-a", "evidence_ids": ["evidence-1"]}, "verdict": "APPROVE", "category": "code", "implementer_invocation_id": "inv-1", "reviewer_invocation_id": "inv-review", "actor_identity_assurance": "host-hook-observed", "issued_by": "supervisor-core-review-finalize", "issued_at": now}],
        "waivers": [],
        "changes": {"files": ["config.json"], "base": base_hash, "head": head_hash, "git_object_format": "sha1", "git_binding_status": "verified", "git_binding_source": "workspace", "git_repository_root": repository_root, "review_artifact": None, "review_artifact_sha256": None, "git_diff_sha256": None, "workspace_base_sha256": workspace_base_hash, "workspace_head_sha256": workspace_head_hash, "diff_hash": diff_hash, "diff": diff, "domains": ["config-agent"], "implementer": "worker-a", "implementer_responsibility_group": "implementation", "implementer_invocation_id": "inv-1", "test_changes": {}},
        "spec": {"status": "approved", "hash": digest("spec"), "path": "spec.md", "content": "Concrete contract"},
        "quality_profile": {"global_gates": [], "common_gates": [{"id": "lint", "command": ["pytest", "-q"]}], "domains": {"config/agent": {"required_gates": ["lint"]}}},
        "capability_breakers": {}, "health": "healthy", "terminal_state": None, "stop_attempts": 0, "started_at": now, "updated_at": now,
    }
    events = [
        invocation_event(invocation_id="inv-1", capability="core-builder", stage="attempt", result=None, actor="worker-a", responsibility_group="implementation", identity_assurance="host-hook-observed"),
        invocation_event(invocation_id="inv-1", capability="core-builder", stage="result", result="success", actor="worker-a", responsibility_group="implementation", identity_assurance="host-hook-observed"),
        invocation_event(invocation_id="inv-gate-runner", capability="independent-gate-runner", stage="attempt", result=None, actor="gate-runner-a", responsibility_group="independent-gate-execution", identity_assurance="host-hook-observed"),
        invocation_event(invocation_id="inv-gate-runner", capability="independent-gate-runner", stage="result", result="success", actor="gate-runner-a", responsibility_group="independent-gate-execution", identity_assurance="host-hook-observed"),
        invocation_event(invocation_id="inv-review", capability="independent-reviewer", stage="attempt", result=None, actor="reviewer-a", responsibility_group="quality-review", identity_assurance="host-hook-observed"),
        invocation_event(invocation_id="inv-review", capability="independent-reviewer", stage="result", result="success", actor="reviewer-a", responsibility_group="quality-review", identity_assurance="host-hook-observed"),
    ]
    request_manifest = {
        "contract": "RequestManifest/v3",
        "goal_id": goal_id,
        "goal_version": 1,
        "goal_sha256": canonical_sha256(state["goal"]),
        "original_request_sha256": state["goal"]["original_request_sha256"],
        "intents": copy.deepcopy(state["intent_manifest"]),
        "runtime": state["runtime"],
        "workspace": str(Path(state["workspace"]).resolve()),
        "session": state["session"],
        "round": state["round"],
    }
    request_manifest["attestation"] = sign_record(request_manifest)
    state["request_manifest"] = request_manifest
    invocation_binding = {
        "runtime": state["runtime"],
        "project": state["project"],
        "workspace": str(Path(state["workspace"]).resolve()),
        "session": state["session"],
        "round": state["round"],
        "goal_id": state["goal"]["goal_id"],
        "goal_version": state["goal"]["version"],
        "request_manifest_sha256": canonical_sha256(request_manifest),
    }
    for event in events:
        event["details"].update(invocation_binding)
        event["attestation"] = sign_record(event)
    state["reviews"][0]["request_manifest_sha256"] = canonical_sha256(request_manifest)
    state["reviews"][0]["attestation"] = sign_record(state["reviews"][0])
    return copy.deepcopy(state), copy.deepcopy(events)
