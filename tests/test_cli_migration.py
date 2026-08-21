from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from supervisor_core.cli import _classify_goal_change, main
from supervisor_core.validation import validate_state


def test_invalid_cli_state_uses_exit_64(capsys):
    assert main(["query", "--runtime", "codex", "--workspace", "Z:/does-not-exist", "--session", "missing"]) == 64
    assert "InvalidState" in capsys.readouterr().out
    assert main(["query", "--runtime", "test", "--workspace", ".", "--session", "s"]) == 64


def test_latest_round_resolves_pointer_and_missing_query_is_invalid(tmp_path, capsys):
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


def test_event_cli_updates_authoritative_state_records(tmp_path, capsys):
    state_root = tmp_path / "state"
    common = ["--runtime", "codex", "--workspace", str(tmp_path), "--session", "s", "--round", "r", "--state-root", str(state_root)]
    assert main(["start", *common, "--message", "implement", "--change-mode", "replace", "--execution-mode", "observe"]) == 0
    started = json.loads(capsys.readouterr().out)
    state_file = Path(started["state_file"])

    records = [
        ("spec_record", {"status": "approved", "hash": "a" * 64, "path": "spec.md", "content": "resolved contract"}),
        ("task_record", {"task_id": "task-1", "goal_id": "g", "goal_version": 1, "criterion_ids": ["criterion-1"], "allowed_paths": ["config.json"], "expected_evidence": ["test"], "status": "doing", "evidence_ids": []}),
        ("evidence_record", {"evidence_id": "e-1", "command": {"category": "test", "args": ["pytest", "token=abc123"]}}),
        ("review_record", {"review_id": "review-1", "verdict": "APPROVE"}),
        ("changes_record", {"files": ["config.json"], "diff_hash": "b" * 64}),
    ]
    for event_type, record in records:
        assert main(["event", *common, "--event-type", event_type, "--data-json", json.dumps({"record": record})]) == 0
        capsys.readouterr()
    assert main(["event", *common, "--event-type", "intent_disposition", "--data-json", json.dumps({"record": {"intent_id": "intent-1", "status": "skipped", "reason": "covered manually", "capability_ids": [], "method": "manual-specialized", "phase": 1}})]) == 0
    capsys.readouterr()

    state = json.loads(state_file.read_text(encoding="utf-8"))
    assert state["spec"]["status"] == "approved"
    assert state["tasks"][0]["task_id"] == "task-1"
    assert state["evidence"][0]["evidence_id"] == "e-1"
    assert state["evidence"][0]["command"]["args"][1].endswith("[REDACTED]")
    assert state["reviews"][0]["review_id"] == "review-1"
    assert state["changes"]["diff_hash"] == "b" * 64
    assert state["intents"][0]["status"] == "skipped"


def test_gate_runner_attests_real_exit_and_rejects_self_report(tmp_path, capsys, monkeypatch):
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
    request = {"record": {"gate_id": "gate.real", "criterion_id": criterion_id, "evidence_id": "real-evidence", "collector_responsibility_group": "quality"}}
    assert main(["event", *common, "--event-type", "gate_run", "--actor", "reviewer-a", "--data-json", json.dumps(request)]) == 2
    runner_output = json.loads(capsys.readouterr().out)
    assert runner_output["exit_code"] == 99
    state = json.loads(state_file.read_text(encoding="utf-8"))
    assert state["evidence"] == []
    events = [json.loads(line) for line in state_file.with_name("events.jsonl").read_text(encoding="utf-8").splitlines()]
    assert any(event.get("event_type") == "gate_execution" and event.get("exit_code") == 99 for event in events)
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


def test_two_failures_open_breaker_and_require_configured_fallback(tmp_path, capsys):
    project = tmp_path / ".agent-supervisor" / "project.json"
    project.parent.mkdir()
    project.write_text(json.dumps({
        "project_id": "p", "agent_roles": [{"id": "primary-agent", "fallback_id": "fallback-agent"}],
    }), encoding="utf-8")
    common = ["--runtime", "codex", "--workspace", str(tmp_path), "--session", "breaker", "--round", "r", "--project-file", str(project), "--state-root", str(tmp_path / "state")]
    assert main(["start", *common, "--message", "breaker", "--change-mode", "replace", "--execution-mode", "observe"]) == 0
    state_file = Path(json.loads(capsys.readouterr().out)["state_file"])
    for index in (1, 2):
        invocation_id = f"inv-{index}"
        assert main(["event", *common, "--event-type", "invocation_attempt", "--invocation-id", invocation_id, "--capability", "primary-agent", "--actor", "worker"]) == 0
        capsys.readouterr()
        assert main(["event", *common, "--event-type", "invocation_result", "--invocation-id", invocation_id, "--capability", "primary-agent", "--actor", "worker", "--result", "failed"]) == 0
        capsys.readouterr()
    row = json.loads(state_file.read_text(encoding="utf-8"))["capability_breakers"]["primary-agent"]
    assert row["open"] is True
    assert row["active_capability"] == "fallback-agent"
    assert main(["event", *common, "--event-type", "invocation_attempt", "--invocation-id", "inv-3", "--capability", "primary-agent", "--actor", "worker"]) == 4
    response = json.loads(capsys.readouterr().out)
    assert response["fallback_required"] == "fallback-agent"


def test_bin_bootstrap_runs_from_arbitrary_cwd(tmp_path):
    script = Path(__file__).resolve().parents[1] / "bin" / "agent-supervisor.py"
    completed = subprocess.run([sys.executable, str(script), "--version"], cwd=tmp_path, text=True, capture_output=True)
    assert completed.returncode == 0
    assert completed.stdout.strip() == "3.0.4"


def test_hook_session_start_handles_unicode_space_path(tmp_path):
    workspace = tmp_path / "中文 path"
    workspace.mkdir()
    payload = json.dumps({"session_id": "s", "cwd": str(workspace), "hook_event_name": "SessionStart"}, ensure_ascii=False)
    root = Path(__file__).resolve().parents[1]
    completed = subprocess.run([sys.executable, "-m", "supervisor_core", "hook", "--runtime", "claude", "--event", "SessionStart"], cwd=root, input=payload, text=True, capture_output=True, encoding="utf-8")
    assert completed.returncode == 0
    result = json.loads(completed.stdout)
    assert "ready" in result["hookSpecificOutput"]["additionalContext"]


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
    env = dict(os.environ)
    env.update({"USERPROFILE": str(isolated_home), "HOME": str(isolated_home)})
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
