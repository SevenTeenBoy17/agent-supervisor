from __future__ import annotations

import copy
import hashlib
import subprocess

import pytest

from supervisor_core.attestation import sign_record
from supervisor_core.validation import _domains_from_observed, _validate_changes_and_reviews, validate_state
from supervisor_core.lifecycle import start_round
from supervisor_core.storage import StateContext
from supervisor_core.util import canonical_sha256


def messages(state, events):
    return "\n".join(validate_state(state, events)["errors"])


def reseal_request_manifest(state):
    manifest = state["request_manifest"]
    manifest["goal_id"] = state["goal"]["goal_id"]
    manifest["goal_version"] = state["goal"]["version"]
    manifest["goal_sha256"] = canonical_sha256(state["goal"])
    manifest["original_request_sha256"] = state["goal"]["original_request_sha256"]
    manifest["intents"] = copy.deepcopy(state["intent_manifest"])
    manifest["attestation"] = sign_record(manifest)


def test_valid_structured_state_passes(valid_bundle):
    state, events = valid_bundle
    report = validate_state(state, events)
    assert report["valid"], report


@pytest.mark.parametrize("bad", ["trust me", "", "TODO later"])
def test_untrusted_free_text_evidence_fails(valid_bundle, bad):
    state, events = valid_bundle
    state["evidence"][0]["output_summary"] = bad
    assert "untrusted" in messages(state, events)


@pytest.mark.parametrize("bad", [{}, [], [""], "trust me"])
def test_empty_or_freeform_evidence_fails(valid_bundle, bad):
    state, events = valid_bundle
    state["evidence"] = bad
    assert not validate_state(state, events)["valid"]


def test_unresolved_spec_fails(valid_bundle):
    state, events = valid_bundle
    state["spec"] = {"status": "unresolved"}
    assert "spec unresolved" in messages(state, events)


def test_signed_request_manifest_rejects_omitted_intent_and_goal_rewrite(valid_bundle):
    state, events = valid_bundle
    state["intents"] = []
    state["intent_manifest"] = []
    result = messages(state, events)
    assert "changed after trusted start" in result

    state, events = valid_bundle
    state["goal"]["objective"] = "silently replaced objective"
    assert "changed after trusted start" in messages(state, events)


def test_each_criterion_and_task_require_every_declared_evidence_type(valid_bundle):
    state, events = valid_bundle
    state["goal"]["acceptance_criteria"][0]["expected_evidence"] = ["lint", "build"]
    state["tasks"][0]["expected_evidence"] = ["lint"]
    result = messages(state, events)
    assert "expected evidence does not cover linked criteria" in result
    assert "acceptance criterion lacks valid evidence" in result


def test_failed_unrelated_and_stale_evidence_fail(valid_bundle):
    state, events = valid_bundle
    evidence = state["evidence"][0]
    evidence["exit_code"] = 1
    evidence["relevant"] = False
    evidence["collected_at"] = "2020-01-01T00:00:00Z"
    result = messages(state, events)
    assert "command failed" in result
    assert "unrelated" in result
    assert "stale" in result


@pytest.mark.parametrize("events", [
    [{"event_type": "invocation_attempt", "invocation_id": "inv-1", "capability": "core-builder"}],
    [
        {"event_type": "invocation_attempt", "invocation_id": "inv-1", "capability": "core-builder"},
        {"event_type": "invocation_result", "invocation_id": "inv-1", "capability": "core-builder", "result": "failed"},
    ],
])
def test_attempt_only_or_failed_skill_does_not_count(valid_bundle, events):
    state, _ = valid_bundle
    assert "no successful correlated invocation" in messages(state, events)


def test_pretooluse_generic_event_does_not_count(valid_bundle):
    state, _ = valid_bundle
    events = [{"event_type": "PreToolUse", "capability": "core-builder", "invocation_id": "inv-1"}]
    assert "no successful correlated invocation" in messages(state, events)


def test_out_of_scope_diff_fails(valid_bundle):
    state, events = valid_bundle
    state["changes"]["files"] = ["product/secret.ts"]
    assert "out-of-scope diff" in messages(state, events)


def test_same_responsibility_group_reviewer_fails(valid_bundle):
    state, events = valid_bundle
    state["reviews"][0]["responsibility_group"] = "implementation"
    assert "implementer responsibility group" in messages(state, events)


@pytest.mark.parametrize("flag", ["deleted", "skips_added", "threshold_loosened", "assertions_changed"])
def test_test_integrity_changes_need_separate_review(valid_bundle, flag):
    state, events = valid_bundle
    state["changes"]["test_changes"] = {flag: True}
    assert "test-integrity review" in messages(state, events)


def test_missing_domain_gate_fails(valid_bundle):
    state, events = valid_bundle
    state["quality_profile"]["domains"]["config/agent"]["required_gates"].append("portability")
    assert "required quality gate missing: portability" in messages(state, events)


def test_review_must_bind_exact_diff(valid_bundle):
    state, events = valid_bundle
    state["reviews"][0]["diff_hash"] = "0" * 64
    assert "not bound to current" in messages(state, events)


def test_invocation_result_cannot_change_actor_or_capability(valid_bundle):
    state, events = valid_bundle
    events[1]["actor"] = "different-worker"
    events[1]["capability"] = "different-capability"
    result = messages(state, events)
    assert "capability changed" in result
    assert "no successful correlated invocation" in result


def test_evidence_must_match_registered_command_and_summary_hash(valid_bundle):
    state, events = valid_bundle
    state["evidence"][0]["command"]["args"] = ["echo", "OK"]
    state["evidence"][0]["artifact_hash"] = "0" * 64
    result = messages(state, events)
    assert "command does not match registered gate" in result
    assert "artifact hash does not match" in result


def test_cancelled_task_cannot_authorize_broad_or_secret_path(valid_bundle):
    state, events = valid_bundle
    state["tasks"].append({
        "task_id": "cancelled-broad", "goal_id": state["goal"]["goal_id"],
        "goal_version": state["goal"]["version"], "criterion_ids": ["criterion-1"],
        "allowed_paths": ["**"], "expected_evidence": ["lint"],
        "status": "cancelled", "evidence_ids": [],
    })
    assert "path exceeds GoalContract scope" in messages(state, events)


def test_reviewer_identity_and_rerun_collector_must_be_independent(valid_bundle):
    state, events = valid_bundle
    state["reviews"][0]["reviewer"] = "worker-a"
    state["evidence"][0]["collector"] = "somebody-else"
    result = messages(state, events)
    assert "actor/implementer identity is not independent" in result
    assert "did not collect its rerun evidence" in result


def test_project_review_policy_binds_distinct_successful_actor_invocations(valid_bundle):
    state, events = valid_bundle
    state["quality_profile"]["review"] = {
        "record_must_bind": ["implementer_invocation_id", "reviewer_invocation_id", "actor_identity_assurance"]
    }
    state["changes"]["implementer_invocation_id"] = "inv-1"
    state["reviews"][0].update({
        "implementer_invocation_id": "inv-1",
        "reviewer_invocation_id": "inv-review",
        "actor_identity_assurance": "host-hook-observed",
    })
    report = validate_state(state, events)
    assert report["valid"], report
    assert any("not a security boundary" in warning for warning in report["warnings"])

    state["reviews"][0]["actor_identity_assurance"] = "declared-codex"
    assert "not host-hook-observed" in messages(state, events)
    state["reviews"][0]["actor_identity_assurance"] = "host-hook-observed"
    state["reviews"][0]["reviewer_invocation_id"] = "inv-1"
    result = messages(state, events)
    assert "reviewer identity lacks a successful correlated invocation" in result
    assert "invocation identities are not independently bound" in result


def test_local_hmac_is_declared_as_integrity_only_not_host_security(valid_bundle):
    state, events = valid_bundle
    assert state["attestation_authority"]["same_user_adversary_resistant"] is False
    report = validate_state(state, events)
    assert report["valid"], report
    assert any("same-user processes" in warning for warning in report["warnings"])


def test_invented_waiver_fails_but_original_user_authorization_is_bound(valid_bundle):
    state, events = valid_bundle
    source = "SUPERVISOR-WAIVE:criterion-1 accept documented baseline"
    source_hash = hashlib.sha256(source.encode()).hexdigest()
    waiver = {
        "contract": "UserWaiver/v3", "waiver_id": "waiver-1", "criterion_id": "criterion-1",
        "authorized_by": "user", "source_authorization": source,
        "source_authorization_sha256": source_hash, "reason": "documented baseline",
        "authorized_at": state["started_at"],
    }
    state["evidence"][0]["criterion_id"] = "criterion-quality"
    state["goal"]["acceptance_criteria"].append({
        "criterion_id": "criterion-quality", "description": "Quality gate passes",
        "domain": "config-agent", "expected_evidence": ["lint"], "required": False,
    })
    state["tasks"][0]["criterion_ids"] = ["criterion-quality"]
    state["waivers"] = [waiver]
    assert "lacks original authorization" in messages(state, events)
    state["goal"]["waiver_authorizations"] = [{"criterion_id": "criterion-1", "request_sha256": source_hash}]
    reseal_request_manifest(state)
    report = validate_state(state, events)
    assert report["valid"], report
    assert report["waived_criteria"] == ["criterion-1"]


def test_core_observes_real_workspace_delta_not_declared_state(tmp_path):
    workspace = tmp_path / "repo"
    workspace.mkdir()
    subprocess.run(["git", "init", "-q", str(workspace)], check=True)
    subprocess.run(["git", "-C", str(workspace), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(workspace), "config", "user.name", "Supervisor Test"], check=True)
    (workspace / "config.json").write_text("{}\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(workspace), "add", "config.json"], check=True)
    subprocess.run(["git", "-C", str(workspace), "commit", "-qm", "baseline"], check=True)
    ctx = StateContext.build(runtime="codex", project="p", workspace=str(workspace), session="s", round_id="r", state_root=tmp_path / "state")
    state = start_round(
        ctx, message="change config", change_mode="replace", execution_mode="observe",
        project_config={"supervisor_scope": {"allowed_change_globs": ["config.json"]}}, quality_profile={},
    )
    (workspace / "config.json").write_text('{"v":3}\n', encoding="utf-8")
    report = validate_state(state, [])
    assert any("real workspace diff omitted" in error and "config.json" in error for error in report["errors"])


def test_observed_paths_force_quality_domains_and_test_integrity():
    profile = {
        "profiles": {
            "ui": {"applies_to": ["src/**/*.tsx"]},
            "api_db": {"applies_to": ["src/app/api/**", "drizzle/**"]},
            "config_agent": {"applies_to": [".agent-supervisor/**", "AGENTS.md"]},
        }
    }
    domains = _domains_from_observed(profile, ["src/app/student/page.tsx", "src/app/api/users/route.ts", "AGENTS.md", "tests/auth.test.ts"])
    assert {"ui", "api/db", "config/agent", "code"}.issubset(domains)


def test_observed_test_change_requires_separate_integrity_review(valid_bundle):
    state, events = valid_bundle
    errors = []
    _validate_changes_and_reviews(
        state,
        {row["evidence_id"]: row for row in state["evidence"]},
        events,
        errors,
        [],
        {"files": ["tests/new-behavior.test.ts"], "base": state["changes"]["base"], "head": state["changes"]["head"], "diff_hash": state["changes"]["diff_hash"]},
    )
    assert any("test-integrity review" in error for error in errors)


def test_zero_skill_requires_review(valid_bundle):
    state, _ = valid_bundle
    state["intents"][0].update(status="skipped", reason="no domain capability", capability_ids=[])
    assert "zero-skill round lacks" in messages(state, [])
    state["reviews"][0]["category"] = "zero-skill-routing"
    assert "zero-skill round lacks" not in messages(state, [])
