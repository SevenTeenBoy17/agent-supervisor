from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess

import pytest
from jsonschema import Draft202012Validator

from supervisor_core.attestation import sign_record
from supervisor_core.contracts import invocation_event, validate_review_shape
from supervisor_core.validation import (
    _domains_from_observed,
    _path_allowed,
    _pattern_within,
    _trusted_invocation_for_runtime,
    _validate_changes_and_reviews,
    validate_state,
)
from supervisor_core.lifecycle import start_round
from supervisor_core.storage import StateContext
from supervisor_core.util import canonical_sha256, redact, redact_for_persistence


def messages(state, events):
    return "\n".join(validate_state(state, events)["errors"])


@pytest.mark.parametrize("boolean_version", [True, False])
def test_review_goal_version_rejects_boolean_int_subclasses(
    valid_bundle, boolean_version: bool,
) -> None:
    state, _ = copy.deepcopy(valid_bundle)
    state["reviews"][0]["goal_version"] = boolean_version
    assert validate_review_shape(state["reviews"][0]) is False


def reseal_request_manifest(state, events=None):
    manifest = state["request_manifest"]
    manifest["goal_id"] = state["goal"]["goal_id"]
    manifest["goal_version"] = state["goal"]["version"]
    manifest["goal_sha256"] = canonical_sha256(state["goal"])
    manifest["original_request_sha256"] = state["goal"]["original_request_sha256"]
    manifest["intents"] = copy.deepcopy(state["intent_manifest"])
    manifest["attestation"] = sign_record(manifest)
    if events is not None:
        binding = {
            "runtime": state["runtime"],
            "project": state["project"],
            "workspace": str(Path(state["workspace"]).resolve()),
            "session": state["session"],
            "round": state["round"],
            "goal_id": state["goal"]["goal_id"],
            "goal_version": state["goal"]["version"],
            "request_manifest_sha256": canonical_sha256(manifest),
        }
        for event in events:
            event["details"].update(binding)
            event["attestation"] = sign_record(event)


def test_valid_structured_state_passes(valid_bundle):
    state, events = valid_bundle
    report = validate_state(state, events)
    assert report["valid"], report


@pytest.mark.parametrize(
    "authorization",
    [
        "a" * 64,
        {"action_sha256": "a" * 64},
        {"action_sha256": "not-a-hash", "request_sha256": "b" * 64},
        {"action_sha256": "a" * 64, "request_sha256": "b" * 64, "extra": True},
    ],
)
def test_t3_authorization_requires_exact_action_and_granting_request_hashes(valid_bundle, authorization):
    state, events = valid_bundle
    state["goal"]["t3_action_authorizations"] = [authorization]
    reseal_request_manifest(state, events)

    assert "GoalContract T3 authorization" in messages(state, events)


def test_goal_contract_schema_binds_t3_action_to_granting_request(valid_bundle):
    state, _ = valid_bundle
    root_schema = json.loads(
        (Path(__file__).resolve().parents[1] / "schemas" / "contracts.schema.json").read_text(
            encoding="utf-8"
        )
    )
    schema = {
        "$schema": root_schema["$schema"],
        "$defs": root_schema["$defs"],
        "$ref": "#/$defs/GoalContract",
    }
    validator = Draft202012Validator(schema)
    valid = copy.deepcopy(state["goal"])
    valid["t3_action_authorizations"] = [{
        "action_sha256": "a" * 64,
        "request_sha256": "b" * 64,
    }]
    assert list(validator.iter_errors(valid)) == []

    valid["t3_action_authorizations"] = ["a" * 64]
    assert list(validator.iter_errors(valid))


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


def test_signed_request_manifest_rejects_omitted_intent(valid_bundle):
    state, events = valid_bundle
    state["intents"] = []
    state["intent_manifest"] = []
    result = messages(state, events)
    assert "changed after trusted start" in result


def test_signed_request_manifest_rejects_goal_rewrite_independently(valid_bundle):
    state, events = valid_bundle
    assert state["intents"] and state["intent_manifest"]
    state["goal"]["objective"] = "silently replaced objective"
    result = messages(state, events)
    assert "GoalContract or atomic intent manifest changed after trusted start" in result


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


def test_invalid_round_timestamp_is_reported_without_crashing_validator(valid_bundle):
    state, events = valid_bundle
    state["started_at"] = "not-a-timestamp"
    report = validate_state(state, events)
    assert report["valid"] is False
    assert any("state started_at invalid" in error for error in report["errors"])


@pytest.mark.parametrize("invalid_started_at", [None, 123, [], {}])
def test_non_string_round_timestamp_is_rejected_without_crashing_validator(valid_bundle, invalid_started_at):
    state, events = valid_bundle
    state["started_at"] = invalid_started_at

    report = validate_state(state, events)

    assert report["valid"] is False
    assert any("state started_at invalid" in error for error in report["errors"])


@pytest.mark.parametrize("events", [
    [{"event_type": "invocation_attempt", "invocation_id": "inv-1", "capability": "core-builder"}],
    [
        {"event_type": "invocation_attempt", "invocation_id": "inv-1", "capability": "core-builder"},
        {"event_type": "invocation_result", "invocation_id": "inv-1", "capability": "core-builder", "result": "failed"},
    ],
])
def test_attempt_only_or_failed_skill_does_not_count(valid_bundle, events):
    state, _ = valid_bundle
    assert "no completion-trusted correlated invocation" in messages(state, events)


def test_pretooluse_generic_event_does_not_count(valid_bundle):
    state, _ = valid_bundle
    events = [{"event_type": "PreToolUse", "capability": "core-builder", "invocation_id": "inv-1"}]
    assert "no completion-trusted correlated invocation" in messages(state, events)


def test_manual_specialized_cannot_cover_without_correlated_success(valid_bundle):
    state, events = valid_bundle
    state["intents"][0].update(
        method="manual-specialized",
        capability_ids=["manual-only-capability"],
        reason="a human could run this outside the model",
    )
    assert "no completion-trusted correlated invocation" in messages(state, events)


@pytest.mark.parametrize(
    "candidate",
    ["../config.json", "..\\config.json", "/config.json", "C:/config.json", "//server/share/config.json"],
)
def test_scope_helpers_reject_parent_absolute_drive_and_unc_paths(candidate):
    assert _path_allowed(candidate, ["config.json", "config/**"]) is False
    assert _pattern_within(candidate, "config/**") is False


def test_out_of_scope_diff_fails(valid_bundle):
    state, events = valid_bundle
    state["changes"]["files"] = ["product/secret.ts"]
    assert "out-of-scope diff" in messages(state, events)


def test_same_responsibility_group_reviewer_fails(valid_bundle):
    state, events = valid_bundle
    state["reviews"][0]["reviewer_responsibility_group"] = "implementation"
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
    assert "completion-trusted correlated invocation" in result


def test_host_observed_invocation_cannot_be_replayed_across_rounds(valid_bundle):
    state, events = valid_bundle
    state["round"] = "round-b"
    state["request_manifest"]["round"] = "round-b"
    state["request_manifest"]["attestation"] = sign_record(state["request_manifest"])
    assert "not bound to the active round" in messages(state, events)


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


def test_malformed_scope_policy_entry_fails_closed(valid_bundle):
    state, events = valid_bundle
    state["project_policy"] = {
        "allowed_change_globs": ["config.json", None],
        "out_of_scope_globs": ["product/**", {"bad": "shape"}],
    }
    result = messages(state, events)
    assert "project policy allowed_change_globs invalid" in result
    assert "project policy out_of_scope_globs invalid" in result


def test_reviewer_and_gate_collector_are_separately_bound(valid_bundle):
    state, events = valid_bundle
    state["reviews"][0]["gate_collector"] = "reviewer-a"
    state["evidence"][0]["collector"] = "reviewer-a"
    result = messages(state, events)
    assert "gate collector is not independent" in result


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


@pytest.mark.parametrize(
    "forged_assurance",
    ["codex-explicit-audit", "codex-hook-observation", "host-hook-observed"],
)
def test_codex_caller_forged_identity_cannot_complete_implementation_review_or_gate(
    valid_bundle,
    forged_assurance: str,
) -> None:
    state, events = copy.deepcopy(valid_bundle)
    state["runtime"] = "codex"
    state["request_manifest"]["runtime"] = "codex"
    state["request_manifest"]["attestation"] = sign_record(state["request_manifest"])
    binding = {
        "runtime": "codex",
        "project": state["project"],
        "workspace": str(Path(state["workspace"]).resolve()),
        "session": state["session"],
        "round": state["round"],
        "goal_id": state["goal"]["goal_id"],
        "goal_version": state["goal"]["version"],
        "request_manifest_sha256": canonical_sha256(state["request_manifest"]),
    }
    for event in events:
        event["identity_assurance"] = forged_assurance
        event["details"].update(binding)
        event["attestation"] = sign_record(event)
    state["reviews"][0]["actor_identity_assurance"] = forged_assurance
    state["reviews"][0]["request_manifest_sha256"] = canonical_sha256(
        state["request_manifest"]
    )
    state["reviews"][0]["attestation"] = sign_record(state["reviews"][0])
    state["terminal_state"] = "complete"

    report = validate_state(state, events)

    assert report["valid"] is False
    combined = "\n".join(report["errors"])
    assert not _trusted_invocation_for_runtime(
        events,
        "inv-1",
        actor="worker-a",
        responsibility_group="implementation",
        state=state,
    )
    assert not _trusted_invocation_for_runtime(
        events,
        "inv-review",
        actor="reviewer-a",
        responsibility_group="quality-review",
        state=state,
    )
    assert not _trusted_invocation_for_runtime(
        events,
        "inv-gate-runner",
        actor="gate-runner-a",
        responsibility_group="independent-gate-execution",
        state=state,
    )
    assert "acceptance criterion lacks valid evidence" in combined


def test_codex_core_trusted_builtin_invocation_remains_valid(valid_bundle) -> None:
    state, _ = copy.deepcopy(valid_bundle)
    state["runtime"] = "codex"
    state["request_manifest"]["runtime"] = "codex"
    state["request_manifest"]["attestation"] = sign_record(state["request_manifest"])
    invocation_id = "inv-core-builtin-goal-finalize"
    binding = {
        "runtime": "codex",
        "project": state["project"],
        "workspace": str(Path(state["workspace"]).resolve()),
        "session": state["session"],
        "round": state["round"],
        "goal_id": state["goal"]["goal_id"],
        "goal_version": state["goal"]["version"],
        "request_manifest_sha256": canonical_sha256(state["request_manifest"]),
        "phase": "builtin-finalize",
        "gate_id": "research.goal-finalize",
        "criterion_id": "criterion-1",
    }
    events = [
        invocation_event(
            invocation_id=invocation_id,
            capability="supervisor-core-builtin:research.goal-finalize",
            stage=stage,
            result=result,
            actor="supervisor-core",
            responsibility_group="trusted-runtime",
            identity_assurance="core-trusted-finalize",
            details=binding,
        )
        for stage, result in (("attempt", None), ("result", "success"))
    ]

    assert _trusted_invocation_for_runtime(
        events,
        invocation_id,
        actor="supervisor-core",
        responsibility_group="trusted-runtime",
        state=state,
    )


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
    reseal_request_manifest(state, events)
    report = validate_state(state, events)
    assert report["valid"], report
    assert report["waived_criteria"] == ["criterion-1"]


def test_nested_goal_event_and_evidence_credentials_are_redacted_without_mutating_waiver_hashes():
    uri_userinfo = (
        "https://" + "fixture-user" + ":" + "fixture-pass" + "@" + "example.invalid" + "/resource"
    )
    jwt = "eyJ" + "a" * 18 + "." + "b" * 24 + "." + "c" * 24
    database_url = (
        "postgresql://" + "fixture-db" + ":" + "fixture-pass" + "@" + "db.invalid" + "/app"
    )
    connection_string = (
        "Server=db.invalid;Database=fixture;User Id=fixture;Password=fixture-pass"
    )
    cloud_token = "AKIA" + "A" * 16
    payment_token = "sk_" + "live_" + "p" * 24
    hugging_face_token = "hf_" + "h" * 32
    linear_token = "lin_" + "api_" + "l" * 32
    sentry_token = "sntrys_" + "s" * 32
    sas_url = (
        "https://storage.invalid/object?sv=2024-01-01&sp=rl&sig=" + "q" * 32
    )
    gcs_url = (
        "https://storage.invalid/object?X-Goog-Algorithm=GOOG4-RSA-SHA256"
        "&X-Goog-Credential=fixture%2Fscope&X-Goog-Signature=" + "g" * 64
    )
    waiver_hash = hashlib.sha256(b"fixture-waiver-authorization").hexdigest()
    payload = {
        "goal": {
            "objective": f"inspect {uri_userinfo}",
            "constraints": [f"bearer {jwt}"],
            "waiver_authorizations": [
                {"criterion_id": "criterion-1", "request_sha256": waiver_hash}
            ],
        },
        "event": {
            "details": {
                "argv": [
                    "runner",
                    "--database-url",
                    database_url,
                    f"--connection-string={connection_string}",
                    "--access-token",
                    cloud_token,
                ]
            }
        },
        "evidence": {
            "output_summary": (
                f"provider={payment_token}; jwt={jwt}; hf={hugging_face_token}; "
                f"linear={linear_token}; sentry={sentry_token}; sas={sas_url}; gcs={gcs_url}"
            ),
        },
    }

    clean = redact(payload)
    serialized = json.dumps(clean, sort_keys=True)

    for secret in (
        uri_userinfo,
        jwt,
        database_url,
        connection_string,
        cloud_token,
        payment_token,
        hugging_face_token,
        linear_token,
        sentry_token,
        sas_url,
        gcs_url,
    ):
        assert secret not in serialized
    assert clean["goal"]["waiver_authorizations"][0]["request_sha256"] == waiver_hash
    assert "[REDACTED]" in serialized


def test_hash_bound_nested_credential_is_rejected_without_echoing_value():
    database_url = (
        "postgresql://" + "fixture-db" + ":" + "fixture-pass" + "@" + "db.invalid" + "/app"
    )
    attested_event = {
        "event": {
            "contract": "InvocationEvent/v3",
            "details": {"connection": database_url},
            "attestation": "a" * 64,
        }
    }

    with pytest.raises(ValueError) as failure:
        redact_for_persistence(attested_event)

    assert database_url not in str(failure.value)
    assert str(failure.value) == "sensitive-integrity-bound-record"


def test_core_observes_real_workspace_delta_not_declared_state(tmp_path, monkeypatch):
    workspace = tmp_path / "repo"
    workspace.mkdir()
    git_discovery_variables = (
        "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR",
        "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    )
    for variable in git_discovery_variables:
        monkeypatch.setenv(variable, str(tmp_path / "hostile-git-environment" / variable))
    git_env = os.environ.copy()
    for variable in git_discovery_variables:
        git_env.pop(variable, None)
    git_env["GIT_CONFIG_NOSYSTEM"] = "1"
    git_env["GIT_CONFIG_GLOBAL"] = os.devnull
    subprocess.run(["git", "init", "-q", str(workspace)], check=True, env=git_env)
    subprocess.run(["git", "-C", str(workspace), "config", "user.email", "test@example.invalid"], check=True, env=git_env)
    subprocess.run(["git", "-C", str(workspace), "config", "user.name", "Supervisor Test"], check=True, env=git_env)
    (workspace / "config.json").write_text("{}\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(workspace), "add", "config.json"], check=True, env=git_env)
    subprocess.run(["git", "-C", str(workspace), "commit", "-qm", "baseline"], check=True, env=git_env)
    for variable in git_discovery_variables:
        monkeypatch.delenv(variable, raising=False)
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
    state, events = valid_bundle
    state["intents"][0].update(status="skipped", reason="no domain capability", capability_ids=[])
    assert "zero-skill round lacks" in messages(state, [])
    state["reviews"][0]["category"] = "zero-skill-routing"
    state["reviews"][0]["request_manifest_sha256"] = canonical_sha256(state["request_manifest"])
    state["reviews"][0]["attestation"] = sign_record(state["reviews"][0])
    state["changes"]["files"] = []
    assert "zero-skill round lacks" not in messages(state, events)


def test_zero_skill_review_rejects_same_actor_and_responsibility_group(valid_bundle):
    state, events = valid_bundle
    state["changes"]["files"] = []
    state["intents"][0].update(status="skipped", reason="no healthy matching capability", capability_ids=[])
    review = state["reviews"][0]
    review.update(
        category="zero-skill-routing",
        implementer=review["reviewer"],
        implementer_responsibility_group=review["reviewer_responsibility_group"],
        implementer_invocation_id=review["reviewer_invocation_id"],
        request_manifest_sha256=canonical_sha256(state["request_manifest"]),
    )
    assert "zero-skill round lacks" in messages(state, events)


def test_overlapping_active_task_leases_fail(valid_bundle):
    state, events = valid_bundle
    first = state["tasks"][0]
    first.update(
        status="doing",
        owner="worker-a",
        responsibility_group="implementation-a",
        lease_id="lease-a",
        lease_status="active",
    )
    second = copy.deepcopy(first)
    second.update(
        task_id="task-2",
        owner="worker-b",
        responsibility_group="implementation-b",
        lease_id="lease-b",
    )
    state["tasks"].append(second)
    assert "overlapping active path leases" in messages(state, events)
