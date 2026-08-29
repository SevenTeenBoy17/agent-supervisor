from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import types

import pytest

from supervisor_core import cli as cli_module
from supervisor_core.attestation import sign_record
from supervisor_core.contracts import invocation_event
from supervisor_core.lifecycle import start_round
from supervisor_core.storage import StateContext
from supervisor_core.util import canonical_sha256, sha256_bytes, sha256_file
from supervisor_core.validation import validate_state
from supervisor_core import workspace as workspace_module
from supervisor_core.workspace import capture_workspace_snapshot, workspace_delta


BINDING_FIELDS = (
    "base", "head", "git_object_format", "git_binding_status",
    "git_binding_source", "git_repository_root", "review_artifact_sha256",
    "git_diff_sha256", "workspace_base_sha256", "workspace_head_sha256",
    "diff_hash",
)


def test_external_review_environment_excludes_product_and_token_secrets(
    tmp_path: Path, monkeypatch
) -> None:
    trusted = tmp_path / "python.exe"
    trusted.write_bytes(b"trusted\n")
    registry = {
        "registry_sha256": "a" * 64,
        "entries": {
            "python": {
                "kind": "local",
                "path": str(trusted.resolve()),
                "sha256": sha256_file(trusted),
            }
        },
    }
    forbidden = {
        "DATABASE_URL": "sensitive-database-value",
        "WECHAT_PAY_PRIVATE_KEY": "sensitive-payment-value",
        "OPENAI_API_KEY": "sensitive-provider-value",
        "VERCEL_TOKEN": "sensitive-deployment-value",
    }
    for name, value in forbidden.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("SYSTEMROOT", str(tmp_path))

    environment = cli_module._isolated_review_environment(
        registry,
        {"AGENT_SUPERVISOR_REVIEW_BINDING_FILE": str(tmp_path / "binding.json")},
    )

    assert not (set(forbidden) & set(environment))
    assert environment["PATH"] == str(trusted.parent)
    assert environment["AGENT_SUPERVISOR_TRUST_REGISTRY_SHA256"] == "a" * 64
    assert environment["AGENT_SUPERVISOR_REVIEW_BINDING_FILE"].endswith("binding.json")


def test_bound_review_source_manifest_mismatch_fails_before_review(
    tmp_path: Path,
) -> None:
    module_name = "_agent_supervisor_review_source"
    bound = types.ModuleType(module_name)
    bound.contract = "SupervisorReviewSource/v1"
    bound.profile_root = str(tmp_path.resolve())
    bound.resources = {"supervisor_core/immutable.py": b"VALUE = 1\n"}
    bound.core_manifest_sha256 = "0" * 64
    previous = sys.modules.get(module_name)
    sys.modules[module_name] = bound
    runner = Path(cli_module.__file__).resolve().parents[1] / "bin" / "run-coderabbit-review.py"
    try:
        with pytest.raises(RuntimeError, match="bound review source manifest mismatch"):
            runpy.run_path(str(runner), run_name="__supervisor_bound_review_mismatch__")
    finally:
        if previous is None:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = previous


def test_bound_review_source_uses_release_adapter_names_and_exact_core_manifest(
    tmp_path: Path,
) -> None:
    module_name = "_agent_supervisor_review_source"
    bound = types.ModuleType(module_name)
    bound.contract = "SupervisorReviewSource/v1"
    bound.profile_root = str(tmp_path.resolve())
    bound.resources = {
        "supervisor_core/__init__.py": b"VERSION = 'test'\n",
        "integrations/codex/scripts/hook.py": b"CODEX = True\n",
        "integrations/claude/scripts/hook.py": b"CLAUDE = True\n",
    }
    core_manifest = {
        f"global-core/{name}": sha256_bytes(content)
        for name, content in sorted(bound.resources.items())
    }
    bound.core_manifest_sha256 = canonical_sha256(core_manifest)
    previous = sys.modules.get(module_name)
    sys.modules[module_name] = bound
    runner = Path(cli_module.__file__).resolve().parents[1] / "bin" / "run-coderabbit-review.py"
    try:
        loaded = runpy.run_path(str(runner), run_name="__supervisor_bound_review_valid__")
        groups = loaded["source_groups"]()
        destination = tmp_path / "review"
        destination.mkdir()
        manifest = loaded["prepare_review_tree"](destination, groups)
    finally:
        if previous is None:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = previous
    observed = {row["path"]: row["sha256"] for row in manifest}
    assert {
        path: digest for path, digest in observed.items() if path.startswith("global-core/")
    } == core_manifest
    assert observed["global-codex/scripts/hook.py"] == sha256_bytes(b"CODEX = True\n")
    assert observed["global-claude/scripts/hook.py"] == sha256_bytes(b"CLAUDE = True\n")


def test_release_adapter_manifest_is_projected_from_immutable_resources() -> None:
    resources = {
        "supervisor_core/__init__.py": b"core\n",
        "integrations/codex/scripts/hook.py": b"codex\n",
        "integrations/claude/scripts/hook.py": b"claude\n",
    }
    manifest = cli_module._review_adapter_manifest(resources)
    assert manifest == {
        "global-claude/scripts/hook.py": sha256_bytes(b"claude\n"),
        "global-codex/scripts/hook.py": sha256_bytes(b"codex\n"),
    }


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    env = os.environ.copy()
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    for variable in (
        "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR",
        "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    ):
        env.pop(variable, None)
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=check,
        capture_output=True,
        env=env,
    )


def _repo_with_two_commits(tmp_path: Path, *, object_format: str = "sha1") -> tuple[Path, str, str]:
    repo = tmp_path / f"repo-{object_format}"
    repo.mkdir()
    init = ["init", "-q"]
    if object_format == "sha256":
        init.append("--object-format=sha256")
    result = _git(repo, *init, check=False)
    if result.returncode != 0:
        pytest.skip("host Git does not support SHA-256 repositories")
    _git(repo, "config", "user.email", "test@example.invalid")
    _git(repo, "config", "user.name", "Supervisor Test")
    (repo / "config.json").write_bytes(b'{"v":1}\n')
    _git(repo, "add", "config.json")
    _git(repo, "commit", "-qm", "base")
    base = _git(repo, "rev-parse", "HEAD").stdout.decode().strip()
    (repo / "config.json").write_bytes(b'{"v":2}\n')
    _git(repo, "add", "config.json")
    _git(repo, "commit", "-qm", "head")
    head = _git(repo, "rev-parse", "HEAD").stdout.decode().strip()
    return repo, base, head


def _review_output_artifact(
    tmp_path: Path,
    binding: dict,
    *,
    suffix: str,
    before: bytes | None = b'{"v":2}\n',
    after: bytes = b'{"v":3}\n',
    executable_payload: bool = False,
) -> dict:
    repo = tmp_path / f"artifact-repo-{suffix}"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "artifact@example.invalid")
    _git(repo, "config", "user.name", "Review Artifact")
    payload_manifest = {
        "files": [{"path": "config.json", "sha256": sha256_bytes(after)}]
    }
    review_manifest_bytes = (
        json.dumps(payload_manifest, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    (repo / "REVIEW_MANIFEST.json").write_bytes(review_manifest_bytes)
    (repo / "CONTEXT.md").write_bytes(b"bounded review context\n")
    if before is not None:
        (repo / "config.json").write_bytes(before)
    _git(repo, "add", "REVIEW_MANIFEST.json", "CONTEXT.md")
    if before is not None:
        _git(repo, "add", "config.json")
    _git(repo, "commit", "-qm", "artifact baseline")
    base = _git(repo, "rev-parse", "HEAD").stdout.decode().strip()
    (repo / "config.json").write_bytes(after)
    _git(repo, "add", "config.json")
    if executable_payload:
        _git(repo, "update-index", "--chmod=+x", "config.json")
    _git(repo, "commit", "-qm", "artifact head")
    head = _git(repo, "rev-parse", "HEAD").stdout.decode().strip()
    bundle = tmp_path / f"review-{suffix}.bundle"
    _git(repo, "bundle", "create", str(bundle), "--all")
    rendered = _git(
        repo, "diff", "--binary", "--full-index", "--no-ext-diff", base, head
    ).stdout
    source_review_manifest = {
        "CONTEXT.md": sha256_bytes(b"bounded review context\n"),
        "REVIEW_MANIFEST.json": sha256_bytes(review_manifest_bytes),
        "config.json": sha256_bytes(after),
    }
    manifest = {
        "contract": "ReviewArtifactManifest/v1",
        "git_binding_source": "review-artifact",
        "review_mode": "full-snapshot",
        "bundle_sha256": sha256_file(bundle),
        "git_object_format": "sha1",
        "base": base,
        "head": head,
        "diff_hash": binding["diff_hash"],
        "git_diff_sha256": sha256_bytes(rendered),
        "workspace_base_sha256": binding["workspace_base_sha256"],
        "workspace_head_sha256": binding["workspace_head_sha256"],
        "files": sorted(binding["workspace_delta_manifest"]),
        "workspace_delta_manifest": copy.deepcopy(
            binding["workspace_delta_manifest"]
        ),
        "source_review_manifest": source_review_manifest,
        "source_review_manifest_sha256": canonical_sha256(
            source_review_manifest
        ),
    }
    manifest_file = tmp_path / f"review-{suffix}.manifest.json"
    manifest_file.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    return {
        "contract": "ReviewOutputArtifact/v1",
        "review_category": "independent",
        "review_artifact": {
            "kind": "git-bundle-v1",
            "bundle_path": str(bundle.resolve()),
            "bundle_sha256": manifest["bundle_sha256"],
            "manifest_path": str(manifest_file.resolve()),
            "manifest_sha256": sha256_file(manifest_file),
        },
        "review_summary": {
            "engine": "coderabbit",
            "authenticated": True,
            "status": "pass",
            "exit_code": 0,
            "structured_events": 1,
            "terminal_outcome": "success",
            "finding_count": 0,
            "complete_reported_findings": 0,
            "blocking_findings": 0,
            "severity_counts": {"critical": 0, "major": 0, "minor": 0},
            "protocol_blockers": [],
            "context_bound": True,
            "issues": [],
            "stdout_sha256": sha256_bytes(b""),
            "stderr_sha256": sha256_bytes(b""),
        },
        "base": base,
        "head": head,
        "git_object_format": "sha1",
        "git_diff_sha256": manifest["git_diff_sha256"],
        "workspace_base_sha256": binding["workspace_base_sha256"],
        "workspace_head_sha256": binding["workspace_head_sha256"],
        "diff_hash": binding["diff_hash"],
    }


def _resign_round(state: dict, events: list[dict]) -> None:
    state["request_manifest"]["workspace"] = str(Path(state["workspace"]).resolve())
    state["request_manifest"]["attestation"] = sign_record(state["request_manifest"])
    binding = {
        "runtime": state["runtime"],
        "project": state["project"],
        "workspace": str(Path(state["workspace"]).resolve()),
        "session": state["session"],
        "round": state["round"],
        "goal_id": state["goal"]["goal_id"],
        "goal_version": state["goal"]["version"],
        "request_manifest_sha256": canonical_sha256(state["request_manifest"]),
    }
    for event in events:
        event["details"].update(binding)
        event["attestation"] = sign_record(event)
    state["reviews"][0]["request_manifest_sha256"] = canonical_sha256(state["request_manifest"])
    state["reviews"][0]["attestation"] = sign_record(state["reviews"][0])


def _set_binding(state: dict, binding: dict) -> None:
    for field in BINDING_FIELDS:
        state["changes"][field] = binding.get(field)
        state["evidence"][0][field] = binding.get(field)
        state["reviews"][0][field] = binding.get(field)
    state["changes"]["review_artifact"] = copy.deepcopy(binding.get("review_artifact"))
    state["reviews"][0]["attestation"] = sign_record(state["reviews"][0])


def test_independent_gate_runner_and_reviewer_contract_passes(valid_bundle):
    state, events = valid_bundle
    report = validate_state(state, events)
    assert report["valid"], report


def test_reviewer_self_collection_wrong_group_and_implementer_group_conflict_fail(valid_bundle):
    def fresh_scenario():
        state, events = copy.deepcopy(valid_bundle)
        review = state["reviews"][0]
        evidence = state["evidence"][0]
        assert review["gate_collector"] == "gate-runner-a"
        assert review["gate_collector_responsibility_group"] == "independent-gate-execution"
        assert review["gate_runner_invocation_id"] == "inv-gate-runner"
        assert review["reviewer_responsibility_group"] == "quality-review"
        assert evidence["collector"] == "gate-runner-a"
        assert evidence["collector_responsibility_group"] == "independent-gate-execution"
        assert evidence["collector_invocation_id"] == "inv-gate-runner"
        return state, events

    state, events = fresh_scenario()
    review = state["reviews"][0]
    evidence = state["evidence"][0]
    review["gate_collector"] = review["reviewer"]
    review["gate_collector_responsibility_group"] = review["reviewer_responsibility_group"]
    review["gate_runner_invocation_id"] = review["reviewer_invocation_id"]
    evidence["collector"] = review["reviewer"]
    evidence["collector_responsibility_group"] = review["reviewer_responsibility_group"]
    evidence["collector_invocation_id"] = review["reviewer_invocation_id"]
    assert "gate collector is not independent" in "\n".join(validate_state(state, events)["errors"])

    state, events = fresh_scenario()
    state["evidence"][0]["collector_responsibility_group"] = "wrong-group"
    assert "gate collector does not match rerun evidence" in "\n".join(validate_state(state, events)["errors"])

    state, events = fresh_scenario()
    state["reviews"][0]["gate_collector_responsibility_group"] = "implementation"
    state["evidence"][0]["collector_responsibility_group"] = "implementation"
    assert "gate collector is not independent" in "\n".join(validate_state(state, events)["errors"])

    state, events = fresh_scenario()
    state["reviews"][0]["gate_collector_responsibility_group"] = "forged-independent-group"
    state["evidence"][0]["collector_responsibility_group"] = "forged-independent-group"
    state["reviews"][0]["attestation"] = sign_record(state["reviews"][0])
    errors = "\n".join(validate_state(state, events)["errors"])
    assert "collector invocation lacks accepted runtime assurance" in errors
    assert "gate runner lacks accepted runtime assurance" in errors

    state, events = fresh_scenario()
    state["reviews"][0]["reviewer_responsibility_group"] = "forged-review-group"
    state["reviews"][0]["attestation"] = sign_record(state["reviews"][0])
    assert "reviewer identity is not bound" in "\n".join(
        validate_state(state, events)["errors"]
    )


def test_missing_successful_runner_invocation_and_caller_authored_review_fail(valid_bundle):
    def fresh_scenario():
        return copy.deepcopy(valid_bundle)

    state, events = fresh_scenario()
    events = [event for event in events if not (
        event.get("event_type") == "invocation_result"
        and event.get("invocation_id") == "inv-gate-runner"
    )]
    errors = "\n".join(validate_state(state, events)["errors"])
    assert "collector lacks a successful bound runner invocation" in errors
    assert "gate runner lacks a successful correlated invocation" in errors

    state, events = fresh_scenario()
    state["reviews"][0].pop("attestation")
    state["reviews"][0]["issued_by"] = "caller"
    assert "was not issued by core review_finalize" in "\n".join(validate_state(state, events)["errors"])

    pristine_state, pristine_events = fresh_scenario()
    assert "attestation" in pristine_state["reviews"][0]
    assert pristine_state["reviews"][0]["issued_by"] != "caller"
    assert any(
        event.get("event_type") == "invocation_result"
        and event.get("invocation_id") == "inv-gate-runner"
        for event in pristine_events
    )
    pristine_report = validate_state(pristine_state, pristine_events)
    assert pristine_report["valid"], pristine_report


def test_review_gate_without_core_observed_binding_hash_fails(valid_bundle):
    state, events = valid_bundle
    state["quality_profile"]["common_gates"][0]["id"] = "review.coderabbit"
    state["quality_profile"]["domains"]["config/agent"]["required_gates"] = [
        "review.coderabbit"
    ]
    state["goal"]["acceptance_criteria"][0]["expected_evidence"] = [
        "review.coderabbit"
    ]
    state["tasks"][0]["expected_evidence"] = ["review.coderabbit"]
    state["evidence"][0]["gate_id"] = "review.coderabbit"
    errors = "\n".join(validate_state(state, events)["errors"])
    assert "review gate lacks core-observed binding input" in errors


@pytest.mark.parametrize("object_format", ["sha1", "sha256"])
def test_real_git_commit_binding_accepts_repository_object_format(tmp_path, valid_bundle, object_format):
    repo, base, head = _repo_with_two_commits(tmp_path, object_format=object_format)
    state, events = valid_bundle
    state["workspace"] = str(repo)
    binding = {
        "base": base,
        "head": head,
        "git_object_format": object_format,
        "git_binding_status": "verified",
        "git_binding_source": "workspace",
        "git_repository_root": str(repo.resolve()),
        "review_artifact_sha256": None,
        "git_diff_sha256": None,
        "workspace_base_sha256": state["changes"]["workspace_base_sha256"],
        "workspace_head_sha256": state["changes"]["workspace_head_sha256"],
        "diff_hash": state["changes"]["diff_hash"],
    }
    _set_binding(state, binding)
    _resign_round(state, events)
    report = validate_state(state, events)
    assert report["valid"], report


def test_nonexistent_nonancestor_pseudo_workspace_hash_and_diff_misbinding_fail(tmp_path, valid_bundle):
    repo, base, head = _repo_with_two_commits(tmp_path)
    state, events = valid_bundle
    state["workspace"] = str(repo)
    binding = {
        "base": base,
        "head": "f" * 40,
        "git_object_format": "sha1",
        "git_binding_status": "verified",
        "git_binding_source": "workspace",
        "git_repository_root": str(repo.resolve()),
        "review_artifact_sha256": None,
        "git_diff_sha256": None,
        "workspace_base_sha256": state["changes"]["workspace_base_sha256"],
        "workspace_head_sha256": state["changes"]["workspace_head_sha256"],
        "diff_hash": state["changes"]["diff_hash"],
    }
    _set_binding(state, binding)
    _resign_round(state, events)
    assert "git-head-commit-unresolvable" in "\n".join(validate_state(state, events)["errors"])

    _git(repo, "switch", "--orphan", "unrelated")
    (repo / "other.txt").write_text("unrelated\n", encoding="utf-8")
    _git(repo, "add", "other.txt")
    _git(repo, "commit", "-qm", "unrelated")
    unrelated = _git(repo, "rev-parse", "HEAD").stdout.decode().strip()
    binding["head"] = unrelated
    _set_binding(state, binding)
    _resign_round(state, events)
    assert "git-base-not-ancestor-of-head" in "\n".join(validate_state(state, events)["errors"])

    binding["base"] = state["changes"]["workspace_base_sha256"]
    binding["head"] = state["changes"]["workspace_head_sha256"]
    _set_binding(state, binding)
    _resign_round(state, events)
    assert "base Git OID invalid" in "\n".join(validate_state(state, events)["errors"])

    state, events = valid_bundle
    state["evidence"][0]["diff_hash"] = "0" * 64
    assert "not bound to the reviewed diff" in "\n".join(validate_state(state, events)["errors"])


def test_workspace_delta_separates_git_oids_from_workspace_sha256(tmp_path):
    repo, base, head = _repo_with_two_commits(tmp_path)
    _git(repo, "reset", "--hard", base)
    baseline = capture_workspace_snapshot(str(repo))
    _git(repo, "reset", "--hard", head)
    current = capture_workspace_snapshot(str(repo))
    delta = workspace_delta(baseline, current)
    assert delta["base"] == base
    assert delta["head"] == head
    assert len(delta["base"]) == len(delta["head"]) == 40
    assert len(delta["workspace_base_sha256"]) == len(delta["workspace_head_sha256"]) == 64
    assert delta["git_binding_source"] == "workspace"


def test_review_gate_receives_ephemeral_core_observed_binding_file(tmp_path, monkeypatch):
    repo, _, _ = _repo_with_two_commits(tmp_path)
    output_file = tmp_path / "review-output.json"
    binding_pointer_file = tmp_path / "binding-path.txt"
    ctx = StateContext.build(
        runtime="codex",
        project="review-binding",
        workspace=str(repo),
        session="review-binding-session",
        round_id="review-binding-round",
        state_root=tmp_path / "state",
    )
    command = [
        os.sys.executable,
        "-B",
        "-c",
        (
            "import json,os,pathlib; "
            "p=os.environ['AGENT_SUPERVISOR_REVIEW_BINDING_FILE']; "
            "d=json.loads(pathlib.Path(p).read_text(encoding='utf-8')); "
            "assert d['contract']=='ReviewArtifactBindingInput/v1'; "
            "assert d['workspace_delta_manifest']; "
            f"pathlib.Path({str(binding_pointer_file)!r}).write_text(p,encoding='utf-8'); "
            f"print(pathlib.Path({str(output_file)!r}).read_text(encoding='utf-8'))"
        ),
    ]
    state = start_round(
        ctx,
        message="run immutable review artifact producer",
        change_mode="replace",
        execution_mode="observe",
        quality_profile={
            "common_gates": [{
                "id": "review.coderabbit",
                "command": [
                    "supervisor-trusted-core-runner",
                    "bin/run-coderabbit-review.py",
                    "--review-category",
                    "independent",
                ],
            }]
        },
    )
    (repo / "config.json").write_bytes(b'{"v":3}\n')
    delta = workspace_delta(
        state["workspace_baseline"],
        capture_workspace_snapshot(str(repo), state["workspace_baseline"]["extra_globs"]),
    )
    changes = {
        **{field: delta.get(field) for field in BINDING_FIELDS},
        "review_artifact": delta.get("review_artifact"),
        "files": delta["files"],
        "domains": ["config/agent"],
        "implementer": "worker-binding",
        "implementer_responsibility_group": "implementation",
        "implementer_invocation_id": "worker-binding-invocation",
        "test_changes": {},
    }
    ctx.update(lambda current: current.update({"changes": copy.deepcopy(changes)}))
    state = ctx.load()
    binding = cli_module._review_binding_input(state)
    assert set(binding) == {
        "contract", "workspace_base_sha256", "workspace_head_sha256",
        "diff_hash", "workspace_delta_manifest",
    }
    assert binding["workspace_delta_manifest"] == delta["manifest"]
    output = _review_output_artifact(
        tmp_path, binding, suffix="gate-integration"
    )
    output_file.write_text(
        json.dumps(output, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        cli_module, "_verify_current_source_snapshot", lambda *_args: "source-hash"
    )
    trusted_python = Path(os.sys.executable).resolve()
    monkeypatch.setattr(
        cli_module,
        "_verified_executable_registry",
        lambda *_args: {
            "registry_sha256": "a" * 64,
            "entries": {
                "python": {
                    "kind": "local",
                    "path": str(trusted_python),
                    "sha256": sha256_file(trusted_python),
                }
            },
        },
    )
    monkeypatch.setattr(
        cli_module, "_trusted_core_runner_command", lambda *_args: command
    )
    monkeypatch.setattr(
        cli_module, "_issue_automated_external_review", lambda *_args, **_kwargs: None
    )
    evidence, execution, code = cli_module._run_registered_gate(
        ctx,
        {
            "record": {
                "gate_id": "review.coderabbit",
                "criterion_id": state["goal"]["acceptance_criteria"][0]["criterion_id"],
                "evidence_id": "review-binding-evidence",
            },
        },
    )
    assert code == 0
    assert execution["review_output_artifact"] == output
    assert evidence["review_output_artifact"] == output
    assert evidence["collector"] == "supervisor-core"
    assert evidence["collector_responsibility_group"] == "trusted-core-gate-execution"
    assert evidence["collector_identity_assurance"] == "core-executed-gate"
    assert evidence["collector_completion_eligible"] is True
    assert evidence["review_binding_input_sha256"] == execution["review_binding_input_sha256"]
    assert len(str(execution["review_binding_input_sha256"])) == 64
    assert not Path(binding_pointer_file.read_text(encoding="utf-8")).exists()
    repeated_evidence, repeated_execution, repeated_code = cli_module._run_registered_gate(
        ctx,
        {
            "record": {
                "gate_id": "review.coderabbit",
                "criterion_id": state["goal"]["acceptance_criteria"][0]["criterion_id"],
                "evidence_id": "review-binding-evidence-repeated",
            },
        },
    )
    assert repeated_code == 0
    assert repeated_evidence["collector_invocation_id"] != evidence["collector_invocation_id"]
    assert repeated_execution["gate_grant_id"] != execution["gate_grant_id"]
    assert not Path(binding_pointer_file.read_text(encoding="utf-8")).exists()
    stale = ctx.load()
    stale["changes"]["diff_hash"] = "0" * 64
    with pytest.raises(cli_module.InvalidState, match="failed core verification"):
        cli_module._review_binding_input(stale)


def test_review_gate_output_rejects_missing_malformed_tampered_and_mismatched_artifacts(tmp_path):
    before = b'{"v":2}\n'
    after = b'{"v":3}\n'
    delta_manifest = {
        "config.json": {
            "before": sha256_bytes(before),
            "after": sha256_bytes(after),
        }
    }
    binding = {
        "contract": "ReviewArtifactBindingInput/v1",
        "workspace_base_sha256": "a" * 64,
        "workspace_head_sha256": "b" * 64,
        "diff_hash": canonical_sha256(delta_manifest),
        "workspace_delta_manifest": delta_manifest,
    }

    output = _review_output_artifact(
        tmp_path, binding, suffix="strict-valid", after=after
    )
    parsed, reason = cli_module._parse_review_gate_output(
        json.dumps(output, separators=(",", ":")), "", binding
    )
    assert reason == "verified"
    assert parsed == output

    for raw in ("{}", "not-json", "{}\n{}", '{"contract":1,"contract":2}'):
        parsed, _ = cli_module._parse_review_gate_output(raw, "", binding)
        assert parsed is None
    parsed, reason = cli_module._parse_review_gate_output(
        json.dumps(output, separators=(",", ":")), "unexpected stderr", binding
    )
    assert parsed is None and reason == "review-output-stderr-not-empty"

    mismatched = copy.deepcopy(output)
    mismatched["workspace_head_sha256"] = "c" * 64
    parsed, reason = cli_module._parse_review_gate_output(
        json.dumps(mismatched, separators=(",", ":")), "", binding
    )
    assert parsed is None and reason == "review-output-workspace_head_sha256-mismatch"

    tampered = _review_output_artifact(
        tmp_path, binding, suffix="strict-tampered", after=after
    )
    manifest_path = Path(tampered["review_artifact"]["manifest_path"])
    manifest_path.write_text("{}", encoding="utf-8")
    parsed, reason = cli_module._parse_review_gate_output(
        json.dumps(tampered, separators=(",", ":")), "", binding
    )
    assert parsed is None and reason == "review-artifact-manifest-hash-mismatch"

    wrong_tree = _review_output_artifact(
        tmp_path, binding, suffix="strict-wrong-tree", after=after
    )
    wrong_manifest_path = Path(wrong_tree["review_artifact"]["manifest_path"])
    wrong_manifest = json.loads(wrong_manifest_path.read_text(encoding="utf-8"))
    wrong_manifest["source_review_manifest"]["config.json"] = "0" * 64
    wrong_manifest["source_review_manifest_sha256"] = canonical_sha256(
        wrong_manifest["source_review_manifest"]
    )
    wrong_manifest_path.write_text(
        json.dumps(wrong_manifest, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    wrong_tree["review_artifact"]["manifest_sha256"] = sha256_file(
        wrong_manifest_path
    )
    parsed, reason = cli_module._parse_review_gate_output(
        json.dumps(wrong_tree, separators=(",", ":")), "", binding
    )
    assert parsed is None and reason == "review-artifact-delta-head-mismatch"


def test_review_artifact_git_argv_isolated_from_leading_dash_bundle(
    tmp_path, monkeypatch
):
    delta_manifest = {
        "config.json": {
            "before": sha256_bytes(b'{"v":2}\n'),
            "after": sha256_bytes(b'{"v":3}\n'),
        }
    }
    binding = {
        "contract": "ReviewArtifactBindingInput/v1",
        "workspace_base_sha256": "a" * 64,
        "workspace_head_sha256": "b" * 64,
        "diff_hash": canonical_sha256(delta_manifest),
        "workspace_delta_manifest": delta_manifest,
    }
    output = _review_output_artifact(
        tmp_path, binding, suffix="leading-dash", after=b'{"v":3}\n'
    )
    original_bundle = Path(output["review_artifact"]["bundle_path"])
    leading_dash_bundle = original_bundle.with_name("-review-leading.bundle")
    assert leading_dash_bundle.name.startswith("-")
    original_bundle.rename(leading_dash_bundle)
    output["review_artifact"]["bundle_path"] = str(leading_dash_bundle.resolve())

    observed_calls: list[tuple[str, ...]] = []
    observed_process_commands: list[tuple[str, ...]] = []
    real_git = workspace_module._git
    real_popen = workspace_module.subprocess.Popen

    def recording_git(repo: Path, *args: str):
        observed_calls.append(args)
        return real_git(repo, *args)

    def recording_popen(command, *args, **kwargs):
        observed_process_commands.append(tuple(str(value) for value in command))
        return real_popen(command, *args, **kwargs)

    monkeypatch.setattr(workspace_module, "_git", recording_git)
    monkeypatch.setattr(workspace_module.subprocess, "Popen", recording_popen)
    valid, reason, _ = workspace_module.validate_review_output_artifact(
        output, binding
    )

    assert valid, reason
    assert reason == "verified"
    list_heads = next(
        args for args in observed_calls if args[:2] == ("bundle", "list-heads")
    )
    fetch = next(args for args in observed_calls if args[:2] == ("fetch", "-q"))
    assert list_heads[:3] == ("bundle", "list-heads", "--")
    assert Path(list_heads[3]).name == "review.bundle"
    assert fetch[:3] == ("fetch", "-q", "--")
    assert Path(fetch[3]).name == "review.bundle"
    assert fetch[4].endswith(":refs/review/head")
    assert all(str(leading_dash_bundle) not in args for args in observed_calls)
    batch_commands = [
        command
        for command in observed_process_commands
        if command[-2:] == ("cat-file", "--batch")
    ]
    assert len(batch_commands) == 2
    assert not any(
        "cat-file" in command and "blob" in command
        for command in observed_process_commands
    )


def test_full_snapshot_artifact_rejects_duplicate_manifest_and_bad_base(tmp_path):
    delta_manifest = {
        "config.json": {
            "before": sha256_bytes(b'{"v":2}\n'),
            "after": sha256_bytes(b'{"v":3}\n'),
        }
    }
    binding = {
        "contract": "ReviewArtifactBindingInput/v1",
        "workspace_base_sha256": "d" * 64,
        "workspace_head_sha256": "e" * 64,
        "diff_hash": canonical_sha256(delta_manifest),
        "workspace_delta_manifest": delta_manifest,
    }

    duplicate = _review_output_artifact(tmp_path, binding, suffix="duplicate-json")
    duplicate_manifest_path = Path(duplicate["review_artifact"]["manifest_path"])
    duplicate_raw = duplicate_manifest_path.read_text(encoding="utf-8")
    duplicate_manifest_path.write_text(
        duplicate_raw.replace(
            '{"base":',
            '{"base":"0","base":',
            1,
        ),
        encoding="utf-8",
    )
    duplicate["review_artifact"]["manifest_sha256"] = sha256_file(
        duplicate_manifest_path
    )
    parsed, reason = cli_module._parse_review_gate_output(
        json.dumps(duplicate, separators=(",", ":")), "", binding
    )
    assert parsed is None and reason == "review-artifact-manifest-invalid"

    nonempty_base = _review_output_artifact(
        tmp_path, binding, suffix="nonempty-base"
    )
    nonempty_manifest_path = Path(
        nonempty_base["review_artifact"]["manifest_path"]
    )
    nonempty_manifest = json.loads(
        nonempty_manifest_path.read_text(encoding="utf-8")
    )
    nonempty_manifest["base"] = nonempty_manifest["head"]
    nonempty_manifest["git_diff_sha256"] = sha256_bytes(b"")
    nonempty_manifest_path.write_text(
        json.dumps(nonempty_manifest, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    nonempty_base["base"] = nonempty_base["head"]
    nonempty_base["git_diff_sha256"] = sha256_bytes(b"")
    nonempty_base["review_artifact"]["manifest_sha256"] = sha256_file(
        nonempty_manifest_path
    )
    parsed, reason = cli_module._parse_review_gate_output(
        json.dumps(nonempty_base, separators=(",", ":")), "", binding
    )
    assert parsed is None and reason == "review-artifact-base-tree-manifest-mismatch"

    executable = _review_output_artifact(
        tmp_path, binding, suffix="executable-mode", executable_payload=True
    )
    parsed, reason = cli_module._parse_review_gate_output(
        json.dumps(executable, separators=(",", ":")), "", binding
    )
    assert parsed is not None and reason == "verified"


def test_immutable_full_git_bundle_and_manifest_is_a_valid_alternate_binding(tmp_path, valid_bundle):
    delta_manifest = {
        "config.json": {
            "before": sha256_bytes(b'{"v":1}\n'),
            "after": sha256_bytes(b'{"v":2}\n'),
        }
    }
    diff_hash = canonical_sha256(delta_manifest)
    binding_input = {
        "contract": "ReviewArtifactBindingInput/v1",
        "workspace_base_sha256": "a" * 64,
        "workspace_head_sha256": "b" * 64,
        "diff_hash": diff_hash,
        "workspace_delta_manifest": delta_manifest,
    }
    review_output = _review_output_artifact(
        tmp_path,
        binding_input,
        suffix="alternate-binding",
        before=b'{"v":1}\n',
        after=b'{"v":2}\n',
    )
    artifact = review_output["review_artifact"]
    state, events = copy.deepcopy(valid_bundle)
    state["changes"].pop("diff", None)
    binding = {
        "base": review_output["base"],
        "head": review_output["head"],
        "git_object_format": review_output["git_object_format"],
        "git_binding_status": "verified",
        "git_binding_source": "review-artifact",
        "git_repository_root": None,
        "review_artifact": artifact,
        "review_artifact_sha256": artifact["manifest_sha256"],
        "git_diff_sha256": review_output["git_diff_sha256"],
        "workspace_base_sha256": binding_input["workspace_base_sha256"],
        "workspace_head_sha256": binding_input["workspace_head_sha256"],
        "diff_hash": diff_hash,
    }
    _set_binding(state, binding)
    _resign_round(state, events)
    report = validate_state(state, events)
    assert report["valid"], report

    mismatched_state, mismatched_events = copy.deepcopy((state, events))
    mismatched_state["changes"]["review_artifact"]["manifest_sha256"] = "0" * 64
    assert "immutable review artifact invalid" in "\n".join(
        validate_state(mismatched_state, mismatched_events)["errors"]
    )
