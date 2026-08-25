from __future__ import annotations

import copy
import json
from pathlib import Path

from jsonschema import Draft202012Validator

from supervisor_core.attestation import sign_record
from supervisor_core.contracts import (
    ROUND_PROCESS_SUMMARY_CONTRACT,
    build_round_process_summary,
    invocation_event,
    render_round_process_summary,
    sanitize_process_summary_text,
)
from supervisor_core.util import utc_now


SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "contracts.schema.json"

PROMPT_SECRET = "PROMPT-LEAK-ALPHA-9182"
ARGV_SECRET = "hunter2-argv-secret"
COOKIE_SECRET = "session=cookie-leak-xyz"
TOKEN_SECRET = "sk_live_" + "t" * 24
DB_SECRET = "postgresql://fixture-db:fixture-pass@db.invalid/app"
PII_NAME = "学生张三"
PII_STU = "学号20260824001"
PII_PHONE = "13800138000"
STACK_SECRET = "SECRET_STACK_FRAME_9911"
STDOUT_SECRET = "SECRET_STDOUT_PAYLOAD_7733"
STDERR_SECRET = "SECRET_STDERR_PAYLOAD_6622"


def _schema_validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(
        {
            "$schema": schema["$schema"],
            "$ref": "#/$defs/RoundProcessSummary",
            "$defs": schema["$defs"],
        }
    )


def _state(**overrides: object) -> dict[str, object]:
    now = utc_now()
    state: dict[str, object] = {
        "started_at": now,
        "updated_at": now,
        "terminal_state": "incomplete",
        "goal": {
            "goal_id": "goal-summary",
            "version": 2,
            "change_mode": "extend",
            "objective": "round process summary",
        },
        "intents": [
            {
                "intent_id": "intent-route",
                "status": "covered",
                "kind": "functional",
                "capability_ids": ["dev-supervisor"],
                "text": "sha256:" + "a" * 64,
            },
            {
                "intent_id": "intent-quality",
                "status": "covered",
                "kind": "functional",
                "capability_ids": ["qa_engineer"],
                "text": "sha256:" + "b" * 64,
            },
            {
                "intent_id": "intent-log",
                "status": "deferred",
                "kind": "functional",
                "capability_ids": [],
                "text": "sha256:" + "c" * 64,
            },
        ],
        "capability_inventory": {
            "skills": [
                {"id": "dev-supervisor", "name": "dev-supervisor", "source": "codex"},
                {
                    "id": "coderabbit:code-review",
                    "name": "coderabbit:code-review",
                    "source": "codex-plugin:coderabbit@openai",
                },
                {
                    "id": "design-app",
                    "name": "design-app",
                    "source": "claude-plugin:design@anthropic",
                },
                {"id": "original-skill", "name": "original-skill", "source": "codex"},
                {"id": "fallback-skill", "name": "fallback-skill", "source": "codex"},
            ],
            "agents": [
                {
                    "id": "qa_engineer",
                    "name": "qa_engineer",
                    "capability_kind": "agent",
                },
            ],
        },
        "capability_breakers": {},
        "evidence": [],
        "reviews": [],
        "health": "healthy",
    }
    state.update(overrides)
    return state


def _pair(
    *,
    invocation_id: str,
    capability: str,
    result: str = "success",
    actor: str = "worker-a",
    group: str = "implementation",
    details: dict[str, object] | None = None,
) -> tuple[dict[str, object], dict[str, object]]:
    payload = copy.deepcopy(details or {})
    attempt = invocation_event(
        invocation_id=invocation_id,
        capability=capability,
        stage="attempt",
        result=None,
        actor=actor,
        responsibility_group=group,
        identity_assurance="host-hook-observed",
        details=copy.deepcopy(payload),
    )
    result_event = invocation_event(
        invocation_id=invocation_id,
        capability=capability,
        stage="result",
        result=result,
        actor=actor,
        responsibility_group=group,
        identity_assurance="host-hook-observed",
        details=copy.deepcopy(payload),
    )
    return attempt, result_event


def _signed_review(**overrides: object) -> dict[str, object]:
    review: dict[str, object] = {
        "contract": "ReviewRecord/v3",
        "review_id": "review-003",
        "goal_id": "goal-summary",
        "goal_version": 2,
        "reviewer": "reviewer-a",
        "reviewer_responsibility_group": "quality-review",
        "implementer": "worker-a",
        "implementer_responsibility_group": "implementation",
        "gate_collector": "gate-runner-a",
        "gate_collector_responsibility_group": "independent-gate-execution",
        "gate_runner_invocation_id": "inv-gate-runner",
        "base": None,
        "head": None,
        "git_object_format": None,
        "git_binding_status": "unavailable",
        "git_binding_source": None,
        "git_repository_root": None,
        "review_artifact_sha256": None,
        "git_diff_sha256": None,
        "workspace_base_sha256": "a" * 64,
        "workspace_head_sha256": "b" * 64,
        "diff_hash": "c" * 64,
        "rerun_evidence_ids": ["ev-017"],
        "evidence_verification": {
            "status": "VERIFIED",
            "reviewer": "reviewer-a",
            "evidence_ids": ["ev-017"],
        },
        "verdict": "REQUEST_CHANGES",
        "issued_at": utc_now(),
        "unresolved_p0_p1": 1,
        "review_output_artifact": {
            "review_summary": {
                "issues": [{"id": "p1-test-integrity", "severity": "P1"}],
            }
        },
    }
    review.update(overrides)
    review["attestation"] = sign_record(review)
    return review


def _by_id(summary: dict[str, object]) -> dict[str, dict[str, object]]:
    timeline = summary["timeline"]
    assert isinstance(timeline, list)
    return {
        str(row["canonical_id"]): row
        for row in timeline
        if isinstance(row, dict)
    }


def test_schema_accepts_min_contract_and_rejects_unknown_fields() -> None:
    validator = _schema_validator()
    skill_attempt, skill_result = _pair(
        invocation_id="inv-skill",
        capability="dev-supervisor",
        details={"summary": "建立目标并生成路由"},
    )
    summary = build_round_process_summary(_state(), [skill_attempt, skill_result])
    validator.validate(summary)
    assert summary["contract"] == ROUND_PROCESS_SUMMARY_CONTRACT
    assert set(summary) == {"contract", "round", "intent_summary", "timeline", "quality"}
    assert set(summary["round"]) == {
        "started_at",
        "ended_at",
        "goal_id",
        "goal_version",
        "change_mode",
        "terminal_state",
    }
    assert set(summary["quality"]) == {
        "gates",
        "review_verdict",
        "unresolved_p0_p1",
        "degraded_fallbacks",
    }
    for item in summary["timeline"]:
        assert set(item) == {
            "at",
            "kind",
            "canonical_id",
            "status",
            "intent_ids",
            "contribution",
            "evidence_ids",
        }
    invalid = copy.deepcopy(summary)
    invalid["unexpected"] = True
    assert list(validator.iter_errors(invalid))


def test_unsigned_free_text_success_is_ignored() -> None:
    attempt, result = _pair(
        invocation_id="inv-skill",
        capability="dev-supervisor",
        details={"summary": "建立目标"},
    )
    events = [
        {
            "event_type": "note",
            "status": "success",
            "capability": "invented-skill",
            "summary": "all skills succeeded",
        },
        {
            "event_type": "invocation_result",
            "stage": "result",
            "invocation_id": "inv-forged",
            "capability": "invented-skill",
            "result": "success",
            "actor": "model",
            "responsibility_group": "implementation",
        },
        attempt,
        result,
    ]
    summary = build_round_process_summary(_state(), events)
    by_id = _by_id(summary)
    assert "invented-skill" not in by_id
    assert by_id["dev-supervisor"]["status"] == "success"
    assert by_id["dev-supervisor"]["kind"] == "skill"


def test_unpaired_attempt_or_result_is_not_success() -> None:
    attempt_only, _ = _pair(invocation_id="inv-attempt", capability="dev-supervisor")
    _, result_only = _pair(invocation_id="inv-result", capability="dev-supervisor")
    mismatched_attempt, _ = _pair(
        invocation_id="inv-mismatch",
        capability="dev-supervisor",
        actor="worker-a",
    )
    _, mismatched_result = _pair(
        invocation_id="inv-mismatch",
        capability="other-skill",
        actor="worker-a",
    )
    summary = build_round_process_summary(
        _state(),
        [attempt_only, result_only, mismatched_attempt, mismatched_result],
    )
    assert summary["timeline"] == []


def test_failed_original_and_fallback_are_two_independent_facts() -> None:
    original_attempt, original_result = _pair(
        invocation_id="inv-original",
        capability="original-skill",
        result="failed",
        details={"summary": "primary capability failed"},
    )
    fallback_attempt, fallback_result = _pair(
        invocation_id="inv-fallback",
        capability="fallback-skill",
        result="success",
        details={
            "summary": "fallback capability completed",
            "fallback_for": "original-skill",
        },
    )
    state = _state(
        capability_breakers={
            "original-skill": {
                "open": True,
                "fallback_id": "fallback-skill",
                "fallback_status": "required",
            }
        },
        evidence=[
            {
                "evidence_id": "ev-021",
                "collector_invocation_id": "inv-original",
                "gate_id": "",
                "exit_code": 1,
                "relevant": True,
            },
            {
                "evidence_id": "ev-023",
                "collector_invocation_id": "inv-fallback",
                "gate_id": "",
                "exit_code": 0,
                "relevant": True,
            },
        ],
    )
    events = [
        original_attempt,
        original_result,
        {
            "event_type": "invocation_fallback_required",
            "invocation_id": "inv-original",
            "capability": "original-skill",
            "fallback_id": "fallback-skill",
            "status": "routed",
        },
        fallback_attempt,
        fallback_result,
    ]
    summary = build_round_process_summary(state, events)
    by_id = _by_id(summary)
    assert by_id["original-skill"]["status"] == "failed"
    assert by_id["fallback-skill"]["status"] == "fallback"
    assert by_id["original-skill"]["canonical_id"] != by_id["fallback-skill"]["canonical_id"]
    assert "ev-021" in by_id["original-skill"]["evidence_ids"]
    assert "ev-023" in by_id["fallback-skill"]["evidence_ids"]
    assert "original-skill" in summary["quality"]["degraded_fallbacks"]
    view = render_round_process_summary(summary)
    assert "original-skill" in view
    assert "fallback-skill" in view
    assert "original-skill｜success" not in view


def test_kinds_distinguish_skill_agent_plugin_native_and_methodology_only() -> None:
    events: list[dict[str, object]] = []
    for invocation_id, capability, result, details in (
        ("inv-skill", "dev-supervisor", "success", {"summary": "扫描能力并生成路由"}),
        ("inv-agent", "qa_engineer", "success", {"summary": "focused tests 8/8"}),
        ("inv-plugin", "design-app", "success", {"summary": "exported plugin artifact"}),
        (
            "inv-method",
            "coderabbit:code-review",
            "methodology-only",
            {"methodology_only": True, "summary": "adopted review checklist"},
        ),
        (
            "inv-native",
            "pytest",
            "success",
            {"kind": "native_command", "command_category": "test", "summary": "unit tests"},
        ),
    ):
        group = "quality-review" if capability == "qa_engineer" else "implementation"
        actor = "reviewer-a" if capability == "qa_engineer" else "worker-a"
        attempt, result_event = _pair(
            invocation_id=invocation_id,
            capability=capability,
            result=result,
            actor=actor,
            group=group,
            details=details,
        )
        events.extend([attempt, result_event])
    summary = build_round_process_summary(_state(), events)
    by_id = _by_id(summary)
    assert by_id["dev-supervisor"]["kind"] == "skill"
    assert by_id["dev-supervisor"]["status"] == "success"
    assert by_id["qa_engineer"]["kind"] == "agent"
    assert by_id["qa_engineer"]["status"] == "success"
    assert by_id["design-app"]["kind"] == "plugin_app"
    assert by_id["design-app"]["status"] == "success"
    assert by_id["coderabbit:code-review"]["kind"] == "plugin_app"
    assert by_id["coderabbit:code-review"]["status"] == "methodology-only"
    assert by_id["pytest"]["kind"] == "native_command"
    assert by_id["pytest"]["status"] == "success"
    view = render_round_process_summary(summary)
    assert "Skill｜dev-supervisor｜success" in view
    assert "Agent｜qa_engineer｜success" in view
    assert "Plugin/App｜design-app｜success" in view
    assert "Plugin/App｜coderabbit:code-review｜methodology-only" in view
    assert "Command｜pytest｜success" in view


def test_user_view_is_short_and_keeps_evidence_ids_not_raw_payloads() -> None:
    events: list[dict[str, object]] = []
    evidence = []
    for index in range(6):
        invocation_id = f"inv-cmd-{index}"
        attempt, result = _pair(
            invocation_id=invocation_id,
            capability="pytest",
            details={
                "kind": "native_command",
                "summary": f"command batch {index}",
                "stdout": "x" * 4000,
            },
        )
        events.extend([attempt, result])
        evidence.append({
            "evidence_id": f"ev-cmd-{index}",
            "collector_invocation_id": invocation_id,
            "gate_id": "",
            "exit_code": 0,
            "relevant": True,
        })
    skill_attempt, skill_result = _pair(
        invocation_id="inv-skill",
        capability="dev-supervisor",
        details={"summary": "建立目标"},
    )
    events.extend([skill_attempt, skill_result])
    state = _state(evidence=evidence)
    summary = build_round_process_summary(state, events)
    view = render_round_process_summary(summary)
    assert view.startswith("# RoundProcessSummary/v1")
    assert view.count("\n") <= 20
    assert "x" * 50 not in view
    assert "ev-cmd-0" in json.dumps(summary)
    assert "stdout" not in view.lower() or "[stdio-redacted]" in view or "stdout" not in view
    assert "4000" not in view


def test_quality_and_review_come_from_structured_signed_records() -> None:
    gate_attempt, gate_result = _pair(
        invocation_id="inv-gate",
        capability="supervisor-core-gate:lint",
        details={"gate_id": "lint", "summary": "lint completed"},
    )
    qa_attempt, qa_result = _pair(
        invocation_id="inv-qa",
        capability="qa_engineer",
        actor="reviewer-a",
        group="quality-review",
        details={"summary": "focused tests 8/8"},
    )
    state = _state(
        evidence=[
            {
                "evidence_id": "ev-lint",
                "collector_invocation_id": "inv-gate",
                "gate_id": "lint",
                "exit_code": 0,
                "relevant": True,
            },
            {
                "evidence_id": "ev-017",
                "collector_invocation_id": "inv-qa",
                "gate_id": "tests",
                "exit_code": 1,
                "relevant": True,
            },
        ],
        reviews=[_signed_review()],
    )
    summary = build_round_process_summary(state, [gate_attempt, gate_result, qa_attempt, qa_result])
    gates = {row["id"]: row["status"] for row in summary["quality"]["gates"]}
    assert gates["lint"] == "PASS"
    assert gates["tests"] == "FAIL"
    assert summary["quality"]["review_verdict"] == "REQUEST_CHANGES"
    assert summary["quality"]["unresolved_p0_p1"]
    by_id = _by_id(summary)
    assert by_id["lint"]["kind"] == "quality_gate"
    assert by_id["review-003"]["kind"] == "review"
    view = render_round_process_summary(summary)
    assert "独立 reviewer REQUEST_CHANGES" in view
    assert "未宣称 complete" in view


def test_privacy_anti_examples_are_redacted_in_summary_and_user_view() -> None:
    attempt, result = _pair(
        invocation_id="inv-private",
        capability="dev-supervisor",
        details={
            "summary": f"handled {PII_NAME} {PII_STU} {PII_PHONE}",
            "prompt": f"please run {PROMPT_SECRET}",
            "argv": ["tool", "--password", ARGV_SECRET],
            "cookie": f"Cookie: {COOKIE_SECRET}",
            "token": TOKEN_SECRET,
            "database_url": DB_SECRET,
            "stack": (
                "Traceback (most recent call last):\n"
                f"  File \"app.py\", line 1, in <module>\n{STACK_SECRET}"
            ),
            "stdout": STDOUT_SECRET,
            "stderr": STDERR_SECRET,
        },
    )
    native_attempt, native_result = _pair(
        invocation_id="inv-native",
        capability="pytest",
        details={
            "kind": "native_command",
            "summary": (
                "Traceback (most recent call last):\n"
                f"  File \"suite.py\", line 9, in test_x\n{STACK_SECRET}"
            ),
            "stdout": STDOUT_SECRET,
            "stderr": STDERR_SECRET,
        },
    )
    state = _state(
        evidence=[
            {
                "evidence_id": "ev-private",
                "collector_invocation_id": "inv-private",
                "gate_id": "lint",
                "exit_code": 0,
                "relevant": True,
                "output_summary": STDOUT_SECRET,
            }
        ]
    )
    summary = build_round_process_summary(state, [attempt, result, native_attempt, native_result])
    rendered = render_round_process_summary(summary)
    blob = json.dumps(summary, ensure_ascii=False) + "\n" + rendered
    for secret in (
        PROMPT_SECRET,
        ARGV_SECRET,
        COOKIE_SECRET,
        TOKEN_SECRET,
        DB_SECRET,
        "张三",
        "20260824001",
        PII_PHONE,
        STACK_SECRET,
        STDOUT_SECRET,
        STDERR_SECRET,
        "fixture-pass",
    ):
        assert secret not in blob
    assert "Traceback" not in rendered
    by_id = _by_id(summary)
    assert by_id["dev-supervisor"]["contribution"]
    assert "ev-private" in by_id["dev-supervisor"]["evidence_ids"]


def test_apply_patch_v2_without_explicit_kind_is_native_command() -> None:
    attempt, result = _pair(
        invocation_id="inv-patch-v2",
        capability="apply_patch_v2",
        details={"summary": "patched src/baseline.py"},
    )
    summary = build_round_process_summary(_state(), [attempt, result])
    row = _by_id(summary)["apply_patch_v2"]
    assert row["kind"] == "native_command"
    assert row["status"] == "success"
    view = render_round_process_summary(summary)
    assert "Command｜apply_patch_v2｜success" in view
    assert "Skill｜apply_patch_v2｜" not in view


def test_folded_native_mixed_status_is_not_success() -> None:
    events: list[dict[str, object]] = []
    for index, status in enumerate(
        ("success", "success", "success", "failed", "success", "failed")
    ):
        attempt, result = _pair(
            invocation_id=f"inv-fold-{index}",
            capability="pytest",
            result=status,
            details={
                "kind": "native_command",
                "summary": f"command batch {index}",
            },
        )
        events.extend([attempt, result])
    summary = build_round_process_summary(_state(), events)
    view = render_round_process_summary(summary)
    assert "native-commands｜success" not in view
    assert "Command｜native-commands｜failed" in view
    assert "失败" in view
    assert view.count("\n") <= 20


def test_missing_required_gates_render_as_missing() -> None:
    state = _state(quality_profile={"global_gates": ["lint", "typecheck"]})
    summary = build_round_process_summary(state, [])
    gates = {row["id"]: row["status"] for row in summary["quality"]["gates"]}
    assert gates["lint"] == "MISSING"
    assert gates["typecheck"] == "MISSING"
    view = render_round_process_summary(summary)
    assert "lint MISSING" in view
    assert "typecheck MISSING" in view
    assert "lint PASS" not in view


def test_sanitize_helper_strips_stack_stdio_and_pii() -> None:
    dirty = (
        f"prompt={PROMPT_SECRET}\n"
        "Traceback (most recent call last):\n"
        '  File "app.py", line 1, in <module>\n'
        f"{STACK_SECRET}\n"
        f"stdout={STDOUT_SECRET}\n"
        f"{PII_NAME} {PII_STU} {PII_PHONE}"
    )
    clean = sanitize_process_summary_text(dirty)
    assert PROMPT_SECRET not in clean
    assert STACK_SECRET not in clean
    assert STDOUT_SECRET not in clean
    assert "张三" not in clean
    assert PII_PHONE not in clean
    assert "Traceback" not in clean


def test_failed_plugin_app_keeps_failed_status_when_review_verdict_exists() -> None:
    attempt, result = _pair(
        invocation_id="inv-plugin",
        capability="design-app",
        result="failed",
        details={"kind": "plugin_app", "summary": "plugin export failed"},
    )
    summary = build_round_process_summary(
        _state(reviews=[_signed_review()]),
        [attempt, result],
    )
    by_id = _by_id(summary)
    assert by_id["design-app"]["kind"] == "plugin_app"
    assert by_id["design-app"]["status"] == "failed"
    view = render_round_process_summary(summary)
    assert "Plugin/App｜design-app｜failed" in view
    assert "Plugin/App｜design-app｜REQUEST_CHANGES" not in view
    assert "独立 reviewer REQUEST_CHANGES" in view


def test_review_findings_p0_surfaces_even_when_count_and_artifact_issues_are_empty() -> None:
    review = _signed_review(
        unresolved_p0_p1=0,
        review_output_artifact={"review_summary": {"issues": []}},
        findings=[{"id": "finding-p0", "severity": "P0"}],
    )
    summary = build_round_process_summary(_state(reviews=[review]), [])
    unresolved = summary["quality"]["unresolved_p0_p1"]
    assert any("P0:finding-p0" in str(marker) for marker in unresolved)
    view = render_round_process_summary(summary)
    assert "未解决 P0/P1=1" in view
