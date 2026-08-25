from __future__ import annotations

import copy

from supervisor_core.contracts import build_goal, normalize_intents
from supervisor_core.routing import route_intents, split_intents
from supervisor_core.validation import (
    PROGRESS_GUARD_ALLOW,
    PROGRESS_GUARD_REFUSE_REDUNDANT,
    progress_guard_decision,
    record_intent_capability_attempt,
)


USER_CORE_REQUEST = (
    "仅编写 Supervisor 后续交接文档：三项核心需求为每轮深度理解并自动路由 Skill、"
    "全过程质量监工及时纠偏与最终验收、每轮结束输出简约时间线日志。"
)

USER_NUMBERED_REQUEST = (
    "我的核心功能需求是： 1.每轮对话任务开始的时候，需要对我的任务做深度理解、思考分析，"
    "并对skill池（已安装已有的）进行扫描，明确过程、其中表面以及背后需要用到哪些skill进行思考并进行对应调用以及进行质量检查。"
    " 2.进行质量监工，审查监工每轮对话完成过程以及结果，避免在错误道路越走越远、及时纠正偏差以及进行最终成果验收把关"
    " 3.每次对话任务结束完成后，需要返回简约核心的过程日志，比如在哪些时间节点调用了什么skill、agent、插件应用等以及对应完成的情况质量等,"
    "以及再让其避免在goal模式或者完成任务过程中反复进行一些无关紧要、或者做切实没必要的重复的工作 "
    "深度思考如何全方面、多轮次进行验证测试，确保这个agent可以在codex中以及claude中在不同的项目中均可以使用，尤其是codex中进行使用，无bug,"
    "以及不要用现有的项目进行测试验证 请先深度理解上述需求以及现有的agent的所有内容以及结构等，进行优化升级以及进行全面测试检查，"
    "确保所有功能可以用、无误后再交付给我"
)

NOISE_SKILLS = (
    "figma:figma-create-new-file",
    "animal-island-ui-style",
    "build-ios-apps:swiftui-performance-audit",
)

CORE_SKILLS = (
    "dev-supervisor",
    "ce-plan",
    "coderabbit:code-review",
)


def _skill(skill_id: str, description: str) -> dict[str, object]:
    return {
        "id": skill_id,
        "name": skill_id,
        "description": description,
        "active": True,
        "automatic": True,
        "availability": "enabled",
        "health": "healthy",
    }


def _inventory() -> dict[str, list[dict[str, object]]]:
    return {
        "skills": [
            _skill("dev-supervisor", "goal quality capability routing supervisor 监工 调度"),
            _skill("ce-plan", "plan intents acceptance criteria supervisor"),
            _skill(
                "coderabbit:code-review",
                "CodeRabbit independent review and process log 审查 日志",
            ),
            _skill("figma:figma-create-new-file", "create a Figma design file"),
            _skill("animal-island-ui-style", "cute animal island UI style"),
            _skill(
                "build-ios-apps:swiftui-performance-audit",
                "SwiftUI iOS performance audit",
            ),
            _skill(
                "vendor:very-long-capability-name-that-exceeds-thirty-chars",
                "supervisor routing quality 监工",
            ),
        ]
    }


def test_exact_chinese_core_request_has_three_functional_intents_and_scope_constraint() -> None:
    rows = normalize_intents(split_intents(USER_CORE_REQUEST), USER_CORE_REQUEST)
    functional = [
        row
        for row in rows
        if row["kind"] == "functional" and not row["depends_on_intent_ids"]
    ]
    constraints = [row for row in rows if row["kind"] == "scope-constraint"]
    assert len(functional) == 3
    assert constraints
    texts = [row["text"] for row in functional]
    joined = " ".join(texts)
    assert "自动路由 Skill" in joined or "Skill" in joined
    assert "质量监工" in joined or "监工" in joined
    assert "日志" in joined or "时间线" in joined
    assert all("仅编写" not in row["text"] for row in functional)
    assert any("仅编写" in row["text"] for row in constraints)
    keys = [row["dedupe_key"] for row in rows]
    assert len(keys) == len(set(keys))
    pairs = {(row["text"], row["domain"]) for row in rows}
    by_text: dict[str, set[str]] = {}
    for text, domain in pairs:
        by_text.setdefault(text, set()).add(domain)
    assert all(len(domains) == 1 for domains in by_text.values())


def test_normalize_intents_merges_same_text_copied_across_domains() -> None:
    rows = normalize_intents(
        [
            {"text": USER_CORE_REQUEST, "domain": "goal-alignment"},
            {"text": USER_CORE_REQUEST, "domain": "quality-gate"},
            {"text": USER_CORE_REQUEST, "domain": "deep-audit"},
        ],
        USER_CORE_REQUEST,
    )
    assert len(rows) == 1
    assert rows[0]["dedupe_key"]


def test_build_goal_accepts_out_of_scope_alias_and_non_goals() -> None:
    goal = build_goal(
        USER_CORE_REQUEST,
        change_mode="replace",
        supplied={
            "objective": "交接文档三项核心需求",
            "out_of_scope": ["src/**", "Brown Zone product features"],
            "non_goals": ["不修复生产代码", "不切换全局指针"],
            "acceptance_criteria": [
                {
                    "description": "三项顶层意图路由正确",
                    "domain": "capability-reuse",
                    "expected_evidence": ["goal-output"],
                }
            ],
        },
    )
    assert "src/**" in goal["scope"]["out"]
    assert "Brown Zone product features" in goal["scope"]["out"]
    assert "不修复生产代码" in goal["non_goals"]
    assert "不切换全局指针" in goal["non_goals"]


def test_exact_request_does_not_select_unrelated_skills() -> None:
    result = route_intents(
        message=USER_CORE_REQUEST,
        inventory=_inventory(),
        phase_budget=3,
    )
    selected = set(result["selected_capabilities"])
    assert result["total_capability_limit"] is None
    assert all(len(phase["capability_ids"]) <= 3 for phase in result["phases"])
    assert selected.isdisjoint(NOISE_SKILLS)
    functional = [
        row
        for row in result["coverage"]
        if row.get("kind") == "functional" and not row.get("depends_on_intent_ids")
    ]
    assert len(functional) == 3
    assert any(row["status"] == "skipped" and row.get("kind") == "scope-constraint" for row in result["coverage"])


def test_covered_intents_are_skipped_on_reroute() -> None:
    intents = normalize_intents(
        [
            {
                "intent_id": "intent-quality",
                "text": "全过程质量监工及时纠偏与最终验收",
                "domain": "quality-gate",
                "status": "covered",
                "capability_ids": ["dev-supervisor"],
                "evidence_ids": ["ev-quality-1"],
            }
        ]
    )
    result = route_intents(
        message=USER_CORE_REQUEST,
        inventory=_inventory(),
        supplied_intents=intents,
        phase_budget=3,
    )
    assert result["coverage"][0]["status"] == "skipped"
    assert "already covered" in result["coverage"][0]["reason"]
    assert result["coverage"][0]["capability_ids"] == []


def test_attempted_capability_without_progress_is_refused_redundant() -> None:
    intents = normalize_intents(
        [
            {
                "intent_id": "intent-understanding",
                "text": "每轮深度理解并自动路由 Skill",
                "domain": "capability-reuse",
                "acceptance_criteria": ["criterion-capability-reuse"],
                "evidence_ids": [],
                "attempted_capabilities": [
                    {
                        "capability_id": "figma:figma-create-new-file",
                        "result": "failed",
                        "evidence_ids": [],
                    }
                ],
            }
        ]
    )
    result = route_intents(
        message=USER_CORE_REQUEST,
        inventory=_inventory(),
        supplied_intents=intents,
        phase_budget=3,
    )
    refused = [
        row
        for row in result["rejected"]
        if row["status"] == "refused-redundant"
        and row["capability_id"] == "figma:figma-create-new-file"
        and row["intent_id"] == "intent-understanding"
    ]
    assert refused
    assert refused[0]["reason"] == "already-attempted-without-new-evidence"
    for row in result["coverage"]:
        assert "figma:figma-create-new-file" not in row["capability_ids"]
    assert "figma:figma-create-new-file" not in result["selected_capabilities"]


def test_invocation_result_stamp_makes_reroute_refuse_redundant() -> None:
    first = route_intents(
        message=USER_CORE_REQUEST,
        inventory=_inventory(),
        supplied_intents=normalize_intents(
            [
                {
                    "intent_id": "intent-understanding",
                    "text": "每轮深度理解并自动路由 Skill",
                    "domain": "capability-reuse",
                }
            ]
        ),
        phase_budget=3,
    )
    covered = next(
        row for row in first["coverage"] if row.get("intent_id") == "intent-understanding"
    )
    assert covered["capability_ids"]
    chosen = str(covered["capability_ids"][0])
    state = {"intents": [copy.deepcopy(covered)]}
    record_intent_capability_attempt(
        state,
        chosen,
        result="success",
        invocation_id="inv-live-supervisor",
    )
    second = route_intents(
        message=USER_CORE_REQUEST,
        inventory=_inventory(),
        supplied_intents=state["intents"],
        phase_budget=3,
    )
    refused = [
        row
        for row in second["rejected"]
        if row["status"] == "refused-redundant"
        and row["capability_id"] == chosen
        and row["intent_id"] == "intent-understanding"
    ]
    assert refused
    assert chosen not in second["selected_capabilities"]


def test_attempted_capability_with_new_evidence_is_not_refused() -> None:
    intents = normalize_intents(
        [
            {
                "intent_id": "intent-quality",
                "text": "全过程质量监工及时纠偏与最终验收",
                "domain": "quality-gate",
                "acceptance_criteria": ["criterion-quality-gate"],
                "evidence_ids": ["ev-quality-2"],
                "attempted_capabilities": [
                    {
                        "capability_id": "dev-supervisor",
                        "result": "failed",
                        "evidence_ids": [],
                    }
                ],
            }
        ]
    )
    assert progress_guard_decision(intents[0], "dev-supervisor") == PROGRESS_GUARD_ALLOW
    result = route_intents(
        message=USER_CORE_REQUEST,
        inventory=_inventory(),
        supplied_intents=intents,
        phase_budget=3,
    )
    assert not any(
        row["capability_id"] == "dev-supervisor" and row["status"] == "refused-redundant"
        for row in result["rejected"]
    )


def test_progress_guard_refuses_unchanged_failed_attempt() -> None:
    intent = normalize_intents(
        [
            {
                "text": "全过程质量监工及时纠偏与最终验收",
                "attempted_capabilities": [
                    {
                        "capability_id": "figma:figma-create-new-file",
                        "result": "failed",
                        "evidence_ids": [],
                    }
                ],
                "evidence_ids": [],
            }
        ]
    )[0]
    assert (
        progress_guard_decision(intent, "figma:figma-create-new-file")
        == PROGRESS_GUARD_REFUSE_REDUNDANT
    )
    assert progress_guard_decision(intent, "dev-supervisor") == PROGRESS_GUARD_ALLOW


def test_phase_budget_unlimited_total_preserves_long_capability_names() -> None:
    intents = [
        {
            "intent_id": "intent-quality",
            "text": "全过程质量监工及时纠偏与最终验收",
            "domain": "quality-gate",
        }
    ]
    result = route_intents(
        message=USER_CORE_REQUEST,
        inventory=_inventory(),
        supplied_intents=intents,
        phase_budget=3,
    )
    assert result["total_capability_limit"] is None
    assert all(len(phase["capability_ids"]) <= 3 for phase in result["phases"])
    for capability_id in result["selected_capabilities"]:
        assert capability_id == capability_id.strip()
        assert "..." not in capability_id


def test_numbered_chinese_request_keeps_coherent_intents() -> None:
    rows = normalize_intents(split_intents(USER_NUMBERED_REQUEST), USER_NUMBERED_REQUEST)
    functional = [
        row
        for row in rows
        if row["kind"] == "functional" and not row["depends_on_intent_ids"]
    ]
    texts = [row["text"] for row in rows]
    joined = " ".join(texts)
    assert 3 <= len(functional) <= 10
    assert "扫描" in joined or "skill" in joined.casefold()
    assert "监工" in joined or "质量" in joined
    assert "日志" in joined
    assert "重复" in joined or "无关" in joined
    assert any(
        row["kind"] == "scope-constraint" and "不要用现有" in row["text"]
        for row in rows
    )
    assert {"结果", "agent", "结构等", "明确过程", "其中表面", "思考分析"}.isdisjoint(
        {row["text"].strip() for row in rows}
    )
    assert all(len(row["text"]) >= 4 for row in rows)
    keys = [row["dedupe_key"] for row in rows]
    assert len(keys) == len(set(keys))


def test_host_name_codex_does_not_select_unrelated_slide_skill() -> None:
    inventory = _inventory()
    inventory["skills"].append(
        _skill("codex-ppt", "generate powerpoint slides from articles")
    )
    result = route_intents(
        message=USER_NUMBERED_REQUEST,
        inventory=inventory,
        phase_budget=3,
    )
    selected = set(result["selected_capabilities"])
    assert "codex-ppt" not in selected
    assert selected.isdisjoint(NOISE_SKILLS)
    log_rows = [
        row
        for row in result["coverage"]
        if "日志" in str(row.get("text") or "")
    ]
    assert log_rows
    assert any(
        {"dev-supervisor", "supervisor"} & set(row.get("capability_ids") or [])
        for row in log_rows
    )
    assert all(len(phase["capability_ids"]) <= 3 for phase in result["phases"])
    assert result["total_capability_limit"] is None


CODEX_VERIFY_PROMPT = (
    "使用 dev-supervisor（Supervisor v3.1.4）。本轮只在当前工作区 D:\\yuanma\\test 做验证，不要连到其他产品仓库。\n\n"
    "必须：\n"
    "1. 实时扫描当前已安装且启用的 Skill/Agent/Plugin，禁止用历史缓存；给出 inventory hash。\n"
    "2. 把任务拆成多个原子意图/子任务。不同子任务、不同阶段可以调用不同 Skill。整轮没有最低数量、也没有总上限；每一阶段只选当前真正需要的能力，需要更多就开下一阶段，禁止凑数（例如 PPT、可爱 UI 等无关 Skill）。\n"
    "3. 打开并执行选中的 SKILL.md。只有同一 invocation_id 的 attempt + result=success 才算用过；scheduled/deferred 不算成功。已 attempt 且无新证据的不得重复（refused-redundant）。\n"
    "4. 缺证据不要宣称 complete。结束只输出 RoundProcessSummary/v1，外加「阶段 → Skill → 选用/跳过原因」。\n\n"
    "验证任务：\n"
    "写一份一页说明到 src/supervisor-usage.md，讲清「理解需求、扫描本地 Skill、按子任务分阶段调用、质量把关」。不要做实现以外的无关工作。"
)


def test_marked_verify_task_is_not_exploded_into_protocol_product_intents() -> None:
    rows = normalize_intents(split_intents(CODEX_VERIFY_PROMPT), CODEX_VERIFY_PROMPT)
    functional = [row for row in rows if row["kind"] == "functional"]
    constraints = [row for row in rows if row["kind"] == "scope-constraint"]
    joined = " ".join(row["text"] for row in functional)
    assert constraints
    assert any("supervisor-usage.md" in row["text"] for row in functional)
    assert len(functional) <= 3
    assert "实时扫描当前已安装" not in joined
    assert all("dev-supervisor" not in row["text"] for row in functional)
    selected = set(
        route_intents(
            message=CODEX_VERIFY_PROMPT,
            inventory=_inventory(),
            phase_budget=3,
        )["selected_capabilities"]
    )
    assert selected.isdisjoint(NOISE_SKILLS)
    assert "codex-ppt" not in selected


def test_unmarked_numbered_product_request_still_has_three_functional_intents() -> None:
    rows = normalize_intents(split_intents(USER_NUMBERED_REQUEST), USER_NUMBERED_REQUEST)
    functional = [
        row
        for row in rows
        if row["kind"] == "functional" and not row.get("depends_on_intent_ids")
    ]
    assert len(functional) >= 3


def test_covered_disposition_without_evidence_stays_deferred() -> None:
    from supervisor_core.cli import _intent_has_bound_evidence, _apply_state_record

    state = {
        "intents": [{"intent_id": "intent-1", "status": "deferred", "evidence_ids": []}],
        "evidence": [],
    }
    payload = {
        "record": {
            "intent_id": "intent-1",
            "status": "covered",
            "reason": "wrote the file",
        }
    }
    assert _intent_has_bound_evidence(state, state["intents"][0], payload["record"]) is False
    _apply_state_record(state, payload, "intent_disposition")
    assert state["intents"][0]["status"] == "deferred"
    assert "EvidenceRecord" in str(state["intents"][0].get("reason") or "")


def test_child_intents_keep_distinct_text_and_parent_link() -> None:
    rows = normalize_intents(
        [
            {
                "intent_id": "intent-quality",
                "text": "全过程质量监工及时纠偏与最终验收",
                "domain": "quality-gate",
                "kind": "functional",
            },
            {
                "intent_id": "intent-quality-privacy",
                "text": "结束日志不得输出凭据或原始错误栈",
                "domain": "review",
                "kind": "functional",
                "depends_on_intent_ids": ["intent-quality"],
            },
        ]
    )
    child = next(row for row in rows if row["intent_id"] == "intent-quality-privacy")
    parent = next(row for row in rows if row["intent_id"] == "intent-quality")
    assert child["depends_on_intent_ids"] == ["intent-quality"]
    assert child["text"] != parent["text"]
