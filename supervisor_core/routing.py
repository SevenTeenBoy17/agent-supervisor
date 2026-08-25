from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from .contracts import intent_dedupe_key, normalize_intents

_DOMAIN_TERMS: dict[str, tuple[str, ...]] = {
    "ui": ("ui", "frontend", "interface", "page", "前端", "界面", "页面"),
    "api": ("api", "endpoint", "backend", "接口", "后端"),
    "db": ("db", "database", "schema", "数据库", "数据层"),
    "review": (
        "review",
        "reviewer",
        "coderabbit",
        "code rabbit",
        "审查",
        "复核",
        "独立审核",
        "日志",
        "时间线",
        "结束日志",
        "过程日志",
        "简约",
        "结束",
    ),
    "goal-alignment": ("目标", "对齐", "goal", "intent", "需求", "supervisor"),
    "quality-gate": ("质量", "把关", "监工", "验证", "证据", "纠偏", "验收"),
    "capability-reuse": (
        "skill",
        "capability",
        "reuse",
        "routing",
        "router",
        "能力",
        "复用",
        "调用",
        "路由",
        "调度",
        "理解",
        "扫描",
        "agent",
        "已安装",
        "安装并启用",
        "已启用",
        "无总量限制",
        "不限数量",
        "数量限制",
        "总量限制",
        "发挥价值",
        "物尽其用",
    ),
    "testing-acceptance": ("测试验收", "验收测试", "验收", "acceptance test", "acceptance testing"),
    "version-scoring": (
        "前后版本",
        "版本对比",
        "版本比较",
        "多维评分",
        "评分报告",
        "version comparison",
        "version scoring",
        "scorecard",
    ),
    "visualization": ("可视化", "数据可视化", "data visualization", "visualization"),
    "deep-audit": ("深度", "全面", "复审", "扫描", "审计", "audit"),
    "defect-discovery": ("缺陷", "不足", "问题", "重大", "风险", "bug"),
    "repair-design": ("修复", "升级", "优化", "设计", "implement", "解决"),
}

_DOMAIN_PREFERENCES: dict[str, tuple[str, ...]] = {
    "ui": ("ui_implementer", "engineering-frontend-developer"),
    "api": ("api_wirer", "engineering-backend-architect"),
    "db": ("db_architect", "engineering-database-optimizer"),
    "review": (
        "supervisor",
        "dev-supervisor",
        "reviewer",
        "engineering-code-reviewer",
        "testing-reality-checker",
        "code-review-graph-helper",
    ),
    "goal-alignment": ("supervisor", "dev-supervisor", "ce-plan"),
    "quality-gate": ("supervisor", "dev-supervisor", "code-review-graph-helper", "ce-code-review"),
    "capability-reuse": ("supervisor", "dev-supervisor", "ce-agent-native-architecture"),
    "testing-acceptance": ("testing-reality-checker", "ce-proof", "qa_engineer"),
    "version-scoring": (
        "version-scoring-report",
        "data-analytics:build-report",
        "data-analytics:kpi-reporting",
        "build-web-data-visualization:data-visualization",
    ),
    "visualization": (
        "build-web-data-visualization:data-visualization",
        "data-analytics:visualize-data",
        "data-analytics:build-dashboard",
    ),
    "deep-audit": (
        "code-review-graph-helper",
        "ce-doc-review",
        "deep-research",
        "ce-agent-native-architecture",
    ),
    "defect-discovery": ("code-review-graph-helper", "ce-code-review", "ce-debug"),
    "repair-design": ("superpowers:executing-plans", "ce-work", "supervisor", "dev-supervisor"),
}

_TECHNICAL_DOMAINS = {"ui", "api", "db"}
_REVIEW_DOMAINS = {"review", "testing-acceptance"}
_DOMAIN_GROUP_TERMS: dict[str, tuple[str, ...]] = {
    "ui": ("ui", "frontend", "ux"),
    "api": ("api", "backend"),
    "db": ("db", "database"),
    "review": ("review", "reviewer", "qa", "audit"),
}

# These words describe ordinary development context rather than a distinctive
# capability.  They must not turn short fragments such as "global adapters",
# "project hooks", or "test integrity" into apparently strong matches.
_RAW_STOPWORDS = {
    "a",
    "all",
    "an",
    "and",
    "adapter",
    "adapters",
    "agent",
    "as",
    "at",
    "before",
    "build",
    "by",
    "capability",
    "code",
    "coding",
    "create",
    "dev",
    "developer",
    "for",
    "framework",
    "frameworks",
    "from",
    "global",
    "have",
    "hook",
    "hooks",
    "in",
    "integrity",
    "into",
    "is",
    "it",
    "of",
    "on",
    "or",
    "project",
    "review",
    "reviewer",
    "skill",
    "test",
    "tests",
    "testing",
    "the",
    "then",
    "this",
    "to",
    "tool",
    "tools",
    "update",
    "with",
}

# Canonical-name anchors receive the strongest routing confidence, so keep the
# exclusion set deliberately broader than prose stopwords.  A capability named
# only after generic work (for example "code-review") is not self-identifying.
_GENERIC_CANONICAL_TERMS = _RAW_STOPWORDS | {
    "anthropic",
    "chatgpt",
    "claude",
    "codex",
    "debug",
    "fix",
    "grok",
    "implementation",
    "implement",
    "issue",
    "openai",
    "plugin",
    "reuse",
    "route",
    "router",
    "routing",
    "safe",
    "safely",
}

_SUPPLIED_SINGLETON_ACTION_TERMS = {"audit", "build", "implement", "review"}
_SCOPE_CONSTRAINT_MARKERS = (
    "仅编写",
    "只写",
    "不修复",
    "不发布",
    "非目标",
    "不要",
    "禁止",
    "不得宣称",
    "本轮只",
    "不切换全局",
    "不改产品",
    "不得修改",
    "不提交",
)
_NUMBERED_MARKER = re.compile(
    r"(^|[\s。；;：:])(?:\d{1,3}[.)]\s*|\d{1,3}、\s*|"
    r"[（(]\d{1,3}[）)]\s*|[一二三四五六七八九十]+[、.)]\s*)"
)
_NUMBERED_NEW_TOPIC = re.compile(r"(请先|深度思考如何|另外|此外)")
_HEADING_ONLY = re.compile(r"^(?:我的)?核心功能需求是$|^需求如下$|^如下$")
_NOISE_CLAUSES = {"思考分析", "明确过程", "其中表面", "结构等", "插件应用等"}
_DEFAULT_CLAUSE_SPLIT = re.compile(r"[。！？!?；;，,、：\n]+")
_CONJUNCTION_SPLIT = re.compile(
    r"(?i)\b(?:and\s+then|then|also|plus|as\s+well\s+as)\b|"
    r"\band\s+(?=(?:add|fix|update|remove|delete|run|verify|test|review|implement|build|create|ensure|support|write|check|deploy)\b)|"
    r"并且|然后|同时(?:还|再)?|以及|另外|此外|还要|"
    r"并(?=补充|添加|新增|修复|实现|验证|检查|运行|更新|删除|完成|支持|部署|审查|测试)"
)


def _clause_has_term(lowered: str, term: str) -> bool:
    folded = term.casefold()
    if any("\u4e00" <= character <= "\u9fff" for character in folded):
        return folded in lowered
    return bool(re.search(rf"(?<![a-z0-9]){re.escape(folded)}(?![a-z0-9])", lowered))


def _is_scope_constraint_clause(clause: str) -> bool:
    lowered = clause.casefold()
    return any(marker.casefold() in lowered for marker in _SCOPE_CONSTRAINT_MARKERS)


def _clause_domain_matches(clause: str) -> list[str]:
    lowered = clause.casefold()
    scored: list[tuple[int, str]] = []
    for domain, terms in _DOMAIN_TERMS.items():
        weight = 0
        for term in terms:
            if not _clause_has_term(lowered, term):
                continue
            weight += (
                len(term)
                if any("\u4e00" <= character <= "\u9fff" for character in term)
                else 1
            )
        if weight:
            scored.append((weight, domain))
    scored.sort(key=lambda row: -row[0])
    matches = [domain for _weight, domain in scored]
    if _TECHNICAL_DOMAINS.intersection(matches):
        matches = [domain for domain in matches if domain != "repair-design"]
    return matches or ["general"]


def _primary_domain(matches: list[str], used: set[str]) -> str:
    unused = [domain for domain in matches if domain not in used]
    pool = unused or list(matches)
    if "general" in pool and len(pool) > 1:
        pool = [domain for domain in pool if domain != "general"]
    return pool[0]


def _compact_clause(clause: str) -> str:
    return re.sub(r"[\s\d.、，,：:；;！!？?（）()]+", "", clause)


def _is_noise_clause(clause: str) -> bool:
    compact = _compact_clause(clause)
    return (not compact) or bool(_HEADING_ONLY.match(compact)) or compact in _NOISE_CLAUSES or len(compact) <= 2


def _split_default_clauses(text: str) -> list[str]:
    conjunctions = _CONJUNCTION_SPLIT.sub("\n", text)
    return [part.strip() for part in _DEFAULT_CLAUSE_SPLIT.split(conjunctions) if part.strip()]


def _split_numbered_item_body(text: str) -> list[str]:
    return [part.strip() for part in re.split(r"[。！？!?]+", text) if part.strip()]


def _split_soft_clauses(text: str) -> list[str]:
    prepared = re.sub(r"以及(?=不要|禁止|不得)", "\n", text)
    prepared = re.sub(r"(请先)", r"\n\1", prepared)
    return [
        part.strip(" ，,、")
        for part in re.split(r"[。！？!?\n]+", prepared)
        if part.strip(" ，,、")
    ]


def _split_numbered_item(text: str) -> list[str]:
    remaining = text.strip()
    clauses: list[str] = []
    while remaining:
        topic = _NUMBERED_NEW_TOPIC.search(remaining)
        if topic is None:
            clauses.extend(_split_numbered_item_body(remaining))
            break
        if topic.start() > 0:
            clauses.extend(_split_numbered_item_body(remaining[: topic.start()]))
            remaining = remaining[topic.start() :].strip()
            continue
        clauses.extend(_split_soft_clauses(remaining))
        break
    return clauses


def _clauses_from_numbered_message(message: str, matches: list[re.Match[str]]) -> list[str]:
    clauses: list[str] = []
    preamble = message[: matches[0].start()].strip()
    if preamble:
        clauses.extend(_split_default_clauses(preamble))
    for index, match in enumerate(matches):
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(message)
        body = message[start:end].strip()
        if body:
            clauses.extend(_split_numbered_item(body))
    return clauses


def split_intents(message: str) -> list[dict[str, Any]]:
    matches = list(_NUMBERED_MARKER.finditer(message))
    if len(matches) >= 2:
        clauses = _clauses_from_numbered_message(message, matches)
    else:
        numbered = _NUMBERED_MARKER.sub(
            lambda match: (match.group(1) if match.group(1) else "") + "\n",
            message,
        )
        clauses = _split_default_clauses(numbered)
    if not clauses and message.strip():
        clauses = [message.strip()]
    intents: list[dict[str, Any]] = []
    seen: set[str] = set()
    used_domains: set[str] = set()
    for clause in clauses:
        if _is_noise_clause(clause):
            continue
        if _is_scope_constraint_clause(clause):
            domain = "scope-constraint"
            kind = "scope-constraint"
        else:
            domain = _primary_domain(_clause_domain_matches(clause), used_domains)
            kind = "functional"
            used_domains.add(domain)
        key = intent_dedupe_key(clause)
        if not key or key in seen:
            continue
        seen.add(key)
        intents.append(
            {
                "intent_id": f"intent-{len(intents) + 1}",
                "text": clause,
                "domain": domain,
                "kind": kind,
                "dedupe_key": key,
            }
        )
    return intents


def _terms(text: str) -> set[str]:
    folded = text.casefold()
    # Treat punctuation as a separator.  Keeping punctuation inside tokens made
    # identifiers at clause boundaries ("CodeRabbit," / "activation.") fail to
    # compare consistently and let compound generic tokens inflate overlap.
    latin = set(re.findall(r"[a-z][a-z0-9]*", folded))
    chinese = {
        term
        for terms in _DOMAIN_TERMS.values()
        for term in terms
        if any("\u4e00" <= c <= "\u9fff" for c in term) and term in folded
    }
    return latin | chinese


def _high_information_terms(text: str) -> set[str]:
    return {term for term in _terms(text) if term not in _RAW_STOPWORDS}


def _canonical_anchor_terms(capability: dict[str, Any]) -> set[str]:
    canonical = " ".join(str(capability.get(key, "")) for key in ("id", "name"))
    return {term for term in _terms(canonical) if term not in _GENERIC_CANONICAL_TERMS}


def _is_multichar_chinese_term(term: str) -> bool:
    return len(term) >= 2 and any("\u4e00" <= character <= "\u9fff" for character in term)


def _intent_role(intent: dict[str, Any]) -> str:
    explicit = str(intent.get("role") or "").casefold()
    if explicit in {"implementation", "review"}:
        return explicit
    return "review" if str(intent.get("domain") or "general") in _REVIEW_DOMAINS else "implementation"


def _group_matches_domain(group: str, domain: str) -> bool:
    normalized = group.casefold().replace("_", "-")
    return any(term in normalized for term in _DOMAIN_GROUP_TERMS.get(domain, ()))


def _intent_dependency_plan(
    atomic: list[dict[str, Any]],
) -> tuple[list[str], dict[str, list[str]], list[str]]:
    """Validate and topologically order the declared atomic-intent DAG."""
    order: list[str] = []
    positions: dict[str, int] = {}
    dependencies: dict[str, list[str]] = {}
    errors: list[str] = []
    for index, intent in enumerate(atomic):
        intent_id = str(intent.get("intent_id") or "").strip()
        if not intent_id:
            errors.append(f"intent at index {index} has no identity")
            continue
        if intent_id in positions:
            errors.append(f"duplicate intent id: {intent_id}")
            continue
        positions[intent_id] = index
        order.append(intent_id)
        dependencies[intent_id] = [
            str(value).strip()
            for value in intent.get("depends_on_intent_ids", [])
            if isinstance(value, str) and value.strip()
        ]
        if len(dependencies[intent_id]) != len(set(dependencies[intent_id])):
            errors.append(f"duplicate dependency for intent: {intent_id}")
    known = set(order)
    for intent_id in order:
        for dependency in dependencies[intent_id]:
            if dependency == intent_id:
                errors.append(f"self dependency for intent: {intent_id}")
            elif dependency not in known:
                errors.append(
                    f"missing dependency for intent {intent_id}: {dependency}"
                )
    if errors:
        return order, dependencies, errors

    indegree = {intent_id: len(dependencies[intent_id]) for intent_id in order}
    dependents: dict[str, list[str]] = defaultdict(list)
    for intent_id in order:
        for dependency in dependencies[intent_id]:
            dependents[dependency].append(intent_id)
    ready = [intent_id for intent_id in order if indegree[intent_id] == 0]
    topological: list[str] = []
    while ready:
        ready.sort(key=positions.__getitem__)
        current = ready.pop(0)
        topological.append(current)
        for dependent in sorted(dependents[current], key=positions.__getitem__):
            indegree[dependent] -= 1
            if indegree[dependent] == 0:
                ready.append(dependent)
    if len(topological) != len(order):
        cyclic = [intent_id for intent_id in order if indegree[intent_id] > 0]
        errors.append(f"intent dependency cycle: {', '.join(cyclic)}")
        return order, dependencies, errors
    return topological, dependencies, []


def _global_capability_identity_conflicts(
    skills: list[Any], agents: list[Any]
) -> tuple[list[str], list[dict[str, Any]]]:
    """Index every Skill/primary/fallback by one casefold canonical identity."""
    index: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for collection, rows in (("skill", skills), ("agent", agents)):
        for raw in rows:
            if not isinstance(raw, dict):
                continue
            canonical_id = str(
                raw.get("id") or raw.get("name") or ""
            ).strip().casefold()
            if not canonical_id:
                continue
            index[canonical_id].append(
                {
                    "kind": collection,
                    "fallback_only": bool(raw.get("fallback_only")),
                    "responsibility_group": str(
                        raw.get("responsibility_group") or ""
                    ),
                }
            )
    conflicts = sorted(
        canonical_id
        for canonical_id, records in index.items()
        if len(records) > 1
    )
    diagnostics = [
        {
            "code": "canonical-capability-id-collision",
            "canonical_id": canonical_id,
            "record_count": len(index[canonical_id]),
            "kinds": sorted({row["kind"] for row in index[canonical_id]}),
            "responsibility_groups": sorted(
                {
                    row["responsibility_group"]
                    for row in index[canonical_id]
                    if row["responsibility_group"].strip()
                },
                key=str.casefold,
            ),
            "includes_fallback": any(
                row["fallback_only"] for row in index[canonical_id]
            ),
        }
        for canonical_id in conflicts
    ]
    return conflicts, diagnostics


def _invalid_route(
    *,
    message: str,
    atomic: list[dict[str, Any]],
    phase_budget: int,
    errors: list[str],
    dependency_order: list[str],
    dependencies: dict[str, list[str]],
    identity_conflicts: list[str] | None = None,
    identity_conflict_diagnostics: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    reason = "; ".join(errors)
    return {
        "schema_version": 3,
        "message": message,
        "coverage": [
            {
                "contract": "IntentCoverage/v3",
                "intent_id": str(intent.get("intent_id") or f"intent-{index}"),
                "text": str(intent.get("text") or ""),
                "domain": str(intent.get("domain") or "general"),
                "status": "failed",
                "reason": reason,
                "capability_ids": [],
                "skill_capability_ids": [],
                "agent_capability_ids": [],
                "role": _intent_role(intent),
                "required_responsibility_groups": list(
                    intent.get("required_responsibility_groups", [])
                ),
                "depends_on_intent_ids": list(
                    intent.get("depends_on_intent_ids", [])
                ),
            }
            for index, intent in enumerate(atomic, start=1)
        ],
        "phases": [],
        "selected_capabilities": [],
        "selected_skills": [],
        "selected_agents": [],
        "phase_budget": phase_budget,
        "total_capability_limit": None,
        "zero_skill": True,
        "zero_skill_reviewed": False,
        "zero_skill_review_status": "not-applicable-invalid-route",
        "review_required": True,
        "dependency_graph": {
            "status": "invalid",
            "topological_intent_order": dependency_order,
            "dependencies": dependencies,
        },
        "identity_conflicts": list(identity_conflicts or []),
        "identity_conflict_diagnostics": list(
            identity_conflict_diagnostics or []
        ),
        "rejected": [],
        "valid": False,
        "errors": errors,
    }


def route_intents(
    *,
    message: str,
    inventory: dict[str, Any] | None,
    supplied_intents: Any = None,
    phase_budget: int = 3,
    zero_skill_reviewed: bool = False,
) -> dict[str, Any]:
    if phase_budget not in {2, 3}:
        raise ValueError("phase budget must be 2 or 3")
    caller_supplied_intents = supplied_intents is not None
    if supplied_intents is None:
        atomic = split_intents(message)
    else:
        atomic = normalize_intents(supplied_intents)
        supplied_rows = supplied_intents if isinstance(supplied_intents, list) else []
        for index, item in enumerate(atomic):
            item.setdefault("domain", "general")
            raw = supplied_rows[index] if index < len(supplied_rows) else None
            if isinstance(raw, dict) and (
                raw.get("_preserve_routing") is True
                or raw.get("carried_from_goal_version") is not None
            ):
                # This in-memory flag prevents a privacy-safe hash label from
                # being treated as the original request on a later round.
                item["_preserve_routing"] = True
    dependency_order, intent_dependencies, dependency_errors = (
        _intent_dependency_plan(atomic)
    )
    if dependency_errors:
        return _invalid_route(
            message=message,
            atomic=atomic,
            phase_budget=phase_budget,
            errors=dependency_errors,
            dependency_order=dependency_order,
            dependencies=intent_dependencies,
        )
    inventory = inventory if isinstance(inventory, dict) else {}
    raw_skills = inventory.get("skills")
    if not isinstance(raw_skills, list):
        raw_skills = inventory.get("capabilities")
    if not isinstance(raw_skills, list):
        raw_skills = []
    raw_agents = inventory.get("agents")
    if not isinstance(raw_agents, list):
        raw_agents = []

    identity_conflicts, identity_conflict_diagnostics = (
        _global_capability_identity_conflicts(raw_skills, raw_agents)
    )
    if identity_conflicts:
        conflict_errors = [
            f"canonical capability identity collision: {capability_id}"
            for capability_id in identity_conflicts
        ]
        return _invalid_route(
            message=message,
            atomic=atomic,
            phase_budget=phase_budget,
            errors=conflict_errors,
            dependency_order=dependency_order,
            dependencies=intent_dependencies,
            identity_conflicts=identity_conflicts,
            identity_conflict_diagnostics=identity_conflict_diagnostics,
        )

    def eligible(rows: list[Any], capability_kind: str) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for raw in rows:
            # route_intents receives only an inventory, not a trusted host-event
            # context.  It therefore cannot promote any Agent claim.  A future
            # host integration must validate current session+inventory liveness
            # before adding an explicitly trusted routing input; Skills remain
            # independently routable from their installed descriptors.
            agent_liveness_verified = capability_kind != "agent"
            if not (
                isinstance(raw, dict)
                and raw.get("active", True)
                and raw.get("automatic", True)
                and raw.get("availability", "enabled") == "enabled"
                and raw.get("health", "healthy") == "healthy"
                and agent_liveness_verified
            ):
                continue
            row = dict(raw)
            # Collection membership, not a Skill-controlled inner field,
            # establishes whether the record may carry Agent identity.
            row["capability_kind"] = capability_kind
            result.append(row)
        return result

    skills = eligible(raw_skills, "skill")
    agents = eligible(raw_agents, "agent")
    capabilities = skills + agents
    capabilities_by_id: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for capability in capabilities:
        capability_id = str(capability.get("id") or capability.get("name") or "").strip()
        if capability_id:
            capabilities_by_id[capability_id.casefold()].append(capability)
    selected: list[str] = []
    selected_skills: list[str] = []
    selected_agents: list[str] = []
    capability_roles: dict[str, set[str]] = defaultdict(set)
    coverage: list[dict[str, Any]] = []
    rejected: list[dict[str, str]] = []
    from .validation import (
        PROGRESS_GUARD_REFUSE_REDUNDANT,
        progress_guard_decision,
    )
    for index, intent in enumerate(atomic, start=1):
        text = str(intent.get("text", ""))
        domain = str(intent.get("domain", "general"))
        role = _intent_role(intent)
        intent_id = str(intent.get("intent_id") or f"intent-{index}")
        required_groups = {
            str(group).casefold()
            for group in intent.get("required_responsibility_groups", [])
            if isinstance(group, str) and group.strip()
        }
        blocked_capabilities: set[str] = set()
        for attempt in intent.get("attempted_capabilities") or []:
            if not isinstance(attempt, dict):
                continue
            attempted_id = str(attempt.get("capability_id") or "").strip()
            if not attempted_id:
                continue
            if progress_guard_decision(intent, attempted_id) == PROGRESS_GUARD_REFUSE_REDUNDANT:
                blocked_capabilities.add(attempted_id)
                rejected.append(
                    {
                        "intent_id": intent_id,
                        "capability_id": attempted_id,
                        "status": "refused-redundant",
                        "reason": "already-attempted-without-new-evidence",
                    }
                )
        if str(intent.get("status") or "") == "covered":
            coverage.append(
                {
                    "contract": "IntentCoverage/v3",
                    "intent_id": intent_id,
                    "text": text,
                    "domain": domain,
                    "kind": str(intent.get("kind") or "functional"),
                    "dedupe_key": str(intent.get("dedupe_key") or intent_dedupe_key(text)),
                    "acceptance_criteria": list(intent.get("acceptance_criteria") or []),
                    "evidence_ids": list(intent.get("evidence_ids") or []),
                    "attempted_capabilities": list(intent.get("attempted_capabilities") or []),
                    "status": "skipped",
                    "reason": "already covered; redundant routing skipped",
                    "capability_ids": [],
                    "skill_capability_ids": [],
                    "agent_capability_ids": [],
                    "role": role,
                    "required_responsibility_groups": sorted(required_groups),
                    "depends_on_intent_ids": list(intent.get("depends_on_intent_ids", [])),
                }
            )
            continue
        if str(intent.get("kind") or "") == "scope-constraint" or domain == "scope-constraint":
            coverage.append(
                {
                    "contract": "IntentCoverage/v3",
                    "intent_id": intent_id,
                    "text": text,
                    "domain": "scope-constraint",
                    "kind": "scope-constraint",
                    "dedupe_key": str(intent.get("dedupe_key") or intent_dedupe_key(text)),
                    "acceptance_criteria": list(intent.get("acceptance_criteria") or []),
                    "evidence_ids": list(intent.get("evidence_ids") or []),
                    "attempted_capabilities": list(intent.get("attempted_capabilities") or []),
                    "status": "skipped",
                    "reason": "scope/non-goal constraint; not a functional routing target",
                    "capability_ids": [],
                    "skill_capability_ids": [],
                    "agent_capability_ids": [],
                    "role": role,
                    "required_responsibility_groups": sorted(required_groups),
                    "depends_on_intent_ids": list(intent.get("depends_on_intent_ids", [])),
                }
            )
            continue
        preserve_routing = intent.get("_preserve_routing") is True
        if preserve_routing:
            prior_ids = [
                str(value).strip()
                for value in intent.get("capability_ids", [])
                if isinstance(value, str) and value.strip() and value.strip() not in blocked_capabilities
            ]
            chosen_capabilities: list[dict[str, Any]] = []
            chosen_ids: list[str] = []
            for prior_capability_id in prior_ids:
                candidates = capabilities_by_id.get(
                    prior_capability_id.casefold(), []
                )
                candidate = next(
                    (
                        row for row in candidates
                        if row.get("capability_kind") == "agent"
                    ),
                    candidates[0] if candidates else None,
                )
                capability_id = str(
                    candidate.get("id") or candidate.get("name") or ""
                ).strip() if candidate is not None else ""
                if candidate is not None and capability_id not in chosen_ids:
                    chosen_ids.append(capability_id)
                    chosen_capabilities.append(candidate)

            missing_required_groups: list[str] = []
            for group in sorted(required_groups):
                if any(
                    row.get("capability_kind") == "agent"
                    and str(row.get("responsibility_group") or "").casefold() == group
                    for row in chosen_capabilities
                ):
                    continue
                replacement = next(
                    (
                        row for row in agents
                        if str(row.get("responsibility_group") or "").casefold() == group
                    ),
                    None,
                )
                if replacement is None:
                    missing_required_groups.append(group)
                    continue
                replacement_id = str(
                    replacement.get("id") or replacement.get("name") or ""
                ).strip()
                if replacement_id and replacement_id not in chosen_ids:
                    chosen_ids.append(replacement_id)
                    chosen_capabilities.append(replacement)
            if missing_required_groups:
                chosen_ids = []
                chosen_capabilities = []

            if chosen_ids:
                for capability_id, capability in zip(chosen_ids, chosen_capabilities):
                    if capability_id not in selected:
                        selected.append(capability_id)
                    target = (
                        selected_agents
                        if capability.get("capability_kind") == "agent"
                        else selected_skills
                    )
                    if capability_id not in target:
                        target.append(capability_id)
                    capability_roles[capability_id].add(role)
                coverage.append(
                    {
                        "contract": "IntentCoverage/v3",
                        "intent_id": str(intent.get("intent_id") or f"intent-{index}"),
                        "text": text,
                        "domain": domain,
                        "status": "deferred",
                        "reason": "carried routing preserved without re-ranking prior prompt text",
                        "capability_ids": chosen_ids,
                        "skill_capability_ids": [
                            capability_id
                            for capability_id, capability in zip(chosen_ids, chosen_capabilities)
                            if capability.get("capability_kind") == "skill"
                        ],
                        "agent_capability_ids": [
                            capability_id
                            for capability_id, capability in zip(chosen_ids, chosen_capabilities)
                            if capability.get("capability_kind") == "agent"
                        ],
                        "role": role,
                        "required_responsibility_groups": sorted(required_groups),
                        "depends_on_intent_ids": list(intent.get("depends_on_intent_ids", [])),
                    }
                )
            else:
                coverage.append(
                    {
                        "contract": "IntentCoverage/v3",
                        "intent_id": str(intent.get("intent_id") or f"intent-{index}"),
                        "text": text,
                        "domain": domain,
                        "status": "skipped",
                        "reason": (
                            f"required responsibility groups unavailable: {', '.join(missing_required_groups)}"
                            if missing_required_groups
                            else "carried capabilities unavailable; prior raw prompt was not retained and was not re-ranked"
                        ),
                        "capability_ids": [],
                        "skill_capability_ids": [],
                        "agent_capability_ids": [],
                        "role": role,
                        "required_responsibility_groups": sorted(required_groups),
                        "depends_on_intent_ids": list(intent.get("depends_on_intent_ids", [])),
                    }
                )
            continue
        raw_terms = _terms(text)
        raw_high_information = _high_information_terms(text)
        # Domain expansion helps order already-qualified candidates; it must not
        # qualify a capability that has no evidence in the original request.
        wanted = _terms(text) | set(_DOMAIN_TERMS.get(domain, ()))
        ranked = []
        for capability in capabilities:
            capability_id = str(capability.get("id") or capability.get("name") or "").strip()
            if not capability_id or capability_id in blocked_capabilities:
                continue
            ranking_fields = ["id", "name", "description", "owns"]
            if capability.get("capability_kind") == "agent":
                ranking_fields.append("responsibility_group")
            haystack = " ".join(
                str(capability.get(key, "")) for key in ranking_fields
            )
            capability_terms = _terms(haystack)
            raw_overlap = raw_high_information & {
                term for term in capability_terms if term not in _RAW_STOPWORDS
            }
            score = len(wanted & capability_terms)
            if domain != "general" and _clause_has_term(haystack.casefold(), domain):
                score += 3
            preferences = _DOMAIN_PREFERENCES.get(domain, ())
            preferred = capability_id in preferences
            if preferred:
                score += 100 - preferences.index(capability_id)
            group = (
                str(capability.get("responsibility_group") or "").casefold()
                if capability.get("capability_kind") == "agent"
                else ""
            )
            required_group_match = bool(group and group in required_groups)
            if required_group_match:
                score += 200
            if capability.get("capability_kind") == "agent" and (
                required_group_match or (role == "review" and preferred)
            ):
                score += 50
            domain_group_match = bool(group and _group_matches_domain(group, domain))
            canonical_anchor = bool(
                raw_high_information & _canonical_anchor_terms(capability)
            )
            supplied_singleton_action_match = bool(
                caller_supplied_intents
                and len(raw_terms) == 1
                and raw_terms <= _SUPPLIED_SINGLETON_ACTION_TERMS
                and raw_terms & capability_terms
            )
            supplied_chinese_domain_match = bool(
                any(
                    _is_multichar_chinese_term(term)
                    for term in raw_overlap & set(_DOMAIN_TERMS.get(domain, ()))
                )
            )
            if canonical_anchor:
                confidence = 3
            elif preferred or required_group_match:
                confidence = 2
            elif (
                len(raw_overlap) >= 2
                or (domain_group_match and raw_overlap)
                or supplied_singleton_action_match
                or supplied_chinese_domain_match
            ):
                confidence = 1
            else:
                confidence = 0
            criteria = intent.get("acceptance_criteria") or []
            if criteria and confidence and not (
                preferred
                or raw_overlap
                or any(
                    _high_information_terms(str(criterion)) & capability_terms
                    for criterion in criteria
                    if isinstance(criterion, str)
                )
            ):
                confidence = 0
            if confidence:
                ranked.append((confidence, score, capability_id, capability))
        ranked.sort(key=lambda row: (-row[0], -row[1], row[2]))
        chosen_ids: list[str] = []
        missing_required_groups: list[str] = []
        if required_groups:
            for group in sorted(required_groups):
                winner = next(
                    (
                        row for row in ranked
                        if row[3].get("capability_kind") == "agent"
                        and str(row[3].get("responsibility_group") or "").casefold() == group
                    ),
                    None,
                )
                if winner:
                    chosen_ids.append(winner[2])
                else:
                    missing_required_groups.append(group)
            if missing_required_groups:
                # A capability from another responsibility group cannot satisfy
                # an explicit ownership/reviewer contract.  Do not partially
                # schedule the intent and do not fall back to the top scorer.
                chosen_ids = []
        elif domain in _DOMAIN_GROUP_TERMS:
            grouped: dict[str, tuple[int, int, str, dict[str, Any]]] = {}
            for row in ranked:
                group = str(row[3].get("responsibility_group") or "").strip()
                if group and _group_matches_domain(group, domain) and group not in grouped:
                    grouped[group] = row
            chosen_ids = [row[2] for row in grouped.values()]
        if not required_groups and not chosen_ids and ranked:
            chosen_ids = [ranked[0][2]]
        chosen_ids = [item for item in chosen_ids if item not in blocked_capabilities]
        if chosen_ids:
            for chosen in chosen_ids:
                if chosen not in selected:
                    selected.append(chosen)
                capability_roles[chosen].add(role)
                chosen_record = next(
                    (row[3] for row in ranked if row[2] == chosen),
                    None,
                )
                if isinstance(chosen_record, dict):
                    target = (
                        selected_agents
                        if chosen_record.get("capability_kind") == "agent"
                        else selected_skills
                    )
                    if chosen not in target:
                        target.append(chosen)
            chosen_records = {
                chosen: next((row[3] for row in ranked if row[2] == chosen), {})
                for chosen in chosen_ids
            }
            coverage.append(
                {
                    "contract": "IntentCoverage/v3",
                    "intent_id": str(intent.get("intent_id") or f"intent-{index}"),
                    "text": text,
                    "domain": domain,
                    "kind": str(intent.get("kind") or "functional"),
                    "dedupe_key": str(intent.get("dedupe_key") or intent_dedupe_key(text)),
                    "acceptance_criteria": list(intent.get("acceptance_criteria") or []),
                    "evidence_ids": list(intent.get("evidence_ids") or []),
                    "attempted_capabilities": list(intent.get("attempted_capabilities") or []),
                    "status": "deferred",
                    "reason": f"scheduled for capabilities {', '.join(chosen_ids)}",
                    "capability_ids": chosen_ids,
                    "skill_capability_ids": [
                        chosen for chosen in chosen_ids
                        if chosen_records[chosen].get("capability_kind") == "skill"
                    ],
                    "agent_capability_ids": [
                        chosen for chosen in chosen_ids
                        if chosen_records[chosen].get("capability_kind") == "agent"
                    ],
                    "role": role,
                    "required_responsibility_groups": sorted(required_groups),
                    "depends_on_intent_ids": list(intent.get("depends_on_intent_ids", [])),
                }
            )
        else:
            coverage.append(
                {
                    "contract": "IntentCoverage/v3",
                    "intent_id": str(intent.get("intent_id") or f"intent-{index}"),
                    "text": text,
                    "domain": domain,
                    "kind": str(intent.get("kind") or "functional"),
                    "dedupe_key": str(intent.get("dedupe_key") or intent_dedupe_key(text)),
                    "acceptance_criteria": list(intent.get("acceptance_criteria") or []),
                    "evidence_ids": list(intent.get("evidence_ids") or []),
                    "attempted_capabilities": list(intent.get("attempted_capabilities") or []),
                    "status": "skipped",
                    "reason": (
                        f"required responsibility groups unavailable: {', '.join(missing_required_groups)}"
                        if missing_required_groups
                        else "no high-signal enabled, automatic, healthy capability matched this atomic intent"
                    ),
                    "capability_ids": [],
                    "skill_capability_ids": [],
                    "agent_capability_ids": [],
                    "role": role,
                    "required_responsibility_groups": sorted(required_groups),
                    "depends_on_intent_ids": list(intent.get("depends_on_intent_ids", [])),
                }
            )
    phases: list[dict[str, Any]] = []
    coverage_by_id = {
        str(item.get("intent_id") or ""): item for item in coverage
    }
    intent_phases: dict[str, list[int]] = defaultdict(list)
    explicit_dependency_mode = any(intent_dependencies.values())
    dependency_execution_errors: list[str] = []
    intent_levels: dict[str, int] = {}
    for intent_id in dependency_order:
        dependencies = intent_dependencies.get(intent_id, [])
        intent_levels[intent_id] = (
            max(intent_levels[dependency] for dependency in dependencies) + 1
            if dependencies
            else 0
        )
    role_order = {"implementation": 0, "review": 1}
    groups: dict[tuple[int, str], list[str]] = defaultdict(list)
    for intent_id in dependency_order:
        item = coverage_by_id.get(intent_id)
        if isinstance(item, dict) and item.get("capability_ids"):
            groups[(intent_levels[intent_id], str(item.get("role") or "implementation"))].append(intent_id)

    for (_level, role), group_intents in sorted(
        groups.items(),
        key=lambda row: (
            row[0][0],
            role_order.get(row[0][1], 2),
            dependency_order.index(row[1][0]),
        ),
    ):
        capability_order: list[str] = []
        capability_intents: dict[str, list[str]] = defaultdict(list)
        for intent_id in group_intents:
            item = coverage_by_id[intent_id]
            for capability_id in item.get("capability_ids", []):
                if capability_id not in capability_order:
                    capability_order.append(capability_id)
                if intent_id not in capability_intents[capability_id]:
                    capability_intents[capability_id].append(intent_id)
        previous_chunk_phase: int | None = None
        for offset in range(0, len(capability_order), phase_budget):
            chunk = capability_order[offset : offset + phase_budget]
            chunk_intents = [
                intent_id
                for intent_id in group_intents
                if any(intent_id in capability_intents[value] for value in chunk)
            ]
            phase_dependencies: list[int] = []
            for intent_id in chunk_intents:
                for dependency_id in intent_dependencies.get(intent_id, []):
                    bound = intent_phases.get(dependency_id, [])
                    if not bound:
                        dependency_execution_errors.append(
                            f"intent dependency has no executable phase: {intent_id} -> {dependency_id}"
                        )
                    for phase_id in bound:
                        if phase_id not in phase_dependencies:
                            phase_dependencies.append(phase_id)
            if (
                not explicit_dependency_mode
                and role == "review"
                and not phase_dependencies
            ):
                phase_dependencies = [
                    phase["phase"]
                    for phase in phases
                    if phase.get("role") == "implementation"
                ]
            if (
                previous_chunk_phase is not None
                and previous_chunk_phase not in phase_dependencies
            ):
                phase_dependencies.append(previous_chunk_phase)
            phase_id = len(phases) + 1
            phases.append(
                {
                    "phase": phase_id,
                    "capability_ids": chunk,
                    "intent_ids": chunk_intents,
                    "role": role,
                    "depends_on": sorted(phase_dependencies),
                }
            )
            for intent_id in chunk_intents:
                intent_phases[intent_id].append(phase_id)
            previous_chunk_phase = phase_id
    for intent_id, item_phases in intent_phases.items():
        item = coverage_by_id[intent_id]
        item["phase"] = item_phases[0]
        item["phases"] = list(item_phases)
    zero_skill = not selected
    required_group_errors = [
        f"{item['intent_id']}: {item['reason']}"
        for item in coverage
        if item["status"] == "skipped" and item["required_responsibility_groups"]
    ]
    dependency_execution_errors = list(dict.fromkeys(dependency_execution_errors))
    zero_skill_valid = bool(
        not zero_skill
        and not required_group_errors
        and not dependency_execution_errors
    )
    zero_skill_review_status = (
        "not-required"
        if not zero_skill
        else "claimed-unverified"
        if zero_skill_reviewed
        else "missing"
    )
    zero_skill_errors: list[str] = [
        *required_group_errors,
        *dependency_execution_errors,
    ]
    if zero_skill:
        zero_skill_errors.append(
            "zero-skill review was claimed but the flag is not evidence; a structured independent ReviewRecord must be validated at finalization"
            if zero_skill_reviewed
            else "zero-skill routing is missing a structured independent ReviewRecord"
        )
    return {
        "schema_version": 3,
        "message": message,
        "coverage": coverage,
        "phases": phases,
        "selected_capabilities": selected,
        "selected_skills": selected_skills,
        "selected_agents": selected_agents,
        "phase_budget": phase_budget,
        "total_capability_limit": None,
        "zero_skill": zero_skill,
        "zero_skill_reviewed": zero_skill_reviewed,
        "zero_skill_review_status": zero_skill_review_status,
        "review_required": bool(zero_skill or dependency_execution_errors),
        "dependency_graph": {
            "status": "invalid" if dependency_execution_errors else "valid",
            "topological_intent_order": dependency_order,
            "dependencies": intent_dependencies,
        },
        "identity_conflicts": [],
        "identity_conflict_diagnostics": [],
        "rejected": rejected,
        "valid": zero_skill_valid,
        "errors": zero_skill_errors,
    }
