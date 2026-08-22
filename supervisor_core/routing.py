from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from .contracts import normalize_intents

_DOMAIN_TERMS: dict[str, tuple[str, ...]] = {
    "ui": ("ui", "frontend", "interface", "page", "前端", "界面", "页面"),
    "api": ("api", "endpoint", "backend", "接口", "后端"),
    "db": ("db", "database", "schema", "数据库", "数据层"),
    "review": ("review", "reviewer", "审查", "复核", "独立审核"),
    "goal-alignment": ("目标", "对齐", "goal", "intent", "需求"),
    "quality-gate": ("质量", "把关", "监工", "验证", "证据"),
    "capability-reuse": ("skill", "capability", "reuse", "routing", "router", "能力", "复用", "调用", "路由", "agent"),
    "deep-audit": ("深度", "全面", "复审", "扫描", "审计", "audit"),
    "defect-discovery": ("缺陷", "不足", "问题", "重大", "风险", "bug"),
    "repair-design": ("修复", "升级", "优化", "设计", "implement", "解决"),
}

_DOMAIN_PREFERENCES: dict[str, tuple[str, ...]] = {
    "ui": ("ui_implementer", "engineering-frontend-developer"),
    "api": ("api_wirer", "engineering-backend-architect"),
    "db": ("db_architect", "engineering-database-optimizer"),
    "review": ("reviewer", "engineering-code-reviewer", "testing-reality-checker", "code-review-graph-helper"),
    "goal-alignment": ("supervisor", "dev-supervisor", "ce-plan"),
    "quality-gate": ("supervisor", "dev-supervisor", "code-review-graph-helper", "ce-code-review"),
    "capability-reuse": ("supervisor", "dev-supervisor", "ce-agent-native-architecture"),
    "deep-audit": ("code-review-graph-helper", "ce-doc-review", "deep-research"),
    "defect-discovery": ("code-review-graph-helper", "ce-code-review", "ce-debug"),
    "repair-design": ("superpowers:executing-plans", "ce-work", "supervisor", "dev-supervisor"),
}

_TECHNICAL_DOMAINS = {"ui", "api", "db"}
_REVIEW_DOMAINS = {"review"}
_DOMAIN_GROUP_TERMS: dict[str, tuple[str, ...]] = {
    "ui": ("ui", "frontend", "ux"),
    "api": ("api", "backend"),
    "db": ("db", "database"),
    "review": ("review", "reviewer", "qa", "audit"),
}


def _clause_has_term(lowered: str, term: str) -> bool:
    folded = term.casefold()
    if any("\u4e00" <= character <= "\u9fff" for character in folded):
        return folded in lowered
    return bool(re.search(rf"(?<![a-z0-9]){re.escape(folded)}(?![a-z0-9])", lowered))


def split_intents(message: str) -> list[dict[str, Any]]:
    numbered = re.sub(
        r"(^|[\s。；;])(?:\d{1,3}[.)]\s+|\d{1,3}、\s*|[（(]\d{1,3}[）)]\s*|[一二三四五六七八九十]+[、.)]\s*)",
        lambda match: (match.group(1) if match.group(1) else "") + "\n",
        message,
    )
    conjunctions = re.sub(
        r"(?i)\b(?:and\s+then|then|also|plus|as\s+well\s+as)\b|"
        r"\band\s+(?=(?:add|fix|update|remove|delete|run|verify|test|review|implement|build|create|ensure|support|write|check|deploy)\b)|"
        r"并且|然后|同时(?:还|再)?|以及|另外|此外|还要|"
        r"并(?=补充|添加|新增|修复|实现|验证|检查|运行|更新|删除|完成|支持|部署|审查|测试)",
        "\n",
        numbered,
    )
    clauses = [part.strip() for part in re.split(r"[。！？!?；;，,\n]+", conjunctions) if part.strip()]
    if not clauses and message.strip():
        clauses = [message.strip()]
    intents: list[dict[str, Any]] = []
    seen: set[str] = set()
    for clause in clauses:
        matches = []
        lowered = clause.casefold()
        for domain, terms in _DOMAIN_TERMS.items():
            if any(_clause_has_term(lowered, term) for term in terms):
                matches.append(domain)
        # A concrete implementation domain is more informative than the generic
        # "implement/repair" meta-domain triggered by the same clause.
        if _TECHNICAL_DOMAINS.intersection(matches):
            matches = [domain for domain in matches if domain != "repair-design"]
        if not matches:
            matches = ["general"]
        for domain in matches:
            key = f"{domain}:{clause}"
            if key not in seen:
                intents.append({"intent_id": f"intent-{len(intents) + 1}", "text": clause, "domain": domain})
                seen.add(key)
    return intents


def _terms(text: str) -> set[str]:
    latin = set(re.findall(r"[a-zA-Z][a-zA-Z0-9_.:+/-]*", text.casefold()))
    chinese = {term for terms in _DOMAIN_TERMS.values() for term in terms if any("\u4e00" <= c <= "\u9fff" for c in term) and term in text}
    return latin | chinese


def _intent_role(intent: dict[str, Any]) -> str:
    explicit = str(intent.get("role") or "").casefold()
    if explicit in {"implementation", "review"}:
        return explicit
    return "review" if str(intent.get("domain") or "general") in _REVIEW_DOMAINS else "implementation"


def _group_matches_domain(group: str, domain: str) -> bool:
    normalized = group.casefold().replace("_", "-")
    return any(term in normalized for term in _DOMAIN_GROUP_TERMS.get(domain, ()))


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
    if supplied_intents is None:
        atomic = split_intents(message)
    else:
        atomic = normalize_intents(supplied_intents)
        for item in atomic:
            item.setdefault("domain", "general")
    inventory = inventory if isinstance(inventory, dict) else {}
    raw_capabilities = inventory.get("skills")
    if not isinstance(raw_capabilities, list):
        raw_capabilities = inventory.get("capabilities")
    if not isinstance(raw_capabilities, list):
        raw_capabilities = []
    capabilities = [
        row
        for row in raw_capabilities
        if isinstance(row, dict)
        and row.get("active", True)
        and row.get("automatic", True)
        and row.get("availability", "enabled") == "enabled"
        and row.get("health", "healthy") == "healthy"
    ]
    selected: list[str] = []
    capability_roles: dict[str, set[str]] = defaultdict(set)
    coverage: list[dict[str, Any]] = []
    for index, intent in enumerate(atomic, start=1):
        text = str(intent.get("text", ""))
        domain = str(intent.get("domain", "general"))
        role = _intent_role(intent)
        required_groups = {
            str(group).casefold()
            for group in intent.get("required_responsibility_groups", [])
            if isinstance(group, str) and group.strip()
        }
        wanted = _terms(text) | set(_DOMAIN_TERMS.get(domain, ()))
        ranked = []
        for capability in capabilities:
            capability_id = str(capability.get("id") or capability.get("name") or "").strip()
            if not capability_id:
                continue
            haystack = " ".join(
                str(capability.get(key, ""))
                for key in ("id", "name", "description", "owns", "responsibility_group")
            )
            score = len(wanted & _terms(haystack))
            if domain != "general" and _clause_has_term(haystack.casefold(), domain):
                score += 3
            preferences = _DOMAIN_PREFERENCES.get(domain, ())
            if capability_id in preferences:
                score += 100 - preferences.index(capability_id)
            group = str(capability.get("responsibility_group") or "").casefold()
            if group and group in required_groups:
                score += 200
            if score:
                ranked.append((score, capability_id, capability))
        ranked.sort(key=lambda row: (-row[0], row[1]))
        chosen_ids: list[str] = []
        missing_required_groups: list[str] = []
        if required_groups:
            for group in sorted(required_groups):
                winner = next(
                    (row for row in ranked if str(row[2].get("responsibility_group") or "").casefold() == group),
                    None,
                )
                if winner:
                    chosen_ids.append(winner[1])
                else:
                    missing_required_groups.append(group)
            if missing_required_groups:
                # A capability from another responsibility group cannot satisfy
                # an explicit ownership/reviewer contract.  Do not partially
                # schedule the intent and do not fall back to the top scorer.
                chosen_ids = []
        elif domain in _DOMAIN_GROUP_TERMS:
            grouped: dict[str, tuple[int, str, dict[str, Any]]] = {}
            for row in ranked:
                group = str(row[2].get("responsibility_group") or "").strip()
                if group and _group_matches_domain(group, domain) and group not in grouped:
                    grouped[group] = row
            chosen_ids = [row[1] for row in grouped.values()]
        if not required_groups and not chosen_ids and ranked:
            chosen_ids = [ranked[0][1]]
        if chosen_ids:
            for chosen in chosen_ids:
                if chosen not in selected:
                    selected.append(chosen)
                capability_roles[chosen].add(role)
            coverage.append(
                {
                    "contract": "IntentCoverage/v3",
                    "intent_id": str(intent.get("intent_id") or f"intent-{index}"),
                    "text": text,
                    "domain": domain,
                    "status": "deferred",
                    "reason": f"scheduled for capabilities {', '.join(chosen_ids)}",
                    "capability_ids": chosen_ids,
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
                        else "no enabled, automatic, healthy capability matched this atomic intent"
                    ),
                    "capability_ids": [],
                    "role": role,
                    "required_responsibility_groups": sorted(required_groups),
                    "depends_on_intent_ids": list(intent.get("depends_on_intent_ids", [])),
                }
            )
    phases: list[dict[str, Any]] = []
    capability_phase: dict[tuple[str, str], int] = {}
    implementation_ids = [item for item in selected if "implementation" in capability_roles[item]]
    review_ids = [item for item in selected if "review" in capability_roles[item]]
    for role, role_ids in (("implementation", implementation_ids), ("review", review_ids)):
        for offset in range(0, len(role_ids), phase_budget):
            ids = role_ids[offset : offset + phase_budget]
            phase_id = len(phases) + 1
            phases.append({"phase": phase_id, "capability_ids": ids, "intent_ids": [], "role": role, "depends_on": []})
            for capability_id in ids:
                capability_phase[(capability_id, role)] = phase_id
    implementation_phases = [phase["phase"] for phase in phases if phase["role"] == "implementation"]
    for phase in phases:
        if phase["role"] == "review":
            phase["depends_on"] = list(implementation_phases)
    for item in coverage:
        if item["capability_ids"]:
            item_phases = sorted({
                capability_phase[(capability_id, item["role"])]
                for capability_id in item["capability_ids"]
            })
            item["phase"] = item_phases[0]
            item["phases"] = item_phases
            for phase_number in item_phases:
                phases[phase_number - 1]["intent_ids"].append(item["intent_id"])
    zero_skill = not selected
    required_group_errors = [
        f"{item['intent_id']}: {item['reason']}"
        for item in coverage
        if item["status"] == "skipped" and item["required_responsibility_groups"]
    ]
    zero_skill_valid = not zero_skill and not required_group_errors
    zero_skill_review_status = (
        "not-required"
        if not zero_skill
        else "claimed-unverified"
        if zero_skill_reviewed
        else "missing"
    )
    zero_skill_errors: list[str] = list(required_group_errors)
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
        "phase_budget": phase_budget,
        "total_capability_limit": None,
        "zero_skill": zero_skill,
        "zero_skill_reviewed": zero_skill_reviewed,
        "zero_skill_review_status": zero_skill_review_status,
        "review_required": zero_skill,
        "valid": zero_skill_valid,
        "errors": zero_skill_errors,
    }
