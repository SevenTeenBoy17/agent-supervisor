from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from .contracts import normalize_intents

_DOMAIN_TERMS: dict[str, tuple[str, ...]] = {
    "goal-alignment": ("目标", "对齐", "goal", "intent", "需求"),
    "quality-gate": ("质量", "把关", "监工", "review", "审查", "验证", "证据"),
    "capability-reuse": ("skill", "能力", "复用", "调用", "路由", "agent"),
    "deep-audit": ("深度", "全面", "复审", "扫描", "审计", "audit"),
    "defect-discovery": ("缺陷", "不足", "问题", "重大", "风险", "bug"),
    "repair-design": ("修复", "升级", "优化", "设计", "implement", "解决"),
}

_DOMAIN_PREFERENCES: dict[str, tuple[str, ...]] = {
    "goal-alignment": ("supervisor", "dev-supervisor", "ce-plan"),
    "quality-gate": ("supervisor", "dev-supervisor", "code-review-graph-helper", "ce-code-review"),
    "capability-reuse": ("supervisor", "dev-supervisor", "ce-agent-native-architecture"),
    "deep-audit": ("code-review-graph-helper", "ce-doc-review", "deep-research"),
    "defect-discovery": ("code-review-graph-helper", "ce-code-review", "ce-debug"),
    "repair-design": ("superpowers:executing-plans", "ce-work", "supervisor", "dev-supervisor"),
}


def split_intents(message: str) -> list[dict[str, Any]]:
    clauses = [part.strip() for part in re.split(r"[。！？!?；;\n]+", message) if part.strip()]
    if not clauses and message.strip():
        clauses = [message.strip()]
    intents: list[dict[str, Any]] = []
    seen: set[str] = set()
    for clause in clauses:
        matches = []
        lowered = clause.casefold()
        for domain, terms in _DOMAIN_TERMS.items():
            if any(term.casefold() in lowered for term in terms):
                matches.append(domain)
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


def route_intents(
    *,
    message: str,
    inventory: dict[str, Any],
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
    capabilities = [
        row
        for row in inventory.get("skills", inventory.get("capabilities", []))
        if isinstance(row, dict)
        and row.get("active", True)
        and row.get("automatic", True)
        and row.get("availability", "enabled") == "enabled"
        and row.get("health", "healthy") == "healthy"
    ]
    selected: list[str] = []
    coverage: list[dict[str, Any]] = []
    for index, intent in enumerate(atomic, start=1):
        text = str(intent.get("text", ""))
        domain = str(intent.get("domain", "general"))
        wanted = _terms(text) | set(_DOMAIN_TERMS.get(domain, ()))
        ranked = []
        for capability in capabilities:
            capability_id = str(capability.get("id") or capability.get("name"))
            haystack = " ".join(str(capability.get(key, "")) for key in ("id", "name", "description", "owns"))
            score = len(wanted & _terms(haystack))
            if domain != "general" and domain in haystack.casefold():
                score += 3
            preferences = _DOMAIN_PREFERENCES.get(domain, ())
            if capability_id in preferences:
                score += 100 - preferences.index(capability_id)
            if score:
                ranked.append((score, capability_id, capability))
        ranked.sort(key=lambda row: (-row[0], row[1].casefold()))
        chosen = ranked[0][1] if ranked else ""
        if chosen:
            if chosen not in selected:
                selected.append(chosen)
            coverage.append(
                {
                    "contract": "IntentCoverage/v3",
                    "intent_id": str(intent.get("intent_id") or f"intent-{index}"),
                    "text": text,
                    "domain": domain,
                    "status": "deferred",
                    "reason": f"scheduled for capability {chosen}",
                    "capability_ids": [chosen],
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
                    "reason": "no enabled, automatic, healthy capability matched this atomic intent",
                    "capability_ids": [],
                }
            )
    phases: list[dict[str, Any]] = []
    capability_phase: dict[str, int] = {}
    for offset in range(0, len(selected), phase_budget):
        ids = selected[offset : offset + phase_budget]
        phase_id = len(phases) + 1
        phases.append({"phase": phase_id, "capability_ids": ids})
        for capability_id in ids:
            capability_phase[capability_id] = phase_id
    for item in coverage:
        if item["capability_ids"]:
            item["phase"] = capability_phase[item["capability_ids"][0]]
    zero_skill = not selected
    zero_skill_valid = not zero_skill or (
        zero_skill_reviewed
        and bool(coverage)
        and all(item["status"] == "skipped" and bool(item["reason"].strip()) for item in coverage)
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
        "valid": zero_skill_valid,
        "errors": [] if zero_skill_valid else ["zero-skill routing requires concrete skipped reasons and an approving review"],
    }
