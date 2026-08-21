from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Any

from .attestation import sign_record
from .constants import CHANGE_MODES, EXECUTION_MODES, INTENT_STATES, REVIEW_VERDICTS
from .util import canonical_sha256, sha256_text, stable_id, utc_now


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _string_list(value: Any) -> list[str]:
    return [item.strip() for item in _list(value) if isinstance(item, str) and item.strip()]


def _unique(items: list[Any]) -> list[Any]:
    result: list[Any] = []
    seen: set[str] = set()
    for item in items:
        marker = repr(item)
        if marker not in seen:
            seen.add(marker)
            result.append(copy.deepcopy(item))
    return result


def build_goal(
    message: str,
    *,
    change_mode: str,
    previous_goal: dict[str, Any] | None = None,
    supplied: dict[str, Any] | None = None,
    default_evidence: list[str] | None = None,
    default_evidence_by_domain: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    if change_mode not in CHANGE_MODES:
        raise ValueError(f"invalid change mode: {change_mode}")
    supplied = copy.deepcopy(supplied or {})
    previous_goal = previous_goal or {}
    same_identity = change_mode in {"continue", "extend"} and previous_goal.get("goal_id")
    goal_id = str(previous_goal["goal_id"]) if same_identity else str(supplied.get("goal_id") or stable_id("goal"))
    version = int(previous_goal.get("version", 0)) + 1 if same_identity else int(supplied.get("version", 1))
    previous_criteria = _list(previous_goal.get("acceptance_criteria"))
    supplied_criteria = _list(supplied.get("acceptance_criteria"))
    if change_mode == "continue" and previous_goal:
        objective = str(supplied.get("objective") or previous_goal.get("objective") or message).strip()
        raw_criteria = supplied_criteria if "acceptance_criteria" in supplied else previous_criteria
    elif change_mode == "extend" and previous_goal:
        extension = str(supplied.get("objective") or message).strip()
        previous_objective = str(previous_goal.get("objective") or "").strip()
        objective = extension if supplied.get("objective") else " — ".join(item for item in (previous_objective, extension) if item)
        raw_criteria = _unique(previous_criteria + (supplied_criteria or [{"description": extension, "domain": "config-agent", "expected_evidence": default_evidence or ["goal-output"]}]))
    else:
        objective = str(supplied.get("objective") or message).strip()
        raw_criteria = supplied_criteria
    if not raw_criteria:
        raw_criteria = [{"description": objective, "domain": "config-agent", "expected_evidence": default_evidence or ["goal-output"]}]
    criteria: list[dict[str, Any]] = []
    domain_defaults = default_evidence_by_domain or {}
    for index, raw in enumerate(raw_criteria, start=1):
        if isinstance(raw, str):
            raw = {"description": raw}
        if not isinstance(raw, dict):
            continue
        description = str(raw.get("description", "")).strip()
        domain = str(raw.get("domain") or "config-agent")
        evidence_defaults = domain_defaults.get(domain) or domain_defaults.get(domain.replace("-", "/")) or default_evidence or ["goal-output"]
        criteria.append(
            {
                "criterion_id": str(raw.get("criterion_id") or f"criterion-{index}"),
                "description": description,
                "domain": domain,
                "expected_evidence": _string_list(raw.get("expected_evidence")) or evidence_defaults,
                "required": bool(raw.get("required", True)),
            }
        )
    supplied_scope = supplied.get("scope") if isinstance(supplied.get("scope"), dict) else {}
    previous_scope = previous_goal.get("scope") if isinstance(previous_goal.get("scope"), dict) else {}

    def merged_list(name: str, supplied_value: Any) -> list[str]:
        previous_values = _string_list(previous_goal.get(name))
        current_values = _string_list(supplied_value)
        if change_mode == "continue" and previous_goal and not current_values:
            return previous_values
        if change_mode == "extend" and previous_goal:
            return _unique(previous_values + current_values)
        return current_values

    scope_in = _string_list(supplied_scope.get("in") if supplied_scope else supplied.get("scope_in"))
    scope_out = _string_list(supplied_scope.get("out") if supplied_scope else supplied.get("scope_out"))
    if change_mode == "continue" and previous_goal:
        scope_in = scope_in or _string_list(previous_scope.get("in"))
        scope_out = scope_out or _string_list(previous_scope.get("out"))
    elif change_mode == "extend" and previous_goal:
        scope_in = _unique(_string_list(previous_scope.get("in")) + scope_in)
        scope_out = _unique(_string_list(previous_scope.get("out")) + scope_out)

    request_hash = sha256_text(message)
    waiver_authorizations = _list(previous_goal.get("waiver_authorizations")) if change_mode in {"continue", "extend"} else []
    for match in re.finditer(r"(?i)(?:SUPERVISOR-WAIVE\s*[:：]\s*|豁免\s+)([A-Za-z0-9_.:-]+)", message):
        waiver_authorizations.append({"criterion_id": match.group(1), "request_sha256": request_hash})

    return {
        "contract": "GoalContract/v3",
        "goal_id": goal_id,
        "version": version,
        "original_request_sha256": request_hash,
        "change_mode": change_mode,
        "objective": objective,
        "acceptance_criteria": criteria,
        "scope": {"in": scope_in, "out": scope_out},
        "constraints": merged_list("constraints", supplied.get("constraints")),
        "non_goals": merged_list("non_goals", supplied.get("non_goals")),
        "assumptions": merged_list("assumptions", supplied.get("assumptions")),
        "risks": merged_list("risks", supplied.get("risks")),
        "waiver_authorizations": _unique(waiver_authorizations),
        "created_at": utc_now(),
    }


def normalize_intents(raw: Any, message: str = "") -> list[dict[str, Any]]:
    if raw is None:
        raw = [{"text": message}] if message.strip() else []
    intents: list[dict[str, Any]] = []
    for index, item in enumerate(_list(raw), start=1):
        if isinstance(item, str):
            item = {"text": item}
        if not isinstance(item, dict):
            continue
        text = str(item.get("text", "")).strip()
        status = str(item.get("status") or "deferred")
        intents.append(
            {
                "contract": "IntentCoverage/v3",
                "intent_id": str(item.get("intent_id") or f"intent-{index}"),
                "text": text,
                "status": status if status in INTENT_STATES else "failed",
                "reason": str(item.get("reason") or "awaiting routing").strip(),
                "capability_ids": _string_list(item.get("capability_ids")),
                "method": str(item.get("method") or "capability"),
                "phase": int(item.get("phase", 0) or 0),
                "domain": str(item.get("domain") or "general"),
            }
        )
    return intents


def new_state(
    goal: dict[str, Any],
    intents: list[dict[str, Any]],
    *,
    runtime: str,
    project: str,
    workspace: str,
    session: str,
    round_id: str,
    execution_mode: str,
    quality_profile: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if execution_mode not in EXECUTION_MODES:
        raise ValueError(f"invalid execution mode: {execution_mode}")
    intent_manifest = [
        {
            "intent_id": str(intent.get("intent_id") or ""),
            "text_sha256": sha256_text(str(intent.get("text") or "")),
            "domain": str(intent.get("domain") or "general"),
        }
        for intent in intents
    ]
    request_manifest = {
        "contract": "RequestManifest/v3",
        "goal_id": goal.get("goal_id"),
        "goal_version": goal.get("version"),
        "goal_sha256": canonical_sha256(goal),
        "original_request_sha256": goal.get("original_request_sha256"),
        "intents": intent_manifest,
        "runtime": runtime,
        "workspace": str(Path(workspace).resolve()),
        "session": session,
        "round": round_id,
    }
    request_manifest["attestation"] = sign_record(request_manifest)
    return {
        "schema_version": 3,
        "runtime": runtime,
        "project": project,
        "workspace": str(Path(workspace).resolve()),
        "session": session,
        "round": round_id,
        "execution_mode": execution_mode,
        "goal": goal,
        "intents": intents,
        "intent_manifest": intent_manifest,
        "request_manifest": request_manifest,
        "tasks": [],
        "evidence": [],
        "reviews": [],
        "claims": [],
        "waivers": [],
        "changes": {"files": [], "base": "", "head": "", "diff_hash": "", "domains": [], "test_changes": {}},
        "spec": {"status": "unresolved", "hash": "", "path": ""},
        "capability_breakers": {},
        "health": "healthy",
        "terminal_state": None,
        "stop_attempts": 0,
        "started_at": utc_now(),
        "updated_at": utc_now(),
    }


def invocation_event(
    *, invocation_id: str, capability: str, stage: str, result: str | None, actor: str, details: dict[str, Any] | None = None
) -> dict[str, Any]:
    if stage not in {"attempt", "result"}:
        raise ValueError("invocation stage must be attempt or result")
    return {
        "contract": "InvocationEvent/v3",
        "event_type": f"invocation_{stage}",
        "invocation_id": invocation_id,
        "capability": capability,
        "stage": stage,
        "result": result if stage == "result" else None,
        "actor": actor,
        "details": details or {},
        "timestamp": utc_now(),
    }


def validate_review_shape(review: Any) -> bool:
    return (
        isinstance(review, dict)
        and review.get("contract") == "ReviewRecord/v3"
        and bool(str(review.get("review_id", "")).strip())
        and bool(str(review.get("goal_id", "")).strip())
        and isinstance(review.get("goal_version"), int)
        and bool(str(review.get("reviewer", "")).strip())
        and bool(str(review.get("responsibility_group", "")).strip())
        and bool(str(review.get("implementer", "")).strip())
        and bool(re.fullmatch(r"[0-9a-f]{64}", str(review.get("base", ""))))
        and bool(re.fullmatch(r"[0-9a-f]{64}", str(review.get("head", ""))))
        and bool(re.fullmatch(r"[0-9a-f]{64}", str(review.get("diff_hash", ""))))
        and review.get("verdict") in REVIEW_VERDICTS
        and isinstance(review.get("rerun_evidence_ids"), list)
        and bool(review.get("rerun_evidence_ids"))
    )
