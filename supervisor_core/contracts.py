from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

from .attestation import sign_record, verify_record
from .constants import CHANGE_MODES, EXECUTION_MODES, INTENT_STATES, REVIEW_VERDICTS, TERMINAL_STATES
from .util import canonical_sha256, parse_time, redact, sha256_text, stable_id, utc_now


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_GIT_OID_LENGTHS = {"sha1": 40, "sha256": 64}
_INTENT_DEDUPE_PUNCT = re.compile(
    r"[\s\-—–_.,;:：、。！？!?；;，,()（）\[\]【】\"'“”]+"
)
_INTENT_KINDS = {"functional", "scope-constraint"}
_TECHNICAL_CRITERION_DOMAINS = {
    "ui": ("ui", "frontend", "interface", "page", "前端", "界面", "页面"),
    "api": ("api", "endpoint", "backend", "接口", "后端"),
    "db": ("db", "database", "schema", "数据库", "数据层"),
}


def _derived_criterion_domains(text: str, fallback: str) -> list[str]:
    """Expand UI/API/DB mentions into distinct criteria without cloning intents."""
    lowered = str(text or "").casefold()
    found: list[str] = []
    for domain, terms in _TECHNICAL_CRITERION_DOMAINS.items():
        if any(term.casefold() in lowered for term in terms):
            found.append(domain)
    fallback_domain = str(fallback or "general").strip() or "general"
    return found or [fallback_domain]


def _list(value: Any) -> list[Any]:
    # Contract builders may append or normalize rows. Never hand them a caller's
    # authoritative list by reference (especially a prior signed goal record).
    return copy.deepcopy(value) if isinstance(value, list) else []


def _string_list(value: Any) -> list[str]:
    return [item.strip() for item in _list(value) if isinstance(item, str) and item.strip()]


def _int_or_zero(value: Any) -> int:
    """Normalize an untrusted optional integer without aborting contract creation."""
    try:
        return int(value or 0)
    except (TypeError, ValueError, OverflowError):
        return 0


def _unique(items: list[Any]) -> list[Any]:
    result: list[Any] = []
    seen: set[str] = set()
    for item in items:
        marker = repr(item)
        if marker not in seen:
            seen.add(marker)
            result.append(copy.deepcopy(item))
    return result


def _t3_authorizations(value: Any) -> list[dict[str, str]]:
    """Keep only structured, exact-action approvals from trusted prior goals."""
    result: list[dict[str, str]] = []
    for item in _list(value):
        if not isinstance(item, dict):
            continue
        action_sha256 = str(item.get("action_sha256") or "").strip().casefold()
        request_sha256 = str(item.get("request_sha256") or "").strip().casefold()
        if _SHA256_RE.fullmatch(action_sha256) and _SHA256_RE.fullmatch(request_sha256):
            result.append({
                "action_sha256": action_sha256,
                "request_sha256": request_sha256,
            })
    return _unique(result)


def _waiver_authorizations(value: Any) -> list[dict[str, str]]:
    """Keep only structured, hash-bound waivers from trusted prior goals."""
    result: list[dict[str, str]] = []
    for item in _list(value):
        if not isinstance(item, dict):
            continue
        criterion_id = str(item.get("criterion_id") or "").strip()
        request_sha256 = str(item.get("request_sha256") or "").strip().casefold()
        if criterion_id and "\x00" not in criterion_id and _SHA256_RE.fullmatch(request_sha256):
            result.append({
                "criterion_id": criterion_id,
                "request_sha256": request_sha256,
            })
    return _unique(result)


def _trusted_authorization_records(
    value: Any, *, request_sha256: str
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Translate a separately authenticated request binding into goal records.

    Request prose and caller-supplied GoalContract fields are deliberately not
    inputs to this function. The embedding host is responsible for authenticating
    this metadata before passing it to ``build_goal``.
    """
    if value is None:
        return [], []
    if not isinstance(value, dict):
        raise ValueError("trusted authorizations must be an object")
    bound_request = str(value.get("request_sha256") or "").strip().casefold()
    if not _SHA256_RE.fullmatch(bound_request) or bound_request != request_sha256:
        raise ValueError("trusted authorizations request hash mismatch")

    raw_waivers = value.get("waiver_criterion_ids", [])
    raw_actions = value.get("t3_action_sha256s", [])
    if not isinstance(raw_waivers, list) or not isinstance(raw_actions, list):
        raise ValueError("trusted authorization identifiers must be lists")

    waivers: list[dict[str, str]] = []
    for raw in raw_waivers:
        criterion_id = raw.strip() if isinstance(raw, str) else ""
        if not criterion_id or "\x00" in criterion_id:
            raise ValueError("trusted waiver criterion id is invalid")
        waivers.append({
            "criterion_id": criterion_id,
            "request_sha256": request_sha256,
        })

    actions: list[dict[str, str]] = []
    for raw in raw_actions:
        action_sha256 = raw.strip().casefold() if isinstance(raw, str) else ""
        if not _SHA256_RE.fullmatch(action_sha256):
            raise ValueError("trusted T3 action hash is invalid")
        actions.append({
            "action_sha256": action_sha256,
            "request_sha256": request_sha256,
        })
    return _unique(waivers), _unique(actions)


def _merge_contract_rows(previous: list[Any], current: list[Any]) -> list[Any]:
    """Append genuinely new contract rows without replacing prior identities."""
    result = copy.deepcopy(previous)
    seen: set[str] = set()

    def markers(item: Any) -> set[str]:
        if isinstance(item, dict):
            values: set[str] = set()
            identity = str(item.get("criterion_id") or item.get("intent_id") or "").strip()
            if identity:
                values.add(f"id:{identity}")
            description = str(item.get("description") or item.get("text") or "").strip()
            if description:
                domain = str(item.get("domain") or "general").strip() or "general"
                values.add(f"semantic:{domain}\0{description}")
            return values
        value = str(item).strip()
        return {f"semantic:general\0{value}"} if value else set()

    for item in result:
        seen.update(markers(item))
    for item in current:
        item_markers = markers(item)
        if item_markers & seen:
            continue
        result.append(copy.deepcopy(item))
        seen.update(item_markers)
    return result


def build_goal(
    message: str,
    *,
    change_mode: str,
    previous_goal: dict[str, Any] | None = None,
    supplied: dict[str, Any] | None = None,
    default_evidence: list[str] | None = None,
    default_evidence_by_domain: dict[str, list[str]] | None = None,
    default_intents: list[dict[str, Any]] | None = None,
    trusted_authorizations: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if change_mode not in CHANGE_MODES:
        raise ValueError(f"invalid change mode: {change_mode}")
    supplied = copy.deepcopy(supplied or {})
    supplied_criteria_present = "acceptance_criteria" in supplied
    raw_supplied_criteria = supplied.get("acceptance_criteria")
    if supplied_criteria_present and not isinstance(raw_supplied_criteria, list):
        raise ValueError("supplied acceptance criteria must be a list")
    previous_goal = previous_goal or {}
    same_identity = change_mode in {"continue", "extend"} and previous_goal.get("goal_id")
    if same_identity:
        goal_id = str(previous_goal["goal_id"])
    elif previous_goal and change_mode == "replace":
        # A replacement is a new goal even when a caller tries to recycle the
        # previous id. The superseded round remains independently addressable.
        goal_id = stable_id("goal")
    else:
        goal_id = str(supplied.get("goal_id") or stable_id("goal"))
    version = int(previous_goal.get("version", 0)) + 1 if same_identity else int(supplied.get("version", 1))
    previous_criteria = _list(previous_goal.get("acceptance_criteria"))
    supplied_criteria = _list(raw_supplied_criteria)
    if (
        supplied_criteria_present
        and supplied_criteria
        and not any(isinstance(raw, (str, dict)) for raw in supplied_criteria)
    ):
        raise ValueError(
            "supplied acceptance criteria contain no valid string or object entries"
        )
    for index, raw in enumerate(supplied_criteria):
        if isinstance(raw, str):
            raw = {"description": raw}
            supplied_criteria[index] = raw
        if isinstance(raw, dict) and not str(raw.get("criterion_id") or "").strip():
            description = str(raw.get("description") or "").strip()
            domain = str(raw.get("domain") or "general").strip() or "general"
            raw["criterion_id"] = stable_id("criterion", f"{domain}\0{description}")
    derived_criteria: list[dict[str, Any]] = []
    seen_defaults: set[tuple[str, str]] = set()
    for raw_intent in _list(default_intents):
        if not isinstance(raw_intent, dict):
            continue
        description = str(raw_intent.get("text") or "").strip()
        fallback_domain = str(raw_intent.get("domain") or "general").strip() or "general"
        if not description:
            continue
        for domain in _derived_criterion_domains(description, fallback_domain):
            marker = (domain, description)
            if marker in seen_defaults:
                continue
            seen_defaults.add(marker)
            derived_criteria.append(
                {
                    "criterion_id": stable_id("criterion", f"{domain}\0{description}"),
                    "description": description,
                    "domain": domain,
                }
            )
    if change_mode == "continue" and previous_goal:
        objective = str(previous_goal.get("objective") or supplied.get("objective") or message).strip()
        raw_criteria = _merge_contract_rows(previous_criteria, supplied_criteria)
    elif change_mode == "extend" and previous_goal:
        extension = str(supplied.get("objective") or message).strip()
        previous_objective = str(previous_goal.get("objective") or "").strip()
        objective = extension if supplied.get("objective") else " — ".join(item for item in (previous_objective, extension) if item)
        raw_criteria = _merge_contract_rows(
            previous_criteria,
            supplied_criteria
            or derived_criteria
            or [{
                "criterion_id": stable_id("criterion", f"general\0{extension}"),
                "description": extension,
                "domain": "general",
                "expected_evidence": default_evidence or ["goal-output"],
            }],
        )
    else:
        objective = str(supplied.get("objective") or message).strip()
        raw_criteria = supplied_criteria
    if not raw_criteria:
        raw_criteria = derived_criteria or [
            {
                "criterion_id": stable_id("criterion", f"general\0{objective}"),
                "description": objective,
                "domain": "general",
                "expected_evidence": default_evidence or ["goal-output"],
            }
        ]
    criteria: list[dict[str, Any]] = []
    domain_defaults = default_evidence_by_domain or {}
    for index, raw in enumerate(raw_criteria, start=1):
        if isinstance(raw, str):
            raw = {"description": raw}
        if not isinstance(raw, dict):
            continue
        description = str(raw.get("description", "")).strip()
        if not description:
            raise ValueError(
                f"acceptance criterion {index} description must not be empty"
            )
        domain = str(raw.get("domain") or "general").strip() or "general"
        evidence_candidates = [domain, domain.replace("-", "/")]
        if domain in {"api", "db", "database", "backend"}:
            evidence_candidates.append("api/db")
        if domain in {"config", "agent", "config-agent"}:
            evidence_candidates.append("config/agent")
        evidence_defaults: list[str] = []
        for candidate in evidence_candidates:
            if domain_defaults.get(candidate):
                evidence_defaults = _string_list(domain_defaults[candidate])
                break
        evidence_defaults = evidence_defaults or _string_list(default_evidence) or ["goal-output"]
        criteria.append(
            {
                "criterion_id": str(raw.get("criterion_id") or stable_id("criterion", f"{domain}\0{description}")),
                "description": description,
                "domain": domain,
                "expected_evidence": _string_list(raw.get("expected_evidence")) or list(evidence_defaults),
                "required": bool(raw.get("required", True)),
            }
        )
    supplied_scope = supplied.get("scope") if isinstance(supplied.get("scope"), dict) else {}
    previous_scope = previous_goal.get("scope") if isinstance(previous_goal.get("scope"), dict) else {}

    def merged_list(name: str, supplied_value: Any) -> list[str]:
        previous_values = _string_list(previous_goal.get(name))
        current_values = _string_list(supplied_value)
        if change_mode in {"continue", "extend"} and previous_goal:
            return _unique(previous_values + current_values)
        return current_values

    scope_in = _string_list(supplied_scope.get("in") if supplied_scope else supplied.get("scope_in"))
    scope_out = _string_list(supplied_scope.get("out") if supplied_scope else supplied.get("scope_out"))
    scope_out = _unique(scope_out + _string_list(supplied.get("out_of_scope")))
    if change_mode == "continue" and previous_goal:
        scope_in = scope_in or _string_list(previous_scope.get("in"))
        scope_out = scope_out or _string_list(previous_scope.get("out"))
    elif change_mode == "extend" and previous_goal:
        scope_in = _unique(_string_list(previous_scope.get("in")) + scope_in)
        scope_out = _unique(_string_list(previous_scope.get("out")) + scope_out)

    request_hash = sha256_text(message)
    waiver_authorizations = (
        _waiver_authorizations(previous_goal.get("waiver_authorizations"))
        if change_mode in {"continue", "extend"}
        else []
    )
    t3_action_authorizations = (
        _t3_authorizations(previous_goal.get("t3_action_authorizations"))
        if change_mode in {"continue", "extend"}
        else []
    )
    trusted_waivers, trusted_t3_actions = _trusted_authorization_records(
        trusted_authorizations,
        request_sha256=request_hash,
    )
    waiver_authorizations.extend(trusted_waivers)
    t3_action_authorizations.extend(trusted_t3_actions)

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
        "t3_action_authorizations": _unique(t3_action_authorizations),
        "created_at": utc_now(),
    }


def intent_dedupe_key(text: str) -> str:
    """Fingerprint intent prose without domain, so copies across domains collapse."""
    return _INTENT_DEDUPE_PUNCT.sub("", str(text or "").strip().casefold())


def _attempted_capability_rows(value: Any) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for item in _list(value):
        if isinstance(item, str):
            item = {"capability_id": item}
        if not isinstance(item, dict):
            continue
        capability_id = str(item.get("capability_id") or item.get("id") or "").strip()
        if not capability_id:
            continue
        result = str(item.get("result") or "").strip()
        by_id[capability_id] = {
            "capability_id": capability_id,
            "result": result,
            "evidence_ids": _string_list(item.get("evidence_ids")),
        }
    return list(by_id.values())


def _merge_intent_row(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(existing)
    if merged.get("kind") != "functional" and incoming.get("kind") == "functional":
        merged["kind"] = "functional"
        merged["domain"] = incoming.get("domain") or merged.get("domain")
    merged["capability_ids"] = _unique(
        _string_list(merged.get("capability_ids")) + _string_list(incoming.get("capability_ids"))
    )
    merged["acceptance_criteria"] = _unique(
        _string_list(merged.get("acceptance_criteria"))
        + _string_list(incoming.get("acceptance_criteria"))
    )
    merged["evidence_ids"] = _unique(
        _string_list(merged.get("evidence_ids")) + _string_list(incoming.get("evidence_ids"))
    )
    merged["attempted_capabilities"] = _attempted_capability_rows(
        list(merged.get("attempted_capabilities") or [])
        + list(incoming.get("attempted_capabilities") or [])
    )
    merged["depends_on_intent_ids"] = _unique(
        _string_list(merged.get("depends_on_intent_ids"))
        + _string_list(incoming.get("depends_on_intent_ids"))
    )
    return merged


def normalize_intents(raw: Any, message: str = "") -> list[dict[str, Any]]:
    if raw is None:
        raw = [{"text": message}] if message.strip() else []
    intents: list[dict[str, Any]] = []
    by_key: dict[str, int] = {}
    for index, item in enumerate(_list(raw), start=1):
        if isinstance(item, str):
            item = {"text": item}
        if not isinstance(item, dict):
            continue
        text = str(item.get("text", "")).strip()
        status = str(item.get("status") or "deferred")
        kind = str(item.get("kind") or "").strip()
        if kind not in _INTENT_KINDS:
            kind = (
                "scope-constraint"
                if str(item.get("domain") or "") == "scope-constraint"
                else "functional"
            )
        dedupe_key = str(item.get("dedupe_key") or "").strip() or intent_dedupe_key(text)
        row = {
            "contract": "IntentCoverage/v3",
            "intent_id": str(item.get("intent_id") or f"intent-{index}"),
            "text": text,
            "status": status if status in INTENT_STATES else "failed",
            "reason": str(item.get("reason") or "awaiting routing").strip(),
            "capability_ids": _string_list(item.get("capability_ids")),
            "method": str(item.get("method") or "capability"),
            "phase": _int_or_zero(item.get("phase")),
            "domain": str(item.get("domain") or "general"),
            "role": str(item.get("role") or ""),
            "required_responsibility_groups": _string_list(item.get("required_responsibility_groups")),
            "depends_on_intent_ids": _string_list(item.get("depends_on_intent_ids")),
            "kind": kind,
            "dedupe_key": dedupe_key,
            "acceptance_criteria": _string_list(item.get("acceptance_criteria")),
            "evidence_ids": _string_list(item.get("evidence_ids")),
            "attempted_capabilities": _attempted_capability_rows(
                item.get("attempted_capabilities")
            ),
        }
        merge_key = dedupe_key or f"unique:{index}:{row['intent_id']}"
        existing_index = by_key.get(merge_key)
        if existing_index is not None and dedupe_key:
            intents[existing_index] = _merge_intent_row(intents[existing_index], row)
            continue
        by_key[merge_key] = len(intents)
        intents.append(row)
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
        "attestation_authority": {
            "contract": "AttestationAuthority/v3",
            "scheme": "local-process-hmac-sha256",
            "assurance": "local-integrity-only",
            "same_user_adversary_resistant": False,
            "limitation": "detects accidental/out-of-band mutation but is not a host security boundary",
        },
        "tasks": [],
        "evidence": [],
        "reviews": [],
        "claims": [],
        "waivers": [],
        "changes": {
            "files": [],
            "base": None,
            "head": None,
            "git_object_format": None,
            "git_binding_status": "unavailable",
            "git_binding_source": None,
            "git_repository_root": None,
            "review_artifact": None,
            "review_artifact_sha256": None,
            "git_diff_sha256": None,
            "workspace_base_sha256": "",
            "workspace_head_sha256": "",
            "diff_hash": "",
            "domains": [],
            "test_changes": {},
        },
        "spec": {"status": "unresolved", "hash": "", "path": ""},
        "capability_breakers": {},
        "health": "healthy",
        "terminal_state": None,
        "stop_attempts": 0,
        "started_at": utc_now(),
        "updated_at": utc_now(),
    }


def invocation_event(
    *, invocation_id: str, capability: str, stage: str, result: str | None, actor: str,
    details: dict[str, Any] | None = None, identity_assurance: str = "declared-runtime",
    responsibility_group: str | None = None,
) -> dict[str, Any]:
    if stage not in {"attempt", "result"}:
        raise ValueError("invocation stage must be attempt or result")
    event = {
        "contract": "InvocationEvent/v3",
        "event_type": f"invocation_{stage}",
        "invocation_id": invocation_id,
        "capability": capability,
        "stage": stage,
        "result": result if stage == "result" else None,
        "actor": actor,
        "responsibility_group": responsibility_group,
        "identity_assurance": identity_assurance,
        "details": details or {},
        "timestamp": utc_now(),
    }
    if identity_assurance in {"codex-explicit-audit", "codex-hook-observation"}:
        event["identity_provenance"] = "caller-declared-local-observation"
        event["completion_eligible"] = False
    elif identity_assurance == "core-executed-gate":
        event["identity_provenance"] = "core-minted-single-use-gate-execution"
        event["completion_eligible"] = True
    if identity_assurance in {
        "host-hook-observed",
        "codex-explicit-audit",
        "codex-hook-observation",
        "core-executed-gate",
        "core-trusted-finalize",
    }:
        event["attestation_scope"] = "local-integrity-only"
        event["attestation"] = sign_record(event)
    return event


def validate_review_shape(review: Any) -> bool:
    if not isinstance(review, dict):
        return False
    object_format = str(review.get("git_object_format") or "")
    oid_length = _GIT_OID_LENGTHS.get(object_format)
    git_binding_status = review.get("git_binding_status")
    if git_binding_status == "verified":
        binding_source = review.get("git_binding_source")
        git_binding_valid = bool(
            oid_length
            and binding_source in {"workspace", "review-artifact"}
            and re.fullmatch(rf"[0-9a-f]{{{oid_length}}}", str(review.get("base", "")))
            and re.fullmatch(rf"[0-9a-f]{{{oid_length}}}", str(review.get("head", "")))
            and (
                (
                    binding_source == "workspace"
                    and bool(str(review.get("git_repository_root") or "").strip())
                    and review.get("review_artifact_sha256") in {None, ""}
                )
                or (
                    binding_source == "review-artifact"
                    and review.get("git_repository_root") in {None, ""}
                    and bool(_SHA256_RE.fullmatch(str(review.get("review_artifact_sha256") or "")))
                    and bool(_SHA256_RE.fullmatch(str(review.get("git_diff_sha256") or "")))
                )
            )
        )
    else:
        git_binding_valid = bool(
            git_binding_status in {"unavailable", "degraded"}
            and review.get("base") in {None, ""}
            and review.get("head") in {None, ""}
        )
    verification = review.get("evidence_verification")
    return (
        review.get("contract") == "ReviewRecord/v3"
        and bool(str(review.get("review_id", "")).strip())
        and bool(str(review.get("goal_id", "")).strip())
        and type(review.get("goal_version")) is int
        and bool(str(review.get("reviewer", "")).strip())
        and bool(str(review.get("reviewer_responsibility_group", "")).strip())
        and bool(str(review.get("implementer", "")).strip())
        and bool(str(review.get("implementer_responsibility_group", "")).strip())
        and bool(str(review.get("gate_collector", "")).strip())
        and bool(str(review.get("gate_collector_responsibility_group", "")).strip())
        and bool(str(review.get("gate_runner_invocation_id", "")).strip())
        and git_binding_valid
        and bool(re.fullmatch(r"[0-9a-f]{64}", str(review.get("workspace_base_sha256", ""))))
        and bool(re.fullmatch(r"[0-9a-f]{64}", str(review.get("workspace_head_sha256", ""))))
        and bool(re.fullmatch(r"[0-9a-f]{64}", str(review.get("diff_hash", ""))))
        and review.get("verdict") in REVIEW_VERDICTS
        and isinstance(review.get("rerun_evidence_ids"), list)
        and bool(review.get("rerun_evidence_ids"))
        and all(isinstance(item, str) and bool(item.strip()) for item in review.get("rerun_evidence_ids"))
        and len(set(review.get("rerun_evidence_ids"))) == len(review.get("rerun_evidence_ids"))
        and isinstance(verification, dict)
        and verification.get("status") == "VERIFIED"
        and bool(str(verification.get("reviewer", "")).strip())
        and isinstance(verification.get("evidence_ids"), list)
    )


ROUND_PROCESS_SUMMARY_CONTRACT = "RoundProcessSummary/v1"
_TIMELINE_KINDS = {
    "skill", "agent", "plugin_app", "native_command", "quality_gate", "review",
}
_TIMELINE_STATUSES = {
    "success", "failed", "refused", "cancelled", "fallback",
    "methodology-only", "not-invoked",
}
_CONTRIBUTION_MAX = 96
_USER_VIEW_DETAIL_LIMIT = 8
_NATIVE_VIEW_FOLD_AFTER = 3
_UNSAFE_SUMMARY_KEYS = {
    "prompt", "raw_prompt", "original_request", "message", "stdin",
    "stdout", "stderr", "raw", "raw_output", "raw_stdout", "raw_stderr",
    "argv", "args", "command", "stack", "traceback", "exception",
    "cookie", "set_cookie", "cookie_header", "token", "access_token",
    "authorization", "password", "secret", "output", "database_url",
    "db_url", "connection_string", "pii",
}
_NATIVE_COMMAND_IDS = {
    "bash", "shell", "sh", "zsh", "pwsh", "powershell", "cmd", "git",
    "pytest", "python", "python3", "node", "npm",
    "exec_command", "execcommand", "apply_patch", "applypatch", "applypatchv2",
    "write", "edit", "writefile", "multiedit", "createfile", "movefile", "renamefile",
    "notebookedit", "read",
}
_NATIVE_CATEGORIES = {"shell", "git", "native", "command", "exec", "test"}
_KIND_LABELS = {
    "skill": "Skill",
    "agent": "Agent",
    "plugin_app": "Plugin/App",
    "native_command": "Command",
    "quality_gate": "Gate",
    "review": "Review",
}
_STACK_BLOCK_RE = re.compile(
    r"(?ms)Traceback \(most recent call last\):(?:\n[ \t].*)*(?:\n\S.*)?"
)
_STACK_FILE_RE = re.compile(r'(?m)^\s*File "[^"]+", line \d+, in .+(?:\n.*)?')
_JAVA_STACK_RE = re.compile(r"(?m)^\s+at [\w.$]+\([^)\n]*\)$")
_EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
_PHONE_RE = re.compile(r"(?<!\d)(?:\+?86[-\s]?)?1[3-9]\d{9}(?!\d)")
_CN_ID_RE = re.compile(r"\b\d{17}[\dXx]\b")
_STUDENT_NO_RE = re.compile(r"(?i)(?:学号|student(?:[\s_-]*id)?)\s*[:：#]?\s*[A-Za-z0-9_-]+")
_STUDENT_NAME_RE = re.compile(r"学生[:：]?\s*\S{1,4}")
_STDIO_BLOCK_RE = re.compile(r"(?is)\b(?:stdout|stderr|traceback)\b\s*[:=].+")
_PROMPT_BLOCK_RE = re.compile(r"(?is)\b(?:prompt|raw_prompt|original_request)\b\s*[:=].+")


def sanitize_process_summary_text(value: Any, *, limit: int = _CONTRIBUTION_MAX) -> str:
    """One-way user-view sanitizer. Never used as an integrity input."""
    if value is None:
        return ""
    if not isinstance(value, str):
        try:
            value = json.dumps(value, ensure_ascii=False, sort_keys=True)
        except (TypeError, ValueError):
            value = str(value)
    clean = str(redact(value))
    clean = _STACK_BLOCK_RE.sub("[stack-redacted]", clean)
    clean = _STACK_FILE_RE.sub("[stack-redacted]", clean)
    clean = _JAVA_STACK_RE.sub("[stack-redacted]", clean)
    clean = _STDIO_BLOCK_RE.sub("[stdio-redacted]", clean)
    clean = _PROMPT_BLOCK_RE.sub("[prompt-redacted]", clean)
    clean = _EMAIL_RE.sub("[REDACTED]", clean)
    clean = _PHONE_RE.sub("[REDACTED]", clean)
    clean = _CN_ID_RE.sub("[REDACTED]", clean)
    clean = _STUDENT_NO_RE.sub("[REDACTED]", clean)
    clean = _STUDENT_NAME_RE.sub("学生[REDACTED]", clean)
    clean = re.sub(r"\s+", " ", clean).strip()
    if limit and len(clean) > limit:
        clean = clean[: max(0, limit - 1)].rstrip() + "…"
    return clean


def _event_attested(event: Any) -> bool:
    if not isinstance(event, dict):
        return False
    if not isinstance(event.get("attestation"), str) or not event.get("attestation"):
        return False
    return bool(verify_record(event))


def _details(event: dict[str, Any]) -> dict[str, Any]:
    value = event.get("details")
    return value if isinstance(value, dict) else {}


def _capability_indexes(state: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    inventory = state.get("capability_inventory")
    if not isinstance(inventory, dict):
        inventory = {}
    skills: dict[str, dict[str, Any]] = {}
    agents: dict[str, dict[str, Any]] = {}
    for row in _list(inventory.get("skills")):
        if not isinstance(row, dict):
            continue
        key = str(row.get("id") or row.get("name") or "").strip().casefold()
        if key:
            skills[key] = row
    for row in _list(inventory.get("agents")):
        if not isinstance(row, dict):
            continue
        key = str(row.get("id") or row.get("name") or "").strip().casefold()
        if key:
            agents[key] = row
    return skills, agents


def _normalized_capability_marker(capability: str) -> str:
    leaf = str(capability or "").casefold().split("__")[-1]
    unversioned = re.sub(r"(?:[@._-]?v?\d+)+$", "", leaf)
    return re.sub(r"[^a-z]", "", unversioned)


def _classify_timeline_kind(
    capability: str,
    event: dict[str, Any],
    skills: dict[str, dict[str, Any]],
    agents: dict[str, dict[str, Any]],
) -> str:
    details = _details(event)
    explicit = str(
        details.get("kind")
        or details.get("capability_kind")
        or event.get("capability_kind")
        or ""
    ).strip()
    if explicit in _TIMELINE_KINDS:
        return explicit
    cap = str(capability or "").strip()
    cap_key = cap.casefold()
    cap_marker = _normalized_capability_marker(cap)
    event_type = str(event.get("event_type") or "")
    if (
        details.get("gate_id")
        or event.get("gate_id")
        or event_type in {"gate_execution", "gate_run"}
        or cap.startswith("supervisor-core-gate:")
        or cap.startswith("supervisor-core-builtin:")
    ):
        return "quality_gate"
    if event_type in {"review_finalized", "review_record"} or event.get("contract") == "ReviewRecord/v3":
        return "review"
    if cap_key in agents or str(details.get("capability_kind") or "") == "agent":
        return "agent"
    skill = skills.get(cap_key)
    if skill:
        source = str(skill.get("source") or "").casefold()
        skill_kind = str(skill.get("capability_kind") or "").strip()
        if (
            "plugin" in source
            or skill_kind in {"plugin", "plugin_app", "app"}
            or str(skill.get("kind") or "") in {"plugin", "plugin_app", "app"}
        ):
            return "plugin_app"
        return "skill"
    tool_kind = str(details.get("tool_kind") or "").casefold()
    if (
        "plugin" in cap_key
        or cap_key.startswith("mcp")
        or tool_kind in {"mcp", "plugin", "app", "plugin_app"}
    ):
        return "plugin_app"
    category = str(details.get("command_category") or event.get("command_category") or "").casefold()
    if (
        cap_key in _NATIVE_COMMAND_IDS
        or cap_marker in _NATIVE_COMMAND_IDS
        or category in _NATIVE_CATEGORIES
    ):
        return "native_command"
    if "/" in cap or "\\" in cap or cap.endswith(".exe"):
        return "native_command"
    return "skill"


def _trusted_invocation_pairs(events: list[dict[str, Any]]) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    attempts: dict[str, list[dict[str, Any]]] = {}
    results: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        if not isinstance(event, dict) or not _event_attested(event):
            continue
        event_type = event.get("event_type")
        invocation_id = str(event.get("invocation_id") or "").strip()
        if not invocation_id:
            continue
        if event_type == "invocation_attempt" and event.get("stage") == "attempt":
            attempts.setdefault(invocation_id, []).append(event)
        elif event_type == "invocation_result" and event.get("stage") == "result":
            results.setdefault(invocation_id, []).append(event)
    pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for invocation_id, result_rows in results.items():
        attempt_rows = attempts.get(invocation_id) or []
        if len(attempt_rows) != 1 or len(result_rows) != 1:
            continue
        attempt, result = attempt_rows[0], result_rows[0]
        if str(attempt.get("capability") or "") != str(result.get("capability") or ""):
            continue
        if not str(attempt.get("capability") or "").strip():
            continue
        if str(attempt.get("actor") or "") != str(result.get("actor") or ""):
            continue
        if not str(attempt.get("actor") or "").strip():
            continue
        if attempt.get("responsibility_group") != result.get("responsibility_group"):
            continue
        pairs.append((attempt, result))
    return pairs


def _fallback_capability_ids(state: dict[str, Any], events: list[dict[str, Any]]) -> set[str]:
    found: set[str] = set()
    breakers = state.get("capability_breakers")
    if isinstance(breakers, dict):
        for row in breakers.values():
            if not isinstance(row, dict):
                continue
            fallback_id = str(row.get("fallback_id") or "").strip()
            if fallback_id:
                found.add(fallback_id)
    for event in events:
        if not isinstance(event, dict):
            continue
        if event.get("event_type") == "invocation_fallback_required":
            fallback_id = str(event.get("fallback_id") or "").strip()
            if fallback_id:
                found.add(fallback_id)
        details = _details(event) if event.get("event_type") == "invocation_result" else {}
        for key in ("fallback_for", "fallback_of"):
            original = str(details.get(key) or "").strip()
            capability = str(event.get("capability") or "").strip()
            if original and capability and capability != original:
                found.add(capability)
    return found


def _degraded_fallback_originals(state: dict[str, Any], events: list[dict[str, Any]]) -> list[str]:
    originals: list[str] = []
    seen: set[str] = set()
    breakers = state.get("capability_breakers")
    if isinstance(breakers, dict):
        for capability, row in breakers.items():
            if not isinstance(row, dict):
                continue
            if row.get("open") is True or row.get("fallback_status") in {"required", "unavailable"}:
                name = str(capability).strip()
                if name and name not in seen:
                    seen.add(name)
                    originals.append(name)
    for event in events:
        if not isinstance(event, dict):
            continue
        if event.get("event_type") != "invocation_fallback_required":
            continue
        name = str(event.get("capability") or "").strip()
        if name and name not in seen:
            seen.add(name)
            originals.append(name)
        details_original = str(_details(event).get("fallback_for") or "").strip()
        if details_original and details_original not in seen:
            seen.add(details_original)
            originals.append(details_original)
    return originals


def _timeline_status(
    result: dict[str, Any],
    *,
    fallback_ids: set[str],
) -> str:
    details = _details(result)
    if (
        details.get("methodology_only") is True
        or result.get("result") == "methodology-only"
        or str(details.get("adoption") or details.get("mode") or "").strip() == "methodology-only"
    ):
        return "methodology-only"
    capability = str(result.get("capability") or "").strip()
    is_fallback = bool(
        capability in fallback_ids
        or str(details.get("fallback_for") or "").strip()
        or str(details.get("fallback_of") or "").strip()
    )
    raw = str(result.get("result") or "").strip()
    if is_fallback and raw == "success":
        return "fallback"
    if raw in _TIMELINE_STATUSES:
        return raw
    if raw == "manual-specialized":
        return "methodology-only"
    return "failed"


def _contains_unsafe_payload(text: str, details: dict[str, Any]) -> bool:
    if not text:
        return False
    for key in _UNSAFE_SUMMARY_KEYS:
        raw = details.get(key)
        if isinstance(raw, str) and raw.strip() and raw.strip() in text:
            return True
        if isinstance(raw, (list, tuple)):
            for item in raw:
                if isinstance(item, str) and item.strip() and item.strip() in text:
                    return True
    return False


def _safe_contribution(result: dict[str, Any], *, default: str) -> str:
    details = _details(result)
    text = ""
    for key in ("contribution", "summary"):
        raw = details.get(key)
        if isinstance(raw, str) and raw.strip():
            text = raw
            break
    if _contains_unsafe_payload(text, details):
        text = ""
    clean = sanitize_process_summary_text(text)
    return clean or default


def _intent_ids_for_capability(state: dict[str, Any], capability: str, event: dict[str, Any]) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    details = _details(event)
    for item in _string_list(details.get("intent_ids")):
        if item not in seen:
            seen.add(item)
            found.append(item)
    cap = str(capability or "").strip()
    for intent in _list(state.get("intents")):
        if not isinstance(intent, dict):
            continue
        capability_ids = set(_string_list(intent.get("capability_ids")))
        if cap and cap in capability_ids:
            intent_id = str(intent.get("intent_id") or "").strip()
            if intent_id and intent_id not in seen:
                seen.add(intent_id)
                found.append(intent_id)
    return found


def _evidence_ids_for_invocation(state: dict[str, Any], invocation_id: str, capability: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for row in _list(state.get("evidence")):
        if not isinstance(row, dict):
            continue
        evidence_id = str(row.get("evidence_id") or "").strip()
        if not evidence_id or evidence_id in seen:
            continue
        collector = str(row.get("collector_invocation_id") or "").strip()
        execution = str(row.get("execution_id") or "").strip()
        if collector == invocation_id or execution == invocation_id:
            seen.add(evidence_id)
            found.append(evidence_id)
            continue
        if capability and str(row.get("gate_id") or "") == capability:
            seen.add(evidence_id)
            found.append(evidence_id)
    return found


def _event_time(event: dict[str, Any]) -> str:
    for key in ("timestamp", "recorded_at", "collected_at", "finished_at", "issued_at"):
        value = event.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    details = _details(event)
    for key in ("timestamp", "finished_at"):
        value = details.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return utc_now()


def _status_default_contribution(status: str) -> str:
    return {
        "success": "完成关联调用",
        "failed": "调用失败",
        "refused": "调用被拒绝",
        "cancelled": "调用取消",
        "fallback": "fallback 已执行",
        "methodology-only": "仅采用方法论",
        "not-invoked": "未调用",
    }.get(status, "已记录结构化结果")


def _trusted_reviews(state: dict[str, Any]) -> list[dict[str, Any]]:
    trusted: list[dict[str, Any]] = []
    for review in _list(state.get("reviews")):
        if not isinstance(review, dict) or not validate_review_shape(review):
            continue
        if review.get("attestation"):
            if not _event_attested(review):
                continue
        else:
            continue
        trusted.append(review)
    return trusted


def _quality_from_state(
    state: dict[str, Any],
    events: list[dict[str, Any]],
    trusted_invocation_ids: set[str],
) -> dict[str, Any]:
    gates: list[dict[str, str]] = []
    seen_gates: set[str] = set()
    for row in _list(state.get("evidence")):
        if not isinstance(row, dict):
            continue
        gate_id = str(row.get("gate_id") or "").strip()
        if not gate_id or gate_id in seen_gates:
            continue
        collector = str(row.get("collector_invocation_id") or "").strip()
        if collector and collector not in trusted_invocation_ids:
            continue
        if not collector:
            continue
        seen_gates.add(gate_id)
        passed = row.get("exit_code") == 0 and row.get("relevant") is True
        gates.append({"id": gate_id, "status": "PASS" if passed else "FAIL"})
    for event in events:
        if not isinstance(event, dict) or event.get("event_type") != "gate_execution":
            continue
        if not _event_attested(event):
            continue
        gate_id = str(event.get("gate_id") or "").strip()
        if not gate_id or gate_id in seen_gates:
            continue
        seen_gates.add(gate_id)
        exit_code = event.get("exit_code")
        status = "PASS" if exit_code == 0 and event.get("status") != "degraded" else "FAIL"
        gates.append({"id": gate_id, "status": status})

    reviews = _trusted_reviews(state)
    verdict: str | None = None
    rank = {"APPROVE": 1, "NEEDS_DISCUSSION": 2, "REQUEST_CHANGES": 3}
    for review in reviews:
        current = str(review.get("verdict") or "")
        if current not in REVIEW_VERDICTS:
            continue
        if verdict is None or rank.get(current, 0) > rank.get(verdict, 0):
            verdict = current

    unresolved: list[str] = []
    seen_unresolved: set[str] = set()
    for review in reviews:
        issue_markers: list[str] = []
        for issue in _review_issue_rows(review):
            severity = str(issue.get("severity") or issue.get("level") or "").strip().upper()
            if severity not in {"P0", "P1"}:
                continue
            issue_id = str(issue.get("id") or issue.get("path") or severity).strip()
            marker = sanitize_process_summary_text(f"{severity}:{issue_id}", limit=48)
            if marker and marker not in seen_unresolved:
                seen_unresolved.add(marker)
                issue_markers.append(marker)
        if issue_markers:
            unresolved.extend(issue_markers)
            continue
        raw_count = review.get("unresolved_p0_p1")
        if type(raw_count) is int and raw_count > 0:
            marker = f"p0-p1:{review.get('review_id')}:{raw_count}"
            if marker not in seen_unresolved:
                seen_unresolved.add(marker)
                unresolved.append(marker)

    profile = state.get("quality_profile") if isinstance(state.get("quality_profile"), dict) else {}
    required_gates: set[str] = set()
    for key in ("global_gates", "common_gates", "gates"):
        for row in _list(profile.get(key)):
            if isinstance(row, str) and row.strip():
                required_gates.add(row.strip())
            elif isinstance(row, dict) and str(row.get("id") or "").strip():
                required_gates.add(str(row.get("id")).strip())
    domains = profile.get("domains") if isinstance(profile.get("domains"), dict) else {}
    for domain_row in domains.values():
        required = domain_row.get("required_gates") if isinstance(domain_row, dict) else domain_row
        for gate in _list(required):
            if isinstance(gate, str) and gate.strip():
                required_gates.add(gate.strip())
    for gate_id in sorted(required_gates):
        if gate_id not in seen_gates:
            seen_gates.add(gate_id)
            gates.append({"id": gate_id, "status": "MISSING"})
    gates.sort(key=lambda row: str(row.get("id") or ""))
    return {
        "gates": gates,
        "review_verdict": verdict,
        "unresolved_p0_p1": unresolved,
        "degraded_fallbacks": _degraded_fallback_originals(state, events),
    }


def _canonical_id_for(kind: str, capability: str, event: dict[str, Any]) -> str:
    details = _details(event)
    if kind == "quality_gate":
        gate_id = str(details.get("gate_id") or event.get("gate_id") or "").strip()
        if gate_id:
            return gate_id
        for prefix in ("supervisor-core-gate:", "supervisor-core-builtin:"):
            if capability.startswith(prefix):
                return capability[len(prefix):] or capability
    if kind == "review":
        review_id = str(event.get("review_id") or details.get("review_id") or "").strip()
        if review_id:
            return review_id
    return capability


def _intent_summary_rows(state: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for intent in _list(state.get("intents")):
        if not isinstance(intent, dict):
            continue
        intent_id = str(intent.get("intent_id") or "").strip()
        if not intent_id:
            continue
        status = str(intent.get("status") or "deferred")
        if status not in INTENT_STATES:
            status = "failed"
        row: dict[str, Any] = {"intent_id": intent_id, "status": status}
        kind = str(intent.get("kind") or "").strip()
        if kind in _INTENT_KINDS:
            row["kind"] = kind
        rows.append(row)
    return rows


def build_round_process_summary(
    state: dict[str, Any] | None,
    events: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    """Build RoundProcessSummary/v1 from signed, associated structured records only."""
    state = state if isinstance(state, dict) else {}
    events = [event for event in _list(events) if isinstance(event, dict)]
    goal = state.get("goal") if isinstance(state.get("goal"), dict) else {}
    skills, agents = _capability_indexes(state)
    pairs = _trusted_invocation_pairs(events)
    fallback_ids = _fallback_capability_ids(state, events)
    trusted_invocation_ids = {
        str(result.get("invocation_id") or "")
        for _attempt, result in pairs
        if str(result.get("invocation_id") or "").strip()
    }

    timeline: list[dict[str, Any]] = []
    for attempt, result in pairs:
        capability = str(result.get("capability") or "").strip()
        kind = _classify_timeline_kind(capability, result, skills, agents)
        status = _timeline_status(result, fallback_ids=fallback_ids)
        invocation_id = str(result.get("invocation_id") or "").strip()
        timeline.append({
            "at": _event_time(result) or _event_time(attempt),
            "kind": kind,
            "canonical_id": _canonical_id_for(kind, capability, result),
            "status": status,
            "intent_ids": _intent_ids_for_capability(state, capability, result),
            "contribution": _safe_contribution(
                result, default=_status_default_contribution(status)
            ),
            "evidence_ids": _evidence_ids_for_invocation(state, invocation_id, capability),
        })

    for review in _trusted_reviews(state):
        verdict = str(review.get("verdict") or "")
        status = {
            "APPROVE": "success",
            "REQUEST_CHANGES": "failed",
            "NEEDS_DISCUSSION": "refused",
        }.get(verdict, "failed")
        review_id = str(review.get("review_id") or "").strip()
        if not review_id:
            continue
        if any(item.get("kind") == "review" and item.get("canonical_id") == review_id for item in timeline):
            continue
        unresolved = review.get("unresolved_p0_p1")
        if type(unresolved) is int and unresolved > 0:
            contribution = f"独立审查 {verdict}；未解决 P0/P1={unresolved}"
        else:
            contribution = f"独立审查 {verdict}"
        timeline.append({
            "at": str(review.get("issued_at") or state.get("updated_at") or utc_now()),
            "kind": "review",
            "canonical_id": review_id,
            "status": status,
            "intent_ids": _string_list(review.get("intent_ids")),
            "contribution": sanitize_process_summary_text(contribution),
            "evidence_ids": _string_list(review.get("rerun_evidence_ids")),
        })

    def sort_key(item: dict[str, Any]) -> tuple[str, str, str]:
        return (str(item.get("at") or ""), str(item.get("kind") or ""), str(item.get("canonical_id") or ""))

    timeline.sort(key=sort_key)

    started_at = str(state.get("started_at") or "").strip() or utc_now()
    terminal = state.get("terminal_state")
    if terminal not in TERMINAL_STATES:
        terminal = None
    ended_at = (
        str(state.get("updated_at") or "").strip() or utc_now()
        if terminal in TERMINAL_STATES
        else None
    )
    change_mode = str(goal.get("change_mode") or "replace")
    if change_mode not in CHANGE_MODES:
        change_mode = "replace"
    goal_version = goal.get("version")
    if type(goal_version) is not int or goal_version < 1:
        goal_version = 1
    goal_id = str(goal.get("goal_id") or "").strip() or "goal-unknown"

    return {
        "contract": ROUND_PROCESS_SUMMARY_CONTRACT,
        "round": {
            "started_at": started_at,
            "ended_at": ended_at,
            "goal_id": goal_id,
            "goal_version": goal_version,
            "change_mode": change_mode,
            "terminal_state": terminal,
        },
        "intent_summary": _intent_summary_rows(state),
        "timeline": timeline,
        "quality": _quality_from_state(state, events, trusted_invocation_ids),
    }


def _hhmm(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        return "--:--"
    try:
        return parse_time(value).strftime("%H:%M")
    except (TypeError, ValueError, OSError):
        return "--:--"


def _review_issue_rows(review: dict[str, Any]) -> list[dict[str, Any]]:
    """Collect issue dicts from the review artifact and ``findings`` without aliasing."""
    rows: list[dict[str, Any]] = []
    seen: set[int] = set()

    def _take(value: Any) -> None:
        candidates: list[Any] = []
        if isinstance(value, list):
            candidates = value
        elif isinstance(value, dict):
            nested = value.get("issues")
            if isinstance(nested, list):
                candidates = nested
        for item in candidates:
            if not isinstance(item, dict):
                continue
            marker = id(item)
            if marker in seen:
                continue
            seen.add(marker)
            rows.append(item)

    artifact = review.get("review_output_artifact")
    summary = artifact.get("review_summary") if isinstance(artifact, dict) else None
    if isinstance(summary, dict):
        _take(summary.get("issues"))
    _take(review.get("findings"))
    return rows


def _display_status(item: dict[str, Any], quality: dict[str, Any]) -> str:
    if item.get("kind") == "review" and quality.get("review_verdict"):
        return str(quality.get("review_verdict"))
    return str(item.get("status") or "")


def _folded_status(items: list[dict[str, Any]]) -> str:
    statuses = [str(item.get("status") or "") for item in items]
    if any(status == "failed" for status in statuses):
        return "failed"
    if any(status == "refused" for status in statuses):
        return "refused"
    if any(status == "cancelled" for status in statuses):
        return "cancelled"
    if any(status == "methodology-only" for status in statuses):
        return "methodology-only"
    if any(status == "fallback" for status in statuses):
        return "fallback"
    if statuses and all(status == "success" for status in statuses):
        return "success"
    return "not-invoked"


def _fold_timeline_for_view(timeline: list[dict[str, Any]]) -> list[dict[str, Any]]:
    native = [item for item in timeline if item.get("kind") == "native_command"]
    others = [item for item in timeline if item.get("kind") != "native_command"]
    visible = others[:_USER_VIEW_DETAIL_LIMIT]
    hidden_others = others[_USER_VIEW_DETAIL_LIMIT:]
    if hidden_others:
        counts = {"success": 0, "failed": 0, "fallback": 0}
        evidence: list[str] = []
        for item in hidden_others:
            status = str(item.get("status") or "")
            if status in counts:
                counts[status] += 1
            for evidence_id in _string_list(item.get("evidence_ids")):
                if len(evidence) < 4:
                    evidence.append(evidence_id)
        visible.append({
            "at": str(hidden_others[0].get("at") or ""),
            "kind": "skill",
            "canonical_id": "folded-phase",
            "status": _folded_status(hidden_others),
            "intent_ids": [],
            "contribution": (
                f"某阶段 {len(hidden_others)} 次调用，成功 {counts['success']}、"
                f"失败 {counts['failed']}、fallback {counts['fallback']}"
            ),
            "evidence_ids": evidence,
            "_label": "Skill",
        })
    if len(native) > _NATIVE_VIEW_FOLD_AFTER:
        kept = native[:_NATIVE_VIEW_FOLD_AFTER]
        folded = native[_NATIVE_VIEW_FOLD_AFTER:]
        counts = {"success": 0, "failed": 0, "fallback": 0}
        evidence = []
        for item in folded:
            status = str(item.get("status") or "")
            if status in counts:
                counts[status] += 1
            for evidence_id in _string_list(item.get("evidence_ids")):
                if len(evidence) < 4:
                    evidence.append(evidence_id)
        kept.append({
            "at": str(folded[0].get("at") or ""),
            "kind": "native_command",
            "canonical_id": "native-commands",
            "status": _folded_status(folded),
            "intent_ids": [],
            "contribution": (
                f"某阶段 {len(folded)} 次命令，成功 {counts['success']}、"
                f"失败 {counts['failed']}、fallback {counts['fallback']}"
            ),
            "evidence_ids": evidence,
        })
        visible.extend(kept)
    else:
        visible.extend(native)
    return visible


def render_round_process_summary(summary: dict[str, Any] | None) -> str:
    """Render the short user-facing Markdown log from RoundProcessSummary/v1."""
    summary = summary if isinstance(summary, dict) else {}
    round_info = summary.get("round") if isinstance(summary.get("round"), dict) else {}
    quality = summary.get("quality") if isinstance(summary.get("quality"), dict) else {}
    intents = summary.get("intent_summary") if isinstance(summary.get("intent_summary"), list) else []
    timeline = summary.get("timeline") if isinstance(summary.get("timeline"), list) else []
    started = _hhmm(round_info.get("started_at"))
    ended = _hhmm(round_info.get("ended_at"))
    terminal = round_info.get("terminal_state") or "incomplete"
    goal_id = sanitize_process_summary_text(round_info.get("goal_id") or "goal-unknown", limit=64)
    change_mode = str(round_info.get("change_mode") or "replace")
    version = round_info.get("goal_version") or 1
    intent_parts: list[str] = []
    for row in intents:
        if not isinstance(row, dict):
            continue
        intent_id = sanitize_process_summary_text(row.get("intent_id") or "", limit=32)
        status = str(row.get("status") or "")
        if intent_id and status:
            intent_parts.append(f"{intent_id} {status}")
    intent_line = "；".join(intent_parts) if intent_parts else "无"
    lines = [
        "# RoundProcessSummary/v1",
        "",
        f"本轮：{started}–{ended}｜{goal_id} v{version}｜{change_mode}｜终态 {terminal}",
        f"意图：{intent_line}",
    ]
    for item in _fold_timeline_for_view([row for row in timeline if isinstance(row, dict)]):
        at = _hhmm(item.get("at"))
        kind = _KIND_LABELS.get(str(item.get("kind") or ""), str(item.get("kind") or "Skill"))
        canonical = sanitize_process_summary_text(item.get("canonical_id") or "", limit=48)
        status = sanitize_process_summary_text(_display_status(item, quality), limit=24)
        contribution = sanitize_process_summary_text(item.get("contribution") or "", limit=_CONTRIBUTION_MAX)
        evidence = ",".join(_string_list(item.get("evidence_ids"))[:4]) or "-"
        lines.append(f"{at} {kind}｜{canonical}｜{status}｜{contribution}｜{evidence}")
    gate_parts = []
    for gate in _list(quality.get("gates")):
        if isinstance(gate, dict) and gate.get("id"):
            gate_parts.append(f"{sanitize_process_summary_text(gate.get('id'), limit=24)} {gate.get('status')}")
    verdict = quality.get("review_verdict") or "无"
    unresolved = _list(quality.get("unresolved_p0_p1"))
    gate_text = "；".join(gate_parts) if gate_parts else "无登记门"
    lines.append(
        f"质量：{gate_text}；独立 reviewer {verdict}；未解决 P0/P1={len(unresolved)}"
    )
    if terminal == "complete":
        conclusion = "结论：已满足完成条件"
    elif terminal == "user-waived":
        conclusion = "结论：用户豁免未闭环项；终态 user-waived；未把豁免写成 complete"
    elif terminal == "blocked":
        conclusion = "结论：已阻断；未宣称 complete"
    else:
        conclusion = "结论：未满足完成条件，未宣称 complete"
        if unresolved:
            conclusion += "；下一步处理未解决 P0/P1"
    lines.append(conclusion)
    return "\n".join(lines).rstrip() + "\n"
