from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Any

from .attestation import sign_record
from .constants import CHANGE_MODES, EXECUTION_MODES, INTENT_STATES, REVIEW_VERDICTS
from .util import canonical_sha256, sha256_text, stable_id, utc_now


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_GIT_OID_LENGTHS = {"sha1": 40, "sha256": 64}


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
        domain = str(raw_intent.get("domain") or "general").strip() or "general"
        marker = (domain, description)
        if not description or marker in seen_defaults:
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
                "phase": _int_or_zero(item.get("phase")),
                "domain": str(item.get("domain") or "general"),
                "role": str(item.get("role") or ""),
                "required_responsibility_groups": _string_list(item.get("required_responsibility_groups")),
                "depends_on_intent_ids": _string_list(item.get("depends_on_intent_ids")),
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
