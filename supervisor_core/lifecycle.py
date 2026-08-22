from __future__ import annotations

import copy
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

from . import workspace as workspace_module
from .contracts import build_goal, new_state, normalize_intents
from .routing import split_intents
from .storage import StateContext, atomic_write_json, exclusive_lock
from .util import json_load, sha256_bytes, sha256_text, utc_now
from .workspace import capture_workspace_snapshot
from .rollout import initial_rollout


_CORE_SCHEMA_ROOT = Path(__file__).with_name("schemas")
_CORE_SCHEMAS = {
    "project": _CORE_SCHEMA_ROOT / "project-config.schema.json",
    "quality": _CORE_SCHEMA_ROOT / "quality-profile.schema.json",
}
_MAX_INLINE_PRIOR_ROUNDS = 20
_PRIVACY_SAFE_TEXT = re.compile(
    r"^(?:Complete host request|Host intent \d+ \([^\r\n]*\)|Legacy [A-Za-z0-9_.-]+) "
    r"sha256:[0-9a-f]{64}$"
)
_PRIVACY_FREE_TEXT_FIELDS = frozenset({
    "assumptions", "comments", "constraints", "content", "description", "diff",
    "explanation", "findings", "message", "non_goals", "notes", "objective",
    "output_summary", "reason", "recommendation", "risks", "source_authorization",
    "source_locator", "statement", "summary", "text", "title",
})
_PRIVACY_LEGACY_LABELS = {"objective": "objective", "description": "criterion", "text": "intent"}
_ROLLOUT_MACHINE_REASON = re.compile(r"^[A-Za-z0-9_.:-]+$")


def _is_reparse_point(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return bool(
        stat.S_ISLNK(metadata.st_mode)
        or (
            hasattr(metadata, "st_file_attributes")
            and bool(metadata.st_file_attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
        )
    )


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
    )


def _lexical_absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def _reject_reparse_path(path: Path, *, label: str) -> None:
    absolute = _lexical_absolute(path)
    anchor = Path(absolute.anchor)
    current = anchor
    if _is_reparse_point(current):
        raise ValueError(f"{label} path contains a symlink or reparse point")
    try:
        parts = absolute.relative_to(anchor).parts
    except ValueError as exc:
        raise ValueError(f"{label} path is not canonical") from exc
    for part in parts:
        current = current / part
        if _is_reparse_point(current):
            raise ValueError(f"{label} path contains a symlink or reparse point")


def _read_stable_json_object(path: Path, *, label: str) -> dict[str, Any]:
    if _is_reparse_point(path):
        raise ValueError(f"{label} must not be a symlink or reparse point")
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"{label} must be a regular file")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened_before = os.fstat(descriptor)
            chunks: list[bytes] = []
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            opened_after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after = path.lstat()
    except ValueError:
        raise
    except OSError as exc:
        raise ValueError(f"{label} is unavailable or changed during validation") from exc
    if (
        _is_reparse_point(path)
        or _file_identity(before) != _file_identity(opened_before)
        or _file_identity(opened_before) != _file_identity(opened_after)
        or _file_identity(opened_after) != _file_identity(after)
    ):
        raise ValueError(f"{label} changed during validation or became a symlink/reparse point")
    try:
        value = json.loads(b"".join(chunks).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} must contain valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _resolve_declared_schema(config_path: Path, schema_reference: str, *, label: str) -> Path:
    reference = schema_reference.strip()
    raw = Path(reference)
    if (
        not reference
        or "\x00" in reference
        or "://" in reference
        or ":" in reference
        or "\\" in reference
        or reference.startswith("~")
        or raw.is_absolute()
        or bool(raw.drive)
        or ".." in raw.parts
    ):
        raise ValueError(f"{label} $schema escape is forbidden; use a local relative schema")
    config_root = Path(os.path.abspath(os.fspath(config_path.parent)))
    schema_root = config_root / "schemas"
    candidate = Path(os.path.abspath(os.fspath(config_root / raw)))
    try:
        relative = candidate.relative_to(schema_root)
    except ValueError as exc:
        raise ValueError(f"{label} $schema must stay inside the sibling schemas directory") from exc
    current = schema_root
    for part in relative.parts:
        if _is_reparse_point(current):
            raise ValueError(f"{label} $schema path contains a symlink or reparse point")
        current = current / part
    if _is_reparse_point(current):
        raise ValueError(f"{label} $schema path contains a symlink or reparse point")
    try:
        resolved_root = schema_root.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(resolved_root)
    except FileNotFoundError as exc:
        raise ValueError(f"{label} $schema file not found: {candidate}") from exc
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError(f"{label} $schema escape or unsafe path is forbidden") from exc
    if not resolved.is_file():
        raise ValueError(f"{label} $schema must be a regular file")
    return resolved


def _reject_external_schema_refs(schema: Any, *, label: str) -> None:
    if isinstance(schema, dict):
        for key, value in schema.items():
            if key in {"$ref", "$dynamicRef"} and (not isinstance(value, str) or not value.startswith("#")):
                raise ValueError(f"{label} external schema ref is forbidden")
            _reject_external_schema_refs(value, label=label)
    elif isinstance(schema, list):
        for value in schema:
            _reject_external_schema_refs(value, label=label)


def _validate_project_contract(value: dict[str, Any], *, label: str) -> None:
    scope = value.get("supervisor_scope", {})
    for key in ("allowed_change_globs", "out_of_scope_globs"):
        for entry in scope.get(key, []):
            raw = Path(entry)
            if "\\" in entry or ":" in entry or raw.is_absolute() or ".." in raw.parts:
                raise ValueError(f"{label} core schema validation failed: unsafe {key} entry")
    quality_profile = value.get("quality_profile")
    if isinstance(quality_profile, str):
        raw = Path(quality_profile)
        if "\\" in quality_profile or ":" in quality_profile or raw.is_absolute() or ".." in raw.parts:
            raise ValueError(f"{label} core schema validation failed: unsafe quality_profile path")


def _validate_quality_contract(value: dict[str, Any], *, label: str) -> None:
    definitions: dict[str, str] = {}

    def register(row: Any) -> None:
        if not isinstance(row, dict):
            return
        gate_id = row.get("id")
        if not isinstance(gate_id, str):
            return
        encoded = json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        previous = definitions.get(gate_id)
        if previous is not None and previous != encoded:
            raise ValueError(f"{label} core schema validation failed: conflicting gate definition {gate_id}")
        definitions[gate_id] = encoded

    for row in value.get("common_gates", []):
        register(row)
    for row in value.get("gates", []):
        register(row)
    profiles = value.get("profiles", {})
    if isinstance(profiles, dict):
        for profile in profiles.values():
            if isinstance(profile, dict):
                for row in profile.get("gates", []):
                    register(row)

    required = set(value.get("global_gates", []))
    domains = value.get("domains", {})
    if isinstance(domains, dict):
        for domain in domains.values():
            if isinstance(domain, dict):
                required.update(domain.get("required_gates", []))
    if isinstance(profiles, dict):
        for profile in profiles.values():
            if isinstance(profile, dict):
                required.update(profile.get("required", []))
    missing = sorted(gate for gate in required if gate not in definitions)
    if missing:
        raise ValueError(f"{label} core schema validation failed: unregistered required gates: {missing}")


def _validated_json_document(path: Path, *, label: str, kind: str) -> dict[str, Any]:
    value = _read_stable_json_object(path, label=label)
    schema_reference = value.get("$schema")
    if not isinstance(schema_reference, str) or not schema_reference.strip():
        raise ValueError(f"{label} must declare a non-empty $schema")
    schema_path = _resolve_declared_schema(path, schema_reference, label=label)
    schema = _read_stable_json_object(schema_path, label=f"{label} $schema")
    _reject_external_schema_refs(schema, label=label)
    core_schema_path = _CORE_SCHEMAS[kind]
    core_schema = _read_stable_json_object(core_schema_path, label=f"{label} core schema")
    try:
        from jsonschema import Draft202012Validator
        from jsonschema.exceptions import SchemaError, ValidationError
    except ImportError as exc:
        raise ValueError(f"{label} requires the jsonschema dependency") from exc
    try:
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(value)
    except (SchemaError, ValidationError) as exc:
        detail = getattr(exc, "message", str(exc))
        raise ValueError(f"{label} declared schema validation failed: {detail}") from exc
    try:
        Draft202012Validator.check_schema(core_schema)
        Draft202012Validator(core_schema).validate(value)
    except (SchemaError, ValidationError) as exc:
        detail = getattr(exc, "message", str(exc))
        raise ValueError(f"{label} core schema validation failed: {detail}") from exc
    if kind == "project":
        _validate_project_contract(value, label=label)
    else:
        _validate_quality_contract(value, label=label)
    return value


def read_project_config(path: str | None, workspace: str) -> dict[str, Any]:
    explicit_path = bool(path)
    if not path:
        candidate = Path(workspace) / ".agent-supervisor" / "project.json"
        path = str(candidate) if candidate.exists() else None
    if not path:
        return {}
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = Path(workspace) / candidate
    candidate = _lexical_absolute(candidate)
    _reject_reparse_path(candidate, label="project config")
    if not candidate.is_file():
        if explicit_path:
            raise ValueError(f"project config not found: {candidate}")
        return {}
    return _validated_json_document(candidate, label="project config", kind="project")


def read_quality_profile(project_config: dict[str, Any], project_file: str | None, workspace: str) -> dict[str, Any]:
    configured = project_config.get("quality_profile")
    if configured:
        candidate = Path(configured)
        if not candidate.is_absolute():
            if project_file:
                project_path = Path(project_file).expanduser()
                if not project_path.is_absolute():
                    project_path = Path(workspace) / project_path
                candidate = project_path.parent / candidate
            else:
                candidate = Path(workspace) / candidate
    else:
        candidate = Path(workspace) / ".agent-supervisor" / "quality-profile.json"
    candidate = _lexical_absolute(candidate)
    _reject_reparse_path(candidate, label="quality profile")
    if not candidate.is_file():
        if configured:
            raise ValueError(f"quality profile not found: {candidate}")
        return {}
    return _validated_json_document(candidate, label="quality profile", kind="quality")


def _previous_state(ctx: StateContext) -> tuple[dict[str, Any], Path | None]:
    pointer = ctx.previous_pointer()
    state_path = pointer.get("state_file")
    if not state_path:
        return {}, None
    path = Path(state_path)
    value = json_load(path, {}) if path.exists() else {}
    return (value if isinstance(value, dict) else {}), path


def _transition_previous_state(
    previous_path: Path,
    *,
    change_mode: str,
    successor: dict[str, Any],
) -> tuple[dict[str, Any], str]:
    """Link one prior round without overwriting concurrent state mutations."""
    link_names = {
        "continue": "continued_by",
        "extend": "extended_by",
        "replace": "superseded_by",
    }
    link_name = link_names[change_mode]
    desired = {
        "goal_id": successor["goal_id"],
        "version": successor["version"],
        "round": successor["round"],
    }
    with exclusive_lock(previous_path.parent / ".state.lock"):
        current = json_load(previous_path, {})
        if not isinstance(current, dict) or not current:
            raise ValueError("previous round state is unavailable during transition")
        for candidate_name in link_names.values():
            existing = current.get(candidate_name)
            if existing is None:
                continue
            if candidate_name != link_name or existing != desired:
                raise ValueError("previous round already has a different successor")
        if change_mode == "replace":
            if current.get("terminal_state") is None:
                current["terminal_state"] = "incomplete"
            tasks = current.get("tasks")
            if isinstance(tasks, list):
                for task in tasks:
                    if (
                        isinstance(task, dict)
                        and task.get("status") not in {"done", "cancelled", "superseded"}
                    ):
                        task["status"] = "superseded"
        current[link_name] = desired
        current["updated_at"] = utc_now()
        atomic_write_json(previous_path, current)
        source_hash = sha256_bytes(previous_path.read_bytes())
        return copy.deepcopy(current), source_hash


def capture_validated_supervisor_source_snapshot() -> dict[str, Any]:
    unavailable = {
        "contract": "SupervisorSourceSnapshot/v3",
        "status": "unavailable",
        "reason": "capture-helper-unavailable",
    }
    capture = getattr(workspace_module, "capture_supervisor_source_snapshot", None)
    if not callable(capture):
        return unavailable
    try:
        snapshot = capture()
    except Exception as exc:
        unavailable["reason"] = f"capture-failed:{type(exc).__name__}"
        return unavailable
    if (
        not isinstance(snapshot, dict)
        or snapshot.get("contract") != "SupervisorSourceSnapshot/v3"
        or not isinstance(snapshot.get("status"), str)
        or not snapshot["status"].strip()
    ):
        unavailable["reason"] = "capture-returned-invalid-contract"
        return unavailable
    if snapshot["status"] in {"healthy", "available", "degraded"}:
        digest = snapshot.get("snapshot_sha256") or snapshot.get("source_sha256")
        if not isinstance(digest, str) or len(digest) != 64 or any(character not in "0123456789abcdefABCDEF" for character in digest):
            unavailable["reason"] = "capture-returned-invalid-digest"
            return unavailable
    return copy.deepcopy(snapshot)


def _privacy_safe_previous_for_carry(
    previous: dict[str, Any], project_config: dict[str, Any]
) -> dict[str, Any]:
    privacy = (
        project_config.get("privacy")
        if isinstance(project_config.get("privacy"), dict)
        else {}
    )
    carried = copy.deepcopy(previous)
    if privacy.get("persist_raw_prompts") is not False:
        return carried

    def opaque(label: str, value: str) -> str:
        text = value.strip()
        if not text or _PRIVACY_SAFE_TEXT.fullmatch(text):
            return text
        return f"Legacy {label} sha256:{sha256_text(text)}"

    def sanitize_text_value(label: str, value: Any) -> Any:
        if isinstance(value, str):
            return opaque(label, value)
        if isinstance(value, list):
            return [sanitize_text_value(label, item) for item in value]
        if isinstance(value, dict):
            # Once a schema field declares this subtree to be free text (for
            # example ReviewRecord.findings), arbitrary nested keys do not
            # regain structural trust.  Opaque every string leaf below it.
            for nested_key, nested_value in list(value.items()):
                value[nested_key] = sanitize_text_value(label, nested_value)
        return value

    def sanitize_record(value: Any, *, inside_rollout: bool = False) -> None:
        if isinstance(value, dict):
            for key, item in list(value.items()):
                nested_inside_rollout = inside_rollout or key == "rollout"
                if (
                    inside_rollout
                    and key in {"reason", "reset_reason"}
                    and isinstance(item, str)
                    and _ROLLOUT_MACHINE_REASON.fullmatch(item)
                ):
                    # These values are core state-machine tokens consumed by
                    # rollback/recovery logic.  Hashing them would corrupt a
                    # carried RolloutState.  Human prose in the same fields is
                    # still treated as free text below.
                    continue
                if key in _PRIVACY_FREE_TEXT_FIELDS:
                    value[key] = sanitize_text_value(_PRIVACY_LEGACY_LABELS.get(key, key), item)
                elif inside_rollout and key == "reset_reason":
                    value[key] = sanitize_text_value(key, item)
                else:
                    sanitize_record(item, inside_rollout=nested_inside_rollout)
        elif isinstance(value, list):
            for item in value:
                sanitize_record(item, inside_rollout=inside_rollout)

    # Walk the complete carry graph, including nested historical rounds, to find
    # the schema-declared free-text fields above. Structural identifiers and
    # other machine fields are intentionally preserved; once a free-text field
    # is selected, every nested string leaf inside that field is made opaque.
    sanitize_record(carried)
    return carried


def start_round(
    ctx: StateContext,
    *,
    message: str,
    change_mode: str,
    execution_mode: str,
    project_config: dict[str, Any] | None = None,
    quality_profile: dict[str, Any] | None = None,
    goal_supplied: dict[str, Any] | None = None,
    intents_supplied: Any = None,
    trusted_authorizations: dict[str, Any] | None = None,
    shadow: bool = False,
) -> dict[str, Any]:
    if not shadow:
        ctx.initialize()
    project_config = project_config or {}
    previous, previous_path = _previous_state(ctx)
    previous_for_carry = _privacy_safe_previous_for_carry(previous, project_config)
    previous_goal = (
        previous_for_carry.get("goal")
        if isinstance(previous_for_carry.get("goal"), dict)
        else None
    )
    policy_configured = "supervisor_scope" in project_config
    raw_policy_scope = project_config.get("supervisor_scope") if policy_configured else None
    policy_scope = raw_policy_scope if isinstance(raw_policy_scope, dict) else {}
    raw_project_allowed = policy_scope.get("allowed_change_globs", [])
    raw_project_denied = policy_scope.get("out_of_scope_globs", [])
    project_allowed = [
        str(value)
        for value in raw_project_allowed
        if isinstance(value, str) and value.strip()
    ] if isinstance(raw_project_allowed, list) else []
    project_denied = [
        str(value)
        for value in raw_project_denied
        if isinstance(value, str) and value.strip()
    ] if isinstance(raw_project_denied, list) else []
    supplied = copy.deepcopy(goal_supplied or {})
    has_explicit_scope = isinstance(supplied.get("scope"), dict) or "scope_in" in supplied or "scope_out" in supplied
    has_previous_scope = bool(
        previous_goal
        and isinstance(previous_goal.get("scope"), dict)
        and previous_goal["scope"].get("in")
    )
    if not has_explicit_scope and not (change_mode in {"continue", "extend"} and has_previous_scope):
        # Thin host adapters do not receive a machine-authored GoalContract. Bound
        # their first goal to the project's declared Supervisor lease; a generic
        # project without a policy remains usable but every concrete task must still
        # name a non-broad child path and pass the workspace-delta gate.
        supplied["scope"] = {
            "in": project_allowed or ["**"],
            "out": project_denied,
        }
    profile = quality_profile or {}
    default_evidence: list[str] = []
    for gate in profile.get("global_gates", []) if isinstance(profile.get("global_gates"), list) else []:
        if isinstance(gate, str) and gate.strip() and gate not in default_evidence:
            default_evidence.append(gate)
    domains = profile.get("domains", {}) if isinstance(profile.get("domains"), dict) else {}
    evidence_by_domain: dict[str, list[str]] = {}
    for domain_id, domain_row in domains.items():
        if not isinstance(domain_row, dict):
            continue
        domain_gates = list(default_evidence)
        for gate in domain_row.get("required_gates", []) if isinstance(domain_row.get("required_gates"), list) else []:
            if isinstance(gate, str) and gate.strip() and gate not in domain_gates:
                domain_gates.append(gate)
        evidence_by_domain[str(domain_id)] = domain_gates
    config_domain = domains.get("config/agent") or domains.get("config-agent")
    if isinstance(config_domain, dict):
        for gate in config_domain.get("required_gates", []) if isinstance(config_domain.get("required_gates"), list) else []:
            if isinstance(gate, str) and gate.strip() and gate not in default_evidence:
                default_evidence.append(gate)
    atomic_intents = intents_supplied if intents_supplied is not None else split_intents(message)
    new_intents = normalize_intents(atomic_intents, message)
    goal = build_goal(
        message,
        change_mode=change_mode,
        previous_goal=previous_goal,
        supplied=supplied,
        default_evidence=default_evidence,
        default_evidence_by_domain=evidence_by_domain,
        default_intents=new_intents,
        trusted_authorizations=trusted_authorizations,
    )
    carried_intents: list[dict[str, Any]] = []
    if previous and change_mode in {"continue", "extend"}:
        for prior in previous_for_carry.get("intents", []) if isinstance(previous_for_carry.get("intents"), list) else []:
            if isinstance(prior, dict) and prior.get("status") not in {"covered", "skipped"}:
                carried = copy.deepcopy(prior)
                carried["carried_from_goal_version"] = previous_goal.get("version") if previous_goal else None
                carried_intents.append(carried)
    intents = carried_intents
    used_intent_ids = {str(row.get("intent_id") or "") for row in intents}
    for incoming in new_intents:
        candidate = str(incoming.get("intent_id") or "")
        if not candidate or candidate in used_intent_ids:
            suffix = len(intents) + 1
            candidate = f"intent-{suffix}"
            while candidate in used_intent_ids:
                suffix += 1
                candidate = f"intent-{suffix}"
            incoming["intent_id"] = candidate
        used_intent_ids.add(candidate)
        intents.append(incoming)
    state = new_state(
        goal,
        intents,
        runtime=ctx.runtime,
        project=str(project_config.get("project_id") or ctx.project),
        workspace=ctx.workspace,
        session=ctx.session,
        round_id=ctx.round,
        execution_mode=execution_mode,
        quality_profile=quality_profile,
    )
    state["quality_profile"] = quality_profile or {}
    if policy_configured:
        # Presence is semantically meaningful: no project policy leaves this
        # layer unrestricted, while an explicit empty/malformed policy must
        # remain distinguishable so write authorization can fail closed.
        state["project_policy"] = copy.deepcopy(raw_policy_scope)
    fallback_map: dict[str, str] = {}
    for row in project_config.get("agent_roles", []) if isinstance(project_config.get("agent_roles"), list) else []:
        if isinstance(row, dict) and isinstance(row.get("id"), str) and isinstance(row.get("fallback_id"), str):
            fallback_map[row["id"]] = row["fallback_id"]
    for row in project_config.get("capabilities", []) if isinstance(project_config.get("capabilities"), list) else []:
        if isinstance(row, dict) and isinstance(row.get("id"), str) and isinstance(row.get("fallback_id"), str):
            fallback_map[row["id"]] = row["fallback_id"]
    state["capability_fallbacks"] = fallback_map
    session_rollout = previous_for_carry.get("rollout") if previous_for_carry else None
    rollout_recovered_degraded = False

    def load_or_recover_rollout(persisted: dict[str, Any] | None) -> dict[str, Any]:
        nonlocal rollout_recovered_degraded
        try:
            return initial_rollout(
                project_config,
                execution_mode,
                persisted or session_rollout,
            )
        except ValueError:
            rollout_recovered_degraded = True
            return initial_rollout(project_config, execution_mode)

    if shadow:
        current_rollout = json_load(ctx.project_rollout_file, {})
        if not isinstance(current_rollout, dict):
            current_rollout = {}
        state["rollout"] = load_or_recover_rollout(current_rollout)
    else:
        # Build a prospective state without advancing the project ledger. The
        # predecessor must accept its forward/superseded link first.
        state["rollout"] = load_or_recover_rollout(ctx.load_project_rollout())
    state["execution_mode"] = str(state["rollout"].get("active_mode") or "observe")
    state["workspace_baseline"] = capture_workspace_snapshot(
        ctx.workspace,
        project_allowed,
    )
    state["supervisor_source_snapshot"] = capture_validated_supervisor_source_snapshot()
    if state["supervisor_source_snapshot"].get("status") not in {"healthy", "available"}:
        state["health"] = "degraded"
    if rollout_recovered_degraded:
        state["health"] = "degraded"
    state["shadow"] = bool(shadow)
    if not shadow and previous and previous_path and change_mode in {"continue", "extend"}:
        previous, source_hash = _transition_previous_state(
            previous_path,
            change_mode=change_mode,
            successor={
                "goal_id": goal["goal_id"],
                "version": goal["version"],
                "round": ctx.round,
            },
        )
        previous_for_carry = _privacy_safe_previous_for_carry(previous, project_config)
        previous_goal = (
            previous_for_carry.get("goal")
            if isinstance(previous_for_carry.get("goal"), dict)
            else None
        )
        # The lineage hash describes the authoritative prior file callers can
        # inspect after this transition, including its forward link.
        prior_rounds = copy.deepcopy(previous_for_carry.get("prior_rounds", [])) if isinstance(previous_for_carry.get("prior_rounds"), list) else []
        prior_rounds.append(
            {
                "contract": "PriorRoundRecord/v3",
                "round": previous.get("round"),
                "goal": copy.deepcopy(previous_for_carry.get("goal")),
                "intents": copy.deepcopy(previous_for_carry.get("intents", [])),
                "tasks": copy.deepcopy(previous_for_carry.get("tasks", [])),
                "evidence": copy.deepcopy(previous_for_carry.get("evidence", [])),
                "reviews": copy.deepcopy(previous_for_carry.get("reviews", [])),
                "claims": copy.deepcopy(previous_for_carry.get("claims", [])),
                "waivers": copy.deepcopy(previous_for_carry.get("waivers", [])),
                "changes": copy.deepcopy(previous_for_carry.get("changes", {})),
                "spec": copy.deepcopy(previous_for_carry.get("spec", {})),
                "terminal_state": previous.get("terminal_state"),
                "source_state_file": str(previous_path),
                "source_state_sha256": source_hash,
                "carried_at": utc_now(),
            }
        )
        prior_archive = (
            copy.deepcopy(previous_for_carry.get("prior_round_archive"))
            if isinstance(previous_for_carry.get("prior_round_archive"), dict)
            else None
        )
        overflow = max(0, len(prior_rounds) - _MAX_INLINE_PRIOR_ROUNDS)
        if overflow:
            evicted = prior_rounds[:overflow]
            prior_rounds = prior_rounds[overflow:]
            previous_count = (
                prior_archive.get("archived_round_count", 0)
                if isinstance(prior_archive, dict)
                else 0
            )
            if not isinstance(previous_count, int) or previous_count < 0:
                previous_count = 0
            anchor = evicted[-1]
            prior_archive = {
                "contract": "PriorRoundArchiveReference/v3",
                "archived_round_count": previous_count + len(evicted),
                "newest_archived_round": anchor.get("round"),
                "anchor_state_file": anchor.get("source_state_file"),
                "anchor_state_sha256": anchor.get("source_state_sha256"),
                "updated_at": utc_now(),
            }
        if prior_archive:
            state["prior_round_archive"] = prior_archive
        state["prior_rounds"] = prior_rounds
        state["lineage"] = {
            "previous_round": previous.get("round"),
            "previous_goal_id": previous_goal.get("goal_id") if previous_goal else None,
            "previous_goal_version": previous_goal.get("version") if previous_goal else None,
            "previous_state_sha256": source_hash,
            "relationship": change_mode,
        }
    if not shadow and change_mode == "replace" and previous and previous_path:
        _transition_previous_state(
            previous_path,
            change_mode=change_mode,
            successor={
                "goal_id": goal["goal_id"],
                "version": goal["version"],
                "round": ctx.round,
            },
        )
    if not shadow:
        # Persist rollout only after every required predecessor transition has
        # succeeded. A transition failure therefore leaves rollout and the
        # session's current-round pointer byte-for-byte unchanged.
        state["rollout"] = ctx.update_project_rollout(load_or_recover_rollout)
        state["execution_mode"] = str(state["rollout"].get("active_mode") or "observe")
        if rollout_recovered_degraded:
            state["health"] = "degraded"
        ctx.save(state)
        ctx.update_session_pointer(
            {
                "state_file": str(ctx.state_file),
                "round": ctx.round,
                "goal_id": goal["goal_id"],
                "goal_version": goal["version"],
                "updated_at": utc_now(),
            }
        )
        ctx.append_event(
            {
                "event_type": "round_started",
                "status": "started",
                "goal_id": goal["goal_id"],
                "goal_version": goal["version"],
                "change_mode": change_mode,
                "execution_mode": state["execution_mode"],
            }
        )
        if rollout_recovered_degraded:
            ctx.append_event(
                {
                    "event_type": "rollout_start_degraded",
                    "status": "degraded",
                    "summary": "persisted rollout invalid; initialized a fresh safe rollout",
                }
            )
    return state


def merge_state(ctx: StateContext, patch: dict[str, Any]) -> dict[str, Any]:
    state = ctx.load()
    if not state:
        raise ValueError("round state not found")
    for key, value in patch.items():
        if key in {"runtime", "project", "workspace", "session", "round", "goal"}:
            continue
        state[key] = value
    state["updated_at"] = utc_now()
    ctx.save(state)
    return state
