from __future__ import annotations

import argparse
import copy
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from .constants import EXIT_COMPLETE, EXIT_DEGRADED, EXIT_INCOMPLETE, EXIT_INVALID
from .attestation import sign_record
from .contracts import invocation_event
from .discovery import baseline_report, parse_roots, scan_skills, write_baseline
from .finalize import finalize_round
from .lifecycle import read_project_config, read_quality_profile, start_round
from .routing import route_intents, split_intents
from .rollout import apply_observation, promote, rollback_active_version
from .storage import StateContext, atomic_write_bytes, atomic_write_json, default_round, default_session, prune_old_state
from .util import json_load, parse_time, redact, sha256_bytes, sha256_text, stable_id, utc_now
from .validation import validate_state


class InvalidState(ValueError):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise InvalidState(message)


def _json_arg(raw: str | None, default: Any = None) -> Any:
    if raw is None:
        return default
    candidate = Path(raw)
    if candidate.exists() and candidate.is_file():
        return json_load(candidate, default)
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise InvalidState(f"invalid JSON argument: {exc}") from exc


def _emit(value: Any) -> None:
    print(json.dumps(redact(value), ensure_ascii=False, indent=2, sort_keys=True))


def _project_identity(project_file: str | None, workspace: str) -> tuple[dict[str, Any], str]:
    config = read_project_config(project_file, workspace)
    return config, str(config.get("project_id") or Path(workspace).resolve().name or "project")


def _context(args: argparse.Namespace, *, require_existing: bool = False) -> StateContext:
    runtime = args.runtime
    workspace = str(Path(args.workspace or os.getcwd()).resolve())
    session = args.session or default_session(runtime)
    config, project = _project_identity(getattr(args, "project_file", None), workspace)
    round_id = args.round
    if isinstance(round_id, str) and round_id.casefold() == "latest":
        round_id = None
    provisional = StateContext.build(
        runtime=runtime,
        project=project,
        workspace=workspace,
        session=session,
        round_id=round_id or "current",
        state_root=getattr(args, "state_root", None),
    )
    if not round_id:
        pointer = provisional.previous_pointer()
        round_id = pointer.get("round")
    if not round_id:
        if require_existing:
            raise InvalidState("no active round for this runtime/project/workspace/session")
        round_id = default_round()
    return StateContext.build(
        runtime=runtime,
        project=project,
        workspace=workspace,
        session=session,
        round_id=str(round_id),
        state_root=getattr(args, "state_root", None),
    )


def command_start(args: argparse.Namespace) -> int:
    ctx = _context(args)
    config, _ = _project_identity(args.project_file, ctx.workspace)
    quality = read_quality_profile(config, args.project_file, ctx.workspace)
    supplied = _json_arg(args.goal_json, {})
    if args.criteria_json:
        supplied["acceptance_criteria"] = _json_arg(args.criteria_json, [])
    intents = _json_arg(args.intents_json, None)
    state = start_round(
        ctx,
        message=args.message,
        change_mode=args.change_mode,
        execution_mode=args.execution_mode,
        project_config=config,
        quality_profile=quality,
        goal_supplied=supplied,
        intents_supplied=intents,
        shadow=args.shadow,
    )
    _emit({"ok": True, "state_file": str(ctx.state_file), "goal": state["goal"], "namespace": {"runtime": ctx.runtime, "project": ctx.project, "workspace": ctx.workspace, "session": ctx.session, "round": ctx.round}})
    return EXIT_COMPLETE


def _clean_event_payload(args: argparse.Namespace) -> dict[str, Any]:
    payload = _json_arg(args.data_json, {}) or {}
    if not isinstance(payload, dict):
        raise InvalidState("event data must be an object")
    for key, value in {
        "event_type": args.event_type,
        "phase": args.phase,
        "status": args.status,
        "capability": args.capability,
        "command_category": args.command_category,
        "summary": args.summary,
        "actor": args.actor,
        "invocation_id": args.invocation_id,
        "result": args.result,
    }.items():
        if value is not None:
            payload[key] = value
    # Raw command lines do not belong in the event ledger. Structured EvidenceRecord
    # retains sanitized args separately when explicitly supplied to state.
    for unsafe in ("command", "argv", "args", "raw", "stdin", "stdout", "stderr"):
        payload.pop(unsafe, None)
    return payload


def _record_from_payload(payload: dict[str, Any], event_type: str) -> dict[str, Any]:
    record = payload.get("record")
    if not isinstance(record, dict) or not record:
        raise InvalidState(f"{event_type} requires a non-empty record object in --data-json")
    return redact(record)


def _upsert_record(rows: list[dict[str, Any]], record: dict[str, Any], identity: str) -> None:
    record_id = str(record.get(identity) or "").strip()
    if not record_id:
        raise InvalidState(f"record requires {identity}")
    for index, existing in enumerate(rows):
        if isinstance(existing, dict) and existing.get(identity) == record_id:
            rows[index] = record
            return
    rows.append(record)


def _record_breaker_result(state: dict[str, Any], capability: str, result: str) -> None:
    breakers = state.setdefault("capability_breakers", {})
    configured_fallback = state.get("capability_fallbacks", {}).get(capability)
    row = breakers.setdefault(capability, {"consecutive_failures": 0, "open": False, "fallback_id": configured_fallback})
    if not row.get("fallback_id") and configured_fallback:
        row["fallback_id"] = configured_fallback
    if result == "success":
        row["consecutive_failures"] = 0
        row["open"] = False
        row.pop("active_capability", None)
        row.pop("fallback_status", None)
    else:
        row["consecutive_failures"] = int(row.get("consecutive_failures", 0)) + 1
        if row["consecutive_failures"] >= 2:
            row["open"] = True
            row["opened_at"] = utc_now()
            row["active_capability"] = row.get("fallback_id")
            row["fallback_status"] = "required" if row.get("fallback_id") else "unavailable"
    state["updated_at"] = utc_now()


def _apply_state_record(state: dict[str, Any], payload: dict[str, Any], event_type: str) -> str | None:
    aliases = {
        "task_record": ("tasks", "task_id"),
        "task_upsert": ("tasks", "task_id"),
        "evidence_record": ("evidence", "evidence_id"),
        "review_record": ("reviews", "review_id"),
        "waiver_record": ("waivers", "waiver_id"),
        "claim_record": ("claims", "claim_id"),
    }
    if event_type in aliases:
        collection, identity = aliases[event_type]
        record = _record_from_payload(payload, event_type)
        rows = state.setdefault(collection, [])
        if not isinstance(rows, list):
            raise InvalidState(f"state.{collection} must be an array")
        _upsert_record(rows, record, identity)
        return str(record.get(identity))
    if event_type == "intent_disposition":
        record = _record_from_payload(payload, event_type)
        intent_id = str(record.get("intent_id") or "").strip()
        if not intent_id:
            raise InvalidState("intent disposition requires intent_id")
        for intent in state.get("intents", []):
            if isinstance(intent, dict) and intent.get("intent_id") == intent_id:
                for key in ("status", "reason", "capability_ids", "method", "phase"):
                    if key in record:
                        intent[key] = record[key]
                return intent_id
        raise InvalidState(f"intent not found: {intent_id}")
    if event_type == "changes_record":
        record = _record_from_payload(payload, event_type)
        state["changes"] = record
        return str(record.get("diff_hash") or "changes")
    if event_type == "spec_record":
        record = _record_from_payload(payload, event_type)
        state["spec"] = record
        return str(record.get("hash") or record.get("status") or "spec")
    if event_type == "rollout_observation":
        record = _record_from_payload(payload, event_type)
        apply_observation(state.setdefault("rollout", {}), record)
        if state["rollout"].get("rollback", {}).get("required") and not state["rollout"].get("rollback", {}).get("performed"):
            rollback = rollback_active_version()
            state["rollout"]["rollback"].update(rollback)
            if not rollback.get("performed"):
                state["health"] = "degraded"
        return str(record.get("observation_id"))
    if event_type == "rollout_promote":
        record = _record_from_payload(payload, event_type)
        if record.get("contract") != "RolloutPromotion/v3":
            raise InvalidState("rollout promotion contract invalid")
        requested_mode = str(record.get("requested_mode") or "")
        promote(state.setdefault("rollout", {}), requested_mode)
        state["execution_mode"] = requested_mode
        return str(record.get("promotion_id") or requested_mode)
    return None


def _registered_gate(state: dict[str, Any], gate_id: str) -> dict[str, Any] | None:
    from .validation import _registered_gate_definitions

    return _registered_gate_definitions(state.get("quality_profile", {})).get(gate_id)


def _evaluate_builtin_gate(
    state: dict[str, Any], events: list[dict[str, Any]], builtin: str, *, finalize_internal: bool
) -> tuple[int, dict[str, Any]]:
    from .validation import successful_invocations

    if builtin == "intent-coverage":
        intents = state.get("intents", [])
        manifest = state.get("intent_manifest", [])
        success_caps, _, invocation_errors = successful_invocations(events)
        failures = list(invocation_errors)
        expected_manifest: list[dict[str, str]] = []
        if not isinstance(intents, list) or not intents:
            failures.append("atomic intents are empty")
            intents = []
        for intent in intents:
            if not isinstance(intent, dict):
                failures.append("intent is not structured")
                continue
            expected_manifest.append({
                "intent_id": str(intent.get("intent_id") or ""),
                "text_sha256": sha256_text(str(intent.get("text") or "")),
                "domain": str(intent.get("domain") or "general"),
            })
            status = intent.get("status")
            reason = str(intent.get("reason") or "").strip()
            if status not in {"covered", "skipped"}:
                failures.append(f"{intent.get('intent_id')}: unresolved status {status}")
            if not reason or reason == "awaiting routing":
                failures.append(f"{intent.get('intent_id')}: missing concrete reason")
            if status == "covered" and intent.get("method") != "manual-specialized":
                capabilities = {str(value) for value in intent.get("capability_ids", []) if isinstance(value, str)}
                if not capabilities.intersection(success_caps):
                    failures.append(f"{intent.get('intent_id')}: no successful correlated invocation")
        if manifest != expected_manifest:
            failures.append("intent manifest does not match the immutable request split")
        artifact = {"builtin": builtin, "intent_count": len(intents), "failures": failures}
        return (0 if not failures else 2), artifact

    if builtin == "claim-source-map":
        claims = state.get("claims", [])
        failures: list[str] = []
        if not isinstance(claims, list) or not claims:
            failures.append("no material claim records were supplied")
            claims = []
        started = parse_time(str(state.get("started_at") or utc_now()))
        seen: set[str] = set()
        for claim in claims:
            if not isinstance(claim, dict) or claim.get("contract") != "ClaimRecord/v3":
                failures.append("claim record contract invalid")
                continue
            claim_id = str(claim.get("claim_id") or "")
            if not claim_id or claim_id in seen:
                failures.append("claim id missing or duplicate")
            seen.add(claim_id)
            if not re.fullmatch(r"[0-9a-f]{64}", str(claim.get("statement_sha256") or "")):
                failures.append(f"{claim_id}: statement hash invalid")
            if not str(claim.get("source_locator") or "").strip() or not str(claim.get("collector") or "").strip():
                failures.append(f"{claim_id}: source locator/collector missing")
            try:
                if parse_time(str(claim.get("collected_at") or "")) < started:
                    failures.append(f"{claim_id}: stale source collection")
            except (TypeError, ValueError):
                failures.append(f"{claim_id}: collection timestamp invalid")
        artifact = {"builtin": builtin, "claim_count": len(claims), "failures": failures}
        return (0 if not failures else 2), artifact

    if builtin == "goal-finalize":
        failures = [] if finalize_internal else ["goal-finalize can only be emitted by the trusted finalize path"]
        artifact = {
            "builtin": builtin,
            "round": state.get("round"),
            "no_file_change": not bool(state.get("changes", {}).get("files")),
            "finalize_preflight": finalize_internal,
            "failures": failures,
        }
        return (0 if not failures else 2), artifact
    return 2, {"builtin": builtin, "failures": ["unsupported builtin gate"]}


def _run_registered_gate(
    ctx: StateContext, payload: dict[str, Any], *, finalize_internal: bool = False
) -> tuple[dict[str, Any], dict[str, Any], int]:
    request = _record_from_payload(payload, "gate_run")
    gate_id = str(request.get("gate_id") or "").strip()
    criterion_id = str(request.get("criterion_id") or "").strip()
    collector = str(payload.get("actor") or request.get("collector") or "runtime").strip()
    collector_group = str(request.get("collector_responsibility_group") or "runtime").strip()
    if not gate_id or not criterion_id or not collector or not collector_group:
        raise InvalidState("gate_run requires gate_id, criterion_id, actor, and collector_responsibility_group")
    state = ctx.load()
    gate = _registered_gate(state, gate_id)
    if not gate:
        raise InvalidState(f"gate is not registered in QualityProfile: {gate_id}")
    command = list(gate["command"])
    execution_id = stable_id("execution")
    evidence_id = str(request.get("evidence_id") or stable_id("evidence"))
    started_at = utc_now()
    if gate.get("builtin"):
        exit_code, artifact = _evaluate_builtin_gate(
            state, ctx.events(), str(gate["builtin"]), finalize_internal=finalize_internal
        )
        combined = json.dumps(artifact, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    else:
        try:
            completed = subprocess.run(
                command,
                cwd=str(state.get("workspace") or ctx.workspace),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=int(request.get("timeout_seconds") or 1200),
                check=False,
            )
            exit_code = int(completed.returncode)
            combined = ((completed.stdout or "") + ("\n" if completed.stdout and completed.stderr else "") + (completed.stderr or ""))
        except (OSError, subprocess.TimeoutExpired) as exc:
            exit_code = 124 if isinstance(exc, subprocess.TimeoutExpired) else 127
            combined = type(exc).__name__
    clean_output = str(redact(combined))
    summary = clean_output[-4000:].strip() or f"gate {gate_id} produced no output"
    finished_at = utc_now()
    changes = state.get("changes", {}) if isinstance(state.get("changes"), dict) else {}
    baseline = state.get("workspace_baseline", {}) if isinstance(state.get("workspace_baseline"), dict) else {}
    bound_base = str(changes.get("base") or baseline.get("snapshot_hash") or sha256_text("no-change-base"))
    bound_head = str(changes.get("head") or baseline.get("snapshot_hash") or sha256_text("no-change-head"))
    bound_diff = str(changes.get("diff_hash") or sha256_text("no-change"))
    goal = state.get("goal", {}) if isinstance(state.get("goal"), dict) else {}
    execution = {
        "contract": "GateExecution/v3",
        "event_type": "gate_execution",
        "execution_id": execution_id,
        "evidence_id": evidence_id,
        "gate_id": gate_id,
        "criterion_id": criterion_id,
        "goal_id": goal.get("goal_id"),
        "goal_version": goal.get("version"),
        "command": {"category": "quality-gate", "args": command},
        "cwd": str(state.get("workspace") or ctx.workspace),
        "state_started_at": state.get("started_at"),
        "started_at": started_at,
        "finished_at": finished_at,
        "collected_at": finished_at,
        "exit_code": exit_code,
        "output_sha256": sha256_text(clean_output),
        "output_summary": summary,
        "output_summary_sha256": sha256_text(summary),
        "artifact_hash": sha256_text(clean_output),
        "base": bound_base,
        "head": bound_head,
        "diff_hash": bound_diff,
        "workspace_snapshot_hash": baseline.get("snapshot_hash"),
        "collector": collector,
        "collector_responsibility_group": collector_group,
        "status": "success" if exit_code == 0 else "failed",
    }
    execution["attestation"] = sign_record(execution)
    evidence = {
        "contract": "EvidenceRecord/v3",
        "evidence_id": evidence_id,
        "execution_id": execution_id,
        "criterion_id": criterion_id,
        "goal_id": execution["goal_id"],
        "goal_version": execution["goal_version"],
        "command": {"category": "quality-gate", "args": command},
        "cwd": str(state.get("workspace") or ctx.workspace),
        "collected_at": execution["collected_at"],
        "exit_code": exit_code,
        "output_summary": summary,
        "artifact_hash": sha256_text(clean_output),
        "output_sha256": sha256_text(clean_output),
        "base": execution["base"],
        "head": execution["head"],
        "diff_hash": execution["diff_hash"],
        "collector": collector,
        "collector_responsibility_group": collector_group,
        "gate_id": gate_id,
        "relevant": True,
    }

    def persist(state_value: dict[str, Any]) -> None:
        if exit_code == 0:
            rows = state_value.setdefault("evidence", [])
            _upsert_record(rows, evidence, "evidence_id")
        state_value["updated_at"] = utc_now()

    ctx.update(persist)
    ctx.append_event(execution)
    try:
        latest = ctx.load()
        global_gates = latest.get("quality_profile", {}).get("global_gates", [])
        kind: str | None = None
        values: dict[str, Any] = {}
        if gate_id == "review.project-supervisor":
            kind, values = "fixture_replay", {"passed": exit_code == 0}
        elif gate_id == "config.historical-replay":
            kind, values = "historical_replay", {"passed": exit_code == 0}
        elif gate_id in global_gates:
            kind, values = "global_gate", {"result": "success" if exit_code == 0 else "failed"}
        if kind:
            observation = {
                "contract": "RolloutObservation/v3",
                "observation_id": f"rollout-{execution_id}",
                "kind": kind,
                "source_contract": "GateExecution/v3",
                "source_id": execution_id,
                "gate_id": gate_id,
                **values,
            }
            observation["attestation"] = sign_record(observation)

            def update_rollout(current: dict[str, Any]) -> dict[str, Any]:
                target = copy.deepcopy(current or latest.get("rollout", {}))
                return apply_observation(target, observation)

            project_rollout = ctx.update_project_rollout(update_rollout)
            ctx.update(lambda state_value: state_value.update({"rollout": copy.deepcopy(project_rollout), "updated_at": utc_now()}))
            ctx.append_event(observation)
    except Exception as exc:
        ctx.update(lambda state_value: state_value.update({"health": "degraded", "updated_at": utc_now()}))
        ctx.append_event({"event_type": "rollout_gate_degraded", "status": "degraded", "summary": type(exc).__name__})
    return evidence, execution, EXIT_COMPLETE if exit_code == 0 else EXIT_INCOMPLETE


def command_event(args: argparse.Namespace) -> int:
    ctx = _context(args, require_existing=True)
    payload = _clean_event_payload(args)
    event_type = str(payload.get("event_type") or "event")
    if event_type == "gate_execution":
        raise InvalidState("gate_execution is reserved for the trusted core runner")
    if event_type == "rollout_observation":
        raise InvalidState("rollout_observation is reserved for trusted core executions/finalization")
    if event_type == "gate_run":
        evidence, execution, code = _run_registered_gate(ctx, payload)
        _emit({"ok": code == EXIT_COMPLETE, "evidence_id": evidence["evidence_id"], "execution_id": execution["execution_id"], "gate_id": evidence["gate_id"], "exit_code": evidence["exit_code"], "state_file": str(ctx.state_file)})
        return code
    if event_type == "rollout_promote":
        record = _record_from_payload(payload, event_type)
        if record.get("contract") != "RolloutPromotion/v3":
            raise InvalidState("rollout promotion contract invalid")
        requested_mode = str(record.get("requested_mode") or "")

        def promote_project(current: dict[str, Any]) -> dict[str, Any]:
            if not current:
                raise InvalidState("project rollout state missing")
            promote(current, requested_mode)
            return current

        project_rollout = ctx.update_project_rollout(promote_project)
        ctx.update(lambda state: state.update({
            "rollout": copy.deepcopy(project_rollout),
            "execution_mode": requested_mode,
            "updated_at": utc_now(),
        }))
        payload.pop("record", None)
        payload["record_id"] = str(record.get("promotion_id") or requested_mode)
        recorded = ctx.append_event(payload)
        _emit({"ok": True, "event": recorded, "state_file": str(ctx.state_file), "active_mode": requested_mode})
        return EXIT_COMPLETE
    invocation_id = str(payload.get("invocation_id") or "")
    capability = str(payload.get("capability") or "")
    is_result = event_type in {"invocation_result", "skill_result"}
    if event_type in {"invocation_attempt", "skill_attempt"}:
        if not invocation_id or not capability:
            raise InvalidState("invocation attempt requires --invocation-id and --capability")
        breaker = ctx.load().get("capability_breakers", {}).get(capability, {})
        if isinstance(breaker, dict) and breaker.get("open") is True:
            fallback_id = str(breaker.get("fallback_id") or "").strip()
            recorded = ctx.append_event({
                "event_type": "invocation_fallback_required",
                "invocation_id": invocation_id,
                "capability": capability,
                "fallback_id": fallback_id or None,
                "status": "routed" if fallback_id else "degraded",
                "actor": str(payload.get("actor") or "runtime"),
                "summary": "capability circuit is open; original attempt was not counted",
            })
            _emit({"ok": False, "event": recorded, "fallback_required": fallback_id or None, "state_file": str(ctx.state_file)})
            return EXIT_DEGRADED
        payload = invocation_event(invocation_id=invocation_id, capability=capability, stage="attempt", result=None, actor=str(payload.get("actor") or "runtime"), details={"phase": payload.get("phase"), "summary": payload.get("summary")})
    elif is_result:
        if not invocation_id or not capability or args.result not in {"success", "failed", "refused", "cancelled", "manual-specialized"}:
            raise InvalidState("invocation result requires id, capability, and a supported result")
        payload = invocation_event(invocation_id=invocation_id, capability=capability, stage="result", result=args.result, actor=str(payload.get("actor") or "runtime"), details={"phase": payload.get("phase"), "summary": payload.get("summary")})
    record_id: str | None = None
    needs_state_update = is_result or event_type in {
        "task_record", "task_upsert", "evidence_record", "review_record", "claim_record",
        "waiver_record", "intent_disposition", "changes_record", "spec_record",
        "rollout_observation", "rollout_promote",
    } or payload.get("status") == "degraded" or payload.get("degraded_prior") is True
    if needs_state_update:
        def mutate(state: dict[str, Any]) -> None:
            nonlocal record_id
            if is_result:
                _record_breaker_result(state, capability, str(args.result))
            record_id = _apply_state_record(state, payload, event_type)
            if payload.get("status") == "degraded" or payload.get("degraded_prior") is True:
                state["health"] = "degraded"
            state["updated_at"] = utc_now()

        ctx.update(mutate)
    elif not ctx.load():
        raise InvalidState("active round state missing")
    if record_id is not None:
        payload.pop("record", None)
        payload["record_id"] = record_id
    recorded = ctx.append_event(payload)
    try:
        prune_old_state(ctx.root.parents[4])
    except (OSError, IndexError):
        # Retention cleanup is maintenance, not evidence. A failure is visible but
        # must not corrupt the event that was already atomically committed.
        ctx.append_event({"event_type": "retention_degraded", "status": "degraded", "summary": "rotated-log cleanup failed"})
        ctx.update(lambda state: state.update({"health": "degraded", "updated_at": utc_now()}))
    _emit({"ok": True, "event": recorded, "state_file": str(ctx.state_file)})
    return EXIT_COMPLETE


def command_validate(args: argparse.Namespace) -> int:
    ctx = _context(args, require_existing=True)
    state = ctx.load()
    if not state:
        raise InvalidState("state not found")
    try:
        report = validate_state(state, ctx.events())
    except Exception as exc:
        state["health"] = "degraded"
        ctx.save(state)
        ctx.append_event({"event_type": "validator_degraded", "status": "degraded", "summary": type(exc).__name__})
        _emit({"valid": False, "health": "degraded", "errors": [f"validator exception: {type(exc).__name__}"]})
        return EXIT_DEGRADED
    _emit(report)
    if report["valid"]:
        return EXIT_COMPLETE
    return EXIT_DEGRADED if report["health"] == "degraded" else EXIT_INCOMPLETE


def command_finalize(args: argparse.Namespace) -> int:
    ctx = _context(args, require_existing=True)
    try:
        from .validation import _profile_gates, _registered_gate_definitions

        state = ctx.load()
        profile = state.get("quality_profile", {}) if isinstance(state.get("quality_profile"), dict) else {}
        domains = {
            str(value) for value in state.get("changes", {}).get("domains", [])
            if isinstance(value, str) and value.strip()
        }
        domains.update(
            str(row.get("domain")) for row in state.get("goal", {}).get("acceptance_criteria", [])
            if isinstance(row, dict) and row.get("domain")
        )
        required = _profile_gates(profile, domains)
        definitions = _registered_gate_definitions(profile)
        passed = {
            str(row.get("gate_id")) for row in state.get("evidence", [])
            if isinstance(row, dict) and row.get("exit_code") == 0
        }
        criteria = [
            row for row in state.get("goal", {}).get("acceptance_criteria", [])
            if isinstance(row, dict) and row.get("criterion_id")
        ]
        for gate_id in sorted(required - passed):
            definition = definitions.get(gate_id, {})
            if not definition.get("builtin"):
                continue
            criterion = next(
                (row for row in criteria if gate_id in row.get("expected_evidence", [])),
                criteria[0] if criteria else None,
            )
            if criterion is None:
                raise InvalidState(f"builtin gate has no acceptance criterion binding: {gate_id}")
            _run_registered_gate(
                ctx,
                {
                    "event_type": "gate_run",
                    "actor": "supervisor-core",
                    "record": {
                        "gate_id": gate_id,
                        "criterion_id": criterion["criterion_id"],
                        "collector": "supervisor-core",
                        "collector_responsibility_group": "trusted-runtime",
                    },
                },
                finalize_internal=True,
            )
    except Exception as exc:
        ctx.update(lambda state: state.update({"health": "degraded", "updated_at": utc_now()}))
        ctx.append_event({
            "event_type": "builtin_finalize_degraded",
            "status": "degraded",
            "summary": type(exc).__name__,
        })
    state, code = finalize_round(ctx, stop_attempt=args.stop_attempt, blocked=args.blocked)
    _emit({"terminal_state": state["terminal_state"], "host_gate": state["host_gate"], "validation": state["validation"], "state_file": str(ctx.state_file)})
    return code


def _handoff(state: dict[str, Any], events: list[dict[str, Any]]) -> str:
    goal = state.get("goal", {})
    validation = state.get("validation", {})
    lines = [
        "# Agent Supervisor Handoff",
        "",
        f"- Goal: {goal.get('objective', '')}",
        f"- Goal ID/version: {goal.get('goal_id', '')} / {goal.get('version', '')}",
        f"- Mode: {state.get('execution_mode', '')}",
        f"- Terminal: {state.get('terminal_state') or 'active'}",
        f"- Health: {state.get('health', '')}",
        "",
        "## Intent coverage",
        "",
    ]
    for intent in state.get("intents", []):
        if isinstance(intent, dict):
            lines.append(f"- [{intent.get('status', '')}] {intent.get('intent_id', '')}: {intent.get('text', '')} — {intent.get('reason', '')}")
    lines.extend(["", "## Validation", ""])
    errors = validation.get("errors", []) if isinstance(validation, dict) else []
    lines.extend([f"- {item}" for item in errors] or ["- Not finalized yet."])
    lines.extend(["", "## Recent events", ""])
    for event in events[-20:]:
        lines.append(f"- #{event.get('sequence')} {event.get('recorded_at')} {event.get('event_type')} {event.get('status', '')}")
    return "\n".join(lines).rstrip() + "\n"


def command_query(args: argparse.Namespace) -> int:
    ctx = _context(args, require_existing=True)
    state = ctx.load()
    if not state:
        raise InvalidState("active round state missing")
    if args.format == "handoff":
        result: Any = _handoff(state, ctx.events())
    elif args.format == "events":
        result = ctx.events()
    else:
        result = state
    if args.output:
        path = Path(args.output)
        if isinstance(result, str):
            path.parent.mkdir(parents=True, exist_ok=True)
            from .storage import atomic_write_bytes

            atomic_write_bytes(path, result.encode("utf-8"))
        else:
            atomic_write_json(path, result)
        _emit({"ok": True, "output": str(path), "format": args.format})
    elif isinstance(result, str):
        print(result, end="")
    else:
        _emit(result)
    return EXIT_COMPLETE


def command_discover(args: argparse.Namespace) -> int:
    inventory = scan_skills(parse_roots(args.roots or [], args.runtime))
    if args.baseline:
        inventory["baseline"] = baseline_report(inventory, Path(args.baseline))
    if args.write_baseline:
        write_baseline(inventory, Path(args.write_baseline))
    if args.output:
        atomic_write_json(Path(args.output), inventory)
    _emit(inventory)
    baseline = inventory.get("baseline", {})
    return EXIT_INCOMPLETE if baseline.get("missing") and not baseline.get("explainable") else EXIT_COMPLETE


def command_route(args: argparse.Namespace) -> int:
    inventory = _json_arg(args.inventory, {"skills": []})
    intents = _json_arg(args.intents_file, None)
    result = route_intents(message=args.message or "", inventory=inventory, supplied_intents=intents, phase_budget=args.phase_budget, zero_skill_reviewed=args.zero_skill_reviewed)
    if args.output:
        atomic_write_json(Path(args.output), result)
    _emit(result)
    return EXIT_COMPLETE if result["valid"] else EXIT_INCOMPLETE


def command_migrate(args: argparse.Namespace) -> int:
    ctx = _context(args)
    source = Path(args.source).expanduser().resolve()
    if not source.exists():
        raise InvalidState(f"migration source missing: {source}")
    destination = ctx.root / "legacy" / f"import-{sha256_text(str(source))[:12]}"
    if destination.exists():
        raise InvalidState("legacy import already exists; refusing overwrite")
    destination.mkdir(parents=True)
    files = [source] if source.is_file() else [path for path in source.rglob("*") if path.is_file()]
    manifest = []
    for path in files:
        relative = Path(path.name) if source.is_file() else path.relative_to(source)
        target = destination / relative
        source_bytes = path.read_bytes()
        source_hash = sha256_bytes(source_bytes)
        sensitive_name = any(token in path.name.casefold() for token in (".env", "credential", "secret", "settings.local"))
        imported = False
        redacted_copy = False
        archived_hash = None
        if not sensitive_name and path.suffix.casefold() in {".json", ".jsonl", ".md", ".txt", ".log", ".yaml", ".yml", ".toml"}:
            try:
                source_text = source_bytes.decode("utf-8")
                if path.suffix.casefold() == ".json":
                    clean_text = json.dumps(redact(json.loads(source_text)), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
                elif path.suffix.casefold() == ".jsonl":
                    clean_lines = []
                    for line in source_text.splitlines():
                        if not line.strip():
                            continue
                        try:
                            clean_lines.append(json.dumps(redact(json.loads(line)), ensure_ascii=False, sort_keys=True))
                        except json.JSONDecodeError:
                            clean_lines.append(str(redact(line)))
                    clean_text = "\n".join(clean_lines) + ("\n" if clean_lines else "")
                else:
                    clean_text = str(redact(source_text))
                clean_bytes = clean_text.encode("utf-8")
                atomic_write_bytes(target, clean_bytes)
                archived_hash = sha256_bytes(clean_bytes)
                imported = True
                redacted_copy = clean_bytes != source_bytes
            except (UnicodeDecodeError, json.JSONDecodeError):
                imported = False
        manifest.append({
            "source": str(path),
            "relative": str(relative),
            "source_sha256": source_hash,
            "archived_sha256": archived_hash,
            "imported": imported,
            "redacted_copy": redacted_copy,
            "omitted_reason": "sensitive-name" if sensitive_name else (None if imported else "non-text-or-undecodable"),
        })
    atomic_write_json(destination / "manifest.json", {"source": str(source), "imported_at": utc_now(), "read_only_source": True, "redacted_archive": True, "files": manifest})
    imported_count = sum(1 for row in manifest if row["imported"])
    ctx.append_event({"event_type": "legacy_migrated", "status": "success", "summary": f"{imported_count} redacted text files archived; source left untouched", "destination": str(destination)})
    _emit({"ok": True, "destination": str(destination), "file_count": len(files), "imported_count": imported_count, "omitted_count": len(files) - imported_count})
    return EXIT_COMPLETE


def command_selftest(args: argparse.Namespace) -> int:
    root = Path(__file__).resolve().parents[1]
    temp_parent = root / ".pytest-tmp"
    temp_parent.mkdir(parents=True, exist_ok=True)
    base_temp = temp_parent / f"selftest-{os.getpid()}-{sha256_text(utc_now())[:8]}"
    command = [sys.executable, "-m", "pytest", "-q", "--basetemp", str(base_temp), str(root / "tests")]
    completed = subprocess.run(command, cwd=root, text=True, capture_output=True)
    discovered_suites = sorted(path.name for path in (root / "tests").glob("test_*.py"))
    result = {
        "command": command,
        "exit_code": completed.returncode,
        "stdout": completed.stdout[-12000:],
        "stderr": completed.stderr[-4000:],
        "discovered_child_suites": discovered_suites,
        "invoked_test_root": str(root / "tests"),
        "all_child_suites_invoked": bool(discovered_suites) and completed.returncode == 0,
    }
    _emit(result)
    return EXIT_COMPLETE if completed.returncode == 0 else EXIT_INCOMPLETE


def _hook_context(payload: dict[str, Any], runtime: str, event: str) -> argparse.Namespace:
    workspace = str(payload.get("cwd") or payload.get("workspace") or os.getcwd())
    session = str(payload.get("session_id") or payload.get("session") or default_session(runtime))
    project_file = str(Path(workspace) / ".agent-supervisor" / "project.json")
    if not Path(project_file).exists():
        project_file = None
    return argparse.Namespace(runtime=runtime, workspace=workspace, session=session, round=None, project_file=project_file, state_root=None)


def _classify_goal_change(prompt: str, previous: dict[str, Any]) -> str:
    lowered = prompt.casefold()
    replace_markers = ("新任务", "新的任务", "换个任务", "不要之前", "停止之前", "替换目标", "replace goal", "new task")
    extend_markers = ("另外", "补充", "新增要求", "再加", "同时还要", "also", "in addition", "extend")
    continue_markers = ("继续", "接着", "尚未", "还没", "未完成", "没跑完", "继续处理", "continue", "resume")
    if any(marker in lowered for marker in replace_markers):
        return "replace"
    if any(marker in lowered for marker in extend_markers):
        return "extend"
    if any(marker in lowered for marker in continue_markers):
        return "continue"
    if previous and previous.get("terminal_state") in {None, "incomplete", "blocked"}:
        goal = previous.get("goal") if isinstance(previous.get("goal"), dict) else previous
        prior_parts = [str(goal.get("objective") or "")]
        criteria = goal.get("acceptance_criteria") or []
        if isinstance(criteria, list):
            prior_parts.extend(
                str(item.get("description") or item.get("text") or "")
                for item in criteria
                if isinstance(item, dict)
            )

        def semantic_terms(value: str) -> set[str]:
            stop = {
                "a", "an", "and", "do", "for", "implement", "new", "old", "please",
                "task", "the", "this", "to", "with", "修改", "任务", "实现", "帮我", "请",
            }
            terms = {token for token in re.findall(r"[a-z0-9_]{3,}", value.casefold()) if token not in stop}
            for chunk in re.findall(r"[\u3400-\u9fff]{2,}", value):
                terms.update(chunk[index:index + 2] for index in range(len(chunk) - 1))
            return terms

        incoming_terms = semantic_terms(prompt)
        previous_terms = semantic_terms(" ".join(prior_parts))
        if incoming_terms and previous_terms:
            overlap = len(incoming_terms & previous_terms) / min(len(incoming_terms), len(previous_terms))
            if overlap < 0.12:
                return "replace"
        # Sparse or genuinely ambiguous follow-ups stay attached to unfinished work.
        return "continue"
    return "replace" if previous else "continue"


def command_hook(args: argparse.Namespace) -> int:
    try:
        payload = json.load(sys.stdin)
        if not isinstance(payload, dict):
            raise InvalidState("hook stdin must be an object")
        ns = _hook_context(payload, args.runtime, args.event)
        adapter = payload.get("_agent_supervisor_adapter", {})
        if args.event == "UserPromptSubmit":
            prompt = str(payload.get("prompt") or payload.get("user_prompt") or "").strip()
            previous_ctx = _context(ns, require_existing=False)
            previous = previous_ctx.load() if previous_ctx.state_file.exists() else {}
            if not previous:
                pointer = previous_ctx.previous_pointer()
                previous = json_load(Path(pointer["state_file"]), {}) if pointer.get("state_file") else {}
            change_mode = _classify_goal_change(prompt, previous)
            config, project = _project_identity(ns.project_file, ns.workspace)
            round_id = f"round-{sha256_text(session_key := (ns.session + prompt + utc_now()))[:16]}"
            ctx = StateContext.build(runtime=ns.runtime, project=project, workspace=ns.workspace, session=ns.session, round_id=round_id)
            quality = read_quality_profile(config, ns.project_file, ns.workspace)
            state = start_round(
                ctx,
                message=prompt,
                change_mode=change_mode,
                execution_mode=str(config.get("execution_mode") or "warn"),
                project_config=config,
                quality_profile=quality,
                intents_supplied=split_intents(prompt),
            )
            if isinstance(adapter, dict) and adapter.get("degraded_prior") is True:
                state["health"] = "degraded"
                ctx.save(state)
                ctx.append_event({"event_type": "adapter_recovered", "status": "degraded", "degraded_prior": True, "adapter_version": adapter.get("adapter_version")})
            print(json.dumps({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "additionalContext": f"Supervisor v3 goal {state['goal']['goal_id']} v{state['goal']['version']} started in {state['execution_mode']} mode."}}, ensure_ascii=False))
            return EXIT_COMPLETE
        ctx = _context(ns, require_existing=args.event != "SessionStart")
        if args.event == "SessionStart":
            print(json.dumps({"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": "Supervisor v3 ready; goal will be classified on the next prompt."}}))
            return EXIT_COMPLETE
        state = ctx.load()
        if isinstance(adapter, dict) and adapter.get("degraded_prior") is True:
            state["health"] = "degraded"
            ctx.save(state)
            ctx.append_event({"event_type": "adapter_recovered", "status": "degraded", "degraded_prior": True, "adapter_version": adapter.get("adapter_version")})
        tool_name = str(payload.get("tool_name") or payload.get("tool") or "unknown")
        tool_input = payload.get("tool_input") if isinstance(payload.get("tool_input"), dict) else {}
        capability_name = str(
            tool_input.get("skill")
            or tool_input.get("capability")
            or tool_input.get("agent")
            or tool_input.get("subagent_type")
            or tool_name
        )
        invocation_id = str(payload.get("tool_use_id") or payload.get("invocation_id") or stable_id("invocation"))
        if args.event == "PreToolUse":
            breaker = state.get("capability_breakers", {}).get(capability_name, {})
            if isinstance(breaker, dict) and breaker.get("open") is True:
                fallback_id = str(breaker.get("fallback_id") or "").strip()
                ctx.append_event({
                    "event_type": "invocation_fallback_required",
                    "invocation_id": invocation_id,
                    "capability": capability_name,
                    "fallback_id": fallback_id or None,
                    "status": "routed" if fallback_id else "degraded",
                    "actor": "claude",
                    "summary": "open circuit prevented the original capability from counting as used",
                })
                output: dict[str, Any] = {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "additionalContext": f"Supervisor circuit open for {capability_name}; use fallback {fallback_id or 'manual verified fallback'}. The original capability will not count as success.",
                    }
                }
                if state.get("execution_mode") == "enforce":
                    output["hookSpecificOutput"].update({
                        "permissionDecision": "deny",
                        "permissionDecisionReason": f"Capability circuit open; route to {fallback_id or 'documented manual fallback'}.",
                    })
                print(json.dumps(output, ensure_ascii=False))
                return EXIT_COMPLETE
            ctx.append_event(invocation_event(invocation_id=invocation_id, capability=capability_name, stage="attempt", result=None, actor="claude", details={"summary": f"{tool_name} attempt"}))
            print("{}")
            return EXIT_COMPLETE
        if args.event in {"PostToolUse", "PostToolUseFailure"}:
            responses = [payload.get("tool_response"), payload.get("tool_result")]
            failed = (
                args.event == "PostToolUseFailure"
                or bool(payload.get("is_error"))
                or bool(payload.get("isError"))
                or payload.get("success") is False
                or any(
                    isinstance(response, dict)
                    and (bool(response.get("isError")) or bool(response.get("is_error")) or response.get("success") is False)
                    for response in responses
                )
            )
            result_name = "failed" if failed else "success"
            ctx.update(lambda state_value: _record_breaker_result(state_value, capability_name, result_name))
            ctx.append_event(invocation_event(invocation_id=invocation_id, capability=capability_name, stage="result", result=result_name, actor="claude", details={"summary": f"{tool_name} completed"}))
            print("{}")
            return EXIT_COMPLETE
        if args.event == "SubagentStop":
            # SubagentStop shares the parent Claude session in many hosts. Validate
            # a read-only snapshot and record it; never finalize/mutate the parent
            # terminal state from a child lifecycle event.
            report = validate_state(state, ctx.events())
            ctx.append_event(
                {
                    "event_type": "subagent_stop_review",
                    "status": "valid" if report["valid"] else "incomplete",
                    "actor": str(payload.get("agent_id") or "subagent"),
                    "summary": f"read-only subagent stop review; errors={len(report['errors'])}",
                }
            )
            print("{}")
            return EXIT_COMPLETE
        if args.event == "Stop":
            finalized, _ = finalize_round(ctx)
            if finalized["host_gate"]["should_block"]:
                reason = "; ".join(finalized["validation"]["errors"][:5])
                print(json.dumps({"decision": "block", "reason": f"Supervisor v3 incomplete: {reason}"}, ensure_ascii=False))
            else:
                print("{}")
            return EXIT_COMPLETE  # hooks fail open; persisted state remains authoritative
        ctx.append_event({"event_type": f"hook_{args.event}", "status": "observed", "summary": "hook lifecycle event"})
        print("{}")
        return EXIT_COMPLETE
    except Exception as exc:
        # Never put raw payload or exception args on stdout. The thin adapter may spool
        # a separately redacted degraded event and report it on recovery.
        print(json.dumps({"agent_supervisor": {"health": "degraded", "error": type(exc).__name__, "fail_open": True}}))
        return EXIT_COMPLETE


def _add_namespace(parser: argparse.ArgumentParser, *, round_required: bool = False) -> None:
    parser.add_argument("--runtime", choices=("claude", "codex"), required=True)
    parser.add_argument("--workspace", default=os.getcwd())
    parser.add_argument("--session")
    parser.add_argument("--round", required=round_required)
    parser.add_argument("--project-file")
    parser.add_argument("--state-root", help=argparse.SUPPRESS)


def build_parser() -> Parser:
    parser = Parser(prog="agent-supervisor", description="Agent Supervisor v3 shared core")
    parser.add_argument("--version", action="version", version="3.0.0")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("start")
    _add_namespace(p)
    p.add_argument("--message", required=True)
    p.add_argument("--change-mode", choices=("continue", "extend", "replace"), required=True)
    p.add_argument("--execution-mode", choices=("observe", "warn", "enforce"), default="warn")
    p.add_argument("--goal-json")
    p.add_argument("--criteria-json")
    p.add_argument("--intents-json")
    p.add_argument("--shadow", action="store_true")
    p.set_defaults(func=command_start)
    p = sub.add_parser("event")
    _add_namespace(p)
    p.add_argument("--event-type", required=True)
    p.add_argument("--phase")
    p.add_argument("--status")
    p.add_argument("--capability")
    p.add_argument("--command-category")
    p.add_argument("--summary")
    p.add_argument("--actor")
    p.add_argument("--invocation-id")
    p.add_argument("--result")
    p.add_argument("--data-json")
    p.set_defaults(func=command_event)
    p = sub.add_parser("validate")
    _add_namespace(p)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=command_validate)
    p = sub.add_parser("finalize")
    _add_namespace(p)
    p.add_argument("--stop-attempt", type=int)
    p.add_argument("--blocked", action="store_true")
    p.set_defaults(func=command_finalize)
    p = sub.add_parser("query")
    _add_namespace(p)
    p.add_argument("--format", choices=("json", "handoff", "events"), default="json")
    p.add_argument("--output")
    p.set_defaults(func=command_query)
    p = sub.add_parser("migrate")
    _add_namespace(p)
    p.add_argument("--source", required=True)
    p.set_defaults(func=command_migrate)
    p = sub.add_parser("discover")
    p.add_argument("--runtime", required=True)
    p.add_argument("--roots", nargs="*")
    p.add_argument("--baseline")
    p.add_argument("--write-baseline")
    p.add_argument("--output")
    p.set_defaults(func=command_discover)
    p = sub.add_parser("route")
    p.add_argument("--message")
    p.add_argument("--intents-file")
    p.add_argument("--inventory", required=True)
    p.add_argument("--phase-budget", type=int, default=3)
    p.add_argument("--zero-skill-reviewed", action="store_true")
    p.add_argument("--output")
    p.set_defaults(func=command_route)
    p = sub.add_parser("selftest")
    p.set_defaults(func=command_selftest)
    p = sub.add_parser("hook")
    p.add_argument("--runtime", default="claude")
    p.add_argument("--event", required=True)
    p.set_defaults(func=command_hook)
    return parser


def main(argv: list[str] | None = None) -> int:
    # Windows console/code-page defaults are not stable across PowerShell, Node,
    # Claude hooks, and paths containing CJK characters. The hook protocol is UTF-8.
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="replace")
    try:
        args = build_parser().parse_args(argv)
        return int(args.func(args))
    except (InvalidState, ValueError, OSError, json.JSONDecodeError) as exc:
        _emit({"ok": False, "error": type(exc).__name__, "message": str(exc)})
        return EXIT_INVALID


if __name__ == "__main__":
    raise SystemExit(main())
