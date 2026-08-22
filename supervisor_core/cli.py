from __future__ import annotations

import argparse
import copy
from datetime import timedelta
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

from .constants import EXIT_COMPLETE, EXIT_DEGRADED, EXIT_INCOMPLETE, EXIT_INVALID
from .attestation import sign_record
from .contracts import invocation_event
from .discovery import baseline_report, parse_roots, scan_skills, write_baseline
from .finalize import finalize_round
from .lifecycle import (
    _reject_reparse_path,
    capture_validated_supervisor_source_snapshot,
    read_project_config,
    read_quality_profile,
    start_round,
)
from .routing import route_intents, split_intents
from .rollout import (
    RolloutReplayIntegrityError,
    active_version_snapshot,
    apply_observation,
    promote,
    reset_rollback_cycle,
    rollback_active_version,
)
from .storage import StateContext, atomic_write_bytes, atomic_write_json, default_round, default_session, prune_old_state
from .util import canonical_sha256, json_load, parse_time, redact, redact_for_persistence, sha256_bytes, sha256_file, sha256_text, stable_id, utc_now
from .validation import _project_policy_scope, validate_state
from .workspace import (
    canonical_workspace_path,
    path_matches_lease,
    resolve_handoff_output_path,
    validated_supervisor_source_snapshot_hash,
)


class InvalidState(ValueError):
    pass


class SupervisorSourceSnapshotMismatch(RuntimeError):
    pass


_DEFAULT_GATE_TIMEOUT_SECONDS = 1200
_MIN_GATE_TIMEOUT_SECONDS = 1
_MAX_GATE_TIMEOUT_SECONDS = 1800
_DEFAULT_ROLLBACK_CLAIM_LEASE_SECONDS = 30
_MIN_ROLLBACK_CLAIM_LEASE_SECONDS = 1
_MAX_ROLLBACK_CLAIM_LEASE_SECONDS = 3600
_MAX_GATE_CAPTURE_BYTES = 64 * 1024
_GATE_CAPTURE_CHUNK_BYTES = 16 * 1024


def _run_gate_subprocess_bounded(
    command: list[str],
    *,
    cwd: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    """Drain both pipes concurrently while retaining only a bounded byte tail."""
    process = subprocess.Popen(
        command,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        bufsize=0,
    )
    if process.stdout is None or process.stderr is None:
        process.kill()
        process.wait()
        raise OSError("gate subprocess pipes unavailable")

    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    totals = {"stdout": 0, "stderr": 0}

    def drain(name: str, stream: Any) -> None:
        try:
            while True:
                chunk = stream.read(_GATE_CAPTURE_CHUNK_BYTES)
                if not chunk:
                    break
                totals[name] += len(chunk)
                target = buffers[name]
                if len(chunk) >= _MAX_GATE_CAPTURE_BYTES:
                    target[:] = chunk[-_MAX_GATE_CAPTURE_BYTES:]
                else:
                    target.extend(chunk)
                    excess = len(target) - _MAX_GATE_CAPTURE_BYTES
                    if excess > 0:
                        del target[:excess]
        except (OSError, ValueError):
            return

    readers = [
        threading.Thread(target=drain, args=("stdout", process.stdout), daemon=True),
        threading.Thread(target=drain, args=("stderr", process.stderr), daemon=True),
    ]
    for reader in readers:
        reader.start()

    timed_out = False
    try:
        return_code = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        return_code = 124
    finally:
        for reader in readers:
            try:
                reader.join(timeout=2)
            except (RuntimeError, ValueError):
                pass
        for stream in (process.stdout, process.stderr):
            try:
                stream.close()
            except (OSError, RuntimeError, ValueError):
                pass
        for reader in readers:
            try:
                reader.join(timeout=1)
            except (RuntimeError, ValueError):
                pass

    def decoded_tail(name: str) -> str:
        data = bytes(buffers[name])
        if totals[name] > len(data):
            boundary = data.find(b"\n")
            data = data[boundary + 1 :] if boundary >= 0 else b""
        return data.decode("utf-8", errors="replace")

    return {
        "exit_code": 124 if timed_out else int(return_code),
        "timed_out": timed_out,
        "stdout": decoded_tail("stdout"),
        "stderr": decoded_tail("stderr"),
        "stdout_truncated": totals["stdout"] > len(buffers["stdout"]),
        "stderr_truncated": totals["stderr"] > len(buffers["stderr"]),
    }


def _gate_timeout_seconds(value: Any) -> int:
    if isinstance(value, bool):
        return _DEFAULT_GATE_TIMEOUT_SECONDS
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        return _DEFAULT_GATE_TIMEOUT_SECONDS
    return max(_MIN_GATE_TIMEOUT_SECONDS, min(parsed, _MAX_GATE_TIMEOUT_SECONDS))


def _rollback_claim_lease_seconds(value: Any = None) -> int:
    raw = (
        os.environ.get("AGENT_SUPERVISOR_ROLLBACK_CLAIM_LEASE_SECONDS", str(_DEFAULT_ROLLBACK_CLAIM_LEASE_SECONDS))
        if value is None else value
    )
    if isinstance(raw, bool):
        return _DEFAULT_ROLLBACK_CLAIM_LEASE_SECONDS
    try:
        parsed = int(raw)
    except (TypeError, ValueError, OverflowError):
        return _DEFAULT_ROLLBACK_CLAIM_LEASE_SECONDS
    return max(_MIN_ROLLBACK_CLAIM_LEASE_SECONDS, min(parsed, _MAX_ROLLBACK_CLAIM_LEASE_SECONDS))


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


def _reject_sensitive_contract_input(value: Any, label: str) -> None:
    if redact(value) != value:
        raise InvalidState(f"{label} contains sensitive data that cannot be persisted in integrity-bound state")


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


def _initialize_cli_source_snapshot(ctx: StateContext, state: dict[str, Any], *, shadow: bool) -> dict[str, Any]:
    snapshot = state.get("supervisor_source_snapshot")
    if not isinstance(snapshot, dict):
        snapshot = capture_validated_supervisor_source_snapshot()
    if shadow:
        state["supervisor_source_snapshot"] = copy.deepcopy(snapshot)
        if validated_supervisor_source_snapshot_hash(snapshot) is None:
            state["health"] = "degraded"
        return state

    def persist(current: dict[str, Any]) -> None:
        if not isinstance(current.get("supervisor_source_snapshot"), dict):
            current["supervisor_source_snapshot"] = copy.deepcopy(snapshot)
        if validated_supervisor_source_snapshot_hash(current.get("supervisor_source_snapshot")) is None:
            current["health"] = "degraded"

    return ctx.update(persist)


def _verify_current_source_snapshot(ctx: StateContext, state: dict[str, Any] | None = None) -> str:
    state = state if isinstance(state, dict) else ctx.load()
    expected = state.get("supervisor_source_snapshot")
    current = capture_validated_supervisor_source_snapshot()
    expected_hash = validated_supervisor_source_snapshot_hash(expected)
    observed_hash = validated_supervisor_source_snapshot_hash(current)
    if expected_hash and observed_hash and expected_hash == observed_hash:
        return observed_hash

    reason = (
        "missing-or-invalid-start-snapshot" if expected_hash is None
        else "current-source-snapshot-degraded" if observed_hash is None
        else "source-changed-after-start"
    )

    def degrade(current_state: dict[str, Any]) -> None:
        current_state["health"] = "degraded"
        current_state["source_snapshot_integrity"] = {
            "status": "mismatch",
            "reason": reason,
            "expected_snapshot_sha256": expected_hash,
            "observed_snapshot_sha256": observed_hash,
            "checked_at": utc_now(),
        }
        current_state["updated_at"] = utc_now()

    ctx.update(degrade)
    ctx.append_event({
        "event_type": "supervisor_source_snapshot_mismatch",
        "status": "degraded",
        "reason": reason,
        "expected_snapshot_sha256": expected_hash,
        "observed_snapshot_sha256": observed_hash,
    })
    raise SupervisorSourceSnapshotMismatch(reason)


def command_start(args: argparse.Namespace) -> int:
    ctx = _context(args)
    config, _ = _project_identity(args.project_file, ctx.workspace)
    quality = read_quality_profile(config, args.project_file, ctx.workspace)
    supplied = _json_arg(args.goal_json, {})
    if not isinstance(supplied, dict):
        raise InvalidState("--goal-json must be an object")
    if args.criteria_json:
        supplied["acceptance_criteria"] = _json_arg(args.criteria_json, [])
    intents = _json_arg(args.intents_json, None)
    _reject_sensitive_contract_input(
        {"message": args.message, "goal": supplied, "intents": intents},
        "start request",
    )
    state = start_round(
        ctx,
        message=args.message,
        change_mode=args.change_mode,
        execution_mode=args.execution_mode,
        project_config=config,
        quality_profile=quality,
        goal_supplied=supplied,
        intents_supplied=intents,
        trusted_authorizations=None,
        shadow=args.shadow,
    )
    state = _initialize_cli_source_snapshot(ctx, state, shadow=bool(args.shadow))
    _emit({
        "ok": True,
        "shadow": bool(args.shadow),
        "persisted": not bool(args.shadow),
        "state_file": None if args.shadow else str(ctx.state_file),
        "goal": state["goal"],
        "intents": state.get("intents", []),
        "execution_mode": state.get("execution_mode"),
        "namespace": {"runtime": ctx.runtime, "project": ctx.project, "workspace": ctx.workspace, "session": ctx.session, "round": ctx.round},
    })
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
    try:
        return redact_for_persistence(record)
    except ValueError as exc:
        raise InvalidState(f"{event_type} contains sensitive data in an integrity-bound field") from exc


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
            rollback = rollback_active_version(expected_active=active_version_snapshot())
            state["rollout"]["rollback"].update(rollback)
            if not rollback.get("performed"):
                state["health"] = "degraded"
        return str(record.get("observation_id"))
    if event_type == "rollout_promote":
        record = _record_from_payload(payload, event_type)
        if record.get("contract") != "RolloutPromotion/v3":
            raise InvalidState("rollout promotion contract invalid")
        requested_mode = str(record.get("requested_mode") or "").strip().casefold()
        promote(state.setdefault("rollout", {}), requested_mode)
        state["execution_mode"] = str(state["rollout"]["active_mode"])
        return str(record.get("promotion_id") or requested_mode)
    return None


def _registered_gate(state: dict[str, Any], gate_id: str) -> dict[str, Any] | None:
    from .validation import _registered_gate_definitions

    return _registered_gate_definitions(state.get("quality_profile", {})).get(gate_id)


def _global_gate_ids(state: dict[str, Any]) -> list[str]:
    profile = state.get("quality_profile") if isinstance(state.get("quality_profile"), dict) else {}
    raw = profile.get("global_gates")
    if not isinstance(raw, list):
        return []
    return [value.strip() for value in raw if isinstance(value, str) and value.strip()]


def _invocation_state_binding(state: dict[str, Any]) -> dict[str, Any]:
    goal = state.get("goal", {}) if isinstance(state.get("goal"), dict) else {}
    manifest = state.get("request_manifest") if isinstance(state.get("request_manifest"), dict) else {}
    return {
        "runtime": state.get("runtime"),
        "project": state.get("project"),
        "workspace": str(Path(str(state.get("workspace") or "")).resolve()),
        "session": state.get("session"),
        "round": state.get("round"),
        "goal_id": goal.get("goal_id"),
        "goal_version": goal.get("version"),
        "request_manifest_sha256": canonical_sha256(manifest),
    }


def _windows_executable_candidates(path: Path, pathext: str) -> list[Path]:
    extensions: list[str] = []
    for raw in (pathext or ".COM;.EXE;.BAT;.CMD").split(";"):
        extension = raw.strip()
        if not extension:
            continue
        if not extension.startswith("."):
            extension = f".{extension}"
        if extension.casefold() not in {item.casefold() for item in extensions}:
            extensions.append(extension)
    path_text = str(path)
    if any(path_text.casefold().endswith(extension.casefold()) for extension in extensions):
        return [path]
    return [Path(f"{path}{extension}") for extension in extensions]


def _resolve_gate_command(
    command: list[str], *, cwd: str, environ: dict[str, str] | None = None
) -> tuple[list[str], str, str]:
    """Resolve argv[0] without Windows' implicit current-directory search."""
    if not command or not str(command[0]).strip():
        raise FileNotFoundError("registered gate command is empty")
    environment = os.environ if environ is None else environ
    token = str(command[0])
    lookup_token = token[1:-1] if len(token) >= 2 and token[0] == token[-1] == '"' else token
    explicit = os.path.isabs(lookup_token) or bool(os.path.dirname(lookup_token))
    if os.name == "nt" and re.match(r"^[A-Za-z]:", lookup_token):
        explicit = True

    bases: list[Path] = []
    if explicit:
        base = Path(os.path.expandvars(os.path.expanduser(lookup_token)))
        if not base.is_absolute():
            base = Path(cwd) / base
        bases.append(base)
    else:
        for raw_entry in str(environment.get("PATH") or "").split(os.pathsep):
            entry = raw_entry.strip().strip('"')
            if not entry:
                continue
            expanded = os.path.expandvars(os.path.expanduser(entry))
            if not os.path.isabs(expanded):
                continue
            bases.append(Path(expanded) / lookup_token)

    candidates: list[Path] = []
    for base in bases:
        if os.name == "nt":
            candidates.extend(_windows_executable_candidates(base, str(environment.get("PATHEXT") or "")))
        else:
            candidates.append(base)
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if resolved.is_file() and (os.name == "nt" or os.access(resolved, os.X_OK)):
            executable_hash = sha256_file(resolved)
            return [str(resolved), *command[1:]], str(resolved), executable_hash
    raise FileNotFoundError(f"registered gate executable was not found in trusted PATH entries: {token}")


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
            if status == "covered":
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
        changes = state.get("changes") if isinstance(state.get("changes"), dict) else {}
        artifact = {
            "builtin": builtin,
            "round": state.get("round"),
            "no_file_change": not bool(changes.get("files")),
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
    source_snapshot_hash = _verify_current_source_snapshot(ctx, state)
    gate = _registered_gate(state, gate_id)
    if not gate:
        raise InvalidState(f"gate is not registered in QualityProfile: {gate_id}")
    global_gates_at_start = _global_gate_ids(state)
    gate_active_identity = active_version_snapshot() if gate_id in global_gates_at_start else None
    command = list(gate.get("command") or [])
    if not command and not gate.get("builtin"):
        raise InvalidState(f"registered gate has no executable command or builtin: {gate_id}")
    precondition_command = list(gate["precondition"]) if gate.get("precondition") else None
    execution_id = stable_id("execution")
    evidence_id = str(request.get("evidence_id") or stable_id("evidence"))
    started_at = utc_now()
    resolved_executable: str | None = None
    resolved_executable_sha256: str | None = None
    precondition: dict[str, Any] | None = None
    command_executed = True
    infrastructure_degraded = False
    gate_timeout = _gate_timeout_seconds(request.get("timeout_seconds"))

    def run_external_step(step_command: list[str], category: str) -> dict[str, Any]:
        step_started = utc_now()
        step_resolved: str | None = None
        step_resolved_sha256: str | None = None
        failure_kind: str | None = None
        try:
            resolved_command, step_resolved, step_resolved_sha256 = _resolve_gate_command(
                step_command, cwd=str(state.get("workspace") or ctx.workspace)
            )
            completed = _run_gate_subprocess_bounded(
                resolved_command,
                cwd=str(state.get("workspace") or ctx.workspace),
                timeout_seconds=gate_timeout,
            )
            step_exit = int(completed["exit_code"])
            raw_output = (
                (completed["stdout"] or "")
                + ("\n" if completed["stdout"] and completed["stderr"] else "")
                + (completed["stderr"] or "")
            )
            if completed["stdout_truncated"] or completed["stderr_truncated"]:
                raw_output = "[bounded gate output truncated]\n" + raw_output
            failure_kind = "timeout" if completed["timed_out"] else None
        except OSError as exc:
            step_exit = 127
            raw_output = type(exc).__name__
            failure_kind = "unavailable"
        clean_step_output = str(redact(raw_output))
        step_summary = clean_step_output[-4000:].strip() or f"{category} produced no output"
        return {
            "command": {"category": category, "args": list(step_command)},
            "resolved_executable": step_resolved,
            "resolved_executable_sha256": step_resolved_sha256,
            "started_at": step_started,
            "finished_at": utc_now(),
            "exit_code": step_exit,
            "output_summary": step_summary,
            "output_sha256": sha256_text(clean_step_output),
            "failure_kind": failure_kind,
            "raw_output": clean_step_output,
        }

    if gate.get("builtin"):
        exit_code, artifact = _evaluate_builtin_gate(
            state, ctx.events(), str(gate["builtin"]), finalize_internal=finalize_internal
        )
        combined = json.dumps(artifact, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    else:
        if precondition_command:
            precondition = run_external_step(precondition_command, "quality-gate-precondition")
            infrastructure_degraded = precondition["failure_kind"] is not None
        if precondition is not None and precondition["exit_code"] != 0:
            command_executed = False
            exit_code = int(precondition["exit_code"])
            combined = f"precondition failed\n{precondition['raw_output']}"
        else:
            main_step = run_external_step(command, "quality-gate")
            resolved_executable = main_step["resolved_executable"]
            resolved_executable_sha256 = main_step["resolved_executable_sha256"]
            exit_code = int(main_step["exit_code"])
            combined = str(main_step["raw_output"])
            infrastructure_degraded = infrastructure_degraded or main_step["failure_kind"] is not None
    if precondition is not None:
        precondition.pop("raw_output", None)
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
        "precondition": precondition,
        "command_executed": command_executed,
        "resolved_executable": resolved_executable,
        "resolved_executable_sha256": resolved_executable_sha256,
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
        "source_snapshot_hash": source_snapshot_hash,
        "collector": collector,
        "collector_responsibility_group": collector_group,
        "status": "degraded" if infrastructure_degraded else ("success" if exit_code == 0 else "failed"),
    }
    # StateContext.transact supplies this field when absent. Bind it before
    # signing so the durable event remains byte-semantically attestable.
    execution["transaction_id"] = stable_id("transaction")
    execution["attestation"] = sign_record(execution)
    evidence = {
        "contract": "EvidenceRecord/v3",
        "evidence_id": evidence_id,
        "execution_id": execution_id,
        "criterion_id": criterion_id,
        "goal_id": execution["goal_id"],
        "goal_version": execution["goal_version"],
        "command": {"category": "quality-gate", "args": command},
        "precondition": precondition,
        "command_executed": command_executed,
        "resolved_executable": resolved_executable,
        "resolved_executable_sha256": resolved_executable_sha256,
        "cwd": str(state.get("workspace") or ctx.workspace),
        "collected_at": execution["collected_at"],
        "exit_code": exit_code,
        "output_summary": summary,
        "artifact_hash": sha256_text(clean_output),
        "output_sha256": sha256_text(clean_output),
        "base": execution["base"],
        "head": execution["head"],
        "diff_hash": execution["diff_hash"],
        "source_snapshot_hash": source_snapshot_hash,
        "collector": collector,
        "collector_responsibility_group": collector_group,
        "gate_id": gate_id,
        "relevant": True,
    }

    def persist(state_value: dict[str, Any]) -> None:
        if exit_code == 0:
            rows = state_value.setdefault("evidence", [])
            _upsert_record(rows, evidence, "evidence_id")
        if infrastructure_degraded:
            state_value["health"] = "degraded"
        state_value["updated_at"] = utc_now()

    # Evidence and its signed GateExecution audit record are one round
    # transaction. If the ledger append fails, transact never commits the
    # in-memory evidence mutation to authoritative state.
    ctx.transact(persist, execution)
    try:
        latest = ctx.load()
        global_gates = _global_gate_ids(latest)
        kind: str | None = None
        values: dict[str, Any] = {}
        if gate_id == "review.project-supervisor":
            kind, values = "fixture_replay", {"passed": exit_code == 0}
        elif gate_id == "config.historical-replay":
            kind, values = "historical_replay", {"passed": exit_code == 0}
        elif gate_id in global_gates and not infrastructure_degraded:
            kind, values = "global_gate", {
                "result": "success" if exit_code == 0 else "failed",
                "active_version": copy.deepcopy(gate_active_identity),
            }
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

            claim_started_at = utc_now()
            lease_seconds = _rollback_claim_lease_seconds()
            claim_expires_at = (
                parse_time(claim_started_at) + timedelta(seconds=lease_seconds)
            ).isoformat(timespec="milliseconds").replace("+00:00", "Z")
            rollback_claim_id = stable_id("rollback-claim", f"{observation['observation_id']}:{claim_started_at}")
            claimed: dict[str, Any] = {"value": False, "expected_active": None, "recovery": False}

            def update_rollout(current: dict[str, Any]) -> dict[str, Any]:
                target = copy.deepcopy(current or latest.get("rollout", {}))
                apply_observation(target, observation)
                row = target.setdefault("rollback", {})
                claim_status = str(row.get("claim_status") or "")
                expired = False
                if claim_status == "in_progress":
                    try:
                        expired = parse_time(str(row.get("claim_expires_at") or "")) <= parse_time(claim_started_at)
                    except ValueError:
                        expired = True
                legacy_incomplete = row.get("attempted") is True and row.get("performed") is not True and not claim_status
                recovery = claim_status == "retriable" or (claim_status == "in_progress" and expired) or legacy_incomplete
                first_claim = row.get("attempted") is not True
                bound_expected = target.get("metrics", {}).get("global_gate_active_identity")
                original_expected = row.get("expected_active") if recovery else bound_expected
                concrete_expected = (
                    isinstance(original_expected, dict)
                    and bool(str(original_expected.get("version") or "").strip())
                    and bool(str(original_expected.get("path") or "").strip())
                )
                if (
                    row.get("required") is True
                    and row.get("performed") is not True
                    and (first_claim or recovery)
                    and concrete_expected
                ):
                    row.update({
                        "attempted": True,
                        "performed": False,
                        "claim_id": rollback_claim_id,
                        "claim_status": "in_progress",
                        "expected_active": copy.deepcopy(original_expected),
                        "attempt_count": int(row.get("attempt_count", 0)) + 1,
                        "recovery_count": int(row.get("recovery_count", 0)) + (1 if recovery else 0),
                        "attempted_at": claim_started_at,
                        "claim_expires_at": claim_expires_at,
                    })
                    claimed["value"] = True
                    claimed["expected_active"] = copy.deepcopy(original_expected)
                    claimed["recovery"] = recovery
                return target

            project_rollout = ctx.update_project_rollout(update_rollout)
            rollback_result: dict[str, Any] | None = None
            if claimed["value"]:
                try:
                    rollback_result = rollback_active_version(expected_active=claimed["expected_active"])
                except Exception as exc:  # Claim is made retriable below; pointer CAS keeps replay safe.
                    rollback_result = {
                        "performed": False,
                        "reason": f"{type(exc).__name__}-before-pointer-confirmation",
                        "target": None,
                    }

                def record_rollback(current: dict[str, Any]) -> dict[str, Any]:
                    row = current.setdefault("rollback", {})
                    if row.get("claim_id") != rollback_claim_id:
                        return current
                    performed = rollback_result.get("performed") is True
                    row.update({
                        "performed": performed,
                        "claim_status": "completed" if performed else "retriable",
                        "target": rollback_result.get("target"),
                        "target_active": copy.deepcopy(rollback_result.get("target_active")),
                        "reason": rollback_result.get("reason"),
                        "completed_at": utc_now(),
                    })
                    if rollback_result.get("reason") == "active-version-cas-mismatch":
                        reset_rollback_cycle(current, "claim-active-version-cas-mismatch")
                        return current
                    if not performed:
                        row["claim_expires_at"] = utc_now()
                    return current

                project_rollout = ctx.update_project_rollout(record_rollback)
            ctx.update(lambda state_value: state_value.update({"rollout": copy.deepcopy(project_rollout), "updated_at": utc_now()}))
            ctx.append_event(observation)
            if rollback_result is not None:
                ctx.append_event({
                    "event_type": "rollout_auto_rollback",
                    "status": "performed" if rollback_result.get("performed") else "retriable",
                    "target": rollback_result.get("target"),
                    "reason": rollback_result.get("reason"),
                    "claim_id": rollback_claim_id,
                    "recovery": claimed.get("recovery") is True,
                })
                if rollback_result.get("performed") is not True:
                    ctx.update(lambda state_value: state_value.update({"health": "degraded", "updated_at": utc_now()}))
    except Exception as exc:
        ctx.update(lambda state_value: state_value.update({"health": "degraded", "updated_at": utc_now()}))
        ctx.append_event({"event_type": "rollout_gate_degraded", "status": "degraded", "summary": type(exc).__name__})
    if infrastructure_degraded:
        return evidence, execution, EXIT_DEGRADED
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
        try:
            evidence, execution, code = _run_registered_gate(ctx, payload)
        except SupervisorSourceSnapshotMismatch:
            integrity = ctx.load().get("source_snapshot_integrity", {})
            _emit({
                "ok": False,
                "health": "degraded",
                "error": "SupervisorSourceSnapshotMismatch",
                "expected_snapshot_sha256": integrity.get("expected_snapshot_sha256"),
                "observed_snapshot_sha256": integrity.get("observed_snapshot_sha256"),
            })
            return EXIT_DEGRADED
        _emit({
            "ok": code == EXIT_COMPLETE,
            "evidence_id": evidence["evidence_id"],
            "execution_id": execution["execution_id"],
            "gate_id": evidence["gate_id"],
            "exit_code": evidence["exit_code"],
            "source_snapshot_hash": execution["source_snapshot_hash"],
            "state_file": str(ctx.state_file),
        })
        return code
    if event_type == "rollout_promote":
        record = _record_from_payload(payload, event_type)
        if record.get("contract") != "RolloutPromotion/v3":
            raise InvalidState("rollout promotion contract invalid")
        requested_mode = str(record.get("requested_mode") or "").strip().casefold()

        def promote_project(current: dict[str, Any]) -> dict[str, Any]:
            if not current:
                raise InvalidState("project rollout state missing")
            promote(current, requested_mode)
            return current

        try:
            project_rollout = ctx.update_project_rollout(promote_project)
        except RolloutReplayIntegrityError:
            degraded = ctx.update(lambda state: state.update({
                "health": "degraded",
                "updated_at": utc_now(),
            }))
            recorded = ctx.append_event({
                "event_type": "rollout_replay_degraded",
                "status": "degraded",
                "reason": "attestation-unavailable-or-invalid",
                "requested_mode": requested_mode,
            })
            _emit({
                "ok": False,
                "health": degraded.get("health"),
                "error": "RolloutReplayIntegrityError",
                "event": recorded,
                "state_file": str(ctx.state_file),
            })
            return EXIT_DEGRADED
        ctx.update(lambda state: state.update({
            "rollout": copy.deepcopy(project_rollout),
            "execution_mode": str(project_rollout["active_mode"]),
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
    invocation_state = ctx.load()
    invocation_assurance = "codex-explicit-audit" if ctx.runtime == "codex" else "declared-runtime"
    invocation_details = {
        "phase": payload.get("phase"),
        "summary": payload.get("summary"),
        **_invocation_state_binding(invocation_state),
    }
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
                "actor": str(payload.get("actor") or ctx.runtime),
                "summary": "capability circuit is open; original attempt was not counted",
            })
            _emit({"ok": False, "event": recorded, "fallback_required": fallback_id or None, "state_file": str(ctx.state_file)})
            return EXIT_DEGRADED
        payload = invocation_event(
            invocation_id=invocation_id,
            capability=capability,
            stage="attempt",
            result=None,
            actor=str(payload.get("actor") or ctx.runtime),
            details=invocation_details,
            identity_assurance=invocation_assurance,
        )
    elif is_result:
        if not invocation_id or not capability or args.result not in {"success", "failed", "refused", "cancelled", "manual-specialized"}:
            raise InvalidState("invocation result requires id, capability, and a supported result")
        payload = invocation_event(
            invocation_id=invocation_id,
            capability=capability,
            stage="result",
            result=args.result,
            actor=str(payload.get("actor") or ctx.runtime),
            details=invocation_details,
            identity_assurance=invocation_assurance,
        )
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
        _verify_current_source_snapshot(ctx, state)
    except SupervisorSourceSnapshotMismatch:
        integrity = ctx.load().get("source_snapshot_integrity", {})
        _emit({
            "valid": False,
            "health": "degraded",
            "error": "SupervisorSourceSnapshotMismatch",
            "expected_snapshot_sha256": integrity.get("expected_snapshot_sha256"),
            "observed_snapshot_sha256": integrity.get("observed_snapshot_sha256"),
        })
        return EXIT_DEGRADED
    try:
        report = validate_state(state, ctx.events())
    except Exception as exc:
        ctx.update(lambda current: current.update({"health": "degraded", "updated_at": utc_now()}))
        ctx.append_event({"event_type": "validator_degraded", "status": "degraded", "summary": type(exc).__name__})
        _emit({"valid": False, "health": "degraded", "errors": [f"validator exception: {type(exc).__name__}"]})
        return EXIT_DEGRADED
    _emit(report)
    if report["valid"]:
        return EXIT_COMPLETE
    return EXIT_DEGRADED if report["health"] == "degraded" else EXIT_INCOMPLETE


def command_finalize(args: argparse.Namespace) -> int:
    ctx = _context(args, require_existing=True)

    def persist_degraded(event_type: str, exc: Exception, *, terminal: bool) -> tuple[dict[str, Any], bool]:
        event = {
            "event_type": event_type,
            "status": "degraded",
            "summary": type(exc).__name__,
            "exit_code": EXIT_DEGRADED,
        }

        def mutate(current: dict[str, Any]) -> None:
            current["health"] = "degraded"
            current["updated_at"] = utc_now()
            if terminal:
                current_attempts = int(current.get("stop_attempts", 0))
                stop_attempt = (
                    current_attempts + 1
                    if args.stop_attempt is None
                    else max(current_attempts, int(args.stop_attempt))
                )
                current["stop_attempts"] = stop_attempt
                current["terminal_state"] = "incomplete"
                current["validation"] = {
                    "valid": False,
                    "health": "degraded",
                    "errors": [f"finalize exception: {type(exc).__name__}"],
                    "warnings": [],
                }
                normalized_mode = str(current.get("execution_mode") or "").strip().casefold()
                host_mode = normalized_mode if normalized_mode in {"observe", "warn", "enforce"} else "enforce"
                current["host_gate"] = {
                    "should_block": stop_attempt <= 2 and host_mode == "enforce",
                    "stop_cap_reached": stop_attempt > 2,
                    "note": "stop cap only releases the host loop; it never converts unresolved work to complete",
                }
                event.update({"stop_attempt": stop_attempt, "error_count": 1})

        try:
            state, _ = ctx.transact(mutate, event)
            return state, True
        except Exception:
            try:
                state = ctx.load()
            except Exception:
                state = {}
            return state if isinstance(state, dict) else {}, False

    try:
        from .validation import _profile_gates, _registered_gate_definitions

        state = ctx.load()
        _verify_current_source_snapshot(ctx, state)
        profile = state.get("quality_profile", {}) if isinstance(state.get("quality_profile"), dict) else {}
        changes = state.get("changes") if isinstance(state.get("changes"), dict) else {}
        raw_domains = changes.get("domains") if isinstance(changes.get("domains"), list) else []
        domains = {
            str(value) for value in raw_domains
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
                None,
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
        _, persisted = persist_degraded("builtin_finalize_degraded", exc, terminal=False)
        if not persisted:
            _emit({
                "terminal_state": "incomplete",
                "health": "degraded",
                "error": type(exc).__name__,
                "degraded_state_persisted": False,
                "state_file": str(ctx.state_file),
            })
            return EXIT_DEGRADED
    try:
        state, code = finalize_round(ctx, stop_attempt=args.stop_attempt, blocked=args.blocked)
    except Exception as exc:
        state, persisted = persist_degraded("round_finalize_degraded", exc, terminal=True)
        _emit({
            "terminal_state": "incomplete",
            "health": "degraded",
            "error": type(exc).__name__,
            "degraded_state_persisted": persisted,
            "state_file": str(ctx.state_file),
        })
        return EXIT_DEGRADED
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
        path = resolve_handoff_output_path(ctx.workspace, ctx.session, args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path = resolve_handoff_output_path(ctx.workspace, ctx.session, str(path))
        if isinstance(result, str):
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


def _migration_file_identity(path: Path) -> tuple[int, int, int, int, int]:
    try:
        _reject_reparse_path(path, label="migration source entry")
        metadata = path.lstat()
    except (OSError, ValueError) as exc:
        raise InvalidState("migration source entry is unavailable or unsafe") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise InvalidState("migration source entry must be a regular file")
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
    )


def command_migrate(args: argparse.Namespace) -> int:
    ctx = _context(args)
    untrusted_source = Path(args.source).expanduser()
    try:
        _reject_reparse_path(untrusted_source, label="migration source")
    except ValueError as exc:
        raise InvalidState(str(exc)) from exc
    source = untrusted_source.resolve()
    if not source.exists():
        raise InvalidState(f"migration source missing: {source}")
    destination = ctx.root / "legacy" / f"import-{sha256_text(str(source))[:12]}"
    if destination.exists():
        if (destination / "manifest.json").exists():
            raise InvalidState("legacy import already exists; refusing overwrite")
        completed_retries = [
            candidate for candidate in destination.parent.glob(f"{destination.name}-retry-*")
            if candidate.is_dir() and (candidate / "manifest.json").is_file()
        ]
        if completed_retries:
            raise InvalidState("legacy import already exists; refusing overwrite")
        # Preserve an interrupted archive for diagnosis and retry into a fresh
        # sibling.  Never overwrite or delete a partially created import.
        destination = destination.with_name(
            f"{destination.name}-retry-{stable_id('retry').removeprefix('retry-')}"
        )
    destination.mkdir(parents=True)
    if source.is_file():
        files = [source]
    elif source.is_dir():
        files = []
        for path in source.rglob("*"):
            try:
                _reject_reparse_path(path, label="migration source entry")
            except ValueError as exc:
                raise InvalidState(str(exc)) from exc
            if path.is_file():
                files.append(path)
    else:
        raise InvalidState(f"migration source must be a regular file or directory: {source}")
    manifest = []
    for path in files:
        relative = Path(path.name) if source.is_file() else path.relative_to(source)
        target = destination / relative
        before_hash = _migration_file_identity(path)
        try:
            source_hash = sha256_file(path)
        except OSError as exc:
            raise InvalidState("migration source entry could not be hashed") from exc
        after_hash = _migration_file_identity(path)
        if before_hash != after_hash:
            raise InvalidState("migration source entry changed while hashing")
        sensitive_name = any(token in path.name.casefold() for token in (".env", "credential", "secret", "settings.local"))
        imported = False
        redacted_copy = False
        archived_hash = None
        if not sensitive_name and path.suffix.casefold() in {".json", ".jsonl", ".md", ".txt", ".log", ".yaml", ".yml", ".toml"}:
            try:
                before_read = _migration_file_identity(path)
                source_bytes = path.read_bytes()
                after_read = _migration_file_identity(path)
                if before_read != after_read or sha256_bytes(source_bytes) != source_hash:
                    raise InvalidState("migration source entry changed while reading")
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
            except InvalidState:
                raise
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


def _execute_selftest(root: Path, base_temp: Path) -> int:
    tests_root = root / "tests"
    discovered_suites = sorted(
        path.relative_to(tests_root).as_posix()
        for path in tests_root.rglob("test_*.py")
        if path.is_file()
    )
    collect_command = [
        sys.executable, "-m", "pytest", "--collect-only", "-q",
        "--basetemp", str(base_temp / "collect"), str(tests_root),
    ]
    collection_timed_out = False
    try:
        collected = subprocess.run(
            collect_command,
            cwd=root,
            text=True,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=300,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        collection_timed_out = True
        collected = subprocess.CompletedProcess(
            collect_command,
            124,
            stdout=str(redact(exc.stdout or "")),
            stderr="selftest collection timeout",
        )
    def suite_relative_to_test_root(raw: str) -> str | None:
        candidate = Path(raw.strip().replace("\\", "/"))
        if candidate.is_absolute():
            try:
                relative = candidate.resolve().relative_to(tests_root.resolve())
            except (OSError, RuntimeError, ValueError):
                return None
        else:
            parts = candidate.parts
            relative = (
                Path(*parts[1:])
                if parts and parts[0].casefold() == tests_root.name.casefold()
                else candidate
            )
        if relative.name.startswith("test_") and relative.suffix == ".py":
            return relative.as_posix()
        return None

    collected_suites = sorted({
        suite
        for line in collected.stdout.splitlines()
        if "::" in line
        for suite in [suite_relative_to_test_root(line.split("::", 1)[0])]
        if suite is not None
    })
    command = [sys.executable, "-m", "pytest", "-q", "--basetemp", str(base_temp / "run"), str(tests_root)]
    timed_out = False
    try:
        completed = subprocess.run(
            command,
            cwd=root,
            text=True,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=1800,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        completed = subprocess.CompletedProcess(
            command,
            124,
            stdout=str(redact(exc.stdout or "")),
            stderr="selftest timeout",
        )
    all_child_suites_invoked = (
        bool(discovered_suites)
        and collected.returncode == 0
        and set(discovered_suites) == set(collected_suites)
        and completed.returncode in {0, 1}
        and not timed_out
    )
    result = {
        "command": command,
        "collection_command": collect_command,
        "collection_exit_code": collected.returncode,
        "exit_code": completed.returncode,
        "stdout": completed.stdout[-12000:],
        "stderr": completed.stderr[-4000:],
        "discovered_child_suites": discovered_suites,
        "collected_child_suites": collected_suites,
        "invoked_test_root": str(tests_root),
        "all_child_suites_invoked": all_child_suites_invoked,
        "collection_timed_out": collection_timed_out,
        "timed_out": timed_out,
    }
    _emit(result)
    if timed_out or collection_timed_out:
        return EXIT_DEGRADED
    return EXIT_COMPLETE if completed.returncode == 0 and all_child_suites_invoked else EXIT_INCOMPLETE


def command_selftest(args: argparse.Namespace) -> int:
    root = Path(__file__).resolve().parents[1]
    temp_parent = root / ".pytest-tmp"
    temp_parent.mkdir(parents=True, exist_ok=True)
    base_temp = temp_parent / f"selftest-{os.getpid()}-{sha256_text(utc_now())[:8]}"
    base_temp.mkdir(parents=False, exist_ok=False)
    try:
        return _execute_selftest(root, base_temp)
    finally:
        # Collection failures, execution failures, result processing, and
        # output failures all share the same bounded cleanup guarantee.
        shutil.rmtree(base_temp, ignore_errors=True)


def _hook_context(
    payload: dict[str, Any], runtime: str, event: str, state_root: str | None = None
) -> argparse.Namespace:
    workspace = str(payload.get("cwd") or payload.get("workspace") or os.getcwd())
    session = str(payload.get("session_id") or payload.get("session") or default_session(runtime))
    project_file = str(Path(workspace) / ".agent-supervisor" / "project.json")
    if not Path(project_file).exists():
        project_file = None
    return argparse.Namespace(
        runtime=runtime,
        workspace=workspace,
        session=session,
        round=None,
        project_file=project_file,
        state_root=state_root,
    )


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


def _privacy_safe_prompt_contract(
    prompt: str, project_config: dict[str, Any]
) -> tuple[dict[str, Any], list[dict[str, Any]], bool]:
    """Derive a useful hash-bound contract without persisting the raw host prompt."""
    privacy = (
        project_config.get("privacy")
        if isinstance(project_config.get("privacy"), dict)
        else {}
    )
    atomic = split_intents(prompt)
    if privacy.get("persist_raw_prompts") is not False:
        return {}, atomic, False

    request_sha256 = sha256_text(prompt)
    safe_intents: list[dict[str, Any]] = []
    safe_criteria: list[dict[str, Any]] = []
    for index, intent in enumerate(atomic or [{"domain": "general", "text": prompt}], start=1):
        domain = str(intent.get("domain") or "general")
        intent_sha256 = sha256_text(str(intent.get("text") or ""))
        safe_text = f"Host intent {index} ({domain}) sha256:{intent_sha256}"
        safe_intent = {
            key: copy.deepcopy(value)
            for key, value in intent.items()
            if key != "text"
        }
        safe_intent["text"] = safe_text
        safe_intents.append(safe_intent)
        safe_criteria.append(
            {
                "criterion_id": f"criterion-host-{index}-{intent_sha256[:12]}",
                "description": safe_text,
                "domain": domain,
                "required": True,
            }
        )
    return (
        {
            "objective": f"Complete host request sha256:{request_sha256}",
            "acceptance_criteria": safe_criteria,
        },
        safe_intents,
        True,
    )


_WRITE_TOOL_MARKERS = {
    "write", "writefile", "edit", "multiedit", "notebookedit", "createfile", "movefile", "renamefile",
}


def _normalized_tool_marker(tool_name: str) -> str:
    leaf_name = tool_name.casefold().split("__")[-1]
    unversioned = re.sub(r"(?:[@._-]?v?\d+)+$", "", leaf_name)
    return re.sub(r"[^a-z]", "", unversioned)


def _apply_patch_write_paths(tool_input: dict[str, Any]) -> tuple[list[str], str | None]:
    raw_patch = next(
        (
            tool_input.get(key)
            for key in ("command", "patch", "input", "text", "content")
            if tool_input.get(key) is not None
        ),
        None,
    )
    if not isinstance(raw_patch, str) or not raw_patch.strip():
        return [], "apply_patch input is missing"
    lines = raw_patch.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    nonempty = [line for line in lines if line.strip()]
    if not nonempty or nonempty[0].strip() != "*** Begin Patch" or nonempty[-1].strip() != "*** End Patch":
        return [], "apply_patch envelope is malformed"
    header = re.compile(r"^\*\*\* (?:Add|Update|Delete) File:\s*(\S(?:.*\S)?)\s*$")
    move = re.compile(r"^\*\*\* Move to:\s*(\S(?:.*\S)?)\s*$")
    declaration_prefix = re.compile(r"^\*\*\* (?:Add|Update|Delete) File\b|^\*\*\* Move to\b")
    paths: list[str] = []
    for line in lines:
        match = header.fullmatch(line) or move.fullmatch(line)
        if match:
            path = match.group(1).strip()
            if "\x00" in path:
                return [], "apply_patch path contains a null byte"
            raw_path = Path(path)
            if (
                raw_path.is_absolute()
                or bool(raw_path.drive)
                or path.startswith(("/", "\\", "~"))
                or bool(re.match(r"^[A-Za-z]:", path))
            ):
                return [], "apply_patch paths must be workspace-relative"
            if ".." in Path(path.replace("\\", "/")).parts:
                return [], "apply_patch paths cannot contain parent traversal"
            if path not in paths:
                paths.append(path)
        elif declaration_prefix.match(line):
            return [], "apply_patch file declaration is malformed"
    if not paths:
        return [], "apply_patch declares no canonical file writes"
    return paths, None


def _known_write_paths(tool_name: str, tool_input: dict[str, Any]) -> list[str]:
    normalized_tool = _normalized_tool_marker(tool_name)
    if normalized_tool == "applypatch":
        paths, error = _apply_patch_write_paths(tool_input)
        return paths if error is None else []
    if normalized_tool not in _WRITE_TOOL_MARKERS:
        return []
    paths: list[str] = []
    for key in (
        "file_path", "path", "notebook_path", "source", "source_path",
        "target_path", "destination", "destination_path",
    ):
        value = tool_input.get(key)
        if isinstance(value, str) and value.strip():
            paths.append(value)
    for key in ("file_paths", "paths"):
        value = tool_input.get(key)
        if isinstance(value, list):
            paths.extend(item for item in value if isinstance(item, str) and item.strip())
    return paths


def _normalize_classifier_command(raw: Any) -> str | None:
    if isinstance(raw, list):
        if not raw or not all(isinstance(item, str) for item in raw):
            return None
        # This string is only classified and hashed; it is never executed.
        # Use the host shell's quoting convention so argv boundaries are not
        # replaced by JSON punctuation or ambiguous plain joining.
        command = subprocess.list2cmdline(raw) if os.name == "nt" else shlex.join(raw)
    elif isinstance(raw, str):
        command = raw
    else:
        return None
    normalized = command.replace("\r\n", "\n").replace("\r", "\n").strip()
    return normalized or None


def _t3_command_action(tool_input: dict[str, Any]) -> tuple[str, str] | None:
    """Classify obvious T3 commands for local, best-effort audit gating.

    This raw-text regex classifier is deliberately not a host security boundary:
    aliases, wrappers, encoded scripts, or other indirection can bypass it. Host
    permissions and explicit human approval remain the authoritative T3 gate.
    """
    raw = next(
        (tool_input.get(key) for key in ("command", "cmd", "script") if tool_input.get(key) is not None),
        None,
    )
    command = _normalize_classifier_command(raw)
    if command is None:
        return None
    lowered = command.casefold()
    category: str | None = None
    if (
        re.search(r"\bgit\b[^\n]*\bpush\b[^\n]*(?:--force(?:-with-lease|-if-includes)?|(?:^|\s)-f(?:\s|$))", lowered)
        or re.search(r"\bgit\b[^\n]*\bpush\b[^\n]*(?:[\s,\"'])\+[^\s,\"']+", lowered)
    ):
        category = "force-push"
    elif (
        re.search(r"(?:^|[;&|\n]\s*)rm\s+[^\n]*(?:-[a-z]*r[a-z]*\b|--recursive\b)", lowered)
        or re.search(r"\bremove-item\b[^\n]*-recurse\b", lowered)
        or re.search(r"\b(?:rmdir|rd)\b[^\n]*(?:/s|\s-r(?:f)?\b)", lowered)
        or re.search(r"(?:^|[;&|]\s*)del\s+[^\n]*/s\b", lowered)
    ):
        category = "recursive-delete"
    elif (
        re.search(r"\b(?:prisma|drizzle(?:-kit)?|alembic|sequelize|knex|typeorm|diesel)\b[^\n]*\b(?:migrate|migration|push|upgrade|downgrade)\b", lowered)
        or re.search(r"\b(?:npm|pnpm|yarn|bun)\b[^\n]*\b(?:db:)?(?:migrate|migration|apply-policies|db:push)\b", lowered)
        or re.search(r"\bmanage\.py\b[^\n]*\bmigrate\b|\brails\b[^\n]*\bdb:migrate\b", lowered)
    ):
        category = "db-migration"
    elif (
        re.search(r"\b(?:vercel|netlify|wrangler|firebase|flyctl|railway|render)\b[^\n]*\bdeploy\b", lowered)
        or re.search(r"\bvercel\b[^\n]*(?:--prod|--production)\b", lowered)
        or re.search(r"\b(?:npm|pnpm|yarn|bun)\b[^\n]*\brun\s+deploy\b", lowered)
        or re.search(r"\bkubectl\b[^\n]*\bapply\b|\bhelm\b[^\n]*\bupgrade\b", lowered)
    ):
        category = "deploy"
    elif (
        re.search(r"\b(?:secret|secrets|secretsmanager|vault)\b[^\n]*\b(?:add|create|delete|destroy|put|remove|rm|set|update|write)\b", lowered)
        or re.search(r"\b(?:vercel|netlify|wrangler)\b[^\n]*\benv\b[^\n]*\b(?:add|create|delete|remove|rm|set|update)\b", lowered)
    ):
        category = "secret-mutation"
    elif re.search(r"\b(?:stripe|billing|payment|subscription)\b[^\n]*\b(?:cancel|charge|create|delete|refund|remove|update)\b", lowered):
        category = "billing"
    elif (
        re.search(r"\b(?:sendmail|mailx)\b", lowered)
        or re.search(r"\b(?:email|mail|resend|smtp)\b[^\n]*\b(?:deliver|send|publish)\b", lowered)
    ):
        category = "mail-send"
    elif re.search(r"\b(?:alpaca|binance|ibkr|broker|trading)\b[^\n]*\b(?:buy|order|sell|trade|transfer|withdraw)\b", lowered):
        category = "money-trade"
    return (category, sha256_text(command)) if category else None


def _pretool_policy(
    state: dict[str, Any], *, tool_name: str, tool_input: dict[str, Any], actor: str
) -> dict[str, Any]:
    t3_action = _t3_command_action(tool_input)
    if t3_action:
        category, action_sha256 = t3_action
        goal = state.get("goal") if isinstance(state.get("goal"), dict) else {}
        authorizations = [
            {
                "action_sha256": str(value.get("action_sha256") or "").casefold(),
                "request_sha256": str(value.get("request_sha256") or "").casefold(),
            }
            for value in goal.get("t3_action_authorizations", [])
            if (
                isinstance(value, dict)
                and re.fullmatch(r"[0-9a-f]{64}", str(value.get("action_sha256") or ""))
                and re.fullmatch(r"[0-9a-f]{64}", str(value.get("request_sha256") or ""))
            )
        ]
        authorization = next(
            (value for value in authorizations if value["action_sha256"] == action_sha256),
            None,
        )
        return {
            "deny": authorization is None,
            "hard_deny": authorization is None,
            "category": category,
            "status": "authorized" if authorization is not None else "denied",
            "action_sha256": action_sha256,
            **(
                {"granting_request_sha256": authorization["request_sha256"]}
                if authorization is not None
                else {}
            ),
            "reason": (
                "exact GoalContract T3 authorization and granting request binding present"
                if authorization is not None
                else "exact GoalContract T3 authorization with granting request binding missing"
            ),
        }

    patch_parse_error: str | None = None
    if _normalized_tool_marker(tool_name) == "applypatch":
        write_paths, patch_parse_error = _apply_patch_write_paths(tool_input)
    else:
        write_paths = _known_write_paths(tool_name, tool_input)
    if patch_parse_error:
        return {
            "deny": True,
            "hard_deny": True,
            "category": "apply-patch-parse",
            "status": "denied",
            "reason": patch_parse_error,
        }
    if not write_paths:
        return {"deny": False, "hard_deny": False, "category": None, "status": "not-applicable"}
    workspace = str(state.get("workspace") or "")
    goal_contract = state.get("goal") if isinstance(state.get("goal"), dict) else {}
    goal_scope = goal_contract.get("scope") if isinstance(goal_contract.get("scope"), dict) else {}
    (
        project_policy_configured,
        project_policy_valid,
        project_allowed,
        project_denied,
    ) = _project_policy_scope(state)
    goal_allowed = [value for value in goal_scope.get("in", []) if isinstance(value, str) and value.strip()]
    goal_denied = [value for value in goal_scope.get("out", []) if isinstance(value, str) and value.strip()]
    active_leases = [
        task for task in state.get("tasks", [])
        if isinstance(task, dict)
        and task.get("lease_status") == "active"
        and bool(str(task.get("lease_id") or "").strip())
        and bool(str(task.get("responsibility_group") or "").strip())
        and str(task.get("owner") or "") == actor
        and task.get("goal_id") == goal_contract.get("goal_id")
        and task.get("goal_version") == goal_contract.get("version")
        and isinstance(task.get("allowed_paths"), list)
    ]
    path_hashes: list[str] = []
    for value in write_paths:
        relative = canonical_workspace_path(workspace, value)
        if relative is None:
            return {
                "deny": True,
                "hard_deny": True,
                "category": "write-lease",
                "status": "denied",
                "path_sha256": sha256_text(str(value)),
                "reason": "write path is non-canonical, outside the workspace, or crosses a reparse point",
            }
        path_hashes.append(sha256_text(relative))
        if project_policy_configured and not project_policy_valid:
            return {
                "deny": True,
                "hard_deny": False,
                "category": "write-scope",
                "status": "denied",
                "path_sha256": sha256_text(relative),
                "reason": "explicit project policy is malformed",
            }
        if (
            not goal_allowed
            or (project_policy_configured and not project_allowed)
            or not path_matches_lease(relative, goal_allowed)
            or (
                project_policy_configured
                and not path_matches_lease(relative, project_allowed)
            )
            or path_matches_lease(relative, goal_denied)
            or path_matches_lease(relative, project_denied)
        ):
            return {
                "deny": True,
                "hard_deny": False,
                "category": "write-scope",
                "status": "denied",
                "path_sha256": sha256_text(relative),
                "reason": "write path is outside the active GoalContract or project policy scope",
            }
        if not any(path_matches_lease(relative, list(task.get("allowed_paths", []))) for task in active_leases):
            return {
                "deny": True,
                "hard_deny": False,
                "category": "write-lease",
                "status": "denied",
                "path_sha256": sha256_text(relative),
                "reason": "no active lease owned by this actor covers the canonical write path",
            }
    return {
        "deny": False,
        "hard_deny": False,
        "category": "write-lease",
        "status": "authorized",
        "path_sha256": path_hashes[0] if len(path_hashes) == 1 else sha256_text("\n".join(path_hashes)),
        "reason": "all canonical write paths are covered by an active actor-owned lease",
    }


def _persist_hook_degraded(payload: Any, args: argparse.Namespace, exc: Exception) -> None:
    safe_payload = payload if isinstance(payload, dict) else {}
    workspace = str(safe_payload.get("cwd") or safe_payload.get("workspace") or os.getcwd())
    session = str(
        safe_payload.get("session_id")
        or safe_payload.get("session")
        or os.environ.get("CLAUDE_SESSION_ID")
        or os.environ.get("CODEX_THREAD_ID")
        or "unidentified-hook-session"
    )
    record = {
        "contract": "AdapterHealth/v3",
        "runtime": args.runtime,
        "session_sha256": sha256_text(session),
        "hook_event": str(args.event),
        "health": "degraded",
        "error_type": type(exc).__name__,
        "recorded_at": utc_now(),
        "recovery_requires": "successful durable hook acknowledgement in a later round",
    }
    try:
        relative = canonical_workspace_path(workspace, ".agent-supervisor/adapter-health.json")
        if relative:
            workspace_root = Path(os.path.abspath(workspace))
            atomic_write_json(workspace_root / Path(relative), record)
    except Exception:
        pass
    try:
        ns = _hook_context(safe_payload, args.runtime, args.event, getattr(args, "state_root", None))
        ctx = _context(ns, require_existing=False)
        if ctx.state_file.exists():
            ctx.update(lambda state: state.update({"health": "degraded", "updated_at": utc_now()}))
            ctx.append_event({
                "event_type": "adapter_hook_degraded",
                "status": "degraded",
                "hook_event": str(args.event),
                "error_type": type(exc).__name__,
            })
    except Exception:
        pass


def command_hook(args: argparse.Namespace) -> int:
    payload: Any = {}
    try:
        payload = json.load(sys.stdin)
        if not isinstance(payload, dict):
            raise InvalidState("hook stdin must be an object")
        ns = _hook_context(payload, args.runtime, args.event, getattr(args, "state_root", None))
        adapter = payload.get("_agent_supervisor_adapter", {})
        if args.event == "UserPromptSubmit":
            prompt = str(payload.get("prompt") or payload.get("user_prompt") or "").strip()
            _reject_sensitive_contract_input(prompt, "UserPromptSubmit")
            previous_ctx = _context(ns, require_existing=False)
            previous = previous_ctx.load() if previous_ctx.state_file.exists() else {}
            if not previous:
                pointer = previous_ctx.previous_pointer()
                previous = json_load(Path(pointer["state_file"]), {}) if pointer.get("state_file") else {}
            change_mode = _classify_goal_change(prompt, previous)
            config, project = _project_identity(ns.project_file, ns.workspace)
            safe_goal, safe_intents, raw_prompt_withheld = _privacy_safe_prompt_contract(
                prompt, config
            )
            round_id = f"round-{sha256_text(session_key := (ns.session + prompt + utc_now()))[:16]}"
            ctx = StateContext.build(
                runtime=ns.runtime,
                project=project,
                workspace=ns.workspace,
                session=ns.session,
                round_id=round_id,
                state_root=getattr(ns, "state_root", None),
            )
            quality = read_quality_profile(config, ns.project_file, ns.workspace)
            state = start_round(
                ctx,
                message=prompt,
                change_mode=change_mode,
                execution_mode=str(config.get("execution_mode") or "warn"),
                project_config=config,
                quality_profile=quality,
                goal_supplied=safe_goal,
                intents_supplied=safe_intents,
                trusted_authorizations=None,
            )
            if raw_prompt_withheld:
                privacy_record = {
                    "raw_prompt_persisted": False,
                    "request_sha256": sha256_text(prompt),
                }
                state = ctx.update(lambda current: current.update({
                    "prompt_privacy": privacy_record,
                    "updated_at": utc_now(),
                }))
            state = _initialize_cli_source_snapshot(ctx, state, shadow=False)
            if isinstance(adapter, dict) and adapter.get("degraded_prior") is True:
                state = ctx.update(lambda current: current.update({"health": "degraded", "updated_at": utc_now()}))
                ctx.append_event({"event_type": "adapter_recovered", "status": "degraded", "degraded_prior": True, "adapter_version": adapter.get("adapter_version")})
            print(json.dumps({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "additionalContext": f"Supervisor v3 goal {state['goal']['goal_id']} v{state['goal']['version']} started in {state['execution_mode']} mode."}}, ensure_ascii=False))
            return EXIT_COMPLETE
        if args.event == "SessionEnd":
            try:
                ctx = _context(ns, require_existing=True)
            except InvalidState:
                print("{}")
                return EXIT_COMPLETE
            ctx.append_event({
                "event_type": "session_end",
                "status": "observed",
                "actor": str(payload.get("actor") or args.runtime),
                "identity_assurance": "host-hook-observed",
            })
            print("{}")
            return EXIT_COMPLETE
        ctx = _context(ns, require_existing=args.event != "SessionStart")
        if args.event == "SessionStart":
            if isinstance(adapter, dict) and adapter.get("degraded_prior") is True:
                ctx.session_root.mkdir(parents=True, exist_ok=True)
                atomic_write_json(
                    ctx.session_root / "adapter-health.json",
                    {
                        "contract": "AdapterHealth/v3",
                        "runtime": ns.runtime,
                        "session": ns.session,
                        "health": "degraded",
                        "degraded_prior": True,
                        "acknowledged_at": utc_now(),
                        "recovery_requires": "durable active round acknowledgement",
                    },
                )
                print(json.dumps({
                    "agent_supervisor": {"health": "degraded", "durable_ack": True},
                    "hookSpecificOutput": {
                        "hookEventName": "SessionStart",
                        "additionalContext": "Supervisor v3 detected prior degraded operation; the marker remains until the next goal round records it.",
                    },
                }, ensure_ascii=False))
                return EXIT_DEGRADED
            print(json.dumps({"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": "Supervisor v3 ready; goal will be classified on the next prompt."}}))
            return EXIT_COMPLETE
        state = ctx.load()
        if isinstance(adapter, dict) and adapter.get("degraded_prior") is True:
            state = ctx.update(lambda current: current.update({"health": "degraded", "updated_at": utc_now()}))
            ctx.append_event({"event_type": "adapter_recovered", "status": "degraded", "degraded_prior": True, "adapter_version": adapter.get("adapter_version")})
        tool_name = str(payload.get("tool_name") or payload.get("tool") or "unknown")
        raw_tool_input = payload.get("tool_input")
        if isinstance(raw_tool_input, dict):
            tool_input = raw_tool_input
        elif isinstance(raw_tool_input, str) and _normalized_tool_marker(tool_name) == "applypatch":
            tool_input = {"patch": raw_tool_input}
        else:
            tool_input = {}
        host_actor = str(payload.get("agent_id") or payload.get("subagent_id") or payload.get("actor") or args.runtime)
        capability_name = str(
            tool_input.get("skill")
            or tool_input.get("capability")
            or tool_input.get("agent")
            or tool_input.get("subagent_type")
            or payload.get("agent_type")
            or payload.get("subagent_type")
            or tool_name
        )
        invocation_id = str(
            payload.get("tool_use_id")
            or payload.get("tool_call_id")
            or payload.get("call_id")
            or payload.get("invocation_id")
            or stable_id("invocation")
        )
        if args.event == "PreToolUse":
            policy = _pretool_policy(
                state,
                tool_name=tool_name,
                tool_input=tool_input,
                actor=host_actor,
            )
            execution_mode = str(state.get("execution_mode") or "enforce").strip().casefold()
            if execution_mode not in {"observe", "warn", "enforce"}:
                execution_mode = "enforce"
            would_deny = policy.get("deny") is True
            should_deny = would_deny and (
                policy.get("hard_deny") is True or execution_mode == "enforce"
            )
            effective_status = policy.get("status")
            if would_deny:
                effective_status = (
                    "denied"
                    if should_deny
                    else "warned"
                    if execution_mode == "warn"
                    else "observed"
                )
            if policy.get("category"):
                ctx.append_event({
                    "event_type": "pretool_policy",
                    "invocation_id": invocation_id,
                    "category": policy.get("category"),
                    "status": effective_status,
                    "policy_status": policy.get("status"),
                    "execution_mode": execution_mode,
                    "would_deny": would_deny,
                    "hard_deny": policy.get("hard_deny") is True,
                    **({"action_sha256": policy["action_sha256"]} if policy.get("action_sha256") else {}),
                    **({"granting_request_sha256": policy["granting_request_sha256"]} if policy.get("granting_request_sha256") else {}),
                    **({"path_sha256": policy["path_sha256"]} if policy.get("path_sha256") else {}),
                })
            if should_deny:
                detail = policy.get("action_sha256") or policy.get("path_sha256") or "unavailable"
                print(json.dumps({
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": f"Supervisor denied {policy.get('category')} action; reference SHA-256 {detail}.",
                    }
                }, ensure_ascii=False))
                return EXIT_COMPLETE
            advisory_output: dict[str, Any] | None = None
            if would_deny and execution_mode == "warn":
                detail = policy.get("action_sha256") or policy.get("path_sha256") or "unavailable"
                advisory_output = {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "additionalContext": (
                            f"Supervisor warning: {policy.get('category')} policy would deny this action "
                            f"in enforce mode; reference SHA-256 {detail}."
                        ),
                    }
                }
            breaker = state.get("capability_breakers", {}).get(capability_name, {})
            if isinstance(breaker, dict) and breaker.get("open") is True:
                fallback_id = str(breaker.get("fallback_id") or "").strip()
                ctx.append_event({
                    "event_type": "invocation_fallback_required",
                    "invocation_id": invocation_id,
                    "capability": capability_name,
                    "fallback_id": fallback_id or None,
                    "status": "routed" if fallback_id else "degraded",
                    "actor": host_actor,
                    "summary": "open circuit prevented the original capability from counting as used",
                })
                output: dict[str, Any] = {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "additionalContext": f"Supervisor circuit open for {capability_name}; use fallback {fallback_id or 'manual verified fallback'}. The original capability will not count as success.",
                    }
                }
                if execution_mode == "enforce":
                    output["hookSpecificOutput"].update({
                        "permissionDecision": "deny",
                        "permissionDecisionReason": f"Capability circuit open; route to {fallback_id or 'documented manual fallback'}.",
                    })
                print(json.dumps(output, ensure_ascii=False))
                return EXIT_COMPLETE
            ctx.append_event(invocation_event(
                invocation_id=invocation_id, capability=capability_name, stage="attempt", result=None,
                actor=host_actor,
                details={"summary": f"{tool_name} attempt", **_invocation_state_binding(state)},
                identity_assurance="host-hook-observed",
            ))
            print(json.dumps(advisory_output, ensure_ascii=False) if advisory_output else "{}")
            return EXIT_COMPLETE
        if args.event in {"PostToolUse", "PostToolUseFailure"}:
            responses = [payload.get("tool_response"), payload.get("tool_result")]
            response_failed = any(
                isinstance(response, dict)
                and (
                    bool(response.get("isError"))
                    or bool(response.get("is_error"))
                    or response.get("success") is False
                    or str(response.get("status") or "").casefold() in {"failed", "failure", "error"}
                    or any(
                        isinstance(response.get(key), (int, str))
                        and str(response.get(key)).strip() not in {"", "0"}
                        for key in ("exit_code", "exitCode")
                    )
                )
                for response in responses
            )
            failed = (
                args.event == "PostToolUseFailure"
                or bool(payload.get("is_error"))
                or bool(payload.get("isError"))
                or payload.get("success") is False
                or response_failed
            )
            result_name = "failed" if failed else "success"
            ctx.update(lambda state_value: _record_breaker_result(state_value, capability_name, result_name))
            ctx.append_event(invocation_event(
                invocation_id=invocation_id, capability=capability_name, stage="result", result=result_name,
                actor=host_actor,
                details={"summary": f"{tool_name} completed", **_invocation_state_binding(state)},
                identity_assurance="host-hook-observed",
            ))
            print("{}")
            return EXIT_COMPLETE
        if args.event == "SubagentStart":
            ctx.append_event({
                "event_type": "subagent_start",
                "status": "observed",
                "actor": host_actor,
                "capability": capability_name,
                "identity_assurance": "host-hook-observed",
            })
            print("{}")
            return EXIT_COMPLETE
        if args.event == "SubagentStop":
            # SubagentStop shares the parent host session. Validate
            # a read-only snapshot and record it; never finalize/mutate the parent
            # terminal state from a child lifecycle event.
            report = validate_state(state, ctx.events())
            ctx.append_event(
                {
                    "event_type": "subagent_stop_review",
                    "status": "valid" if report["valid"] else "incomplete",
                    "actor": host_actor,
                    "identity_assurance": "host-hook-observed",
                    "summary": f"read-only subagent stop review; errors={len(report['errors'])}",
                }
            )
            print("{}")
            return EXIT_COMPLETE
        if args.event == "Stop":
            try:
                _verify_current_source_snapshot(ctx, state)
            except SupervisorSourceSnapshotMismatch:
                pass
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
        _persist_hook_degraded(payload, args, exc)
        print(json.dumps({"agent_supervisor": {"health": "degraded", "error": type(exc).__name__, "fail_open": True}}))
        return EXIT_DEGRADED


def _add_namespace(parser: argparse.ArgumentParser, *, round_required: bool = False) -> None:
    parser.add_argument("--runtime", choices=("claude", "codex"), required=True)
    parser.add_argument("--workspace", default=os.getcwd())
    parser.add_argument("--session")
    parser.add_argument("--round", required=round_required)
    parser.add_argument("--project-file")
    parser.add_argument("--state-root", help=argparse.SUPPRESS)


def build_parser() -> Parser:
    parser = Parser(prog="agent-supervisor", description="Agent Supervisor v3 shared core")
    parser.add_argument("--version", action="version", version="3.1.0")
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
    p.add_argument("--runtime", choices=("claude", "codex"), default="claude")
    p.add_argument("--event", required=True)
    p.add_argument("--state-root", help=argparse.SUPPRESS)
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
    except RuntimeError as exc:
        _emit({
            "ok": False,
            "health": "degraded",
            "error": type(exc).__name__,
            "message": str(exc),
        })
        return EXIT_DEGRADED
    except Exception:
        # Unknown failures are invalid-state outcomes, not user-visible
        # tracebacks.  Keep the response independent of exception text so an
        # attacker-controlled message cannot disclose a credential or path.
        _emit({
            "ok": False,
            "error": "unknown",
            "message": "unexpected supervisor failure",
        })
        return EXIT_INVALID


if __name__ == "__main__":
    raise SystemExit(main())
