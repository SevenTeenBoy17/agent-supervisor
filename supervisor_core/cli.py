from __future__ import annotations

import argparse
import base64
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
import tempfile
import threading
from pathlib import Path, PurePosixPath
from typing import Any

from .constants import EXIT_COMPLETE, EXIT_DEGRADED, EXIT_INCOMPLETE, EXIT_INVALID
from .attestation import sign_record, verify_record
from .contracts import (
    build_round_process_summary,
    invocation_event,
    normalize_intents,
    render_round_process_summary,
)
from .discovery import (
    baseline_report,
    parse_roots,
    scan_skills,
    verify_project_agent_record,
    write_baseline,
)
from .executable_trust import (
    ExecutableTrustError,
    load_trusted_executable_registry,
    registry_public_record,
    resolve_trusted_executable,
    trusted_path,
    verify_registry_record,
)
from .finalize import finalize_round
from .lifecycle import (
    _reject_reparse_path,
    capture_validated_supervisor_source_snapshot,
    read_project_config,
    read_quality_profile,
    start_round,
)
from .routing import route_intents, split_intents
from .runtime_bundle import (
    RuntimeBundleError,
    bound_release_identity,
    bound_resource_bytes,
    bound_resource_map,
    build_runtime_bundle,
    inspect_runtime_bundle,
)
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
from .validation import (
    _BINDING_FIELDS,
    _completion_trusted_invocations,
    _project_policy_scope,
    _runtime_assurance_accepted,
    _trusted_invocation_for_runtime,
    _validate_evidence,
    _validate_live_or_artifact_binding,
    successful_invocations,
    validate_state,
)
from .workspace import (
    canonical_workspace_path,
    capture_workspace_snapshot,
    path_matches_lease,
    resolve_handoff_output_path,
    validate_review_output_artifact,
    validated_supervisor_source_snapshot_hash,
    workspace_delta,
)


class InvalidState(ValueError):
    pass


class SupervisorSourceSnapshotMismatch(RuntimeError):
    pass


class _FrozenGateCommand(list[str]):
    """Command argv carrying immutable stdin that is never persisted in evidence."""

    def __init__(
        self,
        values: list[str],
        input_bytes: bytes,
        *,
        review_resources: dict[str, bytes] | None = None,
        review_profile_root: str | None = None,
        review_core_manifest_sha256: str | None = None,
        review_adapter_manifest: dict[str, str] | None = None,
        review_adapter_manifest_sha256: str | None = None,
    ) -> None:
        super().__init__(values)
        self.input_bytes = input_bytes
        self.review_resources = dict(review_resources or {})
        self.review_profile_root = review_profile_root
        self.review_core_manifest_sha256 = review_core_manifest_sha256
        self.review_adapter_manifest = dict(review_adapter_manifest or {})
        self.review_adapter_manifest_sha256 = review_adapter_manifest_sha256

    def execution_input_bytes(self) -> bytes:
        if not self.review_resources:
            return self.input_bytes
        payload = {
            "contract": "SupervisorReviewSourceFrame/v1",
            "core_manifest_sha256": self.review_core_manifest_sha256,
            "profile_root": self.review_profile_root,
            "adapter_manifest": self.review_adapter_manifest,
            "adapter_manifest_sha256": self.review_adapter_manifest_sha256,
            "resources": {
                name: base64.b64encode(content).decode("ascii")
                for name, content in sorted(self.review_resources.items())
            },
        }
        encoded = json.dumps(
            payload,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        if len(encoded) > _MAX_GATE_STDIN_BYTES:
            raise InvalidState("frozen review source exceeds its bounded transport")
        return encoded


_DEFAULT_GATE_TIMEOUT_SECONDS = 1200
_MIN_GATE_TIMEOUT_SECONDS = 1
_MAX_GATE_TIMEOUT_SECONDS = 1800
_DEFAULT_ROLLBACK_CLAIM_LEASE_SECONDS = 30
_MIN_ROLLBACK_CLAIM_LEASE_SECONDS = 1
_MAX_ROLLBACK_CLAIM_LEASE_SECONDS = 3600
_MAX_GATE_CAPTURE_BYTES = 64 * 1024
_GATE_CAPTURE_CHUNK_BYTES = 16 * 1024
_MAX_GATE_STDIN_BYTES = 4 * 1024 * 1024


def _run_gate_subprocess_bounded(
    command: list[str],
    *,
    cwd: str,
    timeout_seconds: float,
    extra_env: dict[str, str] | None = None,
    input_bytes: bytes | None = None,
    replace_env: bool = False,
) -> dict[str, Any]:
    """Drain both pipes concurrently while retaining only a bounded byte tail."""
    if input_bytes is not None and (
        not isinstance(input_bytes, bytes) or len(input_bytes) > _MAX_GATE_STDIN_BYTES
    ):
        raise ValueError("gate subprocess stdin exceeds its bounded contract")
    process_environment = None
    if extra_env is not None:
        process_environment = {} if replace_env else os.environ.copy()
        process_environment.update(extra_env)
    process = subprocess.Popen(
        command,
        cwd=cwd,
        stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        bufsize=0,
        env=process_environment,
    )
    if process.stdout is None or process.stderr is None or (
        input_bytes is not None and process.stdin is None
    ):
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

    input_state = {"complete": input_bytes is None, "error": False}

    def write_input() -> None:
        assert process.stdin is not None
        try:
            written = process.stdin.write(input_bytes or b"")
            process.stdin.flush()
            input_state["complete"] = written == len(input_bytes or b"")
        except (BrokenPipeError, OSError, ValueError):
            input_state["error"] = True
        finally:
            try:
                process.stdin.close()
            except (OSError, ValueError):
                pass

    writer = (
        threading.Thread(target=write_input, daemon=True)
        if input_bytes is not None
        else None
    )
    if writer is not None:
        writer.start()

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
        if writer is not None:
            try:
                writer.join(timeout=2)
                if writer.is_alive():
                    input_state["error"] = True
            except (RuntimeError, ValueError):
                input_state["error"] = True
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

    reader_incomplete: list[bool] = []
    for reader in readers:
        try:
            reader_incomplete.append(bool(reader.is_alive()))
        except (AttributeError, RuntimeError, ValueError):
            # A reader whose terminal state cannot be established is not safe
            # evidence of a complete capture. Preserve the process result, but
            # make downstream evidence fail closed on truncation.
            reader_incomplete.append(True)

    captured_buffers = {
        name: bytes(value)
        for name, value in buffers.items()
    }
    captured_totals = dict(totals)

    def decoded_tail(name: str) -> str:
        data = captured_buffers[name]
        if captured_totals[name] > len(data):
            boundary = data.find(b"\n")
            data = data[boundary + 1 :] if boundary >= 0 else b""
        return data.decode("utf-8", errors="replace")

    return {
        "exit_code": 124 if timed_out else int(return_code),
        "timed_out": timed_out,
        "stdout": decoded_tail("stdout"),
        "stderr": decoded_tail("stderr"),
        "stdout_truncated": (
            captured_totals["stdout"] > len(captured_buffers["stdout"])
            or reader_incomplete[0]
        ),
        "stderr_truncated": (
            captured_totals["stderr"] > len(captured_buffers["stderr"])
            or reader_incomplete[1]
        ),
        "stdin_complete": bool(input_state["complete"] and not input_state["error"]),
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


def _command_audit_record(category: str, args: list[str]) -> dict[str, Any]:
    """Represent a credential-free command with a stable structural digest."""
    structure: list[str] = []
    for index, raw in enumerate(args):
        token = str(raw)
        if index == 0:
            structure.append("executable")
        elif os.path.isabs(token):
            structure.append("absolute-path")
        elif token.startswith(("-", "/")):
            structure.append(f"option:{token.partition('=')[0].casefold()}")
        else:
            structure.append("value")
    return {
        "category": category,
        "args": list(args),
        "args_structure_sha256": canonical_sha256(structure),
    }


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


def _initialize_executable_registry(
    ctx: StateContext,
    state: dict[str, Any],
    *,
    shadow: bool,
) -> tuple[dict[str, Any], bool]:
    try:
        record = registry_public_record(load_trusted_executable_registry())
        degraded = False
    except (ExecutableTrustError, OSError, RuntimeError, ValueError) as exc:
        record = {
            "contract": "TrustedExecutableRegistry/v1",
            "status": "unavailable",
            "reason": type(exc).__name__,
        }
        degraded = True
    if shadow:
        state["trusted_executable_registry"] = copy.deepcopy(record)
        if degraded:
            state["health"] = "degraded"
        return state, degraded

    def persist(current: dict[str, Any]) -> None:
        current["trusted_executable_registry"] = copy.deepcopy(record)
        if degraded:
            current["health"] = "degraded"
        current["updated_at"] = utc_now()

    return ctx.update(persist), degraded


def _verified_executable_registry(
    ctx: StateContext, state: dict[str, Any]
) -> dict[str, Any]:
    record = state.get("trusted_executable_registry")
    try:
        return verify_registry_record(record)
    except (ExecutableTrustError, OSError, RuntimeError, ValueError) as exc:
        reason = f"trusted-executable-registry:{type(exc).__name__}"
        ctx.update(lambda current: current.update({
            "health": "degraded",
            "source_snapshot_integrity": {
                "status": "mismatch",
                "reason": reason,
                "checked_at": utc_now(),
            },
            "updated_at": utc_now(),
        }))
        ctx.append_event({
            "event_type": "trusted_executable_registry_mismatch",
            "status": "degraded",
            "reason": reason,
        })
        raise SupervisorSourceSnapshotMismatch(
            reason
        ) from exc


def _execution_release_identity() -> dict[str, Any] | None:
    """Use the stage-0 identity frozen for this process, never a later pointer."""
    bound = bound_release_identity()
    return copy.deepcopy(bound) if isinstance(bound, dict) else active_version_snapshot()


def _isolated_review_environment(
    registry: dict[str, Any],
    extra: dict[str, str] | None = None,
) -> dict[str, str]:
    """Build a credential-minimal environment for the external review boundary."""
    allowed = {
        "APPDATA", "COMSPEC", "HOMEDRIVE", "HOMEPATH", "LOCALAPPDATA",
        "OS", "PROGRAMDATA", "SYSTEMDRIVE", "SYSTEMROOT", "TEMP", "TMP",
        "USERDOMAIN", "USERNAME", "USERPROFILE", "WINDIR",
    }
    environment = {
        name: value
        for name, value in os.environ.items()
        if name.upper() in allowed and isinstance(value, str)
    }
    environment.update({
        "AGENT_SUPERVISOR_TRUST_REGISTRY_SHA256": str(
            registry.get("registry_sha256") or ""
        ),
        "NoDefaultCurrentDirectoryInExePath": "1",
        "PATH": trusted_path(registry),
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
    })
    environment.update(extra or {})
    return environment


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


def _capability_discovery_summary(
    inventory: dict[str, Any], *, root_count: int
) -> dict[str, Any]:
    """Bind a concise discovery result to stable inventory content."""
    skills = [
        copy.deepcopy(row)
        for row in inventory.get("skills", [])
        if isinstance(row, dict)
    ]
    ignored = [
        copy.deepcopy(row)
        for row in inventory.get("ignored", [])
        if isinstance(row, dict)
    ]
    agents = [
        copy.deepcopy(row)
        for row in inventory.get("agents", [])
        if isinstance(row, dict)
    ]
    identity_collisions = [
        copy.deepcopy(row)
        for row in inventory.get("identity_collisions", [])
        if isinstance(row, dict)
    ]
    stable_payload = {
        "skills": sorted(skills, key=canonical_sha256),
        "agents": sorted(agents, key=canonical_sha256),
        "ignored": sorted(ignored, key=canonical_sha256),
        "identity_collisions": sorted(identity_collisions, key=canonical_sha256),
        "counts": copy.deepcopy(
            inventory.get("counts")
            if isinstance(inventory.get("counts"), dict)
            else {}
        ),
    }
    return {
        "contract": "CapabilityDiscoverySummary/v3",
        "status": (
            "degraded" if stable_payload["identity_collisions"] else "healthy"
        ),
        "scanned_at": str(inventory.get("generated_at") or utc_now()),
        "root_count": int(root_count),
        "counts": copy.deepcopy(stable_payload["counts"]),
        "inventory_sha256": canonical_sha256(stable_payload),
    }


def _trusted_capability_discovery(
    project_config: dict[str, Any],
    workspace: str,
    runtime: str,
    root_values: list[str] | None = None,
) -> tuple[list[Any], dict[str, Any], dict[str, Any]]:
    """Run the one trusted Skill + project-Agent discovery pipeline."""
    roots = parse_roots(list(root_values or []), runtime)
    inventory = scan_skills(
        roots,
        project_config=project_config,
        workspace=workspace,
    )
    project_agents = inventory.get("agents")
    if not isinstance(project_agents, list):
        raise InvalidState("capability inventory agents must be an array")
    counts = inventory.setdefault("counts", {})
    if not isinstance(counts, dict):
        raise InvalidState("capability inventory counts must be an object")
    counts.update(
        {
            "agents_discovered": len(project_agents),
            "agents_active": sum(1 for row in project_agents if row.get("active")),
            "agents_unavailable": sum(
                1
                for row in project_agents
                if row.get("availability") == "unavailable"
            ),
            "agent_fallbacks": sum(
                1 for row in project_agents if row.get("fallback_only")
            ),
        }
    )
    discovery = _capability_discovery_summary(inventory, root_count=len(roots))
    return roots, inventory, discovery


def _capability_start_degraded(
    ctx: StateContext,
    state: dict[str, Any],
    args: argparse.Namespace,
    *,
    stage: str,
    error: BaseException,
    inventory: dict[str, Any] | None = None,
    discovery: dict[str, Any] | None = None,
) -> int:
    """Persist and emit only a stable failure code plus exception type."""
    degradation = {
        "contract": "CapabilityBootstrapDegradation/v3",
        "stage": stage,
        "reason_code": f"capability-{stage}-failed",
        "error_type": type(error).__name__,
        "recorded_at": utc_now(),
    }
    if not bool(args.shadow):
        def persist(current: dict[str, Any]) -> None:
            current["health"] = "degraded"
            current["capability_bootstrap_degradation"] = copy.deepcopy(
                degradation
            )
            if isinstance(inventory, dict):
                current["capability_inventory"] = copy.deepcopy(inventory)
            if isinstance(discovery, dict):
                current["discovery"] = copy.deepcopy(discovery)
            current["updated_at"] = utc_now()

        state = ctx.update(persist)
    else:
        state["health"] = "degraded"
    _emit(
        {
            "ok": False,
            "shadow": bool(args.shadow),
            "persisted": not bool(args.shadow),
            "state_file": None if args.shadow else str(ctx.state_file),
            "health": "degraded",
            "terminal_state": "incomplete",
            "discovery": copy.deepcopy(discovery),
            "capability_route": None,
            "degradation": degradation,
        }
    )
    return EXIT_DEGRADED


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
    raw_atomic_intents = (
        normalize_intents(intents, args.message)
        if intents is not None
        else normalize_intents(split_intents(args.message), args.message)
    )
    if not raw_atomic_intents:
        raw_atomic_intents = normalize_intents(
            [{"text": args.message, "domain": "general"}], args.message
        )
    safe_goal, safe_intents, raw_prompt_withheld = _privacy_safe_prompt_contract(
        args.message, config, raw_atomic_intents
    )
    if raw_prompt_withheld:
        supplied = safe_goal
        intents = safe_intents
    _reject_sensitive_contract_input(
        {
            "message": args.message,
            "goal": supplied,
            "intents": intents,
            "project_config": config,
            "quality_profile": quality,
        },
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
    state, executable_registry_degraded = _initialize_executable_registry(
        ctx, state, shadow=bool(args.shadow)
    )
    state = _initialize_cli_source_snapshot(ctx, state, shadow=bool(args.shadow))
    try:
        roots, inventory, discovery = _trusted_capability_discovery(
            config,
            ctx.workspace,
            args.runtime,
            list(getattr(args, "roots", None) or []),
        )
    except Exception as exc:
        return _capability_start_degraded(
            ctx, state, args, stage="discovery", error=exc
        )
    supplied_intents = _routing_intents_for_start(state, raw_atomic_intents)
    try:
        routed = route_intents(
            message=args.message,
            inventory=inventory,
            supplied_intents=supplied_intents,
            phase_budget=int(getattr(args, "phase_budget", 3)),
            zero_skill_reviewed=bool(
                getattr(args, "zero_skill_reviewed", False)
            ),
        )
        capability_route = (
            _privacy_safe_capability_route(routed, state, args.message)
            if raw_prompt_withheld
            else routed
        )
        capability_route["inventory_sha256"] = discovery["inventory_sha256"]
    except Exception as exc:
        return _capability_start_degraded(
            ctx,
            state,
            args,
            stage="routing",
            error=exc,
            inventory=inventory,
            discovery=discovery,
        )
    if not bool(args.shadow):
        def persist_capabilities(current: dict[str, Any]) -> None:
            current["capability_inventory"] = copy.deepcopy(inventory)
            current["discovery"] = copy.deepcopy(discovery)
            current["capability_route"] = copy.deepcopy(capability_route)
            current["intents"] = copy.deepcopy(
                capability_route.get("coverage", [])
            )
            if raw_prompt_withheld:
                current["prompt_privacy"] = {
                    "raw_prompt_persisted": False,
                    "request_sha256": sha256_text(args.message),
                }
            current["updated_at"] = utc_now()

        state = ctx.update(persist_capabilities)
    _emit({
        "ok": bool(capability_route.get("valid")),
        "shadow": bool(args.shadow),
        "persisted": not bool(args.shadow),
        "state_file": None if args.shadow else str(ctx.state_file),
        "goal": state["goal"],
        "intents": capability_route.get("coverage", []),
        "execution_mode": state.get("execution_mode"),
        "discovery": discovery,
        "capability_route": capability_route,
        "terminal_state": (
            "active"
            if capability_route.get("valid") and not executable_registry_degraded
            else "incomplete"
        ),
        "namespace": {"runtime": ctx.runtime, "project": ctx.project, "workspace": ctx.workspace, "session": ctx.session, "round": ctx.round},
    })
    if executable_registry_degraded:
        return EXIT_DEGRADED
    return EXIT_COMPLETE if capability_route.get("valid") else EXIT_INCOMPLETE


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
        "responsibility_group": args.responsibility_group,
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
        clean = redact_for_persistence(record)
    except ValueError as exc:
        raise InvalidState(f"{event_type} contains sensitive data in an integrity-bound field") from exc
    if event_type == "evidence_record":
        command = clean.get("command") if isinstance(clean, dict) else None
        raw_args = command.get("args") if isinstance(command, dict) else None
        if isinstance(raw_args, list) and all(isinstance(item, str) for item in raw_args):
            command["args_structure_sha256"] = canonical_sha256(
                [
                    "executable"
                    if index == 0
                    else "absolute-path"
                    if os.path.isabs(item)
                    else f"option:{item.partition('=')[0].casefold()}"
                    if item.startswith(("-", "/"))
                    else "value"
                    for index, item in enumerate(raw_args)
                ]
            )
    return clean


def _upsert_record(rows: list[dict[str, Any]], record: dict[str, Any], identity: str) -> None:
    record_id = str(record.get(identity) or "").strip()
    if not record_id:
        raise InvalidState(f"record requires {identity}")
    for index, existing in enumerate(rows):
        if isinstance(existing, dict) and existing.get(identity) == record_id:
            rows[index] = record
            return
    rows.append(record)


def _trusted_current_agent_liveness(
    state: dict[str, Any],
    record: dict[str, Any],
    inventory_sha256: str,
) -> dict[str, Any] | None:
    """Return one trusted, current-session Agent liveness success or fail closed.

    Codex does not expose a complete host Agent lifecycle to this core.  It may
    audit explicit capability contributions, but must never turn a caller claim
    into host liveness.  Other runtimes may populate this core-owned collection
    only through a future trusted host integration.
    """
    if str(state.get("runtime") or "").strip().casefold() == "codex":
        return None
    if record.get("host_liveness_status") != "verified":
        return None
    evidence_rows = state.get("trusted_agent_liveness")
    if not isinstance(evidence_rows, list):
        return None
    capability_id = str(record.get("id") or "").strip()
    config_sha256 = str(record.get("sha256") or "").strip().casefold()
    if not capability_id or not re.fullmatch(r"[0-9a-f]{64}", config_sha256):
        return None
    matches: list[dict[str, Any]] = []
    for raw in evidence_rows:
        if not isinstance(raw, dict):
            continue
        observed_at = str(raw.get("observed_at") or "")
        try:
            parse_time(observed_at)
        except (TypeError, ValueError):
            continue
        if (
            raw.get("contract") == "TrustedAgentLiveness/v1"
            and raw.get("status") == "success"
            and raw.get("trusted_host_event") is True
            and str(raw.get("runtime") or "") == str(state.get("runtime") or "")
            and str(raw.get("project") or "") == str(state.get("project") or "")
            and str(raw.get("workspace") or "") == str(state.get("workspace") or "")
            and str(raw.get("session") or "") == str(state.get("session") or "")
            and str(raw.get("round") or "") == str(state.get("round") or "")
            and str(raw.get("capability_id") or "").strip().casefold()
            == capability_id.casefold()
            and str(raw.get("config_sha256") or "").casefold() == config_sha256
            and str(raw.get("inventory_sha256") or "").casefold()
            == inventory_sha256
            and re.fullmatch(
                r"[0-9a-f]{64}",
                str(raw.get("host_capability_identity_sha256") or "").casefold(),
            )
            and str(raw.get("probe_actor") or "").strip()
            and str(raw.get("evidence_id") or "").strip()
        ):
            matches.append(raw)
    return copy.deepcopy(matches[0]) if len(matches) == 1 else None


def _trusted_fallback_binding(
    state: dict[str, Any], capability: str
) -> dict[str, Any] | None:
    """Return a current inventory-bound Agent fallback or fail closed."""
    inventory = state.get("capability_inventory")
    discovery = state.get("discovery")
    route = state.get("capability_route")
    if not all(isinstance(value, dict) for value in (inventory, discovery, route)):
        return None
    expected_inventory_sha256 = str(
        discovery.get("inventory_sha256") or ""
    ).casefold()
    if (
        not re.fullmatch(r"[0-9a-f]{64}", expected_inventory_sha256)
        or route.get("inventory_sha256") != expected_inventory_sha256
        or discovery.get("status") != "healthy"
        or route.get("valid") is not True
    ):
        return None
    try:
        observed = _capability_discovery_summary(
            inventory,
            root_count=int(discovery.get("root_count")),
        )
    except (TypeError, ValueError):
        return None
    if (
        observed.get("inventory_sha256") != expected_inventory_sha256
        or observed.get("status") != "healthy"
    ):
        return None

    configured = state.get("capability_fallbacks")
    fallback_id = (
        str(configured.get(capability) or "").strip()
        if isinstance(configured, dict)
        else ""
    )
    agents = inventory.get("agents")
    if not fallback_id or not isinstance(agents, list):
        return None
    primaries = [
        row
        for row in agents
        if isinstance(row, dict)
        and row.get("id") == capability
        and row.get("fallback_only") is False
        and row.get("active") is True
        and row.get("automatic") is True
        and row.get("availability") == "enabled"
        and row.get("health") == "healthy"
        and row.get("host_liveness_status") == "verified"
        and row.get("fallback_id") == fallback_id
    ]
    fallbacks = [
        row
        for row in agents
        if isinstance(row, dict)
        and row.get("id") == fallback_id
        and row.get("fallback_only") is True
        and row.get("primary_id") == capability
        and row.get("active") is False
        and row.get("automatic") is False
        and row.get("availability") == "fallback-only"
        and row.get("health") == "healthy"
        and row.get("host_liveness_status") == "verified"
    ]
    if len(primaries) != 1 or len(fallbacks) != 1:
        return None
    primary, fallback = primaries[0], fallbacks[0]
    group = str(primary.get("responsibility_group") or "").strip()
    primary_liveness = _trusted_current_agent_liveness(
        state, primary, expected_inventory_sha256
    )
    fallback_liveness = _trusted_current_agent_liveness(
        state, fallback, expected_inventory_sha256
    )
    if (
        not group
        or fallback.get("responsibility_group") != group
        or primary_liveness is None
        or fallback_liveness is None
        or not verify_project_agent_record(primary, str(state.get("workspace") or ""))
        or not verify_project_agent_record(fallback, str(state.get("workspace") or ""))
    ):
        return None
    return {
        "contract": "TrustedFallbackBinding/v3",
        "primary_id": capability,
        "fallback_id": fallback_id,
        "responsibility_group": group,
        "primary_sha256": primary.get("sha256"),
        "fallback_sha256": fallback.get("sha256"),
        "inventory_sha256": expected_inventory_sha256,
        "primary_liveness_evidence_id": primary_liveness.get("evidence_id"),
        "fallback_liveness_evidence_id": fallback_liveness.get("evidence_id"),
    }


def _breaker_fallback_id(
    state: dict[str, Any], capability: str, breaker: Any
) -> str:
    if not isinstance(breaker, dict) or breaker.get("fallback_status") != "required":
        return ""
    binding = breaker.get("fallback_binding")
    fallback_id = str(breaker.get("fallback_id") or "").strip()
    current_binding = _trusted_fallback_binding(state, capability)
    return fallback_id if (
        isinstance(binding, dict)
        and binding.get("contract") == "TrustedFallbackBinding/v3"
        and binding.get("fallback_id") == fallback_id
        and current_binding is not None
        and binding == current_binding
    ) else ""


def _record_breaker_result(state: dict[str, Any], capability: str, result: str) -> None:
    breakers = state.setdefault("capability_breakers", {})
    fallback_map = state.get("capability_fallbacks")
    configured_fallback = (
        fallback_map.get(capability) if isinstance(fallback_map, dict) else None
    )
    row = breakers.setdefault(capability, {"consecutive_failures": 0, "open": False, "fallback_id": configured_fallback})
    if not row.get("fallback_id") and configured_fallback:
        row["fallback_id"] = configured_fallback
    if result == "success":
        row["consecutive_failures"] = 0
        row["open"] = False
        row.pop("active_capability", None)
        row.pop("fallback_status", None)
        row.pop("fallback_binding", None)
        row.pop("fallback_unavailable_reason", None)
    else:
        row["consecutive_failures"] = int(row.get("consecutive_failures", 0)) + 1
        if row["consecutive_failures"] >= 2:
            row["open"] = True
            row["opened_at"] = utc_now()
            binding = _trusted_fallback_binding(state, capability)
            if binding is not None:
                row["fallback_id"] = binding["fallback_id"]
                row["active_capability"] = binding["fallback_id"]
                row["fallback_status"] = "required"
                row["fallback_binding"] = binding
                row.pop("fallback_unavailable_reason", None)
            else:
                row.pop("active_capability", None)
                row.pop("fallback_binding", None)
                row["fallback_status"] = "unavailable"
                row["fallback_unavailable_reason"] = (
                    "trusted-inventory-fallback-unavailable"
                )
                state["health"] = "degraded"
    state["updated_at"] = utc_now()


def _apply_state_record(state: dict[str, Any], payload: dict[str, Any], event_type: str) -> str | None:
    aliases = {
        "task_record": ("tasks", "task_id"),
        "task_upsert": ("tasks", "task_id"),
        "evidence_record": ("evidence", "evidence_id"),
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
            rollback = rollback_active_version(expected_active=_execution_release_identity())
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


def _hook_identity_assurance(runtime: str) -> str:
    # Codex passes hook payloads through a caller-accessible local adapter; no
    # external host signature authenticates actor/responsibility-group fields.
    return (
        "codex-hook-observation"
        if str(runtime).strip().casefold() == "codex"
        else "host-hook-observed"
    )


def _bound_audit_invocation_attempt(
    state: dict[str, Any],
    events: list[dict[str, Any]],
    invocation_id: str,
    actor: str,
    responsibility_group: str,
) -> dict[str, Any] | None:
    """Accept a locally attested observation for execution, never identity."""
    matches = [
        event
        for event in events
        if isinstance(event, dict)
        and event.get("event_type") == "invocation_attempt"
        and event.get("invocation_id") == invocation_id
    ]
    if len(matches) != 1:
        return None
    attempt = matches[0]
    details = attempt.get("details") if isinstance(attempt.get("details"), dict) else {}
    assurance = attempt.get("identity_assurance")
    return attempt if (
        attempt.get("actor") == actor
        and attempt.get("responsibility_group") == responsibility_group
        and assurance in {
            "host-hook-observed",
            "codex-explicit-audit",
            "codex-hook-observation",
            "core-executed-gate",
            "core-trusted-finalize",
        }
        and verify_record(attempt)
        and all(
            details.get(key) == value
            for key, value in _invocation_state_binding(state).items()
        )
    ) else None


def _trusted_invocation_attempt(
    state: dict[str, Any], events: list[dict[str, Any]], invocation_id: str, actor: str,
    responsibility_group: str,
) -> dict[str, Any] | None:
    attempt = _bound_audit_invocation_attempt(
        state, events, invocation_id, actor, responsibility_group
    )
    if attempt is None:
        return None
    details = attempt.get("details") if isinstance(attempt.get("details"), dict) else {}
    assurance = attempt.get("identity_assurance")
    core_finalize_identity_valid = bool(
        assurance != "core-trusted-finalize"
        or (
            actor == "supervisor-core"
            and responsibility_group == "trusted-runtime"
            and bool(str(details.get("gate_id") or "").strip())
            and bool(str(details.get("criterion_id") or "").strip())
            and attempt.get("capability")
            == f"supervisor-core-builtin:{details.get('gate_id')}"
            and details.get("phase") == "builtin-finalize"
        )
    )
    core_gate_identity_valid = bool(
        assurance != "core-executed-gate"
        or (
            actor == "supervisor-core"
            and responsibility_group == "trusted-core-gate-execution"
            and bool(str(details.get("gate_id") or "").strip())
            and bool(str(details.get("criterion_id") or "").strip())
            and attempt.get("capability")
            == f"supervisor-core-gate:{details.get('gate_id')}"
            and details.get("phase") == "registered-gate-execution"
            and attempt.get("identity_provenance")
            == "core-minted-single-use-gate-execution"
            and attempt.get("completion_eligible") is True
        )
    )
    return attempt if (
        core_finalize_identity_valid
        and core_gate_identity_valid
        and _runtime_assurance_accepted(state, assurance)
    ) else None


def _unique_finalize_invocation_id(events: list[dict[str, Any]]) -> str:
    existing = {
        str(event.get("invocation_id"))
        for event in events
        if isinstance(event, dict) and event.get("invocation_id")
    }
    for _ in range(8):
        candidate = stable_id("invocation")
        if candidate not in existing:
            return candidate
    raise InvalidState("could not allocate a unique trusted finalize invocation id")


def _core_gate_invocation_event(
    state: dict[str, Any], *, invocation_id: str, gate_id: str,
    criterion_id: str, stage: str, result: str | None,
) -> dict[str, Any]:
    return invocation_event(
        invocation_id=invocation_id,
        capability=f"supervisor-core-gate:{gate_id}",
        stage=stage,
        result=result,
        actor="supervisor-core",
        responsibility_group="trusted-core-gate-execution",
        identity_assurance="core-executed-gate",
        details={
            "phase": "registered-gate-execution",
            "gate_id": gate_id,
            "criterion_id": criterion_id,
            **_invocation_state_binding(state),
        },
    )


def _finalize_invocation_event(
    state: dict[str, Any], *, invocation_id: str, gate_id: str,
    criterion_id: str, stage: str, result: str | None,
) -> dict[str, Any]:
    return invocation_event(
        invocation_id=invocation_id,
        capability=f"supervisor-core-builtin:{gate_id}",
        stage=stage,
        result=result,
        actor="supervisor-core",
        responsibility_group="trusted-runtime",
        identity_assurance="core-trusted-finalize",
        details={
            "phase": "builtin-finalize",
            "gate_id": gate_id,
            "criterion_id": criterion_id,
            **_invocation_state_binding(state),
        },
    )


def _run_finalize_builtin_gate(
    ctx: StateContext, state: dict[str, Any], *, gate_id: str,
    criterion_id: str,
) -> tuple[dict[str, Any], dict[str, Any], int]:
    """Run one builtin under a signed, single-attempt finalize identity."""
    invocation_id = _unique_finalize_invocation_id(ctx.events())
    attempt = _finalize_invocation_event(
        state,
        invocation_id=invocation_id,
        gate_id=gate_id,
        criterion_id=criterion_id,
        stage="attempt",
        result=None,
    )
    ctx.append_event(attempt)
    try:
        outcome = _run_registered_gate(
            ctx,
            {
                "event_type": "gate_run",
                "actor": "supervisor-core",
                "record": {
                    "gate_id": gate_id,
                    "criterion_id": criterion_id,
                    "collector": "supervisor-core",
                    "collector_responsibility_group": "trusted-runtime",
                    "collector_invocation_id": invocation_id,
                },
            },
            finalize_internal=True,
        )
        gate_result = "success" if int(outcome[2]) == 0 else "failed"
    except BaseException:
        ctx.append_event(_finalize_invocation_event(
            state,
            invocation_id=invocation_id,
            gate_id=gate_id,
            criterion_id=criterion_id,
            stage="result",
            result="failed",
        ))
        raise
    ctx.append_event(_finalize_invocation_event(
        state,
        invocation_id=invocation_id,
        gate_id=gate_id,
        criterion_id=criterion_id,
        stage="result",
        result=gate_result,
    ))
    return outcome


def _gate_binding(state: dict[str, Any]) -> dict[str, Any]:
    changes = state.get("changes") if isinstance(state.get("changes"), dict) else {}
    if changes.get("diff_hash"):
        return changes
    baseline = state.get("workspace_baseline") if isinstance(state.get("workspace_baseline"), dict) else {}
    current = capture_workspace_snapshot(
        str(state.get("workspace") or ""),
        [value for value in baseline.get("extra_globs", []) if isinstance(value, str)],
    )
    return workspace_delta(baseline, current)


def _core_codex_changes_record(
    state: dict[str, Any], request: dict[str, Any]
) -> dict[str, Any]:
    """Replace caller identity/binding claims with a core-observed workspace record."""
    caller_forbidden = {
        "implementer",
        "implementer_responsibility_group",
        "implementer_invocation_id",
        "producer_identity_assurance",
        "issued_by",
        "issued_at",
        "attestation",
    }
    if caller_forbidden.intersection(request):
        raise InvalidState("Codex changes_record caller cannot declare producer identity")
    baseline = state.get("workspace_baseline")
    if not isinstance(baseline, dict):
        raise InvalidState("Codex changes_record requires a workspace baseline")
    current = capture_workspace_snapshot(
        str(state.get("workspace") or ""),
        [
            value
            for value in baseline.get("extra_globs", [])
            if isinstance(value, str)
        ],
    )
    observed = workspace_delta(baseline, current)
    domains = request.get("domains")
    safe_domains = sorted({
        value.strip()
        for value in domains
        if isinstance(value, str) and value.strip()
    }) if isinstance(domains, list) else []
    record = {
        "contract": "ChangesRecord/v3",
        "goal_id": state.get("goal", {}).get("goal_id"),
        "goal_version": state.get("goal", {}).get("version"),
        "request_manifest_sha256": canonical_sha256(
            state.get("request_manifest", {})
        ),
        "files": copy.deepcopy(observed.get("files", [])),
        "manifest": copy.deepcopy(observed.get("manifest", {})),
        "domains": safe_domains,
        "test_changes": {},
        **{field: observed.get(field) for field in _BINDING_FIELDS},
        "implementer": "codex-local-workspace",
        "implementer_responsibility_group": "local-workspace-producer",
        "implementer_invocation_id": f"core-workspace-{str(observed.get('diff_hash') or '')[:24]}",
        "producer_identity_assurance": "core-observed-local-workspace",
        "issued_by": "supervisor-core-workspace-observer",
        "issued_at": utc_now(),
    }
    record["attestation"] = sign_record(record)
    return record


def _requires_review_binding_file(gate_id: str) -> bool:
    # QualityProfile gate IDs are case- and whitespace-sensitive schema values.
    if gate_id[:1].isspace() or gate_id[-1:].isspace():
        return False
    return gate_id in {"review.coderabbit", "review.coderabbit.test-integrity"} or gate_id.startswith(
        "review.code-review-graph."
    )


def _review_binding_input(
    state: dict[str, Any],
    *,
    supervisor_source_snapshot_sha256: str | None = None,
    review_core_manifest_sha256: str | None = None,
    review_adapter_manifest: dict[str, str] | None = None,
    review_adapter_manifest_sha256: str | None = None,
) -> dict[str, Any]:
    """Build a core-observed, signed input for immutable review artifact producers."""
    baseline = (
        state.get("workspace_baseline")
        if isinstance(state.get("workspace_baseline"), dict)
        else None
    )
    changes = state.get("changes") if isinstance(state.get("changes"), dict) else None
    if not isinstance(baseline, dict) or not isinstance(changes, dict):
        raise InvalidState("review gate requires workspace baseline and changes record")
    workspace = str(state.get("workspace") or "")
    current = capture_workspace_snapshot(
        workspace,
        [
            value for value in baseline.get("extra_globs", [])
            if isinstance(value, str)
        ],
    )
    observed = workspace_delta(baseline, current)
    errors: list[str] = []
    if observed.get("git_binding_status") != "verified":
        errors.append("active workspace Git binding is not verified")
    if set(map(str, changes.get("files", []))) != set(map(str, observed.get("files", []))):
        errors.append("changes files do not match active workspace delta")
    for field in ("workspace_base_sha256", "workspace_head_sha256", "diff_hash"):
        if changes.get(field) != observed.get(field):
            errors.append(f"changes {field} does not match active workspace delta")
    _validate_live_or_artifact_binding(
        state, changes, "review gate changes", errors, observed=observed
    )
    if changes.get("git_binding_status") != "verified" or errors:
        raise InvalidState("review gate binding input failed core verification")
    binding = {
        "contract": "ReviewArtifactBindingInput/v1",
        "workspace_base_sha256": observed.get("workspace_base_sha256"),
        "workspace_head_sha256": observed.get("workspace_head_sha256"),
        "diff_hash": observed.get("diff_hash"),
        "workspace_delta_manifest": copy.deepcopy(observed.get("manifest", {})),
    }
    source_binding_values = (
        supervisor_source_snapshot_sha256,
        review_core_manifest_sha256,
        review_adapter_manifest,
        review_adapter_manifest_sha256,
    )
    if any(value is not None for value in source_binding_values):
        if not (
            isinstance(supervisor_source_snapshot_sha256, str)
            and re.fullmatch(r"[0-9a-f]{64}", supervisor_source_snapshot_sha256)
            and isinstance(review_core_manifest_sha256, str)
            and re.fullmatch(r"[0-9a-f]{64}", review_core_manifest_sha256)
            and isinstance(review_adapter_manifest, dict)
            and bool(review_adapter_manifest)
            and isinstance(review_adapter_manifest_sha256, str)
            and re.fullmatch(r"[0-9a-f]{64}", review_adapter_manifest_sha256)
        ):
            raise InvalidState("review source binding fields are incomplete")
        assert isinstance(review_adapter_manifest, dict)
        normalized_adapter_manifest: dict[str, str] = {}
        for logical, digest in review_adapter_manifest.items():
            if not (
                isinstance(logical, str)
                and logical.startswith(("global-codex/", "global-claude/"))
                and "\\" not in logical
                and "//" not in logical
                and not any(part in {"", ".", ".."} for part in logical.split("/"))
                and isinstance(digest, str)
                and re.fullmatch(r"[0-9a-f]{64}", digest)
            ):
                raise InvalidState("review adapter source manifest is invalid")
            normalized_adapter_manifest[logical] = digest
        normalized_adapter_manifest = dict(sorted(normalized_adapter_manifest.items()))
        if canonical_sha256(normalized_adapter_manifest) != review_adapter_manifest_sha256:
            raise InvalidState("review adapter source manifest hash mismatch")
        binding.update({
            "supervisor_source_snapshot_sha256": supervisor_source_snapshot_sha256,
            "review_core_manifest_sha256": review_core_manifest_sha256,
            "review_adapter_manifest": normalized_adapter_manifest,
            "review_adapter_manifest_sha256": review_adapter_manifest_sha256,
        })
    return binding


def _parse_review_gate_output(
    stdout: str,
    stderr: str,
    binding_input: dict[str, Any],
    *,
    stdout_truncated: bool = False,
    stderr_truncated: bool = False,
) -> tuple[dict[str, Any] | None, str]:
    """Accept one unambiguous JSON object and fully revalidate its artifact."""
    if stdout_truncated or stderr_truncated:
        return None, "review-output-truncated"
    if stderr.strip():
        return None, "review-output-stderr-not-empty"
    lines = stdout.strip().splitlines()
    if len(lines) != 1 or not lines[0].strip():
        return None, "review-output-must-be-one-json-line"

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON value: {value}")

    try:
        parsed = json.loads(
            lines[0],
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (TypeError, ValueError, json.JSONDecodeError):
        return None, "review-output-json-invalid-or-ambiguous"
    valid, reason, normalized = validate_review_output_artifact(parsed, binding_input)
    if not valid or not isinstance(normalized, dict):
        return None, reason
    return copy.deepcopy(normalized), "verified"


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
    command: list[str],
    *,
    cwd: str,
    trusted_registry: dict[str, Any],
) -> tuple[list[str], str, str]:
    """Resolve argv[0] only through the round-bound machine trust registry."""
    if not command or not str(command[0]).strip():
        raise FileNotFoundError("registered gate command is empty")
    token = str(command[0])
    try:
        resolved, executable_hash = resolve_trusted_executable(
            token, trusted_registry, cwd=cwd
        )
    except (ExecutableTrustError, OSError, RuntimeError, ValueError) as exc:
        raise FileNotFoundError(
            "registered gate executable is not in the round-bound trust registry"
        ) from exc
    return [resolved, *command[1:]], resolved, executable_hash


def _path_contains_link_or_reparse(path: Path) -> bool:
    current = Path(os.path.abspath(os.fspath(path)))
    while True:
        details = os.lstat(current)
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        attributes = getattr(details, "st_file_attributes", 0)
        if stat.S_ISLNK(details.st_mode) or bool(
            reparse_flag and attributes & reparse_flag
        ):
            return True
        if current.parent == current:
            return False
        current = current.parent


def _review_profile_root(snapshot_roots: Any) -> str:
    if not isinstance(snapshot_roots, dict):
        raise InvalidState("trusted review source roots are unavailable")
    candidates: list[Path] = []
    for key, expected_segments in (
        ("codex-adapter", (".codex", "skills", "dev-supervisor", "scripts")),
        ("claude-adapter", (".claude", "skills", "supervisor", "scripts")),
    ):
        raw = snapshot_roots.get(key)
        if not isinstance(raw, str) or not raw:
            raise InvalidState("trusted review adapter root is unavailable")
        path = Path(os.path.abspath(os.fspath(Path(raw))))
        if tuple(part.casefold() for part in path.parts[-4:]) != tuple(
            part.casefold() for part in expected_segments
        ):
            raise InvalidState("trusted review adapter layout is invalid")
        candidates.append(path.parents[3])
    if os.path.normcase(str(candidates[0])) != os.path.normcase(str(candidates[1])):
        raise InvalidState("trusted review adapters do not share one profile root")
    return str(candidates[0])


def _review_adapter_manifest(snapshot_roots: dict[str, Any]) -> dict[str, str]:
    """Freeze every adapter file selected by the independent review runner."""
    codex_scripts = Path(str(snapshot_roots["codex-adapter"]))
    claude_scripts = Path(str(snapshot_roots["claude-adapter"]))
    codex_root = codex_scripts.parent
    claude_root = claude_scripts.parent
    excluded_directories = {
        ".git", "__pycache__", ".pytest_cache", ".codex-supervisor",
        "state", "logs", "cache", "handoffs", "review-artifacts",
        "test-results", ".next", "node_modules",
    }

    def excluded(path: Path) -> bool:
        lowered = [part.casefold() for part in path.parts]
        name = path.name.casefold()
        return (
            any(part in excluded_directories for part in lowered)
            or any(part.startswith(".pytest-tmp") for part in lowered)
            or name == "settings.local.json"
            or name.startswith("settings.local.")
            or name.endswith((".key", ".pem", ".pfx", ".log"))
            or name.startswith(".env")
        )

    codex_candidates: list[Path] = []
    for current, directories, files in os.walk(codex_root):
        current_path = Path(current)
        directories[:] = [
            name
            for name in directories
            if not excluded((current_path / name).relative_to(codex_root))
        ]
        codex_candidates.extend(
            current_path / name
            for name in files
            if not excluded((current_path / name).relative_to(codex_root))
        )
    claude_candidates = [
        claude_root / "SKILL.md",
        *(claude_scripts / name for name in (
            "sup-v3-hook.py", "sup-selftest.py", "sup-discover.py", "sup-log.py",
            "sup-plan.py", "configure-v3-hooks.py",
        )),
        *(claude_root / "tests" / name for name in (
            "test_dispatch_ledger.py", "test_precision.py", "test_retrieval.py",
            "test_v3_adapter.py", "test_verifier.py",
        )),
    ]
    manifest: dict[str, str] = {}
    for label, root, candidates in (
        ("global-codex", codex_root, codex_candidates),
        ("global-claude", claude_root, claude_candidates),
    ):
        absolute_root = Path(os.path.abspath(os.fspath(root)))
        for candidate in sorted(set(candidates)):
            if not candidate.exists() and not candidate.is_symlink():
                continue
            absolute = Path(os.path.abspath(os.fspath(candidate)))
            try:
                relative = absolute.relative_to(absolute_root)
                if excluded(relative) or _path_contains_link_or_reparse(absolute):
                    raise InvalidState("review adapter source contains indirection")
                before = absolute.stat(follow_symlinks=False)
                content = absolute.read_bytes()
                after = absolute.stat(follow_symlinks=False)
            except (OSError, RuntimeError, ValueError) as exc:
                raise InvalidState("review adapter source could not be frozen") from exc
            if (
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                or not stat.S_ISREG(after.st_mode)
                or len(content) != after.st_size
            ):
                raise InvalidState("review adapter source changed while freezing")
            manifest[f"{label}/{relative.as_posix()}"] = sha256_bytes(content)
    if not manifest:
        raise InvalidState("review adapter source manifest is empty")
    return dict(sorted(manifest.items()))


def _frozen_review_resources(
    core_root: Path,
    snapshot: dict[str, Any],
) -> tuple[dict[str, bytes], str, str, dict[str, str], str] | None:
    """Freeze the exact core/test payload that the independent reviewer will see."""
    roots = snapshot.get("roots") if isinstance(snapshot, dict) else None
    if not isinstance(roots, dict) or not {
        "shared-core", "codex-adapter", "claude-adapter"
    } <= set(roots):
        return None
    try:
        resources = bound_resource_map()
    except RuntimeBundleError as exc:
        raise InvalidState("bound review resources are unavailable") from exc
    if resources is None:
        try:
            version = (core_root / "VERSION").read_text(encoding="utf-8").strip()
            inspected = inspect_runtime_bundle(build_runtime_bundle(core_root, version))
            resources = dict(inspected["members"])
        except (OSError, RuntimeError, ValueError, RuntimeBundleError) as exc:
            raise InvalidState("review source could not be frozen") from exc
    # Small synthetic tests may bind only the runner. They still exercise the
    # immutable runner transport, but are not a publishable full review source.
    if "supervisor_core/__init__.py" not in resources:
        return None
    snapshot_files = snapshot.get("files") if isinstance(snapshot, dict) else None
    if not isinstance(snapshot_files, dict):
        raise InvalidState("trusted review source snapshot is unavailable")
    for logical, record in snapshot_files.items():
        if not isinstance(logical, str) or not logical.startswith("shared-core/"):
            continue
        relative = logical.removeprefix("shared-core/")
        content = resources.get(relative)
        if (
            not isinstance(record, dict)
            or record.get("status") != "hashed"
            or not isinstance(content, bytes)
            or record.get("sha256") != sha256_bytes(content)
            or record.get("size") != len(content)
        ):
            raise InvalidState("frozen review source does not match the round snapshot")
    core_manifest = {
        f"global-core/{name}": sha256_bytes(content)
        for name, content in sorted(resources.items())
    }
    profile_root = _review_profile_root(roots)
    adapter_manifest = _review_adapter_manifest(roots)
    return (
        resources,
        profile_root,
        canonical_sha256(core_manifest),
        adapter_manifest,
        canonical_sha256(adapter_manifest),
    )


def _trusted_core_runner_command(
    state: dict[str, Any], gate_id: str, gate: dict[str, Any]
) -> list[str]:
    """Resolve and freeze the source-snapshotted core review runner, fail closed."""
    if gate.get("trusted_core_runner") is not True:
        raise InvalidState(f"quality gate {gate_id} is not an immutable trusted-core runner")
    marker = list(gate.get("command") or [])
    expected_category = {
        "review.coderabbit": "independent",
        "review.coderabbit.test-integrity": "test-integrity",
    }.get(gate_id)
    expected_marker = [
        "supervisor-trusted-core-runner",
        "bin/run-coderabbit-review.py",
        "--review-category",
        expected_category,
    ]
    if expected_category is None or marker != expected_marker:
        raise InvalidState("trusted-core runner declaration is not exact")
    bound_identity = bound_release_identity()
    core_root = Path(os.path.abspath(os.fspath(
        Path(str(bound_identity["path"]))
        if isinstance(bound_identity, dict)
        else Path(__file__).parent.parent
    )))
    runner = core_root / "bin" / "run-coderabbit-review.py"
    bundled_content = bound_resource_bytes("bin/run-coderabbit-review.py")
    if bundled_content is not None:
        content = bundled_content
    else:
        try:
            if _path_contains_link_or_reparse(core_root) or _path_contains_link_or_reparse(runner):
                raise InvalidState("trusted-core runner path contains indirection")
            before = os.stat(runner, follow_symlinks=False)
            content = runner.read_bytes()
            after = os.stat(runner, follow_symlinks=False)
        except OSError as exc:
            raise InvalidState("trusted-core runner is unavailable") from exc
        identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if (
            identity_before != identity_after
            or not stat.S_ISREG(after.st_mode)
            or len(content) != after.st_size
        ):
            raise InvalidState("trusted-core runner changed during verification")
    snapshot = state.get("supervisor_source_snapshot")
    snapshot_files = snapshot.get("files") if isinstance(snapshot, dict) else None
    snapshot_roots = snapshot.get("roots") if isinstance(snapshot, dict) else None
    logical = "shared-core/bin/run-coderabbit-review.py"
    source_record = snapshot_files.get(logical) if isinstance(snapshot_files, dict) else None
    if (
        not isinstance(snapshot_roots, dict)
        or os.path.normcase(str(snapshot_roots.get("shared-core") or ""))
        != os.path.normcase(str(core_root))
        or not isinstance(source_record, dict)
        or source_record.get("status") != "hashed"
        or source_record.get("sha256") != sha256_bytes(content)
        or source_record.get("size") != len(content)
    ):
        raise InvalidState("trusted-core runner does not match the active source snapshot")
    executable = Path(sys.executable)
    if not executable.is_absolute() or not executable.is_file():
        raise InvalidState("trusted Python executable is unavailable")
    frozen = _frozen_review_resources(core_root, snapshot)
    if frozen is None:
        resources: dict[str, bytes] = {}
        profile_root = None
        core_manifest_sha256 = None
        adapter_manifest: dict[str, str] = {}
        adapter_manifest_sha256 = None
        bootstrap = (
            "import sys;"
            "logical=sys.argv.pop(1);"
            "source=sys.stdin.buffer.read();"
            "sys.argv[0]=logical;"
            "scope={'__name__':'__main__','__file__':logical,'__package__':None,'__spec__':None};"
            "exec(compile(source,logical,'exec'),scope,scope)"
        )
    else:
        (
            resources,
            profile_root,
            core_manifest_sha256,
            adapter_manifest,
            adapter_manifest_sha256,
        ) = frozen
        bootstrap = (
            "import base64,json,sys,types\n"
            "logical=sys.argv.pop(1)\n"
            "raw=sys.stdin.buffer.read()\n"
            "frame=json.loads(raw.decode('ascii'))\n"
            "assert frame.get('contract')=='SupervisorReviewSourceFrame/v1'\n"
            "encoded=frame.get('resources')\n"
            "assert isinstance(encoded,dict) and encoded\n"
            "resources={k:base64.b64decode(v,validate=True) for k,v in encoded.items()}\n"
            "source=resources['bin/run-coderabbit-review.py']\n"
            "runtime=types.ModuleType('_agent_supervisor_review_source')\n"
            "runtime.contract='SupervisorReviewSource/v1'\n"
            "runtime.resources=resources\n"
            "runtime.profile_root=frame.get('profile_root')\n"
            "runtime.core_manifest_sha256=frame.get('core_manifest_sha256')\n"
            "sys.modules[runtime.__name__]=runtime\n"
            "sys.argv[0]=logical\n"
            "scope={'__name__':'__main__','__file__':logical,'__package__':None,'__spec__':None}\n"
            "exec(compile(source,logical,'exec'),scope,scope)"
        )
    return _FrozenGateCommand([
        str(executable),
        "-I",
        "-S",
        "-X",
        "utf8",
        "-c",
        bootstrap,
        logical,
        "--review-category",
        str(expected_category),
    ], content, review_resources=resources, review_profile_root=profile_root,
        review_core_manifest_sha256=core_manifest_sha256,
        review_adapter_manifest=adapter_manifest,
        review_adapter_manifest_sha256=adapter_manifest_sha256)


def _evaluate_builtin_gate(
    state: dict[str, Any], events: list[dict[str, Any]], builtin: str, *, finalize_internal: bool
) -> tuple[int, dict[str, Any]]:
    if builtin == "intent-coverage":
        intents = state.get("intents", [])
        manifest = state.get("intent_manifest", [])
        success_caps, _, invocation_errors = _completion_trusted_invocations(
            state, events
        )
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
                    failures.append(
                        f"{intent.get('intent_id')}: no completion-trusted correlated invocation and no locally-audited correlated capability invocation"
                    )
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
    ctx: StateContext, payload: dict[str, Any], *, finalize_internal: bool = False,
    codex_core_internal: bool = False,
) -> tuple[dict[str, Any], dict[str, Any], int]:
    request = _record_from_payload(payload, "gate_run")
    gate_id = str(request.get("gate_id") or "").strip()
    criterion_id = str(request.get("criterion_id") or "").strip()
    if (
        str(ctx.runtime).strip().casefold() == "codex"
        and not finalize_internal
        and not codex_core_internal
    ):
        allowed_request_fields = {"gate_id", "criterion_id", "evidence_id"}
        if set(request) - allowed_request_fields or str(payload.get("actor") or "").strip():
            raise InvalidState(
                "Codex gate_run caller may request only gate_id, criterion_id, and evidence_id"
            )
        if not gate_id or not criterion_id:
            raise InvalidState("gate_run requires gate_id and criterion_id")
        state = ctx.load()
        if _registered_gate(state, gate_id) is None:
            raise InvalidState(f"gate is not registered in QualityProfile: {gate_id}")
        invocation_id = _unique_finalize_invocation_id(ctx.events())
        ctx.append_event(_core_gate_invocation_event(
            state,
            invocation_id=invocation_id,
            gate_id=gate_id,
            criterion_id=criterion_id,
            stage="attempt",
            result=None,
        ))
        internal_record = {
            "gate_id": gate_id,
            "criterion_id": criterion_id,
            "collector": "supervisor-core",
            "collector_responsibility_group": "trusted-core-gate-execution",
            "collector_invocation_id": invocation_id,
        }
        if request.get("evidence_id") is not None:
            internal_record["evidence_id"] = request["evidence_id"]
        try:
            outcome = _run_registered_gate(
                ctx,
                {
                    "event_type": "gate_run",
                    "actor": "supervisor-core",
                    "record": internal_record,
                },
                codex_core_internal=True,
            )
            gate_result = "success" if int(outcome[2]) == EXIT_COMPLETE else "failed"
        except BaseException:
            ctx.append_event(_core_gate_invocation_event(
                state,
                invocation_id=invocation_id,
                gate_id=gate_id,
                criterion_id=criterion_id,
                stage="result",
                result="failed",
            ))
            raise
        ctx.append_event(_core_gate_invocation_event(
            state,
            invocation_id=invocation_id,
            gate_id=gate_id,
            criterion_id=criterion_id,
            stage="result",
            result=gate_result,
        ))
        if (
            gate_result == "success"
            and outcome[0].get("gate_id")
            in {"review.coderabbit", "review.coderabbit.test-integrity"}
            and isinstance(outcome[0].get("review_output_artifact"), dict)
        ):
            _issue_automated_external_review(
                ctx,
                evidence=outcome[0],
                execution=outcome[1],
                review_output=outcome[0]["review_output_artifact"],
            )
        return outcome
    collector = str(payload.get("actor") or request.get("collector") or "runtime").strip()
    collector_group = str(request.get("collector_responsibility_group") or "runtime").strip()
    collector_invocation_id = str(request.get("collector_invocation_id") or "").strip()
    if not gate_id or not criterion_id or not collector or not collector_group or not collector_invocation_id:
        raise InvalidState(
            "gate_run requires gate_id, criterion_id, actor, collector_responsibility_group, "
            "and collector_invocation_id"
        )
    state = ctx.load()
    completion_trusted_attempt = _trusted_invocation_attempt(
        state, ctx.events(), collector_invocation_id, collector, collector_group
    )
    attempt = completion_trusted_attempt or _bound_audit_invocation_attempt(
        state, ctx.events(), collector_invocation_id, collector, collector_group
    )
    if attempt is None:
        raise InvalidState(
            "gate_run collector lacks a locally attested active-round invocation attempt"
        )
    collector_identity_assurance = str(attempt.get("identity_assurance") or "")
    collector_completion_eligible = completion_trusted_attempt is not None
    if finalize_internal:
        attempt_details = (
            attempt.get("details")
            if isinstance(attempt.get("details"), dict)
            else {}
        )
        if not (
            collector == "supervisor-core"
            and collector_group == "trusted-runtime"
            and collector_identity_assurance == "core-trusted-finalize"
            and attempt.get("capability") == f"supervisor-core-builtin:{gate_id}"
            and attempt_details.get("phase") == "builtin-finalize"
            and attempt_details.get("gate_id") == gate_id
            and attempt_details.get("criterion_id") == criterion_id
        ):
            raise InvalidState(
                "trusted finalize gate invocation identity/group/binding mismatch"
            )
    if codex_core_internal:
        attempt_details = (
            attempt.get("details")
            if isinstance(attempt.get("details"), dict)
            else {}
        )
        if not (
            collector == "supervisor-core"
            and collector_group == "trusted-core-gate-execution"
            and collector_identity_assurance == "core-executed-gate"
            and attempt.get("capability") == f"supervisor-core-gate:{gate_id}"
            and attempt_details.get("phase") == "registered-gate-execution"
            and attempt_details.get("gate_id") == gate_id
            and attempt_details.get("criterion_id") == criterion_id
        ):
            raise InvalidState(
                "core-executed gate invocation identity/group/binding mismatch"
            )
    source_snapshot_hash = _verify_current_source_snapshot(ctx, state)
    gate = _registered_gate(state, gate_id)
    if not gate:
        raise InvalidState(f"gate is not registered in QualityProfile: {gate_id}")
    executable_registry = (
        {}
        if gate.get("builtin")
        else _verified_executable_registry(ctx, state)
    )
    global_gates_at_start = _global_gate_ids(state)
    gate_active_identity = _execution_release_identity() if gate_id in global_gates_at_start else None
    command = list(gate.get("command") or [])
    if not command and not gate.get("builtin"):
        raise InvalidState(f"registered gate has no executable command or builtin: {gate_id}")
    runtime_input_bytes: bytes | None = None
    if gate.get("trusted_core_runner") is True:
        frozen_runtime_command = _trusted_core_runner_command(
            state, gate_id, gate
        )
        runtime_command = list(frozen_runtime_command)
        runtime_input_bytes = (
            frozen_runtime_command.execution_input_bytes()
            if isinstance(frozen_runtime_command, _FrozenGateCommand)
            else getattr(frozen_runtime_command, "input_bytes", None)
        )
        review_core_manifest_sha256 = getattr(
            frozen_runtime_command, "review_core_manifest_sha256", None
        )
        review_adapter_manifest = getattr(
            frozen_runtime_command, "review_adapter_manifest", None
        )
        review_adapter_manifest_sha256 = getattr(
            frozen_runtime_command, "review_adapter_manifest_sha256", None
        )
    else:
        runtime_command = command
        review_core_manifest_sha256 = None
        review_adapter_manifest = None
        review_adapter_manifest_sha256 = None
    review_binding = (
        _review_binding_input(
            state,
            supervisor_source_snapshot_sha256=(
                source_snapshot_hash if review_core_manifest_sha256 else None
            ),
            review_core_manifest_sha256=review_core_manifest_sha256,
            review_adapter_manifest=review_adapter_manifest,
            review_adapter_manifest_sha256=review_adapter_manifest_sha256,
        )
        if _requires_review_binding_file(gate_id) and not gate.get("builtin")
        else None
    )
    review_binding_input_sha256 = (
        canonical_sha256(review_binding) if isinstance(review_binding, dict) else None
    )
    precondition_command = list(gate["precondition"]) if gate.get("precondition") else None
    if redact(command) != command or (
        precondition_command is not None
        and redact(precondition_command) != precondition_command
    ):
        raise InvalidState(
            "registered gate command contains inline sensitive data; use a credential-free wrapper or environment indirection"
        )
    execution_id = stable_id("execution")
    evidence_id = str(request.get("evidence_id") or stable_id("evidence"))
    if any(
        isinstance(event, dict)
        and event.get("event_type") == "gate_grant"
        and event.get("collector_invocation_id") == collector_invocation_id
        and event.get("gate_id") == gate_id
        and event.get("criterion_id") == criterion_id
        for event in ctx.events()
    ):
        raise InvalidState("gate_run grant for this runner/gate/criterion was already consumed")
    if any(
        isinstance(record, dict) and record.get("evidence_id") == evidence_id
        for record in state.get("evidence", [])
    ):
        raise InvalidState("gate_run evidence_id already exists")
    gate_grant_id = stable_id("gate-grant")
    gate_grant = {
        "contract": "GateGrant/v3",
        "event_type": "gate_grant",
        "grant_id": gate_grant_id,
        "execution_id": execution_id,
        "evidence_id": evidence_id,
        "gate_id": gate_id,
        "criterion_id": criterion_id,
        "collector": collector,
        "collector_responsibility_group": collector_group,
        "collector_invocation_id": collector_invocation_id,
        "collector_identity_assurance": collector_identity_assurance,
        "collector_completion_eligible": collector_completion_eligible,
        "review_binding_input_sha256": review_binding_input_sha256,
        "issued_at": utc_now(),
        **_invocation_state_binding(state),
    }
    gate_grant["attestation"] = sign_record(gate_grant)
    ctx.append_event(gate_grant)
    started_at = utc_now()
    resolved_executable: str | None = None
    resolved_executable_sha256: str | None = None
    precondition: dict[str, Any] | None = None
    command_executed = True
    infrastructure_degraded = False
    gate_timeout = _gate_timeout_seconds(request.get("timeout_seconds"))
    review_binding_temp: tempfile.TemporaryDirectory[str] | None = None
    gate_extra_env: dict[str, str] | None = None
    if isinstance(review_binding, dict):
        review_binding_temp = tempfile.TemporaryDirectory(
            prefix="agent-supervisor-review-binding-"
        )
        review_binding_file = Path(review_binding_temp.name) / "binding.json"
        atomic_write_json(review_binding_file, review_binding)
        gate_extra_env = {
            "AGENT_SUPERVISOR_REVIEW_BINDING_FILE": str(review_binding_file.resolve()),
        }

    def run_external_step(
        step_command: list[str],
        category: str,
        *,
        input_bytes: bytes | None = None,
        isolated_environment: bool = False,
    ) -> dict[str, Any]:
        step_started = utc_now()
        step_resolved: str | None = None
        step_resolved_sha256: str | None = None
        failure_kind: str | None = None
        step_stdout = ""
        step_stderr = ""
        stdout_truncated = False
        stderr_truncated = False
        try:
            resolved_command, step_resolved, step_resolved_sha256 = _resolve_gate_command(
                step_command,
                cwd=str(state.get("workspace") or ctx.workspace),
                trusted_registry=executable_registry,
            )
            execution_env = (
                _isolated_review_environment(executable_registry, gate_extra_env)
                if isolated_environment
                else {
                    **dict(gate_extra_env or {}),
                    "PATH": trusted_path(executable_registry),
                    "NoDefaultCurrentDirectoryInExePath": "1",
                }
            )
            completed = _run_gate_subprocess_bounded(
                resolved_command,
                cwd=str(state.get("workspace") or ctx.workspace),
                timeout_seconds=gate_timeout,
                extra_env=execution_env,
                input_bytes=input_bytes,
                replace_env=isolated_environment,
            )
            step_exit = int(completed["exit_code"])
            step_stdout = str(completed["stdout"] or "")
            step_stderr = str(completed["stderr"] or "")
            stdout_truncated = bool(completed["stdout_truncated"])
            stderr_truncated = bool(completed["stderr_truncated"])
            raw_output = (
                step_stdout
                + ("\n" if step_stdout and step_stderr else "")
                + step_stderr
            )
            if stdout_truncated or stderr_truncated:
                raw_output = "[bounded gate output truncated]\n" + raw_output
            failure_kind = "timeout" if completed["timed_out"] else None
            if not completed.get("stdin_complete", True):
                step_exit = 127
                raw_output = "trusted gate input delivery failed"
                failure_kind = "unavailable"
        except OSError as exc:
            step_exit = 127
            raw_output = type(exc).__name__
            failure_kind = "unavailable"
        clean_step_output = str(redact(raw_output))
        step_summary = clean_step_output[-4000:].strip() or f"{category} produced no output"
        return {
            "command": _command_audit_record(category, step_command),
            "resolved_executable": step_resolved,
            "resolved_executable_sha256": step_resolved_sha256,
            "started_at": step_started,
            "finished_at": utc_now(),
            "exit_code": step_exit,
            "output_summary": step_summary,
            "output_sha256": sha256_text(clean_step_output),
            "failure_kind": failure_kind,
            "raw_output": clean_step_output,
            "raw_stdout": step_stdout,
            "raw_stderr": step_stderr,
            "stdout_truncated": stdout_truncated,
            "stderr_truncated": stderr_truncated,
        }

    review_output_artifact: dict[str, Any] | None = None
    main_step: dict[str, Any] | None = None
    try:
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
                main_step = run_external_step(
                    runtime_command,
                    "quality-gate",
                    input_bytes=runtime_input_bytes,
                    isolated_environment=gate.get("trusted_core_runner") is True,
                )
                resolved_executable = main_step["resolved_executable"]
                resolved_executable_sha256 = main_step["resolved_executable_sha256"]
                exit_code = int(main_step["exit_code"])
                combined = str(main_step["raw_output"])
                infrastructure_degraded = infrastructure_degraded or main_step["failure_kind"] is not None
                if isinstance(review_binding, dict) and exit_code == 0:
                    review_output_artifact, artifact_reason = _parse_review_gate_output(
                        str(main_step.get("raw_stdout") or ""),
                        str(main_step.get("raw_stderr") or ""),
                        review_binding,
                        stdout_truncated=bool(main_step.get("stdout_truncated")),
                        stderr_truncated=bool(main_step.get("stderr_truncated")),
                    )
                    if review_output_artifact is None:
                        exit_code = 2
                        combined = (
                            f"review gate artifact output rejected: {artifact_reason}\n"
                            f"{main_step['raw_output']}"
                        )
    finally:
        if review_binding_temp is not None:
            review_binding_temp.cleanup()
    try:
        post_source_snapshot_hash = _verify_current_source_snapshot(ctx)
        if post_source_snapshot_hash != source_snapshot_hash:
            raise SupervisorSourceSnapshotMismatch("source-changed-during-gate")
    except SupervisorSourceSnapshotMismatch as exc:
        exit_code = 4
        infrastructure_degraded = True
        combined = f"trusted source changed during gate: {type(exc).__name__}"
    # Raw streams are transient parsing inputs only.  In particular, review
    # gates need their exact stdout long enough to validate the immutable
    # artifact, but no raw stdout/stderr may enter state or the event ledger.
    for step in (precondition, main_step):
        if isinstance(step, dict):
            for field in ("raw_output", "raw_stdout", "raw_stderr"):
                step.pop(field, None)
    clean_output = str(redact(combined))
    summary = clean_output[-4000:].strip() or f"gate {gate_id} produced no output"
    finished_at = utc_now()
    changes = state.get("changes", {}) if isinstance(state.get("changes"), dict) else {}
    baseline = state.get("workspace_baseline", {}) if isinstance(state.get("workspace_baseline"), dict) else {}
    binding = _gate_binding(state)
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
        "command": _command_audit_record("quality-gate", command),
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
        "base": binding.get("base"),
        "head": binding.get("head"),
        "git_object_format": binding.get("git_object_format"),
        "git_binding_status": binding.get("git_binding_status"),
        "git_binding_source": binding.get("git_binding_source"),
        "git_repository_root": binding.get("git_repository_root"),
        "review_artifact_sha256": binding.get("review_artifact_sha256"),
        "git_diff_sha256": binding.get("git_diff_sha256"),
        "workspace_base_sha256": binding.get("workspace_base_sha256"),
        "workspace_head_sha256": binding.get("workspace_head_sha256"),
        "diff_hash": binding.get("diff_hash"),
        "workspace_snapshot_hash": baseline.get("snapshot_hash"),
        "source_snapshot_hash": source_snapshot_hash,
        "collector": collector,
        "collector_responsibility_group": collector_group,
        "collector_invocation_id": collector_invocation_id,
        "collector_identity_assurance": collector_identity_assurance,
        "collector_completion_eligible": collector_completion_eligible,
        "review_binding_input_sha256": review_binding_input_sha256,
        "review_output_artifact": copy.deepcopy(review_output_artifact),
        "gate_grant_id": gate_grant_id,
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
        "command": _command_audit_record("quality-gate", command),
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
        "git_object_format": execution["git_object_format"],
        "git_binding_status": execution["git_binding_status"],
        "git_binding_source": execution["git_binding_source"],
        "git_repository_root": execution["git_repository_root"],
        "review_artifact_sha256": execution["review_artifact_sha256"],
        "git_diff_sha256": execution["git_diff_sha256"],
        "workspace_base_sha256": execution["workspace_base_sha256"],
        "workspace_head_sha256": execution["workspace_head_sha256"],
        "diff_hash": execution["diff_hash"],
        "source_snapshot_hash": source_snapshot_hash,
        "collector": collector,
        "collector_responsibility_group": collector_group,
        "collector_invocation_id": collector_invocation_id,
        "collector_identity_assurance": collector_identity_assurance,
        "collector_completion_eligible": collector_completion_eligible,
        "review_binding_input_sha256": review_binding_input_sha256,
        "review_output_artifact": copy.deepcopy(review_output_artifact),
        "gate_grant_id": gate_grant_id,
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
        if collector_completion_eligible and gate_id == "review.project-supervisor":
            kind, values = "fixture_replay", {"passed": exit_code == 0}
        elif collector_completion_eligible and gate_id == "config.historical-replay":
            kind, values = "historical_replay", {"passed": exit_code == 0}
        elif (
            collector_completion_eligible
            and gate_id in global_gates
            and not infrastructure_degraded
        ):
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


def _issue_automated_external_review(
    ctx: StateContext, *, evidence: dict[str, Any], execution: dict[str, Any],
    review_output: dict[str, Any],
) -> dict[str, Any] | None:
    """Mint an immutable external ReviewRecord from a core-executed gate only."""
    state = ctx.load()
    if str(state.get("runtime") or "").strip().casefold() != "codex":
        return None
    gate_id = str(evidence.get("gate_id") or "")
    expected_category = {
        "review.coderabbit": "independent",
        "review.coderabbit.test-integrity": "test-integrity",
    }.get(gate_id)
    if expected_category is None or review_output.get("review_category") != expected_category:
        raise InvalidState("automated external review category/gate mismatch")
    events = ctx.events()
    execution_id = str(execution.get("execution_id") or "")
    ledger_executions = [
        row
        for row in events
        if isinstance(row, dict)
        and row.get("event_type") == "gate_execution"
        and row.get("execution_id") == execution_id
    ]
    if (
        execution.get("contract") != "GateExecution/v3"
        or len(ledger_executions) != 1
        or not verify_record(execution)
        or not verify_record(ledger_executions[0])
        or any(
            ledger_executions[0].get(key) != value
            for key, value in execution.items()
        )
    ):
        raise InvalidState("automated external review GateExecution provenance invalid")
    latest_event = events[-1] if events else None
    execution_sequence = ledger_executions[0].get("sequence")
    result_sequence = latest_event.get("sequence") if isinstance(latest_event, dict) else None
    if (
        not isinstance(latest_event, dict)
        or latest_event.get("event_type") != "invocation_result"
        or latest_event.get("invocation_id")
        != evidence.get("collector_invocation_id")
        or latest_event.get("result") != "success"
        or not isinstance(execution_sequence, int)
        or not isinstance(result_sequence, int)
        or result_sequence != execution_sequence + 1
    ):
        raise InvalidState("automated external review is not the just-completed core execution")
    state_evidence = [
        row
        for row in state.get("evidence", [])
        if isinstance(row, dict)
        and row.get("evidence_id") == evidence.get("evidence_id")
    ]
    if len(state_evidence) != 1 or state_evidence[0] != evidence:
        raise InvalidState("automated external review evidence is not the persisted gate result")
    provenance_fields = (
        "evidence_id",
        "execution_id",
        "gate_id",
        "criterion_id",
        "goal_id",
        "goal_version",
        "collector",
        "collector_responsibility_group",
        "collector_invocation_id",
        "collector_identity_assurance",
        "collector_completion_eligible",
        "gate_grant_id",
        "source_snapshot_hash",
        "review_binding_input_sha256",
        "review_output_artifact",
        *_BINDING_FIELDS,
    )
    if any(evidence.get(field) != execution.get(field) for field in provenance_fields):
        raise InvalidState("automated external review evidence/execution binding mismatch")
    if (
        evidence.get("collector") != "supervisor-core"
        or evidence.get("collector_responsibility_group")
        != "trusted-core-gate-execution"
        or evidence.get("collector_identity_assurance") != "core-executed-gate"
        or evidence.get("collector_completion_eligible") is not True
        or evidence.get("exit_code") != 0
        or execution.get("status") != "success"
        or review_output != evidence.get("review_output_artifact")
        or review_output != execution.get("review_output_artifact")
    ):
        raise InvalidState("automated external review core collector provenance invalid")
    runner_invocation_id = str(evidence.get("collector_invocation_id") or "")
    if not _trusted_invocation_for_runtime(
        events,
        runner_invocation_id,
        actor="supervisor-core",
        responsibility_group="trusted-core-gate-execution",
        state=state,
    ):
        raise InvalidState("automated external review lacks a trusted core gate success")
    baseline = state.get("workspace_baseline")
    observed: dict[str, Any] | None = None
    if isinstance(baseline, dict):
        current = capture_workspace_snapshot(
            str(state.get("workspace") or ""),
            [
                value
                for value in baseline.get("extra_globs", [])
                if isinstance(value, str)
            ],
        )
        observed = workspace_delta(baseline, current)
    criterion_ids = {
        str(row.get("criterion_id"))
        for row in state.get("goal", {}).get("acceptance_criteria", [])
        if isinstance(row, dict) and row.get("criterion_id")
    }
    evidence_state = copy.deepcopy(state)
    evidence_state["evidence"] = [copy.deepcopy(evidence)]
    evidence_errors: list[str] = []
    _, verified_evidence, _ = _validate_evidence(
        evidence_state,
        criterion_ids,
        events,
        evidence_errors,
        observed,
    )
    if evidence_errors or evidence.get("evidence_id") not in verified_evidence:
        raise InvalidState("automated external review evidence failed core verification")
    summary = review_output.get("review_summary")
    if (
        not isinstance(summary, dict)
        or summary.get("engine") != "coderabbit"
        or summary.get("authenticated") is not True
        or summary.get("context_bound") is not True
        or summary.get("status") != "pass"
        or summary.get("blocking_findings") != 0
        or summary.get("severity_counts", {}).get("critical") != 0
        or summary.get("severity_counts", {}).get("major") != 0
    ):
        raise InvalidState("automated external review output is not an approval")
    changes = state.get("changes") if isinstance(state.get("changes"), dict) else {}
    if not changes.get("files"):
        return None
    if not (
        changes.get("implementer") == "codex-local-workspace"
        and changes.get("implementer_responsibility_group")
        == "local-workspace-producer"
        and changes.get("producer_identity_assurance")
        == "core-observed-local-workspace"
        and changes.get("issued_by") == "supervisor-core-workspace-observer"
        and verify_record(changes)
        and all(evidence.get(field) == changes.get(field) for field in _BINDING_FIELDS)
    ):
        raise InvalidState("automated external review lacks a core-observed producer binding")
    artifact_sha256 = canonical_sha256(review_output)
    review_id = f"review-coderabbit-{expected_category}-{str(execution.get('execution_id') or '')}"
    if any(
        isinstance(row, dict) and row.get("review_id") == review_id
        for row in state.get("reviews", [])
    ):
        raise InvalidState("automated external review id already exists")
    reviewer = (
        "coderabbit-test-integrity"
        if expected_category == "test-integrity"
        else "coderabbit"
    )
    reviewer_group = (
        "external-coderabbit-test-integrity"
        if expected_category == "test-integrity"
        else "external-coderabbit-independent-review"
    )
    goal = state.get("goal") if isinstance(state.get("goal"), dict) else {}
    findings = copy.deepcopy(summary.get("issues", []))
    review = {
        "contract": "ReviewRecord/v3",
        "review_id": review_id,
        "review_mode": "automated-external",
        "review_category": expected_category,
        "goal_id": goal.get("goal_id"),
        "goal_version": goal.get("version"),
        "reviewer": reviewer,
        "reviewer_responsibility_group": reviewer_group,
        "implementer": "codex-local-workspace",
        "implementer_responsibility_group": "local-workspace-producer",
        "gate_collector": "supervisor-core",
        "gate_collector_responsibility_group": "trusted-core-gate-execution",
        "gate_runner_invocation_id": evidence.get("collector_invocation_id"),
        **{field: changes.get(field) for field in _BINDING_FIELDS},
        "rerun_evidence_ids": [evidence.get("evidence_id")],
        "evidence_verification": {
            "status": "VERIFIED",
            "reviewer": "supervisor-core-external-review-validator",
            "evidence_ids": [evidence.get("evidence_id")],
        },
        "verdict": "APPROVE",
        "implementer_invocation_id": changes.get("implementer_invocation_id"),
        "reviewer_invocation_id": f"external-artifact-{artifact_sha256[:24]}",
        "actor_identity_assurance": "core-attested-external-review",
        "trust_domains": {
            "producer": "core-observed-codex-local-workspace",
            "reviewer": "authenticated-external-coderabbit",
            "gate_execution": "core-executed-registered-gate",
        },
        "external_review_artifact_sha256": artifact_sha256,
        "findings": findings,
        "unresolved_p0_p1": 0,
        "request_manifest_sha256": canonical_sha256(
            state.get("request_manifest", {})
        ),
        "issued_by": "supervisor-core-automated-external-review",
        "issued_at": utc_now(),
    }
    review["attestation"] = sign_record(review)
    event = {
        "contract": "ReviewFinalization/v3",
        "event_type": "review_finalized",
        "review_id": review_id,
        "review_sha256": canonical_sha256(review),
        "reviewer": reviewer,
        "verdict": "APPROVE",
        "review_category": expected_category,
        "issued_at": review["issued_at"],
        "transaction_id": stable_id("transaction"),
    }
    event["attestation"] = sign_record(event)

    def persist_review(state_value: dict[str, Any]) -> None:
        rows = state_value.setdefault("reviews", [])
        if not isinstance(rows, list):
            raise InvalidState("state.reviews must be an array")
        if any(
            isinstance(row, dict) and row.get("review_id") == review_id
            for row in rows
        ):
            raise InvalidState("automated external review id already exists")
        rows.append(copy.deepcopy(review))
        state_value["updated_at"] = utc_now()

    ctx.transact(persist_review, event)
    return review


def _finalize_review(ctx: StateContext, payload: dict[str, Any]) -> dict[str, Any]:
    request = _record_from_payload(payload, "review_finalize")
    if request.get("contract") != "ReviewRecord/v3":
        raise InvalidState("review_finalize requires ReviewRecord/v3 assertion")
    if any(key in request for key in ("attestation", "issued_by", "issued_at")):
        raise InvalidState("review_finalize core-issued fields are caller-forbidden")
    state = ctx.load()
    _verify_current_source_snapshot(ctx, state)
    events = ctx.events()
    reviewer = str(payload.get("actor") or "").strip()
    reviewer_group = str(request.get("reviewer_responsibility_group") or "").strip()
    reviewer_invocation_id = str(request.get("reviewer_invocation_id") or "").strip()
    gate_collector = str(request.get("gate_collector") or "").strip()
    gate_collector_group = str(request.get("gate_collector_responsibility_group") or "").strip()
    gate_runner_invocation_id = str(request.get("gate_runner_invocation_id") or "").strip()
    if not all((reviewer, reviewer_group, reviewer_invocation_id, gate_collector, gate_collector_group, gate_runner_invocation_id)):
        raise InvalidState("review_finalize reviewer and gate-runner identities are incomplete")
    if request.get("reviewer") != reviewer:
        raise InvalidState("review_finalize actor does not match reviewer assertion")
    _, results, invocation_errors = successful_invocations(events)
    if invocation_errors:
        raise InvalidState("review_finalize invocation ledger is inconsistent")
    reviewer_result = results.get(reviewer_invocation_id)
    runner_result = results.get(gate_runner_invocation_id)
    if (
        not isinstance(reviewer_result, dict)
        or reviewer_result.get("result") != "success"
        or reviewer_result.get("actor") != reviewer
        or not _trusted_invocation_for_runtime(
            events, reviewer_invocation_id, actor=reviewer,
            responsibility_group=reviewer_group, state=state
        )
    ):
        raise InvalidState("review_finalize reviewer lacks a successful trusted invocation")
    if (
        not isinstance(runner_result, dict)
        or runner_result.get("result") != "success"
        or runner_result.get("actor") != gate_collector
        or not _trusted_invocation_for_runtime(
            events, gate_runner_invocation_id, actor=gate_collector,
            responsibility_group=gate_collector_group, state=state
        )
    ):
        raise InvalidState("review_finalize gate runner lacks a successful trusted invocation")
    changes = state.get("changes") if isinstance(state.get("changes"), dict) else {}
    implementer = str(changes.get("implementer") or "")
    implementer_group = str(changes.get("implementer_responsibility_group") or "")
    if (
        not implementer
        or request.get("implementer") != implementer
        or request.get("implementer_responsibility_group") != implementer_group
    ):
        raise InvalidState("review_finalize implementer binding does not match changes")
    implementer_invocation_id = str(changes.get("implementer_invocation_id") or "")
    implementer_result = results.get(implementer_invocation_id)
    if (
        not isinstance(implementer_result, dict)
        or implementer_result.get("result") != "success"
        or implementer_result.get("actor") != implementer
        or not _trusted_invocation_for_runtime(
            events, implementer_invocation_id, actor=implementer,
            responsibility_group=implementer_group, state=state
        )
    ):
        raise InvalidState("review_finalize implementer lacks a successful trusted invocation")
    if (
        reviewer in {implementer, gate_collector}
        or gate_collector == implementer
        or reviewer_group in {implementer_group, gate_collector_group}
        or gate_collector_group == implementer_group
    ):
        raise InvalidState("review_finalize requires three independent identities and responsibility groups")
    if request.get("implementer_invocation_id") != implementer_invocation_id:
        raise InvalidState("review_finalize implementer invocation does not match changes")
    if any(request.get(field) != changes.get(field) for field in _BINDING_FIELDS):
        raise InvalidState("review_finalize assertion is not bound to the active changes")
    binding_errors: list[str] = []
    observed: dict[str, Any] | None = None
    baseline = (
        state.get("workspace_baseline")
        if isinstance(state.get("workspace_baseline"), dict)
        else None
    )
    workspace_path = Path(str(state.get("workspace") or ""))
    if isinstance(baseline, dict) and workspace_path.exists():
        current = capture_workspace_snapshot(
            str(workspace_path),
            [
                value for value in baseline.get("extra_globs", [])
                if isinstance(value, str)
            ],
        )
        observed = workspace_delta(baseline, current)
        if set(map(str, changes.get("files", []))) != set(map(str, observed.get("files", []))):
            binding_errors.append("changes files do not match the active workspace delta")
        for field in ("workspace_base_sha256", "workspace_head_sha256", "diff_hash"):
            if changes.get(field) != observed.get(field):
                binding_errors.append(f"changes {field} does not match the active workspace delta")
        if changes.get("git_binding_source") == "workspace":
            for field in (
                "base", "head", "git_object_format", "git_binding_status",
                "git_binding_source", "git_repository_root",
            ):
                if changes.get(field) != observed.get(field):
                    binding_errors.append(f"changes {field} does not match the active Git workspace")
    _validate_live_or_artifact_binding(
        state, changes, "review_finalize changes", binding_errors, observed=observed
    )
    if changes.get("git_binding_status") != "verified" or binding_errors:
        raise InvalidState("review_finalize changes binding failed core verification")
    rerun_ids = request.get("rerun_evidence_ids")
    if (
        not isinstance(rerun_ids, list)
        or not rerun_ids
        or not all(isinstance(value, str) and value.strip() for value in rerun_ids)
        or len(set(rerun_ids)) != len(rerun_ids)
    ):
        raise InvalidState("review_finalize rerun_evidence_ids invalid")
    evidence = {
        str(record.get("evidence_id")): record
        for record in state.get("evidence", [])
        if isinstance(record, dict) and record.get("evidence_id")
    }
    if not set(rerun_ids).issubset(evidence):
        raise InvalidState("review_finalize evidence is missing")
    criterion_ids = {
        str(row.get("criterion_id"))
        for row in state.get("goal", {}).get("acceptance_criteria", [])
        if isinstance(row, dict) and row.get("criterion_id")
    }
    evidence_state = copy.deepcopy(state)
    evidence_state["evidence"] = [copy.deepcopy(evidence[value]) for value in rerun_ids]
    evidence_errors: list[str] = []
    _, verified_evidence, _ = _validate_evidence(
        evidence_state, criterion_ids, events, evidence_errors, observed
    )
    if evidence_errors or not set(rerun_ids).issubset(verified_evidence):
        raise InvalidState("review_finalize rerun evidence failed core verification")
    for evidence_id in rerun_ids:
        record = evidence[evidence_id]
        if (
            record.get("collector") != gate_collector
            or record.get("collector_responsibility_group") != gate_collector_group
            or record.get("collector_invocation_id") != gate_runner_invocation_id
            or any(record.get(field) != changes.get(field) for field in _BINDING_FIELDS)
        ):
            raise InvalidState("review_finalize evidence is not bound to the declared independent gate runner")
    verification = request.get("evidence_verification")
    if (
        not isinstance(verification, dict)
        or verification.get("status") != "VERIFIED"
        or verification.get("reviewer") != reviewer
        or verification.get("evidence_ids") != rerun_ids
    ):
        raise InvalidState("review_finalize evidence verification assertion invalid")
    if request.get("verdict") not in {"APPROVE", "REQUEST_CHANGES", "NEEDS_DISCUSSION"}:
        raise InvalidState("review_finalize verdict invalid")
    goal = state.get("goal") if isinstance(state.get("goal"), dict) else {}
    if request.get("goal_id") != goal.get("goal_id") or request.get("goal_version") != goal.get("version"):
        raise InvalidState("review_finalize goal binding invalid")
    review_id = str(request.get("review_id") or "").strip()
    if not review_id or any(
        isinstance(record, dict) and record.get("review_id") == review_id
        for record in state.get("reviews", [])
    ):
        raise InvalidState("review_finalize review_id missing or already used")
    review = copy.deepcopy(request)
    review["actor_identity_assurance"] = reviewer_result.get("identity_assurance")
    review["request_manifest_sha256"] = canonical_sha256(state.get("request_manifest", {}))
    review["issued_by"] = "supervisor-core-review-finalize"
    review["issued_at"] = utc_now()
    review["attestation"] = sign_record(review)
    event = {
        "contract": "ReviewFinalization/v3",
        "event_type": "review_finalized",
        "review_id": review_id,
        "review_sha256": canonical_sha256(review),
        "reviewer": reviewer,
        "verdict": review.get("verdict"),
        "issued_at": review["issued_at"],
        "transaction_id": stable_id("transaction"),
    }
    event["attestation"] = sign_record(event)

    def persist(state_value: dict[str, Any]) -> None:
        rows = state_value.setdefault("reviews", [])
        if not isinstance(rows, list):
            raise InvalidState("state.reviews must be an array")
        rows.append(copy.deepcopy(review))
        state_value["updated_at"] = utc_now()

    ctx.transact(persist, event)
    return review


def command_event(args: argparse.Namespace) -> int:
    ctx = _context(args, require_existing=True)
    payload = _clean_event_payload(args)
    event_type = str(payload.get("event_type") or "event")
    if event_type == "gate_execution":
        raise InvalidState("gate_execution is reserved for the trusted core runner")
    if event_type == "rollout_observation":
        raise InvalidState("rollout_observation is reserved for trusted core executions/finalization")
    if event_type == "review_record":
        raise InvalidState("review_record is forbidden; use core-issued review_finalize")
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
    if event_type == "review_finalize":
        review = _finalize_review(ctx, payload)
        _emit({
            "ok": True,
            "review_id": review["review_id"],
            "verdict": review["verdict"],
            "issued_by": review["issued_by"],
            "state_file": str(ctx.state_file),
        })
        return EXIT_COMPLETE
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
    if event_type == "changes_record" and str(ctx.runtime).strip().casefold() == "codex":
        state_for_changes = ctx.load()
        _verify_current_source_snapshot(ctx, state_for_changes)
        caller_request = _record_from_payload(payload, event_type)
        payload["record"] = _core_codex_changes_record(
            state_for_changes, caller_request
        )
    if event_type == "handoff_requested":
        live_state = ctx.load()
        payload["goal_drift"] = goal_drift_report(live_state)
        payload["summary"] = str(payload.get("summary") or "phase-transition")
        payload["reason"] = str(payload.get("reason") or payload.get("summary") or "phase-transition")
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
        breaker_state = ctx.load()
        breaker = breaker_state.get("capability_breakers", {}).get(capability, {})
        if isinstance(breaker, dict) and breaker.get("open") is True:
            fallback_id = _breaker_fallback_id(
                breaker_state, capability, breaker
            )
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
            responsibility_group=(
                str(payload.get("responsibility_group") or "").strip() or None
            ),
        )
    elif is_result:
        if not invocation_id or not capability or args.result not in {
            "success", "failed", "refused", "cancelled", "manual-specialized", "methodology-only",
        }:
            raise InvalidState("invocation result requires id, capability, and a supported result")
        payload = invocation_event(
            invocation_id=invocation_id,
            capability=capability,
            stage="result",
            result=args.result,
            actor=str(payload.get("actor") or ctx.runtime),
            details=invocation_details,
            identity_assurance=invocation_assurance,
            responsibility_group=(
                str(payload.get("responsibility_group") or "").strip() or None
            ),
        )
    record_id: str | None = None
    needs_state_update = is_result or event_type in {
        "task_record", "task_upsert", "evidence_record", "claim_record",
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
    if event_type == "handoff_requested":
        emit_stage_checkpoint(
            ctx,
            ctx.load(),
            reason=str(payload.get("reason") or "phase-transition"),
            actor=str(payload.get("actor") or ctx.runtime),
        )
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
        from .validation import _profile_gates, _registered_gate_definitions, _test_paths_changed

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
        if _test_paths_changed(changes):
            required.add("review.coderabbit.test-integrity")
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
            _run_finalize_builtin_gate(
                ctx,
                ctx.load(),
                gate_id=gate_id,
                criterion_id=str(criterion["criterion_id"]),
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
    summary = build_round_process_summary(state, events)
    return render_round_process_summary(summary)


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


def _execute_selftest(
    root: Path,
    base_temp: Path,
    *,
    environment: dict[str, str] | None = None,
) -> int:
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
            env=environment,
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
            env=environment,
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
    try:
        registry = load_trusted_executable_registry()
    except (ExecutableTrustError, OSError, RuntimeError, ValueError) as exc:
        _emit({"ok": False, "health": "degraded", "reason": type(exc).__name__})
        return EXIT_DEGRADED
    data_root = Path(str(registry["registry_path"])).parent
    temp_parent = data_root / ".selftest-tmp"
    temp_parent.mkdir(parents=True, exist_ok=True)
    base_temp = temp_parent / f"selftest-{os.getpid()}-{sha256_text(utc_now())[:8]}"
    base_temp.mkdir(parents=False, exist_ok=False)
    extracted: tempfile.TemporaryDirectory[str] | None = None
    try:
        resources = bound_resource_map()
        if resources is None:
            root = Path(__file__).resolve().parents[1]
        else:
            extracted = tempfile.TemporaryDirectory(
                prefix="bound-runtime-", dir=temp_parent
            )
            root = Path(extracted.name)
            for relative, content in sorted(resources.items()):
                path = PurePosixPath(relative)
                if (
                    path.is_absolute()
                    or any(part in {"", ".", ".."} for part in path.parts)
                    or not isinstance(content, bytes)
                ):
                    raise InvalidState("bound selftest resource path is invalid")
                target = root.joinpath(*path.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
            if not (root / "tests").is_dir():
                _emit({
                    "ok": False,
                    "health": "degraded",
                    "reason": "bound-runtime-test-bundle-missing",
                })
                return EXIT_DEGRADED
        environment = _isolated_review_environment(registry)
        environment.update({
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": str(root),
            "TEMP": str(base_temp),
            "TMP": str(base_temp),
        })
        return _execute_selftest(root, base_temp, environment=environment)
    finally:
        # Collection failures, execution failures, result processing, and
        # output failures all share the same bounded cleanup guarantee.
        shutil.rmtree(base_temp, ignore_errors=True)
        if extracted is not None:
            extracted.cleanup()


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


def _routing_intents_for_start(
    state: dict[str, Any], raw_atomic_intents: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Combine locked prior routing with raw current intents only in memory."""
    persisted = state.get("intents")
    if not isinstance(persisted, list) or not persisted:
        return copy.deepcopy(raw_atomic_intents)
    carried: list[dict[str, Any]] = []
    current: list[dict[str, Any]] = []
    for row in persisted:
        if not isinstance(row, dict):
            continue
        copied = copy.deepcopy(row)
        if copied.get("carried_from_goal_version") is not None:
            copied["_preserve_routing"] = True
            carried.append(copied)
        else:
            current.append(copied)
    if len(current) != len(raw_atomic_intents):
        raise InvalidState("current atomic intent count changed before routing")
    for persisted_row, raw_row in zip(current, raw_atomic_intents):
        merged = copy.deepcopy(persisted_row)
        for key in (
            "text",
            "domain",
            "role",
            "required_responsibility_groups",
            "depends_on_intent_ids",
        ):
            if key in raw_row:
                merged[key] = copy.deepcopy(raw_row[key])
        carried.append(merged)
    return carried


def _privacy_safe_capability_route(
    route: dict[str, Any], state: dict[str, Any], prompt: str
) -> dict[str, Any]:
    """Replace transient route prose with the state contract's opaque labels."""
    safe = copy.deepcopy(route)
    safe["message"] = f"sha256:{sha256_text(prompt)}"
    safe_text_by_id = {
        str(row.get("intent_id") or ""): str(row.get("text") or "")
        for row in state.get("intents", [])
        if isinstance(row, dict) and row.get("intent_id")
    }
    coverage = safe.get("coverage")
    if isinstance(coverage, list):
        for row in coverage:
            if not isinstance(row, dict):
                continue
            intent_id = str(row.get("intent_id") or "")
            persisted_text = safe_text_by_id.get(intent_id)
            if persisted_text:
                row["text"] = persisted_text
            else:
                row["text"] = f"Host intent sha256:{sha256_text(str(row.get('text') or ''))}"
    return safe


def _privacy_safe_prompt_contract(
    prompt: str,
    project_config: dict[str, Any],
    atomic_intents: list[dict[str, Any]] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]], bool]:
    """Derive a useful hash-bound contract without persisting the raw host prompt."""
    privacy = (
        project_config.get("privacy")
        if isinstance(project_config.get("privacy"), dict)
        else {}
    )
    atomic = normalize_intents(
        atomic_intents if atomic_intents is not None else split_intents(prompt),
        prompt,
    )
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
            "contract": "IntentCoverage/v3",
            "intent_id": str(intent.get("intent_id") or f"intent-{index}"),
            "text": safe_text,
            "status": str(intent.get("status") or "deferred"),
            "reason": "awaiting routing",
            "capability_ids": copy.deepcopy(intent.get("capability_ids", [])),
            "method": str(intent.get("method") or "capability"),
            "phase": int(intent.get("phase") or 0),
            "domain": domain,
            "role": str(intent.get("role") or ""),
            "required_responsibility_groups": copy.deepcopy(
                intent.get("required_responsibility_groups", [])
            ),
            "depends_on_intent_ids": copy.deepcopy(
                intent.get("depends_on_intent_ids", [])
            ),
        }
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


def _timeline_kind_for_tool(tool_name: str) -> str | None:
    marker = _normalized_tool_marker(tool_name)
    if marker in _WRITE_TOOL_MARKERS or marker in {
        "applypatch", "execcommand", "bash", "shell", "pwsh", "powershell", "cmd",
    }:
        return "native_command"
    return None


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


_T3_RISK_CATEGORIES = {
    "force-push",
    "recursive-delete",
    "db-migration",
    "deploy",
    "secret-mutation",
    "billing",
    "mail-send",
    "money-trade",
}
_WRITE_RISK_CATEGORIES = {
    "write-lease",
    "write-scope",
    "apply-patch-parse",
}


def _risk_tier_for_category(category: str | None) -> str:
    if not category:
        return "none"
    if category in _T3_RISK_CATEGORIES:
        return "t3"
    if category in _WRITE_RISK_CATEGORIES:
        return "write"
    return "none"


def _stamp_pretool_policy(policy: dict[str, Any]) -> dict[str, Any]:
    stamped = dict(policy)
    stamped.setdefault("risk_tier", _risk_tier_for_category(str(stamped.get("category") or "") or None))
    return stamped


def _goal_criterion_ids(goal: dict[str, Any]) -> set[str]:
    return {
        str(row.get("criterion_id") or "").strip()
        for row in goal.get("acceptance_criteria") or []
        if isinstance(row, dict) and str(row.get("criterion_id") or "").strip()
    }


def _lease_criterion_ids(task: dict[str, Any]) -> list[str]:
    return [
        str(item).strip()
        for item in task.get("criterion_ids") or []
        if str(item).strip()
    ]


def goal_drift_report(state: dict[str, Any]) -> dict[str, Any]:
    """Compare the live GoalContract against the signed request_manifest."""
    goal = state.get("goal") if isinstance(state.get("goal"), dict) else {}
    manifest = state.get("request_manifest") if isinstance(state.get("request_manifest"), dict) else {}
    current_hash = canonical_sha256(goal) if goal else ""
    bound_hash = str(manifest.get("goal_sha256") or "")
    id_mismatch = bool(manifest) and (
        str(manifest.get("goal_id") or "") != str(goal.get("goal_id") or "")
        or (
            manifest.get("goal_version") is not None
            and manifest.get("goal_version") != goal.get("version")
        )
    )
    hash_mismatch = bool(bound_hash and current_hash and bound_hash != current_hash)
    drifted = id_mismatch or hash_mismatch
    return {
        "status": "drift" if drifted else "aligned",
        "goal_id": goal.get("goal_id"),
        "goal_version": goal.get("version"),
        "change_mode": goal.get("change_mode"),
        "goal_sha256": current_hash or None,
        "request_manifest_goal_sha256": bound_hash or None,
        "reason": (
            "goal contract diverged from signed request_manifest"
            if drifted
            else "goal aligned with signed request_manifest"
        ),
    }


def emit_stage_checkpoint(
    ctx: StateContext,
    state: dict[str, Any],
    *,
    reason: str,
    actor: str,
) -> dict[str, Any]:
    """Persist a short handoff and a structured drift check before a risky stage."""
    drift = goal_drift_report(state)
    summary = build_round_process_summary(state, ctx.events())
    handoff_text = render_round_process_summary(summary)
    handoff_written = False
    try:
        default_output = (
            Path(ctx.workspace)
            / ".agent-supervisor"
            / "handoffs"
            / sha256_text(str(ctx.session))
            / "latest.md"
        )
        output = resolve_handoff_output_path(ctx.workspace, ctx.session, str(default_output))
        output.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_bytes(output, handoff_text.encode("utf-8"))
        handoff_written = True
    except (OSError, TypeError, ValueError):
        handoff_written = False
    event = {
        "event_type": "stage_checkpoint",
        "status": "drift" if drift["status"] == "drift" else "recorded",
        "reason": reason,
        "actor": actor,
        "goal_drift": drift,
        "handoff_sha256": sha256_text(handoff_text),
        "handoff_written": handoff_written,
        "summary_contract": "RoundProcessSummary/v1",
        "goal_id": drift.get("goal_id"),
        "goal_version": drift.get("goal_version"),
    }
    return ctx.append_event(event)


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


def _evaluate_pretool_policy(
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
    bound_criteria: list[str] = []
    goal_criteria = _goal_criterion_ids(goal_contract)
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
        covering = [
            task
            for task in active_leases
            if path_matches_lease(relative, list(task.get("allowed_paths", [])))
        ]
        if not covering:
            return {
                "deny": True,
                "hard_deny": False,
                "category": "write-lease",
                "status": "denied",
                "path_sha256": sha256_text(relative),
                "reason": "no active lease owned by this actor covers the canonical write path",
            }
        path_bound = [
            criterion_id
            for task in covering
            for criterion_id in _lease_criterion_ids(task)
            if not goal_criteria or criterion_id in goal_criteria
        ]
        if goal_criteria and not path_bound:
            return {
                "deny": True,
                "hard_deny": False,
                "category": "write-lease",
                "status": "denied",
                "path_sha256": sha256_text(relative),
                "goal_id": goal_contract.get("goal_id"),
                "goal_version": goal_contract.get("version"),
                "criterion_ids": [],
                "reason": "active lease is not bound to a current goal criterion",
            }
        bound_criteria.extend(path_bound)
    unique_criteria = list(dict.fromkeys(bound_criteria))
    return {
        "deny": False,
        "hard_deny": False,
        "category": "write-lease",
        "status": "authorized",
        "path_sha256": path_hashes[0] if len(path_hashes) == 1 else sha256_text("\n".join(path_hashes)),
        "goal_id": goal_contract.get("goal_id"),
        "goal_version": goal_contract.get("version"),
        "criterion_ids": unique_criteria,
        "reason": "all canonical write paths are covered by an active actor-owned lease",
    }


def _pretool_policy(
    state: dict[str, Any], *, tool_name: str, tool_input: dict[str, Any], actor: str
) -> dict[str, Any]:
    return _stamp_pretool_policy(
        _evaluate_pretool_policy(
            state, tool_name=tool_name, tool_input=tool_input, actor=actor
        )
    )


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
            raw_atomic_intents = normalize_intents(
                split_intents(prompt), prompt
            )
            if not raw_atomic_intents:
                raw_atomic_intents = normalize_intents(
                    [{"text": prompt, "domain": "general"}], prompt
                )
            safe_goal, safe_intents, raw_prompt_withheld = _privacy_safe_prompt_contract(
                prompt, config, raw_atomic_intents
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
            _reject_sensitive_contract_input(
                {"project_config": config, "quality_profile": quality},
                "UserPromptSubmit project contract",
            )
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
            state, registry_degraded = _initialize_executable_registry(
                ctx, state, shadow=False
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
            route: dict[str, Any] | None = None
            try:
                roots, inventory, discovery = _trusted_capability_discovery(
                    config, ctx.workspace, ns.runtime, []
                )
                supplied_intents = _routing_intents_for_start(
                    state, raw_atomic_intents
                )
                routed = route_intents(
                    message=prompt,
                    inventory=inventory,
                    supplied_intents=supplied_intents,
                    phase_budget=3,
                    zero_skill_reviewed=False,
                )
                route = (
                    _privacy_safe_capability_route(routed, state, prompt)
                    if raw_prompt_withheld
                    else routed
                )
                route["inventory_sha256"] = discovery["inventory_sha256"]

                def persist_capabilities(current: dict[str, Any]) -> None:
                    current["capability_inventory"] = copy.deepcopy(inventory)
                    current["discovery"] = copy.deepcopy(discovery)
                    current["capability_route"] = copy.deepcopy(route)
                    current["intents"] = copy.deepcopy(route.get("coverage", []))
                    current["updated_at"] = utc_now()

                state = ctx.update(persist_capabilities)
            except Exception as exc:
                degradation = {
                    "contract": "CapabilityBootstrapDegradation/v3",
                    "stage": "native-hook-bootstrap",
                    "reason_code": "capability-native-hook-bootstrap-failed",
                    "error_type": type(exc).__name__,
                    "recorded_at": utc_now(),
                }
                state = ctx.update(lambda current: current.update({
                    "health": "degraded",
                    "capability_bootstrap_degradation": degradation,
                    "updated_at": utc_now(),
                }))
            if isinstance(adapter, dict) and adapter.get("degraded_prior") is True:
                state = ctx.update(lambda current: current.update({"health": "degraded", "updated_at": utc_now()}))
                ctx.append_event({"event_type": "adapter_recovered", "status": "degraded", "degraded_prior": True, "adapter_version": adapter.get("adapter_version")})
            route_phases = route.get("phases", []) if isinstance(route, dict) else []
            route_context = json.dumps(route_phases, ensure_ascii=False, separators=(",", ":"))
            print(json.dumps({"hookSpecificOutput": {
                "hookEventName": "UserPromptSubmit",
                "additionalContext": (
                    f"Supervisor v3 goal {state['goal']['goal_id']} v{state['goal']['version']} "
                    f"started in {state['execution_mode']} mode. Execute the complete ordered Skill route; "
                    f"scheduled is not success: {route_context}"
                ),
            }}, ensure_ascii=False))
            if registry_degraded or route is None:
                return EXIT_DEGRADED
            return EXIT_COMPLETE if route.get("valid") else EXIT_INCOMPLETE
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
                "identity_assurance": _hook_identity_assurance(args.runtime),
                "identity_provenance": (
                    "caller-declared-local-observation"
                    if str(args.runtime).strip().casefold() == "codex"
                    else "host-lifecycle-observation"
                ),
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
        raw_responsibility_group = (
            tool_input.get("responsibility_group")
            or payload.get("responsibility_group")
        )
        host_responsibility_group = (
            str(raw_responsibility_group).strip()
            if raw_responsibility_group is not None
            else None
        ) or None
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
                goal_row = state.get("goal") if isinstance(state.get("goal"), dict) else {}
                ctx.append_event({
                    "event_type": "pretool_policy",
                    "invocation_id": invocation_id,
                    "category": policy.get("category"),
                    "risk_tier": policy.get("risk_tier") or _risk_tier_for_category(
                        str(policy.get("category") or "") or None
                    ),
                    "status": effective_status,
                    "policy_status": policy.get("status"),
                    "execution_mode": execution_mode,
                    "would_deny": would_deny,
                    "hard_deny": policy.get("hard_deny") is True,
                    "goal_id": policy.get("goal_id") or goal_row.get("goal_id"),
                    "goal_version": (
                        policy.get("goal_version")
                        if policy.get("goal_version") is not None
                        else goal_row.get("version")
                    ),
                    "criterion_ids": list(policy.get("criterion_ids") or []),
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
                fallback_id = _breaker_fallback_id(
                    state, capability_name, breaker
                )
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
                        "additionalContext": f"Supervisor circuit open for {capability_name}; {('use verified fallback ' + fallback_id) if fallback_id else 'no inventory-verified fallback is available'}. The original capability will not count as success.",
                    }
                }
                if execution_mode == "enforce":
                    output["hookSpecificOutput"].update({
                        "permissionDecision": "deny",
                        "permissionDecisionReason": f"Capability circuit open; {('route to verified fallback ' + fallback_id) if fallback_id else 'no verified fallback is available'}.",
                    })
                print(json.dumps(output, ensure_ascii=False))
                return EXIT_COMPLETE
            attempt_details = {"summary": f"{tool_name} attempt", **_invocation_state_binding(state)}
            tool_kind = _timeline_kind_for_tool(tool_name)
            if tool_kind:
                attempt_details["kind"] = tool_kind
            ctx.append_event(invocation_event(
                invocation_id=invocation_id, capability=capability_name, stage="attempt", result=None,
                actor=host_actor,
                details=attempt_details,
                identity_assurance=_hook_identity_assurance(args.runtime),
                responsibility_group=host_responsibility_group,
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
            result_details = {"summary": f"{tool_name} completed", **_invocation_state_binding(state)}
            tool_kind = _timeline_kind_for_tool(tool_name)
            if tool_kind:
                result_details["kind"] = tool_kind
            ctx.append_event(invocation_event(
                invocation_id=invocation_id, capability=capability_name, stage="result", result=result_name,
                actor=host_actor,
                details=result_details,
                identity_assurance=_hook_identity_assurance(args.runtime),
                responsibility_group=host_responsibility_group,
            ))
            print("{}")
            return EXIT_COMPLETE
        if args.event == "PreCompact":
            emit_stage_checkpoint(
                ctx, state, reason="precompact", actor=host_actor,
            )
            print("{}")
            return EXIT_COMPLETE
        if args.event == "SubagentStart":
            emit_stage_checkpoint(
                ctx, state, reason="subagent_start", actor=host_actor,
            )
            ctx.append_event({
                "event_type": "subagent_start",
                "status": "observed",
                "actor": host_actor,
                "capability": capability_name,
                "identity_assurance": _hook_identity_assurance(args.runtime),
                "identity_provenance": (
                    "caller-declared-local-observation"
                    if str(args.runtime).strip().casefold() == "codex"
                    else "host-lifecycle-observation"
                ),
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
                    "identity_assurance": _hook_identity_assurance(args.runtime),
                    "identity_provenance": (
                        "caller-declared-local-observation"
                        if str(args.runtime).strip().casefold() == "codex"
                        else "host-lifecycle-observation"
                    ),
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
    parser.add_argument("--version", action="version", version="3.1.1")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("start")
    _add_namespace(p)
    p.add_argument("--message", required=True)
    p.add_argument("--change-mode", choices=("continue", "extend", "replace"), required=True)
    p.add_argument("--execution-mode", choices=("observe", "warn", "enforce"), default="warn")
    p.add_argument("--goal-json")
    p.add_argument("--criteria-json")
    p.add_argument("--intents-json")
    p.add_argument("--roots", nargs="*")
    p.add_argument("--phase-budget", type=int, choices=(2, 3), default=3)
    p.add_argument("--zero-skill-reviewed", action="store_true")
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
    p.add_argument("--responsibility-group")
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
