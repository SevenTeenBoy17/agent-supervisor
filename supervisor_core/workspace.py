from __future__ import annotations

import json
import fnmatch
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Any

from .util import sha256_bytes, sha256_text, utc_now


_GIT_TIMEOUT_SECONDS = 15

_CORE_SOURCE_WHITELIST = (
    "bin/agent-supervisor.py",
    "supervisor_core/__init__.py",
    "supervisor_core/__main__.py",
    "supervisor_core/attestation.py",
    "supervisor_core/cli.py",
    "supervisor_core/constants.py",
    "supervisor_core/contracts.py",
    "supervisor_core/discovery.py",
    "supervisor_core/finalize.py",
    "supervisor_core/lifecycle.py",
    "supervisor_core/rollout.py",
    "supervisor_core/routing.py",
    "supervisor_core/schemas/project-config.schema.json",
    "supervisor_core/schemas/quality-profile.schema.json",
    "supervisor_core/storage.py",
    "supervisor_core/util.py",
    "supervisor_core/validation.py",
    "supervisor_core/workspace.py",
)

_CLAUDE_ADAPTER_WHITELIST = (
    "sup-v3-hook.py",
    "sup-selftest.py",
    "sup-discover.py",
)

_CODEX_ADAPTER_WHITELIST = (
    "codex-supervisor-hook.py",
    "supervisor-bootstrap.ps1",
    "supervisor-core.ps1",
    "supervisor-event.ps1",
    "supervisor-finalize.ps1",
    "supervisor-gate.ps1",
    "supervisor-handoff.ps1",
    "supervisor-record.ps1",
    "supervisor-turn-ended.ps1",
    "supervisor-validate.ps1",
)


def _required_supervisor_source_names() -> set[str]:
    return {
        *(f"shared-core/{relative}" for relative in _CORE_SOURCE_WHITELIST),
        *(f"codex-adapter/{filename}" for filename in _CODEX_ADAPTER_WHITELIST),
        *(f"claude-adapter/{filename}" for filename in _CLAUDE_ADAPTER_WHITELIST),
    }


def _absolute_path(path: Path) -> Path:
    """Return a lexical absolute path without following a link/reparse target."""
    return Path(os.path.abspath(os.fspath(path)))


def _supervisor_source_roots() -> dict[str, Path]:
    # Hooks may deliberately redirect their state HOME for isolation tests or
    # portable deployments.  Source identity must still bind to the actual
    # installed adapters, not to that writable state location.
    install_home = os.environ.get("AGENT_SUPERVISOR_INSTALL_HOME")
    home = _absolute_path(Path(install_home)) if install_home else _absolute_path(Path.home())
    if home.name.casefold() in {".claude", ".codex"}:
        home = home.parent
    return {
        "shared-core": _absolute_path(Path(__file__).parent.parent),
        "codex-adapter": _absolute_path(home / ".codex" / "skills" / "dev-supervisor" / "scripts"),
        "claude-adapter": _absolute_path(home / ".claude" / "skills" / "supervisor" / "scripts"),
    }


def _runtime_only_path(relative: str) -> bool:
    parts = tuple(part.casefold() for part in Path(relative.replace("\\", "/")).parts)
    if not parts:
        return False
    if parts[0] == ".codex-supervisor":
        return True
    if "__pycache__" in parts and parts[-1].endswith((".pyc", ".pyo")):
        return True
    if parts[0] != ".agent-supervisor" or len(parts) < 2:
        return False
    if parts[1] == ".pytest_cache" or parts[1].startswith(".pytest-tmp"):
        return True
    return parts[1] in {
        "handoffs", "state", "logs", "spool", "cache",
        "timeline.jsonl", "ledger.json", "status.md", "context-snapshot.md",
        "current-goal.md", "handoff.md", ".attestation-key",
    }


def _git(workspace: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    command = ["git", "-C", str(workspace), *args]
    try:
        return subprocess.run(
            command,
            capture_output=True,
            check=False,
            timeout=_GIT_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(command, 124, b"", b"agent-supervisor:git-timeout")
    except OSError:
        return subprocess.CompletedProcess(command, 127, b"", b"agent-supervisor:git-unavailable")


def _git_runtime_failure(result: subprocess.CompletedProcess[bytes]) -> str | None:
    if result.returncode == 124 and b"agent-supervisor:git-timeout" in (result.stderr or b""):
        return "git-timeout"
    if result.returncode == 127 and b"agent-supervisor:git-unavailable" in (result.stderr or b""):
        return "git-unavailable"
    return None


def _is_reparse_point(path: Path) -> bool:
    try:
        value = path.lstat()
    except OSError:
        return False
    return bool(
        stat.S_ISLNK(value.st_mode)
        or (
            hasattr(value, "st_file_attributes")
            and bool(value.st_file_attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
        )
    )


def _path_has_reparse(root: Path, path: Path) -> bool:
    root = _absolute_path(root)
    path = _absolute_path(path)
    try:
        relative = path.relative_to(root)
    except ValueError:
        return True
    current = root
    if _is_reparse_point(current):
        return True
    for part in relative.parts:
        current = current / part
        if _is_reparse_point(current):
            return True
    return False


def _source_file_record(root: Path, path: Path, logical_name: str) -> dict[str, Any]:
    root = _absolute_path(root)
    path = _absolute_path(path)
    try:
        path.relative_to(root)
    except ValueError:
        return {"status": "rejected-escape", "sha256": sha256_text(f"rejected-escape:{logical_name}")}
    if _path_has_reparse(root, path):
        return {"status": "rejected-reparse", "sha256": sha256_text(f"rejected-reparse:{logical_name}")}
    if not path.exists():
        return {"status": "missing", "sha256": sha256_text(f"missing:{logical_name}")}
    try:
        if not path.is_file():
            return {"status": "rejected-non-file", "sha256": sha256_text(f"non-file:{logical_name}")}
        content = path.read_bytes()
    except OSError:
        return {"status": "unreadable", "sha256": sha256_text(f"unreadable:{logical_name}")}
    return {"status": "hashed", "sha256": sha256_bytes(content), "size": len(content)}


def capture_supervisor_source_snapshot() -> dict[str, Any]:
    """Hash only trusted Supervisor source/adapters, never a caller-supplied path."""
    roots = {name: _absolute_path(path) for name, path in _supervisor_source_roots().items()}
    files: dict[str, dict[str, Any]] = {}
    required_names = _required_supervisor_source_names()

    core_root = roots["shared-core"]
    for relative in _CORE_SOURCE_WHITELIST:
        logical = f"shared-core/{relative}"
        files[logical] = _source_file_record(core_root, core_root / relative, logical)

    codex_root = roots["codex-adapter"]
    for filename in _CODEX_ADAPTER_WHITELIST:
        path = codex_root / filename
        logical = f"codex-adapter/{filename}"
        files[logical] = _source_file_record(codex_root, path, logical)

    claude_root = roots["claude-adapter"]
    for filename in _CLAUDE_ADAPTER_WHITELIST:
        path = claude_root / filename
        logical = f"claude-adapter/{filename}"
        files[logical] = _source_file_record(claude_root, path, logical)

    files = {name: files[name] for name in sorted(files)}
    unhealthy = any(
        files[name].get("status") != "hashed"
        for name in required_names
    )
    payload: dict[str, Any] = {
        "contract": "SupervisorSourceSnapshot/v3",
        "status": "degraded" if unhealthy else "healthy",
        "roots": {name: str(roots[name]) for name in sorted(roots)},
        "files": files,
    }
    payload["snapshot_sha256"] = sha256_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    )
    return payload


def validated_supervisor_source_snapshot_hash(snapshot: Any) -> str | None:
    """Return the trusted self-hash only for a complete, healthy source snapshot."""
    if not isinstance(snapshot, dict):
        return None
    observed = str(snapshot.get("snapshot_sha256") or "")
    if not re.fullmatch(r"[0-9a-f]{64}", observed):
        return None
    unsigned = {key: value for key, value in snapshot.items() if key != "snapshot_sha256"}
    calculated = sha256_text(
        json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    )
    if calculated != observed:
        return None
    files = snapshot.get("files")
    required_names = _required_supervisor_source_names()
    if (
        snapshot.get("contract") != "SupervisorSourceSnapshot/v3"
        or snapshot.get("status") != "healthy"
        or not isinstance(snapshot.get("roots"), dict)
        or not isinstance(files, dict)
        or set(files) != required_names
        or any(
            not isinstance(files.get(name), dict) or files[name].get("status") != "hashed"
            for name in required_names
        )
    ):
        return None
    return observed


def canonical_workspace_path(workspace: str, value: Any) -> str | None:
    """Return a safe workspace-relative path, rejecting traversal and reparses."""
    if not isinstance(workspace, str) or not workspace.strip() or "\x00" in workspace:
        return None
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        return None
    raw = Path(value.strip()).expanduser()
    if ".." in raw.parts:
        return None
    root = _absolute_path(Path(workspace))
    candidate = _absolute_path(raw if raw.is_absolute() else root / raw)
    try:
        relative = candidate.relative_to(root)
    except ValueError:
        return None
    if not relative.parts or _path_has_reparse(root, candidate):
        return None
    try:
        resolved_root = root.resolve(strict=True)
        resolved_candidate = candidate.resolve(strict=False)
        resolved_candidate.relative_to(resolved_root)
    except (OSError, RuntimeError, ValueError):
        return None
    return relative.as_posix()


def segment_glob_match(path: str, pattern: str) -> bool:
    """Match slash-delimited paths where ``*`` is local and ``**`` recurses."""
    path_parts = tuple(path.replace("\\", "/").split("/"))
    pattern_parts = tuple(pattern.replace("\\", "/").split("/"))
    memo: dict[tuple[int, int], bool] = {}

    def matches(path_index: int, pattern_index: int) -> bool:
        key = (path_index, pattern_index)
        if key in memo:
            return memo[key]
        if pattern_index == len(pattern_parts):
            result = path_index == len(path_parts)
        elif pattern_parts[pattern_index] == "**":
            result = matches(path_index, pattern_index + 1) or (
                path_index < len(path_parts) and matches(path_index + 1, pattern_index)
            )
        else:
            result = (
                path_index < len(path_parts)
                and fnmatch.fnmatchcase(path_parts[path_index], pattern_parts[pattern_index])
                and matches(path_index + 1, pattern_index + 1)
            )
        memo[key] = result
        return result

    return matches(0, 0)


def path_matches_lease(relative: str, patterns: list[str]) -> bool:
    normalized = relative.replace("\\", "/")
    for raw_pattern in patterns:
        if not isinstance(raw_pattern, str) or not raw_pattern.strip():
            continue
        pattern_path = Path(raw_pattern.replace("\\", "/"))
        if pattern_path.is_absolute() or ".." in pattern_path.parts:
            continue
        pattern = "/".join(part for part in pattern_path.parts if part not in {"", "."})
        if not pattern:
            continue
        if segment_glob_match(normalized, pattern):
            return True
    return False


def resolve_handoff_output_path(workspace: str, session: str, output: str) -> Path:
    if not isinstance(workspace, str) or not workspace.strip() or "\x00" in workspace:
        raise ValueError("query output workspace is empty or invalid")
    if not isinstance(output, str) or not output.strip() or "\x00" in output:
        raise ValueError("query output path is empty or invalid")
    raw = Path(output.strip()).expanduser()
    if ".." in raw.parts:
        raise ValueError("query output traversal is forbidden")
    workspace_root = _absolute_path(Path(workspace))
    allowed_root = workspace_root / ".agent-supervisor" / "handoffs" / sha256_text(session)
    candidate = _absolute_path(raw if raw.is_absolute() else workspace_root / raw)
    try:
        relative = candidate.relative_to(allowed_root)
    except ValueError as exc:
        raise ValueError("query output must stay inside the session handoff directory") from exc
    if not relative.parts:
        raise ValueError("query output must name a file inside the session handoff directory")
    if _path_has_reparse(workspace_root, candidate):
        raise ValueError("query output path contains a symlink or reparse point")
    try:
        resolved_workspace = workspace_root.resolve(strict=True)
        candidate.resolve(strict=False).relative_to(resolved_workspace)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError("query output escapes the canonical workspace") from exc
    return candidate


def _hash_workspace_entry(root: Path, path: Path, relative: str) -> str | None:
    current = path
    while current != root:
        parent = current.parent
        if parent == current:
            return sha256_text(f"unsafe-or-unreadable-entry:{relative}")
        if _is_reparse_point(current):
            try:
                target = os.readlink(current)
            except OSError:
                target = "opaque-reparse-point"
            try:
                link_name = current.relative_to(root).as_posix()
            except ValueError:
                return sha256_text(f"unsafe-or-unreadable-entry:{relative}")
            return sha256_text(f"link-metadata:{link_name}:{target}")
        current = parent
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
        if not resolved.is_file():
            return None
        return sha256_bytes(resolved.read_bytes())
    except (OSError, ValueError):
        return sha256_text(f"unsafe-or-unreadable-entry:{relative}")


def _relative_files(workspace: Path, extra_globs: list[str]) -> tuple[set[str], str | None]:
    result: set[str] = set()
    listed = _git(workspace, "ls-files", "-co", "--exclude-standard", "-z")
    if listed.returncode != 0:
        return set(), _git_runtime_failure(listed) or "git-ls-files-failed"
    for raw in listed.stdout.split(b"\0"):
        if raw:
            result.add(raw.decode("utf-8", errors="surrogateescape").replace("\\", "/"))
    for pattern in extra_globs:
        normalized = str(pattern).replace("\\", "/")
        if not normalized or normalized.startswith("/") or (len(normalized) > 2 and normalized[1] == ":"):
            continue
        try:
            for path in workspace.glob(normalized):
                if (path.is_file() or _is_reparse_point(path)) and ".git" not in path.relative_to(workspace).parts:
                    result.add(path.relative_to(workspace).as_posix())
        except (OSError, ValueError):
            continue
    return {relative for relative in result if not _runtime_only_path(relative)}, None


def _degraded_workspace_snapshot(root: Path, extra_globs: list[str], reason: str) -> dict[str, Any]:
    payload = json.dumps(
        {"git": False, "reason": reason},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return {
        "contract": "WorkspaceSnapshot/v3",
        "status": "degraded",
        "reason": reason,
        "git": False,
        "workspace": str(root),
        "files": {},
        "snapshot_hash": sha256_text(payload),
        "captured_at": utc_now(),
        "extra_globs": extra_globs,
    }


def capture_workspace_snapshot(workspace: str, extra_globs: list[str] | None = None) -> dict[str, Any]:
    requested_globs = list(extra_globs or [])
    if not isinstance(workspace, str) or not workspace.strip() or "\x00" in workspace:
        return _degraded_workspace_snapshot(
            Path("<invalid-workspace>"), requested_globs, "workspace-empty"
        )
    root = Path(workspace).resolve()
    inside = _git(root, "rev-parse", "--is-inside-work-tree")
    runtime_failure = _git_runtime_failure(inside)
    if runtime_failure:
        return _degraded_workspace_snapshot(root, requested_globs, runtime_failure)
    if inside.returncode != 0 or inside.stdout.strip() != b"true":
        return {"contract": "WorkspaceSnapshot/v3", "git": False, "workspace": str(root), "files": {}, "snapshot_hash": sha256_text("non-git"), "captured_at": utc_now(), "extra_globs": requested_globs}
    head_result = _git(root, "rev-parse", "HEAD")
    head_runtime_failure = _git_runtime_failure(head_result)
    if head_runtime_failure:
        return _degraded_workspace_snapshot(
            root,
            requested_globs,
            head_runtime_failure,
        )
    # An unborn repository legitimately has no HEAD yet; its file manifest is
    # still useful and must not be mislabeled as a Supervisor runtime failure.
    head = head_result.stdout.decode("ascii", errors="ignore").strip() if head_result.returncode == 0 else ""
    files: dict[str, str] = {}
    relative_files, list_error = _relative_files(root, requested_globs)
    if list_error:
        return _degraded_workspace_snapshot(root, requested_globs, list_error)
    for relative in sorted(relative_files):
        path = root / Path(relative)
        digest = _hash_workspace_entry(root, path, relative)
        if digest is not None:
            files[relative] = digest
    digest_payload = json.dumps({"head": head, "files": files}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return {
        "contract": "WorkspaceSnapshot/v3",
        "git": True,
        "workspace": str(root),
        "head": head,
        "files": files,
        "snapshot_hash": sha256_text(digest_payload),
        "captured_at": utc_now(),
        "extra_globs": requested_globs,
    }


def workspace_delta(baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    before = baseline.get("files", {}) if isinstance(baseline.get("files"), dict) else {}
    after = current.get("files", {}) if isinstance(current.get("files"), dict) else {}
    changed = {
        path: {"before": before.get(path), "after": after.get(path)}
        for path in sorted(set(before) | set(after))
        if before.get(path) != after.get(path)
    }
    payload = json.dumps(changed, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return {
        "contract": "WorkspaceDelta/v3",
        "files": sorted(changed),
        "base": str(baseline.get("snapshot_hash") or ""),
        "head": str(current.get("snapshot_hash") or ""),
        "diff_hash": sha256_text(payload),
        "manifest": changed,
        "collected_at": utc_now(),
        "collector": "supervisor-core",
    }
