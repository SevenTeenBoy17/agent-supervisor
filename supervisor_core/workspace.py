from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from .util import sha256_bytes, sha256_text, utc_now


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
    return subprocess.run(
        ["git", "-C", str(workspace), *args],
        capture_output=True,
        check=False,
    )


def _relative_files(workspace: Path, extra_globs: list[str]) -> set[str]:
    result: set[str] = set()
    listed = _git(workspace, "ls-files", "-co", "--exclude-standard", "-z")
    if listed.returncode == 0:
        for raw in listed.stdout.split(b"\0"):
            if raw:
                result.add(raw.decode("utf-8", errors="surrogateescape").replace("\\", "/"))
    for pattern in extra_globs:
        normalized = str(pattern).replace("\\", "/")
        if not normalized or normalized.startswith("/") or (len(normalized) > 2 and normalized[1] == ":"):
            continue
        try:
            for path in workspace.glob(normalized):
                if path.is_file() and ".git" not in path.relative_to(workspace).parts:
                    result.add(path.relative_to(workspace).as_posix())
        except (OSError, ValueError):
            continue
    return {relative for relative in result if not _runtime_only_path(relative)}


def capture_workspace_snapshot(workspace: str, extra_globs: list[str] | None = None) -> dict[str, Any]:
    root = Path(workspace).resolve()
    inside = _git(root, "rev-parse", "--is-inside-work-tree")
    if inside.returncode != 0 or inside.stdout.strip() != b"true":
        return {"contract": "WorkspaceSnapshot/v3", "git": False, "workspace": str(root), "files": {}, "snapshot_hash": sha256_text("non-git"), "captured_at": utc_now(), "extra_globs": list(extra_globs or [])}
    head_result = _git(root, "rev-parse", "HEAD")
    head = head_result.stdout.decode("ascii", errors="ignore").strip() if head_result.returncode == 0 else ""
    files: dict[str, str] = {}
    for relative in sorted(_relative_files(root, list(extra_globs or []))):
        path = root / Path(relative)
        try:
            if path.is_file():
                files[relative] = sha256_bytes(path.read_bytes())
        except OSError:
            continue
    digest_payload = json.dumps({"head": head, "files": files}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return {
        "contract": "WorkspaceSnapshot/v3",
        "git": True,
        "workspace": str(root),
        "head": head,
        "files": files,
        "snapshot_hash": sha256_text(digest_payload),
        "captured_at": utc_now(),
        "extra_globs": list(extra_globs or []),
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
