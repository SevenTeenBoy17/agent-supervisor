from __future__ import annotations

import hashlib
import json
import fnmatch
import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Any

from .executable_trust import (
    ExecutableTrustError,
    load_trusted_executable_registry,
    resolve_trusted_executable,
    trusted_path,
)
from .util import (
    canonical_sha256,
    redact,
    sha256_bytes,
    sha256_file,
    sha256_text,
    utc_now,
)


_GIT_TIMEOUT_SECONDS = 15
_SUPPORTED_GIT_FILE_MODES = frozenset({"100644", "100755", "120000"})
_GIT_BATCH_TIMEOUT_MAX_SECONDS = 300
_GIT_BATCH_BYTES_PER_SECOND_FLOOR = 2 * 1024 * 1024
_GIT_BATCH_OBJECTS_PER_SECOND_FLOOR = 256
_MAX_GIT_OUTPUT_BYTES = 16 * 1024 * 1024
_MAX_WORKSPACE_FILES = 10_000
_MAX_WORKSPACE_FILE_BYTES = 64 * 1024 * 1024
_MAX_WORKSPACE_TOTAL_BYTES = 512 * 1024 * 1024
_WORKSPACE_HASH_CHUNK_BYTES = 1024 * 1024
_GIT_OID_LENGTHS = {"sha1": 40, "sha256": 64}
_GIT_REDIRECT_ENVIRONMENT = frozenset(
    {
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_CEILING_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_SYSTEM",
        "GIT_DIFF_OPTS",
        "GIT_DIR",
        "GIT_DISCOVERY_ACROSS_FILESYSTEM",
        "GIT_EXEC_PATH",
        "GIT_EXTERNAL_DIFF",
        "GIT_INDEX_FILE",
        "GIT_NAMESPACE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_REPLACE_REF_BASE",
        "GIT_TEMPLATE_DIR",
        "GIT_WORK_TREE",
    }
)


def _git_batch_timeout_seconds(request_count: int) -> int:
    """Return a bounded timeout for the maximum accepted batch workload.

    Object sizes are not known until ``cat-file --batch`` starts producing its
    response.  Scale against the largest byte budget the requested object count
    is allowed to consume, plus a small per-object allowance, instead of applying
    the single-command timeout to an entire potentially 512 MiB batch.
    """
    bounded_count = max(1, min(int(request_count), _MAX_WORKSPACE_FILES))
    byte_budget = min(
        _MAX_WORKSPACE_TOTAL_BYTES,
        bounded_count * _MAX_WORKSPACE_FILE_BYTES,
    )
    byte_seconds = (
        byte_budget + _GIT_BATCH_BYTES_PER_SECOND_FLOOR - 1
    ) // _GIT_BATCH_BYTES_PER_SECOND_FLOOR
    object_seconds = (
        bounded_count + _GIT_BATCH_OBJECTS_PER_SECOND_FLOOR - 1
    ) // _GIT_BATCH_OBJECTS_PER_SECOND_FLOOR
    return min(
        _GIT_BATCH_TIMEOUT_MAX_SECONDS,
        _GIT_TIMEOUT_SECONDS + byte_seconds + object_seconds,
    )
_RAW_WORKSPACE_PATH_PREFIX = "@agent-supervisor-raw-path-v1:"
_ESCAPED_WORKSPACE_PATH_PREFIX = "@agent-supervisor-utf8-path-v1:"
_REVIEW_OUTPUT_ARTIFACT_FIELDS = {
    "contract",
    "review_category",
    "review_artifact",
    "review_summary",
    "base",
    "head",
    "git_object_format",
    "git_diff_sha256",
    "workspace_base_sha256",
    "workspace_head_sha256",
    "diff_hash",
}
_CODERABBIT_REVIEW_SUMMARY_FIELDS = {
    "engine",
    "authenticated",
    "status",
    "exit_code",
    "structured_events",
    "terminal_outcome",
    "finding_count",
    "complete_reported_findings",
    "blocking_findings",
    "severity_counts",
    "protocol_blockers",
    "context_bound",
    "issues",
    "stdout_sha256",
    "stderr_sha256",
}
_GRAPH_REVIEW_SUMMARY_FIELDS = {
    "engine",
    "check",
    "status",
    "exit_code",
    "output_sha256",
}
_REVIEW_SUMMARY_ISSUE_FIELDS = {
    "kind",
    "severity",
    "path",
    "line",
    "title",
    "message",
}
_REVIEW_SEVERITY_BUCKETS = {
    "critical": frozenset({"p0", "critical", "error"}),
    "major": frozenset({"p1", "major", "high"}),
    "minor": frozenset(
        {
            "p2",
            "p3",
            "minor",
            "medium",
            "low",
            "info",
            "warning",
            "suggestion",
            "nitpick",
        }
    ),
}
_REVIEW_SUPPORTED_SEVERITIES = frozenset().union(
    *_REVIEW_SEVERITY_BUCKETS.values()
)
_REVIEW_ARTIFACT_FIELDS = {
    "kind",
    "bundle_path",
    "bundle_sha256",
    "manifest_path",
    "manifest_sha256",
}
_REVIEW_ARTIFACT_MANIFEST_FIELDS = {
    "contract",
    "git_binding_source",
    "review_mode",
    "bundle_sha256",
    "git_object_format",
    "base",
    "head",
    "diff_hash",
    "git_diff_sha256",
    "workspace_base_sha256",
    "workspace_head_sha256",
    "files",
    "workspace_delta_manifest",
    "source_review_manifest",
    "source_review_manifest_sha256",
}
_REVIEW_ARTIFACT_SOURCE_FIELDS = {
    "supervisor_source_snapshot_sha256",
    "review_core_manifest_sha256",
    "review_adapter_manifest_sha256",
}
_REVIEW_BINDING_SOURCE_FIELDS = _REVIEW_ARTIFACT_SOURCE_FIELDS | {
    "review_adapter_manifest",
}

_CORE_SOURCE_WHITELIST = (
    "bin/agent-supervisor.py",
    "bin/build-core-release-manifest.py",
    "bin/run-coderabbit-review.py",
    "supervisor_core/__init__.py",
    "supervisor_core/__main__.py",
    "supervisor_core/attestation.py",
    "supervisor_core/cli.py",
    "supervisor_core/constants.py",
    "supervisor_core/contracts.py",
    "supervisor_core/discovery.py",
    "supervisor_core/executable_trust.py",
    "supervisor_core/finalize.py",
    "supervisor_core/lifecycle.py",
    "supervisor_core/rollout.py",
    "supervisor_core/routing.py",
    "supervisor_core/runtime_bundle.py",
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
    "supervisor-hook.ps1",
    "supervisor-process-job.py",
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
    from .runtime_bundle import bound_release_identity

    bound_identity = bound_release_identity()
    bound_root = (
        Path(str(bound_identity["path"]))
        if isinstance(bound_identity, dict) and isinstance(bound_identity.get("path"), str)
        else Path(__file__).parent.parent
    )
    return {
        "shared-core": _absolute_path(bound_root),
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
        "handoffs", "state", "logs", "spool", "cache", "records",
        "timeline.jsonl", "ledger.json", "status.md", "context-snapshot.md",
        "current-goal.md", "handoff.md", ".attestation-key",
    }


def _path_is_within(candidate: Path, root: Path) -> bool:
    try:
        return os.path.commonpath(
            (os.path.normcase(str(candidate)), os.path.normcase(str(root)))
        ) == os.path.normcase(str(root))
    except (OSError, ValueError):
        return False


def _git_executable_names() -> tuple[str, ...]:
    if os.name != "nt":
        return ("git",)
    raw_pathext = os.environ.get("PATHEXT")
    if raw_pathext is None:
        raw_pathext = ".COM;.EXE;.BAT;.CMD"
    names: list[str] = []
    observed: set[str] = set()
    for raw_extension in raw_pathext.split(os.pathsep):
        extension = raw_extension.strip()
        if not re.fullmatch(r"\.[A-Za-z0-9]{1,16}", extension):
            continue
        normalized = extension.casefold()
        if normalized in observed:
            continue
        observed.add(normalized)
        names.append(f"git{normalized}")
    return tuple(names)


def _trusted_git_candidate(candidate: Path, workspace: Path) -> Path | None:
    """Return a stable absolute Git executable with no linked path component."""
    lexical = _absolute_path(candidate)
    workspace_lexical = _absolute_path(workspace)
    try:
        workspace_resolved = workspace_lexical.resolve(strict=False)
    except (OSError, RuntimeError):
        workspace_resolved = workspace_lexical
    if _path_is_within(lexical, workspace_lexical) or _path_is_within(
        lexical, workspace_resolved
    ):
        return None

    current = lexical
    candidate_stat: os.stat_result | None = None
    observed_components: list[tuple[Path, os.stat_result]] = []
    while True:
        try:
            value = current.lstat()
        except OSError:
            return None
        if stat.S_ISLNK(value.st_mode) or bool(
            getattr(value, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        ):
            return None
        observed_components.append((current, value))
        if current == lexical:
            candidate_stat = value
        parent = current.parent
        if parent == current:
            break
        current = parent

    if candidate_stat is None or not stat.S_ISREG(candidate_stat.st_mode):
        return None
    if os.name != "nt" and not os.access(lexical, os.X_OK):
        return None
    try:
        resolved = lexical.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    if os.path.normcase(str(resolved)) != os.path.normcase(str(lexical)):
        return None
    if _path_is_within(resolved, workspace_lexical) or _path_is_within(
        resolved, workspace_resolved
    ):
        return None
    for component, initial_stat in observed_components:
        try:
            final_stat = component.lstat()
        except OSError:
            return None
        if stat.S_ISLNK(final_stat.st_mode) or bool(
            getattr(final_stat, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        ):
            return None
        if (
            initial_stat.st_dev,
            initial_stat.st_ino,
            initial_stat.st_mode,
            initial_stat.st_size,
            initial_stat.st_mtime_ns,
        ) != (
            final_stat.st_dev,
            final_stat.st_ino,
            final_stat.st_mode,
            final_stat.st_size,
            final_stat.st_mtime_ns,
        ):
            return None
    return resolved


def _resolve_git_executable(workspace: Path) -> Path | None:
    try:
        registry = load_trusted_executable_registry()
        resolved, _digest = resolve_trusted_executable(
            "git", registry, cwd=str(workspace)
        )
        return _trusted_git_candidate(Path(resolved), workspace)
    except (ExecutableTrustError, OSError, RuntimeError, ValueError):
        return None


def _sanitized_git_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for variable in tuple(environment):
        normalized = variable.upper()
        if (
            normalized in _GIT_REDIRECT_ENVIRONMENT
            or normalized.startswith("GIT_CONFIG_KEY_")
            or normalized.startswith("GIT_CONFIG_VALUE_")
            or normalized == "NODEFAULTCURRENTDIRECTORYINEXEPATH"
        ):
            environment.pop(variable, None)
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_CONFIG_GLOBAL"] = os.devnull
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    environment["NoDefaultCurrentDirectoryInExePath"] = "1"
    try:
        environment["PATH"] = trusted_path(load_trusted_executable_registry())
    except (ExecutableTrustError, OSError, RuntimeError, ValueError):
        environment["PATH"] = ""
    return environment


def _git(workspace: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    executable = _resolve_git_executable(workspace)
    unresolved_command = ["git", "-C", str(workspace), *args]
    if executable is None:
        return subprocess.CompletedProcess(
            unresolved_command,
            127,
            b"",
            b"agent-supervisor:git-unavailable",
        )
    command = [str(executable), "-C", str(workspace), *args]
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            env=_sanitized_git_environment(),
            bufsize=0,
        )
        if process.stdout is None or process.stderr is None:
            process.kill()
            process.wait()
            raise OSError("git-pipes-unavailable")
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        overflow = threading.Event()

        def drain(name: str, stream: Any) -> None:
            try:
                while True:
                    chunk = stream.read(64 * 1024)
                    if not chunk:
                        break
                    target = buffers[name]
                    if len(target) + len(chunk) > _MAX_GIT_OUTPUT_BYTES:
                        overflow.set()
                        try:
                            process.kill()
                        except OSError:
                            pass
                        break
                    target.extend(chunk)
            finally:
                try:
                    stream.close()
                except OSError:
                    pass

        readers = [
            threading.Thread(target=drain, args=("stdout", process.stdout), daemon=True),
            threading.Thread(target=drain, args=("stderr", process.stderr), daemon=True),
        ]
        for reader in readers:
            reader.start()
        try:
            returncode = process.wait(timeout=_GIT_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            for reader in readers:
                reader.join(timeout=2)
            return subprocess.CompletedProcess(
                command, 124, b"", b"agent-supervisor:git-timeout"
            )
        for reader in readers:
            reader.join(timeout=2)
        if overflow.is_set() or any(reader.is_alive() for reader in readers):
            if process.poll() is None:
                process.kill()
                process.wait()
            return subprocess.CompletedProcess(
                command,
                125,
                b"",
                b"agent-supervisor:git-output-limit",
            )
        return subprocess.CompletedProcess(
            command,
            returncode,
            bytes(buffers["stdout"]),
            bytes(buffers["stderr"]),
        )
    except OSError:
        return subprocess.CompletedProcess(command, 127, b"", b"agent-supervisor:git-unavailable")


def _git_batch_blob_sha256(
    workspace: Path,
    requests: list[tuple[str, str]],
) -> tuple[dict[str, str] | None, str | None]:
    """Hash a bounded tree through one ``git cat-file --batch`` process."""
    if not requests:
        return {}, None
    if len(requests) > _MAX_WORKSPACE_FILES:
        return None, "git-batch-request-limit"
    try:
        request_bytes = b"".join(
            object_id.encode("ascii") + b"\n" for _, object_id in requests
        )
    except UnicodeError:
        return None, "git-batch-object-id-invalid"
    if len(request_bytes) > _MAX_GIT_OUTPUT_BYTES:
        return None, "git-batch-request-limit"
    executable = _resolve_git_executable(workspace)
    if executable is None:
        return None, "git-unavailable"
    command = [str(executable), "-C", str(workspace), "cat-file", "--batch"]
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            env=_sanitized_git_environment(),
            bufsize=0,
        )
    except OSError:
        return None, "git-unavailable"
    if process.stdin is None or process.stdout is None or process.stderr is None:
        try:
            process.kill()
            process.wait()
        except OSError:
            pass
        return None, "git-batch-pipes-unavailable"

    observed: dict[str, str] = {}
    failure: list[str] = []
    total_bytes = [0]

    def fail(reason: str) -> None:
        if not failure:
            failure.append(reason)
        try:
            process.kill()
        except OSError:
            pass

    def parse_stdout() -> None:
        try:
            for relative_path, expected_oid in requests:
                header = process.stdout.readline(256)
                if not header.endswith(b"\n"):
                    fail("git-batch-header-invalid")
                    return
                parts = header[:-1].split()
                if len(parts) != 3:
                    fail("git-batch-header-invalid")
                    return
                try:
                    observed_oid = parts[0].decode("ascii")
                    object_type = parts[1].decode("ascii")
                    size = int(parts[2].decode("ascii"))
                except (UnicodeError, ValueError):
                    fail("git-batch-header-invalid")
                    return
                if (
                    observed_oid != expected_oid
                    or object_type != "blob"
                    or size < 0
                    or size > _MAX_GIT_OUTPUT_BYTES
                    or total_bytes[0] + size > _MAX_WORKSPACE_TOTAL_BYTES
                ):
                    fail("git-batch-object-invalid")
                    return
                digest = hashlib.sha256()
                remaining = size
                while remaining:
                    chunk = process.stdout.read(
                        min(_WORKSPACE_HASH_CHUNK_BYTES, remaining)
                    )
                    if not chunk:
                        fail("git-batch-object-truncated")
                        return
                    digest.update(chunk)
                    remaining -= len(chunk)
                if process.stdout.read(1) != b"\n":
                    fail("git-batch-delimiter-invalid")
                    return
                total_bytes[0] += size
                observed[relative_path] = digest.hexdigest()
            if process.stdout.read(1):
                fail("git-batch-extra-output")
        except OSError:
            fail("git-batch-read-failed")
        finally:
            try:
                process.stdout.close()
            except OSError:
                pass

    def drain_stderr() -> None:
        observed_bytes = 0
        try:
            while True:
                chunk = process.stderr.read(64 * 1024)
                if not chunk:
                    return
                observed_bytes += len(chunk)
                if observed_bytes > _MAX_GIT_OUTPUT_BYTES:
                    fail("git-batch-stderr-limit")
                    return
        except OSError:
            fail("git-batch-stderr-failed")
        finally:
            try:
                process.stderr.close()
            except OSError:
                pass

    readers = [
        threading.Thread(target=parse_stdout, daemon=True),
        threading.Thread(target=drain_stderr, daemon=True),
    ]
    for reader in readers:
        reader.start()
    try:
        pending = memoryview(request_bytes)
        while pending:
            written = process.stdin.write(pending)
            if (
                not isinstance(written, int)
                or written <= 0
                or written > len(pending)
            ):
                raise OSError("git batch request short write")
            pending = pending[written:]
    except (OSError, ValueError):
        fail("git-batch-write-failed")
    finally:
        try:
            process.stdin.close()
        except OSError:
            fail("git-batch-write-failed")
    try:
        returncode = process.wait(timeout=_git_batch_timeout_seconds(len(requests)))
    except subprocess.TimeoutExpired:
        fail("git-timeout")
        process.wait()
        returncode = 124
    for reader in readers:
        reader.join(timeout=2)
    if any(reader.is_alive() for reader in readers):
        fail("git-batch-reader-timeout")
    if returncode != 0 or failure or len(observed) != len(requests):
        return None, failure[0] if failure else "git-batch-command-failed"
    return observed, None


def _git_runtime_failure(result: subprocess.CompletedProcess[bytes]) -> str | None:
    if result.returncode == 124 and b"agent-supervisor:git-timeout" in (result.stderr or b""):
        return "git-timeout"
    if result.returncode == 127 and b"agent-supervisor:git-unavailable" in (result.stderr or b""):
        return "git-unavailable"
    if result.returncode == 125 and b"agent-supervisor:git-output-limit" in (result.stderr or b""):
        return "git-output-limit"
    return None


def _git_oid_shape(value: Any, object_format: Any) -> bool:
    oid = str(value or "")
    expected = _GIT_OID_LENGTHS.get(str(object_format or ""))
    return bool(
        expected
        and len(oid) == expected
        and oid == oid.casefold()
        and re.fullmatch(r"[0-9a-f]+", oid)
    )


def _git_object_format(root: Path, head: str = "") -> tuple[str | None, str | None]:
    result = _git(root, "rev-parse", "--show-object-format")
    runtime_failure = _git_runtime_failure(result)
    if runtime_failure:
        return None, runtime_failure
    if result.returncode == 0:
        value = result.stdout.decode("ascii", errors="ignore").strip().casefold()
        if value in _GIT_OID_LENGTHS:
            return value, None
        return None, "git-object-format-unsupported"
    # ``--show-object-format`` was added after SHA-1 repositories. Preserve
    # compatibility with older Git only when HEAD itself proves SHA-1 shape.
    if re.fullmatch(r"[0-9a-f]{40}", head):
        return "sha1", None
    return None, "git-object-format-unavailable"


def validate_git_commit_binding(
    workspace: str,
    *,
    base: Any,
    head: Any,
    object_format: Any,
) -> tuple[bool, str]:
    """Verify an exact Git commit range against the repository object store."""
    fmt = str(object_format or "").casefold()
    base_oid = str(base or "")
    head_oid = str(head or "")
    if fmt not in _GIT_OID_LENGTHS:
        return False, "git-object-format-invalid"
    if not _git_oid_shape(base_oid, fmt) or not _git_oid_shape(head_oid, fmt):
        return False, "git-oid-shape-invalid"
    if not isinstance(workspace, str) or not workspace.strip() or "\x00" in workspace:
        return False, "workspace-invalid"
    root = Path(workspace).resolve()
    inside = _git(root, "rev-parse", "--is-inside-work-tree")
    runtime_failure = _git_runtime_failure(inside)
    if runtime_failure:
        return False, runtime_failure
    if inside.returncode != 0 or inside.stdout.strip() != b"true":
        bare = _git(root, "rev-parse", "--is-bare-repository")
        runtime_failure = _git_runtime_failure(bare)
        if runtime_failure:
            return False, runtime_failure
        if bare.returncode != 0 or bare.stdout.strip() != b"true":
            return False, "git-workspace-unavailable"
    observed_format, format_error = _git_object_format(root, head_oid)
    if format_error:
        return False, format_error
    if observed_format != fmt:
        return False, "git-object-format-mismatch"
    for label, oid in (("base", base_oid), ("head", head_oid)):
        commit = _git(root, "cat-file", "-e", f"{oid}^{{commit}}")
        runtime_failure = _git_runtime_failure(commit)
        if runtime_failure:
            return False, runtime_failure
        if commit.returncode != 0:
            return False, f"git-{label}-commit-unresolvable"
    ancestor = _git(root, "merge-base", "--is-ancestor", base_oid, head_oid)
    runtime_failure = _git_runtime_failure(ancestor)
    if runtime_failure:
        return False, runtime_failure
    if ancestor.returncode != 0:
        return False, "git-base-not-ancestor-of-head"
    return True, "verified"


def validate_review_artifact(
    artifact: Any,
    *,
    base: Any,
    head: Any,
    object_format: Any,
    diff_hash: Any,
    workspace_base_sha256: Any,
    workspace_head_sha256: Any,
) -> tuple[bool, str, dict[str, Any] | None]:
    """Validate an immutable full Git bundle plus its exact JSON manifest."""
    if (
        not isinstance(artifact, dict)
        or set(artifact) != _REVIEW_ARTIFACT_FIELDS
        or artifact.get("kind") != "git-bundle-v1"
    ):
        return False, "review-artifact-contract-invalid", None
    bundle_path = artifact.get("bundle_path")
    manifest_path = artifact.get("manifest_path")
    if not isinstance(bundle_path, str) or not isinstance(manifest_path, str):
        return False, "review-artifact-path-missing", None

    def trusted_regular_file(raw: str) -> Path | None:
        if not raw.strip() or "\x00" in raw:
            return None
        candidate = Path(raw)
        if not candidate.is_absolute():
            return None
        lexical = _absolute_path(candidate)
        try:
            resolved = lexical.resolve(strict=True)
        except OSError:
            return None
        if os.path.normcase(str(lexical)) != os.path.normcase(str(resolved)):
            return None
        if _is_reparse_point(lexical) or not lexical.is_file():
            return None
        return lexical

    bundle = trusted_regular_file(bundle_path)
    manifest_file = trusted_regular_file(manifest_path)
    if bundle is None or manifest_file is None:
        return False, "review-artifact-file-unavailable-or-linked", None
    bundle_sha256 = str(artifact.get("bundle_sha256") or "")
    manifest_sha256 = str(artifact.get("manifest_sha256") or "")
    try:
        if manifest_file.stat().st_size > 8 * 1024 * 1024:
            return False, "review-artifact-manifest-too-large", None
        manifest_bytes = manifest_file.read_bytes()
    except OSError:
        return False, "review-artifact-file-unavailable-or-linked", None
    if not re.fullmatch(r"[0-9a-f]{64}", bundle_sha256):
        return False, "review-artifact-bundle-hash-mismatch", None
    if not re.fullmatch(r"[0-9a-f]{64}", manifest_sha256) or sha256_bytes(manifest_bytes) != manifest_sha256:
        return False, "review-artifact-manifest-hash-mismatch", None
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON key: {key}")
            value[key] = item
        return value

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON value: {value}")

    try:
        manifest = json.loads(
            manifest_bytes.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        return False, "review-artifact-manifest-invalid", None
    manifest_fields = set(manifest) if isinstance(manifest, dict) else set()
    if (
        not isinstance(manifest, dict)
        or (
            manifest_fields != _REVIEW_ARTIFACT_MANIFEST_FIELDS
            and manifest_fields
            != _REVIEW_ARTIFACT_MANIFEST_FIELDS | _REVIEW_ARTIFACT_SOURCE_FIELDS
        )
        or manifest.get("contract") != "ReviewArtifactManifest/v1"
        or manifest.get("git_binding_source") != "review-artifact"
        or manifest.get("review_mode") != "full-snapshot"
    ):
        return False, "review-artifact-manifest-contract-invalid", None
    expected = {
        "bundle_sha256": bundle_sha256,
        "git_object_format": object_format,
        "base": base,
        "head": head,
        "diff_hash": diff_hash,
        "workspace_base_sha256": workspace_base_sha256,
        "workspace_head_sha256": workspace_head_sha256,
    }
    if any(manifest.get(key) != value for key, value in expected.items()):
        return False, "review-artifact-manifest-binding-mismatch", None
    delta_manifest = manifest.get("workspace_delta_manifest")
    if not isinstance(delta_manifest, dict) or canonical_sha256(delta_manifest) != diff_hash:
        return False, "review-artifact-diff-manifest-mismatch", None
    for relative_path, delta in delta_manifest.items():
        if (
            not isinstance(relative_path, str)
            or not relative_path
            or "\x00" in relative_path
            or any(ord(character) < 32 for character in relative_path)
            or "\\" in relative_path
            or relative_path.startswith("/")
            or any(part in {"", ".", ".."} for part in relative_path.split("/"))
            or not isinstance(delta, dict)
            or set(delta) != {"before", "after"}
            or any(
                value is not None
                and (
                    not isinstance(value, str)
                    or not re.fullmatch(r"[0-9a-f]{64}", value)
                )
                for value in delta.values()
            )
        ):
            return False, "review-artifact-delta-entry-invalid", None
    files = manifest.get("files")
    if not isinstance(files, list) or files != sorted(delta_manifest):
        return False, "review-artifact-file-manifest-mismatch", None
    source_manifest = manifest.get("source_review_manifest")
    if not isinstance(source_manifest, dict) or not source_manifest:
        return False, "review-artifact-source-manifest-invalid", None
    for relative_path, content_sha256 in source_manifest.items():
        if (
            not isinstance(relative_path, str)
            or not relative_path
            or "\x00" in relative_path
            or any(ord(character) < 32 for character in relative_path)
            or "\\" in relative_path
            or relative_path.startswith("/")
            or re.match(r"^[A-Za-z]:", relative_path)
            or any(part in {"", ".", ".."} for part in relative_path.split("/"))
            or not isinstance(content_sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", content_sha256)
        ):
            return False, "review-artifact-source-manifest-invalid", None
    if canonical_sha256(source_manifest) != manifest.get("source_review_manifest_sha256"):
        return False, "review-artifact-source-manifest-hash-mismatch", None
    if _REVIEW_ARTIFACT_SOURCE_FIELDS <= manifest_fields:
        for field in _REVIEW_ARTIFACT_SOURCE_FIELDS:
            if not isinstance(manifest.get(field), str) or not re.fullmatch(
                r"[0-9a-f]{64}", manifest[field]
            ):
                return False, "review-artifact-source-binding-invalid", None
        core_manifest = {
            path: digest
            for path, digest in source_manifest.items()
            if path.startswith("global-core/")
        }
        if canonical_sha256(core_manifest) != manifest.get(
            "review_core_manifest_sha256"
        ):
            return False, "review-artifact-core-manifest-mismatch", None
        adapter_manifest = {
            path: digest
            for path, digest in source_manifest.items()
            if path.startswith(("global-codex/", "global-claude/"))
        }
        if (
            not adapter_manifest
            or canonical_sha256(adapter_manifest)
            != manifest.get("review_adapter_manifest_sha256")
        ):
            return False, "review-artifact-adapter-manifest-mismatch", None
    git_diff_sha256 = str(manifest.get("git_diff_sha256") or "")
    if not re.fullmatch(r"[0-9a-f]{64}", git_diff_sha256):
        return False, "review-artifact-git-diff-hash-invalid", None

    fmt = str(object_format or "")
    if fmt not in _GIT_OID_LENGTHS:
        return False, "git-object-format-invalid", None
    init_args = ["init", "--bare", "-q"]
    if fmt == "sha256":
        init_args.insert(2, "--object-format=sha256")
    with tempfile.TemporaryDirectory(prefix="agent-supervisor-review-") as temp_dir:
        sealed_bundle = Path(temp_dir) / "review.bundle"
        try:
            shutil.copyfile(bundle, sealed_bundle)
        except OSError:
            return False, "review-artifact-bundle-copy-failed", None
        if sha256_file(sealed_bundle) != bundle_sha256:
            return False, "review-artifact-bundle-hash-mismatch", None
        repo = Path(temp_dir) / "objects.git"
        initialized = _git(Path(temp_dir), *init_args, str(repo))
        if initialized.returncode != 0:
            return False, "review-artifact-repository-init-failed", None
        verified = _git(repo, "bundle", "verify", str(sealed_bundle))
        if verified.returncode != 0:
            return False, "review-artifact-bundle-verification-failed", None
        heads = _git(repo, "bundle", "list-heads", "--", str(sealed_bundle))
        if heads.returncode != 0:
            return False, "review-artifact-head-list-failed", None
        advertised_ref = None
        for raw_line in heads.stdout.decode("utf-8", errors="replace").splitlines():
            parts = raw_line.split(maxsplit=1)
            if len(parts) == 2 and parts[0].casefold() == str(head).casefold():
                advertised_ref = parts[1].strip()
                break
        if not advertised_ref:
            return False, "review-artifact-head-not-advertised", None
        fetched = _git(repo, "fetch", "-q", "--", str(sealed_bundle), f"{advertised_ref}:refs/review/head")
        if fetched.returncode != 0:
            return False, "review-artifact-fetch-failed", None
        valid, reason = validate_git_commit_binding(
            str(repo), base=base, head=head, object_format=object_format
        )
        if not valid:
            return False, reason, None
        expected_base_tree = dict(source_manifest)
        for relative_path, delta in delta_manifest.items():
            after_sha256 = delta.get("after")
            if after_sha256 is None:
                if relative_path in source_manifest:
                    return False, "review-artifact-delta-head-mismatch", None
            elif source_manifest.get(relative_path) != after_sha256:
                return False, "review-artifact-delta-head-mismatch", None
            before_sha256 = delta.get("before")
            if before_sha256 is None:
                expected_base_tree.pop(relative_path, None)
            else:
                expected_base_tree[relative_path] = before_sha256
        base_tree = _git(repo, "ls-tree", "-r", "-z", "--full-tree", str(base))
        if base_tree.returncode != 0:
            return False, "review-artifact-base-tree-unavailable", None
        base_requests: list[tuple[str, str]] = []
        base_paths: set[str] = set()
        for entry in base_tree.stdout.split(b"\0"):
            if not entry:
                continue
            try:
                metadata, raw_path = entry.split(b"\t", 1)
                mode, object_type, object_id = metadata.decode("ascii").split()
                relative_path = raw_path.decode("utf-8")
            except (UnicodeError, ValueError):
                return False, "review-artifact-base-tree-invalid", None
            if (
                mode not in _SUPPORTED_GIT_FILE_MODES
                or object_type != "blob"
                or not _git_oid_shape(object_id, fmt)
                or relative_path in base_paths
            ):
                return False, "review-artifact-base-tree-mode-invalid", None
            base_paths.add(relative_path)
            base_requests.append((relative_path, object_id))
        observed_base_tree, base_batch_error = _git_batch_blob_sha256(
            repo, base_requests
        )
        if base_batch_error or observed_base_tree is None:
            return False, "review-artifact-base-tree-blob-unavailable", None
        if observed_base_tree != expected_base_tree:
            return False, "review-artifact-base-tree-manifest-mismatch", None
        head_tree = _git(repo, "ls-tree", "-r", "-z", "--full-tree", str(head))
        if head_tree.returncode != 0:
            return False, "review-artifact-head-tree-unavailable", None
        head_requests: list[tuple[str, str]] = []
        head_paths: set[str] = set()
        for entry in head_tree.stdout.split(b"\0"):
            if not entry:
                continue
            try:
                metadata, raw_path = entry.split(b"\t", 1)
                mode, object_type, object_id = metadata.decode("ascii").split()
                relative_path = raw_path.decode("utf-8")
            except (UnicodeError, ValueError):
                return False, "review-artifact-head-tree-invalid", None
            if (
                mode not in _SUPPORTED_GIT_FILE_MODES
                or object_type != "blob"
                or not _git_oid_shape(object_id, fmt)
                or relative_path in head_paths
            ):
                return False, "review-artifact-head-tree-mode-invalid", None
            head_paths.add(relative_path)
            head_requests.append((relative_path, object_id))
        observed_tree, head_batch_error = _git_batch_blob_sha256(
            repo, head_requests
        )
        if head_batch_error or observed_tree is None:
            return False, "review-artifact-head-tree-blob-unavailable", None
        if observed_tree != source_manifest:
            return False, "review-artifact-head-tree-manifest-mismatch", None
        rendered = _git(
            repo,
            "diff",
            "--binary",
            "--full-index",
            "--no-ext-diff",
            str(base),
            str(head),
        )
        if rendered.returncode != 0 or sha256_bytes(rendered.stdout) != git_diff_sha256:
            return False, "review-artifact-git-diff-mismatch", None
    return True, "verified", manifest


def validate_review_output_artifact(
    output: Any,
    binding_input: Any,
) -> tuple[bool, str, dict[str, Any] | None]:
    """Validate the immutable review copy emitted by a trusted review gate.

    The authoritative EvidenceRecord remains bound to the live workspace.  This
    nested artifact is an independently reproducible copy of the exact workspace
    binding plus the optional immutable core/adapter source binding that core
    injected into the gate process.
    """
    if not isinstance(output, dict) or set(output) != _REVIEW_OUTPUT_ARTIFACT_FIELDS:
        return False, "review-output-artifact-fields-invalid", None
    if output.get("contract") != "ReviewOutputArtifact/v1":
        return False, "review-output-artifact-contract-invalid", None
    if output.get("review_category") not in {"independent", "test-integrity"}:
        return False, "review-output-artifact-category-invalid", None
    summary_valid, summary_reason = _validate_review_summary(
        output.get("review_summary")
    )
    if not summary_valid:
        return False, summary_reason, None
    binding_fields = set(binding_input) if isinstance(binding_input, dict) else set()
    base_binding_fields = {
        "contract",
        "workspace_base_sha256",
        "workspace_head_sha256",
        "diff_hash",
        "workspace_delta_manifest",
    }
    if not isinstance(binding_input, dict) or (
        binding_fields != base_binding_fields
        and binding_fields != base_binding_fields | _REVIEW_BINDING_SOURCE_FIELDS
    ):
        return False, "review-output-binding-input-invalid", None
    if binding_input.get("contract") != "ReviewArtifactBindingInput/v1":
        return False, "review-output-binding-input-contract-invalid", None
    for field in ("workspace_base_sha256", "workspace_head_sha256", "diff_hash"):
        if output.get(field) != binding_input.get(field):
            return False, f"review-output-{field}-mismatch", None
    valid, reason, manifest = validate_review_artifact(
        output.get("review_artifact"),
        base=output.get("base"),
        head=output.get("head"),
        object_format=output.get("git_object_format"),
        diff_hash=output.get("diff_hash"),
        workspace_base_sha256=output.get("workspace_base_sha256"),
        workspace_head_sha256=output.get("workspace_head_sha256"),
    )
    if not valid or not isinstance(manifest, dict):
        return False, reason, None
    if manifest.get("workspace_delta_manifest") != binding_input.get(
        "workspace_delta_manifest"
    ):
        return False, "review-output-workspace-delta-manifest-mismatch", None
    if manifest.get("git_diff_sha256") != output.get("git_diff_sha256"):
        return False, "review-output-git-diff-sha256-mismatch", None
    if _REVIEW_BINDING_SOURCE_FIELDS <= binding_fields:
        if not _REVIEW_ARTIFACT_SOURCE_FIELDS <= set(manifest):
            return False, "review-output-source-binding-missing", None
        for field in _REVIEW_ARTIFACT_SOURCE_FIELDS:
            if manifest.get(field) != binding_input.get(field):
                return False, f"review-output-{field}-mismatch", None
        adapter_manifest = binding_input.get("review_adapter_manifest")
        if not isinstance(adapter_manifest, dict) or not adapter_manifest:
            return False, "review-output-adapter-manifest-invalid", None
        observed_adapter_manifest = {
            path: digest
            for path, digest in manifest.get("source_review_manifest", {}).items()
            if path.startswith(("global-codex/", "global-claude/"))
        }
        if (
            observed_adapter_manifest != adapter_manifest
            or canonical_sha256(adapter_manifest)
            != binding_input.get("review_adapter_manifest_sha256")
        ):
            return False, "review-output-adapter-manifest-mismatch", None
    return True, "verified", output


def _review_nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _review_positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _valid_review_issue_path(value: Any) -> bool:
    if value is None:
        return True
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or "\x00" in value
        or "\\" in value
        or value.startswith(("/", "//"))
        or re.match(r"^[A-Za-z]:", value)
        or ":" in value
        or any(ord(character) < 32 for character in value)
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        return False
    return redact(value) == value


def _validate_review_summary(summary: Any) -> tuple[bool, str]:
    """Validate a fail-closed, redaction-safe independent review summary."""
    if not isinstance(summary, dict):
        return False, "review-summary-fields-invalid"
    # Never include the offending value in an error.  A summary is an
    # integrity-bound record, so silently redacting it would create a different
    # result than the reviewer actually emitted.
    if redact(summary) != summary:
        return False, "review-summary-sensitive-content"
    engine = summary.get("engine")
    if engine == "code-review-graph":
        if set(summary) != _GRAPH_REVIEW_SUMMARY_FIELDS:
            return False, "review-summary-fields-invalid"
        if (
            summary.get("check") not in {"build", "impact"}
            or summary.get("status") != "pass"
            or not _review_nonnegative_int(summary.get("exit_code"))
            or summary.get("exit_code") != 0
            or not isinstance(summary.get("output_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", summary["output_sha256"]) is None
        ):
            return False, "review-summary-graph-metadata-invalid"
        return True, "verified"
    if engine != "coderabbit" or set(summary) != _CODERABBIT_REVIEW_SUMMARY_FIELDS:
        return False, "review-summary-fields-invalid"
    if (
        summary.get("authenticated") is not True
        or summary.get("status") != "pass"
        or not _review_nonnegative_int(summary.get("exit_code"))
        or summary.get("exit_code") != 0
        or not _review_positive_int(summary.get("structured_events"))
        or summary.get("terminal_outcome") != "success"
        or summary.get("context_bound") is not True
    ):
        return False, "review-summary-success-metadata-invalid"

    count_fields = (
        "finding_count",
        "complete_reported_findings",
        "blocking_findings",
    )
    if any(not _review_nonnegative_int(summary.get(field)) for field in count_fields):
        return False, "review-summary-count-invalid"
    finding_count = summary["finding_count"]
    if (
        summary["complete_reported_findings"] != finding_count
        or summary["blocking_findings"] != 0
    ):
        return False, "review-summary-count-mismatch"

    severity_counts = summary.get("severity_counts")
    if (
        not isinstance(severity_counts, dict)
        or set(severity_counts) != set(_REVIEW_SEVERITY_BUCKETS)
        or any(
            not _review_nonnegative_int(severity_counts.get(bucket))
            for bucket in _REVIEW_SEVERITY_BUCKETS
        )
        or sum(severity_counts.values()) != finding_count
    ):
        return False, "review-summary-severity-counts-invalid"
    if severity_counts["critical"] or severity_counts["major"]:
        return False, "review-summary-blocking-severity-invalid"

    blockers = summary.get("protocol_blockers")
    if not isinstance(blockers, list) or blockers:
        return False, "review-summary-protocol-blockers-invalid"
    if any(
        not isinstance(summary.get(field), str)
        or re.fullmatch(r"[0-9a-f]{64}", summary[field]) is None
        for field in ("stdout_sha256", "stderr_sha256")
    ):
        return False, "review-summary-stream-hash-invalid"

    issues = summary.get("issues")
    if not isinstance(issues, list) or len(issues) != finding_count:
        return False, "review-summary-issues-count-invalid"
    observed_counts = {bucket: 0 for bucket in _REVIEW_SEVERITY_BUCKETS}
    for issue in issues:
        if not isinstance(issue, dict) or set(issue) != _REVIEW_SUMMARY_ISSUE_FIELDS:
            return False, "review-summary-issue-fields-invalid"
        severity = issue.get("severity")
        line = issue.get("line")
        title = issue.get("title")
        message = issue.get("message")
        if (
            issue.get("kind") != "finding"
            or severity not in _REVIEW_SUPPORTED_SEVERITIES
            or not _valid_review_issue_path(issue.get("path"))
            or not (
                line is None
                or _review_positive_int(line)
            )
            or not isinstance(title, str)
            or not title.strip()
            or len(title) > 160
            or not isinstance(message, str)
            or len(message) > 500
        ):
            return False, "review-summary-issue-invalid"
        for bucket, severities in _REVIEW_SEVERITY_BUCKETS.items():
            if severity in severities:
                observed_counts[bucket] += 1
                break
    if observed_counts != severity_counts:
        return False, "review-summary-severity-count-mismatch"
    return True, "verified"


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
    from .runtime_bundle import RuntimeBundleError, bound_resource_bytes

    for relative in _CORE_SOURCE_WHITELIST:
        logical = f"shared-core/{relative}"
        try:
            bound_content = bound_resource_bytes(relative)
        except RuntimeBundleError:
            bound_content = None
            files[logical] = {
                "status": "unreadable",
                "sha256": sha256_text(f"unreadable:{logical}"),
            }
        if bound_content is not None:
            files[logical] = {
                "status": "hashed",
                "sha256": sha256_bytes(bound_content),
                "size": len(bound_content),
            }
        elif logical not in files:
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


def _hash_workspace_entry(root: Path, path: Path, relative: str) -> tuple[str | None, int]:
    current = path
    while current != root:
        parent = current.parent
        if parent == current:
            return sha256_text(f"unsafe-or-unreadable-entry:{relative}"), 0
        if _is_reparse_point(current):
            try:
                target = os.readlink(current)
            except OSError:
                target = "opaque-reparse-point"
            try:
                link_name = _persistent_workspace_path(
                    current.relative_to(root).as_posix()
                )
            except ValueError:
                return sha256_text(f"unsafe-or-unreadable-entry:{relative}"), 0
            safe_target = _persistent_workspace_path(str(target))
            return sha256_text(f"link-metadata:{link_name}:{safe_target}"), 0
        current = parent
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
        before = resolved.stat(follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode):
            return None, 0
        if before.st_size > _MAX_WORKSPACE_FILE_BYTES:
            raise ValueError("workspace-file-size-limit")
        digest = hashlib.sha256()
        observed = 0
        with resolved.open("rb") as handle:
            while True:
                chunk = handle.read(_WORKSPACE_HASH_CHUNK_BYTES)
                if not chunk:
                    break
                observed += len(chunk)
                if observed > _MAX_WORKSPACE_FILE_BYTES:
                    raise ValueError("workspace-file-size-limit")
                digest.update(chunk)
        after = resolved.stat(follow_symlinks=False)
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or observed != before.st_size
        ):
            return sha256_text(f"unsafe-or-unreadable-entry:{relative}"), 0
        return digest.hexdigest(), observed
    except ValueError:
        raise
    except (OSError, ValueError):
        return sha256_text(f"unsafe-or-unreadable-entry:{relative}"), 0


def _persistent_workspace_path(relative: str) -> str:
    """Return an injective, UTF-8-safe representation of a Git path.

    Git path output is bytes.  Python's ``surrogateescape`` preserves a byte
    sequence that is not valid UTF-8, but those surrogate code points cannot
    be encoded by the Supervisor's canonical JSON writer.  Raw paths therefore
    use a reserved hexadecimal namespace.  Legitimate UTF-8 names beginning
    with either reserved prefix are themselves escaped into a disjoint
    namespace, so no valid filename can alias a raw-byte filename.
    """
    if any(0xD800 <= ord(character) <= 0xDFFF for character in relative):
        raw = relative.encode("utf-8", errors="surrogateescape")
        return f"{_RAW_WORKSPACE_PATH_PREFIX}{raw.hex()}"
    if relative.startswith(
        (_RAW_WORKSPACE_PATH_PREFIX, _ESCAPED_WORKSPACE_PATH_PREFIX)
    ):
        return (
            f"{_ESCAPED_WORKSPACE_PATH_PREFIX}"
            f"{relative.encode('utf-8').hex()}"
        )
    return relative


def _relative_files(workspace: Path, extra_globs: list[str]) -> tuple[set[str], str | None]:
    result: set[str] = set()
    listed = _git(workspace, "ls-files", "-co", "--exclude-standard", "-z")
    if listed.returncode != 0:
        return set(), _git_runtime_failure(listed) or "git-ls-files-failed"
    for raw in listed.stdout.split(b"\0"):
        if raw:
            # Git's -z path format uses '/' as its separator on every host.
            # Preserve a literal backslash byte on POSIX instead of silently
            # conflating it with a directory separator.
            result.add(raw.decode("utf-8", errors="surrogateescape"))
            if len(result) > _MAX_WORKSPACE_FILES:
                return set(), "workspace-file-count-limit"
    for pattern in extra_globs:
        normalized = str(pattern).replace("\\", "/")
        if not normalized or normalized.startswith("/") or (len(normalized) > 2 and normalized[1] == ":"):
            continue
        try:
            for path in workspace.glob(normalized):
                if (path.is_file() or _is_reparse_point(path)) and ".git" not in path.relative_to(workspace).parts:
                    result.add(path.relative_to(workspace).as_posix())
                    if len(result) > _MAX_WORKSPACE_FILES:
                        return set(), "workspace-file-count-limit"
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
        "git_object_format": None,
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
        return {
            "contract": "WorkspaceSnapshot/v3",
            "git": False,
            "workspace": str(root),
            "files": {},
            "snapshot_hash": sha256_text("non-git"),
            "captured_at": utc_now(),
            "extra_globs": requested_globs,
            "git_object_format": None,
        }
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
    object_format, format_error = _git_object_format(root, head)
    if format_error:
        return _degraded_workspace_snapshot(root, requested_globs, format_error)
    files: dict[str, str] = {}
    total_bytes = 0
    relative_files, list_error = _relative_files(root, requested_globs)
    if list_error:
        return _degraded_workspace_snapshot(root, requested_globs, list_error)
    for relative in sorted(relative_files):
        path = root / Path(relative)
        persistent_relative = _persistent_workspace_path(relative)
        try:
            digest, observed_bytes = _hash_workspace_entry(
                root,
                path,
                persistent_relative,
            )
        except ValueError as exc:
            return _degraded_workspace_snapshot(
                root,
                requested_globs,
                str(exc),
            )
        total_bytes += observed_bytes
        if total_bytes > _MAX_WORKSPACE_TOTAL_BYTES:
            return _degraded_workspace_snapshot(
                root,
                requested_globs,
                "workspace-total-size-limit",
            )
        if digest is not None:
            files[persistent_relative] = digest
    digest_payload = json.dumps({"head": head, "files": files}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return {
        "contract": "WorkspaceSnapshot/v3",
        "git": True,
        "workspace": str(root),
        "head": head,
        "git_object_format": object_format,
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
    workspace_base_sha256 = str(baseline.get("snapshot_hash") or "")
    workspace_head_sha256 = str(current.get("snapshot_hash") or "")
    object_format = str(
        current.get("git_object_format")
        or baseline.get("git_object_format")
        or ""
    ).casefold()
    baseline_head = str(baseline.get("head") or "")
    current_head = str(current.get("head") or "")
    git_base: str | None = None
    git_head: str | None = None
    git_binding_status = "unavailable"
    git_binding_reason = "git-commit-binding-unavailable"
    git_binding_source: str | None = None
    git_repository_root: str | None = None
    if baseline.get("status") == "degraded" or current.get("status") == "degraded":
        git_binding_status = "degraded"
        git_binding_reason = str(current.get("reason") or baseline.get("reason") or "workspace-snapshot-degraded")
    elif baseline.get("git") is True and current.get("git") is True and baseline_head and current_head:
        workspace = str(current.get("workspace") or baseline.get("workspace") or "")
        root = Path(workspace).resolve() if workspace else Path("<invalid-workspace>")
        merge_base = _git(root, "merge-base", baseline_head, current_head)
        runtime_failure = _git_runtime_failure(merge_base)
        candidate = (
            merge_base.stdout.decode("ascii", errors="ignore").strip().casefold()
            if merge_base.returncode == 0
            else ""
        )
        if runtime_failure:
            git_binding_status = "degraded"
            git_binding_reason = runtime_failure
        elif not candidate:
            git_binding_status = "degraded"
            git_binding_reason = "git-merge-base-unavailable"
        else:
            valid, reason = validate_git_commit_binding(
                workspace,
                base=candidate,
                head=current_head.casefold(),
                object_format=object_format,
            )
            if valid:
                git_base = candidate
                git_head = current_head.casefold()
                git_binding_status = "verified"
                git_binding_reason = "verified"
                git_binding_source = "workspace"
                git_repository_root = str(root)
            else:
                git_binding_status = "degraded"
                git_binding_reason = reason
    return {
        "contract": "WorkspaceDelta/v3",
        "files": sorted(changed),
        "base": git_base,
        "head": git_head,
        "git_object_format": object_format or None,
        "git_binding_status": git_binding_status,
        "git_binding_reason": git_binding_reason,
        "git_binding_source": git_binding_source,
        "git_repository_root": git_repository_root,
        "review_artifact": None,
        "review_artifact_sha256": None,
        "git_diff_sha256": None,
        "workspace_base_sha256": workspace_base_sha256,
        "workspace_head_sha256": workspace_head_sha256,
        "diff_hash": sha256_text(payload),
        "manifest": changed,
        "collected_at": utc_now(),
        "collector": "supervisor-core",
    }
