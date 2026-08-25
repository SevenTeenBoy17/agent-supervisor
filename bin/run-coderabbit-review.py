#!/usr/bin/env python3
"""Review only Supervisor source in a disposable, secret-free Git repository."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import types
from typing import Any, Iterable


MAX_REVIEW_FILES = 512
MAX_REVIEW_FILE_BYTES = 4 * 1024 * 1024
MAX_REVIEW_TOTAL_BYTES = 64 * 1024 * 1024
MAX_REVIEW_DEPTH = 32
MAX_SUBPROCESS_STREAM_BYTES = 4 * 1024 * 1024
_SUBPROCESS_READ_CHUNK = 64 * 1024


_BOUND_REVIEW_SOURCE = sys.modules.get("_agent_supervisor_review_source")
_BOUND_CORE_TEMP: tempfile.TemporaryDirectory[str] | None = None
_BOUND_CORE_MANIFEST_SHA256: str | None = None
if (
    isinstance(_BOUND_REVIEW_SOURCE, types.ModuleType)
    and getattr(_BOUND_REVIEW_SOURCE, "contract", None) == "SupervisorReviewSource/v1"
):
    resources = getattr(_BOUND_REVIEW_SOURCE, "resources", None)
    profile_value = getattr(_BOUND_REVIEW_SOURCE, "profile_root", None)
    expected_core_manifest = getattr(
        _BOUND_REVIEW_SOURCE, "core_manifest_sha256", None
    )
    if (
        not isinstance(resources, dict)
        or not resources
        or not isinstance(profile_value, str)
        or not Path(profile_value).is_absolute()
        or not isinstance(expected_core_manifest, str)
        or not re.fullmatch(r"[0-9a-f]{64}", expected_core_manifest)
    ):
        raise RuntimeError("bound review source contract invalid")
    _BOUND_CORE_TEMP = tempfile.TemporaryDirectory(prefix="supervisor-bound-review-core-")
    CORE_ROOT = Path(_BOUND_CORE_TEMP.name)
    observed_manifest: dict[str, str] = {}
    total_size = 0
    for raw_name, content in sorted(resources.items()):
        if len(observed_manifest) >= MAX_REVIEW_FILES:
            raise RuntimeError("bound review source has too many entries")
        if not isinstance(raw_name, str) or not isinstance(content, bytes):
            raise RuntimeError("bound review source entry invalid")
        relative = PurePosixPath(raw_name)
        if (
            relative.is_absolute()
            or "\\" in raw_name
            or any(part in {"", ".", ".."} for part in relative.parts)
            or len(content) < 1
            or len(content) > 4 * 1024 * 1024
        ):
            raise RuntimeError("bound review source entry invalid")
        total_size += len(content)
        if total_size > 16 * 1024 * 1024:
            raise RuntimeError("bound review source too large")
        target = CORE_ROOT.joinpath(*relative.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        observed_manifest[f"global-core/{raw_name}"] = hashlib.sha256(content).hexdigest()
    observed_manifest_sha256 = hashlib.sha256(
        json.dumps(
            observed_manifest,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    if observed_manifest_sha256 != expected_core_manifest:
        raise RuntimeError("bound review source manifest mismatch")
    _BOUND_CORE_MANIFEST_SHA256 = observed_manifest_sha256
    PROFILE_ROOT = Path(os.path.abspath(profile_value))
else:
    CORE_ROOT = Path(os.path.abspath(Path(__file__).parent.parent))
    if CORE_ROOT.name == ".agent-supervisor":
        PROFILE_ROOT = CORE_ROOT.parent
    elif CORE_ROOT.parent.name == ".agent-supervisor-releases":
        PROFILE_ROOT = CORE_ROOT.parent.parent
    elif (
        (CORE_ROOT / "pyproject.toml").is_file()
        and (CORE_ROOT / "supervisor_core").is_dir()
        and (CORE_ROOT / "integrations").is_dir()
    ):
        # A source checkout is a supported local-review layout.  Its exact
        # files are copied and hashed into the disposable review repository
        # before any external process is launched.
        PROFILE_ROOT = CORE_ROOT
    else:
        raise RuntimeError("unsupported immutable Supervisor core layout")
SUPERVISOR_DATA_ROOT = PROFILE_ROOT / ".agent-supervisor"
PROJECT_ROOT = Path(os.path.abspath(Path.cwd()))
BLOCKING_SEVERITIES = {"p0", "p1", "critical", "major", "high", "error"}
NONBLOCKING_SEVERITIES = {"p2", "p3", "minor", "medium", "low", "info", "warning", "suggestion", "nitpick"}
TERMINAL_EVENT_TYPES = {
    "review_complete", "review_completed", "review_end", "review_result",
    "complete", "completed", "summary",
}
TERMINAL_SUCCESS_STATUSES = {
    "complete", "completed", "finished", "success", "passed", "review_completed",
}
TERMINAL_FAILURE_STATUSES = {"failed", "failure", "error", "blocked", "cancelled", "canceled"}
ERROR_EVENT_TYPES = {"error", "review_error", "fatal"}
FINDING_EVENT_TYPES = {"finding", "review_finding", "issue"}
AUTH_TIMEOUT_SECONDS = 30
REVIEW_TIMEOUT_SECONDS = 900
_ACTIVE_REVIEW_BINDING_FILE: str | None = None
_ACTIVE_REVIEW_ARTIFACT_ROOT: str | None = None
_ACTIVE_REVIEW_CATEGORY = "independent"
REVIEW_CATEGORIES = {"independent", "test-integrity"}
_GIT_REDIRECT_ENV = {
    "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR",
    "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_CONFIG", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT",
}


class DuplicateKeyEvent(ValueError):
    pass


class InvalidAliasShape(ValueError):
    pass


class ReviewScopeError(RuntimeError):
    """The disposable review payload could not be proven safe."""


class ReviewArtifactError(RuntimeError):
    """A stable, redacted review-artifact contract failure."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


_KNOWN_CREDENTIAL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("aws-access-key", re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])")),
    ("github-token", re.compile(r"(?<![A-Za-z0-9])(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})")),
    ("provider-token", re.compile(r"(?<![A-Za-z0-9])sk-(?:ant-|proj-)?[A-Za-z0-9_-]{24,}")),
    (
        "jwt",
        re.compile(
            r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{16,}"
            r"(?![A-Za-z0-9_-])"
        ),
    ),
    (
        "credentialed-url",
        re.compile(
            r"(?i)\b(?:https?|postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss)://"
            r"[^\s/:@]+:[^\s/@]+@[^\s/]+"
        ),
    ),
    (
        "basic-auth",
        re.compile(r"(?i)\bauthorization\s*:\s*basic\s+[A-Za-z0-9+/]{12,}={0,2}"),
    ),
    (
        "slack-webhook",
        re.compile(
            r"(?i)https://hooks\.slack\.com/services/[A-Za-z0-9_-]{8,}/"
            r"[A-Za-z0-9_-]{8,}/[A-Za-z0-9_-]{16,}"
        ),
    ),
    (
        "discord-webhook",
        re.compile(
            r"(?i)https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/"
            r"[0-9]{10,}/[A-Za-z0-9._-]{16,}"
        ),
    ),
    (
        "wecom-webhook",
        re.compile(
            r"(?i)https://qyapi\.weixin\.qq\.com/cgi-bin/webhook/send\?key="
            r"[A-Za-z0-9_-]{16,}"
        ),
    ),
)
_PASSWORD_LITERAL = re.compile(
    r"(?ix)\b(?:password|passwd|pwd)\b\s*(?:=|:)?\s*"
    r"(?:\"([^\"\r\n]{1,256})\"|'([^'\r\n]{1,256})'|([^\s,;)\]}]{1,256}))"
)
_SECRET_ASSIGNMENT = re.compile(
    r"(?ix)\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|mch[_-]?key)\b"
    r"\s*(?:=|:)\s*(?:\"([^\"\r\n]{1,512})\"|'([^'\r\n]{1,512})'|([^\s,;)\]}]{1,512}))"
)
_COOKIE_SESSION_LITERAL = re.compile(
    r"(?ix)(?:"
    r"\b(?:session[_-]?(?:id|token)|connect\.sid|brown[_-]zone[_-]session)\b\s*(?:=|:)\s*"
    r"|\bcookie\s*:\s*(?:[A-Za-z0-9_.-]{1,64}=)?"
    r")(?:\"([^\"\r\n;]{1,512})\"|'([^'\r\n;]{1,512})'|([^\s,;)\]}]{1,512}))"
)
_PLACEHOLDER_MARKERS = {
    "<", "${", "example", "dummy", "placeholder", "redacted", "changeme",
    "process.env", "os.environ", "getenv", "environment variable", "private channel",
}


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateKeyEvent(key)
        value[key] = item
    return value


def strict_json_loads(raw: str) -> Any:
    return json.loads(raw, object_pairs_hook=_reject_duplicate_keys)


_TRUST_REGISTRY_CACHE: dict[str, Any] | None = None
_TRUST_ENTRY_FIELDS = {"kind", "path", "sha256"}
_TRUST_ENTRY_OPTIONAL_FIELDS = {"allowed_argv_sha256"}
_TRUST_REGISTRY_FIELDS = {"contract", "entries", "generated_at"}
_SAFE_ENV_NAMES = {
    "APPDATA", "COMSPEC", "HOMEDRIVE", "HOMEPATH", "LOCALAPPDATA",
    "OS", "PROGRAMDATA", "SYSTEMDRIVE", "SYSTEMROOT", "TEMP", "TMP",
    "USERDOMAIN", "USERNAME", "USERPROFILE", "WINDIR",
}


def _stable_file_digest(path: Path, *, maximum: int) -> tuple[Path, str]:
    lexical = Path(os.path.abspath(os.fspath(path)))
    if not lexical.is_absolute() or _path_has_reparse(lexical):
        raise RuntimeError("trusted executable path invalid")
    resolved = lexical.resolve(strict=True)
    if os.path.normcase(str(resolved)) != os.path.normcase(str(lexical)):
        raise RuntimeError("trusted executable path invalid")
    before = resolved.stat(follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode) or before.st_size < 2 or before.st_size > maximum:
        raise RuntimeError("trusted executable size invalid")
    digest = hashlib.sha256()
    observed_size = 0
    with resolved.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            observed_size += len(chunk)
            if observed_size > maximum:
                raise RuntimeError("trusted executable size invalid")
            digest.update(chunk)
    after = resolved.stat(follow_symlinks=False)
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_after or observed_size != before.st_size:
        raise RuntimeError("trusted executable changed during verification")
    return lexical, digest.hexdigest()


def _load_machine_trust_registry() -> dict[str, Any]:
    global _TRUST_REGISTRY_CACHE
    if isinstance(_TRUST_REGISTRY_CACHE, dict):
        return _TRUST_REGISTRY_CACHE
    expected = os.environ.get("AGENT_SUPERVISOR_TRUST_REGISTRY_SHA256", "")
    path = SUPERVISOR_DATA_ROOT / "trusted-executables.json"
    trusted = _trusted_regular_file(path, "trusted-executable-registry-unavailable")
    before = trusted.stat(follow_symlinks=False)
    if before.st_size < 2 or before.st_size > 1024 * 1024:
        raise RuntimeError("trusted executable registry size invalid")
    content = trusted.read_bytes()
    after = trusted.stat(follow_symlinks=False)
    observed_registry_sha256 = hashlib.sha256(content).hexdigest()
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        if __name__ == "__main__":
            raise RuntimeError("round-bound executable trust registry missing")
        expected = observed_registry_sha256
    if (
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or len(content) != before.st_size
        or observed_registry_sha256 != expected
    ):
        raise RuntimeError("trusted executable registry drift")
    try:
        value = strict_json_loads(content.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, DuplicateKeyEvent):
        raise RuntimeError("trusted executable registry invalid") from None
    if (
        not isinstance(value, dict)
        or set(value) != _TRUST_REGISTRY_FIELDS
        or value.get("contract") != "TrustedExecutableRegistry/v1"
        or not isinstance(value.get("generated_at"), str)
        or not isinstance(value.get("entries"), dict)
        or not value["entries"]
    ):
        raise RuntimeError("trusted executable registry invalid")
    for name, entry in value["entries"].items():
        if (
            not isinstance(name, str)
            or name != name.casefold()
            or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", name)
            or not isinstance(entry, dict)
            or not _TRUST_ENTRY_FIELDS <= set(entry)
            or bool(set(entry) - _TRUST_ENTRY_FIELDS - _TRUST_ENTRY_OPTIONAL_FIELDS)
            or entry.get("kind") not in {"local", "wsl"}
            or not isinstance(entry.get("path"), str)
            or not entry["path"]
            or not isinstance(entry.get("sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])
            or not isinstance(entry.get("allowed_argv_sha256", []), list)
            or len(entry.get("allowed_argv_sha256", [])) > 256
            or any(
                not isinstance(item, str) or not re.fullmatch(r"[0-9a-f]{64}", item)
                for item in entry.get("allowed_argv_sha256", [])
            )
            or len(set(entry.get("allowed_argv_sha256", [])))
            != len(entry.get("allowed_argv_sha256", []))
        ):
            raise RuntimeError("trusted executable registry invalid")
    _TRUST_REGISTRY_CACHE = value
    return value


def _verified_local_executable(name: str) -> str:
    registry = _load_machine_trust_registry()
    entry = registry["entries"].get(name)
    if not isinstance(entry, dict) or entry.get("kind") != "local":
        raise RuntimeError(f"trusted executable unavailable: {name}")
    path, observed = _stable_file_digest(
        Path(entry["path"]), maximum=512 * 1024 * 1024
    )
    if observed != entry["sha256"]:
        raise RuntimeError(f"trusted executable digest mismatch: {name}")
    return str(path)


def _trusted_wsl_entry(name: str) -> tuple[str, str]:
    registry = _load_machine_trust_registry()
    entry = registry["entries"].get(name)
    if not isinstance(entry, dict) or entry.get("kind") != "wsl":
        raise RuntimeError(f"trusted WSL executable unavailable: {name}")
    path = PurePosixPath(str(entry["path"]))
    if (
        not path.is_absolute()
        or path.as_posix() != entry["path"]
        or any(part in {"", ".", ".."} for part in path.parts[1:])
    ):
        raise RuntimeError("trusted WSL executable path invalid")
    return path.as_posix(), str(entry["sha256"])


def _minimal_environment() -> dict[str, str]:
    registry = _load_machine_trust_registry()
    environment = {
        name: value
        for name, value in os.environ.items()
        if name.upper() in _SAFE_ENV_NAMES and isinstance(value, str)
    }
    directories: list[str] = []
    seen: set[str] = set()
    for entry in registry["entries"].values():
        if isinstance(entry, dict) and entry.get("kind") == "local":
            parent = str(Path(str(entry["path"])).parent)
            key = os.path.normcase(parent)
            if key not in seen:
                seen.add(key)
                directories.append(parent)
    if not directories:
        raise RuntimeError("trusted executable PATH unavailable")
    environment.update({
        "NoDefaultCurrentDirectoryInExePath": "1",
        "PATH": os.pathsep.join(directories),
    })
    return environment


def _resolved_command(command: list[str]) -> list[str]:
    if not command:
        raise RuntimeError("empty external command")
    token = str(command[0])
    if token == "git":
        executable = _verified_local_executable("git")
    elif os.path.isabs(token):
        registry = _load_machine_trust_registry()
        matches = [
            name
            for name, entry in registry["entries"].items()
            if isinstance(entry, dict)
            and entry.get("kind") == "local"
            and os.path.normcase(str(entry.get("path") or ""))
            == os.path.normcase(str(Path(os.path.abspath(token))))
        ]
        if len(matches) != 1:
            raise RuntimeError("external command is not registered")
        executable = _verified_local_executable(matches[0])
    else:
        raise RuntimeError("external command alias is not registered")
    return [executable, *command[1:]]


def _alias_values(event: dict[str, Any], keys: tuple[str, ...]) -> list[str]:
    """Return every present alias value so a later alias cannot hide a failure."""
    values: list[str] = []
    for key in keys:
        if key not in event:
            continue
        value = event[key]
        if not isinstance(value, str):
            raise InvalidAliasShape(key)
        values.append(value.strip().casefold())
    return values


def _event_type_group(value: str) -> str:
    if value in ERROR_EVENT_TYPES:
        return "error"
    if value in TERMINAL_EVENT_TYPES:
        return "terminal"
    if value in FINDING_EVENT_TYPES:
        return "finding"
    return "other" if value else "empty"


def _status_group(value: str) -> str:
    if value in TERMINAL_FAILURE_STATUSES or value == "not_authenticated":
        return "failure"
    if value in TERMINAL_SUCCESS_STATUSES or value == "authenticated":
        return "success"
    return "other" if value else "empty"


def _append_once(values: list[str], value: str) -> None:
    if value not in values:
        values.append(value)


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _is_link_or_reparse(path: Path) -> bool:
    try:
        details = os.lstat(path)
    except OSError:
        return False
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    file_attributes = getattr(details, "st_file_attributes", 0)
    return stat.S_ISLNK(details.st_mode) or bool(reparse_flag and file_attributes & reparse_flag)


def _safe_source(source_root: Path, source: Path) -> tuple[Path, Path]:
    """Return resolved source and relative path after rejecting indirection/escape."""
    root_absolute = Path(os.path.abspath(source_root))
    source_absolute = Path(os.path.abspath(source))
    try:
        lexical_relative = source_absolute.relative_to(root_absolute)
    except ValueError as exc:
        raise ReviewScopeError("root-escape") from exc

    current = root_absolute
    for part in (None, *lexical_relative.parts):
        if part is not None:
            current /= part
        if _is_link_or_reparse(current):
            raise ReviewScopeError("link-or-reparse")

    try:
        root_resolved = root_absolute.resolve(strict=True)
        source_resolved = source_absolute.resolve(strict=True)
        relative = source_resolved.relative_to(root_resolved)
    except (OSError, ValueError) as exc:
        raise ReviewScopeError("root-escape") from exc
    if not source_resolved.is_file():
        raise ReviewScopeError("non-regular-source")
    return source_resolved, relative


def _looks_like_literal_secret(value: str, *, minimum_length: int, minimum_classes: int) -> bool:
    candidate = value.strip().strip("`\"'")
    lowered = candidate.casefold()
    if len(candidate) < minimum_length or any(marker in lowered for marker in _PLACEHOLDER_MARKERS):
        return False
    classes = sum((
        any(character.islower() for character in candidate),
        any(character.isupper() for character in candidate),
        any(character.isdigit() for character in candidate),
        any(not character.isalnum() for character in candidate),
    ))
    return classes >= minimum_classes


def credential_finding(content: bytes) -> str | None:
    """Return only a finding category; never return or log credential material."""
    text = content.decode("utf-8", errors="ignore")
    for category, pattern in _KNOWN_CREDENTIAL_PATTERNS:
        for match in pattern.finditer(text):
            matched = match.group(0).casefold()
            synthetic = (
                category != "private-key"
                and (
                    any(marker in matched for marker in _PLACEHOLDER_MARKERS)
                    or (
                        category in {
                            "credentialed-url", "slack-webhook", "discord-webhook",
                            "wecom-webhook",
                        }
                        and ".invalid" in matched
                    )
                )
            )
            if not synthetic:
                return category
    for pattern, minimum_length, minimum_classes, category in (
        (_PASSWORD_LITERAL, 10, 3, "password-literal"),
        (_SECRET_ASSIGNMENT, 16, 2, "secret-assignment"),
    ):
        for match in pattern.finditer(text):
            value = next((item for item in match.groups() if item is not None), "")
            if _looks_like_literal_secret(
                value,
                minimum_length=minimum_length,
                minimum_classes=minimum_classes,
            ):
                return category
    for match in _COOKIE_SESSION_LITERAL.finditer(text):
        value = next((item for item in match.groups() if item is not None), "")
        letter_only_token_shape = (
            len(value) >= 32
            and any(character.islower() for character in value)
            and any(character.isupper() for character in value)
        )
        if (
            (any(character.isdigit() for character in value) or letter_only_token_shape)
            and len(set(value)) >= 8
            and _looks_like_literal_secret(value, minimum_length=20, minimum_classes=2)
        ):
            return "cookie-session-literal"
    return None


def excluded(path: Path) -> bool:
    lowered = [part.casefold() for part in path.parts]
    name = path.name.casefold()
    return (
        any(
            part in {
                ".git",
                "__pycache__",
                ".pytest_cache",
                ".codex-supervisor",
                "state",
                "logs",
                "cache",
                "handoffs",
                "review-artifacts",
            }
            for part in lowered
        )
        or any(part.startswith(".pytest-tmp") for part in lowered)
        or any(part in {"test-results", ".next", "node_modules"} for part in lowered)
        or name == "settings.local.json"
        or name.startswith("settings.local.")
        or name in {"active-version.json", "handoff.md", "timeline.jsonl", "ledger.json"}
        or name.endswith((".key", ".pem", ".pfx", ".log"))
        or name.startswith(".env")
    )


def files_under(root: Path) -> list[Path]:
    root = Path(os.path.abspath(root))
    result: list[Path] = []
    visited = 0
    for current, directories, files in os.walk(root):
        current_path = Path(current)
        try:
            depth = len(current_path.relative_to(root).parts)
        except ValueError as exc:
            raise ReviewScopeError("root-escape") from exc
        if depth > MAX_REVIEW_DEPTH:
            raise ReviewScopeError("review-source-depth-limit")
        retained_directories: list[str] = []
        for name in directories:
            visited += 1
            if visited > MAX_REVIEW_FILES * 8:
                raise ReviewScopeError("review-source-entry-limit")
            candidate = current_path / name
            if excluded(candidate.relative_to(root)):
                continue
            if _is_link_or_reparse(candidate):
                result.append(candidate)
            else:
                retained_directories.append(name)
        directories[:] = retained_directories
        for name in files:
            visited += 1
            if visited > MAX_REVIEW_FILES * 8:
                raise ReviewScopeError("review-source-entry-limit")
            candidate = current_path / name
            if not excluded(candidate.relative_to(root)):
                result.append(candidate)
                if len(result) > MAX_REVIEW_FILES:
                    raise ReviewScopeError("review-source-file-count-limit")
    return result


def _configured_agent_paths(configured: dict[str, Any]) -> list[Path]:
    """Resolve only manifest paths whose filenames are identity-bound."""
    roles = configured.get("agent_roles")
    if not isinstance(roles, list):
        raise ReviewScopeError("invalid-agent-role-manifest")
    paths: list[Path] = []
    for role in roles:
        if not isinstance(role, dict):
            raise ReviewScopeError("invalid-agent-role-manifest")
        agent_id = role.get("id")
        fallback_id = role.get("fallback_id")
        if (
            not isinstance(agent_id, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", agent_id)
            or fallback_id != f"brown_zone_fallback_{agent_id}"
        ):
            raise ReviewScopeError("invalid-agent-config-binding")
        for identity, config_key in (
            (agent_id, "config"),
            (fallback_id, "fallback_config"),
        ):
            relative = role.get(config_key)
            expected = f".codex/agents/{identity}.toml"
            if not isinstance(relative, str) or relative != expected:
                raise ReviewScopeError("invalid-agent-config-binding")
            paths.append(Path(relative))
    return paths


def source_groups(project_root: Path = PROJECT_ROOT, profile_root: Path = PROFILE_ROOT, core_root: Path = CORE_ROOT) -> list[tuple[str, Path, Iterable[Path]]]:
    # Never externalize user settings, hook registries, project manifests, or
    # prompt-bearing state. The immutable workspace binding carries only hashes
    # and paths; externally reviewed source comes from the release snapshot.
    core_candidates: list[Path] = []
    for relative in (
        "supervisor_core",
        "schemas",
        "tests",
        "bin",
        "README.md",
        "pyproject.toml",
        "VERSION",
        ".gitignore",
    ):
        candidate = core_root / relative
        if candidate.is_dir():
            core_candidates.extend(files_under(candidate))
        elif candidate.is_file():
            core_candidates.append(candidate)

    # Bind adapters to the same release snapshot as the core.  Reading the
    # user's installed skill trees would both review different bytes and risk
    # externalizing machine-local configuration accidentally placed there.
    claude_root = core_root / "integrations" / "claude"
    claude_candidates = files_under(claude_root) if claude_root.is_dir() else []
    codex_root = core_root / "integrations" / "codex"
    codex_candidates = files_under(codex_root) if codex_root.is_dir() else []
    return [
        ("global-core", core_root, core_candidates),
        ("release-claude", claude_root, claude_candidates),
        ("release-codex", codex_root, codex_candidates),
    ]


def _review_category_instructions(category: str) -> bytes:
    if category == "test-integrity":
        text = (
            "CodeRabbit independent test-integrity review. Review only whether this diff deletes tests, "
            "adds skip/only/todo, relaxes thresholds, weakens assertions, or changes assertions alongside "
            "implementation in a way that can hide regressions. Treat any unresolved instance as a major "
            "blocking finding. Inspect the complete immutable Supervisor snapshot.\n"
        )
    else:
        text = (
            "CodeRabbit independent implementation review. Inspect the complete "
            "immutable snapshot. Report every correctness, security, goal-alignment, portability, and "
            "quality issue; unresolved critical or major findings block approval.\n"
        )
    return text.encode("utf-8")


def prepare_review_tree(destination: Path, groups: list[tuple[str, Path, Iterable[Path]]] | None = None, *, review_category: str = "independent") -> list[dict[str, str]]:
    prepared: list[tuple[str, Path, bytes]] = []
    manifest: list[dict[str, str]] = []
    total_bytes = 0
    for label, source_root, candidates in groups or source_groups():
        for source in sorted(set(candidates)):
            if not source.exists() and not source.is_symlink():
                continue
            source_resolved, relative = _safe_source(source_root, source)
            if excluded(relative):
                continue
            before = os.stat(source_resolved, follow_symlinks=False)
            if before.st_size < 1 or before.st_size > MAX_REVIEW_FILE_BYTES:
                raise ReviewScopeError("review-source-file-size-limit")
            with source_resolved.open("rb") as handle:
                content = handle.read(MAX_REVIEW_FILE_BYTES + 1)
            if len(content) > MAX_REVIEW_FILE_BYTES:
                raise ReviewScopeError("review-source-file-size-limit")
            after = os.stat(source_resolved, follow_symlinks=False)
            identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            if identity_before != identity_after or len(content) != after.st_size:
                raise ReviewScopeError("source-mutated-during-scan")
            if credential_finding(content):
                raise ReviewScopeError("credential-literal")
            if len(prepared) >= MAX_REVIEW_FILES:
                raise ReviewScopeError("review-source-file-count-limit")
            total_bytes += len(content)
            if total_bytes > MAX_REVIEW_TOTAL_BYTES:
                raise ReviewScopeError("review-source-total-size-limit")
            prepared.append((label, relative, content))

    if review_category not in REVIEW_CATEGORIES:
        raise ReviewScopeError("invalid-review-category")
    if not prepared:
        raise ReviewScopeError("empty-review-scope")
    if destination.exists() and _is_link_or_reparse(destination):
        raise ReviewScopeError("destination-link-or-reparse")
    for label, relative, content in prepared:
        target = destination / label / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        manifest.append({
            "path": target.relative_to(destination).as_posix(),
            "sha256": hashlib.sha256(content).hexdigest(),
        })
    category_path = destination / "REVIEW_CATEGORY.md"
    category_content = _review_category_instructions(review_category)
    category_path.write_bytes(category_content)
    manifest.append({
        "path": "REVIEW_CATEGORY.md",
        "sha256": hashlib.sha256(category_content).hexdigest(),
    })
    manifest = _normalized_source_manifest(manifest)
    (destination / "REVIEW_MANIFEST.json").write_bytes(
        review_manifest_bytes(manifest)
    )
    return manifest


def _normalized_source_manifest(
    manifest: list[dict[str, str]],
) -> list[dict[str, str]]:
    """Return the strict, path-sorted manifest for the committed review payload."""
    normalized: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in manifest:
        if not isinstance(row, dict) or set(row) != {"path", "sha256"}:
            raise ReviewScopeError("invalid-source-manifest")
        path = row.get("path")
        digest = row.get("sha256")
        if (
            not _valid_delta_path(path)
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or path in seen
        ):
            raise ReviewScopeError("invalid-source-manifest")
        seen.add(path)
        normalized.append({"path": path, "sha256": digest})
    return sorted(normalized, key=lambda row: row["path"])


def review_manifest_bytes(manifest: list[dict[str, str]]) -> bytes:
    normalized = _normalized_source_manifest(manifest)
    payload = json.dumps({"files": normalized}, indent=2, sort_keys=True) + "\n"
    return payload.encode("utf-8")


def review_manifest_hash(manifest: list[dict[str, str]]) -> str:
    return hashlib.sha256(review_manifest_bytes(manifest)).hexdigest()


def _expected_full_snapshot_manifest(
    manifest: list[dict[str, str]],
) -> dict[str, str]:
    normalized = _normalized_source_manifest(manifest)
    result = {row["path"]: row["sha256"] for row in normalized}
    if "REVIEW_MANIFEST.json" in result:
        raise ReviewScopeError("invalid-source-manifest")
    result["REVIEW_MANIFEST.json"] = hashlib.sha256(
        review_manifest_bytes(normalized)
    ).hexdigest()
    return dict(sorted(result.items()))


def _verified_full_snapshot_manifest(
    repo: Path,
    baseline: str,
    head: str,
    manifest: list[dict[str, str]],
) -> dict[str, str]:
    """Prove the artifact range is an empty tree followed by the exact payload."""
    try:
        base_tree = _run_bytes(
            ["git", "ls-tree", "-rz", "--full-tree", baseline],
            repo,
            timeout=60,
            env=_git_environment(),
        )
        head_tree = _run_bytes(
            ["git", "ls-tree", "-rz", "--full-tree", head],
            repo,
            timeout=60,
            env=_git_environment(),
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ReviewArtifactError("review-artifact-tree-unavailable") from None
    if base_tree.returncode or base_tree.stdout:
        raise ReviewArtifactError("review-artifact-base-not-empty")
    if head_tree.returncode:
        raise ReviewArtifactError("review-artifact-tree-unavailable")

    observed: dict[str, str] = {}
    for raw in head_tree.stdout.split(b"\0"):
        if not raw:
            continue
        try:
            metadata, path_bytes = raw.split(b"\t", 1)
            mode, object_type, oid = metadata.decode("ascii").split(" ", 2)
            path = path_bytes.decode("utf-8")
        except (UnicodeError, ValueError):
            raise ReviewArtifactError("review-artifact-tree-invalid") from None
        if (
            mode != "100644"
            or object_type != "blob"
            or not _valid_delta_path(path)
            or path in observed
        ):
            raise ReviewArtifactError("review-artifact-tree-invalid")
        blob = _run_bytes(
            ["git", "cat-file", "blob", oid],
            repo,
            timeout=60,
            env=_git_environment(),
        )
        if blob.returncode:
            raise ReviewArtifactError("review-artifact-tree-unavailable")
        observed[path] = hashlib.sha256(blob.stdout).hexdigest()

    expected = _expected_full_snapshot_manifest(manifest)
    if dict(sorted(observed.items())) != expected:
        raise ReviewArtifactError("review-artifact-source-manifest-mismatch")
    return expected


def _bounded_text(value: Any, *, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    without_code = re.sub(r"```.*?```", "[code omitted]", value, flags=re.DOTALL)
    without_code = re.sub(r"`[^`\r\n]*`", "[code omitted]", without_code)
    secret_category = credential_finding(without_code.encode("utf-8", errors="ignore"))
    if secret_category:
        without_code = f"[REDACTED:{secret_category}]"
    normalized = " ".join(without_code.split())
    if len(normalized) <= limit:
        return normalized
    return normalized[: limit - 1].rstrip() + "…"


def _safe_issue_path(event: dict[str, Any]) -> tuple[str, bool]:
    values: list[Any] = [
        event[key] for key in ("fileName", "path", "file", "file_path") if key in event
    ]
    location = event.get("location")
    if isinstance(location, dict):
        values.extend(location[key] for key in ("path", "file", "file_path") if key in location)
    if not values:
        return "", True
    if any(not isinstance(value, str) for value in values):
        return "", False
    normalized_values = {value.strip().replace("\\", "/") for value in values}
    if len(normalized_values) != 1:
        return "", False
    normalized = normalized_values.pop()
    if (
        not normalized
        or normalized.startswith(("/", "//"))
        or re.match(r"^[A-Za-z]:", normalized)
        or ":" in normalized
        or any(ord(character) < 32 for character in normalized)
        or credential_finding(normalized.encode("utf-8", errors="ignore")) is not None
    ):
        return "", False
    parts = normalized.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return "", False
    return "/".join(parts), True


def _issue_line(event: dict[str, Any]) -> int | None:
    values: list[Any] = [
        event[key]
        for key in ("startLine", "lineNumber", "line", "line_number")
        if key in event
    ]
    location = event.get("location")
    if isinstance(location, dict):
        values.extend(location[key] for key in ("line", "line_number") if key in location)
    for value in values:
        if isinstance(value, bool):
            continue
        if isinstance(value, int) and value > 0:
            return value
        if isinstance(value, str) and value.isascii() and value.isdigit() and int(value) > 0:
            return int(value)
    return None


def _first_text(event: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = event.get(key)
        if isinstance(value, str):
            return value
    return ""


def _structured_issue(
    event: dict[str, Any],
    *,
    kind: str,
    severity: str,
) -> tuple[dict[str, Any], bool]:
    path, path_is_valid = _safe_issue_path(event)
    default_title = "CodeRabbit error" if kind == "error" else "CodeRabbit finding"
    title = _bounded_text(
        _first_text(event, ("title", "summary", "comment")), limit=160
    ) or default_title
    message = _bounded_text(
        _first_text(
            event,
            ("codegenInstructions", "message", "description", "detail", "comment"),
        ),
        limit=500,
    )
    return ({
        "kind": kind,
        "severity": severity,
        "path": path,
        "line": _issue_line(event),
        "title": title,
        "message": message,
    }, path_is_valid)


def _parse_agent_output_details(output: str) -> dict[str, Any]:
    protocol_blockers: list[str] = []
    issues: list[dict[str, Any]] = []
    parsed = 0
    terminal_outcome = "missing"
    complete_events = 0
    complete_reported_findings: int | None = None
    finding_events = 0
    review_contexts: list[dict[str, str]] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        try:
            event = strict_json_loads(line)
        except DuplicateKeyEvent:
            _append_once(protocol_blockers, "duplicate-key-event")
            continue
        except json.JSONDecodeError:
            _append_once(protocol_blockers, "unparseable-event")
            continue
        if not isinstance(event, dict):
            _append_once(protocol_blockers, "invalid-event-shape")
            continue
        parsed += 1
        event_type = event.get("type")
        if not isinstance(event_type, str) or not event_type.strip():
            _append_once(protocol_blockers, "invalid-event-type")
            continue
        event_type = event_type.strip().casefold()

        if event_type == "review_context":
            fields = {
                key: event.get(key)
                for key in ("reviewType", "currentBranch", "baseBranch", "baseCommit", "workingDirectory")
            }
            required = ("reviewType", "currentBranch", "baseBranch", "workingDirectory")
            if any(not isinstance(fields[key], str) or not fields[key] for key in required):
                _append_once(protocol_blockers, "invalid-review-context")
                continue
            if fields["baseCommit"] is not None and not isinstance(fields["baseCommit"], str):
                _append_once(protocol_blockers, "invalid-review-context")
                continue
            review_contexts.append({key: str(value or "") for key, value in fields.items()})
            continue

        if event_type == "status":
            if not isinstance(event.get("phase"), str) or not isinstance(event.get("status"), str):
                _append_once(protocol_blockers, "invalid-status-event")
            continue

        # CodeRabbit CLI 0.7.x emits heartbeat progress records between
        # findings.  They are non-terminal and carry no review result.
        if event_type == "heartbeat":
            if event.get("status") != "reviewing":
                _append_once(protocol_blockers, "invalid-heartbeat-event")
            continue

        if event_type == "error":
            if (
                not isinstance(event.get("errorType"), str)
                or not isinstance(event.get("message"), str)
                or not isinstance(event.get("recoverable"), bool)
            ):
                _append_once(protocol_blockers, "invalid-error-event")
            terminal_outcome = "failure"
            issue, _ = _structured_issue(event, kind="error", severity="error")
            issues.append(issue)
            continue

        if event_type == "finding":
            finding_events += 1
            severity_value = event.get("severity")
            severity = severity_value.strip().casefold() if isinstance(severity_value, str) else ""
            if severity not in BLOCKING_SEVERITIES | NONBLOCKING_SEVERITIES:
                _append_once(protocol_blockers, "unknown-severity")
                severity = "unknown"
            instructions = event.get("codegenInstructions")
            suggestions = event.get("suggestions")
            if not isinstance(instructions, str) or not isinstance(suggestions, list) or any(
                not isinstance(item, str) for item in suggestions
            ):
                _append_once(protocol_blockers, "invalid-finding-event")
            issue, path_is_valid = _structured_issue(
                event,
                kind="finding",
                severity=severity,
            )
            issues.append(issue)
            if not path_is_valid:
                _append_once(protocol_blockers, "invalid-issue-path")
            continue

        if event_type == "complete":
            complete_events += 1
            status = event.get("status")
            findings = event.get("findings")
            if (
                status != "review_completed"
                or isinstance(findings, bool)
                or not isinstance(findings, int)
                or findings < 0
            ):
                _append_once(protocol_blockers, "invalid-complete-event")
                terminal_outcome = "ambiguous" if terminal_outcome != "failure" else terminal_outcome
                continue
            if complete_reported_findings is not None and complete_reported_findings != findings:
                _append_once(protocol_blockers, "conflicting-complete-count")
            complete_reported_findings = findings
            if terminal_outcome != "failure":
                terminal_outcome = "success"
            continue

        _append_once(protocol_blockers, "unknown-event-type")

    if complete_events > 1:
        _append_once(protocol_blockers, "multiple-complete-events")
    if complete_reported_findings is not None and complete_reported_findings != finding_events:
        _append_once(protocol_blockers, "finding-count-mismatch")
    return {
        "parsed": parsed,
        "protocol_blockers": protocol_blockers,
        "terminal_outcome": terminal_outcome,
        "issues": issues,
        "finding_events": finding_events,
        "complete_events": complete_events,
        "complete_reported_findings": complete_reported_findings,
        "review_contexts": review_contexts,
    }


def parse_agent_output(output: str) -> tuple[int, list[str], str]:
    details = _parse_agent_output_details(output)
    return details["parsed"], details["protocol_blockers"], details["terminal_outcome"]


def _merge_agent_output_details(stdout: str, stderr: str) -> dict[str, Any]:
    combined = _parse_agent_output_details(stdout)
    if not stderr.strip():
        return combined
    diagnostics = _parse_agent_output_details(stderr)
    combined["parsed"] += diagnostics["parsed"]
    for finding in diagnostics["protocol_blockers"]:
        _append_once(combined["protocol_blockers"], finding)
    # Official agent NDJSON is stdout-only.  Structured findings on stderr are
    # protocol drift and must never be silently double-counted.
    if diagnostics["finding_events"]:
        _append_once(combined["protocol_blockers"], "structured-findings-on-stderr")
    # Review identity/binding records are stdout-only. A stderr context is
    # protocol drift and must never participate in context binding.
    if diagnostics["review_contexts"]:
        _append_once(combined["protocol_blockers"], "review-context-on-stderr")
    combined["issues"].extend(
        issue for issue in diagnostics["issues"] if issue.get("kind") == "error"
    )
    if diagnostics["terminal_outcome"] == "failure":
        combined["terminal_outcome"] = "failure"
    if diagnostics["complete_events"]:
        _append_once(combined["protocol_blockers"], "complete-event-on-stderr")
    return combined


def evaluate_review(
    output: str,
    *,
    stderr: str = "",
    exit_code: int,
    reviewed_files: int,
    manifest_sha256: str,
    expected_base_commit: str | None = None,
    expected_head_commit: str | None = None,
    diff_sha256: str | None = None,
    expected_working_directory: str | None = None,
) -> tuple[dict[str, Any], int]:
    """Map CodeRabbit's structured stream to a fail-closed gate result."""
    details = _merge_agent_output_details(output, stderr)
    parsed = details["parsed"]
    protocol_blockers = details["protocol_blockers"]
    terminal_outcome = details["terminal_outcome"]
    context_bound: bool | None = None
    if expected_base_commit is not None or expected_working_directory is not None:
        contexts = details["review_contexts"]
        context_bound = len(contexts) == 1
        if context_bound:
            context = contexts[0]
            context_bound = (
                context.get("reviewType") == "committed"
                and (expected_base_commit is None or context.get("baseCommit") == expected_base_commit)
                and (
                    expected_working_directory is None
                    or context.get("workingDirectory").rstrip("/")
                    == expected_working_directory.rstrip("/")
                )
            )
        if not context_bound:
            _append_once(protocol_blockers, "review-context-mismatch")
    blocking_issues = [
        issue
        for issue in details["issues"]
        if issue.get("kind") == "error" or issue.get("severity") in BLOCKING_SEVERITIES
    ]
    if exit_code:
        status, gate_exit = "degraded", 4
    elif protocol_blockers or blocking_issues or terminal_outcome == "failure":
        status, gate_exit = "fail", 2
    elif parsed == 0 or terminal_outcome != "success":
        status, gate_exit = "degraded", 4
    else:
        status, gate_exit = "pass", 0
    result: dict[str, Any] = {
        "status": status,
        "exit_code": exit_code,
        "reviewed_files": reviewed_files,
        "manifest_sha256": manifest_sha256,
        "base_commit": expected_base_commit,
        "head_commit": expected_head_commit,
        "diff_sha256": diff_sha256,
        "structured_events": parsed,
        "terminal_outcome": terminal_outcome,
        "finding_count": details["finding_events"],
        "complete_reported_findings": details["complete_reported_findings"],
        "blocking_findings": len(blocking_issues),
        "blocking_severities": sorted({str(issue.get("severity")) for issue in blocking_issues}),
        "protocol_blockers": protocol_blockers,
        "context_bound": context_bound,
        "issues": details["issues"],
    }
    return result, gate_exit


def auth_is_ready(output: str) -> bool:
    authenticated_seen = False
    for line in output.splitlines():
        if not line.strip():
            continue
        try:
            event = strict_json_loads(line)
        except (json.JSONDecodeError, DuplicateKeyEvent):
            return False
        if isinstance(event, dict):
            authenticated = event.get("authenticated")
            if "authenticated" in event and not isinstance(authenticated, bool):
                return False
            try:
                event_types = _alias_values(event, ("type", "event_type"))
                statuses = _alias_values(event, ("status", "state"))
            except InvalidAliasShape:
                return False
            event_groups = {_event_type_group(value) for value in event_types if value}
            status_groups = {_status_group(value) for value in statuses if value}
            if len(event_groups) > 1 or "error" in event_groups:
                return False
            if len(status_groups) > 1 or "failure" in status_groups:
                return False
            if authenticated is False:
                return False
            if authenticated is True and (not statuses or set(statuses) == {"authenticated"}):
                authenticated_seen = True
            if "authenticated" not in event and statuses and set(statuses) == {"authenticated"}:
                authenticated_seen = True
        else:
            return False
    return authenticated_seen


def _run_process_bounded(
    command: list[str],
    cwd: Path,
    *,
    timeout: int,
    env: dict[str, str],
) -> subprocess.CompletedProcess[bytes]:
    """Drain child streams concurrently and stop at a hard per-stream limit."""
    process = subprocess.Popen(
        command,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        env=env,
        bufsize=0,
    )
    if process.stdout is None or process.stderr is None:
        process.kill()
        process.wait()
        raise OSError("subprocess-pipes-unavailable")
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    digests = {"stdout": hashlib.sha256(), "stderr": hashlib.sha256()}
    overflow = threading.Event()

    def drain(name: str, stream: Any) -> None:
        try:
            while True:
                chunk = stream.read(_SUBPROCESS_READ_CHUNK)
                if not chunk:
                    break
                digests[name].update(chunk)
                target = buffers[name]
                if len(target) + len(chunk) > MAX_SUBPROCESS_STREAM_BYTES:
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
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        for reader in readers:
            reader.join(timeout=5)
        raise
    for reader in readers:
        reader.join(timeout=5)
    if any(reader.is_alive() for reader in readers):
        process.kill()
        raise ReviewScopeError("subprocess-drain-timeout")
    if overflow.is_set():
        raise ReviewScopeError("subprocess-output-limit")
    completed = subprocess.CompletedProcess(
        command,
        returncode,
        bytes(buffers["stdout"]),
        bytes(buffers["stderr"]),
    )
    completed.stdout_sha256 = digests["stdout"].hexdigest()
    completed.stderr_sha256 = digests["stderr"].hexdigest()
    return completed


def _run(
    command: list[str],
    cwd: Path,
    *,
    timeout: int = 60,
    env: dict[str, str] | None = None,
    capture_stream_hashes: bool = False,
) -> subprocess.CompletedProcess[str]:
    resolved_command = _resolved_command(command)
    process_environment = env if env is not None else _minimal_environment()
    raw = _run_process_bounded(
        resolved_command,
        cwd=cwd,
        timeout=timeout,
        env=process_environment,
    )
    completed = subprocess.CompletedProcess(
        raw.args,
        raw.returncode,
        (raw.stdout or b"").decode("utf-8", errors="replace"),
        (raw.stderr or b"").decode("utf-8", errors="replace"),
    )
    if capture_stream_hashes:
        completed.stdout_sha256 = getattr(raw, "stdout_sha256")
        completed.stderr_sha256 = getattr(raw, "stderr_sha256")
    return completed


def _run_bytes(
    command: list[str],
    cwd: Path,
    *,
    timeout: int = 60,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    return _run_process_bounded(
        _resolved_command(command),
        cwd=cwd,
        timeout=timeout,
        env=env if env is not None else _minimal_environment(),
    )


def _stream_sha256(completed: subprocess.CompletedProcess[str], name: str) -> str:
    recorded = getattr(completed, f"{name}_sha256", None)
    if isinstance(recorded, str) and re.fullmatch(r"[0-9a-f]{64}", recorded):
        return recorded
    value = getattr(completed, name, "") or ""
    if isinstance(value, bytes):
        return hashlib.sha256(value).hexdigest()
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def _git_environment() -> dict[str, str]:
    environment = _minimal_environment()
    environment.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "Supervisor Review",
        "GIT_AUTHOR_EMAIL": "supervisor-review@example.invalid",
        "GIT_COMMITTER_NAME": "Supervisor Review",
        "GIT_COMMITTER_EMAIL": "supervisor-review@example.invalid",
        "GIT_AUTHOR_DATE": "2000-01-01T00:00:00Z",
        "GIT_COMMITTER_DATE": "2000-01-01T00:00:00Z",
    })
    return environment


def _checked_git(command: list[str], repo: Path, phase: str) -> subprocess.CompletedProcess[str]:
    completed = _run(command, repo, env=_git_environment())
    if completed.returncode:
        raise RuntimeError(f"git-{phase}")
    return completed


def prepare_git_repository(repo: Path, manifest: list[dict[str, str]]) -> str:
    """Create an explicit review-base -> supervisor-changes history."""
    manifest = _normalized_source_manifest(manifest)
    manifest_file = repo / "REVIEW_MANIFEST.json"
    if manifest_file.exists() and _is_link_or_reparse(manifest_file):
        raise ReviewScopeError("destination-link-or-reparse")
    manifest_file.write_bytes(review_manifest_bytes(manifest))
    payload_paths: list[str] = []
    for row in manifest:
        path = row.get("path", "")
        normalized = path.replace("\\", "/")
        if (
            not path
            or path != normalized
            or normalized.startswith("/")
            or re.match(r"^[A-Za-z]:", normalized)
            or any(part in {"", ".", ".."} for part in normalized.split("/"))
        ):
            raise ReviewScopeError("invalid-manifest-path")
        payload_paths.append(normalized)

    for command, phase in (
        (["git", "init", "-q"], "init"),
        (["git", "config", "user.email", "supervisor-review@example.invalid"], "email"),
        (["git", "config", "user.name", "Supervisor Review"], "name"),
        (["git", "config", "commit.gpgsign", "false"], "signing"),
        (["git", "config", "core.autocrlf", "false"], "line-endings"),
        (["git", "config", "core.safecrlf", "false"], "safe-line-endings"),
        (["git", "config", "core.filemode", "false"], "file-modes"),
        (["git", "commit", "--allow-empty", "-qm", "empty review baseline"], "baseline-commit"),
        (["git", "branch", "-M", "review-base"], "base-branch"),
    ):
        _checked_git(command, repo, phase)

    baseline = _checked_git(
        ["git", "rev-parse", "--verify", "refs/heads/review-base"],
        repo,
        "base-revision",
    ).stdout.strip()
    if not re.fullmatch(r"[0-9a-fA-F]{40,64}", baseline):
        raise RuntimeError("git-invalid-base-revision")
    _checked_git(["git", "checkout", "-q", "-b", "supervisor-changes"], repo, "change-branch")
    _checked_git(
        ["git", "add", "-f", "--", *payload_paths, "REVIEW_MANIFEST.json"],
        repo,
        "stage",
    )
    _checked_git(
        [
            "git", "update-index", "--chmod=-x", "--",
            *payload_paths, "REVIEW_MANIFEST.json",
        ],
        repo,
        "normalize-file-modes",
    )
    _checked_git(["git", "commit", "-qm", "Supervisor v3 review payload"], repo, "payload-commit")

    current = _checked_git(["git", "branch", "--show-current"], repo, "current-branch").stdout.strip()
    verified_base = _checked_git(
        ["git", "rev-parse", "--verify", "refs/heads/review-base"],
        repo,
        "verify-base",
    ).stdout.strip()
    _checked_git(
        ["git", "merge-base", "--is-ancestor", "review-base", "supervisor-changes"],
        repo,
        "verify-ancestry",
    )
    if current != "supervisor-changes" or verified_base != baseline:
        raise RuntimeError("git-invalid-review-history")
    return baseline


def review_revision_binding(repo: Path, baseline: str) -> tuple[str, str]:
    """Bind the exact reviewed commit and binary diff to the report."""
    head = _checked_git(
        ["git", "rev-parse", "--verify", "refs/heads/supervisor-changes"],
        repo,
        "head-revision",
    ).stdout.strip()
    if not re.fullmatch(r"[0-9a-fA-F]{40,64}", head):
        raise RuntimeError("git-invalid-head-revision")
    completed = _run_bytes(
        ["git", "diff", "--binary", "--full-index", "--no-ext-diff", baseline, head],
        repo,
        timeout=60,
        env=_git_environment(),
    )
    if completed.returncode:
        raise RuntimeError("git-diff-binding")
    return head, hashlib.sha256(completed.stdout).hexdigest()


_BINDING_KEYS = {
    "contract",
    "workspace_base_sha256",
    "workspace_head_sha256",
    "diff_hash",
    "workspace_delta_manifest",
}
_BINDING_SOURCE_KEYS = {
    "supervisor_source_snapshot_sha256",
    "review_core_manifest_sha256",
    "review_adapter_manifest",
    "review_adapter_manifest_sha256",
}
_SHA256 = re.compile(r"[0-9a-f]{64}")


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _absolute_path(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _path_has_reparse(path: Path) -> bool:
    current = _absolute_path(path)
    while True:
        if _is_link_or_reparse(current):
            return True
        if current.parent == current:
            return False
        current = current.parent


def _trusted_regular_file(path: Path, reason: str) -> Path:
    lexical = _absolute_path(path)
    if _path_has_reparse(lexical):
        raise ReviewArtifactError(reason)
    try:
        resolved = lexical.resolve(strict=True)
    except OSError:
        raise ReviewArtifactError(reason) from None
    if (
        os.path.normcase(str(lexical)) != os.path.normcase(str(resolved))
        or not lexical.is_file()
    ):
        raise ReviewArtifactError(reason)
    return lexical


def _valid_delta_path(value: Any) -> bool:
    if (
        not isinstance(value, str)
        or not value
        or "\x00" in value
        or "\\" in value
        or any(ord(character) < 32 for character in value)
        or re.match(r"^[A-Za-z]:", value)
    ):
        return False
    path = PurePosixPath(value)
    return bool(
        not path.is_absolute()
        and path.as_posix() == value
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


def load_review_binding(path_value: str | os.PathLike[str] | None) -> dict[str, Any]:
    """Load a caller-produced workspace delta without deriving or guessing it."""
    if path_value is None or not str(path_value).strip() or "\x00" in str(path_value):
        raise ReviewArtifactError("review-binding-missing")
    candidate = Path(path_value).expanduser()
    if not candidate.is_absolute():
        raise ReviewArtifactError("review-binding-path-invalid")
    binding_file = _trusted_regular_file(candidate, "review-binding-file-untrusted")
    try:
        if binding_file.stat().st_size > 1024 * 1024:
            raise ReviewArtifactError("review-binding-file-too-large")
        raw = binding_file.read_text(encoding="utf-8")
        binding = strict_json_loads(raw)
    except ReviewArtifactError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, DuplicateKeyEvent):
        raise ReviewArtifactError("review-binding-json-invalid") from None
    binding_keys = set(binding) if isinstance(binding, dict) else set()
    if (
        not isinstance(binding, dict)
        or (
            binding_keys != _BINDING_KEYS
            and binding_keys != _BINDING_KEYS | _BINDING_SOURCE_KEYS
        )
        or binding.get("contract") != "ReviewArtifactBindingInput/v1"
    ):
        raise ReviewArtifactError("review-binding-contract-invalid")
    for key in ("workspace_base_sha256", "workspace_head_sha256", "diff_hash"):
        if not isinstance(binding.get(key), str) or not _SHA256.fullmatch(binding[key]):
            raise ReviewArtifactError("review-binding-hash-invalid")
    for key in (
        "supervisor_source_snapshot_sha256",
        "review_core_manifest_sha256",
        "review_adapter_manifest_sha256",
    ):
        if key in binding and (
            not isinstance(binding.get(key), str)
            or not _SHA256.fullmatch(binding[key])
        ):
            raise ReviewArtifactError("review-binding-source-hash-invalid")
    if _BINDING_SOURCE_KEYS <= binding_keys:
        adapter_manifest = binding.get("review_adapter_manifest")
        if not isinstance(adapter_manifest, dict) or not adapter_manifest:
            raise ReviewArtifactError("review-binding-adapter-manifest-invalid")
        for path, digest in adapter_manifest.items():
            if (
                not _valid_delta_path(path)
                or not path.startswith(("global-codex/", "global-claude/"))
                or not isinstance(digest, str)
                or not _SHA256.fullmatch(digest)
            ):
                raise ReviewArtifactError("review-binding-adapter-manifest-invalid")
        if _canonical_sha256(adapter_manifest) != binding[
            "review_adapter_manifest_sha256"
        ]:
            raise ReviewArtifactError("review-binding-adapter-manifest-invalid")
    delta = binding.get("workspace_delta_manifest")
    if not isinstance(delta, dict):
        raise ReviewArtifactError("review-binding-delta-invalid")
    for path, change in delta.items():
        if not _valid_delta_path(path) or not isinstance(change, dict) or set(change) != {"before", "after"}:
            raise ReviewArtifactError("review-binding-delta-invalid")
        for value in change.values():
            if value is not None and (not isinstance(value, str) or not _SHA256.fullmatch(value)):
                raise ReviewArtifactError("review-binding-delta-invalid")
    if _canonical_sha256(delta) != binding["diff_hash"]:
        raise ReviewArtifactError("review-binding-diff-hash-mismatch")
    return binding


def resolve_artifact_root(path_value: str | os.PathLike[str] | None) -> Path:
    configured = path_value or SUPERVISOR_DATA_ROOT / "review-artifacts"
    if "\x00" in str(configured):
        raise ReviewArtifactError("review-artifact-root-invalid")
    root = Path(configured)
    if not root.is_absolute():
        raise ReviewArtifactError("review-artifact-root-invalid")
    return _absolute_path(root)


def review_artifact_failure_reason(exc: BaseException) -> str:
    return (
        exc.reason
        if isinstance(exc, ReviewArtifactError)
        else "review-artifact-unavailable"
    )


def _prepare_artifact_root(root: Path, repo: Path) -> Path:
    root = _absolute_path(root)
    repo = _absolute_path(repo)
    try:
        root.relative_to(repo)
    except ValueError:
        pass
    else:
        raise ReviewArtifactError("review-artifact-root-ephemeral")
    if _path_has_reparse(root):
        raise ReviewArtifactError("review-artifact-root-untrusted")
    try:
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
    except PermissionError:
        raise ReviewArtifactError("review-artifact-permission-denied") from None
    except OSError:
        raise ReviewArtifactError("review-artifact-root-unavailable") from None
    if _path_has_reparse(root) or not root.is_dir():
        raise ReviewArtifactError("review-artifact-root-untrusted")
    try:
        resolved = root.resolve(strict=True)
    except OSError:
        raise ReviewArtifactError("review-artifact-root-unavailable") from None
    if os.path.normcase(str(root)) != os.path.normcase(str(resolved)):
        raise ReviewArtifactError("review-artifact-root-untrusted")
    return root


def _write_exclusive_bytes(path: Path, content: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def _existing_artifact(
    directory: Path,
    *,
    bundle_sha256: str,
    manifest_sha256: str,
) -> dict[str, str] | None:
    bundle = directory / "review.bundle"
    manifest = directory / "manifest.json"
    try:
        if (
            _path_has_reparse(directory)
            or not directory.is_dir()
            or set(path.name for path in directory.iterdir()) != {bundle.name, manifest.name}
        ):
            return None
        bundle = _trusted_regular_file(bundle, "review-artifact-existing-conflict")
        manifest = _trusted_regular_file(manifest, "review-artifact-existing-conflict")
        if file_hash(bundle) != bundle_sha256 or file_hash(manifest) != manifest_sha256:
            return None
    except (OSError, ReviewArtifactError):
        return None
    return {
        "kind": "git-bundle-v1",
        "bundle_path": str(bundle),
        "bundle_sha256": bundle_sha256,
        "manifest_path": str(manifest),
        "manifest_sha256": manifest_sha256,
    }


def _discard_artifact_staging(directory: Path) -> None:
    """Best-effort cleanup of only the two files created in our private staging dir."""
    for name in ("review.bundle", "manifest.json"):
        try:
            (directory / name).unlink()
        except FileNotFoundError:
            pass
        except OSError:
            return
    try:
        directory.rmdir()
    except OSError:
        pass


def persist_review_artifact(
    repo: Path,
    source_manifest: list[dict[str, str]],
    baseline: str,
    head: str,
    git_diff_sha256: str,
    workspace_binding: dict[str, Any],
    artifact_root: Path,
) -> dict[str, Any]:
    """Publish an immutable bundle and manifest, with the manifest written last."""
    root = _prepare_artifact_root(artifact_root, repo)
    object_format_result = _checked_git(
        ["git", "rev-parse", "--show-object-format"], repo, "object-format"
    )
    object_format = object_format_result.stdout.strip().casefold()
    expected_oid_length = {"sha1": 40, "sha256": 64}.get(object_format)
    if (
        expected_oid_length is None
        or len(baseline) != expected_oid_length
        or len(head) != expected_oid_length
        or not re.fullmatch(r"[0-9a-f]+", baseline)
        or not re.fullmatch(r"[0-9a-f]+", head)
        or not _SHA256.fullmatch(git_diff_sha256)
    ):
        raise ReviewArtifactError("review-artifact-git-binding-invalid")

    source_manifest = _normalized_source_manifest(source_manifest)
    full_snapshot_manifest = _verified_full_snapshot_manifest(
        repo, baseline, head, source_manifest
    )
    source_manifest_sha256 = _canonical_sha256(full_snapshot_manifest)
    try:
        with tempfile.TemporaryDirectory(prefix="supervisor-review-bundle-") as temporary:
            temporary_bundle = Path(temporary) / "review.bundle"
            _checked_git(
                ["git", "bundle", "create", str(temporary_bundle), "--all"],
                repo,
                "bundle-create",
            )
            temporary_bundle = _trusted_regular_file(
                temporary_bundle, "review-artifact-bundle-invalid"
            )
            bundle_sha256 = file_hash(temporary_bundle)
            manifest = {
                "contract": "ReviewArtifactManifest/v1",
                "review_mode": "full-snapshot",
                "git_binding_source": "review-artifact",
                "bundle_sha256": bundle_sha256,
                "git_object_format": object_format,
                "base": baseline,
                "head": head,
                "diff_hash": workspace_binding["diff_hash"],
                "git_diff_sha256": git_diff_sha256,
                "workspace_base_sha256": workspace_binding["workspace_base_sha256"],
                "workspace_head_sha256": workspace_binding["workspace_head_sha256"],
                "files": sorted(workspace_binding["workspace_delta_manifest"]),
                "workspace_delta_manifest": workspace_binding["workspace_delta_manifest"],
                "source_review_manifest": full_snapshot_manifest,
                "source_review_manifest_sha256": source_manifest_sha256,
            }
            if _BINDING_SOURCE_KEYS <= set(workspace_binding):
                manifest.update({
                    "supervisor_source_snapshot_sha256": workspace_binding[
                        "supervisor_source_snapshot_sha256"
                    ],
                    "review_core_manifest_sha256": workspace_binding[
                        "review_core_manifest_sha256"
                    ],
                    "review_adapter_manifest_sha256": workspace_binding[
                        "review_adapter_manifest_sha256"
                    ],
                })
            manifest_bytes = (
                json.dumps(
                    manifest,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
            manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
            directory = root / manifest_sha256
            artifact: dict[str, str] | None = None
            if directory.exists() or _is_link_or_reparse(directory):
                artifact = _existing_artifact(
                    directory,
                    bundle_sha256=bundle_sha256,
                    manifest_sha256=manifest_sha256,
                )
                if artifact is None:
                    raise ReviewArtifactError("review-artifact-existing-conflict")
            else:
                staging: Path | None = None
                try:
                    staging = Path(tempfile.mkdtemp(
                        prefix=f".{manifest_sha256}.",
                        dir=root,
                    ))
                    if _path_has_reparse(staging):
                        raise ReviewArtifactError("review-artifact-root-untrusted")
                    _write_exclusive_bytes(
                        staging / "review.bundle", temporary_bundle.read_bytes()
                    )
                    _write_exclusive_bytes(staging / "manifest.json", manifest_bytes)
                    if _existing_artifact(
                        staging,
                        bundle_sha256=bundle_sha256,
                        manifest_sha256=manifest_sha256,
                    ) is None:
                        raise ReviewArtifactError(
                            "review-artifact-persist-verification-failed"
                        )
                    try:
                        os.rename(staging, directory)
                        staging = None
                    except PermissionError:
                        raise
                    except OSError:
                        if not (directory.exists() or _is_link_or_reparse(directory)):
                            raise
                        existing = _existing_artifact(
                            directory,
                            bundle_sha256=bundle_sha256,
                            manifest_sha256=manifest_sha256,
                        )
                        if existing is None:
                            raise ReviewArtifactError(
                                "review-artifact-existing-conflict"
                            ) from None
                        artifact = existing
                except ReviewArtifactError:
                    raise
                except PermissionError:
                    raise ReviewArtifactError("review-artifact-permission-denied") from None
                except OSError:
                    raise ReviewArtifactError("review-artifact-persist-failed") from None
                finally:
                    if staging is not None:
                        _discard_artifact_staging(staging)
                if artifact is None:
                    artifact = _existing_artifact(
                        directory,
                        bundle_sha256=bundle_sha256,
                        manifest_sha256=manifest_sha256,
                    )
                    if artifact is None:
                        raise ReviewArtifactError(
                            "review-artifact-persist-verification-failed"
                        )
    except ReviewArtifactError:
        raise
    except (OSError, RuntimeError, subprocess.TimeoutExpired):
        raise ReviewArtifactError("review-artifact-bundle-failed") from None

    return {
        "git_binding_source": "review-artifact",
        "git_binding_status": "verified",
        "git_repository_root": None,
        "git_object_format": object_format,
        "base": baseline,
        "head": head,
        "review_artifact_base": baseline,
        "review_artifact_head": head,
        "git_diff_sha256": git_diff_sha256,
        "workspace_base_sha256": workspace_binding["workspace_base_sha256"],
        "workspace_head_sha256": workspace_binding["workspace_head_sha256"],
        "diff_hash": workspace_binding["diff_hash"],
        "source_review_manifest_sha256": source_manifest_sha256,
        "review_artifact": artifact,
        "review_artifact_sha256": artifact["manifest_sha256"],
    }


def _success_review_summary(
    review_result: dict[str, Any],
    *,
    authenticated: bool,
    stdout_sha256: str,
    stderr_sha256: str,
) -> dict[str, Any]:
    """Return a strict, sanitized summary for an already-passed review gate."""
    if authenticated is not True:
        raise ReviewArtifactError("review-summary-auth-invalid")
    if review_result.get("status") != "pass":
        raise ReviewArtifactError("review-summary-status-invalid")
    exit_code = review_result.get("exit_code")
    structured_events = review_result.get("structured_events")
    finding_count = review_result.get("finding_count")
    complete_reported_findings = review_result.get("complete_reported_findings")
    blocking_findings = review_result.get("blocking_findings")
    if exit_code != 0 or isinstance(exit_code, bool):
        raise ReviewArtifactError("review-summary-exit-invalid")
    if (
        isinstance(structured_events, bool)
        or not isinstance(structured_events, int)
        or structured_events <= 0
    ):
        raise ReviewArtifactError("review-summary-events-invalid")
    if review_result.get("terminal_outcome") != "success":
        raise ReviewArtifactError("review-summary-terminal-invalid")
    if (
        isinstance(finding_count, bool)
        or not isinstance(finding_count, int)
        or finding_count < 0
        or isinstance(complete_reported_findings, bool)
        or not isinstance(complete_reported_findings, int)
        or complete_reported_findings != finding_count
    ):
        raise ReviewArtifactError("review-summary-count-invalid")
    if blocking_findings != 0 or isinstance(blocking_findings, bool):
        raise ReviewArtifactError("review-summary-blocking-invalid")
    if review_result.get("protocol_blockers") != []:
        raise ReviewArtifactError("review-summary-protocol-invalid")
    if review_result.get("context_bound") is not True:
        raise ReviewArtifactError("review-summary-context-invalid")
    if any(
        not isinstance(digest, str)
        or not re.fullmatch(r"[0-9a-f]{64}", digest)
        for digest in (stdout_sha256, stderr_sha256)
    ):
        raise ReviewArtifactError("review-summary-stream-hash-invalid")

    raw_issues = review_result.get("issues")
    if not isinstance(raw_issues, list) or len(raw_issues) != finding_count:
        raise ReviewArtifactError("review-summary-issues-invalid")
    severity_counts = {"critical": 0, "major": 0, "minor": 0}
    issues: list[dict[str, Any]] = []
    expected_issue_keys = {"kind", "severity", "path", "line", "title", "message"}
    for raw_issue in raw_issues:
        if not isinstance(raw_issue, dict) or set(raw_issue) != expected_issue_keys:
            raise ReviewArtifactError("review-summary-issue-shape-invalid")
        kind = raw_issue.get("kind")
        severity = raw_issue.get("severity")
        path = raw_issue.get("path")
        line = raw_issue.get("line")
        title = raw_issue.get("title")
        message = raw_issue.get("message")
        if kind != "finding" or not isinstance(severity, str):
            raise ReviewArtifactError("review-summary-issue-kind-invalid")
        severity = severity.strip().casefold()
        if severity in {"p0", "critical", "error"}:
            bucket = "critical"
        elif severity in {"p1", "major", "high"}:
            bucket = "major"
        elif severity in NONBLOCKING_SEVERITIES:
            bucket = "minor"
        else:
            raise ReviewArtifactError("review-summary-severity-invalid")
        # The generic gate may preserve nonblocking findings, but a success
        # artifact must never be able to normalize a blocking finding to pass.
        if bucket != "minor":
            raise ReviewArtifactError("review-summary-blocking-invalid")
        normalized_output_path: str | None
        if path in ("", None):
            normalized_output_path = None
        elif isinstance(path, str):
            normalized_path, path_is_valid = _safe_issue_path({"path": path})
            if not path_is_valid or normalized_path != path:
                raise ReviewArtifactError("review-summary-path-invalid")
            normalized_output_path = normalized_path
        else:
            raise ReviewArtifactError("review-summary-path-invalid")
        if line is not None and (
            isinstance(line, bool) or not isinstance(line, int) or line <= 0
        ):
            raise ReviewArtifactError("review-summary-line-invalid")
        if not isinstance(title, str) or not isinstance(message, str):
            raise ReviewArtifactError("review-summary-text-invalid")
        issues.append({
            "kind": "finding",
            "severity": severity,
            "path": normalized_output_path,
            "line": line,
            "title": _bounded_text(title, limit=160) or "CodeRabbit finding",
            "message": _bounded_text(message, limit=500),
        })
        severity_counts[bucket] += 1

    if sum(severity_counts.values()) != finding_count:
        raise ReviewArtifactError("review-summary-count-invalid")
    return {
        "engine": "coderabbit",
        "authenticated": True,
        "status": "pass",
        "exit_code": 0,
        "structured_events": structured_events,
        "terminal_outcome": "success",
        "finding_count": finding_count,
        "complete_reported_findings": complete_reported_findings,
        "blocking_findings": 0,
        "severity_counts": severity_counts,
        "protocol_blockers": [],
        "context_bound": True,
        "issues": issues,
        "stdout_sha256": stdout_sha256,
        "stderr_sha256": stderr_sha256,
    }


def _supplied_review_summary(review_summary: dict[str, Any]) -> dict[str, Any]:
    """Validate the only non-CodeRabbit summary accepted by this shared renderer."""
    expected_keys = {"engine", "check", "status", "exit_code", "output_sha256"}
    if set(review_summary) != expected_keys:
        raise ReviewArtifactError("review-summary-shape-invalid")
    if (
        review_summary.get("engine") != "code-review-graph"
        or review_summary.get("check") not in {"build", "impact"}
        or review_summary.get("status") != "pass"
        or review_summary.get("exit_code") != 0
        or isinstance(review_summary.get("exit_code"), bool)
        or not isinstance(review_summary.get("output_sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", review_summary["output_sha256"])
    ):
        raise ReviewArtifactError("review-summary-value-invalid")
    return dict(review_summary)


def review_output_artifact(
    artifact_binding: dict[str, Any],
    review_result: dict[str, Any] | None = None,
    *,
    authenticated: bool | None = None,
    stdout_sha256: str | None = None,
    stderr_sha256: str | None = None,
    review_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Render the exact evidence-bearing success object accepted by the core."""
    if review_summary is not None:
        if review_result is not None or any(
            value is not None
            for value in (authenticated, stdout_sha256, stderr_sha256)
        ):
            raise ReviewArtifactError("review-summary-input-conflict")
        if not isinstance(review_summary, dict):
            raise ReviewArtifactError("review-summary-shape-invalid")
        summary = _supplied_review_summary(review_summary)
    else:
        if not isinstance(review_result, dict):
            raise ReviewArtifactError("review-summary-missing")
        summary = _success_review_summary(
            review_result,
            authenticated=authenticated is True,
            stdout_sha256=stdout_sha256 or "",
            stderr_sha256=stderr_sha256 or "",
        )
    return {
        "contract": "ReviewOutputArtifact/v1",
        "review_category": _ACTIVE_REVIEW_CATEGORY,
        "review_artifact": artifact_binding["review_artifact"],
        "base": artifact_binding["base"],
        "head": artifact_binding["head"],
        "git_object_format": artifact_binding["git_object_format"],
        "git_diff_sha256": artifact_binding["git_diff_sha256"],
        "workspace_base_sha256": artifact_binding["workspace_base_sha256"],
        "workspace_head_sha256": artifact_binding["workspace_head_sha256"],
        "diff_hash": artifact_binding["diff_hash"],
        "review_summary": summary,
    }


def build_review_command(prefix: list[str], baseline: str, external_repo: str | None) -> list[str]:
    command = [
        *prefix,
        "review",
        "--agent",
        "--committed",
        "--base",
        "review-base",
        "--base-commit",
        baseline,
    ]
    if external_repo:
        command.extend(["--dir", external_repo, "-c", f"{external_repo}/REVIEW_CATEGORY.md"])
    else:
        command.extend(["-c", "REVIEW_CATEGORY.md"])
    return command


def _validated_wsl_executable(output: str) -> str:
    lines = output.splitlines()
    if len(lines) != 1 or lines[0] != lines[0].strip():
        raise RuntimeError("unsafe WSL executable discovery")
    candidate = lines[0]
    path = PurePosixPath(candidate)
    if (
        not candidate
        or not path.is_absolute()
        or path.as_posix() != candidate
        or "//" in candidate
        or any(part in {"", ".", ".."} for part in path.parts[1:])
        or any(ord(character) < 32 or ord(character) == 127 for character in candidate)
    ):
        raise RuntimeError("unsafe WSL executable discovery")
    return candidate


def coderabbit_command(repo: Path) -> tuple[list[str], list[str], Path, str | None]:
    registry = _load_machine_trust_registry()
    native_entry = registry["entries"].get("coderabbit")
    if isinstance(native_entry, dict) and native_entry.get("kind") == "local":
        native = _verified_local_executable("coderabbit")
        return [native, "auth", "status", "--agent"], [native], repo, None
    wsl = _verified_local_executable("wsl")
    executable, expected_sha256 = _trusted_wsl_entry("coderabbit-wsl")
    probe = _run([wsl, "-e", "/usr/bin/test", "-x", executable], repo)
    if probe.returncode:
        raise RuntimeError("CodeRabbit CLI is unavailable in WSL")
    digest = _run(
        [wsl, "-e", "/usr/bin/sha256sum", "--", executable], repo
    )
    expected_line = f"{expected_sha256}  {executable}"
    if digest.returncode or digest.stdout.strip() != expected_line:
        raise RuntimeError("CodeRabbit CLI identity mismatch in WSL")
    converted = _run([wsl, "-e", "/usr/bin/wslpath", "-a", str(repo)], repo)
    if converted.returncode or not converted.stdout.strip():
        raise RuntimeError("failed to map disposable review repository into WSL")
    wsl_repo = converted.stdout.strip()
    return (
        [wsl, "-e", executable, "auth", "status", "--agent"],
        [wsl, "-e", executable],
        repo,
        wsl_repo,
    )


def _review_result(repo: Path) -> tuple[dict[str, Any], int]:
    try:
        workspace_binding = load_review_binding(_ACTIVE_REVIEW_BINDING_FILE)
        artifact_root = resolve_artifact_root(_ACTIVE_REVIEW_ARTIFACT_ROOT)
    except (OSError, RuntimeError, ValueError) as exc:
        return {
            "status": "degraded",
            "phase": "artifact-binding",
            "reason": review_artifact_failure_reason(exc),
        }, 4
    try:
        manifest = prepare_review_tree(repo, review_category=_ACTIVE_REVIEW_CATEGORY)
    except (OSError, RuntimeError, ValueError) as exc:
        return {
            "status": "degraded",
            "phase": "scope",
            "reason": type(exc).__name__,
        }, 4
    if _BOUND_CORE_MANIFEST_SHA256 is not None:
        observed_core_manifest = {
            row["path"]: row["sha256"]
            for row in manifest
            if row["path"].startswith("global-core/")
        }
        observed_core_manifest_sha256 = _canonical_sha256(observed_core_manifest)
        observed_adapter_manifest = {
            row["path"]: row["sha256"]
            for row in manifest
            if row["path"].startswith(("global-codex/", "global-claude/"))
        }
        if not (
            _BINDING_SOURCE_KEYS <= set(workspace_binding)
            and observed_core_manifest_sha256 == _BOUND_CORE_MANIFEST_SHA256
            and workspace_binding.get("review_core_manifest_sha256")
            == _BOUND_CORE_MANIFEST_SHA256
            and observed_adapter_manifest
            == workspace_binding.get("review_adapter_manifest")
            and _canonical_sha256(observed_adapter_manifest)
            == workspace_binding.get("review_adapter_manifest_sha256")
        ):
            return {
                "status": "degraded",
                "phase": "source-binding",
                "reason": "review-core-manifest-mismatch",
            }, 4
    try:
        baseline = prepare_git_repository(repo, manifest)
        head, diff_sha256 = review_revision_binding(repo, baseline)
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
        return {
            "status": "degraded",
            "phase": "prepare",
            "reason": type(exc).__name__,
        }, 4
    try:
        artifact_binding = persist_review_artifact(
            repo,
            manifest,
            baseline,
            head,
            diff_sha256,
            workspace_binding,
            artifact_root,
        )
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
        return {
            "status": "degraded",
            "phase": "artifact",
            "reason": review_artifact_failure_reason(exc),
        }, 4

    try:
        auth_command, prefix, command_cwd, external_repo = coderabbit_command(repo)
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        return {
            "status": "degraded",
            "phase": "availability",
            "reason": type(exc).__name__,
            **artifact_binding,
        }, 4
    try:
        auth = _run(auth_command, command_cwd, timeout=AUTH_TIMEOUT_SECONDS)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "status": "degraded",
            "phase": "authentication",
            "reason": type(exc).__name__,
            **artifact_binding,
        }, 4
    auth_stderr_sha256 = hashlib.sha256((auth.stderr or "").encode("utf-8")).hexdigest()
    if auth.returncode:
        return {
            "status": "degraded",
            "phase": "authentication",
            "exit_code": auth.returncode,
            "stderr_sha256": auth_stderr_sha256,
            **artifact_binding,
        }, 4
    authenticated = auth_is_ready(auth.stdout or "")
    if not authenticated:
        return {
            "status": "blocked",
            "phase": "authentication",
            "action": "coderabbit auth login --agent",
            "stderr_sha256": auth_stderr_sha256,
            **artifact_binding,
        }, 3

    review_command = build_review_command(prefix, baseline, external_repo)
    try:
        review = _run(
            review_command,
            command_cwd,
            timeout=REVIEW_TIMEOUT_SECONDS,
            capture_stream_hashes=True,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "status": "degraded",
            "phase": "review",
            "reason": type(exc).__name__,
            **artifact_binding,
        }, 4
    review_stdout = review.stdout or ""
    review_stderr = review.stderr or ""
    result, gate_exit = evaluate_review(
        review_stdout,
        stderr=review_stderr,
        exit_code=review.returncode,
        reviewed_files=len(manifest),
        manifest_sha256=review_manifest_hash(manifest),
        expected_base_commit=baseline,
        expected_head_commit=head,
        diff_sha256=diff_sha256,
        expected_working_directory=external_repo,
    )
    result.update(artifact_binding)
    if gate_exit == 0:
        return review_output_artifact(
            artifact_binding,
            result,
            authenticated=authenticated,
            stdout_sha256=_stream_sha256(review, "stdout"),
            stderr_sha256=_stream_sha256(review, "stderr"),
        ), 0
    return result, gate_exit


def _run_review() -> int:
    temporary = tempfile.TemporaryDirectory(prefix="supervisor-v3-coderabbit-")
    try:
        repo = Path(temporary.__enter__())
        report, result_code = _review_result(repo)
    except BaseException:
        try:
            temporary.__exit__(*sys.exc_info())
        except Exception:
            pass
        raise
    try:
        temporary.__exit__(None, None, None)
    except Exception:
        if result_code == 0:
            report = {
                "status": "degraded",
                "phase": "cleanup",
                "reason": "temporary-cleanup-failed",
            }
            result_code = 4
        else:
            report["cleanup_status"] = "degraded"
    print(json.dumps(report, sort_keys=True))
    return result_code


def main(argv: list[str] | None = None) -> int:
    global _ACTIVE_REVIEW_BINDING_FILE, _ACTIVE_REVIEW_ARTIFACT_ROOT, _ACTIVE_REVIEW_CATEGORY
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--review-category",
        choices=sorted(REVIEW_CATEGORIES),
        required=True,
    )
    args = parser.parse_args([] if argv is None else argv)
    _ACTIVE_REVIEW_BINDING_FILE = os.environ.get(
        "AGENT_SUPERVISOR_REVIEW_BINDING_FILE"
    )
    _ACTIVE_REVIEW_ARTIFACT_ROOT = str(SUPERVISOR_DATA_ROOT / "review-artifacts")
    _ACTIVE_REVIEW_CATEGORY = args.review_category
    try:
        return _run_review()
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({
            "status": "degraded",
            "phase": "infrastructure",
            "reason": type(exc).__name__,
        }, sort_keys=True))
        return 4


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
