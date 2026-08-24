from __future__ import annotations

import json
import os
import re
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import yaml

from .storage import atomic_write_json
from .util import json_load, sha256_bytes, utc_now


@dataclass(frozen=True)
class RootSpec:
    path: Path
    source: str
    enabled: bool = True
    cache: bool = False
    unavailable_reason: str = ""


_CODEX_PLUGIN_REGISTRIES = {
    "openai-curated": "openai-curated-remote",
    "openai-curated-remote": "openai-curated-remote",
    "openai-bundled": "openai-bundled",
    "openai-primary-runtime": "openai-primary-runtime",
}
_SAFE_PLUGIN_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_CONCRETE_PLUGIN_VERSION = re.compile(
    r"\d+(?:\.\d+)+(?:[-+._a-zA-Z0-9]*)?"
)


def _canonical_plugin_skill_name(source: str, declared_name: str) -> str:
    """Add the host plugin prefix exactly once without truncating the name."""
    name = str(declared_name or "").strip()
    for marker in ("claude-plugin:", "codex-plugin:"):
        if source.startswith(marker) and ":" not in name:
            plugin = source.removeprefix(marker).split("@", 1)[0]
            return f"{plugin}:{name}"
    return name


def _plugin_namespace(source: str) -> str | None:
    """Return the host-owned namespace for a plugin source, if any."""
    value = str(source or "").strip()
    for marker in ("claude-plugin:", "codex-plugin:"):
        if value.startswith(marker):
            namespace = value.removeprefix(marker).split("@", 1)[0].strip()
            return namespace or None
    return None


def _source_identity(source: str) -> str:
    """Normalize only host-controlled aliases that denote the same source.

    Version and path are deliberately excluded: both can be influenced by Skill
    contents or installation layout and therefore may rank candidates only after a
    single source identity has been selected.
    """
    value = str(source or "").strip()
    for marker in ("claude-plugin:", "codex-plugin:"):
        if not value.startswith(marker):
            continue
        payload = value.removeprefix(marker)
        namespace, separator, origin = payload.partition("@")
        normalized_origin = origin.casefold()
        if marker == "codex-plugin:" and separator:
            normalized_origin = _CODEX_PLUGIN_REGISTRIES.get(
                normalized_origin, normalized_origin
            )
        suffix = f"@{normalized_origin}" if separator else ""
        return f"{marker}{namespace.casefold()}{suffix}"
    return value.casefold()


def _namespace_source_mismatch(source: str, declared_name: str) -> bool:
    """Reject a plugin descriptor that claims another plugin's namespace."""
    namespace = _plugin_namespace(source)
    name = str(declared_name or "").strip()
    if namespace is None or ":" not in name:
        return False
    claimed_namespace = name.split(":", 1)[0].strip()
    return claimed_namespace.casefold() != namespace.casefold()


def _source_trust(record: dict[str, Any]) -> int:
    """Rank host namespace ownership above personal/non-plugin declarations."""
    name = str(record.get("name") or "")
    namespace = _plugin_namespace(str(record.get("source") or ""))
    if namespace is None or ":" not in name:
        return 0
    return int(name.split(":", 1)[0].strip().casefold() == namespace.casefold())


def _fail_closed_source_ambiguity(record: dict[str, Any]) -> None:
    """Make a cross-source tie explicitly unavailable and non-routable."""
    record["active"] = False
    record["automatic"] = False
    record["user_invocable"] = False
    record["availability"] = "unavailable"
    record["health"] = "unavailable"
    record["error"] = "ambiguous-cross-source"


def _canonical_capability_id(record: dict[str, Any]) -> str:
    """Return the one case-insensitive identity shared by every capability kind."""
    return str(record.get("id") or record.get("name") or "").strip().casefold()


def _fail_closed_global_identity_collisions(
    skills: list[dict[str, Any]], agents: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Reject every record participating in a global canonical-ID collision.

    Skill, primary Agent, and fallback Agent identities all enter this index before
    an inventory is emitted.  Source trust, version, responsibility group, and
    fallback position cannot choose a winner because the host invocation identity
    would remain ambiguous.
    """
    index: dict[str, list[dict[str, Any]]] = {}
    for record in [*skills, *agents]:
        canonical_id = _canonical_capability_id(record)
        if canonical_id:
            index.setdefault(canonical_id, []).append(record)

    diagnostics: list[dict[str, Any]] = []
    for canonical_id, group in sorted(index.items()):
        if len(group) < 2:
            continue
        diagnostics.append(
            {
                "code": "canonical-capability-id-collision",
                "canonical_id": canonical_id,
                "record_count": len(group),
                "kinds": sorted(
                    {
                        str(record.get("capability_kind") or "skill")
                        for record in group
                    }
                ),
                "responsibility_groups": sorted(
                    {
                        str(record.get("responsibility_group") or "")
                        for record in group
                        if str(record.get("responsibility_group") or "").strip()
                    },
                    key=str.casefold,
                ),
            }
        )
        for record in group:
            prior_error = str(record.get("error") or "").strip()
            record.update(
                {
                    "active": False,
                    "automatic": False,
                    "user_invocable": False,
                    "availability": "unavailable",
                    "health": "unavailable",
                    "error": "canonical-capability-id-collision",
                    "identity_collision": canonical_id,
                }
            )
            if prior_error and prior_error != "canonical-capability-id-collision":
                record["prior_error"] = prior_error
    return diagnostics


def _safe_directory(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return stat.S_ISDIR(metadata.st_mode) and not _is_link_or_reparse(path, metadata)


def _latest_codex_plugin_skills(
    cache_root: Path, registry_directory: str, plugin_name: str
) -> tuple[Path | None, str]:
    """Select one concrete, non-reparse installed plugin version."""
    registry_root = cache_root / registry_directory
    package_root = registry_root / plugin_name
    if not _safe_directory(cache_root) or not _safe_directory(registry_root):
        return None, "plugin-registry-unavailable"
    if not _safe_directory(package_root):
        return None, "plugin-package-unavailable"
    try:
        registry_resolved = registry_root.resolve(strict=True)
        package_root.resolve(strict=True).relative_to(registry_resolved)
        entries = list(os.scandir(package_root))
    except (OSError, RuntimeError, ValueError):
        return None, "plugin-package-unavailable"
    candidates: list[tuple[tuple[Any, ...], str, Path]] = []
    for entry in entries:
        if _CONCRETE_PLUGIN_VERSION.fullmatch(entry.name) is None:
            continue
        version_path = Path(entry.path)
        try:
            metadata = entry.stat(follow_symlinks=False)
        except OSError:
            continue
        if not stat.S_ISDIR(metadata.st_mode) or _is_link_or_reparse(
            version_path, metadata
        ):
            continue
        skills = version_path / "skills"
        if not _safe_directory(skills):
            continue
        try:
            skills.resolve(strict=True).relative_to(package_root.resolve(strict=True))
        except (OSError, RuntimeError, ValueError):
            continue
        candidates.append((_version_key(entry.name), entry.name, skills))
    if not candidates:
        return None, "plugin-version-unavailable"
    return max(candidates, key=lambda row: (row[0], row[1]))[2], ""


def _codex_default_roots(home: Path) -> list[RootSpec]:
    result = [RootSpec(home / ".codex" / "skills", "codex-personal", True, False)]
    config_path = home / ".codex" / "config.toml"
    if not config_path.exists():
        return result
    try:
        with config_path.open("rb") as handle:
            config = tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        raise ValueError("codex-plugin-config-malformed") from exc
    except OSError as exc:
        raise ValueError("codex-plugin-config-unavailable") from exc
    plugins = config.get("plugins", {}) if isinstance(config, dict) else {}
    if not isinstance(plugins, dict):
        raise ValueError("codex-plugin-config-invalid")
    cache_root = home / ".codex" / "plugins" / "cache"
    seen_plugins: set[tuple[str, str]] = set()
    for raw_plugin_id in sorted(plugins, key=lambda value: str(value).casefold()):
        row = plugins[raw_plugin_id]
        if not isinstance(raw_plugin_id, str) or not isinstance(row, dict):
            raise ValueError("codex-plugin-config-invalid")
        if row.get("enabled") is not True:
            continue
        if "@" in raw_plugin_id:
            plugin_name, registry = raw_plugin_id.rsplit("@", 1)
        else:
            plugin_name = raw_plugin_id
            registry = row.get("source")
        if (
            _SAFE_PLUGIN_COMPONENT.fullmatch(plugin_name or "") is None
            or not isinstance(registry, str)
            or _SAFE_PLUGIN_COMPONENT.fullmatch(registry) is None
        ):
            continue
        registry_directory = _CODEX_PLUGIN_REGISTRIES.get(registry.casefold())
        if registry_directory is None:
            result.append(
                RootSpec(
                    cache_root / "unavailable-registry" / plugin_name,
                    f"codex-plugin:{plugin_name}@{registry}",
                    False,
                    False,
                    "plugin-registry-unknown",
                )
            )
            continue
        plugin_key = (plugin_name.casefold(), registry_directory.casefold())
        if plugin_key in seen_plugins:
            continue
        seen_plugins.add(plugin_key)
        source = f"codex-plugin:{plugin_name}@{registry}"
        skills, reason = _latest_codex_plugin_skills(
            cache_root, registry_directory, plugin_name
        )
        if skills is not None:
            # The enabled config plus one exact physical version is host-callable;
            # an unselected cache copy remains cache-only and is never enumerated.
            result.append(RootSpec(skills, source, True, False))
        else:
            result.append(
                RootSpec(
                    cache_root / registry_directory / plugin_name,
                    source,
                    False,
                    False,
                    reason,
                )
            )
    return result


class _StableSkillReadError(ValueError):
    """Privacy-safe failure raised when a Skill cannot be read as one stable object."""

    def __init__(self, code: str, *, digest: str = "") -> None:
        super().__init__(code)
        self.code = code
        self.digest = digest


def _parse_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    lines = text.splitlines(keepends=True)
    if not lines or lines[0].rstrip("\r\n") != "---":
        return {}, text
    closing_index = next(
        (index for index, line in enumerate(lines[1:], start=1) if line.rstrip("\r\n") == "---"),
        None,
    )
    if closing_index is None:
        raise ValueError("unterminated YAML frontmatter")
    metadata = yaml.safe_load("".join(lines[1:closing_index])) or {}
    if not isinstance(metadata, dict):
        raise ValueError("YAML frontmatter must be an object")
    return metadata, "".join(lines[closing_index + 1 :])


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    """Return the immutable fields used to bind a path to its open descriptor."""
    try:
        identity = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
        )
    except AttributeError as exc:
        raise _StableSkillReadError("skill-read-identity-unavailable") from exc
    if any(not isinstance(value, int) or value < 0 for value in identity):
        raise _StableSkillReadError("skill-read-identity-unavailable")
    return identity


def _validate_skill_metadata(path: Path, metadata: os.stat_result) -> None:
    if _is_link_or_reparse(path, metadata):
        raise _StableSkillReadError("skill-read-link-or-reparse")
    if not stat.S_ISREG(metadata.st_mode):
        raise _StableSkillReadError("skill-read-not-regular")
    _file_identity(metadata)


def _stable_skill_bytes(path: Path) -> tuple[bytes, str]:
    """Read one regular Skill file and bind its bytes to stable path/FD identity."""
    descriptor: int | None = None
    try:
        path_before = path.lstat()
        _validate_skill_metadata(path, path_before)

        flags = os.O_RDONLY
        for flag_name in (
            "O_BINARY",
            "O_CLOEXEC",
            "O_NOINHERIT",
            "O_NOFOLLOW",
            "O_NONBLOCK",
        ):
            flags |= int(getattr(os, flag_name, 0))
        descriptor = os.open(path, flags)
        descriptor_before = os.fstat(descriptor)
        _validate_skill_metadata(path, descriptor_before)

        expected_identity = _file_identity(path_before)
        if _file_identity(descriptor_before) != expected_identity:
            raise _StableSkillReadError("skill-read-file-changed")

        remaining = descriptor_before.st_size
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise _StableSkillReadError("skill-read-file-changed")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise _StableSkillReadError("skill-read-file-changed")

        descriptor_after = os.fstat(descriptor)
        path_after = path.lstat()
        _validate_skill_metadata(path, descriptor_after)
        _validate_skill_metadata(path, path_after)
        if (
            _file_identity(descriptor_after) != expected_identity
            or _file_identity(path_after) != expected_identity
        ):
            raise _StableSkillReadError("skill-read-file-changed")

        data = b"".join(chunks)
        if len(data) != expected_identity[2]:
            raise _StableSkillReadError("skill-read-file-changed")
        return data, sha256_bytes(data)
    except _StableSkillReadError:
        raise
    except OSError as exc:
        raise _StableSkillReadError(f"skill-read-{type(exc).__name__}") from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError as exc:
                # The read cannot be treated as verified when descriptor cleanup
                # itself fails. Avoid surfacing platform-specific exception text.
                raise _StableSkillReadError("skill-read-close-failed") from exc


def _read_stable_skill(path: Path) -> tuple[dict[str, Any], str, str]:
    """Return metadata, body, and SHA-256 from one verified byte read."""
    data, digest = _stable_skill_bytes(path)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _StableSkillReadError("skill-read-utf8-invalid", digest=digest) from exc
    # Preserve Path.read_text's universal-newline behavior for metadata/body
    # consumers while the digest remains bound to the unmodified source bytes.
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    try:
        metadata, body = _parse_frontmatter(text)
    except yaml.YAMLError as exc:
        raise _StableSkillReadError("skill-read-yaml-invalid", digest=digest) from exc
    except ValueError as exc:
        raise _StableSkillReadError(
            "skill-read-frontmatter-invalid", digest=digest
        ) from exc
    return metadata, body, digest


def _frontmatter(path: Path) -> tuple[dict[str, Any], str]:
    metadata, body, _ = _read_stable_skill(path)
    return metadata, body


def _is_link_or_reparse(path: Path, metadata: os.stat_result | None = None) -> bool:
    try:
        metadata = metadata or path.lstat()
    except OSError:
        return False
    return bool(
        stat.S_ISLNK(metadata.st_mode)
        or (
            hasattr(metadata, "st_file_attributes")
            and bool(metadata.st_file_attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
        )
    )


def _scan_skill_paths(root_path: Path) -> tuple[list[Path], list[dict[str, str]]]:
    """Enumerate regular SKILL.md files without following link/reparse entries."""
    pending = [root_path]
    skill_paths: list[Path] = []
    ignored: list[dict[str, str]] = []
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name.casefold())
        except OSError as exc:
            ignored.append({"path": str(directory), "reason": f"directory-scan-unavailable:{type(exc).__name__}"})
            continue
        for entry in entries:
            path = Path(entry.path)
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as exc:
                ignored.append({"path": str(path), "reason": f"entry-unavailable:{type(exc).__name__}"})
                continue
            if _is_link_or_reparse(path, metadata):
                kind = "directory" if stat.S_ISDIR(metadata.st_mode) else "entry"
                ignored.append({"path": str(path), "reason": f"symlink-or-reparse-{kind}"})
                continue
            try:
                resolved = path.resolve(strict=True)
                resolved.relative_to(root_path)
            except (OSError, RuntimeError, ValueError):
                ignored.append({"path": str(path), "reason": "entry-escapes-root-or-changed"})
                continue
            if stat.S_ISDIR(metadata.st_mode):
                pending.append(path)
            elif stat.S_ISREG(metadata.st_mode) and entry.name == "SKILL.md":
                skill_paths.append(path)
    return sorted(skill_paths, key=lambda path: str(path).casefold()), ignored


def _nearest_toml(path: Path, stop: Path) -> dict[str, Any]:
    current = path.parent
    while True:
        for name in ("skill.toml", "plugin.toml", "pyproject.toml"):
            candidate = current / name
            if candidate.exists():
                try:
                    with candidate.open("rb") as handle:
                        data = tomllib.load(handle)
                    return data if isinstance(data, dict) else {}
                except (OSError, tomllib.TOMLDecodeError):
                    return {}
        if current == stop or current.parent == current:
            return {}
        current = current.parent


def _version_from(path: Path, metadata: dict[str, Any], toml_data: dict[str, Any]) -> str:
    if metadata.get("version"):
        return str(metadata["version"])
    for branch in (toml_data.get("project"), toml_data.get("plugin"), toml_data):
        if isinstance(branch, dict) and branch.get("version"):
            return str(branch["version"])
    for parent in path.parents:
        if re.fullmatch(r"\d+(?:\.\d+)+(?:[-+._a-zA-Z0-9]*)?", parent.name):
            return parent.name
    return "unknown"


def _version_key(version: str) -> tuple[Any, ...]:
    normalized = str(version or "").strip()
    if not normalized or normalized.casefold() == "unknown":
        # ``max`` selects the active duplicate, so an unversioned cache entry
        # must never outrank a concrete installed version.
        return (0,)
    precedence = normalized.split("+", 1)[0]
    core, separator, prerelease = precedence.partition("-")

    def component(piece: str) -> tuple[Any, ...]:
        if re.fullmatch(r"[0-9]+", piece):
            significant = piece.lstrip("0") or "0"
            return (0, len(significant), significant)
        return (1, piece.casefold())

    core_components = tuple(component(piece) for piece in re.split(r"[._]", core))
    prerelease_components = tuple(
        component(piece) for piece in re.split(r"[._]", prerelease)
    ) if separator else ()
    # A stable release outranks its prerelease. Build metadata is intentionally
    # ignored for precedence, matching semantic-version ordering.
    return (1, core_components, 0 if separator else 1, prerelease_components)


def _project_agent_path(workspace: str, declared: str) -> Path:
    """Resolve one manifest-declared Agent config without following reparse paths."""
    if not isinstance(declared, str) or not declared.strip():
        raise ValueError("agent-config-path-invalid")
    value = declared.strip()
    raw = Path(value)
    if (
        "\x00" in value
        or "\\" in value
        or ":" in value
        or value.startswith("~")
        or raw.is_absolute()
        or bool(raw.drive)
        or ".." in raw.parts
        or raw.suffix.casefold() != ".toml"
    ):
        raise ValueError("agent-config-path-invalid")

    lexical_root = Path(os.path.abspath(os.fspath(Path(workspace).expanduser())))
    lexical_candidate = Path(os.path.abspath(os.fspath(lexical_root / raw)))
    try:
        relative = lexical_candidate.relative_to(lexical_root)
    except ValueError as exc:
        raise ValueError("agent-config-path-escape") from exc
    current = lexical_root
    for part in relative.parts:
        if _is_link_or_reparse(current):
            raise ValueError("agent-config-reparse-path")
        current = current / part
    if _is_link_or_reparse(current):
        raise ValueError("agent-config-reparse-path")
    try:
        resolved_root = lexical_root.resolve(strict=True)
        resolved_candidate = lexical_candidate.resolve(strict=True)
        resolved_candidate.relative_to(resolved_root)
    except FileNotFoundError as exc:
        raise ValueError("agent-config-missing") from exc
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError("agent-config-path-escape") from exc
    return resolved_candidate


def _project_agent_record(
    *,
    workspace: str,
    agent_id: str,
    config: str,
    responsibility_group: str,
    fallback_id: str | None,
    fallback_only: bool,
    primary_id: str | None = None,
) -> dict[str, Any]:
    """Build one identity-bearing Agent record from the trusted project manifest."""
    record: dict[str, Any] = {
        "id": agent_id,
        "name": agent_id,
        "description": "",
        "source": "project-agent-manifest",
        "capability_kind": "agent",
        "identity_source": "project-manifest-and-config-hash",
        "verification_level": "installed-config",
        "host_liveness_status": "unverified",
        "responsibility_group": responsibility_group,
        "config": config,
        "path": "",
        "sha256": "",
        "automatic": False,
        "manual_only": False,
        "user_invocable": False,
        "availability": "unavailable",
        "health": "unavailable",
        "error": "",
        "active": False,
        "dependencies": [],
        "fallback_id": fallback_id,
        "fallback_only": bool(fallback_only),
    }
    if primary_id:
        record["primary_id"] = primary_id
    if not agent_id or not responsibility_group:
        record["error"] = "agent-manifest-identity-invalid"
        return record
    try:
        path = _project_agent_path(workspace, config)
        data, digest = _stable_skill_bytes(path)
        try:
            parsed = tomllib.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            raise ValueError("agent-config-toml-invalid") from exc
        declared_name = str(parsed.get("name") or "").strip()
        if declared_name != agent_id:
            raise ValueError("agent-config-name-mismatch")
        description = str(parsed.get("description") or "").strip()
        sandbox_mode = str(parsed.get("sandbox_mode") or "").strip()
        if not description or not sandbox_mode:
            raise ValueError("agent-config-contract-incomplete")
        record.update(
            {
                "description": description,
                "path": str(path),
                "sha256": digest,
                "sandbox_mode": sandbox_mode,
                # A valid, immutable TOML file proves installed configuration,
                # not that the current host can launch this Agent.  Codex has no
                # complete host lifecycle proof here, so discovery must remain
                # unavailable until a trusted current-session, inventory-bound
                # liveness success is supplied by a capable host integration.
                "availability": "unavailable",
                "health": "unknown",
                "host_liveness_status": "unverified",
                "active": False,
                "automatic": False,
                "error": "host-liveness-unverified",
            }
        )
    except (_StableSkillReadError, ValueError) as exc:
        record["error"] = exc.code if isinstance(exc, _StableSkillReadError) else str(exc)
    return record


def scan_project_agents(
    project_config: dict[str, Any] | None, workspace: str | None
) -> list[dict[str, Any]]:
    """Discover only Agents explicitly named by the validated project contract."""
    if not isinstance(project_config, dict) or not workspace:
        return []
    rows = project_config.get("agent_roles")
    if not isinstance(rows, list):
        return []
    id_counts: dict[str, int] = {}
    for row in rows:
        if isinstance(row, dict):
            agent_id = str(row.get("id") or "").strip()
            if agent_id:
                id_counts[agent_id.casefold()] = id_counts.get(agent_id.casefold(), 0) + 1

    records: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        agent_id = str(row.get("id") or "").strip()
        group = str(row.get("responsibility_group") or "").strip()
        config = str(row.get("config") or "").strip()
        fallback_id = str(row.get("fallback_id") or "").strip() or None
        record = _project_agent_record(
            workspace=workspace,
            agent_id=agent_id,
            config=config,
            responsibility_group=group,
            fallback_id=fallback_id,
            fallback_only=False,
        )
        if id_counts.get(agent_id.casefold(), 0) != 1:
            record.update(
                {
                    "automatic": False,
                    "availability": "unavailable",
                    "health": "unavailable",
                    "active": False,
                    "error": "agent-manifest-id-ambiguous",
                }
            )
        records.append(record)

        fallback_config = str(row.get("fallback_config") or "").strip()
        if fallback_id and fallback_config:
            records.append(
                _project_agent_record(
                    workspace=workspace,
                    agent_id=fallback_id,
                    config=fallback_config,
                    responsibility_group=group,
                    fallback_id=None,
                    fallback_only=True,
                    primary_id=agent_id,
                )
            )
    # This helper is also used independently by diagnostics.  Apply the same
    # primary/fallback namespace rule here; scan_skills repeats the global pass
    # after adding Skills so cross-kind collisions are covered as well.
    _fail_closed_global_identity_collisions([], records)
    return records


def verify_project_agent_record(record: Any, workspace: str) -> bool:
    """Re-read one discovered Agent config and verify its immutable identity."""
    if not isinstance(record, dict):
        return False
    config = record.get("config")
    expected_path = record.get("path")
    expected_digest = str(record.get("sha256") or "").casefold()
    agent_id = str(record.get("id") or "").strip()
    if (
        not isinstance(config, str)
        or not isinstance(expected_path, str)
        or not re.fullmatch(r"[0-9a-f]{64}", expected_digest)
        or not agent_id
    ):
        return False
    try:
        path = _project_agent_path(workspace, config)
        if str(path) != expected_path:
            return False
        data, digest = _stable_skill_bytes(path)
        parsed = tomllib.loads(data.decode("utf-8"))
    except (
        _StableSkillReadError,
        UnicodeDecodeError,
        tomllib.TOMLDecodeError,
        ValueError,
    ):
        return False
    return bool(
        digest == expected_digest
        and str(parsed.get("name") or "").strip() == agent_id
        and str(parsed.get("description") or "").strip()
        and str(parsed.get("sandbox_mode") or "").strip()
    )


def scan_skills(
    roots: Iterable[RootSpec],
    *,
    project_config: dict[str, Any] | None = None,
    workspace: str | None = None,
) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    ignored: list[dict[str, str]] = []
    for root in roots:
        if root.unavailable_reason:
            ignored.append(
                {
                    "path": str(root.path),
                    "source": root.source,
                    "availability": "unavailable",
                    "reason": root.unavailable_reason,
                }
            )
            continue
        try:
            root_path = root.path.expanduser().resolve()
        except (OSError, RuntimeError) as exc:
            ignored.append({"path": str(root.path), "reason": f"root-unavailable:{type(exc).__name__}"})
            continue
        if not root_path.exists():
            ignored.append({"path": str(root_path), "reason": "root-missing"})
            continue
        skill_paths, scan_ignored = _scan_skill_paths(root_path)
        ignored.extend(scan_ignored)
        for path in skill_paths:
            relative_parts = [part.lower() for part in path.relative_to(root_path).parts]
            if "upstream" in relative_parts[:-1]:
                ignored_name = path.parent.name
                ignored_digest = ""
                ignored_error = ""
                try:
                    ignored_meta, _, ignored_digest = _read_stable_skill(path)
                    ignored_name = str(ignored_meta.get("name") or ignored_name)
                except _StableSkillReadError as exc:
                    ignored_digest = exc.digest
                    ignored_error = exc.code
                ignored_name = _canonical_plugin_skill_name(
                    root.source, ignored_name
                )
                ignored_row = {
                    "path": str(path),
                    "reason": "nested-upstream-copy",
                    "name": ignored_name,
                    "sha256": ignored_digest,
                }
                if ignored_error:
                    ignored_row["error"] = ignored_error
                ignored.append(ignored_row)
                continue
            digest = ""
            try:
                metadata, body, digest = _read_stable_skill(path)
                toml_data = _nearest_toml(path, root_path)
                declared_name = str(metadata.get("name") or path.parent.name).strip()
                name = _canonical_plugin_skill_name(root.source, declared_name)
                description = str(metadata.get("description") or "").strip()
                manual_only = bool(metadata.get("disable-model-invocation", False))
                user_invocable = metadata.get("user-invocable", True) is not False
                if not root.enabled:
                    availability = "disabled"
                else:
                    availability = "cache-only" if root.cache else "enabled"
                health = "healthy" if name and body.strip() else "unknown"
                error = ""
                if _namespace_source_mismatch(root.source, declared_name):
                    availability = "unavailable"
                    health = "unavailable"
                    user_invocable = False
                    error = "namespace-source-mismatch"
            except _StableSkillReadError as exc:
                name = path.parent.name
                declared_name = name
                name = _canonical_plugin_skill_name(root.source, name)
                description = ""
                metadata = {}
                manual_only = False
                user_invocable = False
                availability = "unavailable"
                health = "unavailable"
                error = exc.code
                digest = exc.digest
                toml_data = {}
            version = _version_from(path, metadata, toml_data)
            records.append(
                {
                    "id": name,
                    "name": name,
                    "declared_name": declared_name,
                    "description": description,
                    "version": version,
                    "source": root.source,
                    "source_identity": _source_identity(root.source),
                    "path": str(path),
                    "sha256": digest,
                    "automatic": availability == "enabled" and not manual_only,
                    "manual_only": manual_only,
                    "user_invocable": user_invocable,
                    "availability": availability,
                    "health": health,
                    "error": error,
                    "active": availability == "enabled",
                    "dependencies": metadata.get("dependencies", []),
                    "fallback_id": metadata.get("fallback_id") or metadata.get("fallback"),
                }
            )
    agents = scan_project_agents(project_config, workspace)
    identity_collisions = _fail_closed_global_identity_collisions(records, agents)
    active = [r for r in records if r["active"]]
    active_agents = [row for row in agents if row.get("active")]
    return {
        "schema_version": 3,
        "generated_at": utc_now(),
        "skills": sorted(records, key=lambda r: (r["name"].casefold(), r["version"], r["path"])),
        "agents": sorted(
            agents,
            key=lambda row: (
                str(row.get("id") or "").casefold(),
                bool(row.get("fallback_only")),
                str(row.get("path") or ""),
            ),
        ),
        "ignored": ignored,
        "identity_collisions": identity_collisions,
        "counts": {
            "discovered": len(records),
            "active": len(active),
            "automatic": sum(1 for r in active if r["automatic"]),
            "manual_only": sum(1 for r in active if r["manual_only"]),
            "unavailable": sum(1 for r in records if r["availability"] == "unavailable")
            + sum(
                1
                for row in ignored
                if row.get("availability") == "unavailable"
            ),
            "cache_only": sum(1 for r in records if r["availability"] == "cache-only"),
            "long_names_gt_30": sum(1 for r in records if len(r["name"]) > 30)
            + sum(1 for r in ignored if len(str(r.get("name", ""))) > 30),
            "long_names_active_gt_30": sum(1 for r in active if len(r["name"]) > 30),
            "ignored_upstream": sum(1 for r in ignored if r.get("reason") == "nested-upstream-copy"),
            "agents_discovered": len(agents),
            "agents_active": len(active_agents),
            "agents_unavailable": sum(
                1 for row in agents if row.get("availability") == "unavailable"
            ),
            "agent_fallbacks": sum(1 for row in agents if row.get("fallback_only")),
            "identity_collisions": len(identity_collisions),
        },
    }


def parse_roots(values: list[str], runtime: str) -> list[RootSpec]:
    result: list[RootSpec] = []
    for raw in values:
        fields = raw.split("|", 3)
        path = Path(fields[0])
        source = fields[1] if len(fields) > 1 and fields[1] else runtime
        enabled = fields[2].lower() != "false" if len(fields) > 2 else True
        cache = fields[3].lower() == "true" if len(fields) > 3 else "cache" in [p.lower() for p in path.parts]
        result.append(RootSpec(path, source, enabled, cache))
    if result:
        return result
    home = Path.home()
    if runtime.lower() == "claude":
        result = [RootSpec(home / ".claude" / "skills", "claude-personal", True, False)]
        registry = json_load(home / ".claude" / "plugins" / "installed_plugins.json", {})
        settings = json_load(home / ".claude" / "settings.json", {})
        enabled = settings.get("enabledPlugins", {}) if isinstance(settings, dict) else {}
        plugins = registry.get("plugins", {}) if isinstance(registry, dict) else {}
        if isinstance(enabled, dict) and isinstance(plugins, dict):
            for plugin_id, is_enabled in enabled.items():
                if is_enabled is not True:
                    continue
                installs = plugins.get(plugin_id, [])
                if not isinstance(installs, list):
                    continue
                existing: list[dict[str, Any]] = []
                for row in installs:
                    if not isinstance(row, dict):
                        continue
                    raw_install_path = row.get("installPath")
                    if not isinstance(raw_install_path, str) or not raw_install_path.strip():
                        continue
                    try:
                        if Path(raw_install_path).expanduser().is_dir():
                            existing.append(row)
                    except OSError:
                        continue
                if not existing:
                    continue
                latest = max(existing, key=lambda row: (_version_key(str(row.get("version", "unknown"))), str(row.get("installedAt", ""))))
                # Although the physical location is a cache, installed_plugins.json
                # plus enabledPlugins=true makes this exact version host-callable.
                install_path = Path(str(latest["installPath"]))
                legal_root = install_path / "skills"
                if legal_root.exists():
                    result.append(RootSpec(legal_root, f"claude-plugin:{plugin_id}", True, False))
        return result
    return _codex_default_roots(home)


def baseline_report(inventory: dict[str, Any], baseline_path: Path) -> dict[str, Any]:
    baseline = json_load(baseline_path, {})
    if isinstance(baseline, dict) and isinstance(baseline.get("skills"), list):
        expected = baseline["skills"]
    elif isinstance(baseline, dict) and isinstance(baseline.get("items"), list):
        expected = [row for row in baseline["items"] if isinstance(row, dict) and row.get("kind") == "skill"]
    else:
        expected = []

    def normalized(rows: Any) -> list[dict[str, Any]]:
        unique: dict[str, dict[str, Any]] = {}
        for raw in rows if isinstance(rows, list) else []:
            if not isinstance(raw, dict):
                continue
            row = dict(raw)
            row["name"] = str(row.get("name") or row.get("call") or "")
            if not row["name"]:
                continue
            identity = json.dumps(
                {
                    key: row.get(key)
                    for key in (
                        "name", "version", "source", "sha256",
                        "availability", "manual_only",
                    )
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            unique.setdefault(identity, row)
        # Absolute installation paths vary by machine/profile and are mutable
        # location metadata, not immutable capability identity.
        return list(unique.values())

    expected_rows = normalized(expected)
    actual_rows = normalized(inventory.get("skills", []))
    ignored_by_name = {str(row.get("name")): str(row.get("reason")) for row in inventory.get("ignored", []) if isinstance(row, dict) and row.get("name")}
    missing: list[dict[str, Any]] = []
    added: list[dict[str, Any]] = []
    changed: list[dict[str, Any]] = []
    availability_changed: list[dict[str, Any]] = []

    def row_order(row: dict[str, Any]) -> tuple[Any, ...]:
        return (
            _version_key(str(row.get("version") or "unknown")),
            str(row.get("sha256") or ""),
            str(row.get("manual_only") or ""),
            str(row.get("availability") or ""),
        )

    def immutable_identity(row: dict[str, Any]) -> tuple[Any, ...]:
        return (
            str(row.get("version") or "unknown"),
            str(row.get("sha256") or ""),
            row.get("manual_only"),
        )

    expected_groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    actual_groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in expected_rows:
        expected_groups.setdefault((row["name"], str(row.get("source") or "")), []).append(row)
    for row in actual_rows:
        actual_groups.setdefault((row["name"], str(row.get("source") or "")), []).append(row)

    paired: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for group_key in expected_groups.keys() | actual_groups.keys():
        old_group = sorted(expected_groups.get(group_key, []), key=row_order)
        new_group = sorted(actual_groups.get(group_key, []), key=row_order)

        # Preserve exact version/hash identities first so removing one of
        # several installed versions cannot shift ordinals and mislabel a
        # surviving version as changed.
        for old in list(old_group):
            match = next(
                (new for new in new_group if immutable_identity(new) == immutable_identity(old)),
                None,
            )
            if match is not None:
                old_group.remove(old)
                new_group.remove(match)
                paired.append((old, match))

        # Hash/manual drift normally keeps a version stable; match that next.
        for old in list(old_group):
            match = next(
                (
                    new
                    for new in new_group
                    if str(new.get("version") or "unknown")
                    == str(old.get("version") or "unknown")
                ),
                None,
            )
            if match is not None:
                old_group.remove(old)
                new_group.remove(match)
                paired.append((old, match))

        # Remaining one-for-one records represent an in-place version change.
        while old_group and new_group:
            paired.append((old_group.pop(0), new_group.pop(0)))
        for old in old_group:
            missing.append({
                "name": group_key[0],
                "version": str(old.get("version", "unknown")),
                "source": group_key[1],
                "reason": ignored_by_name.get(group_key[0], "not-discovered"),
            })
        for new in new_group:
            added.append({
                "name": group_key[0],
                "version": str(new.get("version", "unknown")),
                "source": group_key[1],
                "reason": "new-since-baseline",
            })

    for old, new in paired:
        hash_changed = bool(old.get("sha256")) and old.get("sha256") != new.get("sha256")
        version_changed = bool(old.get("version")) and old.get("version") != new.get("version")
        manual_only_changed = "manual_only" in old and old.get("manual_only") != new.get("manual_only")
        availability_transition = (
            bool(old.get("availability"))
            and old.get("availability") != new.get("availability")
        )
        if hash_changed or version_changed or manual_only_changed:
            changed.append({
                "name": str(new.get("name") or ""),
                "version": str(new.get("version", "unknown")),
                "source": str(new.get("source") or ""),
                "reason": "hash-version-source-or-manual-changed",
            })
        elif availability_transition:
            # Availability is live host state, not Skill content. Keep a
            # privacy-bounded transition record so callers can distinguish a
            # newly enabled/disabled capability from immutable baseline drift.
            availability_changed.append({
                "name": str(new.get("name") or ""),
                "version": str(new.get("version", "unknown")),
                "source": str(new.get("source") or ""),
                "from": str(old.get("availability") or ""),
                "to": str(new.get("availability") or ""),
            })
    return {
        "expected": len(expected_rows),
        "actual": len(actual_rows),
        "missing": sorted(missing, key=lambda row: (row["name"], row["source"], row["version"])),
        "added": sorted(added, key=lambda row: (row["name"], row["source"], row["version"])),
        "changed": sorted(changed, key=lambda row: (row["name"], row["source"], row["version"])),
        "availability_changed": sorted(
            availability_changed,
            key=lambda row: (row["name"], row["source"], row["version"]),
        ),
        "explainable": all(row["reason"] != "not-discovered" for row in missing),
    }


def write_baseline(inventory: dict[str, Any], path: Path) -> None:
    legal_names = {
        str(row.get("name"))
        for row in inventory.get("skills", [])
        if isinstance(row, dict) and row.get("name")
    }
    ignored_upstream = []
    for row in inventory.get("ignored", []):
        if (
            not isinstance(row, dict)
            or row.get("reason") != "nested-upstream-copy"
            or not row.get("name")
            or str(row.get("name")) in legal_names
        ):
            continue
        digest = str(row.get("sha256") or "")
        ignored_upstream.append(
            {
                "name": str(row["name"]),
                "version": "ignored-upstream",
                "source": "legacy-upstream-copy",
                "path": str(row.get("path", "")),
                "sha256": digest,
                "availability": "ignored-upstream",
                "manual_only": False,
            }
        )
    rows = [
        {key: row.get(key) for key in ("name", "version", "source", "path", "sha256", "availability", "manual_only")}
        for row in inventory.get("skills", [])
        if isinstance(row, dict)
    ] + ignored_upstream
    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        marker = json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        if marker not in seen:
            seen.add(marker)
            deduped.append(row)
    payload = {
        "schema_version": 3,
        "created_at": utc_now(),
        "skills": deduped,
    }
    atomic_write_json(path, payload)
