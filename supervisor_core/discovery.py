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


def _frontmatter(path: Path) -> tuple[dict[str, Any], str]:
    text = path.read_text(encoding="utf-8")
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


def _skill_file_hash(path: Path) -> tuple[str, str]:
    try:
        return sha256_bytes(path.read_bytes()), ""
    except (OSError, UnicodeError) as exc:
        return "", f"hash-read-{type(exc).__name__}: {exc}"


def scan_skills(roots: Iterable[RootSpec]) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    ignored: list[dict[str, str]] = []
    for root in roots:
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
                try:
                    ignored_meta, _ = _frontmatter(path)
                    ignored_name = str(ignored_meta.get("name") or ignored_name)
                except (OSError, UnicodeError, yaml.YAMLError, ValueError):
                    pass
                if root.source.startswith("claude-plugin:") and ":" not in ignored_name:
                    ignored_name = f"{root.source.removeprefix('claude-plugin:').split('@', 1)[0]}:{ignored_name}"
                ignored.append({"path": str(path), "reason": "nested-upstream-copy", "name": ignored_name})
                continue
            try:
                metadata, body = _frontmatter(path)
                toml_data = _nearest_toml(path, root_path)
                declared_name = str(metadata.get("name") or path.parent.name).strip()
                name = declared_name
                if root.source.startswith("claude-plugin:") and ":" not in name:
                    plugin_prefix = root.source.removeprefix("claude-plugin:").split("@", 1)[0]
                    name = f"{plugin_prefix}:{name}"
                description = str(metadata.get("description") or "").strip()
                manual_only = bool(metadata.get("disable-model-invocation", False))
                user_invocable = metadata.get("user-invocable", True) is not False
                if not root.enabled:
                    availability = "disabled"
                else:
                    availability = "cache-only" if root.cache else "enabled"
                health = "healthy" if name and body.strip() else "unknown"
                error = ""
            except (OSError, UnicodeError, yaml.YAMLError, ValueError) as exc:
                name = path.parent.name
                declared_name = name
                if root.source.startswith("claude-plugin:"):
                    plugin_prefix = root.source.removeprefix("claude-plugin:").split("@", 1)[0]
                    name = f"{plugin_prefix}:{name}"
                description = ""
                metadata = {}
                manual_only = False
                user_invocable = False
                availability = "unavailable"
                health = "unavailable"
                error = f"{type(exc).__name__}: {exc}"
                toml_data = {}
            version = _version_from(path, metadata, toml_data)
            digest, hash_error = _skill_file_hash(path)
            if hash_error:
                availability = "unavailable"
                health = "unavailable"
                user_invocable = False
                error = "; ".join(part for part in (error, hash_error) if part)
            records.append(
                {
                    "id": name,
                    "name": name,
                    "declared_name": declared_name,
                    "description": description,
                    "version": version,
                    "source": root.source,
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
    by_name: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        by_name.setdefault(record["name"], []).append(record)
    for group in by_name.values():
        candidates = [r for r in group if r["availability"] == "enabled" and r["health"] == "healthy"]
        if len(candidates) > 1:
            winner = max(candidates, key=lambda r: (_version_key(r["version"]), r["path"]))
            for record in candidates:
                if record is not winner:
                    record["active"] = False
                    record["availability"] = "duplicate-inactive"
                    record["duplicate_of"] = winner["path"]
    active = [r for r in records if r["active"]]
    return {
        "schema_version": 3,
        "generated_at": utc_now(),
        "skills": sorted(records, key=lambda r: (r["name"].casefold(), r["version"], r["path"])),
        "ignored": ignored,
        "counts": {
            "discovered": len(records),
            "active": len(active),
            "automatic": sum(1 for r in active if r["automatic"]),
            "manual_only": sum(1 for r in active if r["manual_only"]),
            "unavailable": sum(1 for r in records if r["availability"] == "unavailable"),
            "cache_only": sum(1 for r in records if r["availability"] == "cache-only"),
            "long_names_gt_30": sum(1 for r in records if len(r["name"]) > 30)
            + sum(1 for r in ignored if len(str(r.get("name", ""))) > 30),
            "long_names_active_gt_30": sum(1 for r in active if len(r["name"]) > 30),
            "ignored_upstream": sum(1 for r in ignored if r.get("reason") == "nested-upstream-copy"),
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
    return [RootSpec(home / ".codex" / "skills", "codex-personal", True, False)]


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
        source_path = Path(str(row.get("path", "")))
        digest, _ = _skill_file_hash(source_path) if source_path.is_file() else ("", "")
        ignored_upstream.append(
            {
                "name": str(row["name"]),
                "version": "ignored-upstream",
                "source": "legacy-upstream-copy",
                "path": str(source_path),
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
