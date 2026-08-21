from __future__ import annotations

import json
import re
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
    if not text.startswith("---"):
        return {}, text
    parts = text.split("---", 2)
    if len(parts) < 3:
        raise ValueError("unterminated YAML frontmatter")
    metadata = yaml.safe_load(parts[1]) or {}
    if not isinstance(metadata, dict):
        raise ValueError("YAML frontmatter must be an object")
    return metadata, parts[2]


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
    pieces = re.split(r"[.\-+_]", version)
    return tuple((0, int(piece)) if piece.isdigit() else (1, piece.lower()) for piece in pieces)


def scan_skills(roots: Iterable[RootSpec]) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    ignored: list[dict[str, str]] = []
    for root in roots:
        root_path = root.path.expanduser().resolve()
        if not root_path.exists():
            ignored.append({"path": str(root_path), "reason": "root-missing"})
            continue
        for path in root_path.rglob("SKILL.md"):
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
                availability = "enabled" if root.enabled and not root.cache else ("cache-only" if root.cache else "disabled")
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
            records.append(
                {
                    "id": name,
                    "name": name,
                    "declared_name": declared_name,
                    "description": description,
                    "version": version,
                    "source": root.source,
                    "path": str(path),
                    "sha256": sha256_bytes(path.read_bytes()) if path.exists() else "",
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
                existing = [row for row in installs if isinstance(row, dict) and Path(str(row.get("installPath", ""))).exists()]
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
    expected_by_name = {str(r.get("name") or r.get("call")): r for r in expected if isinstance(r, dict)}
    actual_by_name = {r["name"]: r for r in inventory.get("skills", [])}
    ignored_by_name = {str(row.get("name")): str(row.get("reason")) for row in inventory.get("ignored", []) if isinstance(row, dict) and row.get("name")}
    missing = [
        {"name": name, "version": str(expected_by_name[name].get("version", "unknown")), "reason": ignored_by_name.get(name, "not-discovered")}
        for name in expected_by_name.keys() - actual_by_name.keys()
    ]
    added = [{"name": name, "version": actual_by_name[name]["version"], "reason": "new-since-baseline"} for name in actual_by_name.keys() - expected_by_name.keys()]
    changed = []
    for name in expected_by_name.keys() & actual_by_name.keys():
        old, new = expected_by_name[name], actual_by_name[name]
        hash_changed = bool(old.get("sha256")) and old.get("sha256") != new.get("sha256")
        availability_changed = bool(old.get("availability")) and old.get("availability") != new.get("availability")
        version_changed = bool(old.get("version")) and old.get("version") != new.get("version")
        if hash_changed or availability_changed or version_changed:
            changed.append({"name": name, "version": new["version"], "reason": "hash-version-or-availability-changed"})
    return {
        "expected": len(expected),
        "actual": len(inventory.get("skills", [])),
        "missing": missing,
        "added": added,
        "changed": changed,
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
        ignored_upstream.append(
            {
                "name": str(row["name"]),
                "version": "ignored-upstream",
                "source": "legacy-upstream-copy",
                "sha256": sha256_bytes(source_path.read_bytes()) if source_path.is_file() else "",
                "availability": "ignored-upstream",
                "manual_only": False,
            }
        )
    payload = {
        "schema_version": 3,
        "created_at": utc_now(),
        "skills": [
            {key: row.get(key) for key in ("name", "version", "source", "sha256", "availability", "manual_only")}
            for row in inventory.get("skills", [])
        ] + ignored_upstream,
    }
    atomic_write_json(path, payload)
