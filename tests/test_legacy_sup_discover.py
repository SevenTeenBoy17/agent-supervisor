from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
INSTALLED_ADAPTER_TEST_ENV = "AGENT_SUPERVISOR_TEST_INSTALLED_ADAPTERS"


def test_both_adapter_roots_absent_are_reported_unavailable(tmp_path: Path) -> None:
    roots = (tmp_path / "codex", tmp_path / "claude")
    assert _validate_adapter_roots(roots, installation_expected=False)
    with pytest.raises(RuntimeError, match="expected adapter installation is missing"):
        _validate_adapter_roots(roots, installation_expected=True)


def test_one_root_adapter_installation_is_a_hard_failure(tmp_path: Path) -> None:
    roots = (tmp_path / "codex", tmp_path / "claude")
    roots[0].mkdir()
    with pytest.raises(RuntimeError, match="partial adapter installation"):
        _validate_adapter_roots(roots, installation_expected=False)


def _validate_adapter_roots(
    roots: tuple[Path, Path], *, installation_expected: bool
) -> str | None:
    root_exists = tuple(root.exists() for root in roots)
    if not any(root_exists):
        if not installation_expected:
            return "global Claude/Codex adapters are not installed on this host"
        raise RuntimeError(f"expected adapter installation is missing: {roots}")
    if not all(root_exists):
        raise RuntimeError(f"partial adapter installation: {roots}")
    return None


def _resolve_script() -> Path:
    review_bundle = ROOT.parent
    review_bundle_mode = (review_bundle / "REVIEW_MANIFEST.json").is_file()
    installed_opt_in = os.environ.get(INSTALLED_ADAPTER_TEST_ENV)
    if installed_opt_in not in {None, "1"}:
        raise RuntimeError(f"{INSTALLED_ADAPTER_TEST_ENV} must be exactly '1' when set")
    configured = os.environ.get("AGENT_SUPERVISOR_INSTALL_HOME")
    if review_bundle_mode:
        codex_root = review_bundle / "global-codex"
        claude_root = review_bundle / "global-claude"
    elif installed_opt_in == "1":
        install_home = Path(configured).resolve() if configured else Path.home().resolve()
        codex_root = install_home / ".codex" / "skills" / "dev-supervisor"
        claude_root = install_home / ".claude" / "skills" / "supervisor"
    else:
        codex_root = ROOT / "integrations" / "codex"
        claude_root = ROOT / "integrations" / "claude"
    unavailable = _validate_adapter_roots(
        (codex_root, claude_root), installation_expected=True
    )
    if unavailable:
        raise RuntimeError(unavailable)
    candidate = claude_root / "scripts" / "sup-discover.py"
    if not candidate.is_file():
        raise RuntimeError(f"sup-discover adapter under test is missing: {candidate}")
    return candidate


SCRIPT = _resolve_script()


def _load_module():
    spec = importlib.util.spec_from_file_location("legacy_sup_discover_under_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _skill(path: Path, name: str, description: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"---\nname: {name}\ndescription: {description}\nuser-invocable: true\n---\n# Body\n",
        encoding="utf-8",
    )


def test_description_parser_stops_at_the_frontmatter_line(tmp_path):
    module = _load_module()
    path = tmp_path / "SKILL.md"
    _skill(path, "bounded-description", "Only this sentence")

    name, description = module.parse(path)

    assert name == "bounded-description"
    assert description == "Only this sentence"
    assert "user-invocable" not in description


def test_plugin_name_comes_from_installed_or_marketplace_structure(tmp_path):
    module = _load_module()
    plugins = tmp_path / "plugins"
    settings = tmp_path / "settings.json"
    settings.write_text(
        json.dumps({"enabledPlugins": {"atomic-agents@official": True}}),
        encoding="utf-8",
    )
    _skill(
        plugins
        / "cache"
        / "official"
        / "atomic-agents"
        / "1.2.3"
        / ".claude"
        / "skills"
        / "release"
        / "SKILL.md",
        "release",
        "Release safely",
    )
    _skill(
        plugins
        / "marketplaces"
        / "official"
        / "external_plugins"
        / "discord"
        / "skills"
        / "access"
        / "SKILL.md",
        "access",
        "Access Discord",
    )
    module.PERSONAL = tmp_path / "personal"
    module.PLUGINS = plugins
    module.SETTINGS = settings

    inventory = module.collect(include_uninstalled=True)

    assert "atomic-agents:release" in inventory
    assert inventory["atomic-agents:release"]["installed"] is True
    assert "discord:access" in inventory
    assert inventory["discord:access"]["installed"] is False
    assert "external_plugins:access" not in inventory


def test_empty_enabled_plugins_means_no_cached_plugins_are_callable(tmp_path):
    module = _load_module()
    plugins = tmp_path / "plugins"
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({"enabledPlugins": {}}), encoding="utf-8")
    _skill(
        plugins / "cache" / "official" / "atomic-agents" / "1.2.3" / "skills" / "release" / "SKILL.md",
        "release",
        "Release safely",
    )
    module.PERSONAL = tmp_path / "personal"
    module.PLUGINS = plugins
    module.SETTINGS = settings

    inventory = module.collect()

    assert module.PLUGIN_CONFIG_STATUS == "available"
    assert inventory == {}


def test_unreadable_plugin_configuration_is_unavailable_not_enable_all(tmp_path):
    module = _load_module()
    plugins = tmp_path / "plugins"
    settings = tmp_path / "settings.json"
    settings.write_text("{not-json", encoding="utf-8")
    _skill(
        plugins / "cache" / "official" / "atomic-agents" / "1.2.3" / "skills" / "release" / "SKILL.md",
        "release",
        "Release safely",
    )
    module.PERSONAL = tmp_path / "personal"
    module.PLUGINS = plugins
    module.SETTINGS = settings

    inventory = module.collect()

    assert module.PLUGIN_CONFIG_STATUS == "unavailable"
    assert inventory == {}
