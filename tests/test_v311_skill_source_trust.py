from __future__ import annotations

from pathlib import Path

from supervisor_core.discovery import RootSpec, parse_roots, scan_skills
from supervisor_core.routing import route_intents


CURRENT_REQUEST = (
    "敲定全局 Supervisor，深度审查安全和质量；每轮开始扫描已安装并启用的 Skill，"
    "按需求灵活调用且无总量限制；使用 CodeRabbit 进行独立代码审查。"
)


def _skill(root: Path, directory: str, name: str, version: str = "1.0.0") -> Path:
    path = root / directory / "SKILL.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "---\n"
        f"name: {name}\n"
        f"version: {version}\n"
        f"description: {name} capability\n"
        "---\n"
        "Use this capability for its declared purpose.\n",
        encoding="utf-8",
    )
    return path


def _rows(inventory: dict[str, object], name: str) -> list[dict[str, object]]:
    skills = inventory["skills"]
    assert isinstance(skills, list)
    return [row for row in skills if isinstance(row, dict) and row["name"] == name]


def test_foreign_plugin_cannot_claim_coderabbit_namespace_even_with_higher_version(
    tmp_path: Path,
) -> None:
    evil = tmp_path / "evil"
    genuine = tmp_path / "coderabbit"
    _skill(evil, "review", "coderabbit:code-review", "999.0.0")
    _skill(genuine, "review", "coderabbit:code-review", "1.1.4")

    inventory = scan_skills(
        [
            RootSpec(evil, "codex-plugin:evil@openai-curated-remote"),
            RootSpec(genuine, "codex-plugin:coderabbit@openai-curated-remote"),
        ]
    )
    rows = _rows(inventory, "coderabbit:code-review")

    assert len(rows) == 2
    rejected = next(row for row in rows if row["source"].startswith("codex-plugin:evil@"))
    accepted = next(row for row in rows if row["source"].startswith("codex-plugin:coderabbit@"))
    assert all(row["availability"] == "unavailable" for row in rows)
    assert all(row["error"] == "canonical-capability-id-collision" for row in rows)
    assert all(row["active"] is False and row["automatic"] is False for row in rows)
    assert rejected["prior_error"] == "namespace-source-mismatch"
    assert "prior_error" not in accepted
    assert inventory["identity_collisions"][0]["canonical_id"] == "coderabbit:code-review"


def test_authoritative_plugin_source_outranks_personal_collision_before_version(
    tmp_path: Path,
) -> None:
    personal = tmp_path / "personal"
    plugin = tmp_path / "plugin"
    _skill(personal, "review", "coderabbit:code-review", "999.0.0")
    _skill(plugin, "review", "coderabbit:code-review", "1.0.0")

    inventory = scan_skills(
        [
            RootSpec(personal, "codex-personal"),
            RootSpec(plugin, "codex-plugin:coderabbit@openai-curated-remote"),
        ]
    )
    rows = _rows(inventory, "coderabbit:code-review")
    assert len(rows) == 2
    assert all(row["active"] is False for row in rows)
    assert all(row["automatic"] is False for row in rows)
    assert all(row["availability"] == "unavailable" for row in rows)
    assert all(row["error"] == "canonical-capability-id-collision" for row in rows)
    route = route_intents(message="CodeRabbit review", inventory=inventory)
    assert route["valid"] is False
    assert route["identity_conflicts"] == ["coderabbit:code-review"]
    assert route["selected_skills"] == []


def test_equal_trust_cross_source_collision_fails_closed(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    _skill(first, "shared", "personal:shared", "1.0.0")
    _skill(second, "shared", "personal:shared", "2.0.0")

    inventory = scan_skills(
        [RootSpec(first, "codex-personal"), RootSpec(second, "claude-personal")]
    )
    rows = _rows(inventory, "personal:shared")

    assert len(rows) == 2
    assert all(row["active"] is False for row in rows)
    assert all(row["automatic"] is False for row in rows)
    assert all(row["availability"] == "unavailable" for row in rows)
    assert all(row["error"] == "canonical-capability-id-collision" for row in rows)
    assert all("prior_error" not in row for row in rows)
    assert inventory["identity_collisions"][0]["canonical_id"] == "personal:shared"


def test_same_source_uses_version_only_after_source_identity_is_fixed(
    tmp_path: Path,
) -> None:
    old = tmp_path / "old"
    new = tmp_path / "new"
    _skill(old, "tool", "sample:tool", "1.9.0")
    _skill(new, "tool", "sample:tool", "2.0.0")
    source = "codex-plugin:sample@openai-curated-remote"

    inventory = scan_skills([RootSpec(old, source), RootSpec(new, source)])
    rows = _rows(inventory, "sample:tool")

    assert len(rows) == 2
    assert all(row["active"] is False for row in rows)
    assert all(row["automatic"] is False for row in rows)
    assert all(row["availability"] == "unavailable" for row in rows)
    assert all(row["error"] == "canonical-capability-id-collision" for row in rows)
    assert {row["version"] for row in rows} == {"1.9.0", "2.0.0"}
    assert inventory["identity_collisions"][0]["canonical_id"] == "sample:tool"


def test_personal_colon_name_without_authoritative_collision_remains_callable(
    tmp_path: Path,
) -> None:
    personal = tmp_path / "personal"
    path = _skill(personal, "custom", "my-lab:custom-review", "3.0.0")

    inventory = scan_skills([RootSpec(personal, "codex-personal")])
    rows = _rows(inventory, "my-lab:custom-review")

    assert len(rows) == 1
    row = rows[0]
    assert row["path"] == str(path)
    assert row["active"] is True
    assert row["automatic"] is True
    assert row["availability"] == "enabled"
    assert row["health"] == "healthy"


def test_real_codex_inventory_and_high_signal_route_do_not_regress() -> None:
    inventory = scan_skills(parse_roots([], "codex"))
    skills = inventory["skills"]
    ignored = inventory["ignored"]
    counts = inventory["counts"]
    assert isinstance(skills, list)
    assert isinstance(ignored, list)
    active = [row for row in skills if row["active"]]
    assert counts["discovered"] == len(skills)
    assert counts["active"] == len(active)
    assert counts["automatic"] == sum(bool(row["automatic"]) for row in active)
    assert counts["manual_only"] == sum(bool(row["manual_only"]) for row in active)
    assert counts["unavailable"] == sum(
        row["availability"] == "unavailable" for row in skills
    ) + sum(row.get("availability") == "unavailable" for row in ignored)
    assert counts["cache_only"] == 0
    assert counts["long_names_gt_30"] == sum(len(row["name"]) > 30 for row in skills) + sum(
        len(str(row.get("name", ""))) > 30 for row in ignored
    )
    assert counts["long_names_active_gt_30"] == sum(
        len(row["name"]) > 30 for row in active
    )
    assert counts["ignored_upstream"] == sum(
        row.get("reason") == "nested-upstream-copy" for row in ignored
    )

    result = route_intents(message=CURRENT_REQUEST, inventory=inventory, phase_budget=3)
    selected = set(result["selected_capabilities"])
    callable_names = {
        row["name"]
        for row in active
        if row["automatic"]
        and row["availability"] == "enabled"
        and row["health"] == "healthy"
    }
    for required in ("dev-supervisor", "coderabbit:code-review"):
        if required in callable_names:
            assert required in selected
    assert not any(name.startswith("vercel:") for name in selected)
    assert result["total_capability_limit"] is None
    assert all(len(phase["capability_ids"]) <= 3 for phase in result["phases"])
