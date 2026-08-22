from __future__ import annotations

import json
from pathlib import Path

import pytest

from supervisor_core.discovery import RootSpec, baseline_report, scan_skills, write_baseline
from supervisor_core.routing import route_intents, split_intents


def skill(path: Path, name: str, description: str, extra: str = "") -> None:
    path.mkdir(parents=True, exist_ok=True)
    (path / "SKILL.md").write_text(f"---\nname: {name}\ndescription: {description}\n{extra}---\n# {name}\n", encoding="utf-8")


def test_discovery_preserves_long_names_and_invocability(tmp_path):
    root = tmp_path / "skills"
    long_name = "superpowers:dispatching-parallel-agents-with-complete-name"
    skill(root / "long", long_name, "parallel review")
    skill(root / "manual", "manual-secret-skill", "manual", "disable-model-invocation: true\n")
    inventory = scan_skills([RootSpec(root, "test")])
    by_name = {row["name"]: row for row in inventory["skills"]}
    assert long_name in by_name
    assert by_name[long_name]["automatic"] is True
    assert by_name["manual-secret-skill"]["manual_only"] is True
    assert by_name["manual-secret-skill"]["automatic"] is False


def test_discovery_ignores_upstream_and_degrades_broken(tmp_path):
    root = tmp_path / "skills"
    skill(root / "real", "real-skill", "real")
    skill(root / "pkg" / "upstream" / "copy", "copied-skill", "copy")
    broken = root / "broken"
    broken.mkdir(parents=True)
    (broken / "SKILL.md").write_text("---\nname: [not closed\n---\n", encoding="utf-8")
    inventory = scan_skills([RootSpec(root, "test")])
    assert "copied-skill" not in {row["name"] for row in inventory["skills"]}
    assert any(row["name"] == "broken" and row["availability"] == "unavailable" for row in inventory["skills"])
    assert any(row["reason"] == "nested-upstream-copy" for row in inventory["ignored"])


def test_discovery_hash_failure_degrades_only_the_affected_skill(tmp_path, monkeypatch):
    root = tmp_path / "skills"
    skill(root / "healthy", "healthy-skill", "healthy")
    skill(root / "unreadable", "unreadable-skill", "unreadable")
    unreadable = root / "unreadable" / "SKILL.md"
    real_read_bytes = Path.read_bytes

    def selective_read_bytes(path):
        if path == unreadable:
            raise PermissionError("fixture denies hash read")
        return real_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", selective_read_bytes)

    inventory = scan_skills([RootSpec(root, "test")])
    by_name = {row["name"]: row for row in inventory["skills"]}
    assert by_name["healthy-skill"]["health"] == "healthy"
    assert by_name["healthy-skill"]["sha256"]
    assert by_name["unreadable-skill"]["availability"] == "unavailable"
    assert by_name["unreadable-skill"]["health"] == "unavailable"
    assert by_name["unreadable-skill"]["active"] is False
    assert "hash-read-PermissionError" in by_name["unreadable-skill"]["error"]


def test_duplicate_versions_choose_enabled_latest_and_cache_is_not_available(tmp_path):
    root = tmp_path / "enabled"
    cache = tmp_path / "cache"
    skill(root / "plugin" / "1.0.0" / "x", "dup", "v1")
    skill(root / "plugin" / "2.0.0" / "x", "dup", "v2")
    skill(cache / "plugin" / "9.0.0" / "x", "dup", "cached")
    inventory = scan_skills([RootSpec(root, "enabled"), RootSpec(cache, "cache", True, True)])
    active = [row for row in inventory["skills"] if row["name"] == "dup" and row["active"]]
    assert len(active) == 1
    assert active[0]["version"] == "2.0.0"
    assert any(row["availability"] == "cache-only" for row in inventory["skills"] if row["version"] == "9.0.0")


def test_154_baseline_is_exactly_explainable(tmp_path):
    inventory = {
        "skills": [
            {"name": f"skill-{index}", "version": "1.0.0", "source": "fixture", "sha256": f"{index:064x}", "availability": "enabled", "manual_only": index < 11}
            for index in range(154)
        ]
    }
    baseline = tmp_path / "baseline.json"
    write_baseline(inventory, baseline)
    report = baseline_report(inventory, baseline)
    assert report == {
        "expected": 154,
        "actual": 154,
        "missing": [],
        "added": [],
        "changed": [],
        "availability_changed": [],
        "explainable": True,
    }


@pytest.mark.parametrize(
    ("before", "after"),
    [("unavailable", "enabled"), ("enabled", "disabled")],
)
def test_baseline_reports_availability_only_transitions_without_immutable_drift(
    tmp_path, before, after
):
    row = {
        "name": "host-controlled-skill",
        "version": "1.2.3",
        "source": "fixture",
        "path": "C:/skills/host-controlled/SKILL.md",
        "sha256": "a" * 64,
        "availability": before,
        "manual_only": False,
    }
    baseline = tmp_path / "baseline.json"
    write_baseline({"skills": [row]}, baseline)
    live = {"skills": [{**row, "availability": after}]}

    report = baseline_report(live, baseline)

    assert report["changed"] == []
    assert report["availability_changed"] == [{
        "name": "host-controlled-skill",
        "version": "1.2.3",
        "source": "fixture",
        "from": before,
        "to": after,
    }]
    assert set(report["availability_changed"][0]) == {
        "name", "version", "source", "from", "to"
    }
    assert report["explainable"] is True


def test_availability_transition_does_not_mask_hash_drift(tmp_path):
    row = {
        "name": "tampered-skill",
        "version": "1.2.3",
        "source": "fixture",
        "path": "C:/skills/tampered/SKILL.md",
        "sha256": "a" * 64,
        "availability": "unavailable",
        "manual_only": False,
    }
    baseline = tmp_path / "baseline.json"
    write_baseline({"skills": [row]}, baseline)
    live = {
        "skills": [{**row, "availability": "enabled", "sha256": "b" * 64}]
    }

    report = baseline_report(live, baseline)

    assert len(report["changed"]) == 1
    assert report["changed"][0]["reason"] == "hash-version-source-or-manual-changed"
    assert report["availability_changed"] == []


def test_baseline_adds_only_upstream_names_without_legal_wrapper(tmp_path):
    root = tmp_path / "skills"
    skill(root / "wrapped", "wrapped-name", "legal")
    skill(root / "wrapped" / "upstream", "wrapped-name", "duplicate")
    skill(root / "legacy" / "upstream", "legacy-only", "old direct skill")
    inventory = scan_skills([RootSpec(root, "test")])
    baseline = tmp_path / "baseline.json"
    write_baseline(inventory, baseline)
    names = [row["name"] for row in json.loads(baseline.read_text(encoding="utf-8"))["skills"]]
    assert names.count("wrapped-name") == 1
    assert names.count("legacy-only") == 1


def capabilities(count=8):
    domains = [
        ("goal-aligner", "目标 对齐 goal intent requirements"),
        ("quality-reviewer", "质量 把关 监工 review evidence"),
        ("skill-router", "skill 能力 复用 调用 路由 agent"),
        ("deep-auditor", "深度 全面 复审 扫描 审计 audit"),
        ("defect-finder", "缺陷 不足 问题 重大 风险 bug"),
        ("repair-designer", "修复 升级 优化 设计 implement 解决"),
        ("portability-checker", "portable path hook portability"),
        ("concurrency-checker", "concurrency locks isolation"),
    ]
    return {"skills": [{"id": name, "name": name, "description": desc, "active": True, "automatic": True, "availability": "enabled", "health": "healthy"} for name, desc in domains[:count]]}


def test_exact_chinese_request_covers_six_required_concerns():
    message = "需要这个agent切实监工、进行质量和目标对齐把关；复用已有能力，并深度复审，查找重大缺陷，最后给出修复设计。"
    result = route_intents(message=message, inventory=capabilities(6), phase_budget=3)
    domains = {item["domain"] for item in result["coverage"]}
    assert {"goal-alignment", "quality-gate", "capability-reuse", "deep-audit", "defect-discovery", "repair-design"}.issubset(domains)
    assert all(item["capability_ids"] for item in result["coverage"])


def test_supervisor_request_does_not_route_to_unrelated_ui_skill():
    inventory = capabilities(6)
    inventory["skills"].extend(
        [
            {"id": "supervisor", "name": "supervisor", "description": "goal quality capability routing supervisor", "active": True, "automatic": True, "availability": "enabled", "health": "healthy"},
            {"id": "code-review-graph-helper", "name": "code-review-graph-helper", "description": "review impact defects", "active": True, "automatic": True, "availability": "enabled", "health": "healthy"},
            {"id": "superpowers:executing-plans", "name": "superpowers:executing-plans", "description": "execute a repair plan", "active": True, "automatic": True, "availability": "enabled", "health": "healthy"},
            {"id": "animal-island-ui-style", "name": "animal-island-ui-style", "description": "agent skill UI style", "active": True, "automatic": True, "availability": "enabled", "health": "healthy"},
        ]
    )
    message = "需要这个agent切实监工、进行质量和目标对齐把关；复用已有能力，并深度复审，查找重大缺陷，最后给出修复设计。"
    result = route_intents(message=message, inventory=inventory, phase_budget=3)
    assert "animal-island-ui-style" not in result["selected_capabilities"]
    assert {"supervisor", "code-review-graph-helper", "superpowers:executing-plans"}.issubset(result["selected_capabilities"])


def test_words_containing_ui_do_not_false_match_technical_domain():
    domains = {row["domain"] for row in split_intents("Build the agent capability router.")}
    assert domains == {"capability-reuse"}


def test_eight_capabilities_span_unlimited_phases_without_name_truncation():
    intents = [{"intent_id": f"i-{index}", "text": row["description"], "domain": "general"} for index, row in enumerate(capabilities()["skills"])]
    result = route_intents(message="", inventory=capabilities(), supplied_intents=intents, phase_budget=3)
    assert result["total_capability_limit"] is None
    assert len(result["selected_capabilities"]) == 8
    assert len(result["phases"]) == 3
    assert all(len(phase["capability_ids"]) <= 3 for phase in result["phases"])


def test_zero_skill_requires_explicit_review_even_with_reasons():
    result = route_intents(message="unmatched", inventory={"skills": []})
    assert result["valid"] is False
    approved = route_intents(message="unmatched", inventory={"skills": []}, zero_skill_reviewed=True)
    assert approved["zero_skill_reviewed"] is True
    assert approved["review_required"] is True
    assert approved["valid"] is False
    assert "structured" in approved["errors"][0]


def test_null_inventory_degrades_to_zero_skill_instead_of_crashing():
    result = route_intents(message="unmatched", inventory=None)
    assert result["zero_skill"] is True
    assert result["review_required"] is True
    assert result["selected_capabilities"] == []
    assert result["valid"] is False


def test_composite_fullstack_request_routes_one_winner_per_group_and_reviews_last():
    inventory = {
        "skills": [
            {
                "id": "ui-generalist",
                "name": "ui-generalist",
                "description": "UI frontend",
                "responsibility_group": "ui-implementation",
                "active": True,
                "automatic": True,
                "availability": "enabled",
                "health": "healthy",
            },
            {
                "id": "ui-specialist",
                "name": "ui-specialist",
                "description": "UI frontend page interface",
                "responsibility_group": "ui-implementation",
                "active": True,
                "automatic": True,
                "availability": "enabled",
                "health": "healthy",
            },
            {
                "id": "api-worker",
                "name": "api-worker",
                "description": "API endpoint backend",
                "responsibility_group": "api-implementation",
                "active": True,
                "automatic": True,
                "availability": "enabled",
                "health": "healthy",
            },
            {
                "id": "db-worker",
                "name": "db-worker",
                "description": "DB database schema",
                "responsibility_group": "database-implementation",
                "active": True,
                "automatic": True,
                "availability": "enabled",
                "health": "healthy",
            },
            {
                "id": "independent-reviewer",
                "name": "independent-reviewer",
                "description": "independent reviewer review",
                "responsibility_group": "independent-review",
                "active": True,
                "automatic": True,
                "availability": "enabled",
                "health": "healthy",
            },
        ]
    }
    result = route_intents(
        message="Implement the UI, API, and DB, then have an independent reviewer review it.",
        inventory=inventory,
        phase_budget=3,
    )

    assert {row["domain"] for row in result["coverage"]} == {"ui", "api", "db", "review"}
    assert set(result["selected_capabilities"]) == {
        "ui-specialist",
        "api-worker",
        "db-worker",
        "independent-reviewer",
    }
    selected_groups = [
        next(row["responsibility_group"] for row in inventory["skills"] if row["id"] == capability_id)
        for capability_id in result["selected_capabilities"]
    ]
    assert len(selected_groups) == len(set(selected_groups))
    assert all(len(phase["capability_ids"]) <= 3 for phase in result["phases"])
    implementation_phases = {phase["phase"] for phase in result["phases"] if phase["role"] == "implementation"}
    review_phases = [phase for phase in result["phases"] if phase["role"] == "review"]
    assert implementation_phases
    assert review_phases
    assert all(set(phase["depends_on"]) == implementation_phases for phase in review_phases)
    assert all(
        result["phases"][phase_number - 1]["role"] == "review"
        for row in result["coverage"]
        if row["domain"] == "review"
        for phase_number in row["phases"]
    )
