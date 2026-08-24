from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import pytest

import supervisor_core.cli as cli
from supervisor_core.discovery import RootSpec, parse_roots, scan_skills
from supervisor_core.routing import route_intents


REQUEST = (
    "需要这个agent切实监工、进行质量和目标对齐把关；复用已有能力，"
    "并深度复审，查找重大缺陷，最后给出修复设计。"
)
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _skill(path: Path, name: str, description: str, extra: str = "") -> None:
    path.mkdir(parents=True, exist_ok=True)
    (path / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: {description}\n{extra}---\n# {name}\n",
        encoding="utf-8",
    )


def _plugin_config(home: Path) -> None:
    codex = home / ".codex"
    codex.mkdir(parents=True, exist_ok=True)
    (codex / "config.toml").write_text(
        """
[plugins.curated]
enabled = true
source = "openai-curated-remote"

[plugins.bundled]
enabled = true
source = "openai-bundled"

[plugins.primary]
enabled = true
source = "openai-primary-runtime"

[plugins.disabled]
enabled = false
source = "openai-curated-remote"
""".strip()
        + "\n",
        encoding="utf-8",
    )


def _plugin_versions(home: Path) -> dict[str, Path]:
    cache = home / ".codex" / "plugins" / "cache"
    concrete: dict[str, Path] = {}
    for source, package in (
        ("openai-curated-remote", "curated"),
        ("openai-bundled", "bundled"),
        ("openai-primary-runtime", "primary"),
    ):
        for version in ("1.2.0", "2.0.0"):
            skills = cache / source / package / version / "skills"
            _skill(skills / "tool", "tool", f"{source} {version}")
        _skill(cache / source / package / "latest" / "skills" / "alias", "alias", "alias")
        _skill(cache / source / package / "development" / "skills" / "dev", "dev", "dev")
        concrete[source] = cache / source / package / "2.0.0" / "skills"
    _skill(
        cache / "openai-curated-remote" / "disabled" / "9.0.0" / "skills" / "disabled",
        "disabled",
        "disabled",
    )
    return concrete


def test_codex_default_roots_use_only_personal_and_enabled_latest_concrete_plugins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "fake-home"
    personal = home / ".codex" / "skills"
    _skill(personal / "personal", "personal", "personal")
    _plugin_config(home)
    expected_plugins = _plugin_versions(home)
    monkeypatch.setattr(Path, "home", lambda: home)

    roots = parse_roots([], "codex")
    paths = {root.path.resolve() for root in roots}

    assert personal.resolve() in paths
    assert {path.resolve() for path in expected_plugins.values()}.issubset(paths)
    assert len(roots) == 1 + len(expected_plugins)
    assert all(root.enabled and not root.cache for root in roots)
    assert not any("disabled" in root.path.parts for root in roots)
    assert not any(root.path.parent.name in {"latest", "development"} for root in roots)
    assert all(root.path.exists() for root in roots)


def test_codex_plugin_names_are_canonical_and_unroutable_rows_stay_out(tmp_path: Path) -> None:
    root = tmp_path / "plugin" / "2.0.0" / "skills"
    long_name = "already:kept:complete:without:truncation:for:routing"
    _skill(root / "bare", "bare-skill", "目标 对齐")
    _skill(root / "long", long_name, "深度 复审")
    _skill(root / "manual", "manual-skill", "修复 设计", "disable-model-invocation: true\n")
    broken = root / "broken"
    broken.mkdir(parents=True)
    (broken / "SKILL.md").write_text("---\nname: [unterminated\n---\n", encoding="utf-8")

    inventory = scan_skills(
        [RootSpec(root, "codex-plugin:sample@openai-curated-remote")]
    )
    by_name = {row["name"]: row for row in inventory["skills"]}

    assert "sample:bare-skill" in by_name
    assert long_name in by_name
    assert by_name["sample:manual-skill"]["automatic"] is False
    result = route_intents(message=REQUEST, inventory=inventory, phase_budget=2)
    assert "sample:manual-skill" not in result["selected_capabilities"]
    assert "sample:broken" not in result["selected_capabilities"]
    assert all(len(name) == len(str(name)) for name in result["selected_capabilities"])


def _capabilities() -> dict[str, list[dict[str, object]]]:
    rows = (
        ("goal-aligner", "目标 对齐 goal intent requirements"),
        ("quality-reviewer", "质量 把关 监工 review evidence"),
        ("skill-router", "skill 能力 复用 调用 路由 agent"),
        ("deep-auditor", "深度 全面 复审 扫描 审计 audit"),
        ("defect-finder", "缺陷 不足 问题 重大 风险 bug"),
        ("repair-designer", "修复 升级 优化 设计 implement 解决"),
        ("portability-checker", "portable path hook portability"),
        ("concurrency-checker", "concurrency locks isolation"),
    )
    return {
        "skills": [
            {
                "id": name,
                "name": name,
                "description": description,
                "path": f"C:/fixture/{name}/SKILL.md",
                "sha256": f"{index + 1:064x}",
                "active": True,
                "automatic": True,
                "availability": "enabled",
                "health": "healthy",
            }
            for index, (name, description) in enumerate(rows)
        ],
        "agents": [],
        "ignored": [],
        "identity_collisions": [],
        "counts": {},
    }


class _Context:
    def __init__(self, tmp_path: Path) -> None:
        self.workspace = str(tmp_path / "workspace")
        self.runtime = "codex"
        self.project = "fixture"
        self.session = "fixture-session"
        self.round = "fixture-round"
        self.state_file = tmp_path / "state.json"
        self.persisted: dict[str, object] | None = None

    def update(self, mutator):
        assert self.persisted is not None
        mutator(self.persisted)
        return self.persisted


def _start_args(tmp_path: Path, *, shadow: bool) -> argparse.Namespace:
    return argparse.Namespace(
        runtime="codex",
        workspace=str(tmp_path / "workspace"),
        session="fixture-session",
        round="fixture-round",
        state_root=str(tmp_path / "state"),
        project_file=None,
        message=REQUEST,
        change_mode="replace",
        execution_mode="warn",
        goal_json=None,
        criteria_json=None,
        intents_json=None,
        roots=[],
        phase_budget=3,
        zero_skill_reviewed=False,
        shadow=shadow,
    )


@pytest.mark.parametrize("shadow", [False, True])
def test_command_start_always_scans_and_routes_but_shadow_never_persists(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    shadow: bool,
) -> None:
    context = _Context(tmp_path)
    calls = {"scan": 0, "route": 0}
    inventory = _capabilities()

    monkeypatch.setattr(cli, "_context", lambda args: context)
    monkeypatch.setattr(cli, "_project_identity", lambda *args: ({"project_id": "fixture"}, "fixture"))
    monkeypatch.setattr(cli, "read_quality_profile", lambda *args: {})
    monkeypatch.setattr(cli, "parse_roots", lambda roots, runtime: [RootSpec(tmp_path, "fixture")])

    def fake_scan(roots, *, project_config=None, workspace=None):
        calls["scan"] += 1
        assert project_config == {"project_id": "fixture"}
        assert workspace == context.workspace
        return inventory

    def fake_route(**kwargs):
        calls["route"] += 1
        return route_intents(**kwargs)

    monkeypatch.setattr(cli, "scan_skills", fake_scan)
    monkeypatch.setattr(cli, "route_intents", fake_route)
    monkeypatch.setattr(
        cli,
        "capture_validated_supervisor_source_snapshot",
        lambda: {"contract": "SupervisorSourceSnapshot/v3", "sha256": "f" * 64},
    )
    monkeypatch.setattr(cli, "validated_supervisor_source_snapshot_hash", lambda value: "f" * 64)

    def fake_start_round(*args, **kwargs):
        state = {
            "goal": {"goal_id": "goal-r84", "version": 1},
            "intents": [],
            "execution_mode": "warn",
            "health": "healthy",
        }
        if not kwargs["shadow"]:
            context.persisted = state
        return state

    monkeypatch.setattr(cli, "start_round", fake_start_round)

    code = cli.command_start(_start_args(tmp_path, shadow=shadow))
    output = json.loads(capsys.readouterr().out)

    assert code == 0
    assert calls == {"scan": 1, "route": 1}
    assert output["persisted"] is (not shadow)
    assert output["discovery"]["inventory_sha256"]
    assert SHA256.fullmatch(output["discovery"]["inventory_sha256"])
    assert output["capability_route"]["total_capability_limit"] is None
    if shadow:
        assert context.persisted is None
        assert output["state_file"] is None
    else:
        assert context.persisted is not None
        assert context.persisted["discovery"] == output["discovery"]
        assert context.persisted["capability_route"] == output["capability_route"]
        rows = context.persisted["capability_inventory"]["skills"]
        assert all(
            row["name"] and row["path"] and SHA256.fullmatch(row["sha256"])
            and row["availability"] == "enabled"
            for row in rows
        )


def test_current_six_atomic_intents_have_explicit_disposition_and_phase_two_or_three() -> None:
    result = route_intents(message=REQUEST, inventory=_capabilities(), phase_budget=3)
    required = {
        "goal-alignment",
        "quality-gate",
        "capability-reuse",
        "deep-audit",
        "defect-discovery",
        "repair-design",
    }
    coverage = {row["domain"]: row for row in result["coverage"]}

    assert required.issubset(coverage)
    assert result["phase_budget"] in {2, 3}
    assert result["total_capability_limit"] is None
    assert all(
        coverage[domain]["status"] in {"covered", "skipped", "deferred", "unavailable", "failed"}
        and coverage[domain]["reason"]
        for domain in required
    )


def test_eight_capabilities_cross_phases_without_a_total_limit() -> None:
    supplied = [
        {"intent_id": f"intent-{index}", "text": row["description"], "domain": "general"}
        for index, row in enumerate(_capabilities()["skills"], start=1)
    ]
    result = route_intents(
        message="",
        inventory=_capabilities(),
        supplied_intents=supplied,
        phase_budget=2,
    )

    assert result["total_capability_limit"] is None
    assert len(result["selected_capabilities"]) == 8
    assert len(result["phases"]) == 4
    assert all(len(phase["capability_ids"]) <= 2 for phase in result["phases"])


def test_start_discovery_failure_is_structured_degraded_and_never_complete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    context = _Context(tmp_path)
    monkeypatch.setattr(cli, "_context", lambda args: context)
    monkeypatch.setattr(cli, "_project_identity", lambda *args: ({"project_id": "fixture"}, "fixture"))
    monkeypatch.setattr(cli, "read_quality_profile", lambda *args: {})
    monkeypatch.setattr(cli, "parse_roots", lambda roots, runtime: [RootSpec(tmp_path, "fixture")])
    monkeypatch.setattr(cli, "scan_skills", lambda roots: (_ for _ in ()).throw(OSError("fixture failure")))
    monkeypatch.setattr(
        cli,
        "start_round",
        lambda *args, **kwargs: {
            "goal": {"goal_id": "goal-r84", "version": 1},
            "intents": [],
            "execution_mode": "warn",
            "health": "healthy",
        },
    )

    code = cli.command_start(_start_args(tmp_path, shadow=True))
    output = json.loads(capsys.readouterr().out)

    assert code == 4
    assert output["ok"] is False
    assert output["health"] == "degraded"
    assert output["terminal_state"] != "complete"
    assert output["degradation"]["stage"] == "discovery"
    assert "fixture failure" not in json.dumps(output)


def test_zero_skill_is_not_success_even_when_review_is_claimed() -> None:
    result = route_intents(
        message=REQUEST,
        inventory={"skills": []},
        phase_budget=2,
        zero_skill_reviewed=True,
    )

    assert result["zero_skill"] is True
    assert result["review_required"] is True
    assert result["valid"] is False
    assert result["selected_capabilities"] == []
    assert result["zero_skill_review_status"] != "verified"
    assert any("ReviewRecord" in error for error in result["errors"])


def test_compound_canary_routes_acceptance_version_scoring_and_visualization_intents() -> None:
    message = (
        "敲定全局 Supervisor；每轮开始扫描已安装并启用的 Skill；按需求灵活调用，"
        "无总量限制，保证真实发挥价值；测试验收；比较前后版本多维评分；"
        "可视化核心工作、任务和触发条件"
    )
    inventory = {
        "skills": [
            {
                "id": "dev-supervisor",
                "name": "dev-supervisor",
                "description": "global Supervisor goal alignment and round oversight",
                "responsibility_group": "supervisor-oversight",
                "active": True,
                "automatic": True,
                "availability": "enabled",
                "health": "healthy",
            },
            {
                "id": "ce-agent-native-architecture",
                "name": "ce-agent-native-architecture",
                "description": "installed enabled Skill scan and flexible capability routing",
                "responsibility_group": "capability-routing",
                "active": True,
                "automatic": True,
                "availability": "enabled",
                "health": "healthy",
            },
            {
                "id": "testing-reality-checker",
                "name": "testing-reality-checker",
                "description": "测试验收 acceptance testing and evidence gate",
                "responsibility_group": "quality-acceptance",
                "active": True,
                "automatic": True,
                "availability": "enabled",
                "health": "healthy",
            },
            {
                "id": "version-scoring-report",
                "name": "version-scoring-report",
                "description": "比较前后版本并给出多维评分 version scoring report",
                "responsibility_group": "version-analysis",
                "active": True,
                "automatic": True,
                "availability": "enabled",
                "health": "healthy",
            },
            {
                "id": "build-web-data-visualization:data-visualization",
                "name": "build-web-data-visualization:data-visualization",
                "description": "可视化核心工作、任务和触发条件 data visualization",
                "responsibility_group": "data-visualization",
                "active": True,
                "automatic": True,
                "availability": "enabled",
                "health": "healthy",
            },
        ]
    }

    result = route_intents(message=message, inventory=inventory, phase_budget=3)
    expected_capabilities = {
        "dev-supervisor",
        "ce-agent-native-architecture",
        "testing-reality-checker",
        "version-scoring-report",
        "build-web-data-visualization:data-visualization",
    }
    relevant_fragments = ("Supervisor", "Skill", "测试验收", "多维评分", "可视化核心工作")
    relevant_coverage = [
        row
        for row in result["coverage"]
        if any(fragment in row["text"] for fragment in relevant_fragments)
    ]

    assert len(relevant_coverage) >= len(relevant_fragments)
    assert all(row["status"] != "skipped" for row in relevant_coverage)
    assert all(row["capability_ids"] for row in relevant_coverage)
    assert expected_capabilities.issubset(result["selected_capabilities"])
    selected_groups = {
        row["responsibility_group"]
        for row in inventory["skills"]
        if row["id"] in result["selected_capabilities"]
    }
    assert selected_groups == {
        "supervisor-oversight",
        "capability-routing",
        "quality-acceptance",
        "version-analysis",
        "data-visualization",
    }
    assert all(len(phase["capability_ids"]) <= 3 for phase in result["phases"])
    assert result["total_capability_limit"] is None
    assert result["valid"] is True


def test_version_scoring_reuses_data_visualization_when_no_dedicated_report_skill_exists() -> None:
    message = "比较前后版本并进行多维评分；可视化返回核心工作内容、任务和触发条件"
    capability_id = "build-web-data-visualization:data-visualization"
    inventory = {
        "skills": [
            {
                "id": capability_id,
                "name": capability_id,
                "description": "可视化核心工作、任务和触发条件 data visualization",
                "responsibility_group": "data-visualization",
                "active": True,
                "automatic": True,
                "availability": "enabled",
                "health": "healthy",
            }
        ]
    }

    result = route_intents(message=message, inventory=inventory, phase_budget=3)
    relevant = [
        row
        for row in result["coverage"]
        if row["domain"] in {"version-scoring", "visualization"}
    ]

    assert {row["domain"] for row in relevant} == {"version-scoring", "visualization"}
    assert all(row["status"] != "skipped" for row in relevant)
    assert all(row["capability_ids"] == [capability_id] for row in relevant)
    assert result["selected_capabilities"] == [capability_id]
    assert all(len(phase["capability_ids"]) <= 3 for phase in result["phases"])
    assert result["total_capability_limit"] is None
    assert result["valid"] is True
