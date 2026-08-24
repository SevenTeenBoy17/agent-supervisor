from __future__ import annotations

import copy
import io
import json
import shutil
import sys
from argparse import Namespace
from pathlib import Path

import pytest

from supervisor_core.cli import (
    _handoff,
    _privacy_safe_capability_route,
    _privacy_safe_prompt_contract,
    _routing_intents_for_start,
    command_hook,
)
from supervisor_core.contracts import normalize_intents
from supervisor_core.discovery import scan_project_agents
from supervisor_core.lifecycle import start_round
from supervisor_core.routing import route_intents, split_intents
from supervisor_core.storage import StateContext
from supervisor_core.util import sha256_file


SENSITIVE_PHRASE = "绝密代号-蓝鲸-7429"


def _inventory() -> dict[str, list[dict[str, object]]]:
    return {
        "skills": [
            {
                "id": "api-security-audit",
                "name": "api-security-audit",
                "description": "API security boundary audit authentication authorization",
                "active": True,
                "automatic": True,
                "availability": "enabled",
                "health": "healthy",
            },
            {
                "id": "dashboard-visualization",
                "name": "dashboard-visualization",
                "description": "dashboard data visualization chart report",
                "active": True,
                "automatic": True,
                "availability": "enabled",
                "health": "healthy",
            },
            {
                "id": "independent-review",
                "name": "independent-review",
                "description": "independent API security review quality acceptance",
                "active": True,
                "automatic": True,
                "availability": "enabled",
                "health": "healthy",
            },
        ],
        "agents": [
            {
                "id": "api-owner",
                "name": "api-owner",
                "description": "API implementation owner",
                "capability_kind": "agent",
                "responsibility_group": "api-implementation",
                "active": False,
                "automatic": False,
                "availability": "unavailable",
                "health": "unknown",
                "host_liveness_status": "unverified",
            },
            {
                "id": "independent-reviewer",
                "name": "independent-reviewer",
                "description": "independent API security review",
                "capability_kind": "agent",
                "responsibility_group": "independent-review",
                "active": False,
                "automatic": False,
                "availability": "unavailable",
                "health": "unknown",
                "host_liveness_status": "unverified",
            },
        ],
    }


def _atomic_intents() -> list[dict[str, object]]:
    return [
        {
            "intent_id": "intent-api",
            "domain": "api",
            "text": f"API security audit {SENSITIVE_PHRASE}",
            "required_responsibility_groups": ["api-implementation"],
            "role": "implementation",
        },
        {
            "intent_id": "intent-review",
            "domain": "review",
            "text": f"independent API security review {SENSITIVE_PHRASE}",
            "required_responsibility_groups": ["independent-review"],
            "role": "review",
            "depends_on_intent_ids": ["intent-api"],
        },
        {
            "intent_id": "intent-viz",
            "domain": "visualization",
            "text": f"dashboard data visualization {SENSITIVE_PHRASE}",
            "role": "implementation",
        },
    ]


def _route_signature(route: dict[str, object]) -> dict[str, object]:
    coverage = route["coverage"]
    assert isinstance(coverage, list)
    phases = route["phases"]
    assert isinstance(phases, list)
    return {
        "selected_capabilities": route["selected_capabilities"],
        "selected_skills": route["selected_skills"],
        "selected_agents": route["selected_agents"],
        "coverage": [
            {
                    key: row.get(key)
                for key in (
                    "intent_id",
                    "domain",
                    "status",
                    "capability_ids",
                    "skill_capability_ids",
                    "agent_capability_ids",
                    "role",
                    "phase",
                    "phases",
                )
            }
            for row in coverage
        ],
        "phases": phases,
    }


def test_privacy_mode_preserves_route_and_persists_no_raw_prompt(
    tmp_path: Path,
) -> None:
    message = "; ".join(str(row["text"]) for row in _atomic_intents())
    raw_intents = _atomic_intents()
    inventory = _inventory()
    public_config = {"project_id": "privacy-routing", "privacy": {"persist_raw_prompts": True}}
    private_config = {"project_id": "privacy-routing", "privacy": {"persist_raw_prompts": False}}

    public_goal, public_intents, public_withheld = _privacy_safe_prompt_contract(
        message, public_config, raw_intents
    )
    safe_goal, safe_intents, private_withheld = _privacy_safe_prompt_contract(
        message, private_config, raw_intents
    )
    assert not public_withheld
    assert private_withheld
    assert public_goal == {}
    assert [row["text"] for row in public_intents] == [row["text"] for row in raw_intents]
    assert [row["intent_id"] for row in public_intents] == [row["intent_id"] for row in raw_intents]

    public_route = route_intents(
        message=message,
        inventory=inventory,
        supplied_intents=public_intents,
        phase_budget=2,
    )
    private_raw_route = route_intents(
        message=message,
        inventory=inventory,
        supplied_intents=raw_intents,
        phase_budget=2,
    )

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    ctx = StateContext.build(
        runtime="codex",
        project="privacy-routing",
        workspace=str(workspace),
        session="privacy-session",
        round_id="privacy-round",
        state_root=str(tmp_path / "state"),
    )
    state = start_round(
        ctx,
        message=message,
        change_mode="continue",
        execution_mode="observe",
        project_config=private_config,
        quality_profile={},
        goal_supplied=safe_goal,
        intents_supplied=safe_intents,
    )
    private_route = _privacy_safe_capability_route(private_raw_route, state, message)

    def persist(current: dict[str, object]) -> None:
        current["capability_inventory"] = copy.deepcopy(inventory)
        current["capability_route"] = copy.deepcopy(private_route)
        current["intents"] = copy.deepcopy(private_route["coverage"])

    persisted = ctx.update(persist)
    handoff = _handoff(persisted, ctx.events())
    handoff_path = tmp_path / "handoff.md"
    handoff_path.write_text(handoff, encoding="utf-8")

    assert _route_signature(public_route) == _route_signature(private_route)
    assert private_route["message"].startswith("sha256:")
    persisted_blobs = [
        ctx.state_file.read_text(encoding="utf-8"),
        ctx.events_file.read_text(encoding="utf-8"),
        handoff_path.read_text(encoding="utf-8"),
    ]
    assert all(SENSITIVE_PHRASE not in blob for blob in persisted_blobs)


def test_continue_and_extend_preserve_prior_routing_without_hash_text_rerank() -> None:
    inventory = _inventory()
    carried = {
        "intent_id": "intent-carried",
        "domain": "api",
        "text": "Host intent 1 (api) sha256:" + "a" * 64,
        "status": "deferred",
        "reason": "scheduled",
        "capability_ids": ["api-owner"],
        "skill_capability_ids": [],
        "agent_capability_ids": ["api-owner"],
        "required_responsibility_groups": ["api-implementation"],
        "role": "implementation",
        "depends_on_intent_ids": [],
    }
    incoming = [
        {
            "intent_id": "intent-new",
            "domain": "visualization",
            "text": "dashboard data visualization",
            "role": "implementation",
        }
    ]

    signatures = []
    for change_mode, placeholder in (
        ("continue", "a" * 64),
        ("extend", "f" * 64),
    ):
        prior = copy.deepcopy(carried)
        prior["text"] = f"Host intent 1 (api) sha256:{placeholder}"
        prior["carried_from_goal_version"] = 3
        supplied = _routing_intents_for_start(
            {
                "change_mode": change_mode,
                "intents": [prior, copy.deepcopy(incoming[0])],
            },
            incoming,
        )
        assert supplied[0]["_preserve_routing"] is True
        route = route_intents(
            message="opaque follow-up",
            inventory=inventory,
            supplied_intents=supplied,
            phase_budget=2,
        )
        carried_coverage = next(
            row for row in route["coverage"] if row["intent_id"] == "intent-carried"
        )
        assert carried_coverage["capability_ids"] == []
        assert carried_coverage["agent_capability_ids"] == []
        assert "required responsibility groups unavailable" in carried_coverage["reason"]
        assert route["valid"] is False
        signatures.append(
            (
                route["selected_capabilities"],
                [phase["capability_ids"] for phase in route["phases"]],
            )
        )
    assert signatures[0] == signatures[1]


def test_agent_groups_are_discovered_from_trusted_toml_and_skills_cannot_spoof(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    agents_root = workspace / ".codex" / "agents"
    agents_root.mkdir(parents=True)
    (agents_root / "api_owner.toml").write_text(
        'name = "api_owner"\n'
        'description = "API implementation owner"\n'
        'sandbox_mode = "workspace-write"\n',
        encoding="utf-8",
    )
    (agents_root / "reviewer.toml").write_text(
        'name = "reviewer"\n'
        'description = "Independent API reviewer"\n'
        'sandbox_mode = "read-only"\n',
        encoding="utf-8",
    )
    config = {
        "agent_roles": [
            {
                "id": "api_owner",
                "config": ".codex/agents/api_owner.toml",
                "responsibility_group": "api-implementation",
            },
            {
                "id": "reviewer",
                "config": ".codex/agents/reviewer.toml",
                "responsibility_group": "independent-review",
            },
        ]
    }
    agents = scan_project_agents(config, str(workspace))
    assert {
        (row["id"], row["responsibility_group"], row["capability_kind"])
        for row in agents
    } == {
        ("api_owner", "api-implementation", "agent"),
        ("reviewer", "independent-review", "agent"),
    }
    assert all(row["availability"] == "unavailable" for row in agents)
    assert all(row["health"] == "unknown" for row in agents)
    assert all(row["host_liveness_status"] == "unverified" for row in agents)
    assert all(row["active"] is False and row["automatic"] is False for row in agents)
    assert all(len(str(row["sha256"])) == 64 for row in agents)

    spoofed_skills = [
        {
            "id": "skill-pretending-to-own-api",
            "name": "api_owner",
            "description": "API implementation owner",
            "responsibility_group": "api-implementation",
            "capability_kind": "agent",
            "active": True,
            "automatic": True,
            "availability": "enabled",
            "health": "healthy",
        },
        {
            "id": "skill-pretending-to-review",
            "name": "reviewer",
            "description": "independent review",
            "responsibility_group": "independent-review",
            "active": True,
            "automatic": True,
            "availability": "enabled",
            "health": "healthy",
        },
    ]
    intents = [
        {
            "intent_id": "implement",
            "domain": "api",
            "text": "API implementation",
            "required_responsibility_groups": ["api-implementation"],
            "role": "implementation",
        },
        {
            "intent_id": "review",
            "domain": "review",
            "text": "independent review",
            "required_responsibility_groups": ["independent-review"],
            "role": "review",
        },
    ]
    route = route_intents(
        message="API implementation and independent review",
        inventory={"skills": spoofed_skills, "agents": agents},
        supplied_intents=intents,
        phase_budget=2,
    )
    assert route["selected_agents"] == []
    assert route["selected_skills"] == []
    assert route["selected_capabilities"] == []
    assert route["valid"] is False
    assert route["phases"] == []
    assert all(
        "required responsibility groups unavailable" in row["reason"]
        for row in route["coverage"]
    )


def test_missing_trusted_agent_group_is_not_satisfied_by_skill_metadata() -> None:
    intent = {
        "intent_id": "implement",
        "domain": "api",
        "text": "API implementation",
        "required_responsibility_groups": ["api-implementation"],
        "role": "implementation",
    }
    route = route_intents(
        message="API implementation",
        inventory={"skills": _inventory()["skills"] + [{
            "id": "spoof",
            "name": "api implementation",
            "description": "API implementation",
            "responsibility_group": "api-implementation",
            "capability_kind": "agent",
            "active": True,
            "automatic": True,
            "availability": "enabled",
            "health": "healthy",
        }], "agents": []},
        supplied_intents=[intent],
        phase_budget=2,
    )
    assert route["selected_capabilities"] == []
    assert route["coverage"][0]["status"] == "skipped"
    assert "required responsibility groups unavailable" in route["coverage"][0]["reason"]


def _write_hook_workspace(root: Path, *, persist_raw_prompts: bool) -> Path:
    supervisor = root / ".agent-supervisor"
    schemas = supervisor / "schemas"
    agents_root = root / ".codex" / "agents"
    schemas.mkdir(parents=True)
    agents_root.mkdir(parents=True)
    (schemas / "project.schema.json").write_text(
        json.dumps(
            {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "required": [
                    "$schema",
                    "project_id",
                    "execution_mode",
                    "privacy",
                    "agent_roles",
                    "supervisor_scope",
                ],
                "properties": {
                    "$schema": {"type": "string"},
                    "project_id": {"type": "string"},
                    "execution_mode": {"type": "string"},
                    "privacy": {"type": "object"},
                    "agent_roles": {"type": "array"},
                    "supervisor_scope": {"type": "object"},
                },
                "additionalProperties": False,
            }
        ),
        encoding="utf-8",
    )
    roles = []
    for index in range(10):
        primary = f"primary_agent_{index}"
        fallback = f"fallback_agent_{index}"
        group = f"implementation-group-{index}"
        primary_path = agents_root / f"{primary}.toml"
        fallback_path = agents_root / f"{fallback}.toml"
        primary_path.write_text(
            f'name = "{primary}"\n'
            f'description = "API security implementation owner {index}"\n'
            'sandbox_mode = "workspace-write"\n',
            encoding="utf-8",
        )
        fallback_path.write_text(
            f'name = "{fallback}"\n'
            f'description = "API security fallback owner {index}"\n'
            'sandbox_mode = "workspace-write"\n',
            encoding="utf-8",
        )
        roles.append(
            {
                "id": primary,
                "config": f".codex/agents/{primary}.toml",
                "responsibility_group": group,
                "fallback_id": fallback,
                "fallback_config": f".codex/agents/{fallback}.toml",
            }
        )
    project = supervisor / "project.json"
    project.write_text(
        json.dumps(
            {
                "$schema": "./schemas/project.schema.json",
                "project_id": "hook-routing",
                "execution_mode": "observe",
                "privacy": {"persist_raw_prompts": persist_raw_prompts},
                "agent_roles": roles,
                "supervisor_scope": {
                    "allowed_change_globs": [".agent-supervisor/**"],
                    "out_of_scope_globs": [],
                },
            }
        ),
        encoding="utf-8",
    )
    return project


def _write_hook_skill_home(home: Path) -> None:
    definitions = {
        "api-security-audit": "API security boundary audit authentication authorization",
        "dashboard-visualization": "dashboard data visualization chart report",
        "independent-review": "independent review quality acceptance",
    }
    for name, description in definitions.items():
        target = home / ".codex" / "skills" / name / "SKILL.md"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            f"---\nname: {name}\ndescription: {description}\n---\n# Fixture\n",
            encoding="utf-8",
        )
    git_path = shutil.which("git")
    assert git_path is not None
    registry = home / ".agent-supervisor" / "trusted-executables.json"
    registry.parent.mkdir(parents=True, exist_ok=True)
    executables = {
        "git": Path(git_path).resolve(),
        "python": Path(sys.executable).resolve(),
    }
    registry.write_text(
        json.dumps({
            "contract": "TrustedExecutableRegistry/v1",
            "entries": {
                name: {
                    "kind": "local",
                    "path": str(path),
                    "sha256": sha256_file(path),
                }
                for name, path in executables.items()
            },
            "generated_at": "2026-08-24T00:00:00Z",
        }),
        encoding="utf-8",
    )


def _invoke_user_prompt_hook(
    *,
    workspace: Path,
    state_root: Path,
    session: str,
    prompt: str,
    monkeypatch,
    capsys,
) -> tuple[int, dict[str, object], dict[str, object], Path]:
    payload = {
        "session_id": session,
        "cwd": str(workspace),
        "hook_event_name": "UserPromptSubmit",
        "prompt": prompt,
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))
    code = command_hook(
        Namespace(runtime="codex", event="UserPromptSubmit", state_root=str(state_root))
    )
    output = json.loads(capsys.readouterr().out)
    assert code in {0, 2, 4}, output
    assert output.get("hookSpecificOutput", {}).get("hookEventName") == "UserPromptSubmit", output
    candidates = []
    for path in state_root.rglob("state.json"):
        state = json.loads(path.read_text(encoding="utf-8"))
        if state.get("session") == session:
            candidates.append((
                int(state.get("goal", {}).get("version") or 0),
                str(state.get("updated_at") or state.get("started_at") or ""),
                path,
                state,
            ))
    assert candidates
    _version, _updated_at, state_path, state = max(
        candidates, key=lambda row: (row[0], row[1])
    )
    return code, output, state, state_path


def test_real_user_prompt_hook_privacy_route_equivalence_and_continuations(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    home = tmp_path / "home"
    _write_hook_skill_home(home)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    rejected_workspace = tmp_path / "rejected-workspace"
    private_workspace = tmp_path / "private-workspace"
    rejected_workspace.mkdir()
    private_workspace.mkdir()
    _write_hook_workspace(rejected_workspace, persist_raw_prompts=True)
    _write_hook_workspace(private_workspace, persist_raw_prompts=False)
    prompt = (
        f"API security audit {SENSITIVE_PHRASE}; dashboard data visualization; "
        "independent review"
    )

    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(json.dumps({
            "session_id": "rejected-session",
            "cwd": str(rejected_workspace),
            "hook_event_name": "UserPromptSubmit",
            "prompt": prompt,
        })),
    )
    rejected_code = command_hook(
        Namespace(
            runtime="codex",
            event="UserPromptSubmit",
            state_root=str(tmp_path / "rejected-state"),
        )
    )
    rejected_output = json.loads(capsys.readouterr().out)
    assert rejected_code == 4
    assert rejected_output == {
        "agent_supervisor": {
            "health": "degraded",
            "error": "ValueError",
            "fail_open": True,
        }
    }
    assert not list((tmp_path / "rejected-state").rglob("state.json"))

    private_code, private_output, private_state, private_state_path = (
        _invoke_user_prompt_hook(
            workspace=private_workspace,
            state_root=tmp_path / "private-state",
            session="private-session",
            prompt=prompt,
            monkeypatch=monkeypatch,
            capsys=capsys,
        )
    )
    assert private_code == 0
    assert private_output["hookSpecificOutput"]["hookEventName"] == "UserPromptSubmit"
    raw_intents = normalize_intents(split_intents(prompt), prompt)
    memory_route = route_intents(
        message=prompt,
        inventory=private_state["capability_inventory"],
        supplied_intents=raw_intents,
        phase_budget=3,
        zero_skill_reviewed=False,
    )
    assert _route_signature(memory_route) == _route_signature(
        private_state["capability_route"]
    )
    assert private_state["prompt_privacy"]["raw_prompt_persisted"] is False
    assert private_state["capability_route"]["message"].startswith("sha256:")
    assert private_state["discovery"]["counts"]["agents_discovered"] == 20
    agents = private_state["capability_inventory"]["agents"]
    assert sum(row["fallback_only"] is False for row in agents) == 10
    assert sum(row["fallback_only"] is True for row in agents) == 10
    assert sum(row["active"] is True for row in agents) == 0
    assert sum(row["availability"] == "unavailable" for row in agents) == 20
    assert sum(row["host_liveness_status"] == "unverified" for row in agents) == 20

    events_path = private_state_path.with_name("events.jsonl")
    private_handoff = _handoff(
        private_state,
        [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines()],
    )
    assert SENSITIVE_PHRASE not in private_state_path.read_text(encoding="utf-8")
    assert SENSITIVE_PHRASE not in events_path.read_text(encoding="utf-8")
    assert SENSITIVE_PHRASE not in private_handoff

    continued_code, _, continued_state, _ = _invoke_user_prompt_hook(
        workspace=private_workspace,
        state_root=tmp_path / "private-state",
        session="private-session",
        prompt="继续完成 API security audit",
        monkeypatch=monkeypatch,
        capsys=capsys,
    )
    assert continued_code == 0
    assert continued_state["goal"]["change_mode"] == "continue"
    assert continued_state["capability_route"]["valid"] is True
    carried = [
        row
        for row in continued_state["capability_route"]["coverage"]
        if row.get("reason") == "carried routing preserved without re-ranking prior prompt text"
    ]
    assert carried
    assert all(row["capability_ids"] for row in carried)

    extended_code, _, extended_state, _ = _invoke_user_prompt_hook(
        workspace=private_workspace,
        state_root=tmp_path / "private-state",
        session="private-session",
        prompt="另外补充 dashboard data visualization",
        monkeypatch=monkeypatch,
        capsys=capsys,
    )
    assert extended_code == 0
    assert extended_state["goal"]["change_mode"] == "extend"
    assert extended_state["capability_route"]["valid"] is True
    assert SENSITIVE_PHRASE not in json.dumps(extended_state, ensure_ascii=False)


def test_skill_agent_same_canonical_id_is_invalid() -> None:
    inventory = _inventory()
    inventory["skills"][0]["id"] = "api-owner"
    inventory["skills"][0]["name"] = "API-OWNER"
    route = route_intents(
        message="API security implementation",
        inventory=inventory,
        supplied_intents=[{
            "intent_id": "collision",
            "domain": "api",
            "text": "API security implementation",
        }],
    )
    assert route["valid"] is False
    assert route["identity_conflicts"] == ["api-owner"]
    assert route["selected_capabilities"] == []


def test_declared_dependency_dag_binds_phase_dependencies() -> None:
    intents = [
        {
            "intent_id": "implement",
            "domain": "api",
            "text": "API implementation",
            "role": "implementation",
        },
        {
            "intent_id": "visualize",
            "domain": "visualization",
            "text": "dashboard data visualization",
            "depends_on_intent_ids": ["implement"],
            "role": "implementation",
        },
        {
            "intent_id": "review",
            "domain": "review",
            "text": "independent review",
            "depends_on_intent_ids": ["visualize"],
            "role": "review",
        },
    ]
    route = route_intents(
        message="implement then visualize then review",
        inventory=_inventory(),
        supplied_intents=intents,
        phase_budget=2,
    )
    assert route["valid"] is True
    assert route["dependency_graph"]["topological_intent_order"] == [
        "implement",
        "visualize",
        "review",
    ]
    phase_by_intent = {
        intent_id: phase
        for phase in route["phases"]
        for intent_id in phase["intent_ids"]
    }
    assert phase_by_intent["visualize"]["depends_on"] == [
        phase_by_intent["implement"]["phase"]
    ]
    assert phase_by_intent["review"]["depends_on"] == [
        phase_by_intent["visualize"]["phase"]
    ]


@pytest.mark.parametrize(
    "dependencies, expected_error",
    [
        ({"a": ["missing"], "b": []}, "missing dependency"),
        ({"a": ["a"], "b": []}, "self dependency"),
        ({"a": ["b"], "b": ["a"]}, "intent dependency cycle"),
    ],
)
def test_invalid_dependency_graphs_fail_closed(
    dependencies: dict[str, list[str]], expected_error: str
) -> None:
    intents = [
        {
            "intent_id": intent_id,
            "domain": "api",
            "text": f"API security {intent_id}",
            "depends_on_intent_ids": depends_on,
        }
        for intent_id, depends_on in dependencies.items()
    ]
    route = route_intents(
        message="API dependency plan",
        inventory=_inventory(),
        supplied_intents=intents,
    )
    assert route["valid"] is False
    assert route["dependency_graph"]["status"] == "invalid"
    assert any(expected_error in error for error in route["errors"])
    assert route["phases"] == []
