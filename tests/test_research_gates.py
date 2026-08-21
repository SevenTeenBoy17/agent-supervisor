from __future__ import annotations

from supervisor_core.cli import _evaluate_builtin_gate
from supervisor_core.contracts import build_goal
from supervisor_core.util import sha256_text, utc_now
from supervisor_core.validation import _registered_gate_commands, _registered_gate_definitions


def _research_state() -> tuple[dict, list[dict]]:
    now = utc_now()
    intent = {
        "contract": "IntentCoverage/v3",
        "intent_id": "intent-research",
        "text": "verify material claims",
        "status": "covered",
        "reason": "research capability returned successfully",
        "capability_ids": ["researcher"],
        "method": "capability",
        "phase": 1,
        "domain": "research",
    }
    state = {
        "round": "round-research",
        "started_at": now,
        "intents": [intent],
        "intent_manifest": [{
            "intent_id": intent["intent_id"],
            "text_sha256": sha256_text(intent["text"]),
            "domain": "research",
        }],
        "claims": [{
            "contract": "ClaimRecord/v3",
            "claim_id": "claim-1",
            "statement_sha256": sha256_text("material fact"),
            "source_locator": "docs/spec.md:12",
            "collected_at": now,
            "collector": "researcher",
        }],
        "changes": {"files": []},
    }
    events = [
        {"event_type": "invocation_attempt", "invocation_id": "inv-1", "capability": "researcher", "actor": "worker"},
        {"event_type": "invocation_result", "invocation_id": "inv-1", "capability": "researcher", "actor": "worker", "result": "success"},
    ]
    return state, events


def test_research_builtin_gates_are_registered_as_executable_pseudo_commands() -> None:
    profile = {
        "profiles": {"research": {"gates": [
            {"id": "research.intent", "builtin": "intent-coverage"},
            {"id": "research.claims", "builtin": "claim-source-map"},
            {"id": "research.finalize", "builtin": "goal-finalize"},
        ]}}
    }
    definitions = _registered_gate_definitions(profile)
    assert definitions["research.intent"]["builtin"] == "intent-coverage"
    assert _registered_gate_commands(profile)["research.finalize"] == ["supervisor-builtin", "goal-finalize"]


def test_research_builtin_checks_intents_claims_and_trusted_finalize_path() -> None:
    state, events = _research_state()
    assert _evaluate_builtin_gate(state, events, "intent-coverage", finalize_internal=False)[0] == 0
    assert _evaluate_builtin_gate(state, events, "claim-source-map", finalize_internal=False)[0] == 0
    assert _evaluate_builtin_gate(state, events, "goal-finalize", finalize_internal=False)[0] == 2
    assert _evaluate_builtin_gate(state, events, "goal-finalize", finalize_internal=True)[0] == 0

    state["claims"] = []
    code, artifact = _evaluate_builtin_gate(state, events, "claim-source-map", finalize_internal=False)
    assert code == 2
    assert artifact["failures"] == ["no material claim records were supplied"]


def test_goal_contract_uses_domain_specific_research_evidence() -> None:
    goal = build_goal(
        "analyze the evidence",
        change_mode="replace",
        supplied={
            "acceptance_criteria": [{"description": "all claims traced", "domain": "research"}],
        },
        default_evidence=["common.lint"],
        default_evidence_by_domain={
            "research": ["common.lint", "research.intent", "research.claims", "research.finalize"],
        },
    )
    assert goal["acceptance_criteria"][0]["expected_evidence"] == [
        "common.lint", "research.intent", "research.claims", "research.finalize",
    ]
