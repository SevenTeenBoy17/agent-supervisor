from __future__ import annotations

import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from supervisor_core.storage import StateContext
import supervisor_core.storage as storage_module
from supervisor_core.util import redact


def make_context(tmp_path, session="session-a"):
    return StateContext.build(runtime="codex", project="p", workspace=str(tmp_path / "workspace"), session=session, round_id="r", state_root=tmp_path / "state")


def test_100_way_event_write_is_lossless_and_monotonic(tmp_path):
    ctx = make_context(tmp_path)
    with ThreadPoolExecutor(max_workers=32) as pool:
        list(pool.map(lambda value: ctx.append_event({"event_type": "test", "value": value}), range(100)))
    events = ctx.events()
    assert len(events) == 100
    assert sorted(event["sequence"] for event in events) == list(range(1, 101))
    assert sorted(event["value"] for event in events) == list(range(100))
    for line in ctx.events_file.read_text(encoding="utf-8").splitlines():
        assert isinstance(json.loads(line), dict)


def test_100_way_authoritative_state_update_is_lossless(tmp_path):
    ctx = make_context(tmp_path)
    ctx.save({"evidence": []})

    def add(value: int) -> None:
        def mutate(state):
            state.setdefault("evidence", []).append({"evidence_id": f"e-{value}"})
        ctx.update(mutate)

    with ThreadPoolExecutor(max_workers=32) as pool:
        list(pool.map(add, range(100)))
    assert sorted(row["evidence_id"] for row in ctx.load()["evidence"]) == sorted(f"e-{value}" for value in range(100))


def test_100_way_cli_event_updates_keep_state_and_event_ledger(tmp_path):
    root = Path(__file__).resolve().parents[1]
    state_root = tmp_path / "state"
    common = [
        "--runtime", "codex", "--workspace", str(tmp_path), "--session", "cli-100",
        "--round", "round-100", "--state-root", str(state_root),
    ]
    started = subprocess.run(
        [sys.executable, "-m", "supervisor_core", "start", *common, "--message", "concurrency", "--change-mode", "replace", "--execution-mode", "observe"],
        cwd=root, capture_output=True, text=True, check=True,
    )
    state_file = Path(json.loads(started.stdout)["state_file"])

    def record(value: int) -> int:
        payload = json.dumps({"record": {"evidence_id": f"e-{value}"}})
        result = subprocess.run(
            [sys.executable, "-m", "supervisor_core", "event", *common, "--event-type", "evidence_record", "--data-json", payload],
            cwd=root, capture_output=True, text=True, encoding="utf-8", check=False,
        )
        return result.returncode

    with ThreadPoolExecutor(max_workers=24) as pool:
        assert list(pool.map(record, range(100))) == [0] * 100
    state = json.loads(state_file.read_text(encoding="utf-8"))
    assert {row["evidence_id"] for row in state["evidence"]} == {f"e-{value}" for value in range(100)}
    events = [json.loads(line) for line in state_file.with_name("events.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(events) == 101
    assert [row["sequence"] for row in events] == list(range(1, 102))


def test_two_sessions_are_fully_isolated(tmp_path):
    a = make_context(tmp_path, "chat-a")
    b = make_context(tmp_path, "chat-b")
    a.save({"session": "chat-a", "goal": {"goal_id": "a"}})
    b.save({"session": "chat-b", "goal": {"goal_id": "b"}})
    a.append_event({"event_type": "only-a"})
    b.append_event({"event_type": "only-b"})
    assert a.state_file != b.state_file
    assert a.load()["goal"]["goal_id"] == "a"
    assert b.load()["goal"]["goal_id"] == "b"
    assert a.events()[0]["event_type"] == "only-a"
    assert b.events()[0]["event_type"] == "only-b"


def test_secrets_are_redacted_before_persistence(tmp_path):
    ctx = make_context(tmp_path)
    ctx.append_event({"event_type": "command", "password": "do-not-save", "summary": "token=abc123"})
    raw = ctx.events_file.read_text(encoding="utf-8")
    assert "do-not-save" not in raw
    assert "abc123" not in raw
    assert "[REDACTED]" in raw


def test_redaction_covers_standalone_secret_argv_and_common_token_forms():
    clean = redact({
        "args": ["tool", "--api-key", "DUMMY_STANDALONE_SECRET", "--token=value", "safe"],
        "text": "sk-test-REDACT-ME github_pat_DUMMYVALUE Authorization: Basic DUMMY Bearer TOKENVALUE",
    })
    serialized = json.dumps(clean)
    for secret in ("DUMMY_STANDALONE_SECRET", "value", "sk-test-REDACT-ME", "github_pat_DUMMYVALUE", "DUMMY", "TOKENVALUE"):
        assert secret not in serialized
    assert clean["args"][0] == "tool"
    assert clean["args"][-1] == "safe"


def test_waiver_authorization_contract_metadata_survives_persistence(tmp_path):
    ctx = make_context(tmp_path)
    state = {
        "goal": {
            "waiver_authorizations": [
                {"criterion_id": "criterion-1", "request_sha256": "a" * 64}
            ]
        },
        "waivers": [{
            "waiver_id": "waiver-1",
            "source_authorization": "SUPERVISOR-WAIVE criterion-1",
            "source_authorization_sha256": "b" * 64,
        }],
    }
    ctx.save(state)
    persisted = ctx.load()
    assert persisted["goal"]["waiver_authorizations"] == state["goal"]["waiver_authorizations"]
    assert persisted["waivers"] == state["waivers"]


def test_validation_event_reader_includes_rotated_segments(tmp_path, monkeypatch):
    monkeypatch.setattr(storage_module, "DEFAULT_MAX_EVENT_BYTES", 900)
    ctx = make_context(tmp_path)
    for value in range(12):
        ctx.append_event({"event_type": "rotation-probe", "value": value, "summary": "x" * 120})
    assert (ctx.root / "events.1.jsonl").exists()
    events = ctx.events()
    assert [row["value"] for row in events] == list(range(12))
    assert [row["sequence"] for row in events] == list(range(1, 13))
