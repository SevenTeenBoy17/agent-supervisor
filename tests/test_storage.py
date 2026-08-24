from __future__ import annotations

import json
import os
import socket
import stat
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import pytest

import supervisor_core.attestation as attestation_module
import supervisor_core.storage as storage_module
from supervisor_core.attestation import sign_record, verify_record
from supervisor_core.storage import LockTimeout, StateContext, default_session, exclusive_lock
from supervisor_core.util import parse_time, redact


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
    skill_root = tmp_path / "skill-home" / ".codex" / "skills"
    skill_file = skill_root / "concurrency" / "SKILL.md"
    skill_file.parent.mkdir(parents=True)
    skill_file.write_text(
        "---\n"
        "name: concurrency\n"
        "description: concurrency state event capability\n"
        "---\n"
        "# Test concurrency capability\n",
        encoding="utf-8",
    )
    common = [
        "--runtime", "codex", "--workspace", str(tmp_path), "--session", "cli-100",
        "--round", "round-100", "--state-root", str(state_root),
    ]
    started = subprocess.run(
        [sys.executable, "-m", "supervisor_core", "start", *common, "--message", "concurrency", "--change-mode", "replace", "--execution-mode", "observe", "--roots", str(skill_root)],
        cwd=root, capture_output=True, text=True, encoding="utf-8", check=True,
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
    event_token = "R21_EVENT_TOKEN_SENTINEL_91E7"
    ctx.append_event({"event_type": "command", "password": "do-not-save", "summary": f"token={event_token}"})
    raw = ctx.events_file.read_text(encoding="utf-8")
    assert "do-not-save" not in raw
    assert event_token not in raw
    assert "[REDACTED]" in raw


def test_redaction_covers_standalone_secret_argv_and_common_token_forms():
    argv_token = "R21_ARGV_TOKEN_SENTINEL_5B2D"
    clean = redact({
        "args": ["tool", "--api-key", "DUMMY_STANDALONE_SECRET", f"--token={argv_token}", "safe"],
        "text": "sk-test-REDACT-ME github_pat_DUMMYVALUE Authorization: Basic DUMMY Bearer TOKENVALUE",
    })
    serialized = json.dumps(clean)
    for secret in ("DUMMY_STANDALONE_SECRET", argv_token, "sk-test-REDACT-ME", "github_pat_DUMMYVALUE", "DUMMY", "TOKENVALUE"):
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


def test_live_owner_lock_is_not_stolen_only_because_file_is_old(tmp_path):
    lock_path = tmp_path / "live.lock"
    status, process_start = storage_module._process_probe(os.getpid())
    assert status == "alive"
    lock_path.write_text(json.dumps({
        "version": 1,
        "pid": os.getpid(),
        "process_start": process_start,
        "host": socket.gethostname(),
        "owner_nonce": "live-owner",
    }), encoding="utf-8")
    os.utime(lock_path, (0, 0))
    with pytest.raises(LockTimeout):
        with exclusive_lock(lock_path, timeout=0.05):
            pytest.fail("a live owner's lock must not be stolen")


def test_malformed_old_lock_is_not_reclaimed_without_confirmed_dead_owner(tmp_path):
    lock_path = tmp_path / "unknown.lock"
    lock_path.write_text("not-an-owner-record", encoding="utf-8")
    os.utime(lock_path, (0, 0))
    with pytest.raises(LockTimeout):
        with exclusive_lock(lock_path, timeout=0.05):
            pytest.fail("an unidentifiable owner is not confirmed dead")


def test_confirmed_dead_owner_lock_is_reclaimed(tmp_path):
    lock_path = tmp_path / "dead.lock"
    lock_path.write_text(
        json.dumps({
            "version": 1,
            "pid": 2_147_483_647,
            "process_start": "impossible-owner",
            "host": socket.gethostname(),
            "owner_nonce": "dead-owner",
        }),
        encoding="utf-8",
    )
    with exclusive_lock(lock_path, timeout=0.5):
        assert lock_path.exists()
        assert json.loads(lock_path.read_text(encoding="utf-8"))["owner_nonce"] != "dead-owner"


def test_lock_release_does_not_unlink_replacement_owner(tmp_path):
    lock_path = tmp_path / "replacement.lock"
    successor = {
        "version": 1,
        "pid": os.getpid(),
        "process_start": "successor",
        "host": socket.gethostname(),
        "owner_nonce": "successor-owner",
    }
    with exclusive_lock(lock_path):
        lock_path.unlink()
        lock_path.write_text(json.dumps(successor), encoding="utf-8")
    assert json.loads(lock_path.read_text(encoding="utf-8")) == successor


def test_concurrent_first_attestation_key_creation_converges_on_one_key(tmp_path, monkeypatch):
    key_file = tmp_path / "private" / "attestation.key"
    monkeypatch.setenv("AGENT_SUPERVISOR_ATTESTATION_KEY_FILE", str(key_file))
    calls = 0
    calls_lock = threading.Lock()
    second_call = threading.Event()

    def distinct_key(_size: int) -> bytes:
        nonlocal calls
        with calls_lock:
            calls += 1
            call = calls
            if call == 2:
                second_call.set()
        if call == 1:
            second_call.wait(timeout=0.2)
        return bytes([call]) * 32

    class KeySource:
        token_bytes = staticmethod(distinct_key)

    monkeypatch.setattr(attestation_module, "secrets", KeySource)

    def signed_record(value: int) -> dict[str, object]:
        record: dict[str, object] = {"event_type": "concurrent-sign", "value": value}
        record["attestation"] = sign_record(record)
        return record

    with ThreadPoolExecutor(max_workers=16) as pool:
        records = list(pool.map(signed_record, range(16)))

    assert calls == 1
    assert all(verify_record(record) for record in records)
    assert len(key_file.read_bytes()) == 32
    if os.name != "nt":
        assert stat.S_IMODE(key_file.stat().st_mode) == 0o600
        assert stat.S_IMODE(key_file.parent.stat().st_mode) & 0o077 == 0


def test_events_preserve_valid_records_and_report_malformed_tail(tmp_path):
    ctx = make_context(tmp_path)
    valid = ctx.append_event({"event_type": "valid", "value": 1})
    with ctx.events_file.open("a", encoding="utf-8") as handle:
        handle.write('{"event_type":"torn"')
    recovered = ctx.append_event({"event_type": "valid-after-torn-tail", "value": 2})

    events = ctx.events()

    assert valid in events
    assert recovered in events
    degraded = [event for event in events if event.get("event_type") == "event_ledger_degraded"]
    assert len(degraded) == 1
    assert degraded[0]["status"] == "degraded"
    assert degraded[0]["malformed_lines"] == 1
    assert "torn" not in json.dumps(degraded[0])


def test_parse_time_normalizes_naive_and_offset_timestamps_to_utc():
    assert parse_time("2026-08-21T12:30:00") == datetime(2026, 8, 21, 12, 30, tzinfo=timezone.utc)
    assert parse_time("2026-08-21T20:30:00+08:00") == datetime(2026, 8, 21, 12, 30, tzinfo=timezone.utc)


def test_transact_serializes_concurrent_state_and_event_updates(tmp_path):
    ctx = make_context(tmp_path)
    ctx.save({"count": 0})

    def record(value: int) -> None:
        def mutate(state):
            state["count"] += 1

        ctx.transact(mutate, {"event_type": "transaction", "value": value})

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(record, range(16)))

    assert ctx.load()["count"] == 16
    events = ctx.events()
    assert {event["value"] for event in events} == set(range(16))
    assert [event["sequence"] for event in events] == list(range(1, 17))


def test_transact_does_not_commit_state_when_event_write_fails(tmp_path, monkeypatch):
    ctx = make_context(tmp_path)
    ctx.save({"count": 0})
    original_write = storage_module._append_bytes_fsync

    def fail_event_write(path, payload, *args, **kwargs):
        if path == ctx.events_file:
            raise OSError("injected event write failure")
        return original_write(path, payload, *args, **kwargs)

    monkeypatch.setattr(storage_module, "_append_bytes_fsync", fail_event_write)
    with pytest.raises(OSError, match="injected event write failure"):
        ctx.transact(
            lambda state: state.update({"count": 1}),
            {"event_type": "transaction"},
        )

    assert ctx.load()["count"] == 0
    assert not ctx.events_file.exists()


@pytest.mark.parametrize("runtime", ["codex", "claude"])
def test_default_session_requires_explicit_host_session(runtime, monkeypatch):
    monkeypatch.delenv("CODEX_THREAD_ID", raising=False)
    monkeypatch.delenv("CLAUDE_SESSION_ID", raising=False)
    with pytest.raises(ValueError, match="session identity unavailable"):
        default_session(runtime)
