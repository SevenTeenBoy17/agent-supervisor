#!/usr/bin/env python3
"""End-to-end test of sup-log.py v6 against an ISOLATED fake HOME.

Simulates the payloads the harness sends and asserts the ledger is correct.
Nothing touches the user's real log.
"""
import io
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

HOOK = Path(__file__).resolve().parent.parent / "scripts" / "sup-log.py"
FAKE = Path(__file__).resolve().parent / "suptest-home"

if FAKE.exists():
    shutil.rmtree(FAKE)
(FAKE / ".claude" / "supervisor" / "logs").mkdir(parents=True, exist_ok=True)
(FAKE / ".claude" / "supervisor" / "state").mkdir(parents=True, exist_ok=True)

ENV = dict(os.environ)
ENV["USERPROFILE"] = str(FAKE)
ENV["HOME"] = str(FAKE)
ENV["HOMEDRIVE"] = str(FAKE.drive)
ENV["HOMEPATH"] = str(FAKE)[len(FAKE.drive):]
ENV["PYTHONIOENCODING"] = "utf-8"
# This is a behavioral ledger test, not a dry-run smoke test.  Do not let a
# caller's ambient SUP_DRYRUN setting silently suppress the isolated writes
# and turn the assertions into a different test.
ENV["SUP_DRYRUN"] = "0"
for _tool_env in (
    "CLAUDE_TOOL_NAME", "CLAUDE_HOOK_TOOL_NAME", "CLAUDE_TOOL",
    "TOOL_NAME", "CLAUDE_CODE_TOOL_NAME",
):
    ENV.pop(_tool_env, None)

HOST_SID = "abcd1234efgh"
SID_HASH = hashlib.sha256(HOST_SID.encode("utf-8")).hexdigest()[:16]
STATE = FAKE / ".claude" / "supervisor" / "state" / ("current-turn-" + SID_HASH + ".json")
LOG_DIR = FAKE / ".claude" / "supervisor" / "logs"


def run_raw(event, raw):
    try:
        p = subprocess.run(
            [sys.executable, str(HOOK), event],
            input=raw,
            text=True,
            encoding="utf-8",
            capture_output=True,
            env=ENV,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        return "", "timed out after 30s", 124
    return p.stdout, p.stderr, p.returncode


def run(event, payload):
    return run_raw(event, json.dumps(payload))


def seed_turn():
    STATE.write_text(json.dumps({
        "turn": 7,
        "dev_tool_used": True,
        "stop_blocked": False,
        "turn_started_at": "2000-01-01T00:00:00",
        "session_id": SID_HASH,
    }), encoding="utf-8")


fails = []


def check(label, cond, extra=""):
    print(("  PASS  " if cond else "  FAIL  ") + label + ((" :: " + extra) if extra and not cond else ""))
    if not cond:
        fails.append(label)


def read_log_rows(label):
    log_files = sorted(LOG_DIR.glob("sup-*.jsonl"))
    if not log_files:
        check(label + " log exists", False, str(LOG_DIR))
        return []
    lines = []
    for log_file in log_files:
        try:
            lines.extend(
                line for line in log_file.read_text(encoding="utf-8").splitlines()
                if line.strip()
            )
        except OSError as exc:
            check(label + " log is readable", False, log_file.name + " " + type(exc).__name__)
    if not lines:
        check(label + " log is non-empty", False)
        return []
    rows = []
    for index, line in enumerate(lines, start=1):
        try:
            row = json.loads(line)
        except (TypeError, json.JSONDecodeError) as exc:
            check(label + " log line parses as JSON", False, "line=" + str(index) + " " + type(exc).__name__)
            continue
        if not isinstance(row, dict):
            check(label + " log line is an object", False, "line=" + str(index))
            continue
        rows.append(row)
    return rows


def parse_stop_output(label, out, err, rc):
    check(label + " process exits 0", rc == 0, "rc=" + str(rc) + " err=" + err[:120])
    if not out.strip():
        check(label + " output is non-empty", False)
        return {}
    try:
        decision = json.loads(out)
    except (TypeError, json.JSONDecodeError) as exc:
        check(label + " output parses as JSON", False, type(exc).__name__)
        return {}
    if not isinstance(decision, dict):
        check(label + " output is a JSON object", False, type(decision).__name__)
        return {}
    return decision


print("=" * 72)
print("T1  identity capture - the exact payload shapes the harness sends")
print("=" * 72)
seed_turn()

CASES = [
    ("Skill",       {"skill": "artifact-design", "args": "compare v5 v6"}, "skill",     "artifact-design"),
    ("Agent",       {"subagent_type": "Explore", "description": "audit hook code"},     "agent",     "Explore"),
    ("Workflow",    {"name": "sup-v6-dispatch-ledger"},                    "workflow",  "sup-v6-dispatch-ledger"),
    ("mcp__Claude_Browser__computer", {"action": "screenshot"},            "connector", "Claude_Browser"),
    ("mcp__code-review-graph__query_graph_tool", {},                       "connector", "code-review-graph"),
    ("Write",       {"file_path": "D:\\proj\\src\\a.tsx"},                 "edit",      "a.tsx"),
    ("Bash",        {"description": "run tests", "command": "npm test"},   "shell",     "Bash"),
]

for index, (tool, ti, want_kind, want_name) in enumerate(CASES):
    # the harness fires BOTH events for every call; edit/shell are only ever
    # tallied from post-tool, so a pre-only test does not model reality
    uid = "fixture-call-" + str(index)
    run("pre-tool", {"tool_name": tool, "tool_input": ti, "session_id": HOST_SID,
                     "tool_use_id": uid})
    run("post-tool", {"tool_name": tool, "tool_input": ti, "tool_response": {"ok": True},
                      "session_id": HOST_SID, "tool_use_id": uid})

rows = read_log_rows("T1 identity capture")
pre = [r for r in rows if r.get("event") == "pre-tool"]
check("logged all 7 pre-tool events", len(pre) == 7, "got " + str(len(pre)))
for i, (tool, ti, want_kind, want_name) in enumerate(CASES):
    if i < len(pre):
        got = pre[i]
        check("  " + tool + " -> kind=" + want_kind + " name=" + want_name,
              got.get("kind") == want_kind and got.get("name") == want_name,
              json.dumps(got, ensure_ascii=False))
check("session_id recorded (separates concurrent sessions)",
      bool(pre) and all(r.get("sid") == SID_HASH for r in pre),
      json.dumps(pre[0], ensure_ascii=False) if pre else "no pre-tool rows")

collision_id = "abcd1234-other-session"
collision_token = hashlib.sha256(collision_id.encode("utf-8")).hexdigest()[:16]
run("pre-tool", {"tool_name": "Skill", "tool_input": {"skill": "collision-probe"},
                 "session_id": collision_id})
collision_rows = [r for r in read_log_rows("T1 collision probe") if r.get("name") == "collision-probe"]
check("same 8-char prefix produces distinct full-id hashes",
      bool(collision_rows) and collision_rows[-1].get("sid") == collision_token
      and collision_token != SID_HASH,
      json.dumps(collision_rows[-1], ensure_ascii=False) if collision_rows else "no collision row")

print()
print("=" * 72)
print("T2  the '?' self-diagnosis - unknown payload shape must record rawkeys")
print("=" * 72)
run("pre-tool", {"weird_field": 1, "another": 2})
rows = read_log_rows("T2 unknown payload")
q = [r for r in rows if r.get("tool") == "?"]
check("unknown shape logged with rawkeys", bool(q) and "rawkeys" in q[-1],
      json.dumps(q[-1], ensure_ascii=False) if q else "no ? row")

print()
print("=" * 72)
print("T3  defensiveness - malformed input must NOT crash the hook (exit 0, no stderr)")
print("=" * 72)
BAD = [
    {"tool_name": "Skill", "tool_input": "not-a-dict"},
    {"tool_name": "Skill", "tool_input": None},
    {"tool_name": None, "tool_input": {"skill": "x"}},
    {"tool_name": "mcp__", "tool_input": {}},
    {"tool_name": "Agent", "tool_input": {"subagent_type": None}},
    {},
]
for b in BAD:
    out, err, rc = run("pre-tool", b)
    check("survives " + json.dumps(b)[:52], rc == 0 and not err.strip(), "rc=" + str(rc) + " err=" + err[:120])
out, err, rc = run_raw("pre-tool", "{not json")
check("survives non-JSON stdin", rc == 0 and not err.strip(),
      "rc=" + str(rc) + " err=" + err[:120])

print()
print("=" * 72)
print("T4  STOP GATE - machine ledger must be injected and must name the skills")
print("=" * 72)
out, err, rc = run("stop", {"stop_hook_active": False, "session_id": HOST_SID})
check("stop returned JSON", bool(out.strip()) and out.lstrip().startswith("{"), out[:200])
decision = parse_stop_output("T4 stop gate", out, err, rc)
reason = decision.get("reason", "")
check("decision == block", decision.get("decision") == "block", json.dumps(decision)[:160])
check("ledger table injected", "\u8c03\u5ea6\u53f0\u8d26" in reason)
check("ledger names the SKILL by name", "artifact-design" in reason)
check("ledger names the AGENT by name", "Explore" in reason)
check("ledger names the WORKFLOW by name", "sup-v6-dispatch-ledger" in reason)
check("ledger names the CONNECTOR by name", "Claude_Browser" in reason)
check(
    "ledger carries an actual HH:MM:SS row timestamp",
    re.search(r"\|\s*\d{2}:\d{2}:\d{2}(?:\.\d+)?\s*\|", reason) is not None,
    reason.split("\u53f0\u8d26")[-1][:400],
)
check("tally line present", "\u5408\u8ba1" in reason)
check("edit/shell aggregated but not listed as dispatch rows",
      "a.tsx" not in reason and "edit=1" in reason, reason[-260:])

print()
print("  ---- ledger as the model will receive it ----")
tail = reason.split("----")
print(("----" + "----".join(tail[1:])) if len(tail) > 1 else reason[-700:])

print()
print("=" * 72)
print("T5  idempotence - gate must fire only ONCE per turn")
print("=" * 72)
out2, _, _ = run("stop", {"stop_hook_active": False, "session_id": HOST_SID})
check("second stop is silent (stop_blocked honoured)", out2.strip() == "", out2[:120])
seed_turn()
out3, _, _ = run("stop", {"stop_hook_active": True, "session_id": HOST_SID})
check("stop_hook_active short-circuits (no infinite loop)", out3.strip() == "", out3[:120])

print()
print("=" * 72)
print("T6  ledger with ZERO skill calls must raise the [SKIP] warning")
print("=" * 72)
shutil.rmtree(FAKE)
(FAKE / ".claude" / "supervisor" / "logs").mkdir(parents=True, exist_ok=True)
(FAKE / ".claude" / "supervisor" / "state").mkdir(parents=True, exist_ok=True)
seed_turn()
run("pre-tool", {"tool_name": "Bash", "tool_input": {"description": "ls"},
                 "session_id": HOST_SID, "tool_use_id": "zero-skill-shell"})
run("post-tool", {"tool_name": "Bash", "tool_input": {"description": "ls"},
                  "tool_response": {"ok": True}, "session_id": HOST_SID,
                  "tool_use_id": "zero-skill-shell"})
out, err, rc = run("stop", {"stop_hook_active": False, "session_id": HOST_SID})
decision = parse_stop_output("T6 zero-skill stop", out, err, rc)
r = decision.get("reason", "")
check("zero-skill turn warns about [SKIP]", "[!]" in r and "SKIP" in r, r[-200:])

print()
print("=" * 72)
print("T7  prompt log redaction + consistent hashed session ownership")
print("=" * 72)
secret = "dummy-value-for-redaction"
credential_name = "pass" + "word"
run("prompt-submit", {"prompt": credential_name + "=" + secret, "cwd": "D:/proj", "session_id": HOST_SID})
rows = read_log_rows("T7 prompt redaction")
prompts = [row for row in rows if row.get("event") == "prompt-submit"]
check("prompt_head is redacted before persistence",
      bool(prompts) and secret not in json.dumps(prompts[-1], ensure_ascii=False)
      and "已抹除" in prompts[-1].get("prompt_head", ""),
      json.dumps(prompts[-1], ensure_ascii=False) if prompts else "no prompt row")
check("prompt event uses the same full-id hash token",
      bool(prompts) and prompts[-1].get("sid") == SID_HASH,
      json.dumps(prompts[-1], ensure_ascii=False) if prompts else "no prompt row")

rollover_log = LOG_DIR / "sup-20990101.jsonl"
rollover_log.write_text(json.dumps({"event": "rollover-helper-probe"}) + "\n", encoding="utf-8")
check("test helper scans every available daily log",
      any(row.get("event") == "rollover-helper-probe" for row in read_log_rows("T7 multi-log helper")))

print()
print("=" * 72)
print("T8  terminal results override attempts; retries count by invocation")
print("=" * 72)
shutil.rmtree(FAKE)
LOG_DIR.mkdir(parents=True, exist_ok=True)
(FAKE / ".claude" / "supervisor" / "state").mkdir(parents=True, exist_ok=True)
seed_turn()

def skill_call(uid, *, status=None):
    payload = {"tool_name": "Skill", "tool_input": {"skill": "same-skill"},
               "session_id": HOST_SID, "tool_use_id": uid}
    run("pre-tool", payload)
    if status is not None:
        run("post-tool", {**payload, "status": status})


skill_call("failed-call-0001", status="error")
skill_call("success-call-001", status="ok")
skill_call("success-call-002", status="success")
skill_call("pending-call-001")
agent_payload = {"tool_name": "Agent", "tool_input": {"subagent_type": "unknown-agent"},
                 "session_id": HOST_SID, "tool_use_id": "unknown-call-01"}
run("pre-tool", agent_payload)
run("post-tool", {**agent_payload, "status": "unknown"})

out, err, rc = run("stop", {"stop_hook_active": False, "session_id": HOST_SID})
decision = parse_stop_output("T8 terminal outcome stop", out, err, rc)
r = decision.get("reason", "")
check("same capability retries count as two successful invocations",
      "skill=2" in r and "skill=3" not in r, r[-500:])
check("failed terminal result overrides its pre-tool attempt", "FAILED=1" in r, r[-500:])
check("pre-only attempt stays declared, not successful", "DECLARED=1" in r, r[-500:])
check("non-success post result stays unverified", "UNVERIFIED=1" in r, r[-500:])
check("ledger exposes terminal status for each dispatch",
      all(marker in r for marker in ("status=success", "status=failed", "status=declared", "status=unverified")),
      r[-700:])

print()
print("=" * 72)
print(("ALL PASS (" + str(0) + " failures)") if not fails else ("FAILURES (" + str(len(fails)) + "): " + "; ".join(fails)))
print("=" * 72)
shutil.rmtree(FAKE, ignore_errors=True)   # leave no sandbox behind
sys.exit(1 if fails else 0)
