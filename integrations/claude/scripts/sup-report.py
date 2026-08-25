#!/usr/bin/env python3
# =============================================================================
# 已废弃 — 2026-08-20。不要用它，用 sup-query.py。
#
# 两个原因：
#   1. 从未被任何地方调用过（settings.json 无引用；SKILL.md 只在散文里提过一次；
#      current-turn.json 里从来没出现过它会写的 report_emitted 字段）。
#   2. 就算跑起来也没用：它的 classify_tools() 只能打印字面量 "Skill"/"Agent"，
#      因为 v6 之前的日志根本没记是哪个 skill。
#
# 替代品：scripts/sup-query.py（work / skills / idle / turn / prune）
# 保留原因：万一里面有想借鉴的渲染逻辑。可随时删除。
# =============================================================================
"""Render the fixed-format supervisor end-of-turn report from current turn log.

Reads ~/.claude/supervisor/logs/sup-<today>.jsonl and ~/.claude/supervisor/state/current-turn.json
to produce a structured markdown report.

Invocation:
  python sup-report.py [--mode summary|detailed]
"""
from __future__ import annotations
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


SUP_HOME = Path.home() / ".claude" / "supervisor"
LOG_DIR = SUP_HOME / "logs"
STATE_DIR = SUP_HOME / "state"


def load_current_turn_events() -> tuple[list[dict], dict]:
    """Return (events_this_turn, turn_state)."""
    state_file = STATE_DIR / "current-turn.json"
    state = {}
    if state_file.exists():
        try:
            state = json.loads(state_file.read_text(encoding="utf-8"))
        except Exception:
            pass

    turn_started_at = state.get("turn_started_at", "")
    log_file = LOG_DIR / f"sup-{datetime.now().strftime('%Y%m%d')}.jsonl"
    events = []
    if log_file.exists():
        for line in log_file.read_text(encoding="utf-8").splitlines():
            try:
                ev = json.loads(line)
                if turn_started_at and ev.get("ts", "") >= turn_started_at:
                    events.append(ev)
            except Exception:
                continue
    return events, state


def classify_tools(events: list[dict]) -> dict:
    """Group tool usage into skills / mcps / commands / other."""
    skills_used: list[tuple[str, str]] = []
    mcps_used: list[tuple[str, str]] = []
    agents_used: list[tuple[str, str]] = []
    commands: Counter = Counter()
    timeline: list[tuple[str, str]] = []

    for ev in events:
        if ev.get("event") != "pre-tool":
            continue
        tool = ev.get("tool", "?")
        ts = ev.get("ts", "").split("T")[-1][:8]  # HH:MM:SS

        if tool == "Skill":
            skills_used.append((ts, tool))
        elif tool == "Agent":
            agents_used.append((ts, tool))
        elif tool.startswith("mcp__"):
            mcps_used.append((ts, tool))
        else:
            commands[tool] += 1

        if tool in ("Skill", "Agent") or tool.startswith("mcp__"):
            timeline.append((ts, tool))

    return {
        "skills": skills_used,
        "mcps": mcps_used,
        "agents": agents_used,
        "commands": dict(commands),
        "timeline": timeline,
    }


def render_report(events: list[dict], state: dict) -> str:
    classes = classify_tools(events)
    turn_no = state.get("turn", "?")
    started = state.get("turn_started_at", "?")

    lines = []
    lines.append("═" * 60)
    lines.append(f"🛡️ Supervisor 本轮报告 — Turn #{turn_no}")
    lines.append(f"   开始: {started}")
    lines.append(f"   生成: {datetime.now().isoformat(timespec='seconds')}")
    lines.append("═" * 60)
    lines.append("")

    # Timeline
    lines.append("📊 调用时间线")
    if classes["timeline"]:
        for ts, tool in classes["timeline"]:
            lines.append(f"  [{ts}] {tool}")
    else:
        lines.append("  (无 skill / agent / MCP 调用 — 纯对话或仅原生工具)")
    lines.append("")

    # Skills
    lines.append(f"📦 调用的 Skill ({len(classes['skills'])})")
    if classes["skills"]:
        for ts, name in classes["skills"]:
            lines.append(f"  [{ts}] {name}")
    else:
        lines.append("  (无)")
    lines.append("")

    # MCP tools
    lines.append(f"🔧 调用的 MCP 工具 ({len(classes['mcps'])})")
    if classes["mcps"]:
        for ts, name in classes["mcps"]:
            lines.append(f"  [{ts}] {name}")
    else:
        lines.append("  (无)")
    lines.append("")

    # Agents
    if classes["agents"]:
        lines.append(f"🤖 调用的 Agent ({len(classes['agents'])})")
        for ts, name in classes["agents"]:
            lines.append(f"  [{ts}] {name}")
        lines.append("")

    # Native commands top-5
    if classes["commands"]:
        top5 = sorted(classes["commands"].items(), key=lambda x: -x[1])[:5]
        lines.append("⚙️ 原生工具调用（top 5）")
        for cmd, n in top5:
            lines.append(f"  {cmd}: {n}×")
        lines.append("")

    lines.append("🎯 Karpathy 合规自评（需要 Claude 主动判断填写）")
    lines.append("  - 假设明确化: [ ]")
    lines.append("  - 极简实现: [ ]")
    lines.append("  - 外科式修改: [ ]")
    lines.append("  - Goal-driven + 验证: [ ]")
    lines.append("")

    lines.append("⚠️ 待跟进")
    lines.append("  - [Claude 在执行结束时填写未解决事项]")
    lines.append("")

    lines.append("═" * 60)
    return "\n".join(lines)


def main() -> int:
    events, state = load_current_turn_events()
    print(render_report(events, state))

    # Mark report as emitted
    state["report_emitted"] = True
    state["report_emitted_at"] = datetime.now().isoformat(timespec="seconds")
    try:
        (STATE_DIR / "current-turn.json").write_text(
            json.dumps(state, ensure_ascii=False), encoding="utf-8"
        )
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
