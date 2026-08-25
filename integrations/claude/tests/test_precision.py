#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""检索**精度**评测 —— 此前只量了召回，所以噪声问题一直没被抓住。

背景（2026-08-20 实测）：
  真实项目任务 10 条，前三里有对口项 9/10 —— 召回没问题。
  元工具任务 8 条，几乎全是噪声，1 条完全空 —— **精度崩了**。
  而横幅列出的每一条都要在 ⑨ 里逐条处置，所以噪声会直接变成强制性的文书工作。

指标：noise@3 —— 前 3 条候选里被人工标注为「明显不相干」的比例。
判据：整体 noise@3 <= 20%，且元工具组 <= 25%。

标注原则：只标**明显**不相干的。可辩护的边缘项不算噪声，避免把评测调成我想要的样子。
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = Path(__file__).resolve().parent
PLAN = HERE.parent / "scripts" / "sup-plan.py"
spec = importlib.util.spec_from_file_location("supplan", str(PLAN))
if spec is None or spec.loader is None:
    raise RuntimeError("sup-plan module loader unavailable")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

UNMEASURABLE_EXIT = 77

# (提示词, 明显不相干的候选名)
PROJECT = [
    ("把学生端任务中心的卡片排版改好看点",
     ["Bookkeeper & Controller", "Tax Strategist", "Podcast Strategist", "Book Co-Author"]),
    ("点击登录后没反应，帮我彻底排查",
     ["Book Co-Author", "Anthropologist", "ckm:banner-design", "Podcast Strategist"]),
    ("移动端显示不适配，做一下响应式",
     ["Tax Strategist", "Anthropologist", "Blockchain Security Auditor"]),
    ("给落地页加个滚动动效",
     ["Tax Strategist", "Legal Billing & Time Tracking", "Bookkeeper & Controller"]),
    ("帮我做一份初中财商教育的教学课件",
     ["Blockchain Security Auditor", "Data Engineer", "Database Optimizer"]),
    ("审稿人说方法部分不清楚，帮我改论文",
     ["ckm:banner-design", "slack-gif-creator", "Database Optimizer"]),
    ("把这批答题数据做个统计分析",
     ["ckm:banner-design", "slack-gif-creator", "Podcast Strategist"]),
    ("用这张参考图重建一个3D角色模型",
     ["Bookkeeper & Controller", "Legal Client Intake", "Tax Strategist"]),
    ("答题记录的表结构帮我设计一下",
     ["high-end-visual-design", "brandkit", "ckm:banner-design", "Accessibility Auditor"]),
    ("这段代码帮我审查有没有安全问题",
     ["ckm:banner-design", "Podcast Strategist", "slack-gif-creator"]),
]

META = [
    # 措辞一律用**实测出过噪声的原话**，不是我改写过的版本。
    # 第一版评测我无意中换了措辞（「待跟进的那几条」），噪声消失、测试直接通过——
    # 那是把评测调成自己想要的样子，TDD 的红旗。
    ("继续完成⑥ 待跟进的内容",
     ["Content Creator", "Bilibili Content Strategist", "ai-research-writing",
      "Xiaohongshu Specialist", "Weibo Strategist", "WeChat Official Account Manager"]),
    ("把监工的钩子改一下，让它记录自己的执行结果",
     ["Accessibility Auditor", "Feishu Integration Developer", "Bilibili Content Strategist",
      "Inclusive Visuals Specialist"]),
    ("给这个校验器加一条新判据并写回归测试",
     ["ce-test-xcode", "App Store Optimizer", "Bilibili Content Strategist",
      "API Tester"]),
    ("查一下为什么台账显示 agent=1",
     ["Accessibility Auditor", "Agentic Search Optimizer", "ckm:banner-design",
      "Inclusive Visuals Specialist"]),
    ("让 skill 能够灵活调用起来",
     ["claude.ai Base44", "claude.ai Box", "Bilibili Content Strategist",
      "claude.ai Asana", "claude.ai Canva"]),
    ("监工现在各维度真实得几分",
     ["Feishu Integration Developer", "Bilibili Content Strategist", "ckm:banner-design"]),
    ("把这个 Python 钩子脚本的异常处理补全",
     ["ckm:banner-design", "Bilibili Content Strategist", "Roblox Systems Scripter",
      "Godot Gameplay Scripter"]),
    ("把 SKILL.md 瘦身一下，太长了",
     ["ckm:banner-design", "Bilibili Content Strategist", "Podcast Strategist"]),
]


def measure(cases, label, idx):
    slots = noisy = 0
    rows = []
    for prompt, avoid in cases:
        got = [it["call"] for _s, it in m.retrieve(prompt, idx, 3)]
        avoid_casefold = {str(name).casefold() for name in avoid}
        bad = [g for g in got if str(g).casefold() in avoid_casefold]
        slots += len(got)
        noisy += len(bad)
        rows.append((prompt, got, bad))
    rate = (100.0 * noisy / slots) if slots else 0.0
    print()
    print("== %s ==  槽位 %d · 噪声 %d · noise@3 = %.0f%%" % (label, slots, noisy, rate))
    for prompt, got, bad in rows:
        mark = "  " if not bad else "!!"
        bad_casefold = {str(name).casefold() for name in bad}
        print("  %s %-30s %s" % (mark, prompt[:30],
                                 " · ".join(("[" + g + "]") if str(g).casefold() in bad_casefold else g for g in got)
                                 or "（空）"))
    return slots, noisy


def regression_checks():
    """Attack the cache stamp and case-insensitive precision boundary in isolation."""
    if "Straße".casefold() != "STRASSE".casefold():
        return False, "casefold fixture is not Unicode-equivalent"

    saved = {
        name: getattr(m, name)
        for name in (
            "SKILLS_DIR", "AGENTS_DIR", "PLUGINS_DIR", "SETTINGS",
            "CLAUDE_JSON", "AUTH_CACHE", "INDEX",
        )
    }
    try:
        with tempfile.TemporaryDirectory(prefix="sup-plan-stamp-") as raw:
            root = Path(raw)
            first = root / "first"
            second = root / "second"
            for base in (first, second):
                skill = base / "skills" / "nested" / "SKILL.md"
                skill.parent.mkdir(parents=True)
                skill.write_text("---\nname: Straße\n---\nSECRET_A", encoding="utf-8")
                (base / "agents").mkdir()
                (base / "plugins").mkdir()
                (base / "settings.json").write_text('{"enabledPlugins":{}}', encoding="utf-8")
                (base / ".claude.json").write_text(
                    json.dumps({"mcpServers": {"fixture": {"token": "SECRET_A"}}}),
                    encoding="utf-8",
                )
                (base / "auth.json").write_text(
                    json.dumps({"RemoteFixture": {"token": "SECRET_A"}}), encoding="utf-8"
                )

            def bind(base):
                m.SKILLS_DIR = base / "skills"
                m.AGENTS_DIR = base / "agents"
                m.PLUGINS_DIR = base / "plugins"
                m.SETTINGS = base / "settings.json"
                m.CLAUDE_JSON = base / ".claude.json"
                m.AUTH_CACHE = base / "auth.json"
                m.INDEX = base / "state" / "dispatch-index.json"

            bind(first)
            stamp_a = m._sources_stamp()
            stamp_json = json.dumps(stamp_a, sort_keys=True)
            if "SECRET_A" in stamp_json or str(first) in stamp_json:
                return False, "source stamp persisted content or an absolute personal path"

            bind(second)
            stamp_copy = m._sources_stamp()
            if stamp_copy["personal_fingerprint"] != stamp_a["personal_fingerprint"]:
                return False, "personal stamp depends on the absolute root"

            target = second / "skills" / "nested" / "SKILL.md"
            before = target.stat()
            target.write_text("---\nname: Straße\n---\nSECRET_B", encoding="utf-8")
            os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))
            stamp_b = m._sources_stamp()
            if stamp_b["personal_fingerprint"] == stamp_copy["personal_fingerprint"]:
                return False, "bounded personal content change did not invalidate the stamp"

            m._atomic_write_index({"stamp": stamp_b, "items": []})
            if json.loads(m.INDEX.read_text(encoding="utf-8"))["stamp"] != stamp_b:
                return False, "atomic index replacement did not preserve JSON"
            if list(m.INDEX.parent.glob(".*.tmp")):
                return False, "atomic index replacement left a temporary file"
    finally:
        for name, value in saved.items():
            setattr(m, name, value)
    return True, ""


def thresholds_pass(project_slots, project_noise, meta_slots, meta_noise):
    """Reject an empty index instead of treating its zero noise rate as success."""
    if project_slots <= 0 or meta_slots <= 0:
        return False
    overall = 100.0 * (project_noise + meta_noise) / (project_slots + meta_slots)
    meta_rate = 100.0 * meta_noise / meta_slots
    return overall <= 20.0 and meta_rate <= 25.0


def annotated_must_not_names():
    """Return the capability names this precision fixture can actually score."""
    return {
        str(name).strip().casefold()
        for _prompt, names in PROJECT + META
        for name in names
        if str(name).strip()
    }


def indexed_capability_names(idx):
    return {
        str(item.get("call") or "").strip().casefold()
        for item in (idx.get("items") or [])
        if isinstance(item, dict) and str(item.get("call") or "").strip()
    }


def run():
    regression_ok, regression_reason = regression_checks()
    if not regression_ok:
        print("REGRESSION FAILURE: " + regression_reason)
        return 1
    idx, _ = m.load_index()
    if not idx.get("items"):
        print("UNMEASURABLE: capability index is empty; precision was not evaluated")
        return UNMEASURABLE_EXIT
    if not (annotated_must_not_names() & indexed_capability_names(idx)):
        print("UNMEASURABLE: capability index contains none of the annotated must-not names")
        return UNMEASURABLE_EXIT
    print("索引条目:", len(idx["items"]))
    ps, pn = measure(PROJECT, "真实项目任务", idx)
    ms, mn = measure(META, "元工具任务", idx)
    if ps <= 0 or ms <= 0:
        print("UNMEASURABLE: one or more precision groups produced zero candidate slots")
        return UNMEASURABLE_EXIT
    tot_s, tot_n = ps + ms, pn + mn
    overall = (100.0 * tot_n / tot_s) if tot_s else 0.0
    meta_rate = (100.0 * mn / ms) if ms else 0.0
    print()
    print("=" * 74)
    print("整体 noise@3 = %.0f%%   （判据 <= 20%%）" % overall)
    print("元工具 noise@3 = %.0f%%   （判据 <= 25%%）" % meta_rate)
    ok = thresholds_pass(ps, pn, ms, mn)
    print("判定: %s" % ("通过" if ok else "不通过"))
    print("=" * 74)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(run())
