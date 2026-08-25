#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""检索质量评测 —— 拿真实中文提示词量命中率，不靠眼看。

背景：调度是否「灵活」，取决于检索能不能把对口的 skill/agent 摆到模型面前。
用户说中文、描述几乎全是英文，所以这里必须用**中文**提示词做评测集。

指标：
  Recall@6   前 6 条里是否至少命中一个「应该出现」的候选
  Precision  前 6 条里有多少是明显不相干的噪声（人工标注的 must_not）
"""
from __future__ import annotations

import importlib.util
import sys
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

# (提示词, 至少要命中其中一个, 明显不该出现的)
CASES = [
    ("把首页卡片的排版改好看一点，文字太多了",
     ["ce-frontend-design", "high-end-visual-design", "UI Designer", "impeccable",
      "design-taste-frontend", "web-design-guidelines"],
     ["Book Co-Author", "Psychologist", "Tax Strategist", "Loan Officer Assistant"]),

    ("点击登录后没有任何反应，请彻底解决这个问题",
     ["ce-debug", "superpowers:systematic-debugging", "Frontend Developer",
      "vercel:auth", "Code Reviewer"],
     ["Book Co-Author", "Anthropologist", "Podcast Strategist"]),

    ("用three.js做5到7种3D的IP形象",
     ["portfolio-3d-template", "Technical Artist", "XR Immersive Developer",
      "web-shader-extractor", "Senior Developer", "Roblox Avatar Creator"],
     ["Psychologist", "Bookkeeper & Controller", "Legal Client Intake"]),

    ("帮我分析一下这批数据的统计显著性",
     ["Analytics Reporter", "Data Engineer", "Financial Analyst", "xlsx"],
     ["ckm:banner-design", "slack-gif-creator"]),

    ("给这个落地页加一点滚动动效，别太花哨",
     ["gsap-scrolltrigger", "gsap-core", "improve-animations", "animate",
      "find-animation-opportunities", "gsap-timeline"],
     ["Tax Strategist", "Legal Billing & Time Tracking"]),

    ("这段代码帮我审查一下有没有安全问题",
     ["ce-code-review", "Code Reviewer", "Security Engineer",
      "Blockchain Security Auditor", "code-review-graph-helper"],
     ["ckm:banner-design", "Podcast Strategist"]),

    ("帮我做一份教学课件的PPT",
     ["codex-ppt", "pptx", "ckm:slides", "teaching-ppt-design",
      "Corporate Training Designer"],
     ["Blockchain Security Auditor", "Data Engineer"]),

    ("移动端显示不太适配，需要做响应式处理",
     ["ce-frontend-design", "impeccable", "web-design-guidelines",
      "Frontend Developer", "Mobile App Builder", "frontend-design-checklist"],
     ["Tax Strategist", "Anthropologist"]),

    ("帮我规划一下这个功能怎么做，先别写代码",
     ["ce-plan", "brainstorming", "superpowers:brainstorming", "Plan",
      "planning-with-files:planning-with-files", "Software Architect",
      "Sprint Prioritizer", "Product Manager"],
     ["slack-gif-creator", "Legal Document Review"]),

    ("数据库查询有点慢，帮我优化",
     ["Database Optimizer", "Backend Architect", "Data Engineer",
      "vercel:performance-optimizer", "ce-optimize"],
     ["ckm:banner-design", "Podcast Strategist"]),
]



# ---------------------------------------------------------------------------
# 诚实性警告 —— 读这个数字前先读这段
#
# 下面所有用例的对口答案，都是在词表写完之后由同一个人标注的。因此本文件测的是
# **词表自洽**，不是**泛化能力**。2026-08-20 实测过一次代价：一个独立 agent 另写
# 25 条中文提示词，Recall@6 只有 76%，而其中 6 条点名的失败样本在当时是 0/6。
# 那 6 条已被补进下面的 HELD_OUT 组并全部通过——但那是**针对它们补的映射**，
# 所以它们此刻也不再是留出样本了。
#
# 结论：本文件的 Recall 只能用来防回归，**不能当成"检索对新需求也好用"的证据**。
# 想知道真实泛化率，必须拿一批词表作者没见过的新提示词重测。
# ---------------------------------------------------------------------------

# 来自 2026-08-20 对抗审计的 6 条真实失败样本（当时 0/6），现作回归锁定
HELD_OUT = [
    ("学生的答题记录要存下来，帮我设计一下数据表结构",
     ["Database Optimizer", "Backend Architect", "Data Engineer"], []),
    ("把这个复利计算的表单做一下无障碍适配",
     ["Accessibility Auditor", "web-design-guidelines", "frontend-design-checklist",
      "ce-frontend-design", "Inclusive Visuals Specialist"], []),
    ("改完这版先别提交，帮我通读一遍代码",
     ["Code Reviewer", "ce-code-review", "code-review-graph-helper",
      "superpowers:receiving-code-review"], []),
    ("审稿人说方法部分交代不清楚，我该怎么回应",
     ["academic-paper-reviewer", "academic-paper", "ai-research-writing",
      "academic-paper-strategist", "academic-pipeline"], []),
    ("找一下最近三年儿童财商教育方向的文献",
     ["deep-research", "academic-paper-strategist", "academic-pipeline",
      "academic-paper", "academic-paper-composer"], []),
    ("这篇初稿读起来一股AI味，改自然一点",
     ["humanizer", "ai-research-writing", "superpowers:writing-skills"], []),
]

# 短语/寒暄：必须返回空，否则每轮横幅都会塞噪音
MUST_BE_EMPTY = ["继续", "修一下", "这个不对", "复利计算器", "好的", "谢谢"]

def run():
    idx, _ = m.load_index()
    if not idx.get("items"):
        print("UNMEASURABLE: capability index is empty; recall was not evaluated")
        return UNMEASURABLE_EXIT
    available = {
        str(item.get("call") or "")
        for item in idx["items"]
        if isinstance(item, dict)
    }
    expected = {
        candidate
        for _prompt, wanted, _avoid in CASES + HELD_OUT
        for candidate in wanted
    }
    if not available.intersection(expected):
        print("UNMEASURABLE: capability index has no expected retrieval candidates")
        return UNMEASURABLE_EXIT
    n_sk = sum(1 for i in idx["items"] if i["kind"] == "skill")
    print("索引：skill %d / 非 skill 候选 %d" % (n_sk, len(idx["items"]) - n_sk))
    print("=" * 78)
    hit = noise = 0
    for prompt, want, avoid in CASES:
        got = [it["call"] for _sc, it in m.retrieve(prompt, idx, 6)]
        good = [g for g in got if g in want]
        bad = [g for g in got if g in avoid]
        hit += 1 if good else 0
        noise += len(bad)
        mark = "命中" if good else "未命中"
        print("[%s] %s" % (mark, prompt[:34]))
        for g in got:
            tag = " <-对口" if g in want else ("  <-噪声" if g in bad else "")
            print("        %-42s%s" % (g[:42], tag))
        print()
    # --- 回归组：审计点名的 6 条 ---
    ho_hit = 0
    for prompt, want, _avoid in HELD_OUT:
        got = [it["call"] for _sc, it in m.retrieve(prompt, idx, 6)]
        good = [g for g in got if g in want]
        ho_hit += 1 if good else 0
        if not good:
            print("[回归未中] %s -> %s" % (prompt[:30], " · ".join(got[:4]) or "（空）"))
    print("审计留出组 Recall@6: %d/%d" % (ho_hit, len(HELD_OUT)))

    # --- 短语必须为空 ---
    noisy = [q for q in MUST_BE_EMPTY if m.retrieve(q, idx, 6)]
    print("短语误触发: %d/%d %s" % (len(noisy), len(MUST_BE_EMPTY), noisy or ""))

    total = len(CASES)
    print("=" * 78)
    print("Recall@6  : %d/%d = %.0f%%" % (hit, total, 100.0 * hit / total))
    print("标注噪声数: %d（越低越好）" % noise)
    ok = hit >= total * 0.8 and noise <= 3 and ho_hit == len(HELD_OUT) and not noisy
    print("判定      : %s" % ("通过（Recall>=80% 且噪声<=3）" if ok else "不通过，需继续调"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(run())
