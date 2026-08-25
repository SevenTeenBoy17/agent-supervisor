#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sup-query — 把监工攒了几个月的流水变成能回答问题的东西。

在此之前 ~/.claude/supervisor/logs/ 里的数据从来没有任何东西读过。

用法：
    python sup-query.py skills [--days N]   # 我到底在用哪些 skill / agent / connector
    python sup-query.py work   [--days N]   # 我这段时间在哪些项目上、干了多少研发轮
    python sup-query.py turn                # 本轮台账（和 Stop 门禁注入的同一份）
    python sup-query.py idle   [--days N]   # 装了但从没用过的 skill
    python sup-query.py prune  [--keep N]   # 归档旧日志（默认只预演，加 --yes 才真动）

只读；prune 默认预演。
"""
from __future__ import annotations

import gzip
import io
import json
import os
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = Path(__file__).resolve().parent
LOGS = Path.home() / ".claude" / "supervisor" / "logs"
ARCHIVE = LOGS / "archive"


def arg(name, default=None):
    if name in sys.argv:
        i = sys.argv.index(name)
        if i + 1 < len(sys.argv):
            return sys.argv[i + 1]
    return default


def load(days):
    cut = (datetime.now() - timedelta(days=days)).strftime("%Y%m%d")
    for f in sorted(p for p in LOGS.glob("sup-*.jsonl") if p.stem[4:] >= cut):
        for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue


def bar(n, top, width=24):
    if not top:
        return ""
    return "█" * max(1, int(round(width * n / top)))


def cmd_skills(days):
    print()
    print("近 %d 天实际调用情况" % days)
    print("=" * 62)
    buckets = defaultdict(Counter)
    seen = set()
    for e in load(days):
        if e.get("event") != "pre-tool" or "kind" not in e:
            continue
        u = e.get("uid")
        if u:
            if u in seen:
                continue
            seen.add(u)
        k, n = e.get("kind"), e.get("name") or "?"
        if k in ("skill", "agent", "workflow", "connector") and n != "?":
            buckets[k][n] += 1
    titles = {"skill": "Skill", "agent": "Agent （子代理）",
              "workflow": "Workflow", "connector": "Connector / MCP"}
    any_data = False
    for k in ("skill", "agent", "workflow", "connector"):
        c = buckets[k]
        if not c:
            continue
        any_data = True
        print()
        print("  " + titles[k] + "   共 %d 次 / %d 种" % (sum(c.values()), len(c)))
        top = c.most_common(1)[0][1]
        for name, n in c.most_common(14):
            print("    %4d  %-26s %s" % (n, name[:26], bar(n, top)))
    if not any_data:
        print()
        print("  没有带身份的派单记录。身份采集是 v6（2026-08-20）才加的，")
        print("  在那之前日志只记了 \"Skill\" 而不记是哪个。")


def cmd_work(days):
    print()
    print("近 %d 天工作分布" % days)
    print("=" * 62)
    proj, proj_dev = Counter(), Counter()
    per_day = defaultdict(lambda: [0, 0])
    for e in load(days):
        if e.get("event") != "prompt-submit":
            continue
        cwd = (e.get("cwd") or "").strip() or "(未记录)"
        proj[cwd] += 1
        if e.get("dev") is True:
            proj_dev[cwd] += 1
        d = e.get("ts", "")[:10]
        per_day[d][0] += 1
        if e.get("dev") is True:
            per_day[d][1] += 1
    if not proj:
        print("  无数据")
        return
    print()
    print("  按项目")
    top = proj.most_common(1)[0][1]
    for cwd, n in proj.most_common(12):
        short = cwd if len(cwd) <= 38 else "..." + cwd[-35:]
        print("    %4d 轮 (研发 %3d)  %-38s %s" % (n, proj_dev[cwd], short, bar(n, top, 14)))
    print()
    print("  按日期")
    mx = max((v[1] for v in per_day.values()), default=1) or 1
    for d in sorted(per_day):
        tot, dev = per_day[d]
        print("    %s  %3d 轮 / 研发 %3d  %s" % (d, tot, dev, bar(dev, mx, 18)))


def cmd_turn():
    import importlib.util
    spec = importlib.util.spec_from_file_location("suplog", str(HERE / "sup-log.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    out = m.render_ledger()
    print()
    print(out if out else "  (本轮暂无可报的派单记录)")


def cmd_idle(days):
    print()
    print("装了但近 %d 天从未调用的 skill" % days)
    print("=" * 62)
    used = set()
    for e in load(days):
        if e.get("kind") == "skill" and e.get("name") and e.get("name") != "?":
            used.add(e["name"].lower())
    disc = HERE / "sup-discover.py"
    if not disc.exists():
        print("  找不到 sup-discover.py")
        return
    p = subprocess.run([sys.executable, str(disc)], capture_output=True,
                       env=dict(os.environ, PYTHONIOENCODING="utf-8"))
    names = []
    for line in p.stdout.decode("utf-8", "replace").splitlines():
        if line.startswith("  ") and "[" not in line and "TOTAL" not in line:
            names.extend(t for t in line.split() if t and not t.isdigit())
    idle = sorted(n for n in names if n.lower() not in used)
    print()
    print("  已装 %d 个，近 %d 天用过 %d 个，闲置 %d 个"
          % (len(names), days, len(used), len(idle)))
    if used:
        print("  用过的：" + ", ".join(sorted(used)[:20]))
    print()
    print("  注：身份采集 2026-08-20 才上线，在此之前的调用无法追溯，")
    print("  所以「闲置」在积累足够数据前会偏大。")


def cmd_prune(keep, really):
    print()
    cut = (datetime.now() - timedelta(days=keep)).strftime("%Y%m%d")
    olds = sorted(p for p in LOGS.glob("sup-*.jsonl") if p.stem[4:] < cut)
    total = sum(p.stat().st_size for p in LOGS.glob("sup-*.jsonl"))
    freed = sum(p.stat().st_size for p in olds)
    print("日志归档（保留最近 %d 天）" % keep)
    print("=" * 62)
    print("  当前总量 %.1f MB，待归档 %d 个文件 / %.1f MB"
          % (total / 1048576.0, len(olds), freed / 1048576.0))
    if not olds:
        print("  无需归档")
        return
    for p in olds[:10]:
        print("    " + p.name + "  %.2f MB" % (p.stat().st_size / 1048576.0))
    if len(olds) > 10:
        print("    ... 另 %d 个" % (len(olds) - 10))
    if not really:
        print()
        print("  预演模式，未动任何文件。确认后加 --yes 执行：")
        print("    python sup-query.py prune --keep %d --yes" % keep)
        return
    ARCHIVE.mkdir(parents=True, exist_ok=True)
    n = 0
    for p in olds:
        gz = ARCHIVE / (p.name + ".gz")
        with io.open(p, "rb") as fi, gzip.open(gz, "wb") as fo:
            shutil.copyfileobj(fi, fo)
        if gz.exists() and gz.stat().st_size > 0:
            p.unlink()
            n += 1
    print()
    print("  已压缩归档 %d 个文件 -> %s" % (n, ARCHIVE))


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 0
    cmd = sys.argv[1]
    days = int(arg("--days", "30"))
    if not LOGS.exists():
        print("找不到日志目录: " + str(LOGS))
        return 1
    if cmd == "skills":
        cmd_skills(days)
    elif cmd == "work":
        cmd_work(days)
    elif cmd == "turn":
        cmd_turn()
    elif cmd == "idle":
        cmd_idle(days)
    elif cmd == "prune":
        cmd_prune(int(arg("--keep", "60")), "--yes" in sys.argv)
    else:
        print(__doc__)
        return 1
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
