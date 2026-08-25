#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sup-discover — 磁盘实时盘点：到底装了哪些「真能调」的 skill。

为什么需要它：SKILL.md §8.2 的池表是手写快照，写下那一刻就开始过期，
新装的 skill 永远不会自己出现在池表里。文件系统才是权威源。

两个必须避开的坑（2026-08-20 实测踩到过）：
  1. `ListSkills` / `SearchSkills` **看不到本地 skill** —— 它们只枚举 claude.ai 托管的，
     实测返回 18 条，无一条本地/插件 skill。别用它们判断本地有没有某个 skill。
  2. `~/.claude/plugins/` 底下同时有 `cache/`（**已安装**）和 `marketplaces/`（**只是商店目录，
     没装**）。早期版本把两者一起数，报出 191 个，其中一批**根本调不动**
     （实测 `Skill(hook-development)` 直接 Unknown skill —— 它在 marketplaces 里）。
     现在只数 cache/，并按 settings.json 的 enabledPlugins 过滤。

调用名规则（同样实测踩过）：
  - 个人 skill（~/.claude/skills/<name>/）  -> 直接用 <name>
  - 插件 skill                              -> 必须写成 <plugin>:<name>，写裸名会 Unknown skill

用法：
    python sup-discover.py                # 全量清单
    python sup-discover.py <关键词...>     # 按需求词排序取前 25
    python sup-discover.py --new 7        # 近 7 天新装/改动
    python sup-discover.py --all          # 连未安装的 marketplace 条目一起列（默认不列）
"""
from __future__ import annotations

import io
import json
import math
import os
import re
import sys
import time
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

CLAUDE = Path.home() / ".claude"
PERSONAL = CLAUDE / "skills"
PLUGINS = CLAUDE / "plugins"
SETTINGS = CLAUDE / "settings.json"
PLUGIN_CONFIG_STATUS = "unknown"


def enabled_plugins() -> set[str] | None:
    """settings.json 里 enabledPlugins 形如 {'superpowers@market': True}。"""
    global PLUGIN_CONFIG_STATUS
    try:
        cfg = json.loads(io.open(SETTINGS, encoding="utf-8").read())
    except Exception:
        PLUGIN_CONFIG_STATUS = "unavailable"
        return None
    configured = cfg.get("enabledPlugins") if isinstance(cfg, dict) else None
    if not isinstance(configured, dict):
        PLUGIN_CONFIG_STATUS = "unavailable"
        return None
    PLUGIN_CONFIG_STATUS = "available"
    out = set()
    for k, v in configured.items():
        if isinstance(k, str) and v:
            out.add(k.split("@")[0])
    return out


def _parse_record(p: Path):
    try:
        with io.open(p, encoding="utf-8", errors="replace") as handle:
            txt = handle.read(4000)
            mtime = os.fstat(handle.fileno()).st_mtime
    except (OSError, ValueError):
        return None
    m = re.search(r"^---\s*$(.*?)^---\s*$", txt, re.M | re.S)
    fm = m.group(1) if m else txt[:1200]
    n = re.search(r"^name:\s*(.+)$", fm, re.M)
    d = re.search(r"^description:\s*(.+)$", fm, re.M)
    name = n.group(1).strip().strip("'\"") if n else p.parent.name
    desc = " ".join(d.group(1).split())[:300] if d else ""
    return name, desc, mtime


def parse(p: Path):
    """Backward-compatible metadata parser used by legacy callers."""
    record = _parse_record(p)
    return record[:2] if record is not None else None


def collect(include_uninstalled=False):
    """返回 {调用名: {...}}。调用名就是能直接喂给 Skill 工具的那个字符串。"""
    en = enabled_plugins()
    out = {}

    # ---- 个人 skill：裸名即调用名 -------------------------------------------
    if PERSONAL.exists():
        for p in PERSONAL.rglob("SKILL.md"):
            r = _parse_record(p)
            if not r:
                continue
            _declared_name, desc, mtime = r
            # Claude resolves a personal skill from ~/.claude/skills/<name>/,
            # so the directory is the invocation identity.  Frontmatter is
            # editable skill content and must not be able to forge an alias.
            canonical_name = p.parent.name
            out.setdefault(canonical_name, {
                "call": canonical_name, "name": canonical_name, "desc": desc, "kind": "personal",
                "plugin": "", "installed": True, "callable": True, "routable": True,
                "availability_reason": "",
                "path": str(p), "mtime": mtime,
            })

    # ---- 插件 skill：必须 plugin:name ---------------------------------------
    if PLUGINS.exists():
        for p in PLUGINS.rglob("SKILL.md"):
            rel = p.relative_to(PLUGINS).as_posix().split("/")
            if "skills" not in rel:
                continue
            i = rel.index("skills")
            # cache/<market>/<plugin>/<ver>/skills/<name>/SKILL.md  -> 已安装
            # marketplaces/<market>/plugins/<plugin>/skills/<name>/  -> 仅商店，未装
            installed = rel[0] == "cache"
            # Installed cache paths always pin the plugin at cache/<market>/<plugin>,
            # even when package-internal directories appear before skills/.  A
            # marketplace entry places the plugin directly before skills/.
            plugin = rel[2] if installed and len(rel) > 2 else (rel[i - 1] if i >= 1 else "?")
            if not installed and not include_uninstalled:
                continue
            # A cached plugin is callable only when settings.json explicitly
            # enables it.  An empty map means none are enabled; an unreadable
            # map is unavailable and must not turn the entire cache into a
            # false-positive capability inventory.
            if installed and (en is None or plugin not in en):
                continue
            r = _parse_record(p)
            if not r:
                continue
            name, desc, mtime = r
            call = plugin + ":" + name
            if call in out and (out[call].get("installed") or not installed):
                continue
            out[call] = {
                "call": call, "name": name, "desc": desc, "kind": "plugin",
                "plugin": plugin, "installed": installed,
                "callable": installed, "routable": installed,
                "availability_reason": "" if installed else "marketplace_not_installed",
                "path": str(p), "mtime": mtime,
            }
    return out


def main() -> int:
    args = [a for a in sys.argv[1:] if a != "--all"]
    inv = collect(include_uninstalled="--all" in sys.argv)
    callable_items = [v for v in inv.values() if v.get("callable") is True]
    unavailable_items = [v for v in inv.values() if v.get("callable") is not True]
    if PLUGIN_CONFIG_STATUS == "unavailable":
        print(
            "WARNING: enabledPlugins is unavailable; cached plugin skills were excluded.",
            file=sys.stderr,
        )

    if args and args[0] == "--new":
        try:
            days = float(args[1]) if len(args) > 1 else 7.0
        except (TypeError, ValueError):
            print("ERROR: --new expects a positive finite number of days.", file=sys.stderr)
            return 64
        if not math.isfinite(days) or days <= 0:
            print("ERROR: --new expects a positive finite number of days.", file=sys.stderr)
            return 64
        cut = time.time() - days * 86400
        fresh = sorted((v for v in inv.values() if v["mtime"] >= cut), key=lambda v: -v["mtime"])
        fresh_callable = sum(1 for v in fresh if v.get("callable") is True)
        print("NEW/CHANGED in last %s d: callable %d / unavailable %d / visible %d" % (
            days, fresh_callable, len(fresh) - fresh_callable, len(fresh)))
        for v in fresh[:60]:
            label = v["kind"] if v.get("callable") is True else (
                "unavailable:" + v["availability_reason"])
            print("  " + time.strftime("%m-%d %H:%M", time.localtime(v["mtime"]))
                  + "  [" + label + "] " + v["call"])
        return 0

    if args:
        terms = [a.lower() for a in args]
        scored = []
        for v in inv.values():
            hay = (v["call"] + " " + v["desc"]).lower()
            sc = sum(hay.count(t) * (5 if t in v["call"].lower() else 1) for t in terms)
            if sc:
                scored.append((sc, v))
        scored.sort(key=lambda x: -x[0])
        callable_scored = [(sc, v) for sc, v in scored if v.get("callable") is True]
        unavailable_scored = [(sc, v) for sc, v in scored if v.get("callable") is not True]
        print("MATCHES for %s: 可调用匹配 %d / 不可用匹配 %d" % (
            " ".join(terms), len(callable_scored), len(unavailable_scored)))
        print("（可调用项第二列可直接调用；插件 skill 必须带 plugin: 前缀）")
        for sc, v in callable_scored[:25]:
            print("  %3d  %s  %s" % (sc, v["call"], v["desc"][:88]))
        for sc, v in unavailable_scored[:25]:
            print("  %3d  %s  [UNAVAILABLE:%s] %s" % (
                sc, v["call"], v["availability_reason"], v["desc"][:64]))
        return 0

    per = sum(1 for v in callable_items if v["kind"] == "personal")
    plg = len(callable_items) - per
    print("可调用 skill 合计 %d 个（个人 %d / 插件 %d）" % (len(callable_items), per, plg))
    print("插件 skill 的调用名一律是 plugin:name，写裸名会 Unknown skill。")
    for kind, label in (("personal", "个人"), ("plugin", "插件")):
        names = sorted(v["call"] for v in callable_items if v["kind"] == kind)
        print()
        print("[" + label + "] " + str(len(names)))
        line = ""
        for n in names:
            if len(line) + len(n) > 100:
                print("  " + line)
                line = ""
            line += n + "  "
        if line:
            print("  " + line)
    if unavailable_items:
        print()
        print("[Marketplace 未安装/不可用] " + str(len(unavailable_items)))
        for v in sorted(unavailable_items, key=lambda item: item["call"]):
            print("  " + v["call"] + "  [" + v["availability_reason"] + "]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
